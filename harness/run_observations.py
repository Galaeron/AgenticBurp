"""Passive facts a run learns from its own responses, for checks that need
something the run already saw but no capture kept.

The run transport hands every answered hop here (before a redirect is followed),
so a 3xx whose off-scope follow is refused still teaches something. Two facts are
kept, both bounded and best-effort: an observer error never fails a send.

- Allowed redirect targets: a 3xx whose Location's host is off the request's
  origin and equals the host of an absolute-URL query value of that request. That
  is an endpoint redirecting to an external target its allowlist accepted. The
  open-redirect check uses it to try allowlist-bypass shapes (the allowed URL in a
  non-host part of the sentinel URL).
- Public keys: PEM public keys and RSA JWKs found in a response body. The JWT
  check reuses them for its RS256 -> HS256 key-confusion forgery without fetching
  any new path.

Nothing here names an application: parameters, paths and keys are learned from
whatever the target answered.
"""
from __future__ import annotations

import json
import re
import threading
from urllib.parse import parse_qsl, urljoin, urlsplit

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# Bounds: a run keeps a few targets per (origin, path, parameter) and a few keys.
MAX_TARGETS_PER_PARAM = 3
MAX_REDIRECT_KEYS = 256
MAX_PUBLIC_KEYS = 8
MAX_KEYS_PER_BODY = 4
MAX_SCANNED_BODY = 512 * 1024

_PEM_RE = re.compile(
    r"-----BEGIN (RSA )?PUBLIC KEY-----[A-Za-z0-9+/=\s\\]{64,8192}?-----END (RSA )?PUBLIC KEY-----")


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _origin(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return f"{(parts.scheme or '').lower()}://{(parts.netloc or '').lower()}"


def _absolute_http(value: str) -> bool:
    low = (value or "").strip().lower()
    return low.startswith("http://") or low.startswith("https://")


def allowed_redirect_targets(url: str, status, location: str) -> list[tuple[str, str]]:
    """(query parameter, value) pairs this response shows an endpoint redirecting
    to: a 3xx whose Location host is off the request's host and is the host of
    that parameter's absolute http(s) URL value. [] for anything else."""
    if status not in REDIRECT_STATUSES or not location:
        return []
    request_host = _host(url)
    try:
        destination = _host(urljoin(url, location.strip()))
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return []
    if not destination or destination == request_host:
        return []
    return [(name, value) for name, value in pairs
            if _absolute_http(value) and _host(value) == destination]


def _jwk_documents(body: str) -> list[dict]:
    """RSA JWKs in a JSON body: a JWK Set's keys, or one bare JWK."""
    try:
        document = json.loads(body)
    except (TypeError, ValueError):
        return []
    items = []
    if isinstance(document, dict):
        keys = document.get("keys")
        items = keys if isinstance(keys, list) else [document]
    elif isinstance(document, list):
        items = document
    return [item for item in items
            if isinstance(item, dict) and item.get("kty") == "RSA"
            and isinstance(item.get("n"), str) and isinstance(item.get("e"), str)][:MAX_KEYS_PER_BODY]


def public_keys_in(body: str) -> list[tuple[str, str, str]]:
    """(kind, kid, material) for each public key a body carries: kind "pem" with
    the PEM block as served (JSON-escaped newlines unescaped), or "jwk" with one
    RSA JWK as JSON. Cheap when the body carries none."""
    if not body or len(body) > MAX_SCANNED_BODY:
        return []
    out: list[tuple[str, str, str]] = []
    if "-----BEGIN" in body:
        for match in _PEM_RE.finditer(body):
            block = match.group(0)
            if "\\" in block:
                block = block.replace("\\r", "").replace("\\n", "\n").replace("\\/", "/")
            out.append(("pem", "", block))
            if len(out) >= MAX_KEYS_PER_BODY:
                return out
    if '"kty"' in body:
        for item in _jwk_documents(body.strip()):
            out.append(("jwk", str(item.get("kid") or ""),
                        json.dumps({"kty": "RSA", "n": item["n"], "e": item["e"],
                                    **({"kid": item["kid"]} if item.get("kid") else {})})))
    return out[:MAX_KEYS_PER_BODY]


class RunObservations:
    """The run's passive store of the two facts above. Thread-safe; every method
    swallows its own errors so a send never fails here."""

    def __init__(self):
        self._lock = threading.Lock()
        self._targets: dict[tuple[str, str, str], list[str]] = {}
        self._keys: list[tuple[str, str, str, str]] = []   # (source url, kind, kid, material)

    def observe(self, *, method: str, url: str, status, headers, body_fn) -> None:
        try:
            if (method or "GET").upper() == "GET" and status in REDIRECT_STATUSES:
                location = next((v for k, v in (headers or {}).items()
                                 if (k or "").lower() == "location"), "")
                for name, value in allowed_redirect_targets(url, status, location):
                    self.record_redirect_target(url, name, value)
            if status is not None and 200 <= int(status) < 300 and len(self._keys) < MAX_PUBLIC_KEYS:
                body = body_fn() if callable(body_fn) else (body_fn or "")
                if isinstance(body, str) and ("-----BEGIN" in body or '"kty"' in body):
                    for kind, kid, material in public_keys_in(body):
                        self.record_public_key(url, kind, kid, material)
        except Exception:   # passive: never fail the send
            pass

    def record_redirect_target(self, url: str, param: str, value: str) -> None:
        key = (_origin(url), urlsplit(url).path or "/", param)
        with self._lock:
            known = self._targets.get(key)
            if known is None:
                if len(self._targets) >= MAX_REDIRECT_KEYS:
                    return
                known = self._targets[key] = []
            if value not in known and len(known) < MAX_TARGETS_PER_PARAM:
                known.append(value)

    def redirect_targets(self, url: str, param: str) -> list[str]:
        """The allowed external targets seen for this endpoint's parameter."""
        try:
            key = (_origin(url), urlsplit(url).path or "/", param)
        except ValueError:
            return []
        with self._lock:
            return list(self._targets.get(key, ()))

    def record_public_key(self, url: str, kind: str, kid: str, material: str) -> None:
        with self._lock:
            if len(self._keys) >= MAX_PUBLIC_KEYS:
                return
            if any(k[1] == kind and k[3] == material for k in self._keys):
                return
            self._keys.append((url, kind, kid, material))

    def public_keys(self) -> list[tuple[str, str, str, str]]:
        """(source url, kind, kid, material) for every key the run has seen."""
        with self._lock:
            return list(self._keys)
