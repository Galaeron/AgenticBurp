"""
IDOR / BOLA read-differential validator (single principal, read-only, safe).

The cross-identity validator proves broken access control when the tester supplies
a SECOND identity's session (the Autorize move). Many real IDORs need no second
account at all: as ONE authenticated principal you change the object reference in
the request (`?id=wiener` -> `?id=carlos`, `/orders/123` -> `/orders/124`) and the
server hands you another object it should not.

This validator proves exactly that with a THREE-WAY read differential, all as the
captured principal's own session, GET-only (never a write, never a delete):

  R_own       the id in the captured request        (the principal's own object)
  R_foreign   a different, real id                   (numeric neighbour / supplied)
  R_missing   a syntactically-valid but absent id    (control)

If R_foreign is a substantive 2xx that DIFFERS from BOTH R_own and R_missing, the
endpoint is serving per-id objects to whoever asks -- broken object-level
authorization. Requiring a difference from R_missing rules out endpoints that
return the same page for every id (no real object behind the parameter), the main
false positive. The other object's contents are never dumped into the finding.

Off by default with the rest of the active validators (validators.active_enabled),
scope-gated, GET-only.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult

# Query keys that carry an object reference an IDOR would swap.
_ID_QUERY_KEYS = {"id", "user", "user_id", "userid", "uid", "order", "order_id",
                  "account", "account_id", "oid", "object", "resource", "doc",
                  "file", "customer", "customer_id", "profile", "pid", "num"}
# A path segment that looks like an object identifier (numeric / hex / uuid).
_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{4,})$")
_DENIAL = ("not found", "no such", "forbidden", "unauthor", "access denied",
           "sign in", "log in", "login", "please authenticate", "error")


def _locate_id(exchange: HttpExchange):
    """Return (kind, key, value) for the object id in the request, or None.
    kind is 'query' (key is the param name) or 'path' (key is the segment index)."""
    parts = urlsplit(exchange.url)
    for key, val in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in _ID_QUERY_KEYS and val:
            return ("query", key, val)
    segs = [s for s in (parts.path or "").split("/")]
    for i, seg in enumerate(segs):
        if seg and _ID_SEGMENT.match(seg):
            return ("path", i, seg)
    return None


def _with_id(exchange: HttpExchange, kind, key, new_value: str) -> str:
    parts = urlsplit(exchange.url)
    if kind == "query":
        pairs = [(k, new_value if k == key else v)
                 for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        return urlunsplit((parts.scheme, parts.netloc, parts.path,
                           urlencode(pairs), parts.fragment))
    segs = (parts.path or "").split("/")
    segs[key] = new_value
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segs), parts.query, parts.fragment))


def _missing_id(value: str) -> str:
    return "999999987654321" if value.isdigit() else "idor-absent-zzq9x7"


def _foreign_ids(value: str, supplied) -> list[str]:
    out: list[str] = []
    if value.isdigit():
        n = int(value)
        for cand in (n + 1, n - 1, n + 2):
            if cand >= 0 and str(cand) != value:
                out.append(str(cand))
    for s in (supplied or []):
        s = str(s)
        if s and s != value and s not in out:
            out.append(s)
    # Keep the probe bounded.
    return out[:4]


def _is_object(status, body: str) -> bool:
    if status is None or not (200 <= status < 300):
        return False
    if len(body.strip()) < 32:
        return False
    low = body.lower()
    # A denial/login/not-found page is not "an object returned".
    return not any(tok in low[:400] for tok in _DENIAL)


def _distinct(sa, ba: str, sb, bb: str) -> bool:
    if sa != sb:
        return True
    if ba == bb:
        return False
    # Substantive body difference: meaningful size delta or different content.
    if abs(len(ba) - len(bb)) >= 16:
        return True
    return ba.strip() != bb.strip()


class IdorReadValidator(Validator):
    name = "idor_read"
    finding_classes = {"idor", "bola", "broken_object_level_authorization",
                       "insecure_direct_object_reference"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 candidate_ids: list[str] | None = None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        # Foreign object ids observed elsewhere in the run (e.g. usernames mined
        # from public content), tried in addition to numeric neighbours.
        self.candidate_ids = candidate_ids or []

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if (exchange.method or "GET").upper() != "GET":
            return False
        return _locate_id(exchange) is not None

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "idor", summary=why)

    async def _get(self, url: str, headers: dict):
        try:
            await global_throttle.acquire()
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                resp = await client.request("GET", url, headers=headers or None)
            return resp.status_code, (resp.text or "")
        except SafetyGateBlocked:
            return None
        except httpx.HTTPError:
            return None

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        if (exchange.method or "GET").upper() != "GET":
            return self._skip("IDOR read differential is GET-only (no mutating replay)")
        loc = _locate_id(exchange)
        if loc is None:
            return self._skip("no object-id reference (path segment or id query param) to swap")
        kind, key, value = loc
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("host", "content-length")}

        own = await self._get(exchange.url, headers)
        if own is None:
            return ValidationResult(self.name, "error", "idor",
                                    summary="baseline request blocked or failed")
        s_own, b_own = own
        if not _is_object(s_own, b_own):
            return self._skip("baseline id did not return a substantive object as this principal")

        missing = await self._get(_with_id(exchange, kind, key, _missing_id(value)), headers)
        s_miss, b_miss = missing if missing else (None, "")

        foreigns = _foreign_ids(value, self.candidate_ids)
        if not foreigns:
            return ValidationResult(
                self.name, "inconclusive", "idor", confidence=0.0, confirmed=False,
                summary="object-scoped endpoint, but no foreign id available to test",
                evidence=(f"{exchange.method} {exchange.url} is object-scoped on the {kind} id "
                          f"{key!r}, but no numeric neighbour or supplied candidate id was available "
                          f"to attempt a cross-object read."))
        for cand in foreigns:
            fr = await self._get(_with_id(exchange, kind, key, cand), headers)
            if fr is None:
                continue
            s_f, b_f = fr
            if not _is_object(s_f, b_f):
                continue
            if not _distinct(s_own, b_own, s_f, b_f):
                continue  # same as our own object -> not a foreign object
            # The foreign id must also differ from a KNOWN-absent id, else the
            # endpoint just returns the same page for everything (no real object).
            if missing is not None and not _distinct(s_miss, b_miss, s_f, b_f):
                continue
            return ValidationResult(
                self.name, "confirmed", "idor", confidence=0.75, confirmed=True,
                summary=(f"IDOR confirmed: changing the {kind} id {key!r} to another value returned "
                         f"a different user/object's record to the same session."),
                evidence=(f"As the captured principal, {exchange.method} with the {kind} id set to a "
                          f"foreign value returned a substantive object (HTTP {s_f}) that differs from "
                          f"both this principal's own object and a known-absent id -- broken "
                          f"object-level authorization. The other object's contents are redacted; the "
                          f"probe was read-only (no write or delete)."))
        return ValidationResult(
            self.name, "not_confirmed", "idor", confidence=0.0, confirmed=False,
            summary="No cross-object read: foreign ids were denied or returned no distinct object",
            evidence=f"Tried {len(foreigns)} foreign id(s) on the {kind} id {key!r}; access control held.")
