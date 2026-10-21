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

A different object alone is not an IDOR: public records at sequential ids differ
too (R14). So the foreign read is replayed once more with every credential header
removed (R_anon). The object counts as protected only when R_anon is a healthy,
interpretable denial (`_denial`): 401/403, a redirect to a login page, or a login
page. A 5xx, a transport failure or any other answer proves nothing about
authorization (RV-D2 V1), and neither does an absent-id control that failed.

This validator NEVER confirms (RV-D2 V2). One principal reading a protected
object at another id cannot show the object belongs to someone else: alice may
own orders 1 and 2. Its best result is an "inconclusive" candidate that names the
missing evidence -- a second identity's session, so cross_identity can show the
object's owner reads it and this principal should not, or a manual check. A
capture with no credentials, a foreign object served to anyone, or a failed
control is a weaker candidate.

Off by default with the rest of the active validators (validators.active_enabled),
scope-gated, GET-only.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import httpx

from harness import global_throttle
from harness.missing_auth_probe import _AUTH_HEADERS
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
# What an unauthenticated control must look like to count as an authorization
# denial (V1): wording of a login wall, and the path of a login page.
_LOGIN_WALL = ("sign in", "log in", "login", "please authenticate", "unauthor",
               "access denied", "forbidden", "not authorized", "not authorised")
_LOGIN_SEGMENT = re.compile(r"^(log[-_]?[io]n|sign[-_]?(in|on)|o?auth2?|authenticate|authorize"
                            r"|sso|sessions?|cas)(\.\w+)?$", re.IGNORECASE)
_REDIRECT = (301, 302, 303, 307, 308)


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


def _tokens(body: str) -> set[str]:
    return set(re.findall(r"[a-z0-9][a-z0-9_.@$-]*", (body or "").lower()))


def _object_markers(b_foreign: str, b_own: str, b_missing: str) -> set[str]:
    """Tokens only the foreign object's response carries: the part of the page
    that is that object, not the template shared with our own object or the
    absent-id page."""
    return _tokens(b_foreign) - _tokens(b_own) - _tokens(b_missing)


def _exposes_object(markers: set[str], status, body: str) -> bool:
    """Whether a response shows the foreign object. With no markers to look for,
    a 2xx is assumed to show it, so an unbound read can never confirm (R14)."""
    if status is None or not (200 <= status < 300):
        return False
    if not markers:
        return True
    return 2 * len(_tokens(body) & markers) >= len(markers)


def _denial(status, body: str, location: str) -> str:
    """Describe the unauthenticated control as an authorization denial, or ""
    when it is not one (V1). Only an answer that says "log in first" counts:
    401/403, a redirect to a login page, or a 2xx login page. A 5xx, a 404, a
    rate limit or a page that is neither the object nor a login wall says
    nothing about who may read the object."""
    if status in (401, 403):
        return f"HTTP {status}"
    if status in _REDIRECT:
        path = urlsplit(location or "").path or ""
        if any(_LOGIN_SEGMENT.match(seg) for seg in path.split("/") if seg):
            return f"HTTP {status} redirect to the login page {location}"
        return ""
    if status is not None and 200 <= status < 300:
        if any(tok in (body or "").lower()[:400] for tok in _LOGIN_WALL):
            return f"HTTP {status} login page"
    return ""


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
            location = (getattr(resp, "headers", None) or {}).get("location", "") or ""
            return resp.status_code, (resp.text or ""), location
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
        s_own, b_own, _ = own
        if not _is_object(s_own, b_own):
            return self._skip("baseline id did not return a substantive object as this principal")

        missing = await self._get(_with_id(exchange, kind, key, _missing_id(value)), headers)
        s_miss, b_miss, _ = missing if missing else (None, "", "")
        # The absent-id control must itself be a healthy answer: without it the
        # endpoint was never shown to tell a real object from an absent one.
        missing_failed = ("failed or was blocked" if missing is None
                          else f"answered HTTP {s_miss}" if s_miss >= 500 else "")

        foreigns = _foreign_ids(value, self.candidate_ids)
        if not foreigns:
            return ValidationResult(
                self.name, "inconclusive", "idor", confidence=0.0, confirmed=False,
                summary="object-scoped endpoint, but no foreign id available to test",
                evidence=(f"{exchange.method} {exchange.url} is object-scoped on the {kind} id "
                          f"{key!r}, but no numeric neighbour or supplied candidate id was available "
                          f"to attempt a cross-object read."))
        anon_headers = {k: v for k, v in headers.items() if k.lower() not in _AUTH_HEADERS}
        has_session = len(anon_headers) < len(headers)
        candidate = ""  # a distinct foreign object we could not show is protected
        protected = ""  # a protected foreign object this one principal could read
        for cand in foreigns:
            foreign_url = _with_id(exchange, kind, key, cand)
            fr = await self._get(foreign_url, headers)
            if fr is None:
                continue
            s_f, b_f, _ = fr
            if not _is_object(s_f, b_f):
                continue
            if not _distinct(s_own, b_own, s_f, b_f):
                continue  # same as our own object -> not a foreign object
            # The foreign id must also differ from a KNOWN-absent id, else the
            # endpoint just returns the same page for everything (no real object).
            if missing is not None and not _distinct(s_miss, b_miss, s_f, b_f):
                continue
            # R14: a different object is only an IDOR when it is protected and this
            # principal's session is what unlocks it. Replay the same foreign read
            # with every credential header removed (the unauthorized principal).
            if not has_session:
                candidate = candidate or (
                    f"the capture carries no session or credential header, so the foreign "
                    f"object (HTTP {s_f}) is readable without one: a public record or missing "
                    f"authentication, not a proven cross-principal read")
                continue
            if missing_failed:
                candidate = candidate or (
                    f"the absent-id control {missing_failed}, so the endpoint was not shown to "
                    f"tell a real object from an absent one")
                continue
            anon = await self._get(foreign_url, anon_headers)
            if anon is None:
                candidate = candidate or (
                    "the unauthenticated control read of the foreign object was blocked or failed")
                continue
            s_a, b_a, loc_a = anon
            if _exposes_object(_object_markers(b_f, b_own, b_miss), s_a, b_a):
                candidate = candidate or (
                    f"the foreign object is also served without credentials (HTTP {s_a}), so it is "
                    f"public to everyone, not protected from this principal")
                continue
            denied = _denial(s_a, b_a, loc_a)
            if not denied:
                # V1: a 5xx (or any answer that is not a login wall) is a failed
                # control, not proof that access is refused.
                candidate = candidate or (
                    f"the unauthenticated control read of the foreign object answered HTTP {s_a}, "
                    f"which is not an authorization denial (only 401/403, a redirect to a login "
                    f"page or a login page is), so the object was not shown to be protected")
                continue
            # V2: the object is protected and this session reads it, but one
            # principal cannot show it belongs to someone else.
            protected = (
                f"As the captured principal, {exchange.method} with the {kind} id {key!r} set to a "
                f"foreign value returned a substantive object (HTTP {s_f}) that differs from both "
                f"this principal's own object and a known-absent id (HTTP {s_miss}). The same read "
                f"without credentials was refused ({denied}), so the object is protected. That "
                f"does not show it belongs to another user: this principal may own both objects. "
                f"Missing evidence: a second identity, so the cross-identity check can show the "
                f"object's owner and that this principal should be denied it (register its "
                f"session via POST /identities/session-headers), or a manual check that the "
                f"object belongs to another user. The other object's contents are redacted; the "
                f"probe was read-only (no write or delete).")
            break
        if protected:
            return ValidationResult(
                self.name, "inconclusive", "idor", confidence=0.5, confirmed=False,
                summary=(f"IDOR candidate (unconfirmed): changing the {kind} id {key!r} returned "
                         f"another protected object to this session, but a single principal cannot "
                         f"show it belongs to someone else; a second identity is needed to confirm"),
                evidence=protected)
        if candidate:
            return ValidationResult(
                self.name, "inconclusive", "idor", confidence=0.3, confirmed=False,
                summary="IDOR candidate (unconfirmed): another object was readable, but it was not "
                        "shown to be protected from this principal",
                evidence=(f"On the {kind} id {key!r}, a foreign id returned a different object, but "
                          f"{candidate}. Different objects at neighbouring ids are not proof of "
                          f"broken object-level authorization."))
        return ValidationResult(
            self.name, "not_confirmed", "idor", confidence=0.0, confirmed=False,
            summary="No cross-object read: foreign ids were denied or returned no distinct object",
            evidence=f"Tried {len(foreigns)} foreign id(s) on the {kind} id {key!r}; access control held.")
