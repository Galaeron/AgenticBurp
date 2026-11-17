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

On its own this validator never confirms (RV-D2 V2). One principal reading a
protected object at another id cannot show the object belongs to someone else:
alice may own orders 1 and 2. Its best result is an "inconclusive" candidate that
names the missing evidence -- a second identity's session, so cross_identity can
show the object's owner reads it and this principal should not, or a manual check.
A capture with no credentials, a foreign object served to anyone, or a failed
control is a weaker candidate. The one exception is an ownership ledger that
establishes the protected foreign object belongs to a DIFFERENT account: an
operator declaration, or -- only when nothing is declared for it -- ownership the
harness observed for its own test principals (self_ownership.py). The anonymous
control still runs first, so an object also served without credentials is never
confirmed whatever the ledger says.

Off by default with the rest of the active validators (validators.active_enabled),
scope-gated, GET-only.
"""
from __future__ import annotations
from harness import scope_lock

import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import httpx

from harness import access_control_gate, global_throttle
from harness.missing_auth_probe import _AUTH_HEADERS
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .send_failures import SendFailures

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
    kind is 'query' (key is the param name) or 'path' (key is the segment index).

    In order: a query key from the conventional `_ID_QUERY_KEYS`, then a path
    segment that looks like an id, then any other query key NAMED as an identifier
    (`basketId`, `invoice_id`, `uuid`: volatile_params' identifier rule) whose
    value looks like an id (numeric, hex or UUID). The last step finds ids a fixed
    key list misses without moving the id an earlier step already found. Engine.IO
    framing on a polling request (`sid`) is transport state, never an object id."""
    from harness.volatile_params import _is_identifier_name, is_polling_transport
    parts = urlsplit(exchange.url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    for key, val in pairs:
        if key.lower() in _ID_QUERY_KEYS and val:
            return ("query", key, val)
    segs = [s for s in (parts.path or "").split("/")]
    for i, seg in enumerate(segs):
        if seg and _ID_SEGMENT.match(seg):
            return ("path", i, seg)
    polling = is_polling_transport(exchange.url)
    for key, val in pairs:
        if (val and _is_identifier_name(key) and _ID_SEGMENT.match(val.strip())
                and not (polling and key == "sid")):
            return ("query", key, val)
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


# --- two-principal ownership (authz.self_observed_ownership) -------------------
# A field an object names its owning account with.
_OWNER_FIELD = re.compile(
    r"^(?:user_?id|owner(?:_?id)?|owned_?by|customer_?id|account_?id|created_?by(?:_?id)?|"
    r"author_?id|member_?id|user_?email|owner_?email|email)$", re.IGNORECASE)
# JWT claims that name the caller's account, read at the top level or in one
# user object ({"data": {...}}, {"user": {...}}).
_ID_CLAIMS = ("id", "sub", "uid", "user_id", "userid", "account_id", "accountid")
_EMAIL_CLAIMS = ("email", "mail", "upn", "user_email")
_CLAIM_OBJECTS = ("data", "user", "account", "profile", "principal")


def _json_doc(body: str):
    import json
    try:
        return json.loads(body or "")
    except (ValueError, TypeError):
        return None


def _owner_fields(body: str) -> dict[str, tuple[str, str]]:
    """{json path: (kind, value)} of owner-naming scalar fields in a JSON object,
    kind "email" or "id". Values are compared, never reported."""
    out: dict[str, tuple[str, str]] = {}

    def walk(node, path, depth):
        if depth > 4 or len(out) >= 20:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                p = f"{path}/{k}"
                if isinstance(v, (dict, list)):
                    walk(v, p, depth + 1)
                elif (_OWNER_FIELD.match(str(k)) and isinstance(v, (str, int))
                      and not isinstance(v, bool) and str(v).strip()):
                    value = str(v).strip().lower()
                    out[p] = ("email" if "@" in value else "id", value)
        elif isinstance(node, list):
            for i, v in enumerate(node[:20]):
                walk(v, f"{path}/{i}", depth + 1)

    walk(_json_doc(body), "", 0)
    return out


def _session_accounts(session, self_owned) -> dict[str, set[str]]:
    """{"id": {...}, "email": {...}}: the account keys a run identity's own
    credentials name (its JWT claims) plus the account ids the run observed it
    bound to (self_ownership, from its own whoami reads)."""
    from harness.security import is_identity_credential_header
    from .jwt_forge_validator import _JWT_RE, _decode
    keys: dict[str, set[str]] = {"id": set(), "email": set()}

    def take(claims: dict):
        for name in _ID_CLAIMS:
            v = claims.get(name)
            if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip():
                value = str(v).strip().lower()
                keys["email" if "@" in value else "id"].add(value)
        for name in _EMAIL_CLAIMS:
            v = claims.get(name)
            if isinstance(v, str) and "@" in v:
                keys["email"].add(v.strip().lower())

    for name, value in (getattr(session, "headers", None) or {}).items():
        if not is_identity_credential_header(name):
            continue
        for match in _JWT_RE.finditer(value or ""):
            decoded = _decode(match.group(1))
            if not decoded:
                continue
            payload = decoded[1]
            take(payload)
            for obj in _CLAIM_OBJECTS:
                if isinstance(payload.get(obj), dict):
                    take(payload[obj])
    if self_owned is not None:
        try:
            keys["id"] |= {str(i).lower() for i in self_owned.account_ids(session.principal_id)}
        except Exception:
            pass
    return keys


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
                 candidate_ids: list[str] | None = None, ownership=None, run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        # An optional principals.OwnershipLedger (declared + self-observed facts).
        # None keeps the single-principal behaviour: never a confirmation.
        self.ownership = ownership
        self.run_context = run_context
        # Foreign object ids observed elsewhere in the run (e.g. usernames mined
        # from public content), tried in addition to numeric neighbours.
        self.candidate_ids = candidate_ids or []

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if (exchange.method or "GET").upper() != "GET":
            return False
        # An object-access claim only (this leg's own classes, or the access-control
        # markers cross_identity uses): an id in the URL alone made this leg apply to
        # every finding on the route, so its read differential "confirmed" XSS,
        # header and transport findings on /rest/basket/<id> (r5).
        if not (super().applies(finding, exchange)
                or access_control_gate._is_access_control_class(finding.vulnerability_class)):
            return False
        return _locate_id(exchange) is not None

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "idor", summary=why)

    async def _get(self, url: str, headers: dict, failures=None):
        if failures is not None:
            failures.attempted += 1
        try:
            await global_throttle.acquire()
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                resp = await client.request("GET", url, headers=headers or None)
            location = (getattr(resp, "headers", None) or {}).get("location", "") or ""
            return resp.status_code, (resp.text or ""), location
        except (SafetyGateBlocked, httpx.HTTPError) as e:
            if failures is not None:
                failures.exception(SendFailures.label("GET", url), e)
            return None

    async def _reader(self, exchange: HttpExchange):
        """The principal whose credentials made the captured request: the run
        session that owns them, else the capture's credential alias (provisional)."""
        import asyncio
        from harness import principals, store
        from harness.run_context import current_run_context
        ctx = self.run_context or current_run_context()
        if ctx is not None:
            ref, _ = ctx.sessions.bind_headers(exchange.request_headers or {})
            session = ctx.sessions.get(ref)
            if session is not None:
                return session.principal or principals.Principal(
                    id=session.principal_id, role=session.role or "user", provisional=True)
        try:
            pid = await asyncio.to_thread(store.captured_principal_id, exchange)
        except Exception:
            return None
        return principals.Principal(id=pid, provisional=True)

    async def _ownership_of(self, exchange: HttpExchange, url: str):
        """(decision, source, provenance) for the captured principal reading `url`."""
        from harness import principals
        from harness.run_context import current_run_context
        unknown = (principals.AuthzDecision.UNKNOWN, "none", "")
        if self.ownership is None or not hasattr(self.ownership, "authorization_source"):
            return unknown
        reader = await self._reader(exchange)
        if reader is None or reader.is_anonymous:
            return unknown
        ctx = self.run_context or current_run_context()
        ref = principals.object_reference(url, run_id=getattr(ctx, "run_id", "") or "")
        decision, source, provenance = self.ownership.authorization_source(reader, ref, "GET")
        if decision == principals.AuthzDecision.UNAUTHORIZED and reader.provisional \
                and source != "self_observed":
            # A credential alias cannot be compared with a declared owner name.
            return unknown
        return decision, source, provenance

    def _two_principal_ready(self) -> str:
        """"" when a two-principal ownership check can run, else why not. It needs
        the run's self-observed ownership opt-in (authz.self_observed_ownership,
        the owner decision of 2026-11-03) and a second run identity."""
        from harness.run_context import current_run_context
        ctx = self.run_context or current_run_context()
        if ctx is None or getattr(ctx, "self_ownership", None) is None:
            return ("authz.self_observed_ownership is off, so ownership the harness observes for "
                    "its own identities is not used")
        principals = {s.principal_id for s in ctx.sessions.identities()}
        if len(principals) < 2:
            return "the run has no second identity"
        return ""

    async def _two_principal(self, exchange, foreign_url, b_own, b_f, markers, anon_headers):
        """Show the protected foreign object belongs to ANOTHER run identity:
        (a) an owner-naming field in it (userId, ownerId, customerId, email, ...)
        holds one of identity B's own account keys (from B's token claims or B's
        observed account binding); (b) the reader A's own object carries A's key
        at the same field, so the field is the owner and A and B are different
        accounts of the same kind; (c) B's own session reads the same object.
        Returns ({"b": principal, "field": path, "kind": kind, "status": s}, "")
        or (None, the missing evidence). Values are compared, never reported."""
        from harness.run_context import current_run_context
        from harness.security import is_identity_credential_header
        ctx = self.run_context or current_run_context()
        so = getattr(ctx, "self_ownership", None)
        ref, _ = ctx.sessions.bind_headers(exchange.request_headers or {})
        reader = ctx.sessions.get(ref)
        if reader is None:
            return None, "the capture's credentials belong to no run identity"
        mine = _session_accounts(reader, so)
        others = [s for s in ctx.sessions.identities() if s.principal_id != reader.principal_id]
        theirs = [(s, _session_accounts(s, so)) for s in others]
        foreign_fields, own_fields = _owner_fields(b_f), _owner_fields(b_own)
        if not foreign_fields:
            return None, "the foreign object has no owner-naming field (userId, ownerId, email ...)"
        why = ""
        for path, (kind, value) in foreign_fields.items():
            own = own_fields.get(path)
            if own is None or own[0] != kind or own[1] not in mine[kind]:
                why = why or (f"this principal's own object does not carry its own account at the "
                              f"owner field {path}, so that field is not shown to name the owner")
                continue
            if value in mine[kind]:
                why = why or f"the owner field {path} names this principal's own account"
                continue
            owner = next((s for s, keys in theirs if value in keys[kind]), None)
            if owner is None:
                why = why or (f"the owner field {path} names an account no run identity holds "
                              f"(value redacted)")
                continue
            creds = {k: v for k, v in (owner.headers or {}).items() if is_identity_credential_header(k)}
            read = await self._get(foreign_url, dict(anon_headers, **creds))
            if read is None:
                return None, f"the second identity {owner.principal_id}'s read failed or was blocked"
            s_b, b_b, _ = read
            if not (_is_object(s_b, b_b) and _exposes_object(markers, s_b, b_b)
                    and _owner_fields(b_b).get(path) == (kind, value)):
                why = why or (f"the owner field {path} names {owner.principal_id}, but that "
                              f"identity's own session did not read the same object (HTTP {s_b})")
                continue
            return {"b": owner.principal_id, "a": reader.principal_id, "field": path, "kind": kind,
                    "status": s_b}, ""
        return None, why

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {host!r} out of scope")
        if (exchange.method or "GET").upper() != "GET":
            return self._skip("IDOR read differential is GET-only (no mutating replay)")
        loc = _locate_id(exchange)
        if loc is None:
            return self._skip("no object-id reference (path segment or id query param) to swap")
        kind, key, value = loc
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("host", "content-length")}

        baseline = SendFailures()
        own = await self._get(exchange.url, headers, baseline)
        if own is None:
            if baseline.refused:
                return baseline.result(self.name, "idor", "IDOR baseline")
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
        protected_at = (None, "")
        # Why a two-principal ownership check cannot run ("" when it can). When it
        # can, every foreign id is tried for one a second identity owns; otherwise
        # the first protected object ends the probe, as before.
        unready = self._two_principal_ready()
        two_why = ""
        failures = SendFailures()
        for cand in foreigns:
            foreign_url = _with_id(exchange, kind, key, cand)
            fr = await self._get(foreign_url, headers, failures)
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
            # The ledger may know whose object this is (declared first, then
            # self-observed); only then can one principal's read be a crossing.
            from harness.principals import AuthzDecision
            decision, source, provenance = await self._ownership_of(exchange, foreign_url)
            if decision == AuthzDecision.UNAUTHORIZED:
                kind_label = "Self-observed" if source == "self_observed" else "Declared"
                return ValidationResult(
                    self.name, "confirmed", "idor", confidence=0.9, confirmed=True,
                    summary=(f"IDOR confirmed: changing the {kind} id {key!r} returned another "
                             f"account's protected object to this session"),
                    evidence=(f"As the captured principal, {exchange.method} with the {kind} id "
                              f"{key!r} set to a foreign value returned a substantive object "
                              f"(HTTP {s_f}) that differs from this principal's own object and a "
                              f"known-absent id (HTTP {s_miss}); the same read without credentials "
                              f"was refused ({denied}). {kind_label} ownership places that object "
                              f"with a different account than this principal's ({provenance}). The "
                              f"other object's contents are redacted; the probe was read-only."))
            if decision == AuthzDecision.AUTHORIZED:
                candidate = candidate or (
                    f"the foreign object belongs to this principal's own account by "
                    f"{source.replace('_', '-')} ownership, so reading it is not a crossing")
                continue
            # V2: the object is protected and this session reads it, but one
            # principal cannot show it belongs to someone else -- unless the run's
            # self-observed ownership (opt-in) and a second identity can.
            if not unready:
                shown, why = await self._two_principal(
                    exchange, foreign_url, b_own, b_f, _object_markers(b_f, b_own, b_miss),
                    anon_headers)
                if shown:
                    return ValidationResult(
                        self.name, "confirmed", "idor", confidence=0.9, confirmed=True,
                        summary=(f"IDOR confirmed: changing the {kind} id {key!r} returned another "
                                 f"account's protected object to this session (two principals)"),
                        evidence=(f"As the captured principal ({shown['a']}), {exchange.method} with the "
                                  f"{kind} id {key!r} set to a foreign value returned a substantive "
                                  f"object (HTTP {s_f}) that differs from this principal's own object "
                                  f"and a known-absent id (HTTP {s_miss}); the same read without "
                                  f"credentials was refused ({denied}). Self-observed ownership, two "
                                  f"principals: the object's owner field {shown['field']} holds the "
                                  f"{shown['kind']} of run identity {shown['b']}'s own account (from "
                                  f"its credentials), whose own session reads the same object (HTTP "
                                  f"{shown['status']}), while this principal's own object carries this "
                                  f"principal's different {shown['kind']} at that field. The other "
                                  f"object's contents and the account values are redacted; the probe "
                                  f"was read-only."))
                two_why = two_why or why
            if not protected:
                protected_at = (s_f, denied)
            protected = protected or "protected"
            if unready:
                break
        if protected:
            s_f, denied = protected_at
            if unready:
                detail = (f"{unready}; an operator declaration of the object's owner "
                          f"(authz.owners) or authz.self_observed_ownership with a second "
                          f"registered identity whose credentials name the owning account would "
                          f"let this leg confirm")
            else:
                detail = (f"the two-principal check found no other run identity owning a protected "
                          f"foreign object: {two_why or 'no owner evidence'}; an operator "
                          f"declaration of the owner (authz.owners) would let this leg confirm")
            protected = (
                f"As the captured principal, {exchange.method} with the {kind} id {key!r} set to a "
                f"foreign value returned a substantive object (HTTP {s_f}) that differs from both "
                f"this principal's own object and a known-absent id (HTTP {s_miss}). The same read "
                f"without credentials was refused ({denied}), so the object is protected. That "
                f"does not show it belongs to another user: this principal may own both objects. "
                f"Missing evidence: a second identity shown to own the object ({detail}), so the "
                f"cross-identity check can show the object's owner and that this principal should "
                f"be denied it (register its session via POST /identities/session-headers), or a "
                f"manual check that the object belongs to another user. The other object's "
                f"contents are redacted; the probe was read-only (no write or delete).")
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
        if failures.failures:
            return failures.result(self.name, "idor", "IDOR foreign reads")
        return ValidationResult(
            self.name, "not_confirmed", "idor", confidence=0.0, confirmed=False,
            summary="No cross-object read: foreign ids were denied or returned no distinct object",
            evidence=f"Tried {len(foreigns)} foreign id(s) on the {kind} id {key!r}; access control held.")
