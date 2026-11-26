"""Session, token and login-flow readers for the auth-sequence validator: moved verbatim out of
auth_sequence_validator.py (ARC-9). Pure functions over captured exchanges and responses;
every send, gate call and scope check stays in the validator module."""

from __future__ import annotations

import httpx
import json
import re
from urllib.parse import urlsplit, parse_qsl

from harness.models import HttpExchange


_USER_KEYS = ("username", "user", "email", "login", "userid", "user_name")
_PASS_KEYS = ("password", "pass", "passwd", "pwd")
_WEAK_PASSWORD = "123456"
# Session-cookie name heuristics.
_SESSION_COOKIE_RE = re.compile(r"sess|sid|token|auth|jwt|sid|phpsessid|connect", re.I)
# A page/redirect that is asking for a SECOND authentication factor (so the session
# that reached it has only completed step 1, username+password).
_MFA_MARKERS = re.compile(
    r"login2|/mfa|/2fa|/otp|verif(?:y|ication)\s*code|security\s*code|authentication\s*code|"
    r"one[\s-]*time\s*(?:code|password)|\botp\b|two[\s-]*factor|multi[\s-]*factor|2fa", re.I)
# Post-authentication resources to probe for reachability before the 2nd factor.
_PROTECTED_CANDIDATES = ("/my-account", "/account", "/dashboard", "/profile", "/home", "/settings")
# A redirect path segment that names a login page (login, sign-in, logon, login.php, ...).
_LOGIN_SEGMENT = re.compile(r"^(?:log[-_]?in|sign[-_]?in|log[-_]?on)\b", re.I)
# A request path that names a logout (logout, log-out, signout, sign_out, logoff).
_LOGOUT_PATH = re.compile(r"log[-_]?out|sign[-_]?out|log[-_]?off", re.I)
# A logout named in a finding class ("not invalidated on log out", "after signout").
_LOGOUT_WORD = re.compile(r"log[\s_-]?out|sign[\s_-]?out|log[\s_-]?off", re.I)


def _authenticated_signal(status: int, body: str, username: str) -> bool:
    """The positive authenticated-page signal shared by the fixation and logout
    legs: a substantive 2xx showing a logout control or the account's username."""
    from harness.missing_auth_probe import _substantive
    low = (body or "").lower()
    return _substantive(status, body or "") and (
        "log out" in low or "logout" in low or bool(username and username in low))


def _logout_requests(body: str, page_url: str) -> list[tuple[str, str, str | None]]:
    """Same-origin logout requests the page itself offers, as (method, url, body):
    a form whose action path names a logout (submitted with its own fields, e.g. a
    CSRF token), then a link whose path does. Never a guessed path: a wrong
    endpoint that leaves the session alive would look like a missing invalidation."""
    from harness.feature_workflow import extract_forms, extract_links
    origin = urlsplit(page_url)

    def same(u):
        return (urlsplit(u).scheme, urlsplit(u).netloc) == (origin.scheme, origin.netloc)

    out = []
    for form in extract_forms(body or "", page_url):
        if same(form.action) and _LOGOUT_PATH.search(urlsplit(form.action).path):
            method = (form.method or "POST").upper()
            out.append((method, form.action, form.body() if method != "GET" else None))
    for link in extract_links(body or "", page_url):
        if same(link) and _LOGOUT_PATH.search(urlsplit(link).path):
            out.append(("GET", link, None))
    return out


def _anonymous_denial(status: int, body: str, location: str) -> str:
    """Describe the anonymous control as an authorization denial, or "" when it
    is not one (E3). Only an answer that says "log in first" counts: 401/403, a
    redirect to a login page, or a 2xx login page. A 5xx, a 404, a rate limit or
    a page that is neither the account nor a login wall says nothing about
    whether the page needs the session (the rule RV-D2 applies to IDOR)."""
    from harness.missing_auth_probe import _LOGIN_PAGE
    if status in (401, 403):
        return f"HTTP {status}"
    if 300 <= status < 400:
        path = urlsplit(location or "").path
        if any(_LOGIN_SEGMENT.match(seg) for seg in path.split("/") if seg):
            return f"HTTP {status} redirect to the login page {location}"
        return ""
    if 200 <= status < 300 and _LOGIN_PAGE.search(body or ""):
        return f"HTTP {status} login page"
    return ""


def _parse_body(exchange: HttpExchange):
    """(fields, kind) where kind is 'json' or 'form'; fields is a mutable dict."""
    body = exchange.request_body or ""
    ctype = " ".join(v for k, v in (exchange.request_headers or {}).items()
                     if k.lower() == "content-type").lower()
    if "json" in ctype or body.strip().startswith("{"):
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                return dict(obj), "json"
        except (ValueError, TypeError):
            pass
    if "=" in body:
        return dict(parse_qsl(body, keep_blank_values=True)), "form"
    return {}, "form"


def _find_key(fields: dict, keys) -> str | None:
    low = {k.lower(): k for k in fields}
    for k in keys:
        if k in low:
            return low[k]
    return None


def _encode(fields: dict, kind: str) -> str:
    if kind == "json":
        return json.dumps(fields)
    from urllib.parse import urlencode
    return urlencode(fields)


def _session_cookies(set_cookie_headers) -> dict:
    """Map of session-ish cookie name -> value from Set-Cookie header(s)."""
    out = {}
    for sc in set_cookie_headers or []:
        first = sc.split(";", 1)[0]
        if "=" in first:
            n, _, v = first.partition("=")
            if _SESSION_COOKIE_RE.search(n):
                out[n.strip()] = v.strip()
    return out


def _is_expiry_class(low: str) -> bool:
    """A session_expiry claim (WSTG-SESS-07): a token that never expires."""
    from harness.categories import canonicalize
    return (canonicalize(low) == "session_expiry" or "session_expiry" in low
            or "session expiry" in low or "exp claim" in low
            or ("never expire" in low and any(w in low for w in ("token", "session", "jwt"))))


def _session_jwts(exchange, ctx) -> list[tuple[str, list[str], bool]]:
    """(where, claim names, never_expires) for each distinct session JWT the run
    already holds: the captured login response's token, the captured request's
    identity credential headers, then the run identities' credential headers.
    `where` names the place, never the value."""
    from types import SimpleNamespace
    from harness.security import is_identity_credential_header
    from .jwt_forge_validator import _JWT_RE, _decode
    candidates: list[tuple[str, str]] = []
    status = exchange.response_status or 0
    if 200 <= status < 300 and exchange.response_body:
        resp = SimpleNamespace(text=exchange.response_body,
                               headers=httpx.Headers(exchange.response_headers or {}))
        minted = _login_token(resp)
        if minted is not None:
            candidates.append((f"the captured response's {minted[0]}", minted[1]))
    for name, value in (exchange.request_headers or {}).items():
        if is_identity_credential_header(name):
            for match in _JWT_RE.finditer(value or ""):
                candidates.append((f"the captured request's {name} header", match.group(1)))
    sessions = getattr(ctx, "sessions", None)
    for session in (sessions.identities() if sessions is not None else []):
        for name, value in (session.headers or {}).items():
            if is_identity_credential_header(name):
                for match in _JWT_RE.finditer(value or ""):
                    label = session.name or session.principal_id or session.session_id
                    candidates.append((f"run identity {label!r}'s {name} header",
                                       match.group(1)))
    out, seen = [], set()
    for where, token in candidates:
        decoded = _decode(token)
        if decoded is None or token in seen:
            continue
        seen.add(token)
        _lifetime, never = _token_lifetime(token)
        payload = decoded[1]
        claims = sorted(str(k) for k in payload)[:12] if isinstance(payload, dict) else []
        out.append((where, claims, never))
    return out


def _is_logout_class(low: str) -> bool:
    """A session_timeout / logout-invalidation claim (WSTG-SESS-06)."""
    from harness.categories import canonicalize
    # Not a bare "logout": a different claim about the logout endpoint (CSRF on
    # the logout form, say) must not borrow this check's confirmation. Nor a bare
    # "not invalidated": a reset token or a session kept after a password change
    # is a different claim; it counts only when it names a logout.
    return (canonicalize(low) == "session_timeout" or "session_timeout" in low
            or "session timeout" in low or "logout invalidation" in low
            or "logout_invalidation" in low
            or ("not invalidated" in low and bool(_LOGOUT_WORD.search(low))))


# --- bearer-token sessions ------------------------------------------------------
# A login that sets no session cookie may hand the client a token in its body
# (an SPA keeps it in storage and sends it as a bearer header or a cookie the
# script sets). These helpers find it, learn how the run's own identities carry
# such a token, and find a read that only that token authorizes. Token values
# never reach a summary, evidence or raw_output.
_TOKEN_FIELD = re.compile(
    r"^(?:access[_-]?token|id[_-]?token|auth[_-]?token|session[_-]?token|token|jwt|bearer|"
    r"accesstoken|idtoken|authtoken|sessiontoken)$", re.I)
_TOKEN_RESPONSE_HEADERS = ("x-auth-token", "x-access-token", "x-session-token")
# Same-directory and parent-directory reads of the caller's own account.
_SELF_READ_NAMES = ("whoami", "me", "profile", "userinfo", "account", "current", "current-user",
                    "session")
_GENERIC_SELF_READS = ("/api/me", "/me", "/userinfo", "/whoami", "/api/user", "/api/profile",
                       "/api/account")
_SELF_ROUTE = re.compile(r"(?:^|/)(?:whoami|me|profile|userinfo|account|current[-_]?user|session)"
                         r"(?:/|$)", re.I)
# A server-side logout or token revocation, as a route the run observed.
_REVOKE_PATH = re.compile(r"log[-_]?out|sign[-_]?out|log[-_]?off|revoc|revok", re.I)
_MAX_TOKEN_READS = 20
_IDENTIFIER_CLAIMS = ("email", "username", "preferred_username", "upn", "login", "user_name",
                      "mail")


def _json_doc(text):
    try:
        return json.loads(text or "")
    except (ValueError, TypeError):
        return None


def _walk_json(doc, depth: int = 3):
    """(key, value) pairs of a JSON document's nested objects, `depth` levels deep."""
    stack = [(doc, 0)]
    while stack:
        node, level = stack.pop()
        if level > depth:
            continue
        if isinstance(node, dict):
            for k, v in node.items():
                yield str(k), v
                if isinstance(v, (dict, list)):
                    stack.append((v, level + 1))
        elif isinstance(node, list):
            for v in node[:50]:
                if isinstance(v, (dict, list)):
                    stack.append((v, level + 1))


def _login_token(resp) -> tuple[str, str] | None:
    """(where, token): a bearer token the login response hands the client -- a JWT
    or a token-named string in its JSON body, or a token response header. A cookie
    is not one (that is the cookie path). `where` names the field, never the value."""
    from .jwt_forge_validator import _JWT_RE
    doc = _json_doc(getattr(resp, "text", "") or "")
    if isinstance(doc, (dict, list)):
        named = None
        for key, value in _walk_json(doc):
            if not isinstance(value, str):
                continue
            if _JWT_RE.fullmatch(value.strip()):
                return f"the JSON field {key!r} (a JWT)", value.strip()
            if named is None and _TOKEN_FIELD.match(key) and len(value) >= 16 and " " not in value:
                named = (f"the JSON field {key!r}", value)
        if named:
            return named
    headers = getattr(resp, "headers", {}) or {}
    for name in _TOKEN_RESPONSE_HEADERS:
        value = (headers.get(name) or "").strip()
        if len(value) >= 16:
            return f"the {name} response header", value
    auth = (headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer ") and len(auth) > 23:
        return "the Authorization response header", auth[7:].strip()
    return None


def _token_lifetime(token: str) -> tuple[str, bool]:
    """(description, never_expires) of a token, read from a JWT's exp/iat claims."""
    from .jwt_forge_validator import _decode
    decoded = _decode(token)
    if decoded is None:
        return "an opaque token (lifetime not visible)", False
    payload = decoded[1]
    exp, iat = payload.get("exp"), payload.get("iat")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return "a JWT with no exp claim, so it never expires", True
    if isinstance(iat, (int, float)) and not isinstance(iat, bool) and exp > iat:
        minutes = int((exp - iat) // 60)
        span = f"{minutes // 1440} day(s)" if minutes >= 2880 else (
            f"{minutes // 60} hour(s)" if minutes >= 120 else f"{minutes} minute(s)")
        return f"a JWT valid for {span}", False
    return "a JWT with an exp claim", False


def _claim_identifiers(payload, depth: int = 2) -> set[str]:
    """Lower-cased account identifiers (email, username) in a JWT payload,
    including one nested user object ({"data": {...}}, {"user": {...}})."""
    out = set()
    for key, value in _walk_json(payload, depth):
        if not isinstance(value, str) or not value.strip():
            continue
        low = key.lower()
        if low in _IDENTIFIER_CLAIMS or (low == "sub" and "@" in value):
            out.add(value.strip().lower())
    return out


def _token_identifiers(token: str) -> set[str]:
    from .jwt_forge_validator import _decode
    decoded = _decode(token or "")
    return _claim_identifiers(decoded[1]) if decoded else set()


def _identity_identifiers(ctx) -> set[str]:
    """Lower-cased account identifiers the run's own identities carry in their
    JWT claims: accounts the operator registered, so they exist."""
    from harness.security import is_identity_credential_header
    from .jwt_forge_validator import _JWT_RE
    out: set[str] = set()
    sessions = getattr(ctx, "sessions", None)
    if sessions is None:
        return out
    for session in sessions.identities():
        for name, value in (session.headers or {}).items():
            if is_identity_credential_header(name):
                for match in _JWT_RE.finditer(value or ""):
                    out |= _token_identifiers(match.group(1))
    return out


def _token_carriers(ctx, exchange) -> list[tuple[str, str]]:
    """How this app's tokens are sent, as (header, template) with "{}" for the
    token: learned from the run identities' and the captured request's credential
    headers ("Authorization: Bearer {}", "Cookie: token={}"), plus the standard
    bearer header. Never another invented carrier."""
    from harness.security import is_identity_credential_header
    from .jwt_forge_validator import _JWT_RE
    sources = []
    sessions = getattr(ctx, "sessions", None)
    if sessions is not None:
        sources += [s.headers or {} for s in sessions.identities()]
    sources.append(exchange.request_headers or {})
    out: list[tuple[str, str]] = []
    for headers in sources:
        for name, value in headers.items():
            if not is_identity_credential_header(name):
                continue
            match = _JWT_RE.search(value or "")
            if not match:
                continue
            template = value
            if name.lower() == "cookie":
                template = next((part.strip() for part in value.split(";")
                                 if match.group(1) in part), value)
            template = template.replace(match.group(1), "{}")
            canonical = ("Authorization" if name.lower() == "authorization"
                         else "Cookie" if name.lower() == "cookie" else name)
            if (canonical, template) not in out:
                out.append((canonical, template))
    if not any(n == "Authorization" and t.lower().startswith("bearer ") for n, t in out):
        out.insert(0, ("Authorization", "Bearer {}"))
    out.sort(key=lambda c: c[0] != "Authorization")
    return out[:4]


def _carry(headers: dict, carrier: tuple[str, str], token: str) -> dict:
    name, template = carrier
    return dict(headers, **{name: template.replace("{}", token)})


def _carrier_label(carrier: tuple[str, str]) -> str:
    name, template = carrier
    return f"{name}: {template.replace('{}', '<token>')}"


def _shows_account(resp, identifiers: set[str]) -> bool:
    """A 2xx whose body names the account (its email or username)."""
    if resp is None or not 200 <= resp.status_code < 300:
        return False
    low = (resp.text or "").lower()
    return any(i and i in low for i in identifiers)


def _token_denial(resp, identifiers: set[str]) -> str:
    """The anonymous (or revoked-token) answer as a denial of the account read, or
    "": 401/403, a login wall, or a 2xx that no longer names the account. A 5xx,
    a 404 or a rate limit says nothing."""
    denial = _anonymous_denial(resp.status_code, resp.text or "", resp.headers.get("location") or "")
    if denial:
        return denial
    if 200 <= resp.status_code < 300 and not _shows_account(resp, identifiers):
        return f"HTTP {resp.status_code} without the account's identifier"
    return ""


def _self_read_urls(exchange, ctx) -> list[str]:
    """Candidate reads of the caller's own account, most specific first: the run
    identities' GET health probes, self routes the run's crawl saw the app call,
    then same-directory and parent-directory account reads beside the login."""
    p = urlsplit(exchange.url)
    origin = f"{p.scheme}://{p.netloc}"
    urls: list[str] = []
    sessions = getattr(ctx, "sessions", None)
    for session in (sessions.identities() if sessions is not None else []):
        probe = getattr(session, "_probe", None)
        if probe is not None and (probe.method or "GET").upper() == "GET":
            q = urlsplit(probe.url or "")
            if (q.scheme, q.netloc) == (p.scheme, p.netloc):
                urls.append(probe.url)
    routes = getattr(ctx, "client_routes", None)
    for table in (getattr(routes, "api_links", None) or {}, getattr(routes, "api_views", None) or {}):
        for key in list(table)[:200]:
            method, _, path = str(key).partition(" ")
            if (method.upper() == "GET" and path.startswith("/") and _SELF_ROUTE.search(path)
                    and "{" not in path and ":" not in path):
                urls.append(origin + path)
    segs = [s for s in p.path.split("/") if s]
    parents = ["/" + "/".join(segs[:-1]) if len(segs) > 1 else "",
               "/" + "/".join(segs[:-2]) if len(segs) > 2 else ""]
    first = [(parent, name) for parent in parents for name in _SELF_READ_NAMES[:3]]
    rest = [(parent, name) for parent in parents for name in _SELF_READ_NAMES[3:]]
    urls += [f"{origin}{parent}/{name}" for parent, name in first]
    urls += [origin + path for path in _GENERIC_SELF_READS]
    urls += [f"{origin}{parent}/{name}" for parent, name in rest]
    urls += [origin + path for path in _PROTECTED_CANDIDATES]
    seen, out = set(), []
    for url in urls:
        if url not in seen and url != exchange.url:
            seen.add(url)
            out.append(url)
    return out


def _revocation_routes(bodies, exchange, ctx) -> list[tuple[str, str, str | None, str]]:
    """Same-origin server-side logout / token-revocation requests the run itself
    observed, as (method, url, body, where): a logout form or link in a fetched
    page, a logout/revocation path named in a JSON response, or a non-read API
    call the crawl saw the app make. Never a guessed path."""
    p = urlsplit(exchange.url)
    origin = f"{p.scheme}://{p.netloc}"
    out: list[tuple[str, str, str | None, str]] = []
    for text, url in bodies:
        for method, target, body in _logout_requests(text or "", url):
            out.append((method, target, body, f"a logout control on {urlsplit(url).path}"))
        doc = _json_doc(text)
        if isinstance(doc, (dict, list)):
            for key, value in _walk_json(doc, 4):
                if not isinstance(value, str) or len(value) > 300:
                    continue
                q = urlsplit(value)
                path = q.path if (q.scheme, q.netloc) in (("", ""), (p.scheme, p.netloc)) else ""
                if path.startswith("/") and _REVOKE_PATH.search(path):
                    out.append(("POST", origin + path, None,
                                f"named by the JSON field {key!r} of {urlsplit(url).path}"))
    routes = getattr(ctx, "client_routes", None)
    for table in (getattr(routes, "api_links", None) or {}, getattr(routes, "api_views", None) or {}):
        for key in list(table)[:500]:
            method, _, path = str(key).partition(" ")
            method = method.upper()
            if not path.startswith("/") or "{" in path or not _REVOKE_PATH.search(path):
                continue
            if method == "GET" and not _LOGOUT_PATH.search(path):
                continue  # a GET that reads a revocation list does not revoke
            out.append((method or "POST", origin + path, None, "an API call the crawled app made"))
    seen, unique = set(), []
    for row in out:
        if (row[0], row[1]) not in seen:
            seen.add((row[0], row[1]))
            unique.append(row)
    return unique


# R11-8 (c): the summary the recovery-lookup shape leg gives its finding.
RECOVERY_LOOKUP_SHAPE = "account identifier in the query"


def is_recovery_lookup_leg(finding) -> bool:
    """True for a finding the R11-8 (c) recovery-lookup paths raised: the shape
    leg (its summary names RECOVERY_LOOKUP_SHAPE) or the coverage drive, whose
    derived finding carries only its class (summary == class, no evidence). An
    agent's finding carries its own summary and keeps the older behaviour."""
    if getattr(finding, "basis", "") != "derived":
        return False
    summary = (getattr(finding, "summary", "") or "").strip()
    return (RECOVERY_LOOKUP_SHAPE in summary
            or (summary == (finding.vulnerability_class or "").strip()
                and not (getattr(finding, "evidence", "") or "").strip()))


def _query_identifier(exchange) -> tuple[str, str] | None:
    """(name, value) of a username/email query parameter, e.g. a lookup such as
    GET /account/question?email=..."""
    pairs = parse_qsl(urlsplit(exchange.url or "").query, keep_blank_values=True)
    names = {k.lower(): (k, v) for k, v in pairs}
    for key in _USER_KEYS:
        if key in names:
            return names[key]
    return None


def _with_query_value(url: str, name: str, value: str) -> str:
    from urllib.parse import urlencode, urlunsplit
    parts = urlsplit(url)
    pairs = [(k, value if k == name else v)
             for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))
