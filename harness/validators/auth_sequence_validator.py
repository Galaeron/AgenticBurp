"""
Stateful authentication-mechanism confirmation legs.

The auth-family bugs (broken authentication, OWASP A07) can't be confirmed by the
single-request replay-and-diff shape -- each needs a multi-request FLOW with a
state boundary. This leg confirms the three that have a clean, deterministic
oracle, dispatched by the finding's class:

  - session_fixation      -- the session identifier does NOT change across a
                             SUCCESSFUL login and that pre-auth id alone then
                             reaches an authenticated page an anonymous request
                             cannot (an unrotated id without that proof, or after
                             a failed login, is only a candidate).
  - weak_password_policy   -- a trivially weak password is ACCEPTED at registration
                             (throwaway account), i.e. no strength policy.
  - username_enumeration   -- a login/reset response DISCRIMINATES a valid account
                             from an invalid one (after masking the echoed username),
                             leaking which usernames exist.
  - session_timeout        -- logout invalidation (WSTG-SESS-06): a FRESH
                             throwaway login's session reaches an authenticated
                             page (anonymous denied), the page's own logout
                             request is sent on that session, and the SAME
                             pre-logout cookie still reaches the page -- the
                             server never invalidated it. The operator's
                             captured session is never sent to the logout.

Credentials/usernames come from the captured request itself (a login/register
body), so no tester input is needed. All sends route through the safety gate and,
being POSTs, need validators.allow_mutating_replay. Precision is preserved with
matched controls in the fixture (rotating session / policy-enforcing register /
uniform error message), which this leg leaves un-confirmed.

Out of scope here (need an operator decision, see AUTH_LEGS_DECISIONS in
CURRENT_STATE): rate-limit absence (how many attempts constitute "no limit" vs the
gate's mutating-burst ceiling) and reset-token entropy (what entropy threshold /
sample size counts as "predictable").
"""
from __future__ import annotations
from harness import scope_lock

import json
import re
import secrets
from urllib.parse import urlsplit, parse_qsl

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult

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


class AuthSequenceValidator(Validator):
    name = "auth_sequence"
    finding_classes = {
        "session_fixation", "session fixation",
        "weak_password", "weak password", "weak password policy", "weak_password_policy",
        "username_enumeration", "username enumeration", "user enumeration", "user_enumeration",
        "account enumeration",
        "2fa_bypass", "2fa bypass", "mfa_bypass", "mfa bypass", "two_factor_bypass",
        "two-factor bypass", "multi_factor_bypass", "second factor bypass",
        "broken_authentication", "broken authentication", "authentication",
        "session_timeout", "session timeout", "logout_invalidation", "logout invalidation",
        "session not invalidated",
    }
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 confirm_lookup: bool = False):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        # R11-8 (c): a GET lookup reached by the NEW recovery-lookup paths (the
        # shape leg, or the coverage drive's IDNT-04 GET cell) that discriminates a
        # run identity's account from an unknown one is a labelled LEAD until the
        # owner signs off (validators.auth_sequence.confirm_lookup). The older
        # agent-finding path (ed91ca34) keeps confirming, as before.
        self.confirm_lookup = bool(confirm_lookup)

    def _skip(self, why: str, fc="broken_authentication") -> ValidationResult:
        return ValidationResult(self.name, "skipped", fc, summary=why)

    def _not(self, why: str, fc) -> ValidationResult:
        return ValidationResult(self.name, "not_confirmed", fc, confidence=0.0, confirmed=False, summary=why)

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        if self._which_checks(finding.vulnerability_class, exchange) == ["logout"]:
            # Any exchange: validate() mints its own throwaway login from a
            # captured login, or reports why it cannot without sending anything.
            return True
        if (exchange.method or "").upper() not in ("POST", "PUT"):
            # A lookup that takes the account identifier in its query (GET
            # ...?email=) can be an enumeration oracle; no other check reads a GET.
            return (self._which_checks(finding.vulnerability_class, exchange) == ["enum"]
                    and _query_identifier(exchange) is not None)
        fields, _ = _parse_body(exchange)
        return _find_key(fields, _PASS_KEYS) is not None or _find_key(fields, _USER_KEYS) is not None

    def _headers(self, exchange, extra: dict | None = None) -> dict:
        h = {k: v for k, v in (exchange.request_headers or {}).items()
             if k.lower() not in ("content-length", "host", "cookie")}
        h.setdefault("Content-Type", "application/json")
        if extra:
            h.update(extra)
        return h

    def _which_checks(self, vc: str, exchange: HttpExchange) -> list[str]:
        """Return the ordered list of sub-checks to run. For a specific class
        (e.g. "username_enumeration"), returns just that one. For a genuine
        generic label containing "authentication" (e.g. "broken_authentication",
        "Broken Authentication"), returns ALL applicable checks so we don't
        miss a confirmable finding just because the LLM used a vague label.

        Any OTHER unrecognized class returns NO checks. This matters because
        registry.ValidatorRegistry.for_finding / orchestrator_confirm.
        _validate_findings route a finding here not just by its own class but
        also, as a fallback, by substituting the bare PRODUCING-AGENT name
        ("auth") as a stand-in vulnerability_class when the finding's real
        class matches no validator directly. That fallback is reachable for
        ANY auth-family finding, including ones (e.g. cleartext_transmission)
        this validator has no check for at all. "auth" does not contain
        "authentication", so it correctly falls through to no-checks here
        instead of running an unrelated check and mislabelling its result as
        evidence for that unrelated claim -- the reproduced false-confirmation
        bug in REPORT_2026-10-15_decisive_reproducibility.md (6/30 findings
        per run carried a confirmed username-enumeration result that was
        evidence for a completely different claim)."""
        low = (vc or "").strip().lower()
        if "fixation" in low:
            return ["fixation"]
        if "weak" in low or "password polic" in low:
            return ["weak"]
        if "enum" in low:
            return ["enum"]
        if _is_logout_class(low):
            return ["logout"]
        if "2fa" in low or "mfa" in low or "two" in low or "multi" in low or "second factor" in low:
            return ["mfa"]
        if "authentication" not in low:
            return []
        if (exchange.method or "").upper() not in ("POST", "PUT"):
            # A read is no login: only an identifier-in-query lookup is checked.
            return ["enum"] if _query_identifier(exchange) is not None else []
        path = urlsplit(exchange.url).path.lower()
        fields, _ = _parse_body(exchange)
        checks = []
        is_register = "regist" in path or "signup" in path or "sign-up" in path
        if is_register:
            checks.append("weak")
        else:
            checks.append("fixation")
            if _find_key(fields, _USER_KEYS):
                checks.append("enum")
            # A password present + a login (not register) flow may gate a 2nd factor.
            if _find_key(fields, _PASS_KEYS):
                checks.append("mfa")
        return checks

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {host!r} out of scope")
        if not get_default_gate().config.allow_mutating_replay:
            return self._skip("auth-mechanism probes send POSTs; need validators.allow_mutating_replay")
        checks = self._which_checks(finding.vulnerability_class, exchange)
        if not checks:
            return self._skip(
                "no auth_sequence check applies to this finding's class",
                finding.vulnerability_class or "broken_authentication")
        last_result = None
        try:
            for check in checks:
                if check == "fixation":
                    result = await self._check_session_fixation(exchange)
                elif check == "weak":
                    result = await self._check_weak_password(exchange)
                elif check == "mfa":
                    result = await self._check_mfa_bypass(exchange)
                elif check == "logout":
                    result = await self._check_logout_invalidation(exchange)
                else:
                    result = await self._check_username_enum(
                        exchange, new_lookup_leg=is_recovery_lookup_leg(finding))
                if result.confirmed:
                    return result
                last_result = result
        except SafetyGateBlocked:
            return self._skip("mutating auth replay not authorized (validators.allow_mutating_replay)")
        except httpx.HTTPError as e:
            return self._skip(f"request failed: {e.__class__.__name__}")
        return last_result or self._not("no auth-mechanism issue confirmed", "broken_authentication")

    async def _send(self, client, method, url, headers, body):
        await global_throttle.acquire()
        return await client.request(method, url, headers=headers or None, content=body or None)

    # --- session fixation -----------------------------------------------------
    async def _check_session_fixation(self, exchange) -> ValidationResult:
        """R20: a pre-login cookie that was not rotated is only a candidate. The
        login must succeed, and the fixed identifier ALONE (no other cookie, no
        captured credential header) must then reach an authenticated page that
        an anonymous request is denied (E3: a healthy denial, not a 5xx or a
        timeout) -- the planted id is now a logged-in session. Rotation of
        every pre-login cookie is the negative."""
        fc = "session_fixation"
        method = (exchange.method or "POST").upper()
        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as client:
            # 1. establish a pre-auth session by hitting the origin root.
            root = f"{urlsplit(exchange.url).scheme}://{urlsplit(exchange.url).netloc}/"
            try:
                pre = await self._send(client, "GET", root, self._headers(exchange), None)
            except httpx.HTTPError:
                pre = None
            pre_cookies = _session_cookies(pre.headers.get_list("set-cookie")) if pre is not None else {}
            # 2. log in, presenting the pre-auth session cookie if we got one.
            extra = {}
            if pre_cookies:
                extra["Cookie"] = "; ".join(f"{n}={v}" for n, v in pre_cookies.items())
            resp = await self._send(client, method, exchange.url, self._headers(exchange, extra),
                                    exchange.request_body)
            post_cookies = _session_cookies(resp.headers.get_list("set-cookie"))
        if not pre_cookies and not post_cookies:
            minted = _login_token(resp) if resp.status_code < 400 else None
            if minted is None:
                return self._not("no session cookie issued (token-based auth?) -- fixation N/A", fc)
            where, token = minted
            # A token the client already held before logging in -- in the
            # captured login's own credential headers or handed out by the
            # pre-login page -- that the login returns unchanged is the token
            # analogue of an unrotated session id.
            from harness.security import is_identity_credential_header
            held = " ".join(v for k, v in (exchange.request_headers or {}).items()
                            if is_identity_credential_header(k))
            if pre is not None:
                held += " " + (pre.text or "")[:200000] + " " + " ".join(
                    v for k, v in pre.headers.items() if k.lower() in _TOKEN_RESPONSE_HEADERS)
            if token in held:
                return self._candidate(
                    f"the login returned, in {where}, the same token the client presented or was "
                    f"given before authenticating",
                    f"Login answered HTTP {resp.status_code} with no session cookie; its token equals "
                    f"one the client held before the login (value redacted), so a planted pre-login "
                    f"token may become the logged-in one. Not confirmed: whether that token alone "
                    f"reaches an authenticated read was not shown.")
            return self._not(
                f"no session cookie: the login mints a bearer token in {where} (HTTP "
                f"{resp.status_code}); a token created by the login itself cannot be planted "
                f"beforehand -- session fixation N/A", fc)
        # Pre-auth cookies that survive login: re-issued unchanged, or not replaced.
        fixed = {n: v for n, v in pre_cookies.items() if post_cookies.get(n, v) == v}
        if not fixed:
            return self._not("session id rotated on login (no fixation)", fc)
        names = ", ".join(sorted(fixed))
        if resp.status_code >= 400:
            return self._candidate(
                f"pre-login session cookie ({names}) was not rotated, but the login itself failed "
                f"(HTTP {resp.status_code})",
                f"No authenticated session was established, so an unrotated pre-login id proves "
                f"nothing about fixation. Retry with working credentials.")
        proof, failed_control = await self._fixed_id_authenticates(exchange, resp, fixed)
        if proof is None and failed_control:
            return self._candidate(
                f"pre-login session cookie ({names}) survived login and alone reached an authenticated "
                f"page, but the anonymous control was not a healthy denial",
                f"Login answered HTTP {resp.status_code}. Presenting only the fixed {names} reached a page "
                f"showing an authenticated session, but {failed_control}, so the page was not shown to "
                f"need the session. A 5xx, a timeout or a transport error is not an authorization "
                f"denial; retry when the target answers normally.")
        if proof is None:
            return self._candidate(
                f"pre-login session cookie ({names}) was not rotated across login, but that id alone "
                f"never reached an authenticated page",
                f"Login answered HTTP {resp.status_code}. Presenting only the fixed {names} reached no "
                f"page showing an authenticated session (a logout control or the account's username) "
                f"that an anonymous request is denied, so the fixed id is not shown to carry the login.")
        url, status, denial, fixed_read, anon_read = proof
        return ValidationResult(
            self.name, "confirmed", fc, confidence=0.9, confirmed=True,
            summary=f"Session fixation confirmed: the pre-login {names} survived login and alone "
                    f"reaches the authenticated {urlsplit(url).path}.",
            evidence=f"Pre-auth {names} was not rotated by a successful login (HTTP {resp.status_code}). "
                     f"GET {url} with only that cookie returned an authenticated page (HTTP {status}, a "
                     f"logout control or the account's username), while the same request with no session "
                     f"was denied ({denial}): an attacker-planted id becomes a logged-in session."
        # Ticket 6: the login that kept the id (baseline), the fixed id alone reaching
        # the page (attack), and the same page denied with no session (control).
        ).with_artifacts(baseline=resp, attack=fixed_read, controls=[anon_read])

    def _candidate(self, why: str, evidence: str, fc: str = "session_fixation") -> ValidationResult:
        return ValidationResult(self.name, "inconclusive", fc, confidence=0.4, confirmed=False,
                                summary=f"Candidate only, not confirmed: {why}.", evidence=evidence)

    async def _fixed_id_authenticates(self, exchange, login_resp, fixed: dict
                                      ) -> tuple[tuple | None, str]:
        """GET-only proof that the fixed cookie(s) carry the login: the login's
        same-origin redirect target, then common account pages, each fetched in
        a fresh client with only the fixed cookie, and an anonymous control.
        Returns ((url, status, denial, fixed-id response, anonymous response), "")
        on proof, else (None, why the first failed anonymous control did not
        count, or "")."""
        from urllib.parse import urljoin
        fields, _ = _parse_body(exchange)
        ukey = _find_key(fields, _USER_KEYS)
        username = str(fields.get(ukey) or "").strip().lower() if ukey else ""
        p = urlsplit(exchange.url)
        origin = f"{p.scheme}://{p.netloc}"
        targets = []
        loc = login_resp.headers.get("location") or ""
        if loc:
            target = urljoin(exchange.url, loc)
            if urlsplit(target).netloc == p.netloc and urlsplit(target).scheme == p.scheme:
                targets.append(target)
        targets += [origin + path for path in _PROTECTED_CANDIDATES]
        headers = self._page_headers(exchange)

        def authed(status, body):
            return _authenticated_signal(status, body, username)

        seen, failed = set(), ""
        for url in targets:
            if url in seen:
                continue
            seen.add(url)
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as fixed_client:
                try:
                    got = await self._send(fixed_client, "GET", url, dict(
                        headers, Cookie="; ".join(f"{n}={v}" for n, v in fixed.items())), None)
                except httpx.HTTPError:
                    continue
            if not authed(got.status_code, got.text):
                continue
            # E3: a timeout or an HTTP 500 is not the anonymous request being
            # denied. Only a completed, interpretable denial shows the page needs
            # the session.
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as anon:
                try:
                    anon_got = await self._send(anon, "GET", url, dict(headers), None)
                except httpx.HTTPError as e:
                    failed = failed or f"the anonymous control GET {url} failed ({type(e).__name__})"
                    continue
            if authed(anon_got.status_code, anon_got.text):
                continue  # the same page with no session: public, not the fixed id
            denial = _anonymous_denial(anon_got.status_code, anon_got.text or "",
                                       anon_got.headers.get("location") or "")
            if denial:
                return (url, got.status_code, denial, got, anon_got), ""
            failed = failed or (
                f"the anonymous control GET {url} answered HTTP {anon_got.status_code}, which is not an "
                f"authorization denial (only 401/403, a redirect to a login page or a login page is)")
        return None, failed

    def _page_headers(self, exchange) -> dict:
        """Captured headers for a GET of an account page: no credential header
        (the session under test is supplied explicitly) and no Content-Type."""
        from harness.missing_auth_probe import _AUTH_HEADERS
        return {k: v for k, v in self._headers(exchange).items()
                if k.lower() not in _AUTH_HEADERS and k.lower() != "content-type"}

    # --- logout invalidation (session_timeout, WSTG-SESS-06) ------------------
    async def _check_logout_invalidation(self, exchange) -> ValidationResult:
        """A logout that only clears the cookie client-side leaves the session
        valid on the server. Proof, all on a FRESH throwaway login (the
        operator's captured session is never sent, so the tester is not logged
        out): (a) the fresh session alone reaches an authenticated page that an
        anonymous request is denied; (b) the page's own logout request is sent
        on that session; (c) the same pre-logout cookie(s) are replayed against
        the page. Confirmed only when (a) held and (c) still shows the
        authenticated signal; (c) denied or redirected to login is the negative.
        Every send goes through the gate; validate() already requires
        validators.allow_mutating_replay, which covers the logout even as a GET.
        Idle/absolute timeout (WSTG-SESS-07) needs long waits: out of scope."""
        fc = "session_timeout"
        steps: list[dict] = []

        def done(status, summary, evidence="", confidence=0.0):
            return ValidationResult(
                self.name, status, fc, confidence=confidence, confirmed=status == "confirmed",
                summary=summary, evidence=evidence or summary,
                raw_output=json.dumps({"check": "logout_invalidation", "steps": steps}))

        method = (exchange.method or "").upper()
        fields, _ = _parse_body(exchange)
        if method not in ("POST", "PUT") or not (_find_key(fields, _PASS_KEYS)
                                                and _find_key(fields, _USER_KEYS)):
            steps.append({"step": "fresh_session", "status": "unavailable"})
            return done("skipped",
                        "Logout invalidation not tested: no captured login to mint a fresh throwaway "
                        "session, and the captured session is never sent to a logout (that would log "
                        "the tester out). Nothing was sent.",
                        f"The finding's exchange ({method or '?'} {urlsplit(exchange.url).path}) is not a "
                        f"username+password login. Re-run on the captured login request.")

        # 1. Fresh throwaway login (_headers never forwards the captured Cookie).
        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as client:
            body = await self._refresh_login_body(client, exchange)
            login = await self._send(client, method, exchange.url, self._headers(exchange), body)
        fresh = _session_cookies(login.headers.get_list("set-cookie"))
        steps.append({"step": "fresh_login", "status": login.status_code, "cookies": sorted(fresh)})
        if login.status_code < 400 and not fresh:
            minted = _login_token(login)
            if minted is not None:
                steps[-1]["token"] = minted[0]
                return await self._token_logout(exchange, login, minted, steps, done)
        if login.status_code >= 400 or not fresh:
            return done("inconclusive",
                        "Logout invalidation not tested: the fresh login issued no session cookie "
                        f"(HTTP {login.status_code}), so there is no throwaway session to log out. "
                        "Nothing was sent to a logout.")
        names = ", ".join(sorted(fresh))
        cookie = "; ".join(f"{n}={v}" for n, v in fresh.items())

        # 2. (a) The fresh session reaches an authenticated page; anonymous is denied.
        proof, failed = await self._fixed_id_authenticates(exchange, login, fresh)
        if proof is None:
            steps.append({"step": "authenticated_before_logout", "status": "unproven"})
            return done("inconclusive",
                        f"Logout invalidation not tested: the fresh session ({names}) reached no "
                        f"authenticated page that an anonymous request is denied"
                        + (f" ({failed})" if failed else "") + ". Nothing was sent to a logout.")
        # The proven page's response carries the logout control step 3 reads.
        page, status_a, denial_a, page_resp, _anon = proof
        steps.append({"step": "authenticated_before_logout", "url": page, "status": status_a,
                      "anonymous": denial_a})

        # 3. The logout request the page (or the captured login response) offers.
        offered = (_logout_requests(page_resp.text or "", page)
                   or _logout_requests(exchange.response_body or "", exchange.url))
        if not offered:
            steps.append({"step": "logout_request", "status": "not_found"})
            return done("inconclusive",
                        f"Logout invalidation not tested: {urlsplit(page).path} offers no same-origin "
                        f"logout link or form, and no logout path is guessed. Nothing was sent to a "
                        f"logout.")
        lo_method, lo_url, lo_body = offered[0]
        headers = self._page_headers(exchange)

        # 4. (b) Log the FRESH session out.
        lo_headers = dict(headers, Cookie=cookie)
        if lo_body is not None:
            lo_headers["Content-Type"] = "application/x-www-form-urlencoded"
        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as lo_client:
            logout = await self._send(lo_client, lo_method, lo_url, lo_headers, lo_body)
        steps.append({"step": "logout", "method": lo_method, "url": lo_url,
                      "status": logout.status_code})
        if logout.status_code >= 400:
            return done("inconclusive",
                        f"Logout invalidation not tested: {lo_method} {urlsplit(lo_url).path} answered "
                        f"HTTP {logout.status_code}, so the logout itself did not complete.")
        if 200 <= logout.status_code < 300 and _logout_requests(logout.text or "", lo_url):
            return done("inconclusive",
                        f"Logout invalidation not tested: {lo_method} {urlsplit(lo_url).path} answered "
                        f"with another logout control (a confirmation step?), so the logout is not "
                        f"shown to have run.")

        # 5. (c) Replay the authenticated request with the same pre-logout cookie(s).
        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as replay_client:
            after = await self._send(replay_client, "GET", page, dict(headers, Cookie=cookie), None)
        ukey = _find_key(fields, _USER_KEYS)
        username = str(fields.get(ukey) or "").strip().lower() if ukey else ""
        authed_after = _authenticated_signal(after.status_code, after.text or "", username)
        steps.append({"step": "replay_after_logout", "url": page, "status": after.status_code,
                      "authenticated": authed_after})
        if authed_after:
            return done(
                "confirmed",
                f"Logout invalidation missing: the pre-logout {names} still reaches the authenticated "
                f"{urlsplit(page).path} after {lo_method} {urlsplit(lo_url).path}.",
                f"A fresh login's {names} alone reached {page} (HTTP {status_a}, a logout control or "
                f"the account's username) while the same request with no session was denied "
                f"({denial_a}). After {lo_method} {lo_url} on that session (HTTP {logout.status_code}), "
                f"replaying {page} with the same pre-logout cookie still returned the authenticated "
                f"page (HTTP {after.status_code}): logout does not invalidate the session server-side.",
                confidence=0.9)
        denial_c = _anonymous_denial(after.status_code, after.text or "",
                                     after.headers.get("location") or "")
        if denial_c:
            return done("not_confirmed",
                        f"Session invalidated on logout: after {lo_method} {urlsplit(lo_url).path} the "
                        f"pre-logout {names} is denied ({denial_c}).")
        return done("inconclusive",
                    f"Logout invalidation unproven: after {lo_method} {urlsplit(lo_url).path} the replay "
                    f"of {urlsplit(page).path} answered HTTP {after.status_code}, which neither shows the "
                    f"authenticated page nor denies the session.")

    async def _token_read(self, exchange, token, carriers, identifiers, headers):
        """The first read of the caller's own account that the fresh token alone
        authorizes while an anonymous request is denied:
        ((url, carrier, token read, anonymous read, denial), "") or (None, why the
        first anonymous control did not count, or ""). GET-only, at most
        _MAX_TOKEN_READS token sends."""
        sends, failed = 0, ""
        for url in _self_read_urls(exchange, self.run_context):
            for carrier in carriers:
                if sends >= _MAX_TOKEN_READS:
                    return None, failed
                sends += 1
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    try:
                        got = await self._send(client, "GET", url, _carry(headers, carrier, token), None)
                    except httpx.HTTPError:
                        got = None
                if got is None or got.status_code in (404, 405, 410) or got.status_code >= 500:
                    break  # no such read here; another carrier would not change that
                if not _shows_account(got, identifiers):
                    continue
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as anon:
                    try:
                        anon_got = await self._send(anon, "GET", url, dict(headers), None)
                    except httpx.HTTPError as e:
                        failed = failed or f"the anonymous control GET {url} failed ({type(e).__name__})"
                        break
                denial = _token_denial(anon_got, identifiers)
                if denial:
                    return (url, carrier, got, anon_got, denial), ""
                failed = failed or (
                    f"the anonymous control GET {urlsplit(url).path} answered HTTP "
                    f"{anon_got.status_code}, which is not a denial of the account read")
                break
        return None, failed

    async def _token_logout(self, exchange, login, minted, steps, done) -> ValidationResult:
        """WSTG-SESS-06 for a bearer-token session (the login set no cookie but
        returned a token). On the FRESH token only: (a) it alone reads the
        caller's own account while an anonymous request is denied; (b) a
        server-side logout/revocation route the run observed is called with it;
        (c) the same token replays the read. Confirmed when (c) still shows the
        account, the negative when (c) is denied. When the run observed no such
        route the token is reported as a lead with its lifetime: a logout that
        only discards the token in the client cannot revoke it, but that absence
        was not proven, so it is never confirmed."""
        where, token = minted
        lifetime, never_expires = _token_lifetime(token)
        fields, _ = _parse_body(exchange)
        ukey = _find_key(fields, _USER_KEYS)
        identifiers = ({str(fields.get(ukey) or "").strip().lower()} if ukey else set())
        identifiers = {i for i in identifiers | _token_identifiers(token) if len(i) >= 3}
        ctx = self.run_context
        carriers = _token_carriers(ctx, exchange)
        headers = self._page_headers(exchange)
        found, failed = await self._token_read(exchange, token, carriers, identifiers, headers)
        if found is None:
            steps.append({"step": "authenticated_before_logout", "status": "unproven"})
            return done("inconclusive",
                        f"Logout invalidation not tested: the fresh login's bearer token ({where}) "
                        f"authorized no read of the account that an anonymous request is denied"
                        + (f" ({failed})" if failed else "") + ". Nothing was sent to a logout.")
        page, carrier, read, anon, denial = found
        path = urlsplit(page).path
        steps.append({"step": "authenticated_before_logout", "url": page, "status": read.status_code,
                      "carrier": _carrier_label(carrier), "anonymous": denial})
        routes = _revocation_routes([(login.text or "", exchange.url), (read.text or "", page),
                                     (exchange.response_body or "", exchange.url)], exchange, ctx)
        if not routes:
            steps.append({"step": "logout_request", "status": "not_found"})
            return done(
                "inconclusive",
                f"Logout invalidation lead, not confirmed: the login issues a bearer token "
                f"({lifetime}) that alone authorizes {path}, and the run observed no server-side "
                f"logout or token-revocation route, so a logout can only discard the token in the "
                f"client while the server keeps accepting it.",
                f"A fresh login (HTTP {login.status_code}) returned a token in {where} and set no "
                f"session cookie. Sent as {_carrier_label(carrier)} it reads {page} (HTTP "
                f"{read.status_code}, naming the account) while the same request without it got "
                f"{denial}. No logout form or link, no logout/revocation path in a response and no "
                f"logout/revocation API call by the crawled app was observed; no logout path is "
                f"guessed, so nothing was sent to one. Token lifetime: {lifetime}. To confirm, "
                f"capture the app's logout request (or name its revocation endpoint) and re-run: "
                f"this leg logs a fresh token out through it and replays {path}. Token value "
                f"redacted.",
                confidence=0.5 if never_expires else 0.4)
        lo_method, lo_url, lo_body, lo_where = routes[0]
        lo_path = urlsplit(lo_url).path
        lo_headers = _carry(headers, carrier, token)
        if lo_body is not None:
            lo_headers["Content-Type"] = "application/x-www-form-urlencoded"
        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as lo_client:
            logout = await self._send(lo_client, lo_method, lo_url, lo_headers, lo_body)
        steps.append({"step": "logout", "method": lo_method, "url": lo_url, "source": lo_where,
                      "status": logout.status_code})
        if logout.status_code >= 400:
            return done("inconclusive",
                        f"Logout invalidation not tested: {lo_method} {lo_path} ({lo_where}) answered "
                        f"HTTP {logout.status_code}, so the logout itself did not complete.")
        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as replay_client:
            after = await self._send(replay_client, "GET", page, _carry(headers, carrier, token), None)
        still = _shows_account(after, identifiers)
        steps.append({"step": "replay_after_logout", "url": page, "status": after.status_code,
                      "authenticated": still})
        if still:
            return done(
                "confirmed",
                f"Logout invalidation missing: the pre-logout bearer token still authorizes {path} "
                f"after {lo_method} {lo_path}.",
                f"A fresh login's token ({where}; {lifetime}) sent as {_carrier_label(carrier)} read "
                f"{page} (HTTP {read.status_code}, naming the account) while the same request without "
                f"it got {denial}. After {lo_method} {lo_url} ({lo_where}) with that token (HTTP "
                f"{logout.status_code}), replaying {page} with the same token still returned the "
                f"account (HTTP {after.status_code}): the logout does not revoke the token "
                f"server-side. Token value redacted.",
                confidence=0.9).with_artifacts(baseline=read, attack=after, controls=[anon])
        revoked = _token_denial(after, identifiers)
        if revoked:
            return done("not_confirmed",
                        f"Token revoked on logout: after {lo_method} {lo_path} the pre-logout bearer "
                        f"token is denied at {path} ({revoked}).")
        return done("inconclusive",
                    f"Logout invalidation unproven: after {lo_method} {lo_path} the replay of {path} "
                    f"answered HTTP {after.status_code}, which neither shows the account nor denies "
                    f"the token.")

    # --- 2FA / MFA bypass -----------------------------------------------------
    async def _check_mfa_bypass(self, exchange) -> ValidationResult:
        """A step-1 (username+password) login that lands on a SECOND-factor step but
        whose resulting session already reaches a protected resource -- the 2nd factor
        is not enforced on the session. Confirmation is safe (GET-only reads): the
        protected page is reachable with the partial session yet denied with none
        (a healthy denial, as for session fixation; never a redirect to the 2FA step).
        Control (enforcing MFA): the protected page redirects back to the 2FA step,
        so it is non-substantive and this stays un-confirmed."""
        fc = "2fa_bypass"
        from harness.missing_auth_probe import _substantive
        method = (exchange.method or "POST").upper()
        fields, _ = _parse_body(exchange)
        ukey = _find_key(fields, _USER_KEYS)
        username = str(fields.get(ukey) or "").strip() if ukey else ""
        p = urlsplit(exchange.url)
        origin = f"{p.scheme}://{p.netloc}"

        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as client:
            # Step 1: submit username + password. A CSRF-bound login needs a token
            # minted in THIS session, so refresh it from the login page first (the
            # captured token is bound to the crawl's session). The client's jar then
            # carries the matching session cookie into the POST.
            body = await self._refresh_login_body(client, exchange)
            resp = await self._send(client, method, exchange.url, self._headers(exchange), body)
            loc = resp.headers.get("location", "") or ""
            at_mfa = bool(_MFA_MARKERS.search(loc))
            if not at_mfa and loc:
                nxt = loc if loc.startswith("http") else (origin + loc if loc.startswith("/") else None)
                if nxt:
                    try:
                        page = await self._send(client, "GET", nxt, self._headers(exchange), None)
                        at_mfa = bool(_MFA_MARKERS.search((page.text or "")[:2000]))
                    except httpx.HTTPError:
                        pass
            if not at_mfa:
                return self._not("login did not present a second authentication factor; MFA-bypass N/A", fc)

            # Step 2 (the 2FA code) is DELIBERATELY skipped. Probe protected resources
            # with the partial, step-1-only session.
            candidates = ([f"/my-account?id={username}"] if username else []) + list(_PROTECTED_CANDIDATES)
            seen = set()
            unproven = ""  # RV-L L8: a reachable page whose anonymous control did not deny
            for path in candidates:
                if path in seen:
                    continue
                seen.add(path)
                url = origin + path
                try:
                    got = await self._send(client, "GET", url, self._headers(exchange), None)
                except httpx.HTTPError:
                    continue
                body = got.text or ""
                low = body.lower()
                # Require a POSITIVE authenticated-session signal (a logout control or
                # the account's own username). This distinguishes the real account page
                # from a served 2FA-prompt page, without keying on page chrome (the lab
                # title/nav can mention "2fa") -- an enforcing app shows a code prompt
                # here, not the logged-in account, so it lacks this signal.
                authed = ("log out" in low or "logout" in low
                          or (username and username.lower() in low))
                if not (_substantive(got.status_code, body) and authed):
                    continue
                # Control: the same resource with NO session must be denied, else it is
                # simply public (not a bypass).
                anon_answer, denial = "", ""
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as anon:
                    try:
                        anon_got = await self._send(anon, "GET", url, self._headers(exchange), None)
                    except httpx.HTTPError as e:
                        anon_got, anon_answer = None, f"a transport error ({type(e).__name__})"
                if anon_got is not None:
                    if _substantive(anon_got.status_code, anon_got.text or ""):
                        continue
                    # RV-R R1 (owner decision 2026-10-21): only a healthy denial
                    # counts, the rule session fixation uses (E3). A redirect to the
                    # second-factor step is not "log in first", even under a
                    # login-looking path, and any other answer (a 5xx, a 404, a 429,
                    # another redirect) says nothing about whether the page is
                    # protected.
                    status = anon_got.status_code
                    location = anon_got.headers.get("location") or ""
                    if 300 <= status < 400 and _MFA_MARKERS.search(location):
                        anon_answer = f"HTTP {status}, a redirect to the second-factor step {location}"
                    else:
                        denial = _anonymous_denial(status, anon_got.text or "", location)
                        if not denial:
                            anon_answer = f"HTTP {status}" + (
                                f" (redirect to {location})" if 300 <= status < 400 and location else "")
                if not denial:
                    unproven = unproven or (
                        f"GET {url} returned authenticated content (HTTP {got.status_code}) to the "
                        f"step-1-only session, but the same path with no session answered "
                        f"{anon_answer}, which is not an authorization denial (only 401/403, a redirect "
                        f"to a login page or a login page is), so the page may be public or broken "
                        f"rather than protected.")
                    continue
                return ValidationResult(
                    self.name, "confirmed", fc, confidence=0.9, confirmed=True,
                    summary=f"Two-factor authentication bypass confirmed: {path} is reachable with a session "
                            f"that only completed step 1 (username+password), before the second factor.",
                    evidence=f"Login required a second factor (marker in the login response/redirect), yet "
                             f"GET {url} returned authenticated content (HTTP {got.status_code}) while the same "
                             f"path with no session was denied ({denial}). The protected page is reachable "
                             f"without the 2FA code -- the second factor is not enforced on the session."
                # Ticket 6: the step-1 login that stopped at the second factor
                # (baseline), the partial session reaching the page (attack), and the
                # same page denied with no session (control).
                ).with_artifacts(baseline=resp, attack=got, controls=[anon_got])
        if unproven:
            return self._candidate("a page is reachable before the second factor, but the "
                                   "anonymous control did not deny it", unproven, fc)
        return self._not("no protected resource reachable before the second factor", fc)

    async def _refresh_login_body(self, client, exchange) -> str:
        """Return the login body with any CSRF field replaced by a token freshly
        minted in THIS client's session (GET the login page). No csrf field, or the
        page cannot be read, -> the captured body unchanged."""
        fields, kind = _parse_body(exchange)
        csrf_key = next((k for k in fields if re.search(r"csrf|xsrf|authenticity|_token|nonce", k, re.I)), None)
        if csrf_key is None:
            return exchange.request_body

        from harness.validators.source_form import fetch_source_form, CSRF_FIELD_RE

        def select(forms):
            # First form carrying a (non-empty) matching field -- same rule as
            # the original inline loop: the FIRST name-matching field in a form
            # is taken, so a form whose only matching field is empty is skipped
            # entirely (not its other fields).
            for f in forms:
                tok = next((fld.value for fld in f.fields
                            if fld.name == csrf_key or CSRF_FIELD_RE.search(fld.name or "")), None)
                if tok:
                    return f
            return None

        try:
            found = await fetch_source_form(client, [exchange.url], self._headers(exchange), select)
        except Exception:
            return exchange.request_body
        if found is None:
            return exchange.request_body
        tok = next((fld.value for fld in found.form.fields
                    if fld.name == csrf_key or CSRF_FIELD_RE.search(fld.name or "")), None)
        if not tok:
            return exchange.request_body
        updated = dict(fields); updated[csrf_key] = tok
        return _encode(updated, kind)

    # --- weak password policy -------------------------------------------------
    async def _check_weak_password(self, exchange) -> ValidationResult:
        fc = "weak_password"
        fields, kind = _parse_body(exchange)
        pkey = _find_key(fields, _PASS_KEYS)
        if not pkey:
            return self._skip("no password field to test a strength policy", fc)
        ukey = _find_key(fields, _USER_KEYS)
        probe = dict(fields)
        probe[pkey] = _WEAK_PASSWORD
        # unique throwaway identity so we don't collide with an existing account.
        # Neutral throwaway identity -- must NOT contain words the rejection regex
        # looks for (e.g. "policy"), or the reflected username would self-trip it.
        nonce = secrets.token_hex(4)
        if ukey:
            base = str(fields.get(ukey) or "probe")
            probe[ukey] = f"qaprobe{nonce}@example.com" if "@" in base else f"qaprobe{nonce}"
        for extra_email in ("email",):
            ek = _find_key(fields, (extra_email,))
            if ek and ek != ukey:
                probe[ek] = f"qaprobe{nonce}@example.com"
        method = (exchange.method or "POST").upper()
        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as client:
            resp = await self._send(client, method, exchange.url,
                                    self._headers(exchange), _encode(probe, kind))
            body = (resp.text or "")[:400]
        # Accepted weak password: 2xx and the response doesn't signal a policy rejection.
        rejected = re.search(r"weak|too short|at least \d+|minimum|complexity|policy|strength|invalid password",
                             body, re.I)
        if 200 <= resp.status_code < 300 and not rejected:
            return ValidationResult(
                self.name, "confirmed", fc, confidence=0.8, confirmed=True,
                summary=f"Weak password policy confirmed: '{_WEAK_PASSWORD}' accepted at {urlsplit(exchange.url).path}.",
                evidence=f"Registering with password '{_WEAK_PASSWORD}' returned HTTP {resp.status_code} with no "
                         f"strength/complexity rejection -- the endpoint enforces no meaningful password policy.")
        return self._not(f"weak password rejected or not accepted (HTTP {resp.status_code})", fc)

    # --- username enumeration -------------------------------------------------
    async def _check_username_enum(self, exchange, new_lookup_leg: bool = False
                                   ) -> ValidationResult:
        """The same request with an existing account's identifier and a nonexistent
        one, after masking the echoed identifier and per-request tokens. The
        identifier is the captured login/reset body's username field, or -- for a
        lookup that takes it in the query (GET ...?email=) -- that parameter, set
        to a run identity's own identifier (an account known to exist)."""
        fc = "username_enumeration"
        fields, kind = _parse_body(exchange)
        ukey = _find_key(fields, _USER_KEYS)
        query = None if ukey else _query_identifier(exchange)
        if not ukey and query is None:
            return self._skip("no username/email field to test enumeration", fc)
        pkey = _find_key(fields, _PASS_KEYS) if ukey else None
        known_as, qname = "", ""
        if query is not None:
            qname, valid_user = query[0], str(query[1] or "")
            known = _identity_identifiers(self.run_context)
            if valid_user.strip().lower() in known:
                known_as = "a run identity's own identifier"
            else:
                wants_email = "@" in valid_user or not valid_user
                shaped = sorted(i for i in known if ("@" in i) == wants_email)
                if shaped:
                    valid_user, known_as = shaped[0], (
                        "a run identity's own identifier, in place of the captured value")
        else:
            valid_user = str(fields.get(ukey) or "")
        if not valid_user:
            return self._skip("captured username is empty", fc)
        invalid_user = (f"nouser_{secrets.token_hex(4)}@example.com" if "@" in valid_user
                        else f"nouser_{secrets.token_hex(4)}")
        wrong_pw = "wrongpw_" + secrets.token_hex(4)
        method = (exchange.method or "POST").upper()
        headers = self._headers(exchange)
        if query is not None and not exchange.request_body:
            headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}

        async def _probe(client, u):
            """Send the probe for identifier `u`."""
            if query is not None:
                return await self._send(client, method, _with_query_value(exchange.url, qname, u),
                                        headers, exchange.request_body or None)
            f = dict(fields); f[ukey] = u
            if pkey:
                f[pkey] = wrong_pw
            return await self._send(client, method, exchange.url, headers, _encode(f, kind))

        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as client:
            r_valid = await _probe(client, valid_user)
            vstatus, vbody = r_valid.status_code, (r_valid.text or "")
            r_invalid = await _probe(client, invalid_user)
            istatus, ibody = r_invalid.status_code, (r_invalid.text or "")

        def _mask(b, u):
            """Mask echoed username AND strip dynamic tokens so a body that
            merely reflects the input or contains per-request nonces isn't
            mistaken for (or confused with) an existence oracle."""
            b = re.sub(re.escape(u), "<U>", b, flags=re.I)
            b = re.sub(r"[0-9a-f]{32,}", "<TOKEN>", b)
            b = re.sub(r"\d{10,13}", "<TS>", b)
            b = re.sub(r'"csrf[^"]*"\s*:\s*"[^"]*"', '"csrf":"<CSRF>"', b, flags=re.I)
            b = re.sub(r'name="[^"]*(?:csrf|token|nonce)[^"]*"\s+value="[^"]*"',
                        'name="<CSRF>" value="<V>"', b, flags=re.I)
            return b

        vmask, imask = _mask(vbody, valid_user), _mask(ibody, invalid_user)

        async def proof() -> dict:
            """Ticket 6 proof exchanges, never verdict inputs: the non-existent
            account's answer (baseline), the existing account's (attack), and a
            second non-existent account (control), named only when it answers
            exactly like the first, so the difference is not per-request noise.
            Outside a run the control is not sent: it would name nothing."""
            if self.run_context is None:
                return {"baseline": r_invalid, "attack": r_valid}
            other_user = (f"nouser_{secrets.token_hex(4)}@example.com" if "@" in valid_user
                          else f"nouser_{secrets.token_hex(4)}")
            control = None
            try:
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    control = await _probe(client, other_user)
            except (SafetyGateBlocked, httpx.HTTPError):
                control = None
            if control is not None and (
                    control.status_code != istatus
                    or _mask(control.text or "", other_user).strip() != imask.strip()):
                control = None
            return {"baseline": r_invalid, "attack": r_valid, "controls": [control]}

        where = f"{method} {urlsplit(exchange.url).path}?{qname}=" if query is not None else ""
        if query is not None:
            how = (f"Same {where} lookup: an existing account ({known_as})" if known_as
                   else f"Same {where} lookup: the captured identifier")
        else:
            how = "Same wrong password: existing user"
        if query is not None and new_lookup_leg and not self.confirm_lookup and (
                vstatus != istatus or vmask.strip() != imask.strip()):
            differ = (f"HTTP {vstatus} vs HTTP {istatus}" if vstatus != istatus
                      else f"identical status ({vstatus}), different bodies after masking")
            return ValidationResult(
                self.name, "not_confirmed", fc, confidence=0.5, confirmed=False,
                summary=(f"Lead, not confirmed (validators.auth_sequence.confirm_lookup is off, "
                         f"owner sign-off pending): account enumeration through the lookup "
                         f"{where}: an existing account and a non-existent one answer "
                         f"differently ({differ})."),
                evidence=(f"{how} and a random non-existent one: {differ}. The identifiers "
                          f"are redacted here."),
                limitation="a lookup discrimination confirms only with "
                           "validators.auth_sequence.confirm_lookup: true",
                manual_verification=("Look up a known account and an unknown one at the "
                                     "same route; compare the answers."),
            ).with_artifacts(**await proof())
        if vstatus != istatus:
            return ValidationResult(
                self.name, "confirmed", fc, confidence=0.8, confirmed=True,
                summary="Username enumeration confirmed: valid vs invalid account give different HTTP status"
                        + (f" at {where}" if where else "") + ".",
                evidence=f"{how} -> HTTP {vstatus}, non-existent user -> HTTP "
                         f"{istatus}. The status discriminates account existence."
            ).with_artifacts(**await proof())
        if vmask.strip() != imask.strip():
            return ValidationResult(
                self.name, "confirmed", fc, confidence=0.75, confirmed=True,
                summary="Username enumeration confirmed: valid vs invalid account give different responses"
                        + (f" at {where}" if where else "") + ".",
                evidence=f"{how} and a non-existent one, identical status ({vstatus}); after masking the "
                         f"echoed username and stripping dynamic tokens, the bodies still differ, leaking "
                         f"which usernames exist."
            ).with_artifacts(**await proof())
        if query is not None and not known_as:
            return ValidationResult(
                self.name, "inconclusive", fc, confidence=0.0, confirmed=False,
                summary=f"Username enumeration not tested at {where}: the captured identifier is not "
                        f"known to exist (no run identity carries it), so its answer matching a "
                        f"non-existent one's proves nothing.",
                evidence="Register an identity whose token names its account and re-run.")
        if query is not None:
            return self._not(
                f"an existing account ({known_as}) and a non-existent one produced indistinguishable "
                f"responses at {where} (no enumeration for that account; an account lacking the "
                f"looked-up data answers like a missing one)", fc)
        return self._not("valid and invalid usernames produced indistinguishable responses (no enumeration)", fc)
