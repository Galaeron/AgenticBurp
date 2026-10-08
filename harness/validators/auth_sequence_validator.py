"""
Stateful authentication-mechanism confirmation legs.

The auth-family bugs (broken authentication, OWASP A07) can't be confirmed by the
single-request replay-and-diff shape -- each needs a multi-request FLOW with a
state boundary. This leg confirms the three that have a clean, deterministic
oracle, dispatched by the finding's class:

  - session_fixation      -- the session identifier does NOT change across the
                             login boundary (a pre-auth session id is still valid
                             / re-issued unchanged after authenticating).
  - weak_password_policy   -- a trivially weak password is ACCEPTED at registration
                             (throwaway account), i.e. no strength policy.
  - username_enumeration   -- a login/reset response DISCRIMINATES a valid account
                             from an invalid one (after masking the echoed username),
                             leaking which usernames exist.

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
    }
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

    def _skip(self, why: str, fc="broken_authentication") -> ValidationResult:
        return ValidationResult(self.name, "skipped", fc, summary=why)

    def _not(self, why: str, fc) -> ValidationResult:
        return ValidationResult(self.name, "not_confirmed", fc, confidence=0.0, confirmed=False, summary=why)

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        if (exchange.method or "").upper() not in ("POST", "PUT"):
            return False
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
        (e.g. "username_enumeration"), returns just that one. For generic
        "broken_authentication", returns ALL applicable checks so we don't miss
        a confirmable finding just because the LLM used a vague label."""
        low = (vc or "").lower()
        if "fixation" in low:
            return ["fixation"]
        if "weak" in low or "password polic" in low:
            return ["weak"]
        if "enum" in low:
            return ["enum"]
        if "2fa" in low or "mfa" in low or "two" in low or "multi" in low or "second factor" in low:
            return ["mfa"]
        # Generic "broken authentication" — run all applicable checks.
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
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        if not get_default_gate().config.allow_mutating_replay:
            return self._skip("auth-mechanism probes send POSTs; need validators.allow_mutating_replay")
        checks = self._which_checks(finding.vulnerability_class, exchange)
        last_result = None
        try:
            for check in checks:
                if check == "fixation":
                    result = await self._check_session_fixation(exchange)
                elif check == "weak":
                    result = await self._check_weak_password(exchange)
                elif check == "mfa":
                    result = await self._check_mfa_bypass(exchange)
                else:
                    result = await self._check_username_enum(exchange)
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
            return self._not("no session cookie issued (token-based auth?) -- fixation N/A", fc)
        # Fixation: a pre-auth session id survives login unchanged, OR login issues
        # NO fresh session cookie at all despite one existing pre-auth.
        for n, v in pre_cookies.items():
            if post_cookies.get(n) == v:
                return ValidationResult(
                    self.name, "confirmed", fc, confidence=0.85, confirmed=True,
                    summary=f"Session fixation confirmed: cookie {n!r} was not rotated across login.",
                    evidence=f"Pre-auth {n} == post-auth {n}; an attacker-fixed session id survives "
                             f"authentication, so a planted session becomes an authenticated one.")
        if pre_cookies and not post_cookies:
            return ValidationResult(
                self.name, "confirmed", fc, confidence=0.7, confirmed=True,
                summary="Session fixation confirmed: login issued no fresh session cookie.",
                evidence=f"A pre-auth session cookie {list(pre_cookies)} existed but login set no new "
                         f"session cookie, so the pre-auth id remains in force post-authentication.")
        return self._not("session id rotated on login (no fixation)", fc)

    # --- 2FA / MFA bypass -----------------------------------------------------
    async def _check_mfa_bypass(self, exchange) -> ValidationResult:
        """A step-1 (username+password) login that lands on a SECOND-factor step but
        whose resulting session already reaches a protected resource -- the 2nd factor
        is not enforced on the session. Confirmation is safe (GET-only reads): the
        protected page is reachable with the partial session yet denied with none.
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
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as anon:
                    try:
                        anon_got = await self._send(anon, "GET", url, self._headers(exchange), None)
                        anon_ok = _substantive(anon_got.status_code, anon_got.text or "")
                    except httpx.HTTPError:
                        anon_ok = False
                if anon_ok:
                    continue
                return ValidationResult(
                    self.name, "confirmed", fc, confidence=0.9, confirmed=True,
                    summary=f"Two-factor authentication bypass confirmed: {path} is reachable with a session "
                            f"that only completed step 1 (username+password), before the second factor.",
                    evidence=f"Login required a second factor (marker in the login response/redirect), yet "
                             f"GET {url} returned authenticated content (HTTP {got.status_code}) while the same "
                             f"path with no session was denied. The protected page is reachable without the "
                             f"2FA code -- the second factor is not enforced on the session.")
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
    async def _check_username_enum(self, exchange) -> ValidationResult:
        fc = "username_enumeration"
        fields, kind = _parse_body(exchange)
        ukey = _find_key(fields, _USER_KEYS)
        if not ukey:
            return self._skip("no username/email field to test enumeration", fc)
        pkey = _find_key(fields, _PASS_KEYS)
        valid_user = str(fields.get(ukey) or "")
        if not valid_user:
            return self._skip("captured username is empty", fc)
        invalid_user = (f"nouser_{secrets.token_hex(4)}@example.com" if "@" in valid_user
                        else f"nouser_{secrets.token_hex(4)}")
        wrong_pw = "wrongpw_" + secrets.token_hex(4)

        def _probe_body(u):
            f = dict(fields); f[ukey] = u
            if pkey:
                f[pkey] = wrong_pw
            return _encode(f, kind)

        method = (exchange.method or "POST").upper()
        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as client:
            r_valid = await self._send(client, method, exchange.url, self._headers(exchange), _probe_body(valid_user))
            vstatus, vbody = r_valid.status_code, (r_valid.text or "")
            r_invalid = await self._send(client, method, exchange.url, self._headers(exchange), _probe_body(invalid_user))
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
        if vstatus != istatus:
            return ValidationResult(
                self.name, "confirmed", fc, confidence=0.8, confirmed=True,
                summary="Username enumeration confirmed: valid vs invalid account give different HTTP status.",
                evidence=f"Same wrong password: existing user -> HTTP {vstatus}, non-existent user -> HTTP "
                         f"{istatus}. The status discriminates account existence.")
        if vmask.strip() != imask.strip():
            return ValidationResult(
                self.name, "confirmed", fc, confidence=0.75, confirmed=True,
                summary="Username enumeration confirmed: valid vs invalid account give different responses.",
                evidence=f"Same wrong password and identical status ({vstatus}); after masking the echoed "
                         f"username and stripping dynamic tokens, the bodies still differ, leaking "
                         f"which usernames exist.")
        return self._not("valid and invalid usernames produced indistinguishable responses (no enumeration)", fc)
