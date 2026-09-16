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
