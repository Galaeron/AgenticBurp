"""
Rate-limit / lockout absence confirmation leg (V4, WSTG-ATHN-03 / WSTG-BUSL-07).

Oracle (LEG_DECISIONS.md #4): N rapid attempts against an authentication (or
other should-be-limited) endpoint all reach the server with no 429 / lockout /
Retry-After after a threshold -> the endpoint enforces no rate limit.

The decision this leg encodes: "how many attempts = no rate limit, reconciled
with the mutating-burst ceiling." It requests a burst of `min_attempts` via the
safety gate's authorize_burst (so the operator's max_burst_size + the hard
ceiling still cap it). When the gate allows fewer than min_attempts but still
>= 2, the leg fires the reduced burst at lower confidence rather than skipping
entirely. min_attempts defaults to 5 (> typical lockout thresholds of 3,
reasonable with default burst ceilings).

SAFE subset: it REPLAYS THE CAPTURED REQUEST UNCHANGED, N times. A captured login
carries valid credentials, so N successful logins with no throttle is the finding
-- and valid logins don't lock the real account. It deliberately does NOT hammer
wrong credentials (that would risk locking a legitimate account -- the destructive
lockout-trigger variant needs explicit authorization). Mutating; the burst is
authorised once through the gate (needs allow_mutating_replay) then fired via a
plain client, exactly like the race-condition leg.

Reset-answer mode (R11-8 c). A reset or recovery-answer write (an account
identifier plus an answer field) is NOT replayed unchanged: replaying a
successful reset resets again. Instead the burst sends WRONG answers, each one
different, and every other field exactly as captured. It sends only when:
  - the identifier is a run-owned identity's own account (never a real user's);
  - the captured reset was accepted, so the new-password fields it carries are
    already the account's password: even an answer the server wrongly accepts
    changes nothing;
  - each wrong answer is rejected. An accepted one stops the burst at once.
All wrong answers rejected, every attempt answered, none throttled: a
confirmation (validators.rate_limit.confirm_reset_answer, on by default since the
owner decision of 2026-11-19); with the key set false, a LEAD.

Failed-login mode (R11-8 b, owner decision 2026-11-19). When the captured
exchange is the declared login of a run-owned identity (validators/owned_login),
the leg sends `min_attempts` WRONG-password logins for that identity (through
authorize_burst, so validators.max_burst_size caps it), then one login with its
real declared password. The real login must still succeed with no throttle
signal (429/503, Retry-After, lockout or captcha wording): that confirms "no
lockout or rate limit on failed logins". The account it acts on is always the
run's own; its credentials come from the identity configuration and are never
printed. If the real login fails afterwards, the verdict is not-vulnerable and
names the account as left locked.
"""
from __future__ import annotations
from harness import scope_lock

import json
import re
from urllib.parse import urlsplit

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import get_default_gate
from .base import Validator, ValidationResult

# Language / signals that a rate limit or lockout DID engage -- any of these on
# any attempt refutes "no rate limiting".
_THROTTLE_MARKERS = re.compile(
    r"rate ?limit|too many (requests|attempts)|slow down|try again later|"
    r"temporarily (locked|blocked)|account (locked|is locked)|lockout|"
    r"throttl|429|retry.?after",
    re.IGNORECASE,
)


_ANSWER_KEY = re.compile(r"answer", re.I)
_RESET_PATH = re.compile(r"reset|recover|forgot", re.I)
_NEW_SECRET_KEY = re.compile(r"pass|new|repeat|confirm", re.I)
_REJECTED = re.compile(r"\b(wrong|invalid|incorrect|failed|denied|mismatch|not match)", re.I)


def reset_answer_shape(exchange: HttpExchange) -> tuple[str, str] | None:
    """(identifier field, answer field) of a reset / recovery-answer write, else
    None. Needs both fields, plus a new-secret field or a reset-like path."""
    from .auth_sequence_validator import _parse_body, _find_key, _PASS_KEYS, _USER_KEYS
    if (exchange.method or "GET").upper() not in ("POST", "PUT", "PATCH"):
        return None
    fields, _kind = _parse_body(exchange)
    ukey = _find_key(fields, _USER_KEYS)
    akey = next((k for k in fields if _ANSWER_KEY.search(k) and k.lower() not in _PASS_KEYS
                 and isinstance(fields[k], (str, int)) and not isinstance(fields[k], bool)),
                None)
    if not ukey or not akey:
        return None
    others = [k for k in fields if k not in (ukey, akey)]
    if not (_RESET_PATH.search(urlsplit(exchange.url).path)
            or any(_NEW_SECRET_KEY.search(k) for k in others)):
        return None
    return ukey, akey


# Wording that a login is locked out or challenged (beyond _THROTTLE_MARKERS).
_LOCKED = re.compile(r"locked|lockout|suspended|captcha|verify you are (a )?human|"
                     r"too many", re.I)


def _rejected(resp) -> bool:
    status = resp.status_code or 0
    return not 200 <= status < 300 or bool(_REJECTED.search(resp.text or ""))


class RateLimitValidator(Validator):
    name = "rate_limit"
    finding_classes = {"rate_limit", "rate limit", "no rate limiting", "missing rate limit",
                       "missing rate limiting", "brute force", "brute_force", "brute-force",
                       "account lockout", "weak lockout", "lockout", "no lockout"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 min_attempts: int = 5, run_context=None, confirm_reset_answer: bool = True):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.min_attempts = max(2, int(min_attempts))
        self.run_context = run_context
        self.confirm_reset_answer = bool(confirm_reset_answer)

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        return (exchange.method or "GET").upper() not in ("GET", "HEAD", "OPTIONS")

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "rate_limit", summary=why)

    def _throttled(self, resp) -> bool:
        if resp is None:
            return False
        if resp.status_code in (429, 503):
            return True
        headers = getattr(resp, "headers", {}) or {}
        if any(k.lower() == "retry-after" for k in headers):
            return True
        return bool(_THROTTLE_MARKERS.search(resp.text or ""))

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {host!r} out of scope")
        method = (exchange.method or "POST").upper()
        if self.run_context is not None:
            from .owned_login import owned_login_for
            login = owned_login_for(self.run_context, exchange)
            if login is not None:
                return await self._failed_login_burst(login)
        shape = reset_answer_shape(exchange)
        if shape is not None:
            return await self._reset_answer_burst(exchange, method, *shape)

        gate = self.run_context.gate if self.run_context is not None else get_default_gate()
        decision = gate.authorize_burst(
            validator_name=self.name, method=method, url=exchange.url,
            requested_burst_size=self.min_attempts, body=exchange.request_body)
        if not decision.allowed:
            return self._skip(f"burst not authorized by safety gate: {decision.reason}")
        allowed = decision.allowed_burst_size
        if allowed < 2:
            return self._skip(
                f"burst ceiling {allowed} is below 2 -- need at least 2 attempts to "
                f"test rate limiting (raise validators.max_burst_size)")

        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        content = exchange.request_body or None
        completed = 0
        statuses: dict[int, int] = {}
        # Attempts that got no response are never counted as "not limited"
        # (RV-P P4): a dropped or refused attempt may itself be the throttle.
        refused, errors = "", []
        try:
            client = None if self.run_context is not None else httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=False, verify=False)
            try:
                for attempt in range(1, allowed + 1):
                    try:
                        if self.run_context is not None:
                            from types import SimpleNamespace
                            from harness.run_context import TypedRequest
                            from .transport import bind_session
                            session_ref, request_headers = bind_session(self.run_context, headers)
                            result = await self.run_context.executor().execute(
                                TypedRequest(method, exchange.url, headers=request_headers,
                                             body=content),
                                capability=self.name, session_ref=session_ref)
                            if not result.executed:
                                # Nothing more can send once the run refuses (budget, scope).
                                refused = result.outcome
                                break
                            if not result.ok:
                                errors.append(f"attempt {attempt}: "
                                              f"{getattr(result.artifact, 'transport_outcome', '') or result.error}")
                                continue
                            resp = SimpleNamespace(status_code=result.status,
                                                   text=result.body, headers=result.headers)
                        else:
                            await global_throttle.acquire()
                            resp = await client.request(method, exchange.url,
                                                        headers=headers or None, content=content)
                    except httpx.HTTPError as e:
                        errors.append(f"attempt {attempt}: {e.__class__.__name__}")
                        continue
                    completed += 1
                    statuses[resp.status_code] = statuses.get(resp.status_code, 0) + 1
                    if self._throttled(resp):
                        return ValidationResult(
                            self.name, "not_confirmed", "rate_limit", confidence=0.2, confirmed=False,
                            summary=f"Rate limiting / lockout engaged after {completed} attempt(s) -- "
                                    f"the endpoint IS limited.",
                            evidence=f"Attempt {completed} returned a throttle signal "
                                     f"(status/Retry-After/marker). Status distribution: {statuses}.")
            finally:
                if client is not None:
                    await client.aclose()
        except Exception as e:
            return self._skip(f"burst failed: {e.__class__.__name__}")

        if completed < 2:
            return self._skip(f"only {completed} attempt(s) completed -- too few for any claim")
        if refused or errors:
            failed = len(errors) + (allowed - completed - len(errors) if refused else 0)
            why = "; ".join(([f"refused by the run ({refused})"] if refused else []) + errors[:3])
            return ValidationResult(
                self.name, "inconclusive", "rate_limit", confidence=0.0, confirmed=False,
                summary=f"Rate-limit check incomplete: {failed} of {allowed} attempt(s) got no "
                        f"response ({why}); not a negative result",
                evidence=f"{completed} answered attempt(s) carried no 429/Retry-After/lockout "
                         f"signal (status distribution: {statuses}), but an attempt that got no "
                         f"response may itself have been throttled or dropped.")

        # RETIRED (review 2026-09-09): replaying a VALID captured request N times
        # without a 429 does NOT confirm a rate-limit / lockout bypass. A failed-
        # login lockout triggers on INVALID credentials, so a valid-request burst
        # cannot establish it; this leg also counted any non-throttle response
        # (incl. 5xx) as a clean attempt, and had as little as 2 attempts confirm.
        # It now emits an OBSERVATION ("no throttle in N attempts"), never a
        # confirmation. Re-qualify: authorized test account, an invalid-credential
        # burst, an explicit lockout policy/window, and a cooldown/reset control --
        # only then may this emit confirmed=True again (and re-add to the gate's
        # LIVE set if promoted).
        return ValidationResult(
            self.name, "not_confirmed", "rate_limit",
            confidence=0.3 if completed >= self.min_attempts else 0.15, confirmed=False,
            summary=f"OBSERVATION (not confirmed): {completed} rapid {method} attempts to "
                    f"{exchange.url} reached the server with no 429/Retry-After/lockout signal. "
                    f"This is NOT a confirmed rate-limit bypass -- replaying a VALID request "
                    f"cannot establish failed-login lockout, and non-throttle responses count as "
                    f"attempts. Needs an invalid-credential control + explicit policy window.",
            evidence=f"Replayed the captured request {completed} times (min_attempts "
                     f"{self.min_attempts}). Status distribution: {statuses}.")

    async def _failed_login_burst(self, login) -> ValidationResult:
        """Wrong-password burst, then the real login, for a run-owned identity
        (module doc). Never prints the identity's user or password."""
        import secrets
        fc = "rate_limit"
        run = self.run_context
        where = f"{login.method} {urlsplit(login.url).path}"
        account = login.label
        decision = run.gate.authorize_burst(
            validator_name=self.name, method=login.method, url=login.url,
            requested_burst_size=self.min_attempts, body=None)
        if not decision.allowed:
            return self._skip(f"burst not authorized by safety gate: {decision.reason}")
        allowed = decision.allowed_burst_size
        if allowed < 2:
            return self._skip(f"burst ceiling {allowed} is below 2 (raise validators.max_burst_size); "
                              f"no wrong-password login was sent")
        statuses: dict[int, int] = {}
        completed, refused, errors, throttled_at = 0, "", [], 0
        for attempt in range(1, allowed + 1):
            resp, why = await self._send_login(login, "wrong-" + secrets.token_hex(6))
            if resp is None:
                if why.startswith("refused"):
                    refused = why
                    break
                errors.append(f"attempt {attempt}: {why}")
                continue
            completed += 1
            statuses[resp.status_code] = statuses.get(resp.status_code, 0) + 1
            if self._throttled(resp) or _LOCKED.search(resp.text or ""):
                throttled_at = completed
                break
            if not _rejected(resp):
                return ValidationResult(
                    self.name, "inconclusive", fc, confidence=0.0, confirmed=False,
                    summary=f"Failed-login check stopped at {where}: wrong password {completed} for "
                            f"run identity {account!r} was not rejected (HTTP {resp.status_code}).",
                    evidence=f"Status distribution: {statuses}. Credentials redacted.",
                    manual_verification="Check by hand whether this login verifies the password.")
        if refused or errors or (completed < 2 and not throttled_at):
            why = "; ".join(([refused] if refused else []) + errors[:3])
            return ValidationResult(
                self.name, "inconclusive", fc, confidence=0.0, confirmed=False,
                summary=f"Failed-login check incomplete at {where}: {completed} of {allowed} "
                        f"wrong-password login(s) answered" + (f" ({why})" if why else ""),
                evidence=f"Status distribution: {statuses}.")
        resp, why = await self._send_login(login, None)
        real_ok = (resp is not None and 200 <= (resp.status_code or 0) < 300
                   and not _rejected(resp) and not self._throttled(resp)
                   and not _LOCKED.search(resp.text or "")
                   and login.credential_headers(resp.status_code, resp.text, resp.headers) is not None)
        evidence = (f"{completed} wrong-password login(s) for run identity {account!r} "
                    f"(status distribution: {statuses}, burst ceiling {allowed}), then one login "
                    f"with its declared password: "
                    + (f"HTTP {resp.status_code}" if resp is not None else why)
                    + ". Credentials redacted.")
        raw = json.dumps({"check": "failed_login_burst", "identity": account,
                          "wrong_attempts": completed, "statuses": statuses,
                          "throttled_at": throttled_at, "real_login_ok": real_ok})
        if not real_ok:
            return ValidationResult(
                self.name, "not_confirmed", fc, confidence=0.0, confirmed=False,
                summary=f"Failed logins are limited at {where}: after {completed} wrong password(s) "
                        f"the real login for run identity {account!r} did not succeed. The account "
                        f"{account!r} is left locked (or throttled) by this check.",
                evidence=evidence, raw_output=raw,
                limitation=f"run identity {account!r} is left locked; later legs that use it may "
                           f"fail until the lockout expires or it is unlocked")
        if throttled_at:
            return ValidationResult(
                self.name, "not_confirmed", fc, confidence=0.1, confirmed=False,
                summary=f"Failed logins are limited at {where}: a throttle or lockout signal after "
                        f"{throttled_at} wrong password(s); the real login still works.",
                evidence=evidence, raw_output=raw)
        if completed >= self.min_attempts:
            return ValidationResult(
                self.name, "confirmed", fc, confidence=0.8, confirmed=True,
                summary=f"No lockout or rate limit on failed logins at {where}: {completed} wrong "
                        f"passwords in a row for run identity {account!r} were each rejected with "
                        f"no throttle, and the real login still succeeded.",
                evidence=evidence, raw_output=raw)
        why = f"only {completed} of min_attempts {self.min_attempts} attempts were allowed"
        return ValidationResult(
            self.name, "not_confirmed", fc, confidence=0.4, confirmed=False,
            summary=f"Lead, not confirmed ({why}): {completed} wrong passwords at {where} drew no "
                    f"throttle and the real login still succeeded.",
            evidence=evidence, raw_output=raw, limitation=why,
            manual_verification="Raise validators.max_burst_size to min_attempts to confirm.")

    async def _send_login(self, login, password):
        """One anonymous login for `login` (password None = its declared one) via
        the run's executor. (response, "") or (None, why)."""
        from types import SimpleNamespace
        from harness.run_context import TypedRequest
        from .transport import bind_session
        run = self.run_context
        request = login.request(password)
        session_ref, bound = bind_session(run, dict(request.headers or {}))
        result = await run.executor().execute(
            TypedRequest(request.method, request.url, headers=bound, body=request.body),
            capability=self.name, session_ref=session_ref)
        if not result.executed:
            return None, f"refused by the run ({result.outcome})"
        if not result.ok:
            return None, str(getattr(result.artifact, "transport_outcome", "") or result.error)
        return SimpleNamespace(status_code=result.status, text=result.body or "",
                               headers=result.headers or {}), ""

    async def _reset_answer_burst(self, exchange, method, ukey, akey) -> ValidationResult:
        """Wrong-answer burst against a run-owned account's reset (module doc)."""
        import secrets
        from types import SimpleNamespace
        from harness.run_context import TypedRequest
        from .auth_sequence_validator import _encode, _identity_identifiers, _parse_body
        from .transport import bind_session
        fc = "rate_limit"
        run = self.run_context
        if run is None:
            return self._skip("reset-answer guessing needs a run context (run-owned identities)")
        fields, kind = _parse_body(exchange)
        account = str(fields.get(ukey) or "").strip().lower()
        if not account or account not in _identity_identifiers(run):
            return self._skip("reset-answer guessing is sent only for a run-owned identity's own "
                              "account; this reset names another account (redacted)")
        captured_status = exchange.response_status or 0
        if not 200 <= captured_status < 300 or _REJECTED.search(exchange.response_body or ""):
            return self._skip("the captured reset was not accepted, so its new-password fields may "
                              "not be the account's current password: a wrongly accepted answer "
                              "could change it, so nothing is sent")
        decision = run.gate.authorize_burst(
            validator_name=self.name, method=method, url=exchange.url,
            requested_burst_size=self.min_attempts, body=exchange.request_body)
        if not decision.allowed:
            return self._skip(f"burst not authorized by safety gate: {decision.reason}")
        allowed = decision.allowed_burst_size
        if allowed < 2:
            return self._skip(f"burst ceiling {allowed} is below 2 (raise validators.max_burst_size)")
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        where = f"{method} {urlsplit(exchange.url).path}"
        statuses: dict[int, int] = {}
        completed, refused, errors = 0, "", []
        for attempt in range(1, allowed + 1):
            attempt_fields = dict(fields)
            attempt_fields[akey] = "wrong-" + secrets.token_hex(4)
            session_ref, bound = bind_session(run, headers)
            result = await run.executor().execute(
                TypedRequest(method, exchange.url, headers=bound,
                             body=_encode(attempt_fields, kind)),
                capability=self.name, session_ref=session_ref)
            if not result.executed:
                refused = result.outcome
                break
            if not result.ok:
                errors.append(f"attempt {attempt}: "
                              f"{getattr(result.artifact, 'transport_outcome', '') or result.error}")
                continue
            resp = SimpleNamespace(status_code=result.status, text=result.body,
                                   headers=result.headers)
            completed += 1
            statuses[resp.status_code] = statuses.get(resp.status_code, 0) + 1
            if self._throttled(resp):
                return ValidationResult(
                    self.name, "not_confirmed", fc, confidence=0.2, confirmed=False,
                    summary=f"Reset-answer guessing is limited at {where}: a throttle signal "
                            f"after {completed} wrong answer(s).",
                    evidence=f"Status distribution: {statuses}.")
            if not _rejected(resp):
                # Stop at once: the server took a wrong answer (or says nothing).
                return ValidationResult(
                    self.name, "not_confirmed", fc, confidence=0.4, confirmed=False,
                    summary=f"Lead, not confirmed: {where} accepted wrong answer {completed} "
                            f"(HTTP {resp.status_code}, no rejection). The burst stopped there; "
                            f"the answer may not be checked at all.",
                    evidence="Every other field was the accepted capture's own, so the account's "
                             "password was set to the value it already had.",
                    manual_verification="Check by hand whether the reset verifies the answer.")
        if completed < 2 or refused or errors:
            why = "; ".join(([f"refused by the run ({refused})"] if refused else []) + errors[:3])
            return ValidationResult(
                self.name, "inconclusive", fc, confidence=0.0, confirmed=False,
                summary=f"Reset-answer guessing check incomplete at {where}: {completed} of "
                        f"{allowed} wrong answer(s) answered" + (f" ({why})" if why else ""),
                evidence=f"Status distribution: {statuses}.")
        evidence = (f"{completed} different wrong answers for a run-owned account (redacted), "
                    f"every other field as captured; each rejected, none throttled "
                    f"(status distribution: {statuses}, burst ceiling {allowed}).")
        if self.confirm_reset_answer and completed >= self.min_attempts:
            return ValidationResult(
                self.name, "confirmed", fc, confidence=0.75, confirmed=True,
                summary=f"No limit on reset-answer guessing at {where}: {completed} wrong answers "
                        f"in a row were each rejected with no throttle or lockout.",
                evidence=evidence)
        why = ("validators.rate_limit.confirm_reset_answer is off (set false in config)"
               if not self.confirm_reset_answer else
               f"only {completed} of min_attempts {self.min_attempts} attempts were allowed")
        return ValidationResult(
            self.name, "not_confirmed", fc, confidence=0.5, confirmed=False,
            summary=f"Lead, not confirmed ({why}): {completed} wrong reset answers at {where} were "
                    f"each rejected with no throttle or lockout.",
            evidence=evidence, limitation=why,
            manual_verification="Confirm the reset answer can be guessed without limit for a "
                                "test account.")
