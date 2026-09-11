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
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

import global_throttle
from models import Finding, HttpExchange
from safety_gate import get_default_gate
from .base import Validator, ValidationResult

# Language / signals that a rate limit or lockout DID engage -- any of these on
# any attempt refutes "no rate limiting".
_THROTTLE_MARKERS = re.compile(
    r"rate ?limit|too many (requests|attempts)|slow down|try again later|"
    r"temporarily (locked|blocked)|account (locked|is locked)|lockout|"
    r"throttl|429|retry.?after",
    re.IGNORECASE,
)


class RateLimitValidator(Validator):
    name = "rate_limit"
    finding_classes = {"rate_limit", "rate limit", "no rate limiting", "missing rate limit",
                       "missing rate limiting", "brute force", "brute_force", "brute-force",
                       "account lockout", "weak lockout", "lockout", "no lockout"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 min_attempts: int = 5, run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.min_attempts = max(2, int(min_attempts))
        self.run_context = run_context

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
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        method = (exchange.method or "POST").upper()

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
        try:
            client = None if self.run_context is not None else httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=False, verify=False)
            try:
                for _ in range(allowed):
                    try:
                        if self.run_context is not None:
                            from types import SimpleNamespace
                            from run_context import TypedRequest
                            from .transport import bind_session
                            session_ref, request_headers = bind_session(self.run_context, headers)
                            result = await self.run_context.executor().execute(
                                TypedRequest(method, exchange.url, headers=request_headers,
                                             body=content),
                                capability=self.name, session_ref=session_ref)
                            if not result.ok:
                                continue
                            resp = SimpleNamespace(status_code=result.status,
                                                   text=result.body, headers=result.headers)
                        else:
                            await global_throttle.acquire()
                            resp = await client.request(method, exchange.url,
                                                        headers=headers or None, content=content)
                    except httpx.HTTPError:
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
