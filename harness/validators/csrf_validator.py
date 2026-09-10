"""
CSRF confirmation leg (V32, WSTG-SESS-09).

Deterministic property check: a state-changing request is accepted with NO
anti-CSRF token and NO SameSite cookie protection. The oracle:
  (a) the endpoint accepts a mutating method (POST/PUT/PATCH/DELETE),
  (b) replay without any CSRF token still succeeds (2xx),
  (c) the session cookie (if any) lacks SameSite=Lax|Strict.

(a∧b∧c) = CONFIRMED. This is a checkable property, not an execution proof
(same-origin policy is browser-enforced), but the combination is the standard
CSRF condition per WSTG. Active; mutating replay gated by allow_mutating_replay.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

import global_throttle
from models import Finding, HttpExchange
from safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import replay_headers

_CSRF_TOKEN_NAMES = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|__RequestVerificationToken|csrfmiddlewaretoken"
    r"|_csrf_token|anti.?forgery|nonce)",
    re.IGNORECASE)

_SAMESITE_RE = re.compile(r"SameSite\s*=\s*(Strict|Lax|None)", re.IGNORECASE)


def _has_csrf_token(exchange: HttpExchange) -> bool:
    """Check whether the original request carried any CSRF-like token."""
    body = exchange.request_body or ""
    url = exchange.url or ""
    headers = exchange.request_headers or {}
    for source in (body, url):
        if _CSRF_TOKEN_NAMES.search(source):
            return True
    for name in headers:
        if _CSRF_TOKEN_NAMES.search(name):
            return True
    return False


def _session_cookie_samesite(exchange: HttpExchange) -> str | None:
    """Return SameSite value of the session cookie, or None if no session cookie
    or no SameSite attribute."""
    resp_headers = exchange.response_headers or {}
    for name, value in resp_headers.items():
        if name.lower() != "set-cookie":
            continue
        cookie_name = value.split("=", 1)[0].strip().lower()
        if any(k in cookie_name for k in ("session", "sess", "sid", "auth", "token", "jwt")):
            m = _SAMESITE_RE.search(value)
            if m:
                return m.group(1)
            return None
    return None


class CsrfValidator(Validator):
    name = "csrf"
    finding_classes = {"csrf", "cross-site request forgery", "cross site request forgery", "xsrf"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.run_context = run_context

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        method = (exchange.method or "GET").upper()
        return method in ("POST", "PUT", "PATCH", "DELETE")

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "csrf", summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")

        method = (exchange.method or "GET").upper()
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            return self._skip("endpoint does not accept a state-changing method")

        samesite = _session_cookie_samesite(exchange)
        if samesite and samesite.lower() in ("strict", "lax"):
            return ValidationResult(
                self.name, "not_confirmed", "csrf", confidence=0.0, confirmed=False,
                summary=f"Session cookie has SameSite={samesite} — CSRF mitigated.",
                evidence=f"SameSite={samesite} prevents cross-site request submission.")

        headers = replay_headers(exchange)
        strip_headers = dict(headers or {})
        for name in list(strip_headers.keys()):
            if _CSRF_TOKEN_NAMES.search(name):
                del strip_headers[name]

        body = exchange.request_body or ""
        stripped_body = _CSRF_TOKEN_NAMES.sub("REMOVED", body) if body else ""

        try:
            if self.run_context is not None:
                from run_context import TypedRequest
                from .transport import bind_session
                session_ref, request_headers = bind_session(self.run_context, strip_headers)
                outcome = await self.run_context.executor().execute(
                    TypedRequest(method, exchange.url, headers=request_headers,
                                 body=stripped_body or None),
                    capability=self.name, session_ref=session_ref)
                if not outcome.executed:
                    return self._skip(f"CSRF replay declined: {outcome.outcome}")
                if outcome.outcome == "error":
                    return ValidationResult(self.name, "error", "csrf",
                                            summary=f"HTTP error during replay: {outcome.error}")
                status_code = outcome.status or 0
            else:
                await global_throttle.acquire()
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    resp = await client.request(method, exchange.url,
                                                headers=strip_headers or None,
                                                content=stripped_body or None)
                status_code = resp.status_code
        except SafetyGateBlocked:
            return self._skip("mutating CSRF replay not authorized (set validators.allow_mutating_replay)")
        except httpx.HTTPError as e:
            return ValidationResult(
                self.name, "error", "csrf", summary=f"HTTP error during replay: {e}")

        if 200 <= status_code < 300:
            token_present = _has_csrf_token(exchange)
            evidence_parts = [
                f"Replayed {method} {exchange.url} without CSRF token → {status_code}.",
            ]
            if not token_present:
                evidence_parts.append("Original request also carried no CSRF token.")
            if samesite:
                evidence_parts.append(f"Session cookie SameSite={samesite} (not protective).")
            else:
                evidence_parts.append("No SameSite attribute on session cookie.")

            # RETIRED (review 2026-09-09): a token-strip replay returning 2xx does
            # NOT prove CSRF -- it does not show a victim BROWSER can send the
            # request with AMBIENT credentials. Bearer/JSON APIs aren't ambient,
            # Origin/Referer may be enforced server-side, and a default SameSite=Lax
            # already blocks cross-site POSTs even with "no SameSite" in this
            # response. This no longer sets confirmed=True. Re-qualify: a cross-site
            # browser PoC that fires the request with the victim's ambient cookies
            # and independently verifies the state change, plus controls for
            # bearer-only requests, Origin enforcement and default-SameSite; only
            # then confirmed=True (and re-add "csrf" to the gate's LIVE set).
            return ValidationResult(
                self.name, "not_confirmed", "csrf", confidence=0.4, confirmed=False,
                summary=f"OBSERVATION (not confirmed): {method} request was accepted without an "
                        f"anti-CSRF token. NOT a confirmed CSRF -- needs a cross-site browser PoC "
                        f"with ambient credentials (this replay proves neither ambient-credential "
                        f"delivery nor absence of Origin/SameSite protection).",
                evidence=" ".join(evidence_parts))

        return ValidationResult(
            self.name, "not_confirmed", "csrf", confidence=0.0, confirmed=False,
            summary=f"Replay without CSRF token returned {status_code} (rejected).",
            evidence=f"{method} {exchange.url} without token → {status_code}.")
