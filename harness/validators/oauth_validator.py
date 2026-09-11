"""
OAuth / OIDC Validator

Unlike CORS or cache poisoning, a full OAuth flow can't be validated
from a single captured exchange -- completing it requires a real user
session, consent screen interaction, and multi-step state that this
harness doesn't have. This validator is honest about that limit: it
does what CAN be checked from one exchange plus one active probe,
and nothing more.

Checks performed:
1. state parameter presence (passive -- read directly off this exchange)
2. PKCE (code_challenge) presence for authorization_code requests (passive)
3. Token-in-URL exposure for implicit/hybrid flows (passive)
4. redirect_uri exact-match enforcement (active -- one probe request
   with a modified redirect_uri, only attempted when this exchange
   looks like an authorization request)
"""

from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from models import Finding, HttpExchange

log = logging.getLogger("harness.validators.oauth")


@dataclass
class OAuthTestResult:
    test_name: str
    passed: bool
    severity: str
    detail: str
    evidence: str
    vulnerable: bool = False
    checked: bool = True  # False when the check didn't apply to this exchange at all

    def to_dict(self) -> dict:
        return {
            "test": self.test_name, "passed": self.passed, "severity": self.severity,
            "detail": self.detail, "evidence": self.evidence,
            "vulnerable": self.vulnerable, "checked": self.checked,
        }


class OAuthValidator(Validator):
    """
    Validator for OAuth 2.0 / OIDC authorization flow issues.

    Scope is deliberately limited to what a single captured exchange
    (plus one active redirect_uri probe) can establish. It does not
    attempt to complete an authorization flow, exchange a code for a
    token, or hold session state across requests.
    """

    name = "oauth_validator"
    finding_classes = {"oauth", "oauth2", "oidc", "openid connect"}
    active = True

    def __init__(self, timeout: float = 10.0, max_redirects: int = 0,
                 run_context=None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.run_context = run_context
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def get_name(self) -> str:
        return "oauth_validator"

    def get_capability(self) -> str:
        return "oauth_flow_validation"

    def get_execution_plane(self) -> str:
        return "local_tool"

    def plan(self, finding: Finding, exchange: HttpExchange) -> Any:
        from models import TestPlan
        from categories import canonicalize
        import hashlib
        import json

        # Plan ID must incorporate the FULL exchange, not just the URL --
        # see cors_validator.py's plan() for the real, live-reproduced
        # collision this fixes (two different real requests to the same
        # URL producing the same plan_id and clobbering each other).
        exchange_hash = hashlib.sha256(
            json.dumps(exchange.model_dump(), sort_keys=True).encode()
        ).hexdigest()[:16]
        plan_id = f"oauth_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"OAuth/OIDC flow validation for {finding.vulnerability_class}",
            success_signals=["Confirm missing state/PKCE, token exposure, or redirect_uri validation gap"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        tests: list[OAuthTestResult] = []
        try:
            tests.append(self._check_state_param(exchange))
            tests.append(self._check_pkce(exchange))
            tests.append(self._check_token_exposure(exchange))
            tests.append(await self._check_redirect_uri_validation(exchange))

            checked = [t for t in tests if t.checked]
            vulnerable = any(t.vulnerable for t in checked)
            if not checked:
                return ValidationResult(
                    validator=self.get_name(), status="skipped",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary="This exchange doesn't look like an OAuth/OIDC authorization or token "
                            "request (no recognizable OAuth query parameters) -- nothing to check",
                    evidence="", raw_output=self._build_raw_output(tests),
                )

            severities = [t.severity for t in checked if t.vulnerable]
            severity = "critical" if "critical" in severities else ("high" if "high" in severities else "medium")

            vulnerable_tests = [t for t in checked if t.vulnerable]
            summary_parts = []
            if vulnerable_tests:
                summary_parts.append(f"OAuth flow issue(s) confirmed: {len(vulnerable_tests)}")
                for t in vulnerable_tests:
                    summary_parts.append(f"  - {t.test_name}: {t.detail}")
            else:
                summary_parts.append("No OAuth flow issue confirmed by the checks this validator can run "
                                      "(note: this cannot complete a full flow or verify token binding "
                                      "server-side -- only what's visible in this exchange plus a "
                                      "redirect_uri probe)")

            return ValidationResult(
                validator=self.get_name(),
                status="confirmed" if vulnerable else "not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.75 if vulnerable else 0.2,
                confirmed=vulnerable,
                summary=" ".join(summary_parts),
                evidence=self._build_evidence(checked),
                raw_output=self._build_raw_output(tests),
            )
        except Exception as e:
            log.error(f"OAuth validation error: {e}")
            return ValidationResult(
                validator=self.get_name(), status="error",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=f"OAuth validation failed: {e}", evidence="", raw_output=str(e),
            )

    def _check_state_param(self, exchange: HttpExchange) -> OAuthTestResult:
        parsed = urlparse(exchange.url)
        qs = parse_qs(parsed.query)
        is_authz_request = "response_type" in qs and "client_id" in qs
        if not is_authz_request:
            return OAuthTestResult("State Parameter", True, "low", "Not an authorization request", "", checked=False)

        state = qs.get("state", [None])[0]
        if not state:
            return OAuthTestResult(
                "State Parameter", False, "high",
                "No state parameter on the authorization request -- the OAuth flow has no CSRF "
                "protection; an attacker can bind a victim's session to the attacker's own OAuth code",
                f"URL: {exchange.url}", vulnerable=True,
            )
        if len(state) < 8:
            return OAuthTestResult(
                "State Parameter", False, "medium",
                f"state parameter is only {len(state)} characters -- likely not enough entropy "
                "to resist guessing/brute-forcing",
                f"state={state}", vulnerable=True,
            )
        return OAuthTestResult("State Parameter", True, "low",
                                f"state parameter present ({len(state)} chars)", f"state={state}", vulnerable=False)

    def _check_pkce(self, exchange: HttpExchange) -> OAuthTestResult:
        parsed = urlparse(exchange.url)
        qs = parse_qs(parsed.query)
        is_code_flow = qs.get("response_type", [None])[0] == "code"
        if not is_code_flow:
            return OAuthTestResult("PKCE", True, "low", "Not an authorization_code request", "", checked=False)

        has_pkce = "code_challenge" in qs
        if not has_pkce:
            return OAuthTestResult(
                "PKCE", False, "medium",
                "No code_challenge on an authorization_code request. This is a confirmed gap if the "
                "client is public (SPA/mobile/CLI, i.e. cannot keep a client_secret confidential) -- "
                "check the client type before treating this as high severity, since confidential "
                "server-side clients are lower risk without PKCE",
                f"URL: {exchange.url}", vulnerable=True,
            )
        return OAuthTestResult("PKCE", True, "low", "code_challenge present", "", vulnerable=False)

    def _check_token_exposure(self, exchange: HttpExchange) -> OAuthTestResult:
        parsed = urlparse(exchange.url)
        qs = parse_qs(parsed.query)
        fragment_qs = parse_qs(parsed.fragment) if parsed.fragment else {}

        if "access_token" in qs:
            return OAuthTestResult(
                "Token Exposure", False, "high",
                "access_token present directly in the URL query string (not even fragment-based) -- "
                "goes into server access logs and any Referer header sent by the page",
                f"URL: {exchange.url}", vulnerable=True,
            )
        if "access_token" in fragment_qs:
            return OAuthTestResult(
                "Token Exposure", False, "medium",
                "access_token present in the URL fragment (implicit flow) -- stays out of server "
                "logs but still lands in browser history and any script that reads location.hash",
                f"fragment contains access_token", vulnerable=True,
            )
        if "code" in qs:
            return OAuthTestResult(
                "Token Exposure", True, "low",
                "Authorization code in query string (expected for the code flow) -- lower risk than "
                "a raw access token, but still worth confirming it's single-use and short-lived server-side",
                "", vulnerable=False,
            )
        return OAuthTestResult("Token Exposure", True, "low", "No token/code found in this exchange", "", checked=False)

    async def _check_redirect_uri_validation(self, exchange: HttpExchange) -> OAuthTestResult:
        parsed = urlparse(exchange.url)
        qs = parse_qs(parsed.query)
        redirect_uri = qs.get("redirect_uri", [None])[0]
        if not redirect_uri or "client_id" not in qs:
            return OAuthTestResult("Redirect URI Validation", True, "low",
                                    "Not an authorization request with a redirect_uri", "", checked=False)

        # Probe: append an extra path segment to the registered redirect_uri and
        # resend the authorization request. A server doing exact-match validation
        # rejects this; a server doing prefix matching will still redirect there.
        tampered = redirect_uri.rstrip("/") + "/oauth-validator-probe"
        new_qs = dict(qs)
        new_qs["redirect_uri"] = [tampered]
        flat_qs = {k: v[0] for k, v in new_qs.items()}
        probe_url = urlunparse(parsed._replace(query=urlencode(flat_qs)))

        try:
            if self.run_context is not None:
                from types import SimpleNamespace
                from run_context import TypedRequest
                outcome = await self.run_context.executor().execute(
                    TypedRequest("GET", probe_url, headers={"User-Agent": self.user_agent}),
                    capability=self.get_name(), max_redirects=self.max_redirects)
                if not outcome.ok:
                    raise httpx.TransportError(outcome.error or outcome.outcome)
                response = SimpleNamespace(status_code=outcome.status,
                                           headers=outcome.headers)
            else:
                async with httpx.AsyncClient(
                    timeout=self.timeout, follow_redirects=False, max_redirects=self.max_redirects,
                ) as client:
                    import global_throttle
                    await global_throttle.acquire()
                    response = await client.request(
                        "GET", probe_url,  # authorize endpoints are GET by spec; never replay the captured method
                        headers={"User-Agent": self.user_agent},
                    )
        except Exception as e:
            log.debug(f"redirect_uri probe failed: {e}")
            return OAuthTestResult("Redirect URI Validation", True, "low",
                                    "Could not send redirect_uri probe", "", checked=True, vulnerable=False)

        location = response.headers.get("Location", "")
        if response.status_code in (301, 302, 303, 307, 308) and location.startswith(tampered):
            return OAuthTestResult(
                "Redirect URI Validation", False, "high",
                "Authorization server redirected to a modified redirect_uri (extra path segment "
                "appended) instead of rejecting it -- validation is not exact-match, which means "
                "an attacker-controlled path under the same origin (or a broader bypass, depending "
                "on how loose the matching is) could receive the authorization code",
                f"Sent redirect_uri={tampered}, got {response.status_code} Location: {location}",
                vulnerable=True,
            )
        return OAuthTestResult(
            "Redirect URI Validation", True, "low",
            f"Tampered redirect_uri did not result in a redirect there (status {response.status_code}) "
            "-- consistent with exact-match validation, though this probe only tests one variant "
            "(appended path segment), not subdomain or scheme confusion",
            f"Status: {response.status_code}", vulnerable=False,
        )

    def _build_evidence(self, tests: list[OAuthTestResult]) -> str:
        vulnerable = [t for t in tests if t.vulnerable]
        if not vulnerable:
            return "No OAuth flow issues confirmed"
        return " | ".join(f"{t.test_name}: {t.detail} ({t.severity})" for t in vulnerable)

    def _build_raw_output(self, tests: list[OAuthTestResult]) -> str:
        import json
        return json.dumps([t.to_dict() for t in tests], indent=2)
