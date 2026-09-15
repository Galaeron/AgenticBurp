"""
CORS Misconfiguration Validator

This validator performs active testing of CORS misconfigurations
by sending crafted requests and analyzing responses.

Tests performed:
1. Wildcard origin reflection
2. Null origin reflection
3. Credentials + wildcard combination
4. Preflight bypass
5. Header injection via Allow-Headers: *
6. Cache poisoning
7. Inconsistent preflight/actual response
"""

from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

from safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from models import Finding, HttpExchange

log = logging.getLogger("harness.validators.cors")


@dataclass
class CorsTestResult:
    """Result of a CORS test."""
    test_name: str
    passed: bool
    severity: str
    detail: str
    evidence: str
    vulnerable: bool = False
    
    def to_dict(self) -> dict:
        return {
            "test": self.test_name,
            "passed": self.passed,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
            "vulnerable": self.vulnerable,
        }


class CorsValidator(Validator):
    """
    Validator for CORS misconfigurations.
    
    Performs active testing by sending crafted Origin headers
    and analyzing the CORS headers in responses.
    """
    
    name = "cors_validator"
    finding_classes = {"cors", "cors misconfiguration", "cross-origin resource sharing"}
    active = True
    
    def __init__(self, timeout: float = 10.0, max_redirects: int = 5,
                 run_context=None, allowed_hosts: list[str] | None = None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.run_context = run_context
        # Scope guard: like ssrf/xxe/etc., refuse to probe a host outside the
        # configured engagement scope. Passed from the registry
        # (server.allowed_hosts). Empty means "not scoped here" -- the central
        # backstop in orchestrator dispatch (W-2) still applies.
        self.allowed_hosts = allowed_hosts or []
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(
            validator=self.get_name(), status="skipped",
            finding_class="cors", confidence=0.0, confirmed=False,
            summary=why, evidence="", raw_output="",
        )

    def get_name(self) -> str:
        return "cors_validator"
    
    def get_capability(self) -> str:
        return "cors_misconfiguration_detection"
    
    def get_execution_plane(self) -> str:
        return "local_tool"
    
    def plan(self, finding: Finding, exchange: HttpExchange) -> Any:
        """Generate a test plan for CORS validation."""
        from models import TestPlan
        from categories import canonicalize
        import hashlib
        import json

        # Plan ID must incorporate the FULL exchange, not just the URL --
        # found live, against a real Juice Shop run: two different real
        # requests to the same URL (two separate login attempts) produced
        # the exact same plan_id (URL + vulnerability_class only), so the
        # second one's stored source_exchange_hash silently clobbered the
        # first's, and the first's later validation submission was
        # rejected as a "binding_mismatch" -- confirmed live, not
        # hypothetical. Reusing the already-computed full-exchange hash
        # for the plan_id too (not just source_exchange_hash) closes this.
        exchange_hash = hashlib.sha256(
            json.dumps(exchange.model_dump(), sort_keys=True).encode()
        ).hexdigest()[:16]
        plan_id = f"cors_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"CORS misconfiguration validation for {finding.vulnerability_class}",
            success_signals=["Confirm CORS misconfiguration and identify specific vulnerability"],
            source_exchange_hash=exchange_hash,
        )
    
    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        """
        Validate a CORS misconfiguration finding.
        
        Performs multiple CORS tests against the target endpoint.
        """
        
        tests = []
        vulnerable = False

        # Scope guard (defense-in-depth with the central backstop): never send
        # crafted-Origin probes to a host outside the configured engagement.
        host = urlparse(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")

        # Extract base URL for testing
        base_url = self._get_base_url(exchange.url)
        if not base_url:
            return ValidationResult(
                validator=self.get_name(),
                status="error",
                finding_class=finding.vulnerability_class,
                confidence=0.0,
                confirmed=False,
                summary="Could not determine base URL for testing",
                evidence="",
                raw_output="",
            )
        
        # Run all CORS tests
        try:
            tests.append(await self._test_wildcard_origin(base_url, exchange))
            tests.append(await self._test_null_origin(base_url, exchange))
            tests.append(await self._test_credentials_wildcard(base_url, exchange))
            tests.append(await self._test_preflight_bypass(base_url, exchange))
            tests.append(await self._test_vary_origin(base_url, exchange))
            tests.append(await self._test_allow_headers_wildcard(base_url, exchange))
            tests.append(await self._test_expose_headers(base_url, exchange))
            tests.append(await self._test_max_age(base_url, exchange))
            
            # Check if any test found a vulnerability
            vulnerable = any(t.vulnerable for t in tests)
            
            # Determine severity
            if vulnerable:
                severities = [t.severity for t in tests if t.vulnerable]
                if "critical" in severities or "high" in severities:
                    severity = "high"
                else:
                    severity = "medium"
            else:
                severity = "low"
            
            # Build summary
            vulnerable_tests = [t for t in tests if t.vulnerable]
            passed_tests = [t for t in tests if t.passed and not t.vulnerable]
            
            summary_parts = []
            if vulnerable_tests:
                summary_parts.append(f"CORS misconfiguration CONFIRMED: {len(vulnerable_tests)} vulnerability(ies) found")
                for t in vulnerable_tests:
                    summary_parts.append(f"  - {t.test_name}: {t.detail}")
            else:
                summary_parts.append("CORS configuration appears secure")
            
            if passed_tests:
                summary_parts.append(f"  Passed: {len(passed_tests)} tests")
            
            return ValidationResult(
                validator=self.get_name(),
                status="confirmed" if vulnerable else "safe",
                finding_class=finding.vulnerability_class,
                confidence=0.95 if vulnerable else 0.1,
                confirmed=vulnerable,
                summary=" ".join(summary_parts),
                evidence=self._build_evidence(tests),
                raw_output=self._build_raw_output(tests),
            )
            
        except Exception as e:
            log.error(f"CORS validation error: {e}")
            return ValidationResult(
                validator=self.get_name(),
                status="error",
                finding_class=finding.vulnerability_class,
                confidence=0.0,
                confirmed=False,
                summary=f"CORS validation failed: {e}",
                evidence="",
                raw_output=str(e),
            )
    
    def _get_base_url(self, url: str) -> str:
        """Extract base URL from a full URL."""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        # Remove path and query
        return f"{parsed.scheme}://{parsed.netloc}"
    
    async def _send_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict = None,
        follow_redirects: bool = False,
    ) -> httpx.Response | None:
        """Send an HTTP request with custom headers."""
        headers = headers or {}
        headers["User-Agent"] = self.user_agent

        try:
            if self.run_context is not None:
                from run_context import TypedRequest
                outcome = await self.run_context.executor().execute(
                    TypedRequest(method, url, headers=headers),
                    capability=self.get_name(),
                    max_redirects=self.max_redirects if follow_redirects else 0)
                if not outcome.ok:
                    return None
                return httpx.Response(
                    outcome.status or 0, content=(outcome.body or "").encode(),
                    headers=outcome.headers, request=httpx.Request(method, url))
            import global_throttle
            await global_throttle.acquire()
            # No run_context (e.g. the header-audit or a standalone path): route
            # through the SafetyGate rather than a raw client, so this validator
            # can never send an ungated request when active mode is on. CORS
            # probes are GET/OPTIONS only (see _test_preflight_bypass), so the
            # gate admits them without allow_mutating_replay.
            async with GatedAsyncClient(
                get_default_gate(), self.get_name(),
                timeout=self.timeout,
                follow_redirects=follow_redirects,
                max_redirects=self.max_redirects,
            ) as client:
                return await client.request(method, url, headers=headers)
        except SafetyGateBlocked as e:
            log.debug(f"CORS request blocked by safety gate: {e}")
            return None
        except Exception as e:
            log.debug(f"Request failed: {e}")
            return None
    
    async def _test_wildcard_origin(self, base_url: str, exchange: HttpExchange) -> CorsTestResult:
        """Test if server reflects wildcard origin."""
        # Test with arbitrary origin
        test_origin = "https://evil-attacker.com"
        
        headers = {
            "Origin": test_origin,
        }
        
        # Try both GET and POST (depending on original method)
        for method in ["GET"]:  # CORS reflection is method-independent; never replay a captured mutating method
            response = await self._send_request(
                exchange.url,
                method=method,
                headers=headers,
            )
            
            if response is None:
                continue
            
            # Check for wildcard
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                # A bare `Access-Control-Allow-Origin: *` WITHOUT
                # `Access-Control-Allow-Credentials: true` is NOT a
                # vulnerability -- it's the intended, low-risk pattern for a
                # public read-only API, and browsers forbid sending
                # credentials to a wildcard origin. Marking it vulnerable here
                # was the single largest source of false "confirmed" findings
                # in the Juice Shop run (58 of 60 confirmations traced to this
                # check firing on secure and vulnerable endpoints alike). The
                # genuinely dangerous combination -- wildcard AND credentials
                # -- is caught, gated correctly, by _test_credentials_wildcard
                # below; the bare case is reported as informational only so it
                # never flips the finding's `confirmed` flag.
                if acac.lower() == "true":
                    return CorsTestResult(
                        test_name="Wildcard Origin + Credentials",
                        passed=False,
                        severity="critical",
                        detail="Server returns Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true (spec violation, credentialed cross-origin reads possible)",
                        evidence="Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                        vulnerable=True,
                    )
                return CorsTestResult(
                    test_name="Wildcard Origin",
                    passed=True,
                    severity="info",
                    detail="Server returns Access-Control-Allow-Origin: * without Access-Control-Allow-Credentials -- the intended, low-risk pattern for a public read-only API. Informational, not exploitable on its own.",
                    evidence="Response header: Access-Control-Allow-Origin: * (no Allow-Credentials)",
                    vulnerable=False,
                )

            # Check if our origin is reflected
            if acao.lower() == test_origin.lower():
                return CorsTestResult(
                    test_name="Origin Reflection",
                    passed=False,
                    severity="medium",
                    detail=f"Server reflects arbitrary Origin header",
                    evidence=f"Origin: {test_origin} -> Access-Control-Allow-Origin: {acao}",
                    vulnerable=True,
                )
        
        return CorsTestResult(
            test_name="Wildcard Origin",
            passed=True,
            severity="low",
            detail="Server does not use wildcard origin",
            evidence="",
            vulnerable=False,
        )
    
    async def _test_null_origin(self, base_url: str, exchange: HttpExchange) -> CorsTestResult:
        """Test if server allows null origin."""
        headers = {
            "Origin": "null",
        }
        
        for method in ["GET"]:  # CORS reflection is method-independent; never replay a captured mutating method
            response = await self._send_request(
                exchange.url,
                method=method,
                headers=headers,
            )
            
            if response is None:
                continue
            
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            
            if acao.lower() == "null":
                return CorsTestResult(
                    test_name="Null Origin",
                    passed=False,
                    severity="high",
                    detail="Server allows null origin (can be exploited from sandboxed iframes)",
                    evidence=f"Origin: null -> Access-Control-Allow-Origin: {acao}",
                    vulnerable=True,
                )
        
        return CorsTestResult(
            test_name="Null Origin",
            passed=True,
            severity="low",
            detail="Server does not allow null origin",
            evidence="",
            vulnerable=False,
        )
    
    async def _test_credentials_wildcard(self, base_url: str, exchange: HttpExchange) -> CorsTestResult:
        """Test if server allows credentials with wildcard origin."""
        # This is a spec violation but some browsers allow it
        test_origin = "https://evil-attacker.com"
        
        headers = {
            "Origin": test_origin,
        }
        
        for method in ["GET"]:  # CORS reflection is method-independent; never replay a captured mutating method
            response = await self._send_request(
                exchange.url,
                method=method,
                headers=headers,
            )
            
            if response is None:
                continue
            
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")
            
            # Check for the dangerous combination
            if acao == "*" and acac.lower() == "true":
                return CorsTestResult(
                    test_name="Credentials + Wildcard",
                    passed=False,
                    severity="critical",
                    detail="Server allows credentials with wildcard origin (spec violation, critical vulnerability)",
                    evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                    vulnerable=True,
                )
        
        return CorsTestResult(
            test_name="Credentials + Wildcard",
            passed=True,
            severity="low",
            detail="Server does not allow credentials with wildcard",
            evidence="",
            vulnerable=False,
        )
    
    async def _test_preflight_bypass(self, base_url: str, exchange: HttpExchange) -> CorsTestResult:
        """Test if preflight can be bypassed."""
        # Whether the server hands back per-origin CORS headers on a plain
        # ("simple") request that browsers never preflight is method-INDEPENDENT
        # -- it depends on the Origin, not the verb -- so we probe with GET and
        # never send a mutating method (a POST here was an ungated state-changing
        # request to the target; see W-1). The OPTIONS preflight below is also
        # non-mutating.
        test_origin = "https://evil-attacker.com"
        headers = {
            "Origin": test_origin,
        }

        # Simple GET carrying the attacker Origin -- browsers do not preflight it.
        response = await self._send_request(
            exchange.url,
            method="GET",
            headers=headers,
        )
        
        if response is None:
            return CorsTestResult(
                test_name="Preflight Bypass",
                passed=True,
                severity="low",
                detail="Could not test preflight bypass",
                evidence="",
                vulnerable=False,
            )
        
        # Check if CORS headers are present without preflight
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        
        if acao and acao != "*" and acao.lower() != test_origin.lower():
            # Server returns CORS headers without proper preflight
            return CorsTestResult(
                test_name="Preflight Bypass",
                passed=False,
                severity="medium",
                detail="Server returns CORS headers without proper preflight validation",
                evidence=f"Simple GET with attacker Origin returned Access-Control-Allow-Origin: {acao}",
                vulnerable=True,
            )
        
        # Test actual preflight
        preflight_response = await self._send_request(
            exchange.url,
            method="OPTIONS",
            headers={
                "Origin": test_origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        
        if preflight_response is None:
            return CorsTestResult(
                test_name="Preflight Bypass",
                passed=True,
                severity="low",
                detail="Could not test preflight",
                evidence="",
                vulnerable=False,
            )
        
        # Check if preflight response differs from actual response
        preflight_acao = preflight_response.headers.get("Access-Control-Allow-Origin", "")
        if acao and preflight_acao and acao != preflight_acao:
            return CorsTestResult(
                test_name="Preflight Inconsistency",
                passed=False,
                severity="medium",
                detail="Preflight and actual response have different CORS headers",
                evidence=f"Preflight: {preflight_acao}, Actual: {acao}",
                vulnerable=True,
            )
        
        return CorsTestResult(
            test_name="Preflight Bypass",
            passed=True,
            severity="low",
            detail="Preflight handling appears correct",
            evidence="",
            vulnerable=False,
        )
    
    async def _test_vary_origin(self, base_url: str, exchange: HttpExchange) -> CorsTestResult:
        """Test if Vary: Origin header is present."""
        test_origin = "https://evil-attacker.com"
        headers = {
            "Origin": test_origin,
        }
        
        response = await self._send_request(
            exchange.url,
            headers=headers,
        )
        
        if response is None:
            return CorsTestResult(
                test_name="Vary Origin",
                passed=True,
                severity="low",
                detail="Could not test Vary header",
                evidence="",
                vulnerable=False,
            )
        
        vary = response.headers.get("Vary", "").lower()
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        reflects_origin = acao.lower() == test_origin.lower()

        if "origin" not in vary:
            # A missing `Vary: Origin` is ONLY a real cache-poisoning risk
            # when the server REFLECTS the request Origin into
            # Access-Control-Allow-Origin (a per-origin/dynamic value a
            # shared cache could then serve to the wrong origin). With a
            # static `*` ACAO -- or no ACAO at all -- there is nothing
            # origin-specific to cache, so a missing Vary: Origin is
            # harmless. Flagging it unconditionally was the SECOND driver of
            # the Juice Shop CORS false-confirmation storm (after
            # _test_wildcard_origin), independently keeping the finding
            # confirmed via validate()'s any(t.vulnerable) OR even after the
            # wildcard case was downgraded. Only the reflected case is
            # vulnerable; otherwise this is informational.
            if reflects_origin:
                return CorsTestResult(
                    test_name="Vary Origin",
                    passed=False,
                    severity="medium",
                    detail="Reflected Origin without Vary: Origin (a shared cache may serve one origin's CORS response to another)",
                    evidence=f"Access-Control-Allow-Origin: {acao} (reflected), Vary: {vary or '(absent)'}",
                    vulnerable=True,
                )
            return CorsTestResult(
                test_name="Vary Origin",
                passed=True,
                severity="info",
                detail="Missing Vary: Origin, but Access-Control-Allow-Origin is not origin-reflected (static/wildcard/absent) -- no origin-specific response to cache-poison. Informational.",
                evidence=f"Access-Control-Allow-Origin: {acao or '(absent)'}, Vary: {vary or '(absent)'}",
                vulnerable=False,
            )

        return CorsTestResult(
            test_name="Vary Origin",
            passed=True,
            severity="low",
            detail="Vary: Origin header is present",
            evidence=f"Vary: {vary}",
            vulnerable=False,
        )
    
    async def _test_allow_headers_wildcard(self, base_url: str, exchange: HttpExchange) -> CorsTestResult:
        """Test if Access-Control-Allow-Headers: * is present."""
        test_origin = "https://evil-attacker.com"
        headers = {
            "Origin": test_origin,
        }
        
        response = await self._send_request(
            exchange.url,
            headers=headers,
        )
        
        if response is None:
            return CorsTestResult(
                test_name="Allow-Headers Wildcard",
                passed=True,
                severity="low",
                detail="Could not test Allow-Headers",
                evidence="",
                vulnerable=False,
            )
        
        acah = response.headers.get("Access-Control-Allow-Headers", "")
        
        if acah == "*":
            return CorsTestResult(
                test_name="Allow-Headers Wildcard",
                passed=False,
                severity="medium",
                detail="Access-Control-Allow-Headers: * allows any header (can bypass header-based security)",
                evidence=f"Access-Control-Allow-Headers: {acah}",
                vulnerable=True,
            )
        
        return CorsTestResult(
            test_name="Allow-Headers Wildcard",
            passed=True,
            severity="low",
            detail="Allow-Headers is not wildcard",
            evidence=f"Access-Control-Allow-Headers: {acah}",
            vulnerable=False,
        )
    
    async def _test_expose_headers(self, base_url: str, exchange: HttpExchange) -> CorsTestResult:
        """Test if sensitive headers are exposed."""
        test_origin = "https://evil-attacker.com"
        headers = {
            "Origin": test_origin,
        }
        
        response = await self._send_request(
            exchange.url,
            headers=headers,
        )
        
        if response is None:
            return CorsTestResult(
                test_name="Expose Headers",
                passed=True,
                severity="low",
                detail="Could not test Expose-Headers",
                evidence="",
                vulnerable=False,
            )
        
        aceh = response.headers.get("Access-Control-Expose-Headers", "").lower()
        
        sensitive_headers = ["authorization", "cookie", "set-cookie", "proxy-authorization"]
        
        for sh in sensitive_headers:
            if sh in aceh:
                return CorsTestResult(
                    test_name="Expose Headers",
                    passed=False,
                    severity="high",
                    detail=f"Sensitive header '{sh}' exposed via Access-Control-Expose-Headers",
                    evidence=f"Access-Control-Expose-Headers: {aceh}",
                    vulnerable=True,
                )
        
        if aceh == "*":
            return CorsTestResult(
                test_name="Expose Headers",
                passed=False,
                severity="medium",
                detail="Access-Control-Expose-Headers: * (exposes all headers)",
                evidence=f"Access-Control-Expose-Headers: {aceh}",
                vulnerable=True,
            )
        
        return CorsTestResult(
            test_name="Expose Headers",
            passed=True,
            severity="low",
            detail="No sensitive headers exposed",
            evidence=f"Access-Control-Expose-Headers: {aceh}",
            vulnerable=False,
        )
    
    async def _test_max_age(self, base_url: str, exchange: HttpExchange) -> CorsTestResult:
        """Test if Access-Control-Max-Age is too high."""
        test_origin = "https://evil-attacker.com"
        headers = {
            "Origin": test_origin,
        }
        
        response = await self._send_request(
            exchange.url,
            headers=headers,
        )
        
        if response is None:
            return CorsTestResult(
                test_name="Max Age",
                passed=True,
                severity="low",
                detail="Could not test Max-Age",
                evidence="",
                vulnerable=False,
            )
        
        acma = response.headers.get("Access-Control-Max-Age", "")
        
        if acma:
            try:
                max_age = int(acma)
                # More than 1 hour (3600 seconds) is suspicious
                if max_age > 3600:
                    return CorsTestResult(
                        test_name="Max Age",
                        passed=False,
                        severity="low",
                        detail=f"Access-Control-Max-Age is very high ({max_age}s), allows preflight cache poisoning",
                        evidence=f"Access-Control-Max-Age: {acma}",
                        vulnerable=True,
                    )
            except ValueError:
                pass
        
        return CorsTestResult(
            test_name="Max Age",
            passed=True,
            severity="low",
            detail="Max-Age is reasonable",
            evidence=f"Access-Control-Max-Age: {acma}",
            vulnerable=False,
        )
    
    def _build_evidence(self, tests: list[CorsTestResult]) -> str:
        """Build evidence string from test results."""
        vulnerable = [t for t in tests if t.vulnerable]
        if not vulnerable:
            return "No CORS vulnerabilities detected"
        
        parts = []
        for t in vulnerable:
            parts.append(f"{t.test_name}: {t.detail} ({t.severity})")
        return " | ".join(parts)
    
    def _build_raw_output(self, tests: list[CorsTestResult]) -> str:
        """Build raw output from test results."""
        import json
        return json.dumps([t.to_dict() for t in tests], indent=2)
