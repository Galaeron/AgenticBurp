"""
HTTP Request Smuggling Validator

This validator performs active testing for HTTP Request Smuggling vulnerabilities
(CL.TE, TE.CL, TE.TE) by sending crafted requests and analyzing responses.
"""

from __future__ import annotations
import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from models import Finding, HttpExchange

log = logging.getLogger("harness.validators.http_request_smuggling")


@dataclass
class SmugglingTestResult:
    """Result of a request smuggling test."""
    test_type: str  # cl_te, te_cl, te_te
    vulnerable: bool
    severity: str
    detail: str
    evidence: str
    confidence: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            "test_type": self.test_type,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


class HttpRequestSmugglingValidator(Validator):
    """
    Validator for HTTP Request Smuggling vulnerabilities.
    
    Performs active testing by sending crafted requests with conflicting
    Content-Length and Transfer-Encoding headers.
    """
    
    name = "http_request_smuggling_validator"
    finding_classes = {
        "http_request_smuggling",
        "request smuggling",
        "http smuggling",
        "cl.te",
        "te.cl",
        "te.te",
    }
    active = True
    
    def __init__(self, timeout: float = 30.0, max_redirects: int = 0,
                 run_context=None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.run_context = run_context
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        self.client: httpx.AsyncClient | None = None
    
    async def __aenter__(self):
        if self.run_context is None:
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                max_redirects=self.max_redirects,
            )
        return self
    
    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()
    
    def get_name(self) -> str:
        return self.name
    
    def get_capability(self) -> str:
        return "http_request_smuggling_detection"
    
    def get_execution_plane(self) -> str:
        return "local_tool"
    
    def plan(self, finding: Finding, exchange: HttpExchange) -> Any:
        """Generate a test plan for HRS validation."""
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
        plan_id = f"hrs_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            # smuggling technique requires a body-bearing method; never replay the captured method verbatim
            rationale=f"HTTP Request Smuggling detection for {exchange.url} (test_types: cl_te, te_cl, te_te)",
            success_signals=["Detect CL.TE, TE.CL, or TE.TE request smuggling vulnerabilities"],
            source_exchange_hash=exchange_hash,
        )
    
    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        """
        Validate an HRS finding by testing for request smuggling vulnerabilities.
        """
        try:
            base_url = self._get_base_url(exchange.url)
            if not base_url:
                return ValidationResult(
                    validator=self.name,
                    status="error",
                    finding_class=finding.vulnerability_class,
                    confidence=0.0,
                    confirmed=False,
                    summary=f"Could not determine base URL from {exchange.url}",
                    evidence="",
                    raw_output="",
                )
            
            # Perform HRS tests
            tests = await self._perform_hrs_tests(base_url, exchange)
            
            # Check results
            vulnerable_tests = [t for t in tests if t.vulnerable]
            vulnerable = len(vulnerable_tests) > 0
            
            if vulnerable:
                severities = [t.severity for t in vulnerable_tests]
                if "critical" in severities:
                    severity = "critical"
                elif "high" in severities:
                    severity = "high"
                else:
                    severity = "medium"
            else:
                severity = "low"
            
            # RETIRED (review 2026-09-09): a status change / unexpected length / 404
            # from these probes is NOT a confirmed desync -- _send_raw_request uses
            # ordinary httpx and cannot guarantee the claimed raw CL/TE framing or the
            # front-end/back-end connection relationship. This no longer emits a
            # confirmed verdict; a match is a CANDIDATE. Re-qualify: protocol-specific
            # raw transport that controls framing on a kept-alive connection, proven
            # against a paired front-end/back-end desync fixture; only then confirmed=True.
            summary_parts = []
            if vulnerable:
                summary_parts.append(
                    f"HTTP Request Smuggling CANDIDATE (not confirmed): {len(vulnerable_tests)} "
                    f"anomaly type(s) -- ordinary-httpx probe cannot prove raw desync framing")
                for t in vulnerable_tests:
                    summary_parts.append(f"  - {t.test_type.upper()}: {t.detail}")
            else:
                summary_parts.append("No HTTP Request Smuggling anomalies detected")

            return ValidationResult(
                validator=self.name,
                status="not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.4 if vulnerable else 0.1,
                confirmed=False,
                summary=" | ".join(summary_parts),
                evidence=self._build_evidence(tests),
                raw_output=self._build_raw_output(tests),
            )
            
        except Exception as e:
            log.error(f"HRS validation error: {e}")
            import traceback
            return ValidationResult(
                validator=self.name,
                status="error",
                finding_class=finding.vulnerability_class,
                confidence=0.0,
                confirmed=False,
                summary=f"HRS validation failed: {e}",
                evidence="",
                raw_output=traceback.format_exc(),
            )
    
    def _get_base_url(self, url: str) -> str:
        """Extract base URL from a full URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    async def _perform_hrs_tests(self, base_url: str, exchange: HttpExchange) -> list[SmugglingTestResult]:
        """Perform all HRS test types."""
        tests = []
        
        # Ensure client is initialized
        if self.run_context is None and not self.client:
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                max_redirects=self.max_redirects,
            )
        
        # Test CL.TE
        tests.append(await self._test_cl_te(base_url, exchange))
        
        # Test TE.CL
        tests.append(await self._test_te_cl(base_url, exchange))
        
        # Test TE.TE
        tests.append(await self._test_te_te(base_url, exchange))
        
        return tests
    
    async def _test_cl_te(self, base_url: str, exchange: HttpExchange) -> SmugglingTestResult:
        """
        Test for CL.TE vulnerability.
        
        Front-end uses Content-Length, back-end uses Transfer-Encoding.
        """
        # Build CL.TE payload
        # POST with both Content-Length and Transfer-Encoding
        # Body: "0\r\n\r\nGET /404 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        smuggled_request = "GET /404 HTTP/1.1\r\nHost: " + base_url.split('//')[1] + "\r\n\r\n"
        body = "0\r\n\r\n" + smuggled_request
        
        # Content-Length is the length of "0\r\n\r\n" (6 bytes)
        headers = {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
            "User-Agent": self.user_agent,
            "Connection": "keep-alive",
        }
        
        try:
            # Send the smuggled request
            response1 = await self._send_raw_request(
                "POST",  # smuggling technique requires a body-bearing method; never replay the captured method
                exchange.url,
                headers=headers,
                body=body,
            )
            
            if response1 is None:
                return SmugglingTestResult(
                    test_type="cl_te",
                    vulnerable=False,
                    severity="low",
                    detail="Could not send CL.TE test request",
                    evidence="",
                    confidence=0.0,
                )
            
            # Send a follow-up request on the same connection
            # If vulnerable, this might return the smuggled request's response
            followup_headers = {
                "User-Agent": self.user_agent,
                "Connection": "keep-alive",
            }
            
            # Wait a moment for the smuggled request to be processed
            await asyncio.sleep(0.5)
            
            response2 = await self._send_raw_request(
                "GET",
                exchange.url,
                headers=followup_headers,
                body="",
            )
            
            # Check if the follow-up request returned the smuggled response
            if response2 and response2.status_code == 404:
                return SmugglingTestResult(
                    test_type="cl_te",
                    vulnerable=True,
                    severity="critical",
                    detail="CL.TE vulnerability confirmed - smuggled request was processed",
                    evidence=f"Smuggled GET /404 returned 404 in follow-up request",
                    confidence=0.95,
                )
            
            # Alternative detection: check if response contains unexpected content
            if response1 and self._is_unexpected_response(response1, exchange):
                return SmugglingTestResult(
                    test_type="cl_te",
                    vulnerable=True,
                    severity="critical",
                    detail="CL.TE vulnerability suspected - unexpected response received",
                    evidence=f"Response status: {response1.status_code}, content length: {len(response1.text)}",
                    confidence=0.85,
                )
            
            return SmugglingTestResult(
                test_type="cl_te",
                vulnerable=False,
                severity="low",
                detail="No CL.TE vulnerability detected",
                evidence="",
                confidence=0.1,
            )
            
        except Exception as e:
            log.debug(f"CL.TE test error: {e}")
            return SmugglingTestResult(
                test_type="cl_te",
                vulnerable=False,
                severity="low",
                detail=f"CL.TE test failed: {e}",
                evidence="",
                confidence=0.0,
            )
    
    async def _test_te_cl(self, base_url: str, exchange: HttpExchange) -> SmugglingTestResult:
        """
        Test for TE.CL vulnerability.
        
        Front-end uses Transfer-Encoding, back-end uses Content-Length.
        """
        # Build TE.CL payload
        # POST with both Content-Length and Transfer-Encoding: chunked
        # Body: chunked encoding with Content-Length that doesn't match
        
        smuggled_request = "GET /404 HTTP/1.1\r\nHost: " + base_url.split('//')[1] + "\r\n\r\n"
        
        # We'll send: chunk size (hex) + data + chunk size 0
        # Content-Length should be smaller than the actual chunked body
        chunk_data = smuggled_request
        chunk_size = len(chunk_data)
        chunk_size_hex = format(chunk_size, 'x')
        
        # Body: chunk_size_hex\r\nchunk_data\r\n0\r\n\r\n
        body = f"{chunk_size_hex}\r\n{chunk_data}\r\n0\r\n\r\n"
        
        # Set Content-Length to be smaller than actual body
        # This should cause back-end to process only part of the body
        content_length = len(f"{chunk_size_hex}\r\n") + 4  # Just the chunk header + 4 bytes
        
        headers = {
            "Content-Length": str(content_length),
            "Transfer-Encoding": "chunked",
            "User-Agent": self.user_agent,
            "Connection": "keep-alive",
        }
        
        try:
            # Send the TE.CL test request
            response1 = await self._send_raw_request(
                "POST",  # smuggling technique requires a body-bearing method; never replay the captured method
                exchange.url,
                headers=headers,
                body=body,
            )
            
            if response1 is None:
                return SmugglingTestResult(
                    test_type="te_cl",
                    vulnerable=False,
                    severity="low",
                    detail="Could not send TE.CL test request",
                    evidence="",
                    confidence=0.0,
                )
            
            # Send follow-up request
            await asyncio.sleep(0.5)
            
            followup_headers = {
                "User-Agent": self.user_agent,
                "Connection": "keep-alive",
            }
            
            response2 = await self._send_raw_request(
                "GET",
                exchange.url,
                headers=followup_headers,
                body="",
            )
            
            # Check if smuggled request was processed
            if response2 and response2.status_code == 404:
                return SmugglingTestResult(
                    test_type="te_cl",
                    vulnerable=True,
                    severity="critical",
                    detail="TE.CL vulnerability confirmed - smuggled request was processed",
                    evidence=f"Smuggled GET /404 returned 404 in follow-up request",
                    confidence=0.95,
                )
            
            if response1 and self._is_unexpected_response(response1, exchange):
                return SmugglingTestResult(
                    test_type="te_cl",
                    vulnerable=True,
                    severity="critical",
                    detail="TE.CL vulnerability suspected - unexpected response received",
                    evidence=f"Response status: {response1.status_code}",
                    confidence=0.85,
                )
            
            return SmugglingTestResult(
                test_type="te_cl",
                vulnerable=False,
                severity="low",
                detail="No TE.CL vulnerability detected",
                evidence="",
                confidence=0.1,
            )
            
        except Exception as e:
            log.debug(f"TE.CL test error: {e}")
            return SmugglingTestResult(
                test_type="te_cl",
                vulnerable=False,
                severity="low",
                detail=f"TE.CL test failed: {e}",
                evidence="",
                confidence=0.0,
            )
    
    async def _test_te_te(self, base_url: str, exchange: HttpExchange) -> SmugglingTestResult:
        """
        Test for TE.TE vulnerability.
        
        Both servers use Transfer-Encoding but handle it differently.
        """
        # Build TE.TE payload with multiple Transfer-Encoding headers
        smuggled_request = "GET /404 HTTP/1.1\r\nHost: " + base_url.split('//')[1] + "\r\n\r\n"
        
        # Body: chunked with obfuscated Transfer-Encoding
        body = "0\r\n\r\n" + smuggled_request
        
        # Multiple Transfer-Encoding headers
        headers = {
            "Transfer-Encoding": "chunked",
            "X-Transfer-Encoding": "identity",  # Obfuscation attempt
            "User-Agent": self.user_agent,
            "Connection": "keep-alive",
        }
        
        try:
            # Try with standard TE.TE
            response1 = await self._send_raw_request(
                "POST",  # smuggling technique requires a body-bearing method; never replay the captured method
                exchange.url,
                headers=headers,
                body=body,
            )
            
            if response1 and response1.status_code == 404:
                return SmugglingTestResult(
                    test_type="te_te",
                    vulnerable=True,
                    severity="high",
                    detail="TE.TE vulnerability confirmed with obfuscated headers",
                    evidence=f"Smuggled GET /404 returned 404",
                    confidence=0.90,
                )
            
            # Try with different obfuscation
            headers2 = {
                "Transfer-Encoding": "chunked, identity",
                "User-Agent": self.user_agent,
                "Connection": "keep-alive",
            }
            
            response2 = await self._send_raw_request(
                "POST",  # smuggling technique requires a body-bearing method; never replay the captured method
                exchange.url,
                headers=headers2,
                body=body,
            )
            
            if response2 and response2.status_code == 404:
                return SmugglingTestResult(
                    test_type="te_te",
                    vulnerable=True,
                    severity="high",
                    detail="TE.TE vulnerability confirmed with comma-separated headers",
                    evidence=f"Smuggled GET /404 returned 404",
                    confidence=0.90,
                )
            
            if (response1 or response2) and self._is_unexpected_response(response1 or response2, exchange):
                return SmugglingTestResult(
                    test_type="te_te",
                    vulnerable=True,
                    severity="high",
                    detail="TE.TE vulnerability suspected - unexpected response",
                    evidence=f"Response status: {(response1 or response2).status_code}",
                    confidence=0.75,
                )
            
            return SmugglingTestResult(
                test_type="te_te",
                vulnerable=False,
                severity="low",
                detail="No TE.TE vulnerability detected",
                evidence="",
                confidence=0.1,
            )
            
        except Exception as e:
            log.debug(f"TE.TE test error: {e}")
            return SmugglingTestResult(
                test_type="te_te",
                vulnerable=False,
                severity="low",
                detail=f"TE.TE test failed: {e}",
                evidence="",
                confidence=0.0,
            )
    
    async def _send_raw_request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        body: str = "",
    ) -> httpx.Response | None:
        """Send a raw HTTP request with custom headers and body."""
        headers = headers or {}
        headers['User-Agent'] = self.user_agent
        
        try:
            if self.run_context is not None:
                from run_context import TypedRequest
                outcome = await self.run_context.executor().execute(
                    TypedRequest(method, url, headers=headers, body=body or None),
                    capability=self.get_name(), max_redirects=self.max_redirects)
                if not outcome.ok:
                    return None
                return httpx.Response(
                    outcome.status or 0, content=(outcome.body or "").encode(),
                    headers=outcome.headers, request=httpx.Request(method, url))
            if not self.client:
                self.client = httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=False,
                    max_redirects=self.max_redirects,
                )
            
            response = await self.client.request(
                method,
                url,
                headers=headers,
                content=body,
            )
            return response
        except Exception as e:
            log.debug(f"Request to {url} failed: {e}")
            return None
    
    def _is_unexpected_response(self, response: httpx.Response, exchange: HttpExchange) -> bool:
        """Check if a response is unexpected (indicating potential smuggling)."""
        # Compare with the original exchange
        if response.status_code != exchange.response_status:
            return True
        
        # Check for 404 (our smuggled request target)
        if response.status_code == 404:
            return True
        
        # Check for 500 errors (might indicate smuggling)
        if response.status_code >= 500:
            return True
        
        # Check if response content is different from expected
        # (This is a simple check; in practice, you'd need baseline comparison)
        if response.text and len(response.text) > 0:
            # Look for error messages or unexpected content
            error_patterns = [
                r'error',
                r'exception',
                r'traceback',
                r'internal server error',
                r'500',
                r'404',
            ]
            text_lower = response.text.lower()
            for pattern in error_patterns:
                if re.search(pattern, text_lower):
                    return True
        
        return False
    
    def _build_evidence(self, tests: list[SmugglingTestResult]) -> str:
        """Build evidence string from test results."""
        vulnerable = [t for t in tests if t.vulnerable]
        if not vulnerable:
            return "No HTTP Request Smuggling vulnerabilities detected"
        
        parts = []
        for t in vulnerable:
            parts.append(f"{t.test_type.upper()}: {t.detail} ({t.severity})")
        return " | ".join(parts)
    
    def _build_raw_output(self, tests: list[SmugglingTestResult]) -> str:
        """Build raw output from test results."""
        import json
        return json.dumps([t.to_dict() for t in tests], indent=2)
