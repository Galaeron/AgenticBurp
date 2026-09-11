"""
CSP / Clickjacking Validator

Active validator: re-fetches the target URL fresh (rather than trusting
only the captured exchange, in case CSP is applied inconsistently
across requests) and parses the actual CSP directive list and framing
headers.

Checks performed:
1. CSP presence and directive analysis (unsafe-inline, unsafe-eval,
   wildcard sources, object-src)
2. Report-only-without-enforcing-policy detection
3. Clickjacking / framing protection (X-Frame-Options, frame-ancestors)
"""

from __future__ import annotations
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from models import Finding, HttpExchange

log = logging.getLogger("harness.validators.csp")


@dataclass
class CspTestResult:
    test_name: str
    passed: bool
    severity: str
    detail: str
    evidence: str
    vulnerable: bool = False
    checked: bool = True

    def to_dict(self) -> dict:
        return {
            "test": self.test_name, "passed": self.passed, "severity": self.severity,
            "detail": self.detail, "evidence": self.evidence,
            "vulnerable": self.vulnerable, "checked": self.checked,
        }


def _parse_csp(csp: str) -> dict[str, list[str]]:
    """Parse a CSP header value into {directive: [sources]}."""
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


class CspValidator(Validator):
    """Validator for CSP weaknesses and clickjacking exposure."""

    name = "csp_validator"
    finding_classes = {"csp", "content security policy", "content_security_policy", "clickjacking"}
    active = True

    def __init__(self, timeout: float = 10.0, max_redirects: int = 5,
                 run_context=None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.run_context = run_context
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def get_name(self) -> str:
        return "csp_validator"

    def get_capability(self) -> str:
        return "csp_clickjacking_validation"

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
        plan_id = f"csp_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"CSP/clickjacking validation for {finding.vulnerability_class}",
            success_signals=["Confirm missing/weak CSP or missing framing protection"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        tests: list[CspTestResult] = []
        try:
            headers = await self._fetch_fresh_headers(exchange)
            if headers is None:
                headers = exchange.response_headers or {}
                tests.append(CspTestResult("Fresh Fetch", True, "low",
                                            "Could not re-fetch; using headers from the captured exchange", "",
                                            checked=False))

            headers_lower = {k.lower(): v for k, v in headers.items()}
            tests.append(self._check_csp(headers_lower))
            tests.append(self._check_framing(headers_lower))

            checked = [t for t in tests if t.checked]
            vulnerable = any(t.vulnerable for t in checked)
            severities = [t.severity for t in checked if t.vulnerable]
            severity = "high" if "high" in severities else ("medium" if "medium" in severities else "low")

            vulnerable_tests = [t for t in checked if t.vulnerable]
            summary_parts = []
            if vulnerable_tests:
                summary_parts.append(f"CSP/clickjacking issue(s) confirmed: {len(vulnerable_tests)}")
                for t in vulnerable_tests:
                    summary_parts.append(f"  - {t.test_name}: {t.detail}")
            else:
                summary_parts.append("CSP and framing protection look adequate on this fetch")

            return ValidationResult(
                validator=self.get_name(),
                status="confirmed" if vulnerable else "not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.85 if vulnerable else 0.2,
                confirmed=vulnerable,
                summary=" ".join(summary_parts),
                evidence=self._build_evidence(checked),
                raw_output=self._build_raw_output(tests),
            )
        except Exception as e:
            log.error(f"CSP validation error: {e}")
            return ValidationResult(
                validator=self.get_name(), status="error",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=f"CSP validation failed: {e}", evidence="", raw_output=str(e),
            )

    async def _fetch_fresh_headers(self, exchange: HttpExchange) -> dict | None:
        try:
            if self.run_context is not None:
                from run_context import TypedRequest
                outcome = await self.run_context.executor().execute(
                    TypedRequest("GET", exchange.url,
                                 headers={"User-Agent": self.user_agent}),
                    capability=self.get_name(), max_redirects=self.max_redirects)
                return dict(outcome.headers) if outcome.ok else None
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, max_redirects=self.max_redirects,
            ) as client:
                import global_throttle
                await global_throttle.acquire()
                response = await client.get(exchange.url, headers={"User-Agent": self.user_agent})
                return dict(response.headers)
        except Exception as e:
            log.debug(f"Fresh fetch failed: {e}")
            return None

    def _check_csp(self, headers_lower: dict) -> CspTestResult:
        csp = headers_lower.get("content-security-policy", "")
        csp_report_only = headers_lower.get("content-security-policy-report-only", "")

        if not csp and csp_report_only:
            return CspTestResult(
                "CSP Presence", False, "medium",
                "Only Content-Security-Policy-Report-Only is set, with no enforcing "
                "Content-Security-Policy -- violations are logged but nothing is blocked",
                f"CSP-Report-Only: {csp_report_only[:150]}", vulnerable=True,
            )
        if not csp:
            return CspTestResult(
                "CSP Presence", False, "medium",
                "No Content-Security-Policy header present -- no defense-in-depth against XSS "
                "from this layer",
                "Content-Security-Policy header absent", vulnerable=True,
            )

        directives = _parse_csp(csp)
        script_src = directives.get("script-src") or directives.get("default-src") or []
        issues = []
        if "'unsafe-inline'" in script_src:
            issues.append("script-src allows 'unsafe-inline'")
        if "'unsafe-eval'" in script_src:
            issues.append("script-src allows 'unsafe-eval'")
        if "*" in script_src or "https:" in script_src or "http:" in script_src:
            issues.append(f"script-src has an overly broad source: {[s for s in script_src if s in ('*','https:','http:')]}")
        object_src = directives.get("object-src")
        if object_src is None and "default-src" not in directives:
            issues.append("no object-src (and no default-src fallback) restricting plugin content")
        elif object_src and "'none'" not in object_src:
            issues.append(f"object-src is not restricted to 'none': {object_src}")

        if issues:
            return CspTestResult(
                "CSP Directive Analysis", False, "medium",
                "; ".join(issues),
                f"CSP: {csp[:200]}", vulnerable=True,
            )
        return CspTestResult("CSP Directive Analysis", True, "low", "CSP directives look reasonably restrictive",
                              f"CSP: {csp[:200]}", vulnerable=False)

    def _check_framing(self, headers_lower: dict) -> CspTestResult:
        csp = headers_lower.get("content-security-policy", "")
        directives = _parse_csp(csp) if csp else {}
        has_frame_ancestors = "frame-ancestors" in directives
        xfo = headers_lower.get("x-frame-options", "")

        if has_frame_ancestors:
            fa = directives["frame-ancestors"]
            if "*" in fa:
                return CspTestResult(
                    "Framing Protection", False, "medium",
                    f"frame-ancestors allows any origin: {fa}",
                    f"frame-ancestors: {fa}", vulnerable=True,
                )
            return CspTestResult("Framing Protection", True, "low",
                                  f"frame-ancestors restricts framing: {fa}", "", vulnerable=False)

        if xfo:
            if xfo.upper() not in ("DENY", "SAMEORIGIN"):
                return CspTestResult(
                    "Framing Protection", False, "medium",
                    f"X-Frame-Options has a non-standard value: {xfo}",
                    f"X-Frame-Options: {xfo}", vulnerable=True,
                )
            return CspTestResult("Framing Protection", True, "low",
                                  f"X-Frame-Options: {xfo}", "", vulnerable=False)

        return CspTestResult(
            "Framing Protection", False, "medium",
            "No frame-ancestors CSP directive and no X-Frame-Options header -- "
            "this page can be framed by any site (clickjacking exposure)",
            "Both frame-ancestors and X-Frame-Options absent", vulnerable=True,
        )

    def _build_evidence(self, tests: list[CspTestResult]) -> str:
        vulnerable = [t for t in tests if t.vulnerable]
        if not vulnerable:
            return "No CSP/clickjacking issue confirmed"
        return " | ".join(f"{t.test_name}: {t.detail} ({t.severity})" for t in vulnerable)

    def _build_raw_output(self, tests: list[CspTestResult]) -> str:
        import json
        return json.dumps([t.to_dict() for t in tests], indent=2)
