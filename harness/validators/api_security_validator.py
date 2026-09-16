"""
API Security Validator

Active validator covering two of the API-security agent's checks that
lend themselves to a concrete probe from a single captured exchange:

1. Mass assignment -- resend a JSON body with an extra unexpected
   field and see if the response reflects it as accepted.
2. Unbounded resource consumption -- resend with a very large
   limit/count/page_size query parameter and see if the server caps it.

Excessive data exposure and API-versioning/inventory issues stay
agent-only (LLM judgment on what fields "should" be exposed, or on
whether an endpoint "looks" internal, isn't something a validator can
mechanically confirm) -- this validator says so explicitly for those
finding types rather than silently no-op'ing.
"""

from __future__ import annotations
import json as jsonlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse, parse_qs, urlunparse

import httpx

from .base import Validator, ValidationResult
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

log = logging.getLogger("harness.validators.api_security")

_MASS_ASSIGNMENT_PROBE_FIELD = "harnessProbeIsAdmin"
_LIMIT_PARAM_NAMES = {"limit", "count", "page_size", "pagesize", "per_page", "perpage", "size", "max"}


@dataclass
class ApiSecurityTestResult:
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


class ApiSecurityValidator(Validator):
    """Validator for mass assignment and unbounded resource-consumption issues."""

    name = "api_security_validator"
    finding_classes = {"api_security", "api security", "mass assignment", "mass_assignment",
                        "excessive data exposure", "unbounded resource consumption"}
    active = True

    def __init__(self, timeout: float = 10.0, max_redirects: int = 0):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def get_name(self) -> str:
        return "api_security_validator"

    def get_capability(self) -> str:
        return "api_security_validation"

    def get_execution_plane(self) -> str:
        return "local_tool"

    def plan(self, finding: Finding, exchange: HttpExchange) -> Any:
        from harness.models import TestPlan
        from harness.categories import canonicalize
        import hashlib

        # Plan ID must incorporate the FULL exchange, not just the URL --
        # see cors_validator.py's plan() for the real, live-reproduced
        # collision this fixes (two different real requests to the same
        # URL producing the same plan_id and clobbering each other).
        exchange_hash = hashlib.sha256(
            jsonlib.dumps(exchange.model_dump(), sort_keys=True).encode()
        ).hexdigest()[:16]
        plan_id = f"api_sec_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"API security validation for {finding.vulnerability_class}",
            success_signals=["Confirm mass assignment or unbounded resource consumption"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        tests: list[ApiSecurityTestResult] = []
        fc = finding.vulnerability_class.lower()

        if "excessive data exposure" in fc or "versioning" in fc or "inventory" in fc:
            return ValidationResult(
                validator=self.get_name(), status="skipped",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary="This finding type requires judgment about which fields SHOULD be exposed "
                        "or whether an endpoint looks deprecated/internal -- not mechanically "
                        "confirmable by resending a request. Needs manual review.",
                evidence="", raw_output="[]",
            )

        try:
            if exchange.method.upper() in ("POST", "PUT", "PATCH") and exchange.request_body:
                result = await self._probe_mass_assignment(exchange)
                if result is not None:
                    tests.append(result)

            limit_result = await self._probe_unbounded_limit(exchange)
            if limit_result is not None:
                tests.append(limit_result)

            if not tests:
                return ValidationResult(
                    validator=self.get_name(), status="skipped",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary="Neither mass-assignment (needs a JSON POST/PUT/PATCH body) nor "
                            "unbounded-limit (needs a limit/count/page_size-style parameter) "
                            "checks applied to this exchange",
                    evidence="", raw_output="[]",
                )

            vulnerable_tests = [t for t in tests if t.vulnerable]
            vulnerable = bool(vulnerable_tests)
            summary_parts = []
            if vulnerable_tests:
                summary_parts.append(f"API security issue(s) confirmed: {len(vulnerable_tests)}")
                for t in vulnerable_tests:
                    summary_parts.append(f"  - {t.test_name}: {t.detail}")
            else:
                summary_parts.append("No mass assignment or unbounded resource consumption confirmed")

            return ValidationResult(
                validator=self.get_name(),
                status="confirmed" if vulnerable else "not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.75 if vulnerable else 0.2,
                confirmed=vulnerable,
                summary=" ".join(summary_parts),
                evidence=self._build_evidence(tests),
                raw_output=self._build_raw_output(tests),
            )
        except Exception as e:
            log.error(f"API security validation error: {e}")
            return ValidationResult(
                validator=self.get_name(), status="error",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=f"API security validation failed: {e}", evidence="", raw_output=str(e),
            )

    async def _probe_mass_assignment(self, exchange: HttpExchange) -> ApiSecurityTestResult | None:
        try:
            body = jsonlib.loads(exchange.request_body)
        except (jsonlib.JSONDecodeError, TypeError):
            return None
        if not isinstance(body, dict):
            return None

        probed_body = dict(body)
        probed_body[_MASS_ASSIGNMENT_PROBE_FIELD] = True

        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        headers["User-Agent"] = self.user_agent
        headers.setdefault("Content-Type", "application/json")

        try:
            async with GatedAsyncClient(
                get_default_gate(), self.get_name(),
                timeout=self.timeout, follow_redirects=False, max_redirects=self.max_redirects,
            ) as client:
                from harness import global_throttle
                await global_throttle.acquire()
                response = await client.request(
                    exchange.method, exchange.url,
                    headers=headers, content=jsonlib.dumps(probed_body),
                )
        except SafetyGateBlocked as e:
            return ApiSecurityTestResult("Mass Assignment Probe", True, "low",
                                          f"Blocked by safety gate: {e.decision.reason}", "",
                                          checked=True, vulnerable=False)
        except Exception as e:
            log.debug(f"Mass assignment probe failed: {e}")
            return ApiSecurityTestResult("Mass Assignment Probe", True, "low",
                                          f"Could not send probe: {e}", "", checked=True, vulnerable=False)

        try:
            resp_json = response.json()
        except Exception:
            resp_json = None

        reflected = isinstance(resp_json, dict) and _MASS_ASSIGNMENT_PROBE_FIELD in resp_json
        if reflected:
            return ApiSecurityTestResult(
                "Mass Assignment Probe", False, "high",
                f"An unexpected field ({_MASS_ASSIGNMENT_PROBE_FIELD}) added to the request body was "
                "accepted and reflected back in the response -- the endpoint appears to bind the "
                "request body to an internal object without an allowlist of settable fields, which "
                "means a genuinely privileged field name (role, isAdmin, etc.) sent the same way "
                "might also be accepted",
                f"Status {response.status_code}, response contains {_MASS_ASSIGNMENT_PROBE_FIELD}",
                vulnerable=True,
            )
        return ApiSecurityTestResult(
            "Mass Assignment Probe", True, "low",
            f"Unexpected field not reflected back (status {response.status_code}) -- "
            "no evidence of unrestricted mass assignment from this probe alone "
            "(a field that's silently accepted but not echoed back would not be caught by this check)",
            f"Status: {response.status_code}", vulnerable=False,
        )

    async def _probe_unbounded_limit(self, exchange: HttpExchange) -> ApiSecurityTestResult | None:
        parsed = urlparse(exchange.url)
        qs = parse_qs(parsed.query)
        limit_param = next((p for p in qs if p.lower() in _LIMIT_PARAM_NAMES), None)
        if limit_param is None:
            return None

        new_qs = dict(qs)
        new_qs[limit_param] = ["999999"]
        flat_qs = "&".join(f"{k}={v[0]}" for k, v in new_qs.items())
        probe_url = urlunparse(parsed._replace(query=flat_qs))

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=False, max_redirects=self.max_redirects,
            ) as client:
                from harness import global_throttle
                await global_throttle.acquire()
                response = await client.request(
                    "GET", probe_url,  # pagination is inherently a read operation; never replay the captured method
                    headers={"User-Agent": self.user_agent},
                )
        except Exception as e:
            log.debug(f"Unbounded limit probe failed: {e}")
            return ApiSecurityTestResult("Unbounded Limit Probe", True, "low",
                                          f"Could not send probe: {e}", "", checked=True, vulnerable=False)

        body_len = len(response.text or "")
        # Heuristic, not proof: a very large response body to a request for
        # 999999 items is suggestive, not conclusive -- the endpoint might
        # just have few total records regardless of the limit. Flag at
        # moderate confidence and say so.
        if response.status_code == 200 and body_len > 500_000:
            return ApiSecurityTestResult(
                "Unbounded Limit Probe", False, "medium",
                f"Requesting {limit_param}=999999 returned a {body_len}-byte response with no "
                "apparent server-side cap -- worth confirming this scales with actual record "
                "count rather than being capped at a safe maximum",
                f"{limit_param}=999999 -> {response.status_code}, {body_len} bytes", vulnerable=True,
            )
        return ApiSecurityTestResult(
            "Unbounded Limit Probe", True, "low",
            f"{limit_param}=999999 returned {body_len} bytes (status {response.status_code}) -- "
            "no evidence of unbounded response size from this probe",
            f"Status: {response.status_code}, size: {body_len}", vulnerable=False,
        )

    def _build_evidence(self, tests: list[ApiSecurityTestResult]) -> str:
        vulnerable = [t for t in tests if t.vulnerable]
        if not vulnerable:
            return "No API security issue confirmed"
        return " | ".join(f"{t.test_name}: {t.detail} ({t.severity})" for t in vulnerable)

    def _build_raw_output(self, tests: list[ApiSecurityTestResult]) -> str:
        return jsonlib.dumps([t.to_dict() for t in tests], indent=2)
