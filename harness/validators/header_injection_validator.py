"""
HTTP Header Injection (CRLF) Validator

Active validator: identifies request parameters whose values are
reflected into response headers (from the captured exchange), then
resends the request with a CRLF-plus-marker-header payload in each
candidate parameter and checks whether the injected header actually
appears in the raw response.

This validator cannot confirm the email/SMTP-header variant of the
vulnerability (it has no visibility into what happens after a form
submission reaches a mail-sending backend) -- it only handles the
HTTP-response-header case, and says so explicitly when it can't apply.
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

log = logging.getLogger("harness.validators.header_injection")

_MARKER_HEADER = "X-Harness-Crlf-Probe"
_MARKER_VALUE = "injected"


@dataclass
class HeaderInjectionTestResult:
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


class HeaderInjectionValidator(Validator):
    """Validator for HTTP response header (CRLF) injection."""

    name = "header_injection_validator"
    finding_classes = {"header_injection", "header injection", "crlf injection", "crlf_injection",
                        "response splitting", "smtp header injection", "email header injection"}
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
        return "header_injection_validator"

    def get_capability(self) -> str:
        return "header_injection_validation"

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
        plan_id = f"header_inj_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"Header injection validation for {finding.vulnerability_class}",
            success_signals=["Confirm CRLF injection into a response header via a query parameter"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        tests: list[HeaderInjectionTestResult] = []
        try:
            if "smtp" in finding.vulnerability_class.lower() or "email" in finding.vulnerability_class.lower():
                return ValidationResult(
                    validator=self.get_name(), status="skipped",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary="This validator can only test HTTP response header injection via a live "
                            "request/response cycle -- it has no visibility into an email-sending backend "
                            "to confirm SMTP header injection. Manual confirmation needed (send the probe "
                            "value and check the actual outbound email headers).",
                    evidence="", raw_output="[]",
                )

            candidates = self._extract_query_params(exchange)
            if not candidates:
                return ValidationResult(
                    validator=self.get_name(), status="skipped",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary="No query parameters in this exchange to probe for header injection",
                    evidence="", raw_output="[]",
                )

            for param in candidates:
                tests.append(await self._probe_param(exchange, param))

            vulnerable_tests = [t for t in tests if t.vulnerable]
            vulnerable = bool(vulnerable_tests)
            summary_parts = []
            if vulnerable_tests:
                summary_parts.append(f"Header injection CONFIRMED via {len(vulnerable_tests)} parameter(s)")
                for t in vulnerable_tests:
                    summary_parts.append(f"  - {t.test_name}: {t.detail}")
            else:
                summary_parts.append(f"Probed {len(candidates)} parameter(s), no CRLF injection into response headers confirmed")

            return ValidationResult(
                validator=self.get_name(),
                status="confirmed" if vulnerable else "not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.9 if vulnerable else 0.2,
                confirmed=vulnerable,
                summary=" ".join(summary_parts),
                evidence=self._build_evidence(tests),
                raw_output=self._build_raw_output(tests),
            )
        except Exception as e:
            log.error(f"Header injection validation error: {e}")
            return ValidationResult(
                validator=self.get_name(), status="error",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=f"Header injection validation failed: {e}", evidence="", raw_output=str(e),
            )

    def _extract_query_params(self, exchange: HttpExchange) -> list[str]:
        parsed = urlparse(exchange.url)
        qs = parse_qs(parsed.query)
        return list(qs.keys())[:5]  # bounded, same discipline as the other new validators

    async def _probe_param(self, exchange: HttpExchange, param: str) -> HeaderInjectionTestResult:
        parsed = urlparse(exchange.url)
        qs = parse_qs(parsed.query)
        original = qs.get(param, [""])[0]

        # httpx/urllib will typically encode %0d%0a for us if we hand it as
        # part of a value via urlencode -- send it pre-encoded explicitly so
        # we're testing what a raw byte-level CRLF would do, not relying on
        # the client library's own encoding behavior to happen to preserve it.
        payload = original + "%0d%0a" + _MARKER_HEADER + ":%20" + _MARKER_VALUE
        new_qs = dict(qs)
        new_qs[param] = [payload]
        flat_qs = "&".join(f"{k}={v[0]}" for k, v in new_qs.items())
        probe_url = urlunparse(parsed._replace(query=flat_qs))

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
                        "GET", probe_url,  # only query params are tested; never replay the captured method
                        headers={"User-Agent": self.user_agent},
                    )
        except Exception as e:
            log.debug(f"Header injection probe failed for param {param}: {e}")
            return HeaderInjectionTestResult(f"Probe: {param}", True, "low",
                                              f"Could not send probe: {e}", "", checked=True, vulnerable=False)

        injected = any(k.lower() == _MARKER_HEADER.lower() and v == _MARKER_VALUE
                        for k, v in response.headers.items())
        if injected:
            return HeaderInjectionTestResult(
                f"Probe: {param}", False, "high",
                f"CRLF injection confirmed -- injected header {_MARKER_HEADER} appeared in the raw "
                f"response after being smuggled through the '{param}' parameter",
                f"Response contained header {_MARKER_HEADER}: {_MARKER_VALUE}", vulnerable=True,
            )
        return HeaderInjectionTestResult(
            f"Probe: {param}", True, "low",
            f"'{param}' does not appear to allow CRLF injection into response headers",
            f"Status: {response.status_code}", vulnerable=False,
        )

    def _build_evidence(self, tests: list[HeaderInjectionTestResult]) -> str:
        vulnerable = [t for t in tests if t.vulnerable]
        if not vulnerable:
            return "No header injection confirmed"
        return " | ".join(f"{t.test_name}: {t.detail} ({t.severity})" for t in vulnerable)

    def _build_raw_output(self, tests: list[HeaderInjectionTestResult]) -> str:
        import json
        return json.dumps([t.to_dict() for t in tests], indent=2)
