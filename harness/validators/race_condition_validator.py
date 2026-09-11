"""
Race Condition Validator

Active validator: fires many copies of the same request concurrently
(genuinely overlapping, via asyncio.gather -- not sequential) and
checks how many of them came back looking like a "clean success"
rather than a rejection. If a check-then-act operation is meant to
succeed at most once (or some other bounded amount), seeing multiple
concurrent requests all succeed cleanly is direct evidence the
check-then-act window isn't atomic.

This can't know the application's exact success/rejection vocabulary
in advance, so it uses a heuristic: a response counts as a "clean
success" if its status code matches the original captured response's
status AND its body doesn't contain any of a small set of common
rejection-language markers. This is necessarily approximate --
flagged as such in the result -- but a burst producing several
identical-looking successes to an operation whose own response text
implies it should be limited is strong circumstantial evidence
regardless of the exact wording used.
"""

from __future__ import annotations
import asyncio
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

from .base import Validator, ValidationResult
from safety_gate import get_default_gate

if TYPE_CHECKING:
    from models import Finding, HttpExchange

log = logging.getLogger("harness.validators.race_condition")

_REJECTION_MARKERS = re.compile(
    r"already (used|redeemed|claimed|applied|exists)|"
    r"expired|invalid (code|token)|insufficient|limit reached|"
    r"too many|rate limit|not found|forbidden|unauthorized",
    re.IGNORECASE,
)

_BURST_SIZE = 12


@dataclass
class RaceConditionTestResult:
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


class RaceConditionValidator(Validator):
    """Validator for check-then-act race conditions via a concurrent request burst."""

    name = "race_condition_validator"
    finding_classes = {"race_condition", "race condition", "toctou", "time of check to time of use"}
    active = True

    def __init__(self, timeout: float = 15.0, max_redirects: int = 0,
                 burst_size: int = _BURST_SIZE, run_context=None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.burst_size = burst_size
        self.run_context = run_context
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def get_name(self) -> str:
        return "race_condition_validator"

    def get_capability(self) -> str:
        return "race_condition_validation"

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
        plan_id = f"race_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            mutation={"burst_size": str(self.burst_size)},
            rationale=f"Race condition validation for {finding.vulnerability_class}",
            success_signals=[f"Fire {self.burst_size} concurrent copies of this request and count clean successes"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        try:
            if exchange.method.upper() == "GET":
                return ValidationResult(
                    validator=self.get_name(), status="skipped",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary="GET requests are (should be) idempotent -- no check-then-act state "
                            "change to race. This validator only tests mutating methods.",
                    evidence="", raw_output="[]",
                )

            headers = {k: v for k, v in (exchange.request_headers or {}).items()
                       if k.lower() not in ("content-length", "host")}
            headers.setdefault("User-Agent", self.user_agent)

            gate = self.run_context.gate if self.run_context is not None else get_default_gate()
            gate_decision = gate.authorize_burst(
                validator_name=self.get_name(), method=exchange.method, url=exchange.url,
                requested_burst_size=self.burst_size, body=exchange.request_body,
            )
            if not gate_decision.allowed:
                return ValidationResult(
                    validator=self.get_name(), status="blocked",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary=f"Blocked by safety gate: {gate_decision.reason}",
                    evidence="", raw_output="[]",
                )
            effective_burst_size = gate_decision.allowed_burst_size

            async def fire_one():
                try:
                    if self.run_context is not None:
                        from types import SimpleNamespace
                        from run_context import TypedRequest
                        from .transport import bind_session
                        session_ref, request_headers = bind_session(self.run_context, headers)
                        result = await self.run_context.executor().execute(
                            TypedRequest(exchange.method, exchange.url,
                                         headers=request_headers,
                                         body=exchange.request_body or None),
                            capability=self.get_name(), session_ref=session_ref)
                        if not result.ok:
                            return None
                        return SimpleNamespace(status_code=result.status, text=result.body,
                                               headers=result.headers)
                    async with httpx.AsyncClient(
                        timeout=self.timeout, follow_redirects=False, max_redirects=self.max_redirects,
                    ) as client:
                        return await client.request(
                            exchange.method, exchange.url,
                            headers=headers,
                            content=exchange.request_body.encode() if exchange.request_body else None,
                        )
                except Exception as e:
                    log.debug(f"Burst request failed: {e}")
                    return None

            # The overlap is the point -- gather, not a loop with awaits in
            # between, so all N requests are genuinely in flight together.
            # effective_burst_size, not self.burst_size: the gate may have
            # clamped it down to the operator's or the hard ceiling.
            responses = await asyncio.gather(*[fire_one() for _ in range(effective_burst_size)])
            responses = [r for r in responses if r is not None]

            if len(responses) < 2:
                return ValidationResult(
                    validator=self.get_name(), status="error",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary=f"Only {len(responses)}/{effective_burst_size} burst requests completed -- "
                            "too few to draw a conclusion, target may be rate-limiting the burst itself",
                    evidence="", raw_output="[]",
                )

            original_status = exchange.response_status
            clean_successes = 0
            status_counts: dict[int, int] = {}
            for r in responses:
                status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
                body = r.text or ""
                looks_clean = (
                    (original_status is None or r.status_code == original_status)
                    and r.status_code < 400
                    and not _REJECTION_MARKERS.search(body)
                )
                if looks_clean:
                    clean_successes += 1

            vulnerable = clean_successes >= 2
            if vulnerable:
                detail = (
                    f"{clean_successes} of {len(responses)} concurrent requests came back looking like "
                    f"a clean success (status matching the original, no rejection-language markers) -- "
                    f"if this operation is meant to succeed at most once, this is evidence the "
                    f"check-then-act isn't atomic"
                )
            else:
                detail = (
                    f"{clean_successes} of {len(responses)} concurrent requests looked like clean "
                    f"successes -- no evidence of a race condition from this heuristic (note: this "
                    f"can't distinguish a well-locked operation from one that simply doesn't have a "
                    f"'succeed once' business rule at all)"
                )

            return ValidationResult(
                validator=self.get_name(),
                status="confirmed" if vulnerable else "not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.7 if vulnerable else 0.2,
                confirmed=vulnerable,
                summary=detail,
                evidence=f"Status code distribution across burst: {status_counts}",
                raw_output=str({"burst_size": effective_burst_size, "requested_burst_size": self.burst_size,
                                 "completed": len(responses),
                                 "clean_successes": clean_successes, "status_counts": status_counts}),
            )
        except Exception as e:
            log.error(f"Race condition validation error: {e}")
            return ValidationResult(
                validator=self.get_name(), status="error",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=f"Race condition validation failed: {e}", evidence="", raw_output=str(e),
            )
