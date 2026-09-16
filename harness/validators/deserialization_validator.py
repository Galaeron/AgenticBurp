"""
Insecure Deserialization Validator

This validator does ONE thing, deterministically: confirm whether a
value in the captured exchange actually matches a known
serialized-object format's byte-level signature (Java, PHP, Python
pickle, .NET ViewState), rather than relying on the agent's
LLM-based pattern recognition alone. A byte-level magic-number check
is a stricter, independently-obtained confirmation of format identity.

This validator deliberately does NOT attempt to construct or send a
deserialization gadget chain / exploit payload. Building an actual
exploit crosses into malicious-code territory this harness doesn't
do regardless of the legitimate-testing framing -- confirming the
FORMAT is deterministic and safe; confirming EXPLOITABILITY would
require generating a working gadget chain, which this validator
declines and instead names the established third-party tooling
(analyst-run, out of band) appropriate to the identified format.
"""

from __future__ import annotations
import base64
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

log = logging.getLogger("harness.validators.deserialization")

_PHP_SERIALIZED = re.compile(r'^(O:\d+:"[^"]+":\d+:\{|a:\d+:\{|s:\d+:"|i:\d+;|b:[01];)')
_JAVA_MAGIC = b"\xac\xed"
_JAVA_B64_PREFIX = "rO0"  # base64("\xac\xed\x00") -> "rO0" -- the standard visible tell
_DOTNET_VIEWSTATE_FIELD = "__VIEWSTATE"

_FORMAT_TOOLS = {
    "java": "ysoserial (analyst-run, out of band -- this validator does not generate payloads)",
    "php": "PHPGGC (analyst-run, out of band -- this validator does not generate payloads)",
    "dotnet_viewstate": "ysoserial.net / a ViewState MAC-key analysis, if EnableViewStateMac appears absent",
}


@dataclass
class DeserializationTestResult:
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


class DeserializationValidator(Validator):
    """Deterministic format-fingerprint confirmation for serialized-object formats."""

    name = "deserialization_validator"
    finding_classes = {"deserialization", "insecure deserialization", "insecure_deserialization"}
    active = False  # pure local inspection of already-captured data, no network call

    def __init__(self, timeout: float = 5.0, max_redirects: int = 0):
        self.timeout = timeout

    def get_name(self) -> str:
        return "deserialization_validator"

    def get_capability(self) -> str:
        return "deserialization_format_confirmation"

    def get_execution_plane(self) -> str:
        return "local_tool"

    def plan(self, finding: Finding, exchange: HttpExchange) -> Any:
        from harness.models import TestPlan
        from harness.categories import canonicalize
        import hashlib
        import json

        # Plan ID must incorporate the FULL exchange, not just the URL --
        # see cors_validator.py's plan() for the real, live-reproduced
        # collision this fixes (two different real requests to the same
        # URL producing the same plan_id and clobbering each other).
        exchange_hash = hashlib.sha256(
            json.dumps(exchange.model_dump(), sort_keys=True).encode()
        ).hexdigest()[:16]
        plan_id = f"deser_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"Serialized-format confirmation for {finding.vulnerability_class}",
            success_signals=["Deterministically confirm a serialized-object format signature"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        try:
            candidates = self._collect_candidate_values(exchange)
            if not candidates:
                return ValidationResult(
                    validator=self.get_name(), status="skipped",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary="No cookie, header, or body values in this exchange to fingerprint",
                    evidence="", raw_output="[]",
                )

            matches = []
            for source, value in candidates:
                fmt = self._identify_format(value)
                if fmt:
                    matches.append((source, fmt))

            observed = bool(matches)
            if observed:
                lines = [f"  - {source}: {fmt} serialized-object format signature "
                         f"(analyst tooling for exploitability testing: {_FORMAT_TOOLS.get(fmt, 'n/a')})"
                         for source, fmt in matches]
                # RETIRED (review 2026-09-09): a serialized-object FORMAT signature is
                # a structural OBSERVATION, not a confirmed insecure-deserialization
                # vulnerability -- a Java/PHP/ViewState blob may be signed, integrity-
                # checked, or never deserialized untrusted. This no longer sets
                # confirmed=True. Active exploitability is proven by the SEPARATE
                # deserialization_oob leg (a benign OOB pickle/gadget beacon).
                # Re-qualify: keep this as the informational format observation; do
                # not restore a confirmed verdict here.
                summary = ("Serialized-object format OBSERVED (informational, NOT confirmed) in "
                           f"{len(matches)} location(s) -- exploitability needs the deserialization_oob "
                           "leg:\n" + "\n".join(lines))
            else:
                summary = ("No known serialized-object format signature (Java magic bytes, PHP "
                           "serialization syntax, .NET ViewState field) matched any value in this "
                           "exchange -- this doesn't rule out other/obfuscated formats")

            return ValidationResult(
                validator=self.get_name(),
                status="not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.2 if observed else 0.05,  # observation only -- never a confirmation
                confirmed=False,
                summary=summary,
                evidence="; ".join(f"{s}: {f}" for s, f in matches) if matches else "",
                raw_output=str(matches),
            )
        except Exception as e:
            log.error(f"Deserialization validation error: {e}")
            return ValidationResult(
                validator=self.get_name(), status="error",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=f"Deserialization validation failed: {e}", evidence="", raw_output=str(e),
            )

    def _collect_candidate_values(self, exchange: HttpExchange) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []
        req_headers = exchange.request_headers or {}
        cookie = req_headers.get("Cookie") or req_headers.get("cookie")
        if cookie:
            for part in cookie.split(";"):
                if "=" in part:
                    name, _, value = part.strip().partition("=")
                    candidates.append((f"Cookie:{name}", value))
        if exchange.request_body:
            candidates.append(("request_body", exchange.request_body))
        if exchange.response_body:
            candidates.append(("response_body", exchange.response_body[:20000]))
        return candidates

    def _identify_format(self, value: str) -> str | None:
        if not value:
            return None

        if _DOTNET_VIEWSTATE_FIELD in value:
            return "dotnet_viewstate"

        if _PHP_SERIALIZED.match(value.strip()):
            return "php"

        if value.strip().startswith(_JAVA_B64_PREFIX):
            try:
                decoded = base64.b64decode(value.strip()[:16] + "====", validate=False)
                if decoded.startswith(_JAVA_MAGIC):
                    return "java"
            except Exception:
                pass

        # Raw (non-base64) bytes case -- only reachable if the body/value
        # somehow carries raw bytes as text; included for completeness.
        if isinstance(value, str) and "\xac\xed" in value:
            return "java"

        return None
