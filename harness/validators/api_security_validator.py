"""
API Security Validator

Active validator covering two of the API-security agent's checks that
lend themselves to a concrete probe from a single captured exchange:

1. Mass assignment -- resend a JSON body with an extra unexpected
   field; confirmed only on a controlled change of the written object: a
   baseline GET before the write shows the field absent or holding another
   value, the write is accepted (2xx), and an independent GET read-back
   shows the submitted value. An echo, a field already set before, or a
   change with no readable baseline is a candidate, never a confirmation.
   The field is harness-invented metadata: a confirmation shows that
   unknown body fields are bound, not that a protected property changes.
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
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

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
    candidate: bool = False  # signal seen, proof missing -- never a confirmation

    def to_dict(self) -> dict:
        return {
            "test": self.test_name, "passed": self.passed, "severity": self.severity,
            "detail": self.detail, "evidence": self.evidence,
            "vulnerable": self.vulnerable, "checked": self.checked, "candidate": self.candidate,
        }


def _probe_values(value: Any, _depth: int = 0) -> list:
    """Every value the probe field holds in a parsed JSON value (objects nest
    under wrapper keys and lists)."""
    if _depth > 8:
        return []
    out = []
    if isinstance(value, dict):
        if _MASS_ASSIGNMENT_PROBE_FIELD in value:
            out.append(value[_MASS_ASSIGNMENT_PROBE_FIELD])
        value = list(value.values())
    if isinstance(value, list):
        for v in value:
            out += _probe_values(v, _depth + 1)
    return out


def _holds(values: list, submitted: bool) -> bool:
    # Identity, not equality: JSON 1 or 0 is not the boolean that was sent.
    return any(v is submitted for v in values)


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
            candidate_tests = [t for t in tests if t.candidate and not t.vulnerable]
            vulnerable = bool(vulnerable_tests)
            summary_parts = []
            if vulnerable_tests:
                summary_parts.append(f"API security issue(s) confirmed: {len(vulnerable_tests)}")
                for t in vulnerable_tests:
                    summary_parts.append(f"  - {t.test_name}: {t.detail}")
            elif candidate_tests:
                summary_parts.append("Candidate only, not confirmed:")
                for t in candidate_tests:
                    summary_parts.append(f"  - {t.test_name}: {t.detail}")
            else:
                summary_parts.append("No mass assignment or unbounded resource consumption confirmed")

            if vulnerable:
                status, confidence = "confirmed", 0.75
            elif candidate_tests:
                status, confidence = "inconclusive", 0.4
            else:
                status, confidence = "not_confirmed", 0.2
            return ValidationResult(
                validator=self.get_name(),
                status=status,
                finding_class=finding.vulnerability_class,
                confidence=confidence,
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

        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        headers["User-Agent"] = self.user_agent
        headers.setdefault("Content-Type", "application/json")
        url = exchange.url

        after = loc_state = None
        after_note = loc_url = ""
        try:
            async with GatedAsyncClient(
                get_default_gate(), self.get_name(),
                timeout=self.timeout, follow_redirects=False, max_redirects=self.max_redirects,
            ) as client:
                from harness import global_throttle
                # E1: a field that already reads true before a write that changes
                # nothing is not mass assignment. Read the object first, and send
                # a value it does not already hold (false when an earlier probe
                # left it true), so the read-back can show a controlled change.
                baseline, baseline_note = await self._read_state(client, exchange, url)
                before = None if baseline is None else _probe_values(baseline)
                submitted = not (before is not None and _holds(before, True))
                probed_body = dict(body)
                probed_body[_MASS_ASSIGNMENT_PROBE_FIELD] = submitted
                await global_throttle.acquire()
                response = await client.request(
                    exchange.method, url,
                    headers=headers, content=jsonlib.dumps(probed_body),
                )
                # R18: an echo is not persistence (a 400 that names the field to
                # reject it echoes it too). Only an accepted write is re-read,
                # with an independent GET of the object that was baselined.
                if 200 <= response.status_code < 300:
                    after, after_note = await self._read_state(client, exchange, url)
                    loc_url = self._created_location(exchange, response)
                    if loc_url and not (after is not None and _holds(_probe_values(after), submitted)):
                        loc_state, _ = await self._read_state(client, exchange, loc_url)
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

        field, value = _MASS_ASSIGNMENT_PROBE_FIELD, jsonlib.dumps(submitted)
        status = response.status_code
        stored = after is not None and _holds(_probe_values(after), submitted)
        if before is None:
            before_desc = f"could not be read {baseline_note}"
        elif not before:
            before_desc = "absent"
        else:
            before_desc = "holding " + ", ".join(jsonlib.dumps(v) for v in before)
        if stored and before is not None and not _holds(before, submitted):
            return ApiSecurityTestResult(
                "Mass Assignment Probe", False, "medium",
                f"An unexpected field ({field}), {before_desc} in a baseline read of {url}, was sent as "
                f"{value} in an accepted write (status {status}), and an independent read-back of {url} "
                f"shows the submitted value -- the endpoint binds request-body fields it does not expect "
                f"into the stored object, without an allowlist of settable fields. {field} is "
                f"harness-invented metadata: this shows that unknown fields are stored, not that a "
                f"protected property (role, isAdmin, etc.) can be changed; test those explicitly before "
                f"claiming privilege escalation",
                f"Baseline GET {url} -> {field} {before_desc}; write status {status} with {field}={value}; "
                f"read-back GET {url} -> {field}={value}",
                vulnerable=True,
            )
        if stored:
            return self._ma_candidate(
                f"The read-back of {url} shows the submitted {field}={value} after an accepted write "
                f"(status {status}), but the baseline {before_desc}, so no controlled change was shown "
                f"(the value may predate the write).",
                f"Baseline {before_desc}; read-back GET {url} -> {field}={value}")
        if loc_state is not None and _holds(_probe_values(loc_state), submitted):
            return self._ma_candidate(
                f"The write (status {status}) pointed at {loc_url}, which carries the submitted "
                f"{field}={value}, but that object had no baseline before the write, so no controlled "
                f"change was shown.",
                f"Write status {status}; read-back GET {loc_url} -> {field}={value} (no baseline)")
        if _probe_values(resp_json):
            return self._ma_candidate(
                f"The response echoed the unexpected field ({field}) with status {status}, but no "
                f"independent read-back showed the submitted value stored "
                f"{after_note or '(the write was not accepted, so nothing was re-read)'} -- an echo "
                f"alone is not mass assignment (a validation error naming the field echoes it too).",
                f"Status {status}, response contains {field}")
        if before:
            return self._ma_candidate(
                f"{field} was already {before_desc} before the write, and the accepted write of {value} "
                f"(status {status}) did not change it {after_note} -- an earlier probe may have stored "
                f"it, but this attempt did not show the field being bound.",
                f"Baseline GET {url} -> {field} {before_desc}; write status {status} with {field}={value}")
        return ApiSecurityTestResult(
            "Mass Assignment Probe", True, "low",
            f"Unexpected field not reflected back (status {status}) and not seen "
            f"persisted {after_note or '(the write was not accepted)'} -- "
            "no evidence of unrestricted mass assignment from this probe",
            f"Status: {status}", vulnerable=False,
        )

    @staticmethod
    def _ma_candidate(detail: str, evidence: str) -> ApiSecurityTestResult:
        return ApiSecurityTestResult(
            "Mass Assignment Probe", True, "medium",
            f"{detail} Candidate only; confirm by re-reading the object.", evidence,
            vulnerable=False, candidate=True,
        )

    @staticmethod
    def _created_location(exchange: HttpExchange, response) -> str:
        """The write's same-origin Location when it names another object."""
        location = response.headers.get("location") or ""
        if not location:
            return ""
        target = urljoin(exchange.url, location)
        a, b = urlparse(exchange.url), urlparse(target)
        return target if (a.scheme, a.netloc) == (b.scheme, b.netloc) and target != exchange.url else ""

    async def _read_state(self, client, exchange: HttpExchange, url: str) -> tuple[Any, str]:
        """GET url with the captured credentials. Returns (state, note): state is
        the parsed JSON of a 2xx answer, else None with a note saying why."""
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "content-type", "host")}
        headers["User-Agent"] = self.user_agent
        try:
            from harness import global_throttle
            await global_throttle.acquire()
            got = await client.request("GET", url, headers=headers)
        except SafetyGateBlocked as e:
            return None, f"(GET blocked by safety gate: {e.decision.reason})"
        except Exception as e:
            log.debug(f"Mass assignment state read failed: {e}")
            return None, f"(GET {url} failed: {e})"
        if not 200 <= got.status_code < 300:
            return None, f"(GET {url} -> status {got.status_code})"
        try:
            return got.json(), ""
        except Exception:
            return None, f"(GET {url} returned no JSON)"

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
            # I05: the gated client, like the mass-assignment probe, so inside an
            # entered run this probe spends that run (budget, scope, cancellation, TLS).
            async with GatedAsyncClient(
                get_default_gate(), self.get_name(),
                timeout=self.timeout, follow_redirects=False, max_redirects=self.max_redirects,
            ) as client:
                from harness import global_throttle
                await global_throttle.acquire()
                response = await client.request(
                    "GET", probe_url,  # pagination is inherently a read operation; never replay the captured method
                    headers={"User-Agent": self.user_agent},
                )
        except SafetyGateBlocked as e:
            return ApiSecurityTestResult("Unbounded Limit Probe", True, "low",
                                          f"Blocked by safety gate: {e.decision.reason}", "",
                                          checked=True, vulnerable=False)
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
            candidates = [t for t in tests if t.candidate]
            if candidates:
                return "No API security issue confirmed; candidate: " + " | ".join(
                    f"{t.test_name}: {t.evidence}" for t in candidates)
            return "No API security issue confirmed"
        return " | ".join(f"{t.test_name}: {t.evidence} -- {t.detail} ({t.severity})" for t in vulnerable)

    def _build_raw_output(self, tests: list[ApiSecurityTestResult]) -> str:
        return jsonlib.dumps([t.to_dict() for t in tests], indent=2)
