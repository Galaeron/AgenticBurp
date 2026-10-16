"""False-confirmation caller-level regression (ARCH follow-up to e28d2d12).

Claim-A evidence must not confirm claim B. The backstop in
ConfirmMixin._validate_findings only honours a confirmation reached via the
AGENT-FALLBACK route when the validator's result class matches the routing token.
test_agent_routing_caller.py already covers the single mismatched-class negative;
these add the COMPLEMENTS the review asked for: a positive control (a matching
fallback still confirms), per-finding isolation on one exchange (a mismatched
fallback does not leak the proof of a sibling finding that legitimately confirmed),
and proof that the backstop is scoped to the fallback route (a direct match is
untouched). All state the downstream reads -- finding.confirmed / proof_id /
review_verdict and the ValidationReport -- is asserted directly; the API response,
stored finding and exported report all read exactly these.

Removing the class-check in _validate_findings makes the mismatch assertions fail.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator_confirm import ConfirmMixin
from harness.run_context import RunContext
from harness.validators.base import ValidationResult
from harness.validators.registry import ValidatorRegistry


class _FallbackOnly:
    """Passive validator that applies ONLY to a routing token (the producing-agent
    name), never to the finding's own class -- so it is reached via the fallback
    route. `result_class` is what it reports back (echo => well-behaved;
    a fixed unrelated class => the auth_sequence-style bug)."""
    active = False
    run_context = None
    version = "test"

    def __init__(self, name, token, result_class=None):
        self.name = name
        self._token = token
        self._result_class = result_class  # None => echo what it was handed

    def applies(self, finding, exchange):
        return finding.vulnerability_class == self._token

    def plan(self, finding, exchange):
        return None

    async def validate(self, finding, exchange):
        await asyncio.sleep(0)
        cls = self._result_class or finding.vulnerability_class
        return ValidationResult(self.name, "confirmed", cls, confirmed=True,
                                confidence=0.9, summary=f"{cls} proof")


class _DirectAndFallback:
    """Applies to BOTH a direct class and a routing token, always reporting a fixed
    (unrelated) result class. On the direct route the backstop must NOT fire; on the
    fallback route it must."""
    active = False
    run_context = None
    version = "test"
    name = "dual"

    def __init__(self, direct_class, token, result_class):
        self._direct = direct_class
        self._token = token
        self._result_class = result_class

    def applies(self, finding, exchange):
        return finding.vulnerability_class in (self._direct, self._token)

    def plan(self, finding, exchange):
        return None

    async def validate(self, finding, exchange):
        await asyncio.sleep(0)
        return ValidationResult(self.name, "confirmed", self._result_class,
                                confirmed=True, confidence=0.9, summary="fixed proof")


def _caller(validators):
    config = {"validators": {"enabled": True}}
    caller = ConfirmMixin()
    caller.config = config
    caller.allowed_hosts = ["routing.invalid"]
    caller.validator_registry = ValidatorRegistry(config)
    caller.validator_registry.validators = validators
    return caller, config


def _finding(cls, fid):
    return Finding(vulnerability_class=cls, confidence=0.6, severity="medium",
                   summary="hypothesis", evidence="", suggested_test="t",
                   basis="derived", finding_id=fid)


class ConfirmationClassBindingCallerTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, caller, config, report):
        exchange = HttpExchange(url="https://routing.invalid/items", method="GET",
                                response_status=200, response_body="listing")
        context = RunContext.create(allowed_hosts=caller.allowed_hosts, config=config)
        try:
            with patch.object(caller, "_persist_confirmation_proof",
                              AsyncMock(return_value=(True, {"proof_id": "proof-1"}, ""))), \
                 patch.object(caller, "_oracle_gate", AsyncMock()), \
                 patch("harness.store.persist_validation_submission", return_value=(True, "")):
                validations, _ = await caller._validate_findings(
                    exchange, [report], run_context=context)
            return validations
        finally:
            await context.aclose()

    async def test_matching_fallback_label_confirms_and_stamps_the_finding(self):
        """Positive control: a well-behaved validator reached via the fallback route
        echoes the routing token, so the class matches and the confirmation stands --
        the backstop must not block a legitimate fallback confirmation."""
        caller, config = _caller({"echo": _FallbackOnly("echo", token="auth")})
        finding = _finding("cleartext_transmission", "f-pos")
        report = AgentReport(agent="auth", model="synthetic", findings=[finding])
        validations = await self._run(caller, config, report)
        self.assertEqual(len(validations), 1)
        self.assertTrue(validations[0].confirmed)
        # stamped back onto THIS finding's own class, not the routing token
        self.assertEqual(validations[0].finding_class, "cleartext_transmission")
        self.assertTrue(finding.confirmed)
        self.assertEqual(finding.proof_id, "proof-1")
        self.assertEqual(finding.review_verdict, "validator-confirmed")

    async def test_mismatched_fallback_does_not_confirm_or_stamp_proof(self):
        """A fallback validator that reports an UNRELATED class never confirms the
        finding, and stamps no proof onto it (no alternate path restores it)."""
        caller, config = _caller({
            "bug": _FallbackOnly("bug", token="auth", result_class="username_enumeration")})
        finding = _finding("cleartext_transmission", "f-neg")
        report = AgentReport(agent="auth", model="synthetic", findings=[finding])
        validations = await self._run(caller, config, report)
        self.assertEqual(len(validations), 1)
        self.assertFalse(validations[0].confirmed)
        self.assertEqual(validations[0].status, "skipped")
        self.assertEqual(validations[0].finding_class, "cleartext_transmission")
        self.assertFalse(finding.confirmed)
        self.assertEqual(finding.proof_id, "")           # proof never stamped
        self.assertIsNone(finding.review_verdict)

    async def test_per_finding_binding_isolates_mismatch_from_valid_confirmation(self):
        """Two findings on ONE exchange and ONE report (agent 'auth'). The same
        validator reports a fixed unrelated class for both. For the finding it
        reaches by FALLBACK the mismatch is skipped; for the finding it matches
        DIRECTLY the backstop does not apply and the confirmation stands. The valid
        confirmation's proof must not leak onto the skipped finding."""
        # An sqli validator: it legitimately confirms the sqli finding it matches
        # DIRECTLY, but when the agent-fallback mis-routes it onto the cleartext
        # finding it must be skipped, not allowed to stamp "sqli" onto cleartext.
        caller, config = _caller({
            "dual": _DirectAndFallback(direct_class="sqli", token="auth",
                                       result_class="sqli")})
        f_fallback = _finding("cleartext_transmission", "f-fallback")  # reached via 'auth'
        f_direct = _finding("sqli", "f-direct")                        # matched directly
        report = AgentReport(agent="auth", model="synthetic",
                             findings=[f_fallback, f_direct])
        validations = await self._run(caller, config, report)

        by_fid = {v.finding_class: v for v in validations}
        self.assertEqual(len(validations), 2)
        # fallback finding: mismatched class -> skipped, never confirmed/stamped
        self.assertFalse(f_fallback.confirmed)
        self.assertEqual(f_fallback.proof_id, "")
        self.assertFalse(by_fid["cleartext_transmission"].confirmed)
        self.assertEqual(by_fid["cleartext_transmission"].status, "skipped")
        # direct finding: backstop is fallback-only, so the direct match still confirms
        self.assertTrue(f_direct.confirmed)
        self.assertEqual(f_direct.proof_id, "proof-1")
        self.assertTrue(by_fid["sqli"].confirmed)


if __name__ == "__main__":
    unittest.main()
