"""Hermetic tests for P0.1-WIRE: the oracle gate wired into
ConfirmMixin._validate_findings, behind the default-off `oracle.enabled`
config flag.

No network, no model, no live target. Uses the same ScriptedValidator/
FakeRegistry pattern as test_oracle_framework.py, driven through the real
Orchestrator._validate_findings so the wiring itself (not just the oracle
framework in isolation) is exercised.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator_confirm import ConfirmMixin
from harness.validators.base import Validator, ValidationResult


def _exchange():
    return HttpExchange(url="http://127.0.0.1/x?url=http://evil", method="GET")


def _report(cls="ssrf"):
    finding = Finding(vulnerability_class=cls, confidence=0.6, summary="s",
                       evidence="e", suggested_test="t", basis="derived")
    return AgentReport(agent="fake_agent", model="fake_model", findings=[finding])


class ConfirmingValidator(Validator):
    """Confirms once (the initial `_validate_findings` dispatch call), and
    tracks every subsequent call the oracle gate makes if it fires."""
    name = "ssrf"  # self-controlling per negative_controls.SELF_CONTROLLING
    finding_classes = {"ssrf"}
    active = True

    def __init__(self):
        self.calls = 0

    async def validate(self, finding, exchange):
        self.calls += 1
        return ValidationResult(
            "ssrf", "confirmed", "ssrf", confidence=0.9, confirmed=True,
            summary="callback observed", evidence="oob hit")

    def plan(self, finding, exchange):
        return None


class NeverConfirmingValidator(Validator):
    name = "ssrf"
    finding_classes = {"ssrf"}
    active = True

    def __init__(self):
        self.calls = 0

    async def validate(self, finding, exchange):
        self.calls += 1
        return ValidationResult(
            "ssrf", "not_confirmed", "ssrf", confidence=0.0, confirmed=False,
            summary="no callback")

    def plan(self, finding, exchange):
        return None


class FakeValidatorRegistry:
    """Minimal stand-in for validators.registry.ValidatorRegistry: only the
    surface `_validate_findings` and `OracleRegistry` actually use."""
    active_enabled = False

    def __init__(self, validator):
        self._validator = validator

    def for_finding(self, finding, exchange):
        return [self._validator]

    def bind_run_context(self, validators, run_context):
        return validators


class Harness(ConfirmMixin):
    """Bare object exposing exactly the attributes ConfirmMixin's
    _validate_findings/_oracle_gate read, avoiding a full Orchestrator
    construction (which needs Ollama/agent-manager wiring irrelevant here)."""

    def __init__(self, validator, config):
        self.validator_registry = FakeValidatorRegistry(validator)
        self.config = config
        self.allowed_hosts = ["127.0.0.1"]
        self.max_concurrent_validations = 6


def run(coro):
    return asyncio.run(coro)


def _patch_persistence():
    """_validate_findings persists proofs/plans/submissions to the real sqlite
    store; stub those out so the test is hermetic and fast."""
    return (
        patch("harness.orchestrator_confirm.store.persist_proof_record",
              return_value=(True, "")),
        patch("harness.orchestrator_confirm.store.persist_test_plans",
              return_value=None),
        patch("harness.orchestrator_confirm.store.persist_validation_submission",
              return_value=(True, "")),
    )


class TestOracleGateDisabledByDefault(unittest.TestCase):
    def test_disabled_sends_zero_extra_probes(self):
        """Negative control: with oracle.enabled unset (default false), the
        oracle must NEVER be invoked -- the validator sees exactly the ONE
        call _validate_findings itself makes, not the N reproduction calls
        an active oracle would add."""
        validator = ConfirmingValidator()
        h = Harness(validator, config={})
        report = _report()
        p1, p2, p3 = _patch_persistence()
        with p1, p2, p3:
            reports, proofs = run(h._validate_findings(_exchange(), [report]))
        finding = report.findings[0]
        self.assertTrue(finding.confirmed)
        self.assertEqual(finding.verification_state, "candidate")
        self.assertFalse(finding.oracle_verified)
        # Exactly one call: _validate_findings' own dispatch. The oracle
        # gate, if it had fired, would add n_required (default 3) more.
        self.assertEqual(validator.calls, 1)

    def test_explicit_false_also_sends_zero_extra_probes(self):
        validator = ConfirmingValidator()
        h = Harness(validator, config={"oracle": {"enabled": False}})
        report = _report()
        p1, p2, p3 = _patch_persistence()
        with p1, p2, p3:
            run(h._validate_findings(_exchange(), [report]))
        self.assertEqual(validator.calls, 1)
        self.assertEqual(report.findings[0].verification_state, "candidate")


class TestOracleGateEnabled(unittest.TestCase):
    def test_enabled_and_reproduces_promotes_to_verified(self):
        validator = ConfirmingValidator()
        h = Harness(validator, config={"oracle": {"enabled": True, "n_required": 2}})
        report = _report()
        p1, p2, p3 = _patch_persistence()
        with p1, p2, p3:
            run(h._validate_findings(_exchange(), [report]))
        finding = report.findings[0]
        self.assertTrue(finding.confirmed)
        self.assertTrue(finding.oracle_verified)
        self.assertEqual(finding.verification_state, "verified")
        self.assertNotEqual(finding.oracle_capsule_id, "")
        # One dispatch call + n_required (2) reproduction calls.
        self.assertEqual(validator.calls, 3)

    def test_enabled_but_never_confirmed_stays_candidate_no_oracle_call(self):
        """Negative control: a finding that never gets past the initial
        dispatch (not_confirmed) must never reach the oracle gate at all --
        _oracle_gate is only invoked inside the `if result.confirmed:`
        branch."""
        validator = NeverConfirmingValidator()
        h = Harness(validator, config={"oracle": {"enabled": True, "n_required": 3}})
        report = _report()
        p1, p2, p3 = _patch_persistence()
        with p1, p2, p3:
            run(h._validate_findings(_exchange(), [report]))
        finding = report.findings[0]
        self.assertFalse(finding.confirmed)
        self.assertEqual(finding.verification_state, "candidate")
        self.assertFalse(finding.oracle_verified)
        # Only the initial dispatch call -- the oracle gate never fired.
        self.assertEqual(validator.calls, 1)


if __name__ == "__main__":
    unittest.main()
