"""EFF-1: a validator's `not_confirmed` is tri-state on its control (held / failed /
unknown), and only a held control refutes a finding.

Before this, the confirmation gate counted `control_outcome in ("", "control_held")`
as a controlled negative, so any validator that simply did not say -- an SSTI leg
that saw no evaluated product, a sqlmap that crashed -- demoted a live-class finding
to "likely false positive" (`unconfirmed_hypothesis`). The unit tests pin the
mapping; the caller tests run the real confirmation caller (ConfirmMixin) and the
real suppression gate, stubbing only the leg's verdict and persistence. Each
"not refuted" case has a held-control negative control that still refutes, so the
gate has not simply stopped refuting.
"""
import asyncio
import unittest
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

from harness import global_throttle
from harness.confirmation_gate import apply_confirmation_suppression
from harness.control_outcome import (
    CONTROL_FAILED, CONTROL_HELD, CONTROL_NOT_RUN, control_state, covers_case,
    is_controlled_negative)
from harness.models import AgentReport, Finding, HttpExchange, ValidationReport
from harness.orchestrator_confirm import ConfirmMixin
from harness.run_context import RunContext
from harness.validators.base import ValidationResult
from harness.validators.injection_targets import NAMED_PARAMETER_UNTESTED, PARTIAL_COVERAGE
from harness.validators.registry import ValidatorRegistry

_NOT_HELD = ("", None, CONTROL_FAILED, CONTROL_NOT_RUN, "inconclusive",
             NAMED_PARAMETER_UNTESTED, PARTIAL_COVERAGE, "unrecognised-value")


def _finding(vc="sqli"):
    return Finding(vulnerability_class=vc, confidence=0.85, severity="high",
                   summary=f"{vc} on /x", evidence="e", suggested_test="t", basis="derived")


def _gate(outcome, vc="sqli"):
    finding = _finding(vc)
    apply_confirmation_suppression(
        [AgentReport(agent="a", model="test", findings=[finding])],
        validation_reports=[ValidationReport(validator="v", status="not_confirmed",
                                             finding_class=vc, confirmed=False,
                                             control_outcome=outcome)])
    return finding


class ControlStateTests(unittest.TestCase):
    def test_only_control_held_reads_as_held(self):
        self.assertEqual(control_state(CONTROL_HELD), "held")
        self.assertEqual(control_state(" Control_Held "), "held")
        self.assertEqual(control_state(CONTROL_FAILED), "failed")
        for outcome in _NOT_HELD:
            if outcome != CONTROL_FAILED:
                self.assertEqual(control_state(outcome), "unknown", outcome)

    def test_a_controlled_negative_needs_not_confirmed_and_a_held_control(self):
        self.assertTrue(is_controlled_negative("not_confirmed", False, CONTROL_HELD))
        for outcome in _NOT_HELD:
            self.assertFalse(is_controlled_negative("not_confirmed", False, outcome), outcome)
        self.assertFalse(is_controlled_negative("not_confirmed", True, CONTROL_HELD))
        for status in ("inconclusive", "error", "skipped", "", None):
            self.assertFalse(is_controlled_negative(status, False, CONTROL_HELD), status)

    def test_coverage_reading_still_counts_an_unset_outcome_as_covering(self):
        self.assertTrue(covers_case(""))
        self.assertTrue(covers_case(None))
        self.assertTrue(covers_case(CONTROL_HELD))
        for outcome in (CONTROL_FAILED, CONTROL_NOT_RUN, "inconclusive",
                        NAMED_PARAMETER_UNTESTED, PARTIAL_COVERAGE):
            self.assertFalse(covers_case(outcome), outcome)


class GateTriStateTests(unittest.TestCase):
    def test_not_confirmed_with_an_empty_outcome_is_not_refuted(self):
        finding = _gate("")
        self.assertNotEqual(finding.review_verdict, "unconfirmed_hypothesis")
        self.assertEqual(finding.review_verdict, "inconclusive_unverified")
        self.assertTrue(finding.summary.startswith("[Unverified] "))

    def test_no_control_state_but_held_refutes(self):
        for outcome in (o for o in _NOT_HELD if o is not None):  # the model field is a str
            with self.subTest(outcome=outcome):
                self.assertEqual(_gate(outcome).review_verdict, "inconclusive_unverified")

    def test_control_a_held_control_still_refutes(self):
        finding = _gate(CONTROL_HELD)
        self.assertEqual(finding.review_verdict, "unconfirmed_hypothesis")
        self.assertEqual(finding.severity, "low")
        self.assertTrue(finding.summary.startswith("[Hypothesis] "))


class ConfirmationCallerTests(unittest.TestCase):
    """The real caller copies the leg's control_outcome onto the ValidationReport
    the gate reads; a leg that does not report a held control never refutes."""

    @classmethod
    def setUpClass(cls):
        global_throttle.configure(0)

    def run_caller(self, outcome):
        async def run():
            hosts = ["127.0.0.1"]
            config = {"server": {"allowed_hosts": hosts},
                      "validators": {"enabled": True, "active_enabled": True}}
            caller = ConfirmMixin()
            caller.config = config
            caller.allowed_hosts = hosts
            caller.validator_registry = ValidatorRegistry(config)
            leg = caller.validator_registry.validators["ssti"]
            caller.validator_registry.validators = {"ssti": leg}
            finding = Finding(vulnerability_class="ssti", confidence=0.85, severity="high",
                              summary="template expression evaluated", evidence="synthetic",
                              suggested_test="tpl={{7*7}}", basis="derived", finding_id="f-1")
            exchange = HttpExchange(url="http://127.0.0.1:9/render?tpl=hi", method="GET",
                                    response_status=200, response_body="<html>tpl=hi</html>")
            report = AgentReport(agent="ssti", model="synthetic", findings=[finding])
            context = RunContext.create(allowed_hosts=hosts, config=config,
                                        gate_config={"active_enabled": True})
            verdict = ValidationResult("ssti", "not_confirmed", "ssti", confidence=0.0,
                                       confirmed=False, summary="no evaluated product",
                                       control_outcome=outcome)
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.object(type(leg), "validate",
                                                     AsyncMock(return_value=verdict)))
                    stack.enter_context(patch.object(caller, "_persist_confirmation_proof", AsyncMock(
                        return_value=(True, {"proof_id": "synthetic"}, ""))))
                    stack.enter_context(patch("harness.store.persist_test_plans"))
                    stack.enter_context(patch("harness.store.persist_validation_submission",
                                              return_value=(True, "")))
                    stack.enter_context(patch("harness.evidence_ledger.emit"))
                    validations, _ = await caller._validate_findings(
                        exchange, [report], run_context=context)
            finally:
                await context.aclose()
            apply_confirmation_suppression([report], validations)
            self.assertEqual(len(validations), 1, validations)
            return validations[0], finding
        return asyncio.run(run())

    def test_a_leg_that_did_not_report_its_control_does_not_refute(self):
        report, finding = self.run_caller("")
        self.assertEqual((report.status, report.control_outcome), ("not_confirmed", ""))
        self.assertEqual(finding.review_verdict, "inconclusive_unverified")
        self.assertFalse(finding.confirmed)

    def test_a_failed_control_does_not_refute(self):
        report, finding = self.run_caller(CONTROL_FAILED)
        self.assertEqual(report.control_outcome, CONTROL_FAILED)
        self.assertEqual(finding.review_verdict, "inconclusive_unverified")

    def test_control_a_leg_that_reports_a_held_control_refutes(self):
        report, finding = self.run_caller(CONTROL_HELD)
        self.assertEqual(report.control_outcome, CONTROL_HELD)
        self.assertEqual(finding.review_verdict, "unconfirmed_hypothesis")
        self.assertEqual(finding.severity, "low")


if __name__ == "__main__":
    unittest.main()
