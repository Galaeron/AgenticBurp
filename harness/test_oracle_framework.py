"""Hermetic tests for the oracle framework (precision items #1/#2).

No network, no model, no live target -- fake validators with scripted results
drive every path, including negative controls (the point of the framework).
"""
from __future__ import annotations

import asyncio
import unittest

from harness.models import Finding, HttpExchange
from harness.validators.base import Validator, ValidationResult
from harness import oracle_framework
from harness.oracle_framework import (
    Oracle, OracleRegistry, ProofCapsule, derive_verification_state, stamp_finding,
    STATE_VERIFIED, STATE_CANDIDATE,
)


def _finding(cls="ssrf"):
    return Finding(vulnerability_class=cls, confidence=0.8, summary="s",
                   evidence="e", suggested_test="t", basis="derived")


def _exchange(url="http://127.0.0.1/x?url=http://evil"):
    return HttpExchange(url=url, method="GET")


def _confirmed(cls="ssrf"):
    return ValidationResult("fake", "confirmed", cls, confidence=0.95, confirmed=True,
                            summary="hit", evidence="callback")


def _clean(cls="ssrf"):
    return ValidationResult("fake", "not_confirmed", cls, confidence=0.0, confirmed=False,
                            summary="no hit")


class ScriptedValidator(Validator):
    """Returns queued results in order; distinguishes benign-variant calls by URL."""
    name = "fake"
    finding_classes = {"ssrf"}
    active = True

    def __init__(self, results, *, benign_marker=None, benign_result=None):
        self._results = list(results)
        self._benign_marker = benign_marker
        self._benign_result = benign_result
        self.calls = []

    async def validate(self, finding, exchange):
        self.calls.append(exchange.url)
        if self._benign_marker and self._benign_marker in exchange.url:
            return self._benign_result
        return self._results.pop(0)


def run(coro):
    return asyncio.run(coro)


class TestReproduction(unittest.TestCase):
    def test_n_of_n_all_confirmed_reproduces(self):
        v = ScriptedValidator([_confirmed(), _confirmed(), _confirmed()])
        oracle = Oracle(v, n_required=3, require_negative_control=False)
        ok, reps = run(oracle.reproduce(_finding(), _exchange()))
        self.assertTrue(ok)
        self.assertEqual(len(reps), 3)

    def test_one_miss_breaks_reproduction_and_stops_early(self):
        v = ScriptedValidator([_confirmed(), _clean(), _confirmed()])
        oracle = Oracle(v, n_required=3, require_negative_control=False)
        ok, reps = run(oracle.reproduce(_finding(), _exchange()))
        self.assertFalse(ok)
        # Stopped early on the miss -- only two calls, not three.
        self.assertEqual(len(reps), 2)

    def test_n_required_must_be_positive(self):
        with self.assertRaises(ValueError):
            Oracle(ScriptedValidator([]), n_required=0)


class TestCleanNegative(unittest.TestCase):
    def test_executed_not_confirmed_is_clean_negative(self):
        v = ScriptedValidator([_clean(), _clean()])
        oracle = Oracle(v, n_required=2, require_negative_control=False)
        cap = run(oracle.run(_finding(), _exchange()))
        self.assertFalse(cap.reproduced)
        self.assertTrue(cap.reproduction_clean_negative)

    def test_skipped_probe_is_not_clean_negative(self):
        skipped = ValidationResult("fake", "skipped", "ssrf", confirmed=False, summary="out of scope")
        v = ScriptedValidator([skipped])
        oracle = Oracle(v, n_required=2, require_negative_control=False)
        cap = run(oracle.run(_finding(), _exchange()))
        self.assertFalse(cap.reproduced)
        self.assertFalse(cap.reproduction_clean_negative)
        self.assertIn("INCONCLUSIVE", cap.reason)

    def test_error_probe_is_not_clean_negative(self):
        err = ValidationResult("fake", "error", "ssrf", confirmed=False, summary="boom")
        v = ScriptedValidator([err])
        oracle = Oracle(v, n_required=2, require_negative_control=False)
        cap = run(oracle.run(_finding(), _exchange()))
        self.assertFalse(cap.reproduction_clean_negative)


class TestSelfControlling(unittest.TestCase):
    def test_self_controlling_verified_on_reproduction_alone(self):
        v = ScriptedValidator([_confirmed(), _confirmed()])
        oracle = Oracle(v, n_required=2, require_negative_control=False)
        cap = run(oracle.run(_finding(), _exchange()))
        self.assertTrue(cap.reproduced)
        self.assertTrue(cap.verified)
        self.assertFalse(cap.negative_control_available)

    def test_self_controlling_not_verified_when_reproduction_fails(self):
        v = ScriptedValidator([_confirmed(), _clean()])
        oracle = Oracle(v, n_required=2, require_negative_control=False)
        cap = run(oracle.run(_finding(), _exchange()))
        self.assertFalse(cap.reproduced)
        self.assertFalse(cap.verified)
        self.assertIn("did not reproduce", cap.reason)


class TestNegativeControl(unittest.TestCase):
    def _builder(self):
        # Rewrites the URL to a benign marker the ScriptedValidator recognises.
        def build(exchange):
            data = exchange.model_dump()
            data["url"] = "http://127.0.0.1/x?url=BENIGN"
            return HttpExchange(**data)
        return build

    def test_verified_requires_clean_negative_control(self):
        v = ScriptedValidator([_confirmed(), _confirmed(), _confirmed()],
                              benign_marker="BENIGN", benign_result=_clean())
        oracle = Oracle(v, n_required=3, negative_control=self._builder(),
                        require_negative_control=True)
        cap = run(oracle.run(_finding(), _exchange()))
        self.assertTrue(cap.reproduced)
        self.assertTrue(cap.negative_control_available)
        self.assertTrue(cap.negative_control_clean)
        self.assertTrue(cap.verified)

    def test_not_verified_when_negative_control_also_confirms(self):
        # The probe confirms on a benign input too -> not discriminating.
        v = ScriptedValidator([_confirmed(), _confirmed(), _confirmed()],
                              benign_marker="BENIGN", benign_result=_confirmed())
        oracle = Oracle(v, n_required=3, negative_control=self._builder(),
                        require_negative_control=True)
        cap = run(oracle.run(_finding(), _exchange()))
        self.assertTrue(cap.reproduced)
        self.assertTrue(cap.negative_control_available)
        self.assertFalse(cap.negative_control_clean)
        self.assertFalse(cap.verified)
        self.assertIn("negative control ALSO confirmed", cap.reason)

    def test_not_verified_when_control_unavailable_and_required(self):
        v = ScriptedValidator([_confirmed(), _confirmed(), _confirmed()])
        oracle = Oracle(v, n_required=3, negative_control=None,
                        require_negative_control=True)
        cap = run(oracle.run(_finding(), _exchange()))
        self.assertTrue(cap.reproduced)
        self.assertFalse(cap.negative_control_available)
        self.assertFalse(cap.verified)
        self.assertIn("NO negative control", cap.reason)

    def test_builder_returning_none_is_unavailable(self):
        v = ScriptedValidator([_confirmed(), _confirmed()])
        oracle = Oracle(v, n_required=2, negative_control=lambda e: None,
                        require_negative_control=True)
        cap = run(oracle.run(_finding(), _exchange()))
        self.assertFalse(cap.verified)
        self.assertFalse(cap.negative_control_available)


class TestProofCapsule(unittest.TestCase):
    def test_capsule_id_stable_over_decisive_facts(self):
        a = ProofCapsule("v", "ssrf", 3, 3, True, True, True, True, "r")
        b = ProofCapsule("v", "ssrf", 3, 3, True, True, True, True, "different reason")
        # Reason and timestamp are not part of the id; decisive facts are.
        self.assertEqual(a.capsule_id(), b.capsule_id())
        c = ProofCapsule("v", "ssrf", 3, 2, False, False, False, False, "r")
        self.assertNotEqual(a.capsule_id(), c.capsule_id())

    def test_to_dict_roundtrip_keys(self):
        cap = ProofCapsule("v", "ssrf", 3, 3, True, True, True, True, "r")
        d = cap.to_dict()
        self.assertEqual(d["verified"], True)
        self.assertEqual(d["validator"], "v")
        self.assertIn("capsule_id", d)


class TestStateDerivation(unittest.TestCase):
    def test_verified_state_requires_oracle_flag(self):
        f = _finding()
        self.assertEqual(derive_verification_state(f), STATE_CANDIDATE)
        f.confirmed = True  # a leg fired, but no oracle proof
        self.assertEqual(derive_verification_state(f), STATE_CANDIDATE)
        f.oracle_verified = True
        self.assertEqual(derive_verification_state(f), STATE_VERIFIED)

    def test_stamp_finding_verified(self):
        f = _finding()
        cap = ProofCapsule("v", "ssrf", 3, 3, True, True, True, True, "reproduced")
        stamp_finding(f, cap)
        self.assertTrue(f.oracle_verified)
        self.assertEqual(f.verification_state, STATE_VERIFIED)
        self.assertEqual(f.oracle_capsule_id, cap.capsule_id())

    def test_stamp_finding_candidate_on_none(self):
        f = _finding()
        stamp_finding(f, None)
        self.assertFalse(f.oracle_verified)
        self.assertEqual(f.verification_state, STATE_CANDIDATE)
        self.assertEqual(f.oracle_reason, "no oracle applied")

    def test_stamp_finding_dict(self):
        d = {"vulnerability_class": "ssrf"}
        cap = ProofCapsule("v", "ssrf", 3, 3, True, True, True, True, "reproduced")
        stamp_finding(d, cap)
        self.assertTrue(d["oracle_verified"])
        self.assertEqual(d["verification_state"], STATE_VERIFIED)


class FakeRegistry:
    def __init__(self, validators):
        self._validators = validators

    def for_finding(self, finding, exchange):
        return list(self._validators)


class TestOracleRegistry(unittest.TestCase):
    def test_oracle_for_picks_validator_and_builder(self):
        v = ScriptedValidator([_confirmed(), _confirmed()])
        v.name = "ssrf"  # self-controlling in the default set
        reg = OracleRegistry(FakeRegistry([v]), n_required=2)
        oracle = reg.oracle_for(_finding(), _exchange())
        self.assertIsNotNone(oracle)
        # ssrf is self-controlling -> negative control not required.
        self.assertFalse(oracle.require_negative_control)

    def test_oracle_for_none_when_nothing_applies(self):
        reg = OracleRegistry(FakeRegistry([]), n_required=2)
        self.assertIsNone(reg.oracle_for(_finding(), _exchange()))

    def test_verify_end_to_end(self):
        v = ScriptedValidator([_confirmed(), _confirmed()])
        v.name = "ssrf"
        reg = OracleRegistry(FakeRegistry([v]), n_required=2)
        cap = run(reg.verify(_finding(), _exchange()))
        self.assertIsNotNone(cap)
        self.assertTrue(cap.verified)

    def test_non_self_controlling_without_builder_stays_candidate(self):
        v = ScriptedValidator([_confirmed(), _confirmed()])
        v.name = "totally_unknown_leg"  # no builder, not self-controlling
        reg = OracleRegistry(FakeRegistry([v]), n_required=2)
        cap = run(reg.verify(_finding(), _exchange()))
        self.assertTrue(cap.reproduced)
        self.assertFalse(cap.verified)  # can't rule out confirm-on-anything


class PassiveValidator(Validator):
    """Pure passive validator -- re-analyses the captured exchange, no network call."""
    name = "passive_fake"
    finding_classes = {"ssrf"}
    active = False  # sends no traffic

    def __init__(self, result):
        self._result = result
        self.call_count = 0

    async def validate(self, finding, exchange):
        self.call_count += 1
        return self._result


class TestOracleForPassiveOnly(unittest.TestCase):
    """safe_passive_default / passive_only gate: zero live sends for passive validators."""

    def test_passive_only_returns_oracle_for_passive_validator(self):
        v = PassiveValidator(_confirmed())
        reg = OracleRegistry(FakeRegistry([v]), n_required=1)
        oracle = reg.oracle_for(_finding(), _exchange(), passive_only=True)
        self.assertIsNotNone(oracle, "passive_only should return oracle for active=False validator")

    def test_passive_only_skips_active_validator(self):
        v = ScriptedValidator([_confirmed()])  # active=True
        reg = OracleRegistry(FakeRegistry([v]), n_required=1)
        oracle = reg.oracle_for(_finding(), _exchange(), passive_only=True)
        self.assertIsNone(oracle, "passive_only must return None for active=True validator")

    def test_passive_only_false_includes_active_validators(self):
        v = ScriptedValidator([_confirmed()])  # active=True
        reg = OracleRegistry(FakeRegistry([v]), n_required=1)
        oracle = reg.oracle_for(_finding(), _exchange(), passive_only=False)
        self.assertIsNotNone(oracle, "passive_only=False should include active validators")

    def test_passive_oracle_zero_calls_on_no_applicable_validator(self):
        # Negative control on the safety contract: when only active validators exist
        # and passive_only=True, no validate() call is made (zero live sends).
        v = ScriptedValidator([_confirmed()])  # active=True, would send traffic
        reg = OracleRegistry(FakeRegistry([v]), n_required=1)
        oracle = reg.oracle_for(_finding(), _exchange(), passive_only=True)
        self.assertIsNone(oracle)
        self.assertEqual(len(v.calls), 0, "no validate() call must be made when passive_only filtered out all validators")

    def test_passive_validator_reaches_verified_via_passive_oracle(self):
        # A passive validator that confirms N-of-N and has a clean negative
        # should still reach verification_state=verified via oracle.run().
        confirmed_result = _confirmed()
        clean_result = _clean()
        v = PassiveValidator(confirmed_result)

        # Stub: reproduce by returning confirmed twice, then clean for the negative.
        results = [_confirmed(), _confirmed()]
        scripted_passive = ScriptedValidator(results, benign_marker="BENIGN", benign_result=_clean())
        scripted_passive.active = False  # mark as passive
        scripted_passive.name = "passive_scripted"

        def _builder(exchange):
            data = exchange.model_dump()
            data["url"] = "http://127.0.0.1/x?url=BENIGN"
            return HttpExchange(**data)

        oracle = Oracle(scripted_passive, n_required=2, negative_control=_builder,
                        require_negative_control=True)
        cap = run(oracle.run(_finding(), _exchange()))
        self.assertTrue(cap.reproduced)
        self.assertTrue(cap.verified, "passive oracle with clean negative should reach verified")
        self.assertFalse(scripted_passive.active, "validator must be passive (safety invariant)")

    def test_same_class_active_validator_not_run_under_passive_only(self):
        # Discrimination test: same finding, active and passive validator available.
        # passive_only=True must pick passive, not active.
        active_v = ScriptedValidator([_confirmed()])  # active=True
        passive_v = PassiveValidator(_confirmed())    # active=False
        passive_v.finding_classes = {"ssrf"}

        class BothRegistry:
            def for_finding(self, finding, exchange):
                return [active_v, passive_v]  # active first

        reg = OracleRegistry(BothRegistry(), n_required=1)
        oracle = reg.oracle_for(_finding(), _exchange(), passive_only=True)
        self.assertIsNotNone(oracle, "should pick the passive validator")
        self.assertFalse(oracle.validator.active, "oracle must use the passive validator, not the active one")
        self.assertEqual(len(active_v.calls), 0, "active validator must not have been called")


if __name__ == "__main__":
    unittest.main()
