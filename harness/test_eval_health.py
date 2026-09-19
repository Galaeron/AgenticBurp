"""Hermetic tests for eval_health.py (P0.7). Pure function over a plain
job-summary dict -- no live run, no process."""
from __future__ import annotations

import unittest

from harness.eval_health import evaluate_health


def _healthy_job(**overrides) -> dict:
    base = dict(
        exit_code=0,
        expected_artifacts=["result.json", "log.txt"],
        present_artifacts=["result.json", "log.txt"],
        target_healthy=True,
        target_health_reason="",
        expected_phases=["discovery", "investigate", "score"],
        completed_phases=["discovery", "investigate", "score"],
    )
    base.update(overrides)
    return base


class TestEvaluateHealth(unittest.TestCase):
    def test_all_true_is_valid_with_no_reasons(self):
        result = evaluate_health(_healthy_job())
        self.assertTrue(result["eval_valid"])
        self.assertEqual(result["reasons"], [])
        self.assertTrue(result["process_complete"])
        self.assertTrue(result["artifacts_complete"])
        self.assertTrue(result["target_healthy"])
        self.assertTrue(result["no_missing_phase"])

    def test_nonzero_exit_code_invalidates_with_reason(self):
        result = evaluate_health(_healthy_job(exit_code=1))
        self.assertFalse(result["process_complete"])
        self.assertFalse(result["eval_valid"])
        self.assertTrue(any("exit_code" in r for r in result["reasons"]))
        # The other three signals are unaffected -- independence, not an AND
        # that hides which specific signal failed.
        self.assertTrue(result["artifacts_complete"])
        self.assertTrue(result["target_healthy"])
        self.assertTrue(result["no_missing_phase"])

    def test_missing_artifact_invalidates_with_reason(self):
        result = evaluate_health(_healthy_job(present_artifacts=["result.json"]))
        self.assertFalse(result["artifacts_complete"])
        self.assertFalse(result["eval_valid"])
        self.assertTrue(any("log.txt" in r for r in result["reasons"]))
        self.assertTrue(result["process_complete"])

    def test_unhealthy_target_invalidates_with_reason(self):
        result = evaluate_health(_healthy_job(
            target_healthy=False, target_health_reason="stateless DB reset mid-run"))
        self.assertFalse(result["target_healthy"])
        self.assertFalse(result["eval_valid"])
        self.assertTrue(any("stateless DB reset mid-run" in r for r in result["reasons"]))
        self.assertTrue(result["process_complete"])
        self.assertTrue(result["artifacts_complete"])

    def test_missing_phase_invalidates_with_reason(self):
        result = evaluate_health(_healthy_job(completed_phases=["discovery", "investigate"]))
        self.assertFalse(result["no_missing_phase"])
        self.assertFalse(result["eval_valid"])
        self.assertTrue(any("score" in r for r in result["reasons"]))
        self.assertTrue(result["process_complete"])
        self.assertTrue(result["artifacts_complete"])
        self.assertTrue(result["target_healthy"])

    def test_target_health_is_not_inferred_from_exit_code(self):
        """Negative control: a clean exit code (0) must NOT make target_healthy
        default to True -- it must read its own explicit field, defaulting to
        unhealthy when absent."""
        job = {"exit_code": 0}
        result = evaluate_health(job)
        self.assertFalse(result["target_healthy"])
        self.assertFalse(result["eval_valid"])

    def test_missing_job_fields_default_to_unhealthy_not_assumed_fine(self):
        result = evaluate_health({})
        self.assertFalse(result["eval_valid"])
        self.assertGreaterEqual(len(result["reasons"]), 1)

    def test_reviewer_repro_absent_expectations_do_not_read_as_complete(self):
        """R03 reproduction: evaluate_health({'exit_code': 0, 'target_healthy':
        True}) must NOT return eval_valid=True -- no expected_artifacts or
        expected_phases were declared at all, which is unknown, not zero."""
        result = evaluate_health({"exit_code": 0, "target_healthy": True})
        self.assertFalse(result["eval_valid"])
        self.assertFalse(result["artifacts_complete"])
        self.assertFalse(result["no_missing_phase"])
        self.assertTrue(any("expected_artifacts" in r for r in result["reasons"]))
        self.assertTrue(any("expected_phases" in r for r in result["reasons"]))

    def test_explicit_empty_expectations_are_honoured_as_complete(self):
        """An explicitly declared empty list is a real "nothing expected"
        statement, distinct from an absent key, and must read as complete."""
        result = evaluate_health(_healthy_job(
            expected_artifacts=[], present_artifacts=[],
            expected_phases=[], completed_phases=[]))
        self.assertTrue(result["artifacts_complete"])
        self.assertTrue(result["no_missing_phase"])
        self.assertTrue(result["eval_valid"])

    def test_string_false_is_not_read_as_healthy(self):
        """R03 reproduction: target_healthy='false' (a non-empty, truthy
        string) must never be coerced into a healthy bool."""
        result = evaluate_health(_healthy_job(target_healthy="false"))
        self.assertFalse(result["target_healthy"])
        self.assertFalse(result["eval_valid"])
        self.assertTrue(any("target_healthy" in r for r in result["reasons"]))

    def test_non_bool_target_healthy_types_are_rejected(self):
        for bad in (1, "true", None, [], {}):
            with self.subTest(bad=bad):
                result = evaluate_health(_healthy_job(target_healthy=bad))
                self.assertFalse(result["target_healthy"])
                self.assertFalse(result["eval_valid"])


if __name__ == "__main__":
    unittest.main()
