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


if __name__ == "__main__":
    unittest.main()
