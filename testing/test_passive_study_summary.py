"""Offline synthetic CLI controls: no model, traffic, network or hidden labels."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from testing.passive_study_summary import summarize


class StudySummaryTests(unittest.TestCase):
    def fixture(self):
        plan = {"repeats": 3, "profiles": [{"profile_id": "synthetic", "model": "fake",
                "config_hash": "synthetic-config", "hardware": "none"}], "cases": [
            {"case_id": "positive", "stratum": "headers", "expected": ["synthetic-observation"]},
            {"case_id": "negative", "stratum": "ordinary", "expected": []}]}
        rows = [{"profile_id": "synthetic", "case_id": case["case_id"], "repeat": repeat,
                 "status": "complete", "fresh_cache_id": f"synthetic-{case['case_id']}-{repeat}",
                 "predicted": case["expected"], "evidence_complete": True, "latency_ms": 10,
                 "prompt_tokens": 3, "completion_tokens": 1} for case in plan["cases"] for repeat in range(3)]
        return plan, rows

    def cli(self, plan, rows):
        with tempfile.TemporaryDirectory() as tmp:
            plan_path, result_path = Path(tmp) / "plan.json", Path(tmp) / "results.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            result_path.write_text(json.dumps(rows), encoding="utf-8")
            return subprocess.run([sys.executable, "-m", "testing.passive_study_summary", str(plan_path), str(result_path)],
                                  capture_output=True, text=True, timeout=15)

    def test_cli_correct_complete_matrix_and_missing_measurements(self):
        plan, rows = self.fixture()
        result = self.cli(plan, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        profile = json.loads(result.stdout)["profiles"]["synthetic"]
        self.assertEqual((profile["counts"]["planned"], profile["counts"]["tp"], profile["counts"]["tn_cases"]), (6, 3, 3))
        self.assertTrue(profile["quality_eligible"])
        self.assertEqual(profile["measurements"]["peak_memory_bytes"]["unknown"], 6)
        self.assertIsNone(profile["measurements"]["peak_memory_bytes"]["p95"])

    def test_missing_failed_and_disputed_cases_never_shrink_denominator(self):
        plan, rows = self.fixture()
        rows.pop(0)
        rows[0]["status"] = "failed"
        rows[0]["predicted"] = []
        rows[0]["evidence_complete"] = False
        plan["cases"][1]["annotation_disagreement"] = True
        profile = summarize(plan, rows)["profiles"]["synthetic"]
        self.assertEqual(profile["counts"]["planned"], 6)
        self.assertEqual(profile["counts"]["missing"], 1)
        self.assertEqual(profile["counts"]["unscored"], 5)
        self.assertEqual(profile["counts"]["positive_labels_unresolved"], 2)
        self.assertFalse(profile["quality_eligible"])
        # Defective completed-only selection would conceal 5 unavailable cells.
        self.assertNotEqual(profile["counts"]["planned"], sum(r["status"] == "complete" for r in rows))

    def test_wrong_class_is_both_false_positive_and_missed_expected_label(self):
        plan, rows = self.fixture()
        rows[0]["predicted"] = ["different-observation"]
        rows[3]["predicted"] = ["spurious-observation"]
        profile = summarize(plan, rows)["profiles"]["synthetic"]
        self.assertEqual([profile["counts"][key] for key in ("tp", "fp", "fn")], [2, 2, 1])
        self.assertEqual(profile["strata"]["headers"]["fn"], 1)
        self.assertEqual(profile["strata"]["ordinary"]["fp"], 1)

    def test_cli_disputed_positive_labels_remain_visible_separately(self):
        plan, rows = self.fixture()
        plan["cases"][0]["annotation_disagreement"] = True
        result = self.cli(plan, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        profile = json.loads(result.stdout)["profiles"]["synthetic"]
        self.assertEqual(profile["counts"]["disputed_positive_labels"], 3)
        self.assertEqual(profile["counts"]["tp"], 0)
        self.assertEqual(profile["strata"]["headers"]["unscored"], 3)
        self.assertFalse(profile["quality_eligible"])

    def test_duplicate_cells_unknown_cases_cache_reuse_and_nonfinite_rejected(self):
        plan, rows = self.fixture()
        for mutate in (lambda data: data.append(data[0]),
                       lambda data: data[0].update(case_id="unplanned"),
                       lambda data: data[1].update(fresh_cache_id=data[0]["fresh_cache_id"]),
                       lambda data: data[0].update(latency_ms=float("nan")),
                       lambda data: data[0].update(repeat=True)):
            altered = copy.deepcopy(rows)
            mutate(altered)
            with self.assertRaises(ValueError):
                summarize(plan, altered)

    def test_cli_requires_three_repeats_and_withholds_invalid_input(self):
        plan, rows = self.fixture()
        plan["repeats"] = 2
        result = self.cli(plan, rows)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("Invalid study input", result.stderr)


if __name__ == "__main__":
    unittest.main()
