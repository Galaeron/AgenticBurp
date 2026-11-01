from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from testing.web_objective_benchmark import (
    BenchmarkContractError, score, validate_manifest,
)
from testing.run_web_objective_smoke import _config as smoke_config


MANIFEST_PATH = Path(__file__).parent / "web-objective-benchmark" / "manifest.json"


def _mini_manifest():
    return {
        "schema_version": "1.0.0",
        "attempts_per_case": 3,
        "cases": [
            {"id": "v", "pair_id": "p", "expected_class": "sqli",
             "expected_vulnerable": True, "modes": ["captured", "autonomous"]},
            {"id": "f", "pair_id": "p", "expected_class": "sqli",
             "expected_vulnerable": False, "modes": ["captured", "autonomous"]},
        ],
    }


def _record(case, attempt, *, confirmed=False, objective=False, status="success"):
    return {
        "case_id": case, "attempt": attempt, "status": status,
        "objective_verified": objective,
        "findings": ([{"vulnerability_class": "sqli",
                       "verification_state": "confirmed"}] if confirmed else []),
        "human_interventions": 0,
        "artifact_refs": [f"artifacts/{case}-{attempt}.json"],
    }


def _run(mode, records):
    return {
        "schema_version": "1.0.0", "run_id": "r", "mode": mode,
        "model": "fixture-model", "checkout": "fixture-rev",
        "config_hash": "fixture-config", "records": records,
    }


class ManifestTests(unittest.TestCase):
    def test_smoke_config_disables_unrelated_long_running_engagement_phases(self):
        cfg = smoke_config("target.example")
        engagement = cfg["engagement"]
        self.assertFalse(engagement["feature_crawl"])
        self.assertFalse(engagement["coverage_drive_legs"])
        self.assertFalse(engagement["coverage_case_drive"])
        self.assertFalse(cfg["business_context"]["enabled"])

    def test_repository_manifest_has_30_academy_cases_and_10_complete_pairs(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        validate_manifest(manifest)
        academy = [c for c in manifest["cases"] if c["suite"] == "portswigger"]
        private = [c for c in manifest["cases"] if c["suite"] == "private"]
        self.assertEqual(len(academy), 30)
        self.assertEqual(len(private), 20)
        self.assertEqual(len({c["pair_id"] for c in private}), 10)

    def test_pair_must_have_one_vulnerable_and_one_fixed_member(self):
        manifest = _mini_manifest()
        manifest["cases"][1]["expected_vulnerable"] = True
        with self.assertRaises(BenchmarkContractError):
            validate_manifest(manifest)


class ScoringTests(unittest.TestCase):
    def test_complete_clean_run_reports_repeatability_and_is_eligible(self):
        records = []
        for attempt in range(1, 4):
            records.append(_record("v", attempt, confirmed=True, objective=True))
            records.append(_record("f", attempt))
        result = score(_mini_manifest(), _run("autonomous", records))
        self.assertTrue(result["eligible"])
        self.assertEqual(result["objective"]["first_attempt_rate"], 1.0)
        self.assertEqual(result["objective"]["repeatability_rate"], 1.0)
        self.assertEqual(result["controls"]["false_confirmation_cases"], 0)

    def test_false_confirmation_on_fixed_control_fails_eligibility(self):
        records = []
        for attempt in range(1, 4):
            records.append(_record("v", attempt, confirmed=True, objective=True))
            records.append(_record("f", attempt, confirmed=(attempt == 2)))
        result = score(_mini_manifest(), _run("autonomous", records))
        self.assertTrue(result["complete"])
        self.assertFalse(result["eligible"])
        self.assertEqual(result["controls"]["false_confirmation_cases"], 1)

    def test_missing_attempt_is_visible_and_ineligible(self):
        records = [_record("v", 1, confirmed=True)]
        result = score(_mini_manifest(), _run("captured", records))
        self.assertFalse(result["complete"])
        self.assertFalse(result["eligible"])
        self.assertEqual(len(result["cases"]["missing_records"]), 5)

    def test_human_intervention_fails_autonomous_eligibility(self):
        records = []
        for attempt in range(1, 4):
            records.append(_record("v", attempt, confirmed=True, objective=True))
            records.append(_record("f", attempt))
        records[0]["human_interventions"] = 1
        result = score(_mini_manifest(), _run("autonomous", records))
        self.assertTrue(result["complete"])
        self.assertFalse(result["eligible"])
        self.assertFalse(result["gates"]["zero_human_interventions"])

    def test_infrastructure_error_is_complete_but_ineligible(self):
        records = []
        for attempt in range(1, 4):
            records.append(_record("v", attempt, status="error"))
            records[-1]["failure_stage"] = "infrastructure"
            records.append(_record("f", attempt))
        result = score(_mini_manifest(), _run("autonomous", records))
        self.assertTrue(result["complete"])
        self.assertFalse(result["eligible"])
        self.assertFalse(result["gates"]["healthy_execution"])

    def test_wrong_class_confirmation_does_not_count_as_success(self):
        records = []
        for case in ("v", "f"):
            for attempt in range(1, 4):
                rec = _record(case, attempt)
                if case == "v":
                    rec["findings"] = [{"vulnerability_class": "xss",
                                         "verification_state": "confirmed"}]
                records.append(rec)
        result = score(_mini_manifest(), _run("captured", records))
        self.assertEqual(result["objective"]["pass_at_attempt_budget"], 0.0)
        self.assertEqual(len(result["controls"]["wrong_class_confirmation_events"]), 3)

    def test_missing_provenance_or_artifacts_prevents_complete_label(self):
        records = []
        for case in ("v", "f"):
            for attempt in range(1, 4):
                records.append(_record(case, attempt, confirmed=(case == "v")))
        records[0]["artifact_refs"] = []
        run = _run("captured", records)
        run["config_hash"] = ""
        result = score(_mini_manifest(), run)
        self.assertFalse(result["complete"])
        self.assertTrue(any("config_hash" in e for e in result["cases"]["contract_errors"]))
        self.assertTrue(any("artifact" in e for e in result["cases"]["contract_errors"]))


if __name__ == "__main__":
    unittest.main()
