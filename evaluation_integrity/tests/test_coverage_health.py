import unittest

from evaluation_integrity.coverage import summarize_coverage
from evaluation_integrity.health import assess_health


class CoverageTests(unittest.TestCase):
    def test_zero_denominator_has_no_percentage(self):
        result = summarize_coverage({"total_cells": 0, "attempted": 0, "skipped": 0,
                                     "not_applicable": 0, "blocked": 0, "error": 0})
        self.assertIsNone(result["request_level"]["percentages"]["attempted"]["percent"])
        self.assertEqual(result["request_level"]["percentages"]["attempted"]["denominator"], 0)

    def test_missing_fields_are_unknown(self):
        result = summarize_coverage({"total_cells": 10})
        self.assertIsNone(result["request_level"]["attempted"])
        self.assertIsNone(result["request_level"]["skipped"])

    def test_contradictory_totals_are_warned_and_preserved(self):
        result = summarize_coverage({"total_cells": 3, "attempted": 4, "skipped": 1,
                                     "not_applicable": 0, "blocked": 0, "error": 0})
        self.assertEqual(result["request_level"]["attempted"], 4)
        self.assertTrue(any("exceed" in item for item in result["warnings"]))

    def test_finished_process_does_not_mean_complete_coverage(self):
        result = summarize_coverage({"total_cells": 4, "attempted": 1, "skipped": 3,
                                     "not_applicable": 0, "blocked": 0, "error": 0,
                                     "process_complete": True})
        self.assertTrue(any("finished process" in item for item in result["warnings"]))

    def test_attempt_without_decisive_evidence_is_disclosed(self):
        result = summarize_coverage({"total_cells": 2, "attempted": 2, "confirmed": 0,
                                     "controlled_negative": 0})
        self.assertTrue(any("lack decisive" in item for item in result["warnings"]))

    def test_reporting_layers_remain_separate(self):
        result = summarize_coverage({"total_cells": 2, "attempted": 2,
                                     "cases": {"total_cases": 5, "attempted": 4}})
        self.assertEqual(result["request_level"]["reported_total"], 2)
        self.assertEqual(result["case_level"]["reported_total"], 5)
        self.assertFalse(result["layers_combined"])

    def test_not_detected_does_not_infer_controlled_negative(self):
        result = summarize_coverage({"total_cells": 1, "attempted": 1, "not_detected": 1})
        self.assertIsNone(result["request_level"]["controlled_negatives"])


class HealthTests(unittest.TestCase):
    def test_expected_error_is_a_passing_ordinary_control(self):
        result = assess_health([{"control_id": "hc1", "kind": "ordinary_application",
                                 "service": "target", "outcome": "expected_error",
                                 "affected_interval": [1, 2]}])
        self.assertEqual(result["evaluation_validity"], "valid_for_controlled_intervals")

    def test_failed_control_only_invalidates_affected_interval(self):
        result = assess_health([{"control_id": "hc2", "kind": "ordinary_application",
                                 "service": "target", "outcome": "fail",
                                 "affected_interval": [10, 20]}])
        self.assertEqual(result["evaluation_validity"], "invalid_for_affected_intervals")
        self.assertEqual(result["failed_intervals"][0]["affected_interval"], [10, 20])

    def test_absent_controls_leave_validity_unknown(self):
        self.assertEqual(assess_health(None)["evaluation_validity"], "unknown")

    def test_security_responses_and_mixed_service_logs_are_separate(self):
        controls = [{"control_id": "s1", "kind": "security_test", "service": "target",
                     "outcome": "fail"}]
        logs = [{"service": "target", "status": 500, "timestamp": 1},
                {"service": "model", "status": 500, "timestamp": 2},
                {"service": "other", "parseable": False}]
        result = assess_health(controls, logs)
        self.assertEqual(result["evaluation_validity"], "unknown")
        self.assertEqual(result["log_summary"]["records_by_service"], {"model": 1, "target": 1})
        self.assertEqual(result["log_summary"]["unparseable_records"], 1)
        self.assertFalse(result["log_summary"]["http_500_invalidates_evaluation"])


if __name__ == "__main__":
    unittest.main()
