"""
Unit tests for score.py's pure scoring math (SESSION_4_PLAN.md T2.1).

No model, GPU, or fixture -- synthetic predictions with clean classes. This is
what proves the per-OWASP-category precision/recall/F1 arithmetic is correct
before any real (expensive) run produces the published number.
"""
import unittest

import score


class ClassifyTest(unittest.TestCase):
    def test_maps_known_classes(self):
        self.assertEqual(score.classify("sql_injection"), "A03:Injection")
        self.assertEqual(score.classify("reflected_xss"), "A03:Injection")
        self.assertEqual(score.classify("idor"), "A01:Broken-Access-Control")
        self.assertEqual(score.classify("ssrf"), "A10:SSRF")
        self.assertEqual(score.classify("business_logic_flaw"), "A04:Insecure-Design")
        self.assertEqual(score.classify("jwt_alg_none"), "A07:Auth-Failures")
        self.assertIsNone(score.classify("totally_unknown_thing"))
        self.assertIsNone(score.classify(""))


class ScoreMathTest(unittest.TestCase):
    def test_precision_recall_f1(self):
        labeled = {
            "TP1": ["sql_injection"],   # A03 truth, predicts A03  -> tp  A03
            "TP2": [],                  # A03 truth, predicts none -> fn  A03
            "TP3": ["idor"],            # A01 truth, predicts A01  -> tp  A01
            "TN1": [],                  # benign, nothing          -> clean
            "TN2": ["sql_injection"],   # benign, predicts A03     -> fp  A03
        }
        rep = score.score(labeled)
        by = {r["category"]: r for r in rep["per_category"]}

        a03 = by["A03:Injection"]
        self.assertEqual((a03["tp"], a03["fp"], a03["fn"], a03["support"]), (1, 1, 1, 2))
        self.assertEqual(a03["precision"], 0.5)   # 1 / (1 + 1)
        self.assertEqual(a03["recall"], 0.5)      # 1 / 2
        self.assertEqual(a03["f1"], 0.5)

        a01 = by["A01:Broken-Access-Control"]
        self.assertEqual((a01["tp"], a01["fp"], a01["fn"]), (1, 0, 0))
        self.assertEqual(a01["precision"], 1.0)
        self.assertEqual(a01["recall"], 1.0)

        o = rep["overall"]
        self.assertEqual((o["tp"], o["fp"], o["fn"]), (2, 1, 1))
        self.assertEqual(o["recall"], 0.667)      # 2 / 3
        self.assertEqual(o["precision"], 0.667)

    def test_wrong_category_finding_is_a_false_positive(self):
        # A TP exchange that fires the WRONG category: a false positive for that
        # other category, and a miss (fn) for its own true category.
        rep = score.score({"TP9": ["sql_injection"]})   # truth A10:SSRF, predicts A03
        by = {r["category"]: r for r in rep["per_category"]}
        self.assertEqual(by["A10:SSRF"]["fn"], 1)
        self.assertEqual(by["A10:SSRF"]["recall"], 0.0)
        self.assertEqual(by["A03:Injection"]["fp"], 1)


class MetricScopeTest(unittest.TestCase):
    """W-8/W-23: this scorer only matches labels against vulnerability_class
    strings -- it never resolves a proof_id/case_id -- so its output must be
    unambiguously labeled raw detection, never verified-issue, and the CLI
    table/gate must say so too."""

    def test_report_declares_raw_detection_scope(self):
        rep = score.score({"TP1": ["sql_injection"]})
        self.assertEqual(rep["metric_scope"], "raw_detection")
        self.assertEqual(score.METRIC_SCOPE, "raw_detection")

    def test_format_table_names_the_scope_and_disclaims_verified_issue(self):
        rep = score.score({"TP1": ["sql_injection"]})
        table = score.format_table(rep, "test-target", "m")
        self.assertIn("raw_detection", table)
        self.assertIn("NOT verified-issue", table)

    def test_cache_only_run_is_labeled_historical(self):
        self.assertEqual(score.freshness_label(refresh=False), "historical_cache_rescore")

    def test_refreshed_run_is_not_labeled_fresh_end_to_end(self):
        label = score.freshness_label(refresh=True)
        self.assertEqual(label, "live_refresh_no_manifest_binding")
        self.assertNotEqual(label, "fresh_end_to_end")


if __name__ == "__main__":
    unittest.main()
