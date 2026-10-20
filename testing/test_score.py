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


class ScoreProvenanceWiringTest(unittest.TestCase):
    """R01/R05: score.py's own `_score_provenance` is the real production
    consumer of harness.score_provenance -- not just a hermetically-tested
    helper with no caller. Requires the repo root importable (score.py adds
    it lazily itself via `_ensure_harness_importable`)."""

    def test_complete_run_with_a_real_input_file_is_historical_not_fresh(self):
        # Tightened for R45: this used to accept ("fresh", "historical") for a
        # refresh=False run, which is exactly the contradictory label R45 is
        # about -- a cache rescore reads inference from an earlier run, so the
        # only truthful label for it is "historical".
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "detection_fixture.json"
            cache.write_text("{}")
            prov = score._score_provenance(
                corpus="test-target", conf=0.0, min_severity="info",
                n_exchanges=13, cache_path=cache, refresh=False)
            self.assertTrue(prov["complete"])
            self.assertNotEqual(prov["inputs_hash"], "")
            self.assertEqual(prov["evaluation_integrity_label"], "historical")

    def test_reviewer_repro_synthetic_invalid_artifact_zero_exchanges(self):
        """Synthetic invalid artifact (per the review's own ask): a run that
        scored ZERO exchanges must never be labeled fresh/historical -- it
        never actually completed a real scoring pass."""
        prov = score._score_provenance(
            corpus="test-target", conf=0.0, min_severity="info",
            n_exchanges=0, cache_path=None, refresh=False)
        self.assertFalse(prov["complete"])
        self.assertEqual(prov["evaluation_integrity_label"], "invalid")

    def test_synthetic_invalid_artifact_missing_cache_file(self):
        """Synthetic invalid artifact: a cache_path that does not resolve to
        a real file on disk must never produce a fabricated inputs_hash --
        the missing inputs_hash id field alone makes the label invalid."""
        from pathlib import Path
        prov = score._score_provenance(
            corpus="test-target", conf=0.0, min_severity="info",
            n_exchanges=13, cache_path=Path("/does/not/exist/detection_fixture.json"),
            refresh=False)
        self.assertEqual(prov["inputs_hash"], "")
        self.assertEqual(prov["evaluation_integrity_label"], "invalid")

    def test_git_revision_never_raises_outside_a_checkout(self):
        # smoke: must return a string either way, never raise
        self.assertIsInstance(score._git_revision(), str)


class HistoricalCacheProvenanceTests(unittest.TestCase):
    """R45: with refresh=False no inference ran in this invocation; the numbers
    come from a cache written by an earlier run. Its provenance must bind to
    that cache, never to this rescore's own identity (a fresh uuid and the
    current revision, then compared to themselves, labelled it "fresh")."""

    CURRENT = "current-review-revision"

    def _prov(self, cache_text="{}", *, refresh=False, n_exchanges=1, with_cache=True):
        import tempfile
        from pathlib import Path
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "synthetic-cache.json"
            cache.write_text(cache_text)
            with mock.patch.object(score, "_git_revision", return_value=self.CURRENT):
                return score._score_provenance(
                    corpus="synthetic", conf=0, min_severity="info", n_exchanges=n_exchanges,
                    cache_path=cache if with_cache else None, refresh=refresh)

    def test_historical_cache_not_stamped_fresh(self):
        prov = self._prov()
        self.assertEqual(prov["evaluation_integrity_label"], "historical")
        self.assertTrue(prov["complete"])

    def test_cache_provenance_is_not_the_rescore_identity(self):
        prov = self._prov()
        self.assertNotEqual(prov["git_revision"], self.CURRENT,
                            "the current revision did not produce a cached result")
        self.assertEqual(prov["rescore_revision"], self.CURRENT,
                         "the revision that did the rescoring is recorded, under its own name")
        self.assertEqual(prov["provenance_basis"], "historical_cache")

    def test_no_invocation_id_is_invented_for_a_cache(self):
        """The id is derived from the cache (its path and content), so
        rescoring the same cache twice gives the same id and a changed cache
        gives a different one -- a random uuid per call would be an invented
        invocation."""
        import tempfile
        from pathlib import Path
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "synthetic-cache.json"

            def prov(text):
                cache.write_text(text)
                with mock.patch.object(score, "_git_revision", return_value=self.CURRENT):
                    return score._score_provenance(
                        corpus="synthetic", conf=0, min_severity="info", n_exchanges=1,
                        cache_path=cache, refresh=False)

            a, b, c = prov('{"k": 1}'), prov('{"k": 1}'), prov('{"k": 2}')
        self.assertEqual(a["run_id"], b["run_id"])
        self.assertNotEqual(a["run_id"], c["run_id"])
        self.assertIn(a["inputs_hash"], a["run_id"])

    def test_absent_cache_control(self):
        prov = self._prov(with_cache=False)
        self.assertEqual(prov["evaluation_integrity_label"], "invalid")
        self.assertEqual(prov["inputs_hash"], "")

    def test_absent_cache_has_no_derived_id(self):
        self.assertEqual(self._prov(with_cache=False)["run_id"], "",
                         "no cache, nothing to derive an id from")

    def test_unscored_cache_is_invalid(self):
        prov = self._prov(n_exchanges=0)
        self.assertFalse(prov["complete"])
        self.assertEqual(prov["evaluation_integrity_label"], "invalid")

    def test_live_refresh_keeps_its_own_invocation_binding(self):
        """Control: a refresh=True run really did run inference in this
        invocation, so it keeps the current revision and a per-invocation id."""
        first, second = self._prov(refresh=True), self._prov(refresh=True)
        self.assertEqual(first["evaluation_integrity_label"], "fresh")
        self.assertEqual(first["git_revision"], self.CURRENT)
        self.assertNotEqual(first["run_id"], second["run_id"])

    def test_live_refresh_is_labelled_as_such(self):
        self.assertEqual(self._prov(refresh=True)["provenance_basis"], "live_refresh")

    def test_cli_report_for_a_cache_rescore_is_historical_in_both_labels(self):
        """Caller level: `score.main --from-cache` writes the nested label next
        to the outer freshness label; they must not contradict each other."""
        import json
        import sys
        import tempfile
        from pathlib import Path
        from unittest import mock

        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "detection_fixture.json"
            cache.write_text("{}")
            report_path = Path(d) / "report.json"

            async def fake_collect(labels, refresh, corpus, conf, min_severity):
                return {"TP1": ["sql_injection"]}, cache

            for refresh, expect_nested, expect_outer in (
                    (False, "historical", "historical_cache_rescore"),
                    (True, "fresh", "live_refresh_no_manifest_binding")):
                argv = ["score.py", "--from-cache", "--json", str(report_path)]
                if refresh:
                    argv.append("--refresh")
                with mock.patch.object(score, "_collect_from_fixture", fake_collect),                      mock.patch.object(score, "_model_from_config", return_value="m"),                      mock.patch.object(score, "_git_revision", return_value=self.CURRENT),                      mock.patch.object(sys, "argv", argv),                      mock.patch("builtins.print"):
                    self.assertEqual(score.main(), 0)
                prov = json.loads(report_path.read_text())["provenance"]
                self.assertEqual(prov["freshness"], expect_outer)
                self.assertEqual(prov["score_provenance"]["evaluation_integrity_label"], expect_nested)


if __name__ == "__main__":
    unittest.main()
