"""
Caller-level tests for testing/eval_metrics.py (P1-3: unify the evaluation
layers' metric arithmetic into one shared module).

Discovered both via `python -m unittest discover -s testing -p test_*.py`
(harness.suite's smoke/full tiers) and directly via
`python -m unittest testing.test_eval_metrics`. Deterministic and fully
offline -- no model/GPU/network, no *ANSWER_KEY*/blind-target content.

Layout:
  * ``PrimitiveTests`` -- precision/recall/f1/summarize against pinned,
    by-hand-computed values, plus the mandated negative controls (item 3
    of the acceptance criteria): swapping fp/fn changes the result, and the
    dispersion helper actually responds to spread (pstdev/pvariance > 0 for
    a varied run set, == 0.0 for an identical-value run set).
  * ``AblationHarnessAgreementTests`` -- builds a synthetic
    ``ablation_harness.VariantResult`` and asserts ``aggregate()``'s
    precision/recall/tp/fp/fn output agrees with BOTH pinned hand-computed
    numbers AND a direct call into ``eval_metrics`` (item 2). If
    ``ablation_harness`` ever grows a divergent private copy of this
    arithmetic again, its output will stop matching the hand-computed
    numbers pinned here and this test fails.
  * ``BlindEvalAgreementTests`` -- same idea for
    ``run_blind_eval.aggregate_variance`` (loaded by file path, since
    ``blind-target-2`` is not a valid dotted package name -- mirrors
    ``testing/test_blind_eval_harness.py``'s own loader).
"""
from __future__ import annotations

import importlib.util
import math
import sys
import unittest
from pathlib import Path

_TESTING_DIR = Path(__file__).resolve().parent
_ROOT = _TESTING_DIR.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from testing import eval_metrics  # noqa: E402
from harness import ablation_harness as ah  # noqa: E402

_RUNNER_PATH = _ROOT / "testing" / "blind-target-2" / "run_blind_eval.py"


def _load_blind_eval_runner():
    """Load run_blind_eval.py by file path -- see testing/test_blind_eval_
    harness.py's identical loader for why (blind-target-2 has a hyphen)."""
    spec = importlib.util.spec_from_file_location("p1_3_blind_eval_runner", _RUNNER_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Primitives: pinned values + negative controls.
# ---------------------------------------------------------------------------

class PrimitiveTests(unittest.TestCase):
    def test_precision_basic(self):
        # tp=8, fp=2 -> 8/10 = 0.8
        self.assertEqual(eval_metrics.precision(8, 2), 0.8)

    def test_precision_zero_denominator_default_none(self):
        self.assertIsNone(eval_metrics.precision(0, 0))

    def test_precision_zero_denominator_on_zero_override(self):
        self.assertEqual(eval_metrics.precision(0, 0, on_zero=0.0), 0.0)

    def test_recall_basic(self):
        # tp=3, fn=1 -> 3/4 = 0.75
        self.assertEqual(eval_metrics.recall(3, 1), 0.75)

    def test_recall_zero_denominator_default_none(self):
        self.assertIsNone(eval_metrics.recall(0, 0))

    def test_recall_zero_denominator_on_zero_override(self):
        self.assertEqual(eval_metrics.recall(0, 0, on_zero=0.0), 0.0)

    def test_f1_harmonic_mean(self):
        # p=0.8, r=0.75 -> 2*0.8*0.75/(0.8+0.75) = 1.2/1.55
        expected = 2 * 0.8 * 0.75 / (0.8 + 0.75)
        self.assertAlmostEqual(eval_metrics.f1(0.8, 0.75), expected)

    def test_f1_none_propagates(self):
        self.assertIsNone(eval_metrics.f1(None, 0.5))
        self.assertIsNone(eval_metrics.f1(0.5, None))
        self.assertIsNone(eval_metrics.f1(None, None))

    def test_f1_zero_precision_or_recall_collapses_to_zero_not_none(self):
        # Matches strict_score.score_exact_class exactly: a defined-but-zero
        # precision or recall gives F1=0.0, never None (None means
        # "undefined", not "measured zero").
        self.assertEqual(eval_metrics.f1(0.0, 0.6), 0.0)
        self.assertEqual(eval_metrics.f1(0.6, 0.0), 0.0)
        self.assertEqual(eval_metrics.f1(0.0, 0.0), 0.0)

    def test_negative_control_precision_and_recall_differ_on_swapped_fp_fn(self):
        # Not a vacuous check: tp=8/fp=2 (precision=0.8) vs tp=8/fn=2
        # (recall as tp/(tp+fn)=0.8) look the same when fp==fn, so pick
        # fp != fn -- swapping them must change the numeric result.
        tp, fp, fn = 9, 1, 3
        p = eval_metrics.precision(tp, fp)
        r = eval_metrics.recall(tp, fn)
        self.assertNotEqual(p, r)
        self.assertAlmostEqual(p, 0.9)
        self.assertAlmostEqual(r, 0.75)
        # Swapping fp/fn at the call site must swap which value comes out.
        p_swapped = eval_metrics.precision(tp, fn)
        r_swapped = eval_metrics.recall(tp, fp)
        self.assertAlmostEqual(p_swapped, r)
        self.assertAlmostEqual(r_swapped, p)

    def test_summarize_pinned_values(self):
        # mean=2, population variance = mean((x-mean)^2) = (1+0+1)/3 = 2/3
        s = eval_metrics.summarize([1, 2, 3])
        self.assertAlmostEqual(s["mean"], 2.0)
        self.assertAlmostEqual(s["pvariance"], 2 / 3)
        self.assertAlmostEqual(s["pstdev"], math.sqrt(2 / 3))
        self.assertEqual(s["n"], 3)

    def test_summarize_filters_none(self):
        s = eval_metrics.summarize([1.0, None, 3.0, None])
        self.assertEqual(s["n"], 2)
        self.assertAlmostEqual(s["mean"], 2.0)

    def test_summarize_empty_is_all_none(self):
        s = eval_metrics.summarize([])
        self.assertEqual(s, {"mean": None, "pstdev": None, "pvariance": None, "n": 0})
        s2 = eval_metrics.summarize([None, None])
        self.assertEqual(s2["n"], 0)

    def test_summarize_single_value_dispersion_is_zero(self):
        s = eval_metrics.summarize([5.0])
        self.assertEqual(s["pstdev"], 0.0)
        self.assertEqual(s["pvariance"], 0.0)
        self.assertEqual(s["n"], 1)

    def test_negative_control_dispersion_responds_to_spread(self):
        # A run set with real spread must show pstdev>0 and pvariance>0;
        # an identical-value run set must show exactly 0.0 for both. A
        # dispersion helper that always returned 0 (or a constant) would
        # fail this.
        varied = eval_metrics.summarize([10.0, 12.0, 8.0, 11.0])
        identical = eval_metrics.summarize([7.0, 7.0, 7.0, 7.0])
        self.assertGreater(varied["pstdev"], 0.0)
        self.assertGreater(varied["pvariance"], 0.0)
        self.assertEqual(identical["pstdev"], 0.0)
        self.assertEqual(identical["pvariance"], 0.0)


# ---------------------------------------------------------------------------
# Agreement test: harness/ablation_harness.py's aggregate() must produce the
# SAME numbers a direct eval_metrics call (and hand computation) would.
# ---------------------------------------------------------------------------

class AblationHarnessAgreementTests(unittest.TestCase):
    def _variant_result(self):
        variant = ah.VARIANTS[0]  # "A"
        # Three repeats, deliberately non-uniform tp so dispersion is real
        # and fp/fn differ so precision != recall (same negative-control
        # shape as PrimitiveTests.test_negative_control_precision_and_
        # recall_differ_on_swapped_fp_fn).
        runs = [
            ah.RunMetrics(tp=9, fp=1, fn=3),
            ah.RunMetrics(tp=10, fp=1, fn=3),
            ah.RunMetrics(tp=11, fp=1, fn=3),
        ]
        return ah.VariantResult(variant=variant, runs=runs)

    def test_aggregate_precision_recall_match_hand_computed_and_shared_primitive(self):
        result = self._variant_result()
        agg = ah.aggregate(result)

        # Hand-computed: precision = tp/(tp+fp) for tp in {9,10,11}, fp=1
        # -> 0.9, 0.909..., 0.917... ; recall = tp/(tp+fn), fn=3
        # -> 0.75, 0.769..., 0.786...
        hand_precisions = [9 / 10, 10 / 11, 11 / 12]
        hand_recalls = [9 / 12, 10 / 13, 11 / 14]
        expected_p_mean = round(sum(hand_precisions) / 3, 3)
        expected_r_mean = round(sum(hand_recalls) / 3, 3)
        self.assertEqual(agg["precision"]["mean"], expected_p_mean)
        self.assertEqual(agg["recall"]["mean"], expected_r_mean)
        # precision and recall must actually differ here (fp != fn) --
        # otherwise this agreement check would be vacuous.
        self.assertNotEqual(agg["precision"]["mean"], agg["recall"]["mean"])

        # Agreement with the shared primitive directly, run by run.
        direct_precisions = [eval_metrics.precision(r.tp, r.fp) for r in result.runs]
        direct_recalls = [eval_metrics.recall(r.tp, r.fn) for r in result.runs]
        s_p = eval_metrics.summarize(direct_precisions)
        s_r = eval_metrics.summarize(direct_recalls)
        self.assertEqual(agg["precision"]["mean"], round(s_p["mean"], 3))
        self.assertEqual(agg["recall"]["mean"], round(s_r["mean"], 3))
        self.assertEqual(agg["precision"]["stdev"], round(s_p["pstdev"], 3))
        self.assertEqual(agg["recall"]["stdev"], round(s_r["pstdev"], 3))

        # tp varies (9,10,11) across runs -> real dispersion, not vacuously 0.
        self.assertGreater(agg["tp"]["stdev"], 0.0)

    def test_aggregate_zero_denominator_and_empty_runs_conventions_preserved(self):
        # No positives, no predictions at all -> tp=fp=fn=0 -> precision/
        # recall both None (ablation's on_zero=None convention), never 0.0.
        variant = ah.VARIANTS[0]
        runs = [ah.RunMetrics(tp=0, fp=0, fn=0)]
        result = ah.VariantResult(variant=variant, runs=runs)
        agg = ah.aggregate(result)
        self.assertIsNone(agg["precision"]["mean"])
        self.assertIsNone(agg["recall"]["mean"])
        self.assertEqual(agg["precision"]["n"], 0)

        # A single run's dispersion is exactly 0.0, not None -- matches
        # ablation_harness._agg's original "len(vals) > 1 else 0.0" branch.
        runs_one = [ah.RunMetrics(tp=5, fp=1, fn=1)]
        agg_one = ah.aggregate(ah.VariantResult(variant=variant, runs=runs_one))
        self.assertEqual(agg_one["tp"]["stdev"], 0.0)
        self.assertEqual(agg_one["tp"]["n"], 1)


# ---------------------------------------------------------------------------
# Agreement test: run_blind_eval.py's aggregate_variance() must produce the
# SAME numbers a direct eval_metrics call (and hand computation) would.
# ---------------------------------------------------------------------------

class BlindEvalAgreementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rbe = _load_blind_eval_runner()

    def _scorecard(self, n_findings_total, n_quarantined_leads, n_surfaced_findings,
                    controls_clean, elapsed, tokens):
        return {
            "n_findings_total": n_findings_total,
            "n_quarantined_leads": n_quarantined_leads,
            "n_surfaced_findings": n_surfaced_findings,
            "controls_clean": controls_clean,
            "controls_clean_issue_level": controls_clean,
            "n_controls_clean_issue_level": n_surfaced_findings,
            "timing": {"total_elapsed_seconds": elapsed, "total_tokens_spent": tokens},
        }

    def test_aggregate_variance_matches_hand_computed_and_shared_primitive(self):
        scorecards = [
            self._scorecard(2, 0, 2, True, 10.0, 100),
            self._scorecard(4, 1, 3, True, 12.0, 150),
            self._scorecard(3, 0, 3, False, 11.0, 120),
        ]
        result = self.rbe.aggregate_variance(scorecards)

        values = [2.0, 4.0, 3.0]
        expected_mean = sum(values) / 3
        expected_var = sum((v - expected_mean) ** 2 for v in values) / 3
        n_findings = result["variance"]["n_findings_total"]
        self.assertAlmostEqual(n_findings["mean"], expected_mean)
        self.assertAlmostEqual(n_findings["variance"], expected_var)
        self.assertEqual(n_findings["values"], values)

        # Agreement with the shared primitive directly.
        s = eval_metrics.summarize(values)
        self.assertAlmostEqual(n_findings["mean"], s["mean"])
        self.assertAlmostEqual(n_findings["variance"], s["pvariance"])

        # controls_clean: True,True,False -> values [1.0,1.0,0.0], real spread.
        cc = result["variance"]["controls_clean"]
        self.assertGreater(cc["variance"], 0.0)

    def test_aggregate_variance_identical_runs_give_zero_variance(self):
        scorecards = [self._scorecard(2, 0, 2, True, 10.0, 100) for _ in range(4)]
        result = self.rbe.aggregate_variance(scorecards)
        for name in ("n_findings_total", "n_quarantined_leads", "n_surfaced_findings",
                     "controls_clean", "total_elapsed_seconds", "total_tokens_spent"):
            self.assertEqual(result["variance"][name]["variance"], 0.0, name)

    def test_aggregate_variance_empty_scorecards_defaults_to_zero_not_none(self):
        # run_blind_eval's own empty-input convention (0.0/0.0), distinct
        # from ablation_harness's (None) -- both are preserved, not merged.
        result = self.rbe.aggregate_variance([])
        self.assertEqual(result["n_runs"], 0)
        for name, metric in result["variance"].items():
            self.assertEqual(metric["mean"], 0.0, name)
            self.assertEqual(metric["variance"], 0.0, name)

    def test_negative_control_swapped_metrics_are_not_vacuously_equal(self):
        # Sanity check that this agreement test would actually catch a
        # divergent private copy: n_quarantined_leads and n_surfaced_findings
        # differ across these scorecards, so a reintroduced bug that (say)
        # swapped which values feed which metric would change one of these
        # means and this assertion would catch it.
        scorecards = [
            self._scorecard(2, 0, 2, True, 10.0, 100),
            self._scorecard(4, 2, 1, True, 12.0, 150),
        ]
        result = self.rbe.aggregate_variance(scorecards)
        self.assertNotEqual(
            result["variance"]["n_quarantined_leads"]["mean"],
            result["variance"]["n_surfaced_findings"]["mean"],
        )


if __name__ == "__main__":
    unittest.main()
