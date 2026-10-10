"""
Caller-level + negative-control tests for testing/pool_strict_runs.py (FR-3,
F15 -- reviews/2026-09-25/founder-review/REVIEW.md Sec. 9).

Discovered both via `python -m unittest discover -s testing -p test_*.py`
(harness.suite's smoke/full tiers) and directly via
`python -m unittest testing.test_pool_strict_runs`. Fully offline and
deterministic -- no model/GPU/network/harness.store, and the SYNTHETIC
fixtures below are hand-built in this file so these tests never depend on
the (untracked, local-only) real `reviews/2026-09-25/benchmark/*_strict_3x
.json` evidence. A small integration-smoke test additionally runs over those
real files WHEN PRESENT and is skipped cleanly otherwise.

Never reads `*ANSWER_KEY*` or a blind target's `app.py`.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_TESTING_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TESTING_DIR.parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

import pool_strict_runs as psr  # noqa: E402


def _overall(tp: int, fp: int, fn: int) -> dict:
    """Build a minimal `metrics.exact_class.overall` block. Precision/recall
    values here are deliberately NOT internally consistent with tp/fp/fn --
    that is the point: pool_strict_runs must derive its own P/R/F1 from the
    tp/fp/fn it is given, never trust (or propagate) a stored ratio."""
    return {"tp": tp, "fp": fp, "fn": fn, "precision": -1, "recall": -1, "f1": -1}


def _run(tp: int, fp: int, fn: int) -> dict:
    return {"metrics": {"exact_class": {"overall": _overall(tp, fp, fn)}}}


def _artifact(corpus: str, run_counts: list[tuple[int, int, int]]) -> dict:
    return {"corpus": corpus, "runs": [_run(*c) for c in run_counts]}


# Three synthetic runs with KNOWN, hand-computed tp/fp/fn, deliberately
# DIFFERENT across runs (so a first-run-only regression is distinguishable
# from the true all-runs sum). Mirrors the real shape: one corpus, 3 repeats.
_SYNTHETIC_SINGLE_CORPUS = [
    _artifact("synthcorp", [(10, 20, 2), (8, 22, 4), (12, 18, 0)]),
]
# Element-wise sums, computed by hand (not by calling the module under test):
#   tp: 10+8+12 = 30   fp: 20+22+18 = 60   fn: 2+4+0 = 6
_EXPECTED_SUM_TP, _EXPECTED_SUM_FP, _EXPECTED_SUM_FN = 30, 60, 6
# First-run-only pool (run index 0 of the single artifact): tp=10 fp=20 fn=2.
_EXPECTED_FIRST_RUN = (10, 20, 2)

# A second synthetic fixture spanning TWO artifacts/corpora (mirrors pooling
# across webgoat/dvwa/pixelmart/juiceshop), again with hand-computed sums.
_SYNTHETIC_TWO_CORPORA = [
    _artifact("alpha", [(3, 3, 0), (3, 3, 0), (3, 3, 0)]),   # sum: tp9 fp9 fn0
    _artifact("beta", [(8, 26, 0), (8, 26, 0), (8, 27, 0)]),  # sum: tp24 fp79 fn0
]
# Combined by hand: tp = 9+24 = 33, fp = 9+79 = 88, fn = 0
_EXPECTED_TWO_CORPORA_SUM = (33, 88, 0)
# First-run-only pool across the two artifacts: (3,3,0) + (8,26,0) = (11,29,0)
_EXPECTED_TWO_CORPORA_FIRST_RUN = (11, 29, 0)


class PoolStrictRunsCorrectnessTests(unittest.TestCase):
    """Correctness: all_runs_pooled == the element-wise SUM over all runs;
    mean_of_runs == the mean of each run's own P/R/F1. Synthetic-only, no
    dependence on real untracked artifacts."""

    def test_all_runs_pooled_equals_hand_computed_sum_single_corpus(self):
        result = psr.pool_strict_runs(_SYNTHETIC_SINGLE_CORPUS)
        pooled = result["all_runs_pooled"]
        self.assertEqual(pooled["tp"], _EXPECTED_SUM_TP)
        self.assertEqual(pooled["fp"], _EXPECTED_SUM_FP)
        self.assertEqual(pooled["fn"], _EXPECTED_SUM_FN)
        self.assertEqual(pooled["n_runs"], 3)

    def test_all_runs_pooled_equals_hand_computed_sum_multi_corpus(self):
        result = psr.pool_strict_runs(_SYNTHETIC_TWO_CORPORA)
        pooled = result["all_runs_pooled"]
        exp_tp, exp_fp, exp_fn = _EXPECTED_TWO_CORPORA_SUM
        self.assertEqual(pooled["tp"], exp_tp)
        self.assertEqual(pooled["fp"], exp_fp)
        self.assertEqual(pooled["fn"], exp_fn)
        self.assertEqual(pooled["n_runs"], 6)

    def test_precision_recall_are_derived_from_pooled_counts_not_averaged(self):
        """`all_runs_pooled`'s P/R must be derived from the SUMMED tp/fp/fn
        (not averaged in from the individual runs' own precision/recall),
        and `mean_of_runs`'s P/R must be the mean of the individual runs'
        own values (not recomputed from the summed counts). This fixture's
        per-run denominators happen to be constant (tp+fp=30 and tp+fn=12 in
        every run), so both views land on the same number here as a sanity
        check of the arithmetic; `test_precision_recall_not_conflated_between_denominators`
        below uses a fixture where the two views genuinely diverge, proving
        they are not silently the same computation."""
        result = psr.pool_strict_runs(_SYNTHETIC_SINGLE_CORPUS)
        pooled = result["all_runs_pooled"]
        mean = result["mean_of_runs"]

        expected_pooled_p = _EXPECTED_SUM_TP / (_EXPECTED_SUM_TP + _EXPECTED_SUM_FP)
        expected_pooled_r = _EXPECTED_SUM_TP / (_EXPECTED_SUM_TP + _EXPECTED_SUM_FN)
        self.assertAlmostEqual(pooled["precision"], round(expected_pooled_p, 3))
        self.assertAlmostEqual(pooled["recall"], round(expected_pooled_r, 3))

        per_run_precisions = [10 / 30, 8 / 30, 12 / 30]
        per_run_recalls = [10 / 12, 8 / 12, 12 / 12]
        self.assertAlmostEqual(mean["precision"], round(sum(per_run_precisions) / 3, 3))
        self.assertAlmostEqual(mean["recall"], round(sum(per_run_recalls) / 3, 3))

        # The pooled overall block's OWN (deliberately wrong, -1) stored
        # precision/recall must never leak into the result -- everything is
        # recomputed from tp/fp/fn.
        self.assertGreaterEqual(pooled["precision"], 0.0)
        self.assertGreaterEqual(mean["precision"], 0.0)

    def test_per_run_rows_preserve_corpus_and_index(self):
        result = psr.pool_strict_runs(_SYNTHETIC_TWO_CORPORA)
        rows = result["per_run"]
        self.assertEqual(len(rows), 6)
        alpha_rows = [r for r in rows if r["corpus"] == "alpha"]
        beta_rows = [r for r in rows if r["corpus"] == "beta"]
        self.assertEqual(len(alpha_rows), 3)
        self.assertEqual(len(beta_rows), 3)
        self.assertEqual([r["run_index"] for r in alpha_rows], [0, 1, 2])
        self.assertEqual(alpha_rows[0]["tp"], 3)
        self.assertEqual(beta_rows[2]["fp"], 27)

    def test_empty_input_raises_instead_of_reporting_zeros(self):
        with self.assertRaises(ValueError):
            psr.pool_strict_runs([])
        with self.assertRaises(ValueError):
            psr.pool_strict_runs([{"corpus": "empty", "runs": []}])


class FirstRunOnlyNegativeControlTests(unittest.TestCase):
    """NEGATIVE CONTROL: a first-run-only pool (the shape of the ORIGINAL
    hand-transcribed report headline) must be DIFFERENT from
    `all_runs_pooled` whenever runs differ -- i.e. a silent regression to
    "first run only" masquerading as the all-repeat pool is caught loudly by
    this test failing, not by a human noticing a transcription error."""

    def test_first_run_pool_differs_from_all_runs_pooled_single_corpus(self):
        pooled = psr.pool_strict_runs(_SYNTHETIC_SINGLE_CORPUS)["all_runs_pooled"]
        first = psr.first_run_pool(_SYNTHETIC_SINGLE_CORPUS)

        self.assertEqual(first["tp"], _EXPECTED_FIRST_RUN[0])
        self.assertEqual(first["fp"], _EXPECTED_FIRST_RUN[1])
        self.assertEqual(first["fn"], _EXPECTED_FIRST_RUN[2])

        # The actual regression this guards against: someone "fixes" the
        # aggregator to only look at runs[0] and calls it all_runs_pooled.
        self.assertNotEqual((first["tp"], first["fp"], first["fn"]),
                             (pooled["tp"], pooled["fp"], pooled["fn"]))

    def test_first_run_pool_differs_from_all_runs_pooled_multi_corpus(self):
        pooled = psr.pool_strict_runs(_SYNTHETIC_TWO_CORPORA)["all_runs_pooled"]
        first = psr.first_run_pool(_SYNTHETIC_TWO_CORPORA)

        exp_tp, exp_fp, exp_fn = _EXPECTED_TWO_CORPORA_FIRST_RUN
        self.assertEqual((first["tp"], first["fp"], first["fn"]), (exp_tp, exp_fp, exp_fn))
        self.assertNotEqual((first["tp"], first["fp"], first["fn"]),
                             (pooled["tp"], pooled["fp"], pooled["fn"]))

        # Precision/recall must also diverge (not just the raw counts) so a
        # report that swaps in first-run P/R while labelling it "all-repeat"
        # is equally detectable.
        self.assertNotEqual(first["precision"], pooled["precision"])

    def test_precision_recall_not_conflated_between_denominators(self):
        """A regression that reports the MEAN-of-runs P/R but labels it
        all_runs_pooled (or vice versa) must also be distinguishable: build a
        fixture where per-run P/R vary enough that mean != pooled-from-sum."""
        artifacts = [_artifact("gamma", [(1, 9, 0), (9, 1, 0), (1, 1, 8)])]
        result = psr.pool_strict_runs(artifacts)
        pooled = result["all_runs_pooled"]
        mean = result["mean_of_runs"]
        # pooled: tp=11 fp=11 fn=8 -> P = 11/22 = 0.5
        self.assertEqual((pooled["tp"], pooled["fp"], pooled["fn"]), (11, 11, 8))
        self.assertAlmostEqual(pooled["precision"], 0.5)
        # per-run precisions: 1/10=0.1, 9/10=0.9, 1/2=0.5 -> mean = 0.5 (coincidentally
        # equal here); check recall instead, which diverges:
        # per-run recalls: 1/1=1.0, 9/9=1.0, 1/9=0.111 -> mean = 0.704
        # pooled recall: 11/19 = 0.579
        self.assertNotAlmostEqual(pooled["recall"], mean["recall"], places=2)


@unittest.skipUnless(
    (_REPO_ROOT / "reviews" / "2026-09-25" / "benchmark" / "webgoat_strict_3x.json").exists(),
    "2026-09-25 real strict-benchmark artifacts absent (untracked, local-only evidence)",
)
class RealArtifactSmokeTest(unittest.TestCase):
    """Smoke-only: if the real (untracked) 2026-09-25 strict-benchmark
    artifacts happen to be present in this checkout, confirm the module runs
    over them without error and produces internally-consistent output. This
    is NOT the correctness test (that is fully synthetic above) and this
    class is expected to SKIP in a fresh checkout/CI."""

    _CORPORA = ("webgoat", "dvwa", "pixelmart", "juiceshop")

    def test_real_four_corpora_pool_without_error(self):
        bench_dir = _REPO_ROOT / "reviews" / "2026-09-25" / "benchmark"
        artifacts = [psr.load_artifact(bench_dir / f"{c}_strict_3x.json") for c in self._CORPORA]
        result = psr.pool_strict_runs(artifacts)
        pooled = result["all_runs_pooled"]
        first = psr.first_run_pool(artifacts)
        # Internal consistency only (this is what makes it a smoke test, not
        # a hardcoded-number regression test that would break on a re-run):
        self.assertEqual(pooled["n_runs"], sum(len(a["runs"]) for a in artifacts))
        self.assertGreaterEqual(pooled["tp"], first["tp"])
        self.assertGreaterEqual(pooled["fp"], first["fp"])
        self.assertGreaterEqual(pooled["fn"], first["fn"])


if __name__ == "__main__":
    unittest.main()
