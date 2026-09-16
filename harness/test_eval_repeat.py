"""W-23: repeated eval reports variance and gates on the mean, not one run."""
import unittest

from eval_repeat import EvalRun, run_repeated


def _scorer(recalls, precisions):
    seq = {"i": 0}

    def scorer(seed):
        i = seq["i"]
        seq["i"] += 1
        return EvalRun(recall=recalls[i], precision=precisions[i], seed=seed)
    return scorer


class RepeatedEvalTests(unittest.TestCase):
    def test_reports_mean_and_variance_across_runs(self):
        rep = run_repeated(_scorer([0.8, 0.7, 0.75, 0.72, 0.78],
                                   [0.6, 0.6, 0.6, 0.6, 0.6]),
                           list(range(5)))
        s = rep.summary()
        self.assertEqual(s["runs"], 5)
        self.assertAlmostEqual(s["recall"]["mean"], 0.75, places=2)
        self.assertGreater(s["recall"]["stdev"], 0.0)      # variance quantified
        self.assertEqual(s["precision"]["stdev"], 0.0)     # constant -> zero variance

    def test_floor_gate_uses_the_mean(self):
        # one lucky high run cannot clear a floor the mean misses
        rep = run_repeated(_scorer([0.95, 0.70, 0.70, 0.70, 0.70],
                                   [0.6, 0.6, 0.6, 0.6, 0.6]),
                           list(range(5)), recall_floor=0.80)
        ok, reasons = rep.passes_floor()
        self.assertFalse(ok)
        self.assertTrue(any("mean recall" in r for r in reasons))

    def test_precision_floor_enforced(self):
        rep = run_repeated(_scorer([0.9] * 5, [0.30] * 5),
                           list(range(5)), precision_floor=0.50)
        ok, reasons = rep.passes_floor()
        self.assertFalse(ok)
        self.assertTrue(any("mean precision" in r for r in reasons))

    def test_high_variance_is_flagged_even_when_mean_clears(self):
        # mean recall 0.80 clears the floor, but the spread is huge -> flagged
        rep = run_repeated(_scorer([1.0, 0.6, 1.0, 0.6, 0.8],
                                   [0.7] * 5),
                           list(range(5)), recall_floor=0.75)
        ok, reasons = rep.passes_floor()
        self.assertFalse(ok)
        self.assertTrue(any("variance too high" in r for r in reasons))

    def test_stable_run_within_floors_passes(self):
        rep = run_repeated(_scorer([0.82, 0.81, 0.83, 0.80, 0.82],
                                   [0.6, 0.61, 0.59, 0.6, 0.6]),
                           list(range(5)), recall_floor=0.80, precision_floor=0.50)
        ok, reasons = rep.passes_floor()
        self.assertTrue(ok, reasons)


if __name__ == "__main__":
    unittest.main()
