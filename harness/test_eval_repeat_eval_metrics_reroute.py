"""P1-3: harness.eval_repeat's aggregation is routed through testing.eval_metrics.

Golden dicts below were captured from the PRE-reroute driver (inline
statistics.fmean/pstdev) and compared byte-for-byte (sorted-key JSON) against
the rerouted one on venv 3.12 and system 3.14. Every test drives the real
aggregate entry points -- run_repeated -> EvalReport.summary/passes_floor/
compare -- never _agg directly.
"""
import json
import unittest
from unittest import mock

from harness.eval_repeat import EvalReport, EvalRun, run_repeated
from testing import eval_metrics


def _scorer(recalls, precisions):
    def scorer(seed):
        return EvalRun(recall=recalls[seed], precision=precisions[seed], seed=seed)
    return scorer


def _repeat(recalls, precisions):
    return run_repeated(_scorer(recalls, precisions), list(range(len(recalls))),
                        recall_floor=0.75, precision_floor=0.5)


_FIXTURES = {
    "varied5": ([0.8, 0.7, 0.75, 0.72, 0.78], [0.6] * 5),
    "highvar": ([1.0, 0.6, 1.0, 0.6, 0.8], [0.7] * 5),
    "thirds": ([1 / 3, 2 / 3, 1 / 7], [1 / 9, 5 / 11, 3 / 13]),
    "single": ([0.123456789], [0.987654321]),
    "empty": ([], []),
}

_GOLDEN = {
    "varied5": {"floor": [True, []], "summary": {
        "precision": {"high_variance": False, "max": 0.6, "mean": 0.6, "min": 0.6, "n": 5, "stdev": 0.0},
        "recall": {"high_variance": False, "max": 0.8, "mean": 0.75, "min": 0.7, "n": 5, "stdev": 0.0369},
        "runs": 5}},
    "highvar": {"floor": [False, ["recall variance too high to trust the mean (stdev 0.1789 over 5 runs)"]],
                "summary": {
        "precision": {"high_variance": False, "max": 0.7, "mean": 0.7, "min": 0.7, "n": 5, "stdev": 0.0},
        "recall": {"high_variance": True, "max": 1.0, "mean": 0.8, "min": 0.6, "n": 5, "stdev": 0.1789},
        "runs": 5}},
    "thirds": {"floor": [False, [
        "mean recall 0.381 < floor 0.75",
        "mean precision 0.2655 < floor 0.5",
        "recall variance too high to trust the mean (stdev 0.2165 over 3 runs)",
        "precision variance too high to trust the mean (stdev 0.1423 over 3 runs)"]], "summary": {
        "precision": {"high_variance": True, "max": 0.4545, "mean": 0.2655, "min": 0.1111, "n": 3, "stdev": 0.1423},
        "recall": {"high_variance": True, "max": 0.6667, "mean": 0.381, "min": 0.1429, "n": 3, "stdev": 0.2165},
        "runs": 3}},
    "single": {"floor": [False, ["mean recall 0.1235 < floor 0.75"]], "summary": {
        "precision": {"high_variance": False, "max": 0.9877, "mean": 0.9877, "min": 0.9877, "n": 1, "stdev": 0.0},
        "recall": {"high_variance": False, "max": 0.1235, "mean": 0.1235, "min": 0.1235, "n": 1, "stdev": 0.0},
        "runs": 1}},
    "empty": {"floor": [True, []], "summary": {
        "precision": {"high_variance": False, "max": None, "mean": None, "min": None, "n": 0, "stdev": None},
        "recall": {"high_variance": False, "max": None, "mean": None, "min": None, "n": 0, "stdev": None},
        "runs": 0}},
}


def _observe(name):
    rep = _repeat(*_FIXTURES[name])
    return {"summary": rep.summary(), "floor": list(rep.passes_floor())}


def _canon(obj):
    return json.dumps(obj, sort_keys=True)


class EvalRepeatRerouteGoldenTests(unittest.TestCase):
    def test_outputs_byte_identical_to_pre_reroute_golden(self):
        for name in _FIXTURES:
            with self.subTest(fixture=name):
                self.assertEqual(_canon(_observe(name)), _canon(_GOLDEN[name]))

    def test_driver_routes_through_shared_summarize(self):
        with mock.patch.object(eval_metrics, "summarize", wraps=eval_metrics.summarize) as spy:
            _repeat(*_FIXTURES["varied5"]).summary()
        # one call per metric (recall, precision)
        self.assertEqual(spy.call_count, 2)

    def test_summary_matches_direct_eval_metrics_call(self):
        recalls, _ = _FIXTURES["thirds"]
        s = eval_metrics.summarize(recalls)
        got = _repeat(*_FIXTURES["thirds"]).summary()["recall"]
        self.assertEqual(got["mean"], round(s["mean"], 4))
        self.assertEqual(got["stdev"], round(s["pstdev"], 4))
        self.assertEqual(got["n"], s["n"])

    def test_compare_delta_unchanged(self):
        a = EvalReport(runs=[EvalRun(recall=r, precision=0.6, seed=i, corpus_id="c")
                             for i, r in enumerate([0.7, 0.71, 0.69])])
        b = EvalReport(runs=[EvalRun(recall=r, precision=0.65, seed=i, corpus_id="c")
                             for i, r in enumerate([0.8, 0.82, 0.78])])
        delta = a.compare(b)
        self.assertEqual(delta["recall_delta"], 0.1)
        self.assertEqual(delta["precision_delta"], 0.05)
        self.assertTrue(delta["attributable_to_model_only"])


class EvalRepeatRerouteNegativeControlTests(unittest.TestCase):
    """The golden comparison must be load-bearing: a wrong dispersion read
    (variance where the driver reports stdev) must be caught by it."""

    def test_wrong_dispersion_breaks_golden_and_floor(self):
        real = eval_metrics.summarize

        def variance_as_stdev(values):
            s = real(values)
            return {**s, "pstdev": s["pvariance"]}

        with mock.patch.object(eval_metrics, "summarize", side_effect=variance_as_stdev):
            observed = _observe("highvar")
        self.assertNotEqual(_canon(observed), _canon(_GOLDEN["highvar"]))
        # the high-variance gate silently stops firing -- the regression the golden guards
        self.assertFalse(observed["summary"]["recall"]["high_variance"])
        self.assertTrue(observed["floor"][0])


if __name__ == "__main__":
    unittest.main()
