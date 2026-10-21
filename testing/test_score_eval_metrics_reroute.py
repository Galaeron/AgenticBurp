"""
Byte-identical regression coverage for the P1-3 (partial) reroute of
testing/score.py's `score()` -- the nested `_row(c)` per-category helper and
the micro (overall) block -- onto the shared testing/eval_metrics.py
primitives. Mirrors testing/test_strict_score_eval_metrics_reroute.py.

Discovered both via `python -m unittest discover -s testing -p test_*.py`
(harness.suite's smoke/full tiers) and directly via
`python -m unittest testing.test_score_eval_metrics_reroute`. Deterministic
and fully offline -- no model/GPU/network, no fixture file. Never opens an
*ANSWER_KEY* file or a blind target's app.py.

The golden dicts below were captured by running this exact fixture through
the PRE-reroute `score.py` (via `git stash` on the reroute edit alone), then
diffed byte-for-byte against the post-reroute output before being pinned
here.

Fixture (one hand-built `label_category` + `labeled_findings` pair, passed
directly to `score.score(...)` -- no detection_fixture.py, no model):
  * "E1" (truth A03:Injection, predicts sql_injection)      -> tp A03
  * "E2" (truth A03:Injection, predicts nothing)             -> fn A03
  * "E3" (benign/untruthed, predicts sql_injection)          -> fp A03
    => A03:Injection ends with tp=1, fp=1, fn=1, support=2 -- a category
       with every one of tp/fp/fn/support > 0.
  * "E4" (truth A10:SSRF, predicts nothing)                  -> fn A10,
    tp=fp=0 for A10 => precision's denominator (tp+fp) is 0 => precision
    None (the zero-precision-denominator category). recall = 0/1 = 0.0
    (support > 0, so recall stays a real number, not None) => f1 None via
    the "precision is None" branch.
  * "E5" (benign/untruthed, predicts jwt_alg_none)            -> fp A07,
    A07:Auth-Failures never appears as anyone's truth => support 0 (the
    zero-support category) => recall None => f1 None via the "recall is
    None" branch, even though precision = 0/(0+1) = 0.0 is a real number.
  * "E6" (truth A05:Security-Misconfiguration, predicts nothing) -> fn A05
  * "E7" (benign/untruthed, predicts cors_misconfig)          -> fp A05
    => A05 ends with tp=0, fp=1, fn=1, support=1 => precision = 0.0,
    recall = 0.0 (both real, neither None) => f1 = 0.0 via the
    "prec and rec falsy but neither None" branch -- distinct from both
    None-producing branches above.
  Overall (micro): TP=1, FP=3, FN=3 -- all nonzero, so this fixture does
  not by itself cover the micro-zero-denominator case; that is covered
  separately by the empty/benign-only corpus below.

Plus an empty corpus (`score({}, {})`) and a benign-only corpus
(`score({"BENIGN1": [], "BENIGN2": []}, {})`) for the all-benign/empty-
corpus micro -> 0.0 case. Note: `score()` does `label_category = label_category
or _LABEL_CATEGORY` -- an empty dict `{}` is falsy, so BOTH of these calls
silently fall back to the module's real default `_LABEL_CATEGORY` mapping
(hence 6 categories, not 0, in the golden dicts below). That fallback is
pre-existing score() behavior, unchanged by this reroute; it is captured
here exactly as the pre-reroute scorer actually produced it, not
hand-derived. Both calls end up identical (support/tp/fp/fn all 0 for
every category), demonstrating micro precision/recall/f1 all collapse to
0.0 (never a fabricated None) on a wholly empty/benign corpus.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

import score  # noqa: E402
import eval_metrics  # noqa: E402

LABEL_CATEGORY = {
    "E1": "A03:Injection",
    "E2": "A03:Injection",
    "E4": "A10:SSRF",
    "E6": "A05:Security-Misconfiguration",
}

LABELED_FINDINGS = {
    "E1": ["sql_injection"],
    "E2": [],
    "E3": ["sql_injection"],
    "E4": [],
    "E5": ["jwt_alg_none"],
    "E6": [],
    "E7": ["cors_misconfig"],
}

# --- golden dicts: captured from the PRE-reroute scorer on this fixture -----

GOLDEN_MIXED = {'metric_scope': 'raw_detection', 'per_category': [{'category': 'A03:Injection', 'support': 2, 'tp': 1, 'fp': 1, 'fn': 1, 'precision': 0.5, 'recall': 0.5, 'f1': 0.5}, {'category': 'A05:Security-Misconfiguration', 'support': 1, 'tp': 0, 'fp': 1, 'fn': 1, 'precision': 0.0, 'recall': 0.0, 'f1': 0.0}, {'category': 'A07:Auth-Failures', 'support': 0, 'tp': 0, 'fp': 1, 'fn': 0, 'precision': 0.0, 'recall': None, 'f1': None}, {'category': 'A10:SSRF', 'support': 1, 'tp': 0, 'fp': 0, 'fn': 1, 'precision': None, 'recall': 0.0, 'f1': None}], 'overall': {'precision': 0.25, 'recall': 0.25, 'f1': 0.25, 'tp': 1, 'fp': 3, 'fn': 3}}

GOLDEN_EMPTY = {'metric_scope': 'raw_detection', 'per_category': [{'category': 'A01:Broken-Access-Control', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'category': 'A03:Injection', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'category': 'A04:Insecure-Design', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'category': 'A05:Security-Misconfiguration', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'category': 'A07:Auth-Failures', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'category': 'A10:SSRF', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}], 'overall': {'precision': 0.0, 'recall': 0.0, 'f1': 0.0, 'tp': 0, 'fp': 0, 'fn': 0}}

GOLDEN_BENIGN_ONLY = {'metric_scope': 'raw_detection', 'per_category': [{'category': 'A01:Broken-Access-Control', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'category': 'A03:Injection', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'category': 'A04:Insecure-Design', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'category': 'A05:Security-Misconfiguration', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'category': 'A07:Auth-Failures', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'category': 'A10:SSRF', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}], 'overall': {'precision': 0.0, 'recall': 0.0, 'f1': 0.0, 'tp': 0, 'fp': 0, 'fn': 0}}


class ScoreByteIdenticalTest(unittest.TestCase):
    """score() must return, field-for-field, exactly what the pre-reroute
    inline arithmetic returned on this fixture."""

    def test_mixed_fixture_matches_pinned_pre_reroute_golden(self):
        report = score.score(LABELED_FINDINGS, LABEL_CATEGORY)
        self.assertEqual(report, GOLDEN_MIXED)

    def test_empty_corpus_matches_pinned_pre_reroute_golden(self):
        report = score.score({}, {})
        self.assertEqual(report, GOLDEN_EMPTY)

    def test_benign_only_corpus_matches_pinned_pre_reroute_golden(self):
        report = score.score({"BENIGN1": [], "BENIGN2": []}, {})
        self.assertEqual(report, GOLDEN_BENIGN_ONLY)


class ZeroDenominatorNegativeControlTest(unittest.TestCase):
    """Load-bearing negative control (P1-3 acceptance criterion 3): the
    zero-denominator distinction must survive the reroute -- per-category
    precision/recall stay `None` on a zero denominator (`on_zero=None`),
    while micro/overall stay `0.0` (`on_zero=0.0`), never the reverse and
    never swapped tp/fp.

    The two "would fail" tests below prove this is not a vacuous
    assertion: they recompute the SAME real tp/fp/fn counts from the
    actual report through a deliberately WRONG variant of the arithmetic
    (per-category on_zero=0.0, or swapped tp/fp) and show that variant
    produces a value the golden-dict comparison above would have
    rejected."""

    def test_none_vs_zero_distinction_is_preserved(self):
        report = score.score(LABELED_FINDINGS, LABEL_CATEGORY)
        rows = {r["category"]: r for r in report["per_category"]}
        # A10:SSRF: tp=0, fp=0, fn=1, support=1 -- precision's denominator
        # (tp+fp) is genuinely 0, so precision must be None, not a
        # fabricated 0.0; recall's denominator (support) is 1, so recall
        # stays a real 0.0, not None.
        self.assertIsNone(rows["A10:SSRF"]["precision"])
        self.assertEqual(rows["A10:SSRF"]["recall"], 0.0)
        self.assertIsInstance(rows["A10:SSRF"]["recall"], float)
        # A07:Auth-Failures: tp=0, fp=1, fn=0, support=0 -- the reverse
        # split: precision has a real (nonzero) denominator (0.0, not
        # None); support is 0, so recall must be None, not a fabricated
        # 0.0.
        self.assertEqual(rows["A07:Auth-Failures"]["precision"], 0.0)
        self.assertIsNone(rows["A07:Auth-Failures"]["recall"])
        # micro/overall never fabricate None -- always a real float, even
        # though several per-category cells above are None.
        overall = report["overall"]
        self.assertEqual(overall["precision"], 0.25)
        self.assertEqual(overall["recall"], 0.25)
        self.assertIsInstance(overall["precision"], float)
        self.assertIsInstance(overall["recall"], float)
        # And on the wholly empty/benign corpus, micro/overall must be 0.0
        # (not None) precisely because TP+FP == 0 and TP+FN == 0 there.
        empty_overall = score.score({}, {})["overall"]
        self.assertEqual(empty_overall["precision"], 0.0)
        self.assertEqual(empty_overall["recall"], 0.0)
        self.assertEqual(empty_overall["f1"], 0.0)

    def test_wrong_per_category_on_zero_would_have_failed_the_golden_test(self):
        # A bugged reroute that (wrongly) passed on_zero=0.0 for per-category
        # precision/recall, matching the micro convention instead of the
        # per-category one required by the spec.
        real_rows = {r["category"]: r for r in score.score(LABELED_FINDINGS, LABEL_CATEGORY)["per_category"]}
        tp, fp = real_rows["A10:SSRF"]["tp"], real_rows["A10:SSRF"]["fp"]
        self.assertEqual((tp, fp), (0, 0))
        wrong_precision = eval_metrics.precision(tp, fp, on_zero=0.0)
        # The real (correct) per-category precision is None; the wrong
        # variant's is 0.0 -- had score.py actually shipped that bug, the
        # byte-identical assertions above (`assertIsNone(...precision...)`,
        # and `assertEqual(report, GOLDEN_MIXED)`) would both have failed,
        # since GOLDEN_MIXED pins A10:SSRF's precision to `None`, not `0.0`.
        self.assertEqual(wrong_precision, 0.0)
        self.assertNotEqual(wrong_precision, real_rows["A10:SSRF"]["precision"])
        self.assertIsNone(real_rows["A10:SSRF"]["precision"])

    def test_swapped_tp_fp_would_have_failed_the_golden_test(self):
        # A bugged reroute that swapped the tp/fp (or tp/fn) arguments --
        # e.g. `eval_metrics.precision(fp[c], tp[c], ...)` by typo. Use
        # A05:Security-Misconfiguration (tp=0, fp=1, fn=1): tp != fp and
        # tp != fn here, so swapping the arguments actually changes the
        # denominator (unlike A03:Injection, where tp==fp==fn==1 would
        # make a swap a no-op and the control vacuous).
        real_rows = {r["category"]: r for r in score.score(LABELED_FINDINGS, LABEL_CATEGORY)["per_category"]}
        a05 = real_rows["A05:Security-Misconfiguration"]
        tp, fp, fn = a05["tp"], a05["fp"], a05["fn"]
        self.assertEqual((tp, fp, fn), (0, 1, 1))
        wrong_precision = eval_metrics.precision(fp, tp, on_zero=None)  # swapped
        wrong_recall = eval_metrics.recall(fn, tp, on_zero=None)  # swapped
        # Correct: precision=0.0, recall=0.0 (pinned in GOLDEN_MIXED).
        # Swapped: precision=1/(1+0)=1.0, recall=1/(1+0)=1.0 -- values the
        # golden-dict comparison test above would have rejected.
        self.assertEqual(a05["precision"], 0.0)
        self.assertEqual(a05["recall"], 0.0)
        self.assertEqual(wrong_precision, 1.0)
        self.assertEqual(wrong_recall, 1.0)
        self.assertNotEqual(wrong_precision, a05["precision"])
        self.assertNotEqual(wrong_recall, a05["recall"])


if __name__ == "__main__":
    unittest.main()
