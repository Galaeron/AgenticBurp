"""
Byte-identical regression coverage for the P1-3 (partial) reroute of
testing/strict_score.py's four inline precision/recall/F1 blocks onto the
shared testing/eval_metrics.py primitives (score_exact_class's per-class +
micro blocks, score_evidence_supported's per-class + micro blocks).

Discovered both via `python -m unittest discover -s testing -p test_*.py`
(harness.suite's smoke/full tiers) and directly via
`python -m unittest testing.test_strict_score_eval_metrics_reroute`.
Deterministic and fully offline -- no model/GPU/network. Never opens an
*ANSWER_KEY* file or a blind target's app.py.

The golden dicts below were captured by running this exact fixture through
the PRE-reroute `strict_score.py` (via `git stash`), then diffed byte-for-
byte against the post-reroute output before being pinned here -- see
reviews/2026-09-26 for the P1-3 reroute writeup. They are not merely
hand-derived; they are what the scorer actually returned before the change.

Fixture (one manifest, exercised through both scorer functions):
  * P1_FULL_HIT          -- positive exchange fully hit (TP: sqli)
  * P2_WRONG_CLASS       -- wrong-class over-prediction: expects xss, predicts
                            csrf (FN: xss, FP: csrf)
  * P3_MISSED            -- positive exchange with no prediction at all
                            (FN: ssrf)
  * N1_CLEAN_NEGATIVE    -- negative control, no prediction (clean)
  * N2_VIOLATED_NEGATIVE -- negative control, tested_negative=["idor"],
                            predicts idor anyway (FP: idor, doubly bad --
                            fp_on_tested_negative_control)
plus a wholly empty manifest/predictions pair for the all-zero corpus case.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

from labels.manifest import LabelRecord, Manifest, compute_hash  # noqa: E402
from strict_score import score_exact_class, score_evidence_supported  # noqa: E402
import eval_metrics  # noqa: E402


def _record(exchange_id: str, expected=(), tested_negative=(), status="positive",
           label_scope="synthetic fixture", provenance="unit test fixture") -> LabelRecord:
    return LabelRecord(
        exchange_id=exchange_id,
        expected_classes=tuple(expected),
        tested_negative_classes=tuple(tested_negative),
        label_scope=label_scope,
        status=status,
        provenance=provenance,
    )


def _manifest(records, corpus: str = "reroute-golden-corpus") -> Manifest:
    return Manifest(corpus=corpus, version="0.0.1", hash=compute_hash(records), records=tuple(records))


MANIFEST = _manifest([
    _record("P1_FULL_HIT", expected=["sqli"], status="positive"),
    _record("P2_WRONG_CLASS", expected=["xss"], status="positive"),
    _record("P3_MISSED", expected=["ssrf"], status="positive"),
    _record("N1_CLEAN_NEGATIVE", tested_negative=["command_injection"], status="negative"),
    _record("N2_VIOLATED_NEGATIVE", tested_negative=["idor"], status="negative"),
])

PREDICTIONS = {
    "P1_FULL_HIT": ["sql injection"],
    "P2_WRONG_CLASS": ["cross-site request forgery"],
    "P3_MISSED": [],
    "N1_CLEAN_NEGATIVE": [],
    "N2_VIOLATED_NEGATIVE": ["insecure direct object reference"],
}

EMPTY_MANIFEST = _manifest([])


def _always_supported(exchange_id, exact_class, raw):
    return "supported"


def _never_supported(exchange_id, exact_class, raw):
    return "unsupported"


# --- golden dicts: captured from the PRE-reroute scorer on this fixture -----

GOLDEN_EXACT_CLASS = {'metric': 'exact_class_precision_recall', 'per_class': [{'class': 'auth_bypass', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'business_logic', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'command_injection', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'csrf', 'support': 0, 'tp': 0, 'fp': 1, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': 0.0, 'recall': None, 'f1': None}, {'class': 'idor', 'support': 0, 'tp': 0, 'fp': 1, 'fn': 0, 'fp_on_tested_negative_control': 1, 'precision': 0.0, 'recall': None, 'f1': None}, {'class': 'info_disclosure', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'jwt', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'path_traversal', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'security_misconfiguration', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'sqli', 'support': 1, 'tp': 1, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': 1.0, 'recall': 1.0, 'f1': 1.0}, {'class': 'ssrf', 'support': 1, 'tp': 0, 'fp': 0, 'fn': 1, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': 0.0, 'f1': None}, {'class': 'ssti', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'xss', 'support': 1, 'tp': 0, 'fp': 0, 'fn': 1, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': 0.0, 'f1': None}], 'overall': {'tp': 1, 'fp': 2, 'fn': 2, 'precision': 0.333, 'recall': 0.333, 'f1': 0.333}, 'fp_on_tested_negative_control_total': 1}

GOLDEN_EXACT_CLASS_EMPTY = {'metric': 'exact_class_precision_recall', 'per_class': [{'class': 'auth_bypass', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'business_logic', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'command_injection', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'csrf', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'idor', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'info_disclosure', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'jwt', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'path_traversal', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'security_misconfiguration', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'sqli', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'ssrf', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'ssti', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'xss', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'fp_on_tested_negative_control': 0, 'precision': None, 'recall': None, 'f1': None}], 'overall': {'tp': 0, 'fp': 0, 'fn': 0, 'precision': 0.0, 'recall': 0.0, 'f1': 0.0}, 'fp_on_tested_negative_control_total': 0}

GOLDEN_EVIDENCE_NO_HOOK = {'metric': 'evidence_supported_precision_recall', 'status': 'unavailable', 'per_class': None, 'overall': {'tp': None, 'fp': None, 'fn': None, 'precision': None, 'recall': None, 'f1': None}, 'note': 'No evidence_grade_hook supplied -- this is an explicit sentinel, not a real zero. PR-4/BP-1b (reusing evaluation_integrity/evidence_audit.py) fills this in by passing evidence_grade_hook=... into score()/score_evidence_supported(), without reshaping this API.'}

GOLDEN_EVIDENCE_ALWAYS_SUPPORTED = {'metric': 'evidence_supported_precision_recall', 'status': 'computed', 'per_class': [{'class': 'auth_bypass', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'business_logic', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'command_injection', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'csrf', 'support': 0, 'tp': 0, 'fp': 1, 'fn': 0, 'precision': 0.0, 'recall': None, 'f1': None}, {'class': 'idor', 'support': 0, 'tp': 0, 'fp': 1, 'fn': 0, 'precision': 0.0, 'recall': None, 'f1': None}, {'class': 'info_disclosure', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'jwt', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'path_traversal', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'security_misconfiguration', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'sqli', 'support': 1, 'tp': 1, 'fp': 0, 'fn': 0, 'precision': 1.0, 'recall': 1.0, 'f1': 1.0}, {'class': 'ssrf', 'support': 1, 'tp': 0, 'fp': 0, 'fn': 1, 'precision': None, 'recall': 0.0, 'f1': None}, {'class': 'ssti', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'xss', 'support': 1, 'tp': 0, 'fp': 0, 'fn': 1, 'precision': None, 'recall': 0.0, 'f1': None}], 'overall': {'tp': 1, 'fp': 2, 'fn': 2, 'precision': 0.333, 'recall': 0.333, 'f1': 0.333}}

GOLDEN_EVIDENCE_NEVER_SUPPORTED = {'metric': 'evidence_supported_precision_recall', 'status': 'computed', 'per_class': [{'class': 'auth_bypass', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'business_logic', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'command_injection', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'csrf', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'idor', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'info_disclosure', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'jwt', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'path_traversal', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'security_misconfiguration', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'sqli', 'support': 1, 'tp': 0, 'fp': 0, 'fn': 1, 'precision': None, 'recall': 0.0, 'f1': None}, {'class': 'ssrf', 'support': 1, 'tp': 0, 'fp': 0, 'fn': 1, 'precision': None, 'recall': 0.0, 'f1': None}, {'class': 'ssti', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'xss', 'support': 1, 'tp': 0, 'fp': 0, 'fn': 1, 'precision': None, 'recall': 0.0, 'f1': None}], 'overall': {'tp': 0, 'fp': 0, 'fn': 3, 'precision': 0.0, 'recall': 0.0, 'f1': 0.0}}

GOLDEN_EVIDENCE_EMPTY = {'metric': 'evidence_supported_precision_recall', 'status': 'computed', 'per_class': [{'class': 'auth_bypass', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'business_logic', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'command_injection', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'csrf', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'idor', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'info_disclosure', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'jwt', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'path_traversal', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'security_misconfiguration', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'sqli', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'ssrf', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'ssti', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}, {'class': 'xss', 'support': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None}], 'overall': {'tp': 0, 'fp': 0, 'fn': 0, 'precision': 0.0, 'recall': 0.0, 'f1': 0.0}}


class ScoreExactClassByteIdenticalTest(unittest.TestCase):
    """score_exact_class must return, field-for-field, exactly what the
    pre-reroute inline arithmetic returned on this fixture."""

    def test_mixed_fixture_matches_pinned_pre_reroute_golden(self):
        report = score_exact_class(MANIFEST, PREDICTIONS)
        self.assertEqual(report, GOLDEN_EXACT_CLASS)

    def test_empty_corpus_matches_pinned_pre_reroute_golden(self):
        report = score_exact_class(EMPTY_MANIFEST, {})
        self.assertEqual(report, GOLDEN_EXACT_CLASS_EMPTY)


class ScoreEvidenceSupportedByteIdenticalTest(unittest.TestCase):
    """score_evidence_supported must return, field-for-field, exactly what
    the pre-reroute inline arithmetic returned on this fixture -- with no
    hook (the `unavailable` sentinel is untouched by this reroute), with a
    hook that always grades "supported", and with one that never does."""

    def test_no_hook_sentinel_matches_pinned_pre_reroute_golden(self):
        report = score_evidence_supported(MANIFEST, PREDICTIONS)
        self.assertEqual(report, GOLDEN_EVIDENCE_NO_HOOK)

    def test_always_supported_hook_matches_pinned_pre_reroute_golden(self):
        report = score_evidence_supported(MANIFEST, PREDICTIONS, _always_supported)
        self.assertEqual(report, GOLDEN_EVIDENCE_ALWAYS_SUPPORTED)

    def test_never_supported_hook_matches_pinned_pre_reroute_golden(self):
        report = score_evidence_supported(MANIFEST, PREDICTIONS, _never_supported)
        self.assertEqual(report, GOLDEN_EVIDENCE_NEVER_SUPPORTED)

    def test_empty_corpus_with_hook_matches_pinned_pre_reroute_golden(self):
        report = score_evidence_supported(EMPTY_MANIFEST, {}, _always_supported)
        self.assertEqual(report, GOLDEN_EVIDENCE_EMPTY)


class ZeroDenominatorNegativeControlTest(unittest.TestCase):
    """Load-bearing negative control (P1-3 acceptance criterion 3): the
    zero-denominator distinction must survive the reroute -- per-class
    precision/recall stay `None` on a zero denominator (`on_zero=None`),
    while micro/overall stay `0.0` (`on_zero=0.0`), never the reverse and
    never swapped tp/fp.

    The two "would fail" tests below prove this is not a vacuous
    assertion: they recompute the SAME real tp/fp/fn counts from the
    actual report through a deliberately WRONG variant of the arithmetic
    (per-class on_zero=0.0, or swapped tp/fp) and show that variant
    produces a value the golden-dict comparison above would have
    rejected."""

    def test_per_class_none_vs_micro_zero_distinction_is_preserved(self):
        report = score_exact_class(MANIFEST, PREDICTIONS)
        rows = {r["class"]: r for r in report["per_class"]}
        # auth_bypass: tp=fp=fn=support=0 for every metric -- a genuinely
        # undefined class for this fixture, must stay None everywhere.
        self.assertIsNone(rows["auth_bypass"]["precision"])
        self.assertIsNone(rows["auth_bypass"]["recall"])
        self.assertIsNone(rows["auth_bypass"]["f1"])
        # idor: tp=0, fp=1, fn=0, support=0 -- precision has a real (nonzero)
        # denominator (0.0, not None); recall's denominator (support) is 0,
        # so recall must be None, not a fabricated 0.0.
        self.assertEqual(rows["idor"]["precision"], 0.0)
        self.assertIsNone(rows["idor"]["recall"])
        # micro/overall never fabricate None -- always a real float, even
        # though several per-class cells above are None.
        overall = report["overall"]
        self.assertEqual(overall["precision"], 0.333)
        self.assertEqual(overall["recall"], 0.333)
        self.assertIsInstance(overall["precision"], float)
        self.assertIsInstance(overall["recall"], float)
        # And on the wholly empty corpus, micro/overall must be 0.0 (not
        # None) precisely because TP+FP == 0 and TP+FN == 0 there.
        empty_overall = score_exact_class(EMPTY_MANIFEST, {})["overall"]
        self.assertEqual(empty_overall["precision"], 0.0)
        self.assertEqual(empty_overall["recall"], 0.0)
        self.assertEqual(empty_overall["f1"], 0.0)

    def test_wrong_per_class_on_zero_would_have_failed_the_golden_test(self):
        # A bugged reroute that (wrongly) passed on_zero=0.0 for per-class
        # precision/recall, matching the micro convention instead of the
        # per-class one required by the spec.
        real_rows = {r["class"]: r for r in score_exact_class(MANIFEST, PREDICTIONS)["per_class"]}
        tp, fp = real_rows["auth_bypass"]["tp"], real_rows["auth_bypass"]["fp"]
        fn, support = real_rows["auth_bypass"]["fn"], real_rows["auth_bypass"]["support"]
        self.assertEqual((tp, fp, fn, support), (0, 0, 0, 0))
        wrong_precision = eval_metrics.precision(tp, fp, on_zero=0.0)
        wrong_recall = eval_metrics.recall(tp, fn, on_zero=0.0)
        # The real (correct) per-class values are None; the wrong variant's
        # are 0.0 -- had strict_score.py actually shipped that bug, the
        # byte-identical assertions above (`assertIsNone(...precision...)`,
        # and the `assertEqual(report, GOLDEN_EXACT_CLASS)` test) would both
        # have failed, since GOLDEN_EXACT_CLASS pins auth_bypass's precision
        # and recall to `None`, not `0.0`.
        self.assertEqual(wrong_precision, 0.0)
        self.assertEqual(wrong_recall, 0.0)
        self.assertNotEqual(wrong_precision, real_rows["auth_bypass"]["precision"])
        self.assertNotEqual(wrong_recall, real_rows["auth_bypass"]["recall"])
        self.assertIsNone(real_rows["auth_bypass"]["precision"])
        self.assertIsNone(real_rows["auth_bypass"]["recall"])

    def test_swapped_tp_fp_would_have_failed_the_golden_test(self):
        # A bugged reroute that swapped the tp/fp (or tp/fn) arguments --
        # e.g. `eval_metrics.precision(fp[c], tp[c], ...)` by typo.
        real_rows = {r["class"]: r for r in score_exact_class(MANIFEST, PREDICTIONS)["per_class"]}
        tp, fp = real_rows["sqli"]["tp"], real_rows["sqli"]["fp"]
        fn = real_rows["sqli"]["fn"]
        self.assertEqual((tp, fp, fn), (1, 0, 0))  # sqli: fully hit, no FP/FN
        wrong_precision = eval_metrics.precision(fp, tp, on_zero=None)  # swapped
        wrong_recall = eval_metrics.recall(fn, tp, on_zero=None)  # swapped
        # Correct: precision=1.0, recall=1.0 (pinned in GOLDEN_EXACT_CLASS).
        # Swapped: precision=0.0, recall=0.0 -- a value the golden-dict
        # comparison test above would have rejected.
        self.assertEqual(real_rows["sqli"]["precision"], 1.0)
        self.assertEqual(real_rows["sqli"]["recall"], 1.0)
        self.assertEqual(wrong_precision, 0.0)
        self.assertEqual(wrong_recall, 0.0)
        self.assertNotEqual(wrong_precision, real_rows["sqli"]["precision"])
        self.assertNotEqual(wrong_recall, real_rows["sqli"]["recall"])


if __name__ == "__main__":
    unittest.main()
