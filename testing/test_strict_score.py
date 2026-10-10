"""
Caller-level tests for testing/strict_score.py (PR-3, BP-1a).

Discovered both via `python -m unittest discover -s testing -p test_*.py`
(harness.suite's smoke/full tiers) and directly via
`python -m unittest testing.test_strict_score`. Deterministic and fully
offline -- no model/GPU/network. Never opens an *ANSWER_KEY* file or a
blind target's app.py.

Strong assertions run against small SYNTHETIC manifests built in-memory
(mirrors testing/test_label_manifest.py's fixture-builder pattern) so they
do not depend on the real seed corpus. One integration-smoke test loads the
real `testing/labels/pixelmart.labels.json` and scores a trivial prediction
set without error.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

from labels.manifest import EXACT_CLASSES, LabelRecord, Manifest, compute_hash, load_manifest  # noqa: E402
from strict_score import (  # noqa: E402
    baseline_all_classes,
    baseline_always_alert,
    baseline_silent,
    classify_exact,
    passes_precision_gate,
    passes_recall_gate,
    score,
    score_exact_class,
)

SEED_PATH = _TESTING_DIR / "labels" / "pixelmart.labels.json"


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


def _manifest(records: list[LabelRecord], corpus: str = "unittest-corpus") -> Manifest:
    return Manifest(corpus=corpus, version="0.0.1", hash=compute_hash(records), records=tuple(records))


# A BALANCED synthetic manifest: 4 positives (one each of sqli/xss/ssrf/csrf,
# the two R06 regression classes included) + 4 negatives, each negative a
# documented per-class negative control for the sibling positive's class.
def _balanced_manifest() -> Manifest:
    return _manifest([
        _record("P_SQLI", expected=["sqli"], status="positive"),
        _record("N_SQLI", tested_negative=["sqli"], status="negative"),
        _record("P_XSS", expected=["xss"], status="positive"),
        _record("N_XSS", tested_negative=["xss"], status="negative"),
        _record("P_SSRF", expected=["ssrf"], status="positive"),
        _record("N_SSRF", tested_negative=["ssrf"], status="negative"),
        _record("P_CSRF", expected=["csrf"], status="positive"),
        _record("N_CSRF", tested_negative=["csrf"], status="negative"),
    ])


class ClassifierTest(unittest.TestCase):
    """classify_exact() -- the R06 fix itself."""

    def test_every_exact_class_alias_classifies_to_itself(self):
        # Sanity/regression property the baselines below rely on: predicting
        # the literal alias string round-trips through the classifier.
        for c in EXACT_CLASSES:
            self.assertEqual(classify_exact(c), c, f"{c!r} did not classify to itself")

    def test_csrf_is_not_shadowed_by_ssrf(self):
        # The R06 regression: score.py's SSRF keyword list includes the bare
        # substring "request forgery", so "cross-site request forgery" was
        # silently counted as SSRF. Must map to csrf here.
        self.assertEqual(classify_exact("cross-site request forgery"), "csrf")
        self.assertEqual(classify_exact("Cross Site Request Forgery"), "csrf")
        self.assertEqual(classify_exact("CSRF"), "csrf")

    def test_ssrf_still_classifies_correctly(self):
        self.assertEqual(classify_exact("server-side request forgery"), "ssrf")
        self.assertEqual(classify_exact("SSRF"), "ssrf")

    def test_sqli_and_xss_do_not_share_a_bucket(self):
        self.assertEqual(classify_exact("SQL Injection"), "sqli")
        self.assertEqual(classify_exact("Cross-Site Scripting"), "xss")
        self.assertNotEqual(classify_exact("SQL Injection"), classify_exact("Cross-Site Scripting"))

    def test_unrecognised_string_classifies_to_none(self):
        self.assertIsNone(classify_exact("totally unrelated free text"))
        self.assertIsNone(classify_exact(""))


class WrongClassIsNotATPTest(unittest.TestCase):
    """A predicted class must match the exchange's expected_classes
    exactly -- a wrong-class alert is an FP + FN, never a TP."""

    def test_xss_prediction_on_sqli_only_exchange_is_fp_and_fn_not_tp(self):
        manifest = _manifest([_record("TP1", expected=["sqli"])])
        predictions = {"TP1": ["cross-site scripting"]}
        report = score_exact_class(manifest, predictions)
        overall = report["overall"]
        self.assertEqual(overall["tp"], 0)
        self.assertEqual(overall["fp"], 1)
        self.assertEqual(overall["fn"], 1)
        rows = {r["class"]: r for r in report["per_class"]}
        self.assertEqual(rows["sqli"]["tp"], 0)
        self.assertEqual(rows["sqli"]["fn"], 1)
        self.assertEqual(rows["xss"]["fp"], 1)

    def test_sqli_prediction_on_xss_only_exchange_is_fp_and_fn_not_tp(self):
        manifest = _manifest([_record("TP5", expected=["xss"])])
        predictions = {"TP5": ["sql injection"]}
        report = score_exact_class(manifest, predictions)
        self.assertEqual(report["overall"]["tp"], 0)
        self.assertEqual(report["overall"]["fp"], 1)
        self.assertEqual(report["overall"]["fn"], 1)

    def test_csrf_prediction_on_ssrf_exchange_is_fp_not_tp(self):
        # The R06 regression at the scorer level, not just the classifier.
        manifest = _manifest([_record("TP9", expected=["ssrf"])])
        predictions = {"TP9": ["cross-site request forgery"]}
        report = score_exact_class(manifest, predictions)
        self.assertEqual(report["overall"]["tp"], 0)
        rows = {r["class"]: r for r in report["per_class"]}
        self.assertEqual(rows["ssrf"]["fn"], 1)
        self.assertEqual(rows["csrf"]["fp"], 1)


class DedupAndMissTest(unittest.TestCase):

    def test_duplicate_predictions_do_not_inflate_recall(self):
        manifest = _manifest([_record("TP1", expected=["sqli"])])
        predictions = {"TP1": ["sql injection", "SQL Injection", "sqli", "sqli"]}
        report = score_exact_class(manifest, predictions)
        rows = {r["class"]: r for r in report["per_class"]}
        self.assertEqual(rows["sqli"]["tp"], 1)
        self.assertEqual(rows["sqli"]["support"], 1)
        self.assertEqual(rows["sqli"]["recall"], 1.0)
        self.assertEqual(report["overall"]["tp"], 1)

    def test_absent_prediction_on_known_positive_is_a_miss(self):
        manifest = _manifest([_record("TP1", expected=["sqli"])])
        report = score_exact_class(manifest, {})  # no entry at all for TP1
        rows = {r["class"]: r for r in report["per_class"]}
        self.assertEqual(rows["sqli"]["tp"], 0)
        self.assertEqual(rows["sqli"]["fn"], 1)
        self.assertEqual(report["overall"]["fn"], 1)

    def test_multi_class_exchange_partial_match_is_one_tp_one_fn(self):
        manifest = _manifest([_record("TP10", expected=["path_traversal", "info_disclosure"])])
        predictions = {"TP10": ["path traversal"]}
        report = score_exact_class(manifest, predictions)
        rows = {r["class"]: r for r in report["per_class"]}
        self.assertEqual(rows["path_traversal"]["tp"], 1)
        self.assertEqual(rows["info_disclosure"]["fn"], 1)
        self.assertEqual(report["overall"]["tp"], 1)
        self.assertEqual(report["overall"]["fn"], 1)


class SetupAndInconclusiveNeverScoredTest(unittest.TestCase):

    def test_setup_and_inconclusive_never_become_fps_or_positives(self):
        manifest = _manifest([
            _record("TP1", expected=["sqli"], status="positive"),
            _record("SETUP1", status="setup"),
            _record("TP8", status="inconclusive"),
        ])
        predictions = {
            "TP1": ["sql injection"],
            "SETUP1": ["cross-site scripting", "server-side request forgery"],
            "TP8": ["command injection"],
        }
        report = score(manifest, predictions)
        self.assertEqual(report["n_scorable"], 1)  # only TP1; setup/inconclusive excluded
        exact = report["exact_class"]
        # Only TP1's correct sqli prediction should register; the garbage
        # predictions against setup/inconclusive exchange_ids must not leak
        # into fp/tp/fn at all, since those ids are never visited.
        self.assertEqual(exact["overall"]["tp"], 1)
        self.assertEqual(exact["overall"]["fp"], 0)
        self.assertEqual(exact["overall"]["fn"], 0)
        coverage = report["any_alert_coverage"]
        self.assertEqual(coverage["n_scorable"], 1)


class EvidenceSupportedScaffoldTest(unittest.TestCase):

    def test_unavailable_sentinel_when_no_hook_supplied(self):
        manifest = _manifest([_record("TP1", expected=["sqli"])])
        report = score(manifest, {"TP1": ["sql injection"]})
        evidence = report["evidence_supported"]
        self.assertEqual(evidence["status"], "unavailable")
        self.assertIsNone(evidence["overall"]["precision"])
        self.assertIsNone(evidence["overall"]["recall"])
        # Never a fabricated zero.
        self.assertNotEqual(evidence["overall"]["precision"], 0)
        self.assertNotEqual(evidence["overall"]["recall"], 0)

    def test_hook_supplied_computes_a_real_report(self):
        manifest = _manifest([_record("TP1", expected=["sqli"])])
        predictions = {"TP1": ["sql injection"]}

        def always_supported(exchange_id, exact_class, raw):
            return "supported"

        report = score(manifest, predictions, evidence_grade_hook=always_supported)
        evidence = report["evidence_supported"]
        self.assertEqual(evidence["status"], "computed")
        self.assertEqual(evidence["overall"]["tp"], 1)
        self.assertEqual(evidence["overall"]["precision"], 1.0)
        self.assertEqual(evidence["overall"]["recall"], 1.0)

    def test_hook_unsupported_prediction_is_a_miss_not_a_tp(self):
        manifest = _manifest([_record("TP1", expected=["sqli"])])
        predictions = {"TP1": ["sql injection"]}

        def never_supported(exchange_id, exact_class, raw):
            return "unsupported"

        report = score(manifest, predictions, evidence_grade_hook=never_supported)
        evidence = report["evidence_supported"]
        self.assertEqual(evidence["overall"]["tp"], 0)
        self.assertEqual(evidence["overall"]["fn"], 1)


class BaselineNegativeControlsTest(unittest.TestCase):
    """The mandatory negative controls: on a BALANCED synthetic manifest,
    the two indiscriminate baselines fail the exact-class precision gate
    (even at perfect recall / full coverage), and the silent baseline fails
    recall."""

    def setUp(self):
        self.manifest = _balanced_manifest()

    def test_baseline_all_classes_perfect_recall_fails_precision_gate(self):
        predictions = baseline_all_classes(self.manifest)
        report = score(self.manifest, predictions)
        exact = report["exact_class"]["overall"]
        self.assertEqual(exact["recall"], 1.0)  # every expected class is always predicted
        self.assertLess(exact["precision"], 0.1)  # swamped by FPs on every other class
        self.assertFalse(passes_precision_gate(report, 0.5))
        coverage = report["any_alert_coverage"]["coverage"]
        self.assertEqual(coverage, 1.0)

    def test_baseline_always_alert_full_coverage_fails_precision_gate(self):
        predictions = baseline_always_alert(self.manifest, fixed_class="sqli")
        report = score(self.manifest, predictions)
        coverage = report["any_alert_coverage"]["coverage"]
        self.assertEqual(coverage, 1.0)
        exact = report["exact_class"]["overall"]
        self.assertLess(exact["precision"], 0.5)
        self.assertFalse(passes_precision_gate(report, 0.5))

    def test_baseline_silent_fails_recall(self):
        predictions = baseline_silent(self.manifest)
        report = score(self.manifest, predictions)
        exact = report["exact_class"]["overall"]
        self.assertEqual(exact["recall"], 0.0)
        self.assertFalse(passes_recall_gate(report, 0.5))
        coverage = report["any_alert_coverage"]["coverage"]
        self.assertEqual(coverage, 0.0)

    def test_gate_helper_raises_on_unknown_family(self):
        report = score(self.manifest, baseline_silent(self.manifest))
        with self.assertRaises(KeyError):
            passes_precision_gate(report, 0.5, family="not_a_real_family")


class SeedManifestIntegrationSmokeTest(unittest.TestCase):
    """Loads the real seed manifest and scores a trivial prediction set --
    proves the scorer and the real PR-2 manifest actually agree on shape,
    without pinning strong numeric assertions to corpus content."""

    def test_scores_seed_manifest_without_error(self):
        manifest = load_manifest(SEED_PATH)
        manifest.validate()
        predictions = baseline_silent(manifest)
        report = score(manifest, predictions)
        self.assertIn("exact_class", report)
        self.assertIn("any_alert_coverage", report)
        self.assertIn("evidence_supported", report)
        self.assertEqual(report["evidence_supported"]["status"], "unavailable")
        self.assertEqual(report["exact_class"]["overall"]["recall"], 0.0)


if __name__ == "__main__":
    unittest.main()
