"""
Caller-level + negative-control tests for testing/reconcile_benchmark.py
(PR-6, BP-3).

Discovered both via `python -m unittest discover -s testing -p test_*.py`
(harness.suite's smoke/full tiers) and directly via
`python -m unittest testing.test_reconcile_benchmark`.

Runs the reconciliation module over the REAL, committed 2026-09-23 benchmark
artifacts under reviews/2026-09-23/benchmark/ -- read-only, no model, no
network, no harness.store. Also feeds it SYNTHETIC, deliberately-corrupted
artifacts (negative controls) built entirely in this file, to prove the
self-consistency and strict-recall checks are not vacuous.

HARD SAFEGUARDS observed here: no `*ANSWER_KEY*` file or blind-target
`app.py` is read anywhere in this module or in testing/reconcile_benchmark.py
itself -- only the permitted, committed `reviews/2026-09-23/benchmark/*`
result/log artifacts and `harness/config.yaml`.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

_TESTING_DIR = Path(__file__).resolve().parent
_ROOT = _TESTING_DIR.parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

import reconcile_benchmark as rb  # noqa: E402


# The 2026-09-23 benchmark result JSONs live under reviews/2026-09-23/benchmark/
# and their sibling `.log`s are matched by the repo's `*.log` gitignore rule, so
# these artifacts are NOT (and cannot all be) tracked. Tests that read them run
# in a working tree that has them (e.g. the owner's), and skip cleanly in a fresh
# checkout/CI where they are absent. The synthetic negative controls below carry
# their own data and always run -- they are the non-vacuous proof of the logic.
_HAVE_ARTIFACTS = (
    (rb.BENCHMARK_DIR / "pixelmart_default_3x.json").exists()
    and (rb.BENCHMARK_DIR / "pixelmart_default_3x.log").exists()
)
_SKIP_REASON = "2026-09-23 benchmark artifacts absent (git-ignored/untracked)"


# ---------------------------------------------------------------------------
# Real-artifact tests: the saved (untracked) 2026-09-23 benchmark.
# ---------------------------------------------------------------------------

@unittest.skipUnless(_HAVE_ARTIFACTS, _SKIP_REASON)
class RealArtifactReconciliationTests(unittest.TestCase):
    """Runs over the REAL saved benchmark artifacts. A green run here means
    every corpus's stored summary agrees with what this module recomputes
    from that corpus's own per-run rows (self-consistency), while the KNOWN
    cross-file contradictions the 2026-09-24 principal review found are
    still flagged (not raised -- they are expected, documented findings)."""

    @classmethod
    def setUpClass(cls):
        cls.report = rb.run_full_reconciliation()

    def test_pixelmart_recomputed_mean_wall_matches_known_value(self):
        wall = self.report["per_corpus"]["pixelmart"]["recomputed"]["wall_time_s"]
        self.assertAlmostEqual(wall["mean"], 1138.631, places=2)
        self.assertEqual(wall["n"], 3)

    def test_pixelmart_recomputed_precision_recall_match_stored(self):
        pm = self.report["per_corpus"]["pixelmart"]
        self.assertAlmostEqual(pm["recomputed"]["recall"]["mean"],
                                pm["stored"]["recall"]["mean"], places=3)
        self.assertAlmostEqual(pm["recomputed"]["precision"]["mean"],
                                pm["stored"]["precision"]["mean"], places=3)

    def test_pixelmart_tokens_flagged_as_unavailable_not_zero(self):
        pm = self.report["per_corpus"]["pixelmart"]
        flags = {f["check"]: f for f in pm["flags"]}
        self.assertIn("tokens_instrumentation", flags)
        flag = flags["tokens_instrumentation"]
        self.assertEqual(flag["status"], "contradiction")
        self.assertIn("447", flag["detail"])  # ~447k real tokens cited
        self.assertIn("NOT evidence that 0 tokens", flag["detail"])

    def test_pixelmart_breaker_inconsistency_flagged(self):
        pm = self.report["per_corpus"]["pixelmart"]
        flags = {f["check"]: f for f in pm["flags"]}
        self.assertIn("breaker_health_claim", flags)
        self.assertEqual(flags["breaker_health_claim"]["status"], "inconsistency")
        self.assertEqual(pm["breaker_failures_per_run"], [2, 0, 2])

    def test_pixelmart_report_wall_claim_contradiction_flagged(self):
        pm = self.report["per_corpus"]["pixelmart"]
        flags = {f["check"]: f for f in pm["flags"]}
        self.assertIn("report_wall_claim", flags)
        flag = flags["report_wall_claim"]
        self.assertEqual(flag["status"], "contradiction")
        self.assertIn("1330", flag["detail"])
        self.assertIn("1138.6", flag["detail"])

    def test_all_five_corpora_present_and_self_consistent(self):
        # run_full_reconciliation() already raised ReconciliationError in
        # setUpClass if any corpus's own stored summary disagreed with its
        # own per-run rows -- reaching this line at all is part of the
        # assertion. Additionally check every corpus was actually scored.
        self.assertEqual(set(self.report["per_corpus"]),
                          {"pixelmart", "blindtarget2", "dvwa", "webgoat", "juiceshop"})

    def test_blind_corpora_recall_recomputed_from_raw_results_matches_bench_meta(self):
        for name in ("blindtarget2", "dvwa", "webgoat", "juiceshop"):
            data = rb.load_corpus_artifact(name)
            rec = rb.reconcile_blind_style(data, name)
            bench_meta = data["_bench_meta"]
            self.assertAlmostEqual(
                rec["recall_any_finding"]["mean"], bench_meta["recall_any_finding"]["mean"],
                places=3, msg=f"{name}: recomputed recall_any disagrees with _bench_meta")
            self.assertAlmostEqual(
                rec["recall_surfaced_only"]["mean"], bench_meta["recall_surfaced_only"]["mean"],
                places=3, msg=f"{name}: recomputed recall_surfaced disagrees with _bench_meta")

    def test_blind_corpora_tokens_flagged_unavailable(self):
        for name in ("blindtarget2", "dvwa", "webgoat", "juiceshop"):
            rec = self.report["per_corpus"][name]
            checks = {f["check"]: f for f in rec["flags"]}
            self.assertIn("tokens_instrumentation", checks)
            self.assertEqual(checks["tokens_instrumentation"]["status"], "unavailable")

    def test_never_reads_a_forbidden_path(self):
        """Runtime check (not a docstring grep -- this module's own comments
        legitimately NAME the forbidden patterns as part of documenting the
        safeguard): instruments Path.read_text/read_bytes for the duration
        of a full reconciliation run and asserts no touched path matches
        *ANSWER_KEY*/*answerkey* or a blind target's app.py."""
        touched: list[str] = []
        orig_read_text = Path.read_text
        orig_read_bytes = Path.read_bytes

        def tracked_read_text(self, *a, **kw):
            touched.append(str(self))
            return orig_read_text(self, *a, **kw)

        def tracked_read_bytes(self, *a, **kw):
            touched.append(str(self))
            return orig_read_bytes(self, *a, **kw)

        with mock.patch.object(Path, "read_text", tracked_read_text), \
             mock.patch.object(Path, "read_bytes", tracked_read_bytes):
            rb.run_full_reconciliation()

        forbidden = [p for p in touched
                     if "answer_key" in p.lower() or "answerkey" in p.lower()
                     or p.lower().endswith("app.py")]
        self.assertEqual(forbidden, [], f"reconciliation touched forbidden path(s): {forbidden}")
        self.assertGreater(len(touched), 0, "expected the instrumentation to observe some reads")


# ---------------------------------------------------------------------------
# Config-drift manifest tests.
# ---------------------------------------------------------------------------

@unittest.skipUnless(_HAVE_ARTIFACTS, _SKIP_REASON)
class ConfigDriftManifestTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.manifest = rb.build_config_drift_manifest()

    def test_shipped_defaults_match_known_config_anchors(self):
        shipped = self.manifest["shipped_defaults"]
        self.assertEqual(shipped["fail_open_mode"], "all")
        self.assertEqual(shipped["quarantine_unverified_leads"], False)
        self.assertEqual(shipped["routing_mode"], "agents")

    def test_four_blind_corpora_flagged_as_drifted_from_shipped_defaults(self):
        by_corpus = {e["corpus"]: e for e in self.manifest["corpora"]}
        for name in ("blindtarget2", "dvwa", "webgoat", "juiceshop"):
            entry = by_corpus[name]
            self.assertEqual(entry["recorded"]["fail_open_mode"], "curated")
            self.assertEqual(entry["recorded"]["quarantine_unverified_leads"], True)
            self.assertIn("DRIFT", entry["drift"]["fail_open_mode"])
            self.assertIn("DRIFT", entry["drift"]["quarantine_unverified_leads"])

    def test_pixelmart_fingerprint_fields_unavailable_not_fabricated(self):
        by_corpus = {e["corpus"]: e for e in self.manifest["corpora"]}
        entry = by_corpus["pixelmart"]
        self.assertEqual(entry["recorded"]["fail_open_mode"], rb.UNAVAILABLE)
        self.assertEqual(entry["recorded"]["quarantine_unverified_leads"], rb.UNAVAILABLE)
        self.assertIn("unavailable", entry["drift"]["fail_open_mode"])
        self.assertIn("source_note", entry)

    def test_config_yaml_not_modified_by_generating_the_manifest(self):
        before = rb.CONFIG_PATH.read_bytes()
        rb.build_config_drift_manifest()
        after = rb.CONFIG_PATH.read_bytes()
        self.assertEqual(before, after)

    def test_render_table_is_nonempty_markdown(self):
        table = rb.render_config_drift_table(self.manifest)
        self.assertIn("pixelmart", table)
        self.assertIn("blindtarget2", table)
        self.assertIn("Shipped defaults", table)


# ---------------------------------------------------------------------------
# Strict exact-class recall: never inferred from a broad category.
# ---------------------------------------------------------------------------

class StrictRecallNeverInferredTests(unittest.TestCase):

    def test_manifested_corpus_still_refuses_on_the_2026_09_23_artifact_shape(self):
        # These four now HAVE exact-class manifests (seeded 2026-09-25 for the live
        # strict benchmark: webgoat/dvwa/juiceshop from public app knowledge,
        # blindtarget2 all-inconclusive). But the saved 2026-09-23 artifacts carry
        # aggregate tp/fp/fn, not eval_adapter's per-finding stages/attribution, so
        # strict recall must STILL be refused as UNAVAILABLE (never inferred from
        # coarse coverage) -- same refusal as pixelmart, for the same reason.
        checked = 0
        for name in ("pixelmart", "blindtarget2", "dvwa", "webgoat", "juiceshop"):
            if not (rb.LABELS_DIR / f"{name}.labels.json").exists():
                continue  # some manifests are local-only evidence, not committed
            result = rb.strict_exact_class_recall(name)
            self.assertEqual(result["strict_exact_class_recall"], rb.UNAVAILABLE)
            self.assertIsInstance(result["strict_exact_class_recall"], str)
            self.assertIn("eval_adapter.build_eval_artifact's shape", result["reason"])
            checked += 1
        self.assertGreater(checked, 0, "expected at least the pixelmart manifest to exist")

    def test_a_truly_manifestless_corpus_reports_no_manifest(self):
        # The other refusal branch (no manifest at all) is still exercised, via a
        # corpus name that has no *.labels.json -- so the "no exact-class manifest"
        # path cannot silently rot now that the real corpora are all manifested.
        result = rb.strict_exact_class_recall("corpus_with_no_manifest_xyz")
        self.assertEqual(result["strict_exact_class_recall"], rb.UNAVAILABLE)
        self.assertIn("no exact-class manifest", result["reason"])

    def test_pixelmart_manifest_exists_but_artifact_shape_still_refuses(self):
        # PixelMart DOES have testing/labels/pixelmart.labels.json, but the
        # saved 2026-09-23 artifact carries aggregate tp/fp/fn counts, not
        # eval_adapter's per-finding stages/attribution shape -- so this
        # must still refuse to produce a number, for a DIFFERENT reason than
        # the no-manifest corpora above.
        manifest_path = rb.LABELS_DIR / "pixelmart.labels.json"
        self.assertTrue(manifest_path.exists(), "expected seed manifest to exist for this test")
        result = rb.strict_exact_class_recall("pixelmart", saved=None)
        self.assertEqual(result["strict_exact_class_recall"], rb.UNAVAILABLE)
        self.assertIn("not in eval_adapter.build_eval_artifact's shape", result["reason"])

    def test_pixelmart_with_a_properly_shaped_saved_run_DOES_produce_a_number(self):
        # Positive control for the refusal logic above: once a saved run
        # genuinely carries eval_adapter's shape, strict recall stops being
        # unavailable. Uses a minimal synthetic build_eval_artifact-shaped
        # dict (no real store/model/network involved).
        sys.path.insert(0, str(_TESTING_DIR)) if str(_TESTING_DIR) not in sys.path else None
        from labels.manifest import load_manifest
        manifest = load_manifest(rb.LABELS_DIR / "pixelmart.labels.json")
        positive = manifest.positives()[0]
        finding = {
            "finding_id": "f1", "fingerprint": "fp1",
            "vulnerability_class": positive.expected_classes[0],
            "url": "http://pixelmart.invalid/x", "method": "GET",
            "confirmed": False, "basis": "derived", "confidence": 0.9,
            "oracle_verified": False, "proof_id": None,
            "case_id": None, "exchange_id": positive.exchange_id,
            "severity": "high", "parameter_location": None, "parameter_name": None,
        }
        saved = {
            "host": "pixelmart.invalid",
            "quarantine_leads": False,
            "gate_low_confidence_generic": False,
            "generic_confidence_floor": 0.5,
            "exchanges": [{"id": positive.exchange_id, "method": "GET",
                            "url": "http://pixelmart.invalid/x"}],
            "stages": {"raw": [finding]},
            "attribution": {"by_exchange": {positive.exchange_id: ["f1"]}, "unresolved": []},
            "provenance": {"run_id": "synthetic", "inputs_hash": "deadbeef"},
            "instrumentation": {},
            "evidence_inputs": {"proofs": [], "cases": [], "artifacts": []},
        }
        result = rb.strict_exact_class_recall("pixelmart", saved=saved)
        self.assertNotEqual(result["strict_exact_class_recall"], rb.UNAVAILABLE)
        self.assertEqual(result["kind"], "historical_rescore")
        rb.assert_not_fabricated_strict_recall({"strict_exact_class_recall": {"exact_class": {}}})

    def test_assert_not_fabricated_rejects_a_bare_number(self):
        with self.assertRaises(rb.ReconciliationError):
            rb.assert_not_fabricated_strict_recall({"strict_exact_class_recall": 0.909})

    def test_assert_not_fabricated_accepts_the_unavailable_sentinel(self):
        rb.assert_not_fabricated_strict_recall(
            {"strict_exact_class_recall": rb.UNAVAILABLE, "reason": "no manifest"})


# ---------------------------------------------------------------------------
# NEGATIVE CONTROLS -- synthetic, deliberately-corrupted artifacts. Proves
# the reconciliation checks actually fail closed instead of rubber-stamping
# any input.
# ---------------------------------------------------------------------------

def _synthetic_pixelmart_artifact(*, corrupt_wall: bool = False) -> dict:
    """A minimal but structurally valid PixelMart-shaped ("variants") saved
    artifact. `corrupt_wall=True` makes results[0].wall_time_s.mean disagree
    with what run_health's rows actually average to -- the negative control."""
    run_health = [
        {"variant": "A", "repeat": 0, "breaker_failures": 0, "breaker_opened_during_run": False,
         "breaker_ended_open": False, "starved": False, "starved_error": None,
         "model_calls": 10, "model_prompt_tokens": 100, "model_completion_tokens": 10,
         "model_total_tokens": 110, "tp": 5, "fp": 5, "fn": 0, "wall_time_s": 100.0},
        {"variant": "A", "repeat": 1, "breaker_failures": 0, "breaker_opened_during_run": False,
         "breaker_ended_open": False, "starved": False, "starved_error": None,
         "model_calls": 10, "model_prompt_tokens": 100, "model_completion_tokens": 10,
         "model_total_tokens": 110, "tp": 5, "fp": 5, "fn": 0, "wall_time_s": 200.0},
    ]
    true_mean = sum(h["wall_time_s"] for h in run_health) / len(run_health)  # 150.0
    stated_mean = 999.0 if corrupt_wall else true_mean
    return {
        "results": [{
            "variant": "A", "name": "current", "repeats": 2,
            "precision": {"mean": 0.5, "stdev": 0.0, "n": 2},
            "recall": {"mean": 1.0, "stdev": 0.0, "n": 2},
            "tp": {"mean": 5.0, "stdev": 0.0, "n": 2},
            "fp": {"mean": 5.0, "stdev": 0.0, "n": 2},
            "fn": {"mean": 0.0, "stdev": 0.0, "n": 2},
            "cost_tokens": {"mean": 0.0, "stdev": 0.0, "n": 2},
            "wall_time_s": {"mean": stated_mean, "stdev": 0.0, "n": 2},
        }],
        "run_health": run_health,
    }


class NegativeControlTests(unittest.TestCase):
    """Feeds the reconciliation functions synthetic artifacts whose stored
    summary DISAGREES with their own per-run rows. If these checks were
    vacuous (e.g. always returning "ok" without truly recomputing), these
    would pass; they must instead raise."""

    def test_pixelmart_self_consistent_synthetic_artifact_passes(self):
        data = _synthetic_pixelmart_artifact(corrupt_wall=False)
        result = rb.reconcile_pixelmart(data)  # must not raise
        self.assertAlmostEqual(result["recomputed"]["wall_time_s"]["mean"], 150.0)

    def test_pixelmart_corrupted_summary_total_is_rejected(self):
        data = _synthetic_pixelmart_artifact(corrupt_wall=True)
        with self.assertRaises(rb.ReconciliationError) as ctx:
            rb.reconcile_pixelmart(data)
        self.assertIn("self-consistency failure", str(ctx.exception))

    def test_blind_style_corrupted_variance_values_is_rejected(self):
        data = json.loads(
            (rb.BENCHMARK_DIR / "blindtarget2_default_3x.json").read_text(encoding="utf-8"))
        corrupted = copy.deepcopy(data)
        # Tamper with one stored per-run value in the pre-aggregated
        # 'variance' block so it silently disagrees with the SAME metric's
        # real per-run value still sitting in runs[0] -- exactly the kind of
        # drift a real reconciliation bug would need to catch.
        corrupted["variance"]["n_findings_total"]["values"][0] = 999999.0
        with self.assertRaises(rb.ReconciliationError) as ctx:
            rb.reconcile_blind_style(corrupted, "blindtarget2")
        self.assertIn("disagrees", str(ctx.exception))

    def test_blind_style_corrupted_summary_mean_is_rejected(self):
        data = json.loads(
            (rb.BENCHMARK_DIR / "blindtarget2_default_3x.json").read_text(encoding="utf-8"))
        corrupted = copy.deepcopy(data)
        corrupted["variance"]["total_elapsed_seconds"]["mean"] = 1.0
        with self.assertRaises(rb.ReconciliationError):
            rb.reconcile_blind_style(corrupted, "blindtarget2")

    def test_blind_style_corrupted_bench_meta_recall_is_rejected(self):
        data = json.loads(
            (rb.BENCHMARK_DIR / "dvwa_default_3x.json").read_text(encoding="utf-8"))
        corrupted = copy.deepcopy(data)
        corrupted["_bench_meta"]["recall_any_finding"]["mean"] = 0.0
        with self.assertRaises(rb.ReconciliationError):
            rb.reconcile_blind_style(corrupted, "dvwa")

    def test_strict_recall_inferred_from_broad_category_is_rejected(self):
        # Simulate a caller mistakenly presenting blind-eval "recall(any)"
        # (a broad/coarse-category coverage number) as if it were strict
        # exact-class recall -- must be rejected, not silently accepted.
        fabricated_entry = {"strict_exact_class_recall": 1.0,  # recall(any)=1.0, coarse
                             "reason": "mistakenly copied from recall_any_finding"}
        with self.assertRaises(rb.ReconciliationError):
            rb.assert_not_fabricated_strict_recall(fabricated_entry)


if __name__ == "__main__":
    unittest.main()
