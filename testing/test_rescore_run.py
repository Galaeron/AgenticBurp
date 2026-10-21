"""Tests for testing/rescore_run.py (NC-1). Offline, deterministic, read-only.

Proves the runner MAKES the strict scorer load-bearing (re-review N01): it applies
`eval_adapter.rescore_saved_run` to a saved run AND runs the three mandatory
indiscriminate baselines through the precision/recall gates as a built-in negative
control -- refusing to certify a scorecard when the baselines don't all fail.

The saved-run fixture carries an empty raw-findings stage on purpose: the baseline
controls are computed from the MANIFEST inside the runner (that is the "through the
runner" requirement), so the fixture proves the end-to-end path without coupling the
test to the finding->prediction plumbing (which testing/test_eval_adapter.py covers).
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

import rescore_run as rr  # noqa: E402
from labels.manifest import LabelRecord, Manifest, ManifestError, compute_hash  # noqa: E402

_HOST = "nc1-fixture.invalid"


def _record(exchange_id, expected=(), tested_negative=(), status="positive"):
    return LabelRecord(
        exchange_id=exchange_id, expected_classes=tuple(expected),
        tested_negative_classes=tuple(tested_negative), label_scope="nc1 fixture",
        status=status, provenance="nc1 unit fixture -- no answer-key")


def _records():
    return [
        _record("TP1", expected=("sqli",)),
        _record("TP2", expected=("xss",)),
        _record("TP3", expected=("idor",)),
        _record("TN1", tested_negative=("sqli", "xss"), status="negative"),
    ]


def _manifest(records=None, corpus="nc1-unittest"):
    records = _records() if records is None else records
    return Manifest(corpus=corpus, version="0.0.1",
                    hash=compute_hash(records), records=tuple(records))


def _saved(host=_HOST):
    """A build_eval_artifact-shaped saved run with an empty raw stage."""
    return {
        "schema_version": "1.0.0", "kind": "live", "host": host,
        "stages": {"raw": []},
        "exchanges": [
            {"id": "TP1", "method": "GET", "url": f"http://{host}/a?id=1"},
            {"id": "TP2", "method": "GET", "url": f"http://{host}/b"},
        ],
        "attribution": {"by_exchange": {}, "unresolved": []},
        "evidence_inputs": {"proofs": [], "cases": [], "artifacts": []},
        "provenance": {"run_id": "nc1run", "inputs_hash": "nc1hash", "complete": True},
        "instrumentation": {},
    }


class ApplyStrictScorecardTests(unittest.TestCase):
    def test_emits_strict_scorecard_with_provenance(self):
        card = rr.apply_strict_scorecard(_saved(), _manifest(), git_revision="rev1")
        self.assertEqual(card["kind"], "historical_rescore")
        self.assertEqual(card["scorer"], "testing.strict_score")
        self.assertIn("exact_class", card["metrics"])
        # provenance is stamped and marks a rescored (not fresh) run.
        self.assertEqual(card["provenance"]["git_revision"], "rev1")

    def test_baselines_all_fail_their_gates_through_the_runner(self):
        card = rr.apply_strict_scorecard(_saved(), _manifest(), git_revision="rev1")
        ctrls = card["baseline_controls"]
        self.assertTrue(ctrls["discriminating"])
        # always-alert and all-classes must FAIL the precision gate...
        self.assertFalse(ctrls["always_alert"]["passed_gate"])
        self.assertTrue(ctrls["always_alert"]["control_ok"])
        self.assertFalse(ctrls["all_classes"]["passed_gate"])
        self.assertTrue(ctrls["all_classes"]["control_ok"])
        # ...silent must FAIL the recall gate.
        self.assertFalse(ctrls["silent"]["passed_gate"])
        self.assertTrue(ctrls["silent"]["control_ok"])

    def test_refuses_to_certify_when_a_baseline_passes_its_gate(self):
        # NEGATIVE CONTROL: a gate so low the always-alert baseline clears it ->
        # the manifest/scorer can't discriminate -> the runner must REFUSE.
        with self.assertRaises(rr.StrictScorecardError):
            rr.apply_strict_scorecard(_saved(), _manifest(), git_revision="rev1",
                                      precision_gate=0.0)

    def test_coarse_metrics_only_appear_under_historical_label(self):
        coarse = {"precision": 1.0, "recall": 1.0, "note": "coarse OWASP-category"}
        card = rr.apply_strict_scorecard(_saved(), _manifest(), git_revision="rev1",
                                         coarse_metrics=coarse)
        hc = card["historical_coarse"]
        self.assertIsNotNone(hc)
        self.assertIn("historical", hc["label"].lower())
        self.assertEqual(hc["metrics"], coarse)
        # And coarse numbers are NOT hoisted next to the strict metrics.
        self.assertNotIn("precision", card["metrics"])

    def test_no_coarse_block_when_none_supplied_or_saved(self):
        card = rr.apply_strict_scorecard(_saved(), _manifest(), git_revision="rev1")
        self.assertIsNone(card["historical_coarse"])

    def test_format_scorecard_renders_controls_and_discriminating(self):
        card = rr.apply_strict_scorecard(_saved(), _manifest(), git_revision="rev1")
        text = rr.format_scorecard(card)
        self.assertIn("Strict scorecard", text)
        self.assertIn("always_alert", text)
        self.assertIn("discriminating=True", text)


class BaselineControlsTests(unittest.TestCase):
    def test_controls_report_exact_class_overall_for_each_baseline(self):
        ctrls = rr.baseline_controls(_manifest(), precision_gate=0.5, recall_gate=0.5)
        for name in ("always_alert", "all_classes", "silent"):
            self.assertIn("overall", ctrls[name])
        # silent recalls nothing on a manifest with positives.
        self.assertEqual(ctrls["silent"]["overall"]["recall"], 0.0)


class RunFromFilesTests(unittest.TestCase):
    def test_roundtrip_from_disk(self):
        recs = _records()
        manifest_doc = {
            "corpus": "nc1-file", "version": "0.0.1",
            "hash": compute_hash(recs),
            "records": [
                {"exchange_id": r.exchange_id, "expected_classes": list(r.expected_classes),
                 "tested_negative_classes": list(r.tested_negative_classes),
                 "label_scope": r.label_scope, "status": r.status, "provenance": r.provenance}
                for r in recs
            ],
        }
        with tempfile.TemporaryDirectory(prefix="nc1_") as d:
            sp = Path(d) / "saved.json"
            mp = Path(d) / "manifest.json"
            sp.write_text(json.dumps(_saved()), encoding="utf-8")
            mp.write_text(json.dumps(manifest_doc), encoding="utf-8")
            card = rr.run_from_files(sp, mp, git_revision="revfile")
        self.assertEqual(card["corpus"], "nc1-file")
        self.assertTrue(card["baseline_controls"]["discriminating"])


class RescoreCompletionThroughRunnerTests(unittest.TestCase):
    """R41 at the runner's own boundary: the scorecard's provenance carries the
    source run's completion status instead of asserting complete=True."""

    def _card(self, complete):
        saved = _saved()
        saved["provenance"] = dict(saved["provenance"], complete=complete)
        return rr.apply_strict_scorecard(saved, _manifest(), git_revision="rev1")

    def test_incomplete_source_is_incomplete_in_the_scorecard(self):
        self.assertIs(self._card(False)["provenance"]["complete"], False)

    def test_completed_source_control(self):
        card = self._card(True)
        self.assertIs(card["provenance"]["complete"], True)
        self.assertEqual(card["kind"], "historical_rescore")


def _manifest_doc(recs, *, declared_hash=None):
    return {
        "corpus": "rv-c-file", "version": "0.0.1",
        "hash": compute_hash(recs) if declared_hash is None else declared_hash,
        "records": [
            {"exchange_id": r.exchange_id, "expected_classes": list(r.expected_classes),
             "tested_negative_classes": list(r.tested_negative_classes),
             "label_scope": r.label_scope, "status": r.status, "provenance": r.provenance}
            for r in recs
        ],
    }


class ManifestIntegrityTests(unittest.TestCase):
    """R42: a manifest whose declared content hash does not match its records
    must be refused before anything is scored, by the file-based caller and by
    the CLI entry point that wraps it."""

    def _files(self, d, *, declared_hash=None):
        sp, mp = Path(d) / "saved.json", Path(d) / "manifest.json"
        sp.write_text(json.dumps(_saved()), encoding="utf-8")
        mp.write_text(json.dumps(_manifest_doc(_records(), declared_hash=declared_hash)), encoding="utf-8")
        return sp, mp

    def test_corrupt_manifest_hash_is_rejected_by_rescore_caller(self):
        with tempfile.TemporaryDirectory(prefix="rvc_") as d:
            sp, mp = self._files(d, declared_hash="wrong-content-hash")
            with self.assertRaises(ManifestError) as caught:
                rr.run_from_files(sp, mp, git_revision="rev")
        self.assertIn("wrong-content-hash", str(caught.exception))

    def test_valid_manifest_control(self):
        with tempfile.TemporaryDirectory(prefix="rvc_") as d:
            sp, mp = self._files(d)
            card = rr.run_from_files(sp, mp, git_revision="rev")
        self.assertTrue(card["baseline_controls"]["discriminating"])

    def test_records_edited_after_hashing_are_rejected(self):
        """The failure the hash exists for: a record hand-edited without
        updating the declared hash (the declared hash itself is well-formed)."""
        with tempfile.TemporaryDirectory(prefix="rvc_") as d:
            sp, mp = self._files(d)
            doc = json.loads(mp.read_text(encoding="utf-8"))
            doc["records"][0]["expected_classes"] = ["xss"]
            mp.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(ManifestError):
                rr.run_from_files(sp, mp, git_revision="rev")

    def test_in_memory_manifest_with_a_wrong_hash_is_rejected_before_scoring(self):
        recs = _records()
        bad = Manifest(corpus="rv-c-mem", version="0.0.1", hash="wrong-content-hash", records=tuple(recs))
        with mock.patch.object(rr.eval_adapter, "rescore_saved_run",
                               side_effect=AssertionError("must not score")) as scored:
            with self.assertRaises(ManifestError):
                rr.apply_strict_scorecard(_saved(), bad, git_revision="rev")
        scored.assert_not_called()

    def test_cli_reports_a_corrupt_manifest_clearly_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory(prefix="rvc_") as d:
            sp, mp = self._files(d, declared_hash="wrong-content-hash")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = rr.main([str(sp), str(mp), "--git-revision", "rev"])
        self.assertEqual(rc, 2)
        self.assertIn("REFUSED", err.getvalue())
        self.assertIn("manifest hash mismatch", err.getvalue())
        self.assertEqual(out.getvalue(), "", "no scorecard may be printed for a corrupt manifest")

    def test_cli_valid_manifest_control(self):
        with tempfile.TemporaryDirectory(prefix="rvc_") as d:
            sp, mp = self._files(d)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = rr.main([str(sp), str(mp), "--git-revision", "rev"])
        self.assertEqual(rc, 0)
        self.assertIn("Strict scorecard", out.getvalue())


if __name__ == "__main__":
    unittest.main()
