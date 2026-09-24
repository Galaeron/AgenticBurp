"""
Caller-level tests for testing/labels/manifest.py (PR-2, BP-0).

Discovered both via `python -m unittest discover -s testing -p test_*.py`
(harness.suite's smoke/full tiers) and directly via
`python -m unittest testing.test_label_manifest`. Deterministic and fully
offline -- no model/GPU/network -- and this module never opens an
*ANSWER_KEY* file or a blind target's app.py; see manifest.py's own
docstring for the permitted-source discipline the seed data follows.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Make `labels` importable as a bare top-level package regardless of how
# this test module itself was discovered/imported (mirrors the sys.path
# trick testing/score.py already uses for its own corpus-subdir imports:
# `sys.path.insert(0, str(Path(__file__).resolve().parent / corpus))`).
_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

from labels.manifest import (  # noqa: E402
    LabelRecord, ManifestError, compute_hash, load_manifest,
)

SEED_PATH = _TESTING_DIR / "labels" / "pixelmart.labels.json"


def _write_manifest(tmpdir: str, payload: dict) -> Path:
    p = Path(tmpdir) / "manifest.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _valid_record(**overrides) -> dict:
    base = {
        "exchange_id": "X1",
        "expected_classes": ["sqli"],
        "tested_negative_classes": [],
        "label_scope": "GET /api/x -- q param",
        "status": "positive",
        "provenance": "unit test fixture",
    }
    base.update(overrides)
    return base


def _valid_manifest(records: list) -> dict:
    return {
        "corpus": "unittest-corpus",
        "version": "0.0.1",
        "hash": compute_hash(records),
        "records": records,
    }


class SeedPixelmartManifestTest(unittest.TestCase):
    """Loads the real seed manifest -- proves the loader and the seed data
    actually agree, not just synthetic fixtures."""

    def setUp(self):
        self.manifest = load_manifest(SEED_PATH)

    def test_loads_and_validates(self):
        self.assertEqual(self.manifest.corpus, "pixelmart")
        report = self.manifest.validate()
        self.assertEqual(report["n_records"], len(self.manifest.records))
        self.assertGreater(report["n_positive"], 0)

    def test_multiple_expected_classes_round_trip(self):
        tp10 = self.manifest.by_id("TP10")
        self.assertIsNotNone(tp10)
        self.assertEqual(set(tp10.expected_classes), {"path_traversal", "info_disclosure"})
        # Round-trip through to_dict/from_dict preserves both classes.
        rebuilt = LabelRecord.from_dict(tp10.to_dict())
        self.assertEqual(rebuilt.expected_classes, tp10.expected_classes)

    def test_per_class_negatives_are_scoped_not_blanket(self):
        # TN2 is a negative control for sqli on /api/products/1 -- it must
        # NOT be treated as a negative control for an unrelated class (xss)
        # it was never tested against. A benign SQL-safe endpoint is not
        # proof of security against every other vulnerability class.
        sqli_controls = {r.exchange_id for r in self.manifest.negative_controls_for("sqli")}
        xss_controls = {r.exchange_id for r in self.manifest.negative_controls_for("xss")}
        self.assertIn("TN2", sqli_controls)
        self.assertNotIn("TN2", xss_controls)
        tn2 = self.manifest.by_id("TN2")
        self.assertEqual(tn2.tested_negative_classes, ("sqli",))

    def test_unresolved_record_is_surfaced_not_dropped_or_secure(self):
        unresolved = {r.exchange_id for r in self.manifest.unresolved()}
        self.assertIn("TP8", unresolved)
        tp8 = self.manifest.by_id("TP8")
        self.assertEqual(tp8.status, "inconclusive")
        # Never folded into positives/negatives, never scored.
        scorable_ids = {r.exchange_id for r in self.manifest.scorable()}
        self.assertNotIn("TP8", scorable_ids)
        self.assertNotIn(tp8, self.manifest.positives())
        self.assertNotIn(tp8, self.manifest.negatives())

    def test_setup_records_never_positive_or_fp_eligible(self):
        setup_ids = {r.exchange_id for r in self.manifest.setup_records()}
        self.assertTrue(setup_ids)  # at least one setup row exists
        scorable_ids = {r.exchange_id for r in self.manifest.scorable()}
        positive_ids = {r.exchange_id for r in self.manifest.positives()}
        self.assertTrue(setup_ids.isdisjoint(scorable_ids))
        self.assertTrue(setup_ids.isdisjoint(positive_ids))


class LoaderStructuralValidationTest(unittest.TestCase):
    """Synthetic fixtures -- deterministic, offline, no corpus dependency."""

    def test_missing_required_field_is_rejected(self):
        record = _valid_record()
        del record["provenance"]
        payload = _valid_manifest([record])
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, payload)
            with self.assertRaises(ManifestError):
                load_manifest(path)

    def test_bad_status_is_rejected(self):
        record = _valid_record(status="definitely_confirmed")
        payload = _valid_manifest([record])
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, payload)
            with self.assertRaises(ManifestError):
                load_manifest(path)

    def test_unknown_exact_class_is_rejected(self):
        record = _valid_record(expected_classes=["definitely_sqli_i_promise"])
        payload = _valid_manifest([record])
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, payload)
            with self.assertRaises(ManifestError):
                load_manifest(path)

    def test_label_leaking_reserved_key_is_rejected(self):
        # NEGATIVE CONTROL: a stray free-text field that echoes the answer
        # -- exactly the leak shape the loader must refuse, not silently
        # pass through into whatever later reads this record.
        record = _valid_record()
        record["exploit_detail"] = "the actual payload that proves this is TP1"
        payload = _valid_manifest([record])
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, payload)
            with self.assertRaises(ManifestError) as ctx:
                load_manifest(path)
            self.assertIn("possible label leak", str(ctx.exception))

    def test_label_leaking_top_level_field_is_rejected(self):
        record = _valid_record()
        payload = _valid_manifest([record])
        payload["ground_truth_notes"] = "TP1 is definitely SQLi"
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, payload)
            with self.assertRaises(ManifestError) as ctx:
                load_manifest(path)
            self.assertIn("possible label leak", str(ctx.exception))

    def test_duplicate_exchange_id_is_rejected(self):
        r1 = _valid_record(exchange_id="DUPE")
        r2 = _valid_record(exchange_id="DUPE")
        payload = _valid_manifest([r1, r2])
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, payload)
            with self.assertRaises(ManifestError):
                load_manifest(path)

    def test_setup_status_cannot_carry_expected_classes(self):
        record = _valid_record(status="setup", expected_classes=["sqli"])
        payload = _valid_manifest([record])
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, payload)
            with self.assertRaises(ManifestError):
                load_manifest(path)

    def test_negative_status_cannot_assert_expected_classes(self):
        record = _valid_record(status="negative", expected_classes=["sqli"])
        payload = _valid_manifest([record])
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, payload)
            with self.assertRaises(ManifestError):
                load_manifest(path)

    def test_tampered_hash_is_rejected_by_validate(self):
        record = _valid_record()
        payload = _valid_manifest([record])
        payload["hash"] = "0" * 64  # wrong on purpose
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, payload)
            manifest = load_manifest(path)  # structurally fine
            with self.assertRaises(ManifestError):
                manifest.validate()  # content hash does not match

    def test_valid_manifest_round_trips(self):
        record = _valid_record()
        payload = _valid_manifest([record])
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, payload)
            manifest = load_manifest(path)
            report = manifest.validate()
            self.assertEqual(report["n_records"], 1)
            self.assertEqual(manifest.by_id("X1").expected_classes, ("sqli",))


if __name__ == "__main__":
    unittest.main()
