"""Tests for testing/config_manifest.py (NC-3, R14 residual). Offline, read-only.

The load-bearing test regenerates the safety-defaults manifest from the live
harness/config.yaml and asserts it matches the committed snapshot -- so a silent
flip of a passive default fails CI. Independently, the safe shipped values are
asserted directly (REQUIRED_SAFE_VALUES), so regenerating the snapshot to match a
flipped config cannot launder an unsafe change past review.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

import config_manifest as cm  # noqa: E402
from reconcile_benchmark import UNAVAILABLE  # noqa: E402


class SnapshotDriftTests(unittest.TestCase):
    def test_generated_matches_committed_snapshot(self):
        # THE drift guard: changing a safety default in config.yaml without
        # regenerating the snapshot fails here.
        manifest = cm.generate_config_manifest()
        snapshot = cm.load_snapshot()
        self.assertEqual(manifest["safety_defaults"], snapshot["safety_defaults"],
                         "config.yaml safety defaults drifted from the committed snapshot "
                         "-- run `python -m testing.config_manifest --write` only after a "
                         "reviewed, intentional change")
        self.assertEqual(manifest["hash"], snapshot["hash"])

    def test_no_drift_lines_against_snapshot(self):
        self.assertEqual(cm.diff_against_snapshot(cm.generate_config_manifest(),
                                                  cm.load_snapshot()), [])


class SafeValueGuardTests(unittest.TestCase):
    def test_required_safe_values_hold_in_live_config(self):
        safety = cm.generate_config_manifest()["safety_defaults"]
        for key, expected in cm.REQUIRED_SAFE_VALUES.items():
            self.assertEqual(safety.get(key), expected,
                             f"{key} must ship as {expected!r} (safe default)")

    def test_required_safe_values_hold_in_snapshot(self):
        # Independent of regeneration: the committed snapshot itself must encode
        # the safe values, so a flip cannot be laundered by rewriting the snapshot.
        safety = cm.load_snapshot()["safety_defaults"]
        for key, expected in cm.REQUIRED_SAFE_VALUES.items():
            self.assertEqual(safety.get(key), expected)

    def test_all_safety_keys_present_in_live_config(self):
        safety = cm.generate_config_manifest()["safety_defaults"]
        missing = [k for k, v in safety.items() if v == UNAVAILABLE]
        self.assertEqual(missing, [], f"safety key(s) absent from config.yaml: {missing}")


class DriftDetectionTests(unittest.TestCase):
    def test_flipping_active_enabled_is_detected(self):
        # NEGATIVE control: a config that flips the passive default must (a) show
        # active_enabled True and (b) produce drift lines against the snapshot.
        cfg = ("validators:\n"
               "  enabled: true\n"
               "  active_enabled: true\n"      # <-- unsafe flip
               "  allow_mutating_replay: false\n")
        with tempfile.TemporaryDirectory(prefix="nc3_") as d:
            p = Path(d) / "config.yaml"
            p.write_text(cfg, encoding="utf-8")
            flipped = cm.generate_config_manifest(config_path=p)
        self.assertTrue(flipped["safety_defaults"]["validators.active_enabled"])
        drift = cm.diff_against_snapshot(flipped, cm.load_snapshot())
        self.assertTrue(any("validators.active_enabled" in line for line in drift),
                        f"flip not reported as drift: {drift}")
        self.assertNotEqual(flipped["hash"], cm.load_snapshot()["hash"])

    def test_generation_is_deterministic(self):
        self.assertEqual(cm.generate_config_manifest(), cm.generate_config_manifest())


if __name__ == "__main__":
    unittest.main()
