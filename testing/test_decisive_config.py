"""Tests for the Phase 1.2 decisive-run config template + loader/validator."""
from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import decisive_config as dc  # noqa: E402


def _valid_cfg():
    """The committed template with the scope placeholder replaced by a real host."""
    return {
        "server": {"allowed_hosts": ["crapi.internal.test"]},
        "validators": {"active_enabled": True, "allow_mutating_replay": True,
                       "max_burst_size": 5},
        "ollama": {"seed": 1337},
        "coordinator": {"temperature": 0, "seed": 1337},
        "agent_defaults": {"temperature": 0},
    }


class DecisiveConfigTemplateTests(unittest.TestCase):
    def test_committed_template_is_armed_but_scope_is_an_unset_placeholder(self):
        # The committed template must NOT be runnable as-is: its scope is a
        # sentinel the operator has to replace, so loading it fails loud rather
        # than running against a bogus host.
        self.assertTrue(dc.DEFAULT_TEMPLATE.exists())
        with self.assertRaises(dc.DecisiveConfigError) as ctx:
            dc.load_decisive_config()
        self.assertIn(dc.SCOPE_PLACEHOLDER, str(ctx.exception))

    def test_config_hash_is_stable_and_sha256_shaped(self):
        h1 = dc.config_hash()
        h2 = dc.config_hash()
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)
        int(h1, 16)  # hex

    def test_filled_template_loads_and_returns_hash(self):
        with tempfile.TemporaryDirectory() as d:
            import yaml
            p = Path(d) / "run.yaml"
            p.write_text(yaml.safe_dump(_valid_cfg()), encoding="utf-8")
            cfg, h = dc.load_decisive_config(p)
            self.assertTrue(cfg["validators"]["active_enabled"])
            self.assertEqual(len(h), 64)

    def test_hash_changes_when_the_config_changes(self):
        import yaml
        with tempfile.TemporaryDirectory() as d:
            a = Path(d) / "a.yaml"
            b = Path(d) / "b.yaml"
            cfg = _valid_cfg()
            a.write_text(yaml.safe_dump(cfg), encoding="utf-8")
            cfg2 = copy.deepcopy(cfg)
            cfg2["ollama"]["seed"] = 999
            b.write_text(yaml.safe_dump(cfg2), encoding="utf-8")
            self.assertNotEqual(dc.config_hash(a), dc.config_hash(b))


class AssertDecisiveSettingsTests(unittest.TestCase):
    def test_a_fully_armed_filled_config_passes(self):
        dc.assert_decisive_settings(_valid_cfg())  # no raise

    def test_seed_zero_is_accepted(self):
        cfg = _valid_cfg()
        cfg["ollama"]["seed"] = 0  # a valid, fixed seed -- must NOT read as "unset"
        dc.assert_decisive_settings(cfg)

    def test_active_mode_off_rejected(self):
        cfg = _valid_cfg(); cfg["validators"]["active_enabled"] = False
        with self.assertRaises(dc.DecisiveConfigError):
            dc.assert_decisive_settings(cfg)

    def test_mutating_replay_off_rejected(self):
        cfg = _valid_cfg(); cfg["validators"]["allow_mutating_replay"] = False
        with self.assertRaises(dc.DecisiveConfigError):
            dc.assert_decisive_settings(cfg)

    def test_quoted_true_rejected_not_coerced(self):
        cfg = _valid_cfg(); cfg["validators"]["active_enabled"] = "true"
        with self.assertRaises(dc.DecisiveConfigError):
            dc.assert_decisive_settings(cfg)

    def test_burst_below_five_rejected(self):
        cfg = _valid_cfg(); cfg["validators"]["max_burst_size"] = 4
        with self.assertRaises(dc.DecisiveConfigError):
            dc.assert_decisive_settings(cfg)

    def test_missing_seed_rejected(self):
        cfg = _valid_cfg(); cfg["ollama"] = {}
        with self.assertRaises(dc.DecisiveConfigError):
            dc.assert_decisive_settings(cfg)

    def test_nonzero_temperature_rejected(self):
        cfg = _valid_cfg(); cfg["coordinator"]["temperature"] = 0.2
        with self.assertRaises(dc.DecisiveConfigError):
            dc.assert_decisive_settings(cfg)

    def test_placeholder_scope_rejected(self):
        cfg = _valid_cfg(); cfg["server"]["allowed_hosts"] = [dc.SCOPE_PLACEHOLDER]
        with self.assertRaises(dc.DecisiveConfigError):
            dc.assert_decisive_settings(cfg)

    def test_empty_scope_rejected(self):
        cfg = _valid_cfg(); cfg["server"]["allowed_hosts"] = []
        with self.assertRaises(dc.DecisiveConfigError):
            dc.assert_decisive_settings(cfg)


if __name__ == "__main__":
    unittest.main()
