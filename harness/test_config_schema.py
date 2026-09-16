"""W-20: config schema validation + reproducibility fingerprint."""
import unittest
from pathlib import Path

import yaml

import config_schema

_HARNESS = Path(__file__).resolve().parent


class ConfigValidationTests(unittest.TestCase):
    def test_committed_config_yaml_is_valid(self):
        with open(_HARNESS / "config.yaml") as f:
            cfg = yaml.safe_load(f) or {}
        result = config_schema.validate_config(cfg)
        self.assertTrue(result.ok, f"shipped config.yaml has validation errors: {result.errors}")

    def test_mutating_replay_without_active_is_an_error(self):
        cfg = {"validators": {"active_enabled": False, "allow_mutating_replay": True}}
        result = config_schema.validate_config(cfg)
        self.assertFalse(result.ok)
        self.assertTrue(any("allow_mutating_replay" in e for e in result.errors))

    def test_cloud_reasoning_without_model_is_an_error(self):
        cfg = {"coordinator": {"cloud_reasoning": True, "cloud_model": None}}
        result = config_schema.validate_config(cfg)
        self.assertFalse(result.ok)
        self.assertTrue(any("cloud_model" in e for e in result.errors))

    def test_invalid_fail_open_mode_is_an_error(self):
        cfg = {"coordinator": {"fail_open_mode": "everything"}}
        result = config_schema.validate_config(cfg)
        self.assertFalse(result.ok)
        self.assertTrue(any("fail_open_mode" in e for e in result.errors))

    def test_zero_concurrency_is_an_error(self):
        cfg = {"concurrency": {"max_parallel_agents": 0}}
        result = config_schema.validate_config(cfg)
        self.assertFalse(result.ok)

    def test_active_without_scope_is_a_warning_not_error(self):
        cfg = {"validators": {"active_enabled": True}, "server": {"allowed_hosts": []}}
        result = config_schema.validate_config(cfg)
        self.assertTrue(result.ok)  # coherent, just risky
        self.assertTrue(any("allowed_hosts" in w for w in result.warnings))

    def test_strict_raises_on_error(self):
        cfg = {"coordinator": {"fail_open_mode": "nope"}}
        with self.assertRaises(ValueError):
            config_schema.validate_config(cfg, strict=True)

    def test_type_error_in_known_knob_is_caught(self):
        cfg = {"concurrency": {"max_parallel_agents": "lots"}}
        result = config_schema.validate_config(cfg)
        self.assertFalse(result.ok)


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_is_stable_and_order_independent(self):
        a = {"server": {"allowed_hosts": ["x", "y"]}, "validators": {"active_enabled": False}}
        b = {"validators": {"active_enabled": False}, "server": {"allowed_hosts": ["x", "y"]}}
        self.assertEqual(config_schema.config_fingerprint(a), config_schema.config_fingerprint(b))

    def test_fingerprint_changes_on_change(self):
        a = {"validators": {"active_enabled": False}}
        b = {"validators": {"active_enabled": True}}
        self.assertNotEqual(config_schema.config_fingerprint(a), config_schema.config_fingerprint(b))

    def test_fingerprint_and_dump_redact_secrets(self):
        cfg = {"server": {"auth_token": "SECRET123", "allowed_hosts": ["x"]}}
        dump = config_schema.redacted_effective_config(cfg)
        self.assertEqual(dump["server"]["auth_token"], "***")
        # a secret change must not change the fingerprint (redacted first)
        cfg2 = {"server": {"auth_token": "DIFFERENT", "allowed_hosts": ["x"]}}
        self.assertEqual(config_schema.config_fingerprint(cfg),
                         config_schema.config_fingerprint(cfg2))


if __name__ == "__main__":
    unittest.main()
