"""W-20: config schema validation + reproducibility fingerprint."""
import unittest
from pathlib import Path

import yaml

from harness import config_schema

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


class ParseValidatorsFlagsTests(unittest.TestCase):
    """R01: this is the seam SafetyGateConfig.from_dict now routes through
    instead of Python's naive bool(value)."""

    def test_quoted_false_string_coerces_to_false(self):
        flags = config_schema.parse_validators_flags({"active_enabled": "false"})
        self.assertFalse(flags["active_enabled"])

    def test_real_bool_true_coerces_to_true(self):
        flags = config_schema.parse_validators_flags({"active_enabled": True})
        self.assertTrue(flags["active_enabled"])

    def test_ambiguous_string_raises(self):
        with self.assertRaises(ValueError):
            config_schema.parse_validators_flags({"allow_mutating_replay": "sort of"})

    def test_missing_keys_default_false(self):
        flags = config_schema.parse_validators_flags({})
        self.assertEqual(flags, {"active_enabled": False, "allow_mutating_replay": False})


class SafeDefaultGuardTests(unittest.TestCase):
    """P0-4: CI guard against the COMMITTED harness/config.yaml drifting to an
    unsafe default. Unlike validate_config above (type/coherence checks, not
    opinionated about which side of a boolean is "safe"), this asserts the
    actual safe-side value for each flag that sends live traffic or widens
    scope by default. It must pass on the clean committed tree and fail the
    moment any one of these is flipped -- a real negative control per flag,
    not just a schema/type check.
    """

    # (dotted path, "is this cfg value the SAFE default?") pairs. Every flag
    # named in IMPROVEMENT_BACKLOG.md's P0-4 acceptance criteria is covered.
    SAFE_CHECKS: list[tuple[str, "callable"]] = [
        ("server.allowed_hosts",
         lambda cfg: cfg.get("server", {}).get("allowed_hosts", []) == []),
        ("validators.active_enabled",
         lambda cfg: cfg.get("validators", {}).get("active_enabled", False) is False),
        ("validators.allow_mutating_replay",
         lambda cfg: cfg.get("validators", {}).get("allow_mutating_replay", False) is False),
        ("autonomous_discovery.enabled",
         lambda cfg: cfg.get("autonomous_discovery", {}).get("enabled", False) is False),
        ("oracle.enabled",
         lambda cfg: cfg.get("oracle", {}).get("enabled", False) is False),
        ("engagement.auto_escalate",
         lambda cfg: cfg.get("engagement", {}).get("auto_escalate", False) is False),
        ("engagement.driver_execute",
         lambda cfg: cfg.get("engagement", {}).get("driver_execute", False) is False),
        ("engagement.feature_crawl",
         lambda cfg: cfg.get("engagement", {}).get("feature_crawl", False) is False),
        ("engagement.coverage_drive_legs",
         lambda cfg: cfg.get("engagement", {}).get("coverage_drive_legs", False) is False),
        ("coordinator.cloud_primary",
         lambda cfg: cfg.get("coordinator", {}).get("cloud_primary", False) is False),
        ("coordinator.cloud_reasoning",
         lambda cfg: cfg.get("coordinator", {}).get("cloud_reasoning", False) is False),
    ]

    # Unsafe replacement value used to flip each flag for the negative control.
    UNSAFE_VALUES = {
        "server.allowed_hosts": ["evil.example.com"],
        "validators.active_enabled": True,
        "validators.allow_mutating_replay": True,
        "autonomous_discovery.enabled": True,
        "oracle.enabled": True,
        "engagement.auto_escalate": True,
        "engagement.driver_execute": True,
        "engagement.feature_crawl": True,
        "engagement.coverage_drive_legs": True,
        "coordinator.cloud_primary": True,
        "coordinator.cloud_reasoning": True,
    }

    @staticmethod
    def _load_committed_config() -> dict:
        with open(_HARNESS / "config.yaml") as f:
            return yaml.safe_load(f) or {}

    @classmethod
    def _violations(cls, cfg: dict) -> list[str]:
        return [name for name, is_safe in cls.SAFE_CHECKS if not is_safe(cfg)]

    def test_committed_config_yaml_has_all_safe_defaults(self):
        """PASSES on the clean committed tree: every safety-critical flag in
        harness/config.yaml, as actually shipped, must be at its safe default."""
        cfg = self._load_committed_config()
        violations = self._violations(cfg)
        self.assertEqual(
            violations, [],
            f"harness/config.yaml has unsafe default(s) for: {violations} -- "
            "committed config must only move toward safer defaults; put live "
            "overrides in the git-ignored harness/config.local.yaml instead.",
        )

    def test_each_flag_flip_is_caught_by_the_guard(self):
        """Negative control: mutate a COPY of the real committed config, one
        flag at a time, to its unsafe value and assert the guard catches it.
        This must genuinely fail (not vacuously pass) for every flag P0-4 lists."""
        for name, _ in self.SAFE_CHECKS:
            with self.subTest(flag=name):
                cfg = self._load_committed_config()
                section, key = name.split(".")
                cfg.setdefault(section, {})[key] = self.UNSAFE_VALUES[name]
                violations = self._violations(cfg)
                self.assertIn(
                    name, violations,
                    f"flipping {name} to an unsafe value was not caught by the guard",
                )


if __name__ == "__main__":
    unittest.main()
