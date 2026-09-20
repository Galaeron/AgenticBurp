"""P1-4: named operating profiles.

Covers:
  - each named profile resolves to its documented knob values
  - SAFETY: passive-only leaves every active/mutating/discovery/engagement/
    cloud flag OFF, asserted explicitly
  - NEGATIVE CONTROL: with no profile selected (unset/"none"/default),
    resolve_operating_profile is a byte-for-byte no-op
  - the composition rule: an explicit operator override away from the
    shipped baseline wins over the profile's value for that knob
  - the shipped committed config.yaml still passes SafeDefaultGuardTests
    with the new operating_profile key present
  - _PROFILE_KNOB_DEFAULTS actually matches the committed config.yaml, so
    the "is this an explicit override" check can't silently drift
"""
import copy
import unittest
from pathlib import Path

import yaml

from harness import config_schema
from harness.config_schema import (
    OPERATING_PROFILES,
    _PROFILE_KNOB_DEFAULTS,
    _get_dotted,
    resolve_operating_profile,
)
# Imported as a module (not `from ... import SafeDefaultGuardTests`) so pytest's
# unittest collector doesn't pick up and re-run that TestCase a second time
# under this file too -- we only need its _violations() helper here.
from harness import test_config_schema as _test_config_schema

_HARNESS = Path(__file__).resolve().parent


def _load_committed_config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        return yaml.safe_load(f) or {}


class ProfileBaselineMatchesConfigYamlTests(unittest.TestCase):
    """_PROFILE_KNOB_DEFAULTS must actually match the committed config.yaml,
    or "differs from baseline" stops meaning "the operator touched this"."""

    def test_baseline_table_matches_committed_config(self):
        cfg = _load_committed_config()
        for dotted_path, expected in _PROFILE_KNOB_DEFAULTS.items():
            actual = _get_dotted(cfg, dotted_path)
            self.assertEqual(
                actual, expected,
                f"config.yaml's {dotted_path} is {actual!r}, but "
                f"_PROFILE_KNOB_DEFAULTS says {expected!r} -- update one of them.",
            )

    def test_committed_config_ships_profile_unset(self):
        cfg = _load_committed_config()
        self.assertEqual(cfg.get("operating_profile"), "none")


class NegativeControlUnsetProfileTests(unittest.TestCase):
    """With no profile selected, resolution must be a total no-op."""

    def test_missing_key_returns_same_object(self):
        cfg = {"coordinator": {"fail_open_mode": "all"}}
        result = resolve_operating_profile(cfg, None)
        self.assertIs(result, cfg)

    def test_none_string_returns_same_object(self):
        cfg = {"coordinator": {"fail_open_mode": "all"}}
        result = resolve_operating_profile(cfg, "none")
        self.assertIs(result, cfg)

    def test_none_case_insensitive_and_whitespace(self):
        cfg = {"coordinator": {"fail_open_mode": "all"}}
        result = resolve_operating_profile(cfg, "  NoNe  ")
        self.assertIs(result, cfg)

    def test_unset_profile_on_full_committed_config_is_byte_for_byte(self):
        cfg = _load_committed_config()
        before = copy.deepcopy(cfg)
        result = resolve_operating_profile(cfg, cfg.get("operating_profile"))
        self.assertIs(result, cfg)
        self.assertEqual(result, before)

    def test_unknown_profile_name_raises(self):
        with self.assertRaises(ValueError):
            resolve_operating_profile({}, "turbo-nitro-mode")


class NamedProfileResolutionTests(unittest.TestCase):
    """Selecting each named profile against a config at the shipped baseline
    (no explicit overrides) sets exactly its documented knob values."""

    def _base_config(self) -> dict:
        # A config sitting exactly at _PROFILE_KNOB_DEFAULTS' baseline, so no
        # knob in it counts as an "explicit override" -- isolates this test
        # to "does the profile apply its own values."
        return {
            "coordinator": {"fail_open_mode": "all", "model": "qwen3:8b"},
            "concurrency": {
                "max_parallel_agents": 1,
                "max_concurrent_validations": 6,
                "early_termination_batch_size": 3,
            },
            "validators": {"active_enabled": False, "allow_mutating_replay": False},
            "autonomous_discovery": {"enabled": False},
            "oracle": {"enabled": False},
            "agent_defaults": {"model": "qwen3:8b"},
            "reporting": {"quarantine_unverified_leads": False},
        }

    def test_every_documented_profile_name_is_covered(self):
        self.assertEqual(
            set(OPERATING_PROFILES),
            {"passive-only", "laptop", "workstation", "deep-assessment", "ci-eval"},
        )

    def test_each_profile_sets_its_documented_values(self):
        for name, preset in OPERATING_PROFILES.items():
            with self.subTest(profile=name):
                result = resolve_operating_profile(self._base_config(), name)
                for dotted_path, expected in preset.items():
                    self.assertEqual(
                        _get_dotted(result, dotted_path), expected,
                        f"profile {name!r}: {dotted_path} expected {expected!r}",
                    )

    def test_profile_selection_is_case_insensitive(self):
        result = resolve_operating_profile(self._base_config(), "Laptop")
        self.assertEqual(_get_dotted(result, "concurrency.max_parallel_agents"), 1)

    def test_profile_returns_a_copy_not_the_original(self):
        cfg = self._base_config()
        result = resolve_operating_profile(cfg, "workstation")
        self.assertIsNot(result, cfg)
        # original untouched
        self.assertFalse(cfg["validators"]["active_enabled"])
        self.assertTrue(result["validators"]["active_enabled"])


class PassiveOnlySafetyTests(unittest.TestCase):
    """SAFETY (mandatory per backlog acceptance criteria): passive-only
    leaves every active/mutating/discovery/engagement/cloud flag OFF."""

    def test_passive_only_leaves_every_dangerous_flag_off(self):
        base = {
            "coordinator": {
                "fail_open_mode": "all", "model": "qwen3:8b",
                "cloud_primary": False, "cloud_reasoning": False,
            },
            "concurrency": {
                "max_parallel_agents": 1,
                "max_concurrent_validations": 6,
                "early_termination_batch_size": 3,
            },
            "validators": {"active_enabled": False, "allow_mutating_replay": False},
            "autonomous_discovery": {"enabled": False},
            "oracle": {"enabled": False},
            "engagement": {
                "auto_escalate": False, "driver_execute": False,
                "feature_crawl": False, "coverage_drive_legs": False,
            },
            "agent_defaults": {"model": "qwen3:8b"},
        }
        result = resolve_operating_profile(base, "passive-only")

        self.assertFalse(_get_dotted(result, "validators.active_enabled"))
        self.assertFalse(_get_dotted(result, "validators.allow_mutating_replay"))
        self.assertFalse(_get_dotted(result, "autonomous_discovery.enabled"))
        self.assertFalse(_get_dotted(result, "oracle.enabled"))
        # passive-only never touches these -- confirm they simply pass
        # through unchanged from the (already-off) base, not silently on.
        self.assertFalse(_get_dotted(result, "engagement.auto_escalate"))
        self.assertFalse(_get_dotted(result, "engagement.driver_execute"))
        self.assertFalse(_get_dotted(result, "engagement.feature_crawl"))
        self.assertFalse(_get_dotted(result, "engagement.coverage_drive_legs"))
        self.assertFalse(_get_dotted(result, "coordinator.cloud_primary"))
        self.assertFalse(_get_dotted(result, "coordinator.cloud_reasoning"))

    def test_passive_only_against_committed_config_yaml(self):
        cfg = _load_committed_config()
        result = resolve_operating_profile(cfg, "passive-only")
        for path in (
            "validators.active_enabled",
            "validators.allow_mutating_replay",
            "autonomous_discovery.enabled",
            "oracle.enabled",
            "engagement.auto_escalate",
            "engagement.driver_execute",
            "engagement.feature_crawl",
            "engagement.coverage_drive_legs",
            "coordinator.cloud_primary",
            "coordinator.cloud_reasoning",
        ):
            self.assertFalse(_get_dotted(result, path), f"{path} must be False under passive-only")


class ExplicitOverrideWinsTests(unittest.TestCase):
    """Composition rule: an operator value that already differs from the
    shipped baseline wins over the profile's value for that same knob."""

    def test_explicit_override_survives_profile_application(self):
        cfg = {
            "coordinator": {"fail_open_mode": "all", "model": "qwen3:8b"},
            "concurrency": {
                # Operator explicitly tuned this away from the baseline (1).
                "max_parallel_agents": 2,
                "max_concurrent_validations": 6,
                "early_termination_batch_size": 3,
            },
            "validators": {"active_enabled": False, "allow_mutating_replay": False},
            "autonomous_discovery": {"enabled": False},
            "oracle": {"enabled": False},
            "agent_defaults": {"model": "qwen3:8b"},
        }
        result = resolve_operating_profile(cfg, "laptop")
        # laptop would otherwise set this to 1 -- the operator's 2 wins.
        self.assertEqual(_get_dotted(result, "concurrency.max_parallel_agents"), 2)
        # untouched-by-override knobs still take the profile's value.
        self.assertEqual(_get_dotted(result, "coordinator.fail_open_mode"), "curated")

    def test_knob_at_baseline_value_is_not_treated_as_override(self):
        cfg = {
            "coordinator": {"fail_open_mode": "all", "model": "qwen3:8b"},
            "concurrency": {
                "max_parallel_agents": 1,  # == baseline, not an override
                "max_concurrent_validations": 6,
                "early_termination_batch_size": 3,
            },
            "validators": {"active_enabled": False, "allow_mutating_replay": False},
            "autonomous_discovery": {"enabled": False},
            "oracle": {"enabled": False},
            "agent_defaults": {"model": "qwen3:8b"},
        }
        result = resolve_operating_profile(cfg, "workstation")
        self.assertEqual(_get_dotted(result, "concurrency.max_parallel_agents"), 3)


class SafeDefaultGuardStillPassesTests(unittest.TestCase):
    """The new operating_profile key must not trip P0-4's SafeDefaultGuardTests
    against the committed config.yaml."""

    def test_safe_default_guard_passes_with_new_key_present(self):
        cfg = _load_committed_config()
        self.assertIn("operating_profile", cfg)
        violations = _test_config_schema.SafeDefaultGuardTests._violations(cfg)
        self.assertEqual(violations, [], f"safe-default violations: {violations}")


if __name__ == "__main__":
    unittest.main()
