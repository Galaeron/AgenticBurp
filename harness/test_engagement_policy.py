"""P1-6: EngagementPolicy tests.

Covers three things:
1. Enumeration + safe defaults: on the committed harness/config.yaml, every
   active/engagement toggle the policy holds is OFF (negative control,
   mirrors P0-4's SafeDefaultGuardTests style/intent for this new surface).
2. Parity: `EngagementPolicy.from_config` reads the exact same keys, exact
   same defaults, and exact same coercion that Orchestrator.__init__ used
   to apply inline -- for both an all-default config and one with several
   flags/values turned on.
3. Override precedence: the one per-request override in this area (the
   engagement driver's execute gate, orchestrator_chain.py) still ANDs the
   request's `execute` flag with the policy's `engagement_driver_execute`
   at the same point it always did -- a policy-off request can't execute,
   and a policy-on request still won't execute without asking.
"""
import unittest
from pathlib import Path

import yaml

from harness.engagement_policy import EngagementPolicy

_HARNESS = Path(__file__).resolve().parent


def _load_committed_config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        return yaml.safe_load(f) or {}


class EnumerationSafeDefaultsTests(unittest.TestCase):
    """Every active/engagement flag the policy tracks must enumerate to
    False on the clean, committed config.yaml -- explicit, one flag at a
    time, not just an aggregate check."""

    def setUp(self):
        self.policy = EngagementPolicy.from_config(_load_committed_config())

    def test_adaptive_respin_enabled_is_off(self):
        self.assertIs(self.policy.adaptive_respin_enabled, False)

    def test_iterative_agent_enabled_is_off(self):
        self.assertIs(self.policy.iterative_agent_enabled, False)

    def test_engagement_auto_escalate_is_off(self):
        self.assertIs(self.policy.engagement_auto_escalate, False)

    def test_engagement_driver_execute_is_off(self):
        self.assertIs(self.policy.engagement_driver_execute, False)

    def test_engagement_feature_crawl_is_off(self):
        self.assertIs(self.policy.engagement_feature_crawl, False)

    def test_engagement_coverage_drive_is_off(self):
        self.assertIs(self.policy.engagement_coverage_drive, False)

    def test_engagement_coverage_case_drive_is_off(self):
        self.assertIs(self.policy.engagement_coverage_case_drive, False)

    def test_active_flags_all_false(self):
        """Aggregate form of the above: every boolean toggle, enumerated in
        one call, is False -- so a new toggle added later without its own
        explicit test still gets caught here."""
        flags = self.policy.active_flags()
        self.assertTrue(flags, "active_flags() returned nothing to check")
        non_default = {name: value for name, value in flags.items() if value is not False}
        self.assertEqual(
            non_default, {},
            f"committed config.yaml has non-safe-default active/engagement flag(s): {non_default}",
        )

    def test_as_dict_enumerates_every_field(self):
        """as_dict() must expose every declared field (numeric companions
        included), each explicitly, so 'what is actually on' is answerable
        by reading this one dict."""
        d = self.policy.as_dict()
        expected_fields = {
            "adaptive_respin_enabled", "adaptive_respin_max_rounds",
            "adaptive_respin_min_confidence", "iterative_agent_enabled",
            "iterative_agent_max_steps", "engagement_auto_escalate",
            "engagement_driver_execute", "engagement_max_escalations",
            "engagement_feature_crawl", "engagement_coverage_drive",
            "coverage_leg_budget", "engagement_coverage_case_drive",
            "coverage_case_budget",
        }
        self.assertEqual(set(d.keys()), expected_fields)


class ParityTests(unittest.TestCase):
    """Prove from_config's reads match the OLD inline reads Orchestrator.
    __init__ used to do, key-for-key, default-for-default, coercion-for-
    coercion. Each assertion re-implements the old inline expression
    independently (not by importing orchestrator's new thin aliases) so a
    regression in from_config can't hide behind both sides agreeing."""

    def _old_inline_reads(self, config: dict) -> dict:
        """Exact reproduction of the pre-refactor inline reads that lived
        in Orchestrator.__init__, for comparison."""
        respin_cfg = config.get("adaptive_respin", {}) or {}
        iter_cfg = config.get("iterative_agent", {}) or {}
        eng_cfg = config.get("engagement", {}) or {}
        return dict(
            adaptive_respin_enabled=bool(respin_cfg.get("enabled", False)),
            adaptive_respin_max_rounds=int(respin_cfg.get("max_rounds", 1)),
            adaptive_respin_min_confidence=float(
                respin_cfg.get("min_actionable_confidence", 0.4)),
            iterative_agent_enabled=bool(iter_cfg.get("enabled", False)),
            iterative_agent_max_steps=int(iter_cfg.get("max_steps", 250)),
            engagement_auto_escalate=bool(eng_cfg.get("auto_escalate", False)),
            engagement_driver_execute=bool(eng_cfg.get("driver_execute", False)),
            engagement_max_escalations=int(eng_cfg.get("max_auto_escalations", 10)),
            engagement_feature_crawl=bool(eng_cfg.get("feature_crawl", False)),
            engagement_coverage_drive=bool(eng_cfg.get("coverage_drive_legs", False)),
            coverage_leg_budget=int(eng_cfg.get("coverage_leg_budget", 80)),
            engagement_coverage_case_drive=bool(eng_cfg.get("coverage_drive_cases", False)),
            coverage_case_budget=int(eng_cfg.get("coverage_case_budget", 8)),
        )

    def test_parity_on_committed_config(self):
        config = _load_committed_config()
        policy = EngagementPolicy.from_config(config)
        self.assertEqual(policy.as_dict(), self._old_inline_reads(config))

    def test_parity_on_empty_config(self):
        """No keys present at all -- every default must match."""
        config = {}
        policy = EngagementPolicy.from_config(config)
        self.assertEqual(policy.as_dict(), self._old_inline_reads(config))

    def test_parity_with_flags_enabled(self):
        """A representative config with several flags/values turned on --
        proves from_config isn't just matching on the all-False path."""
        config = {
            "adaptive_respin": {
                "enabled": True, "max_rounds": 3, "min_actionable_confidence": 0.6,
            },
            "iterative_agent": {"enabled": True, "max_steps": 40},
            "engagement": {
                "auto_escalate": True,
                "driver_execute": True,
                "max_auto_escalations": 2,
                "feature_crawl": True,
                "coverage_drive_legs": True,
                "coverage_leg_budget": 5,
                "coverage_drive_cases": True,
                "coverage_case_budget": 3,
            },
        }
        policy = EngagementPolicy.from_config(config)
        expected = self._old_inline_reads(config)
        self.assertEqual(policy.as_dict(), expected)
        # Spot-check a few explicitly too, so a future refactor of as_dict()
        # can't silently mask a field-level regression.
        self.assertTrue(policy.adaptive_respin_enabled)
        self.assertEqual(policy.adaptive_respin_max_rounds, 3)
        self.assertTrue(policy.engagement_driver_execute)
        self.assertEqual(policy.coverage_case_budget, 3)

    def test_parity_missing_engagement_section_entirely(self):
        """engagement: (present but empty/None) must behave like the old
        `(config.get("engagement", {}) or {}).get(...)` pattern -- not
        raise, and fall back to defaults."""
        config = {"engagement": None, "adaptive_respin": None, "iterative_agent": None}
        policy = EngagementPolicy.from_config(config)
        self.assertEqual(policy.as_dict(), self._old_inline_reads(config))
        self.assertFalse(policy.engagement_auto_escalate)


class OverridePrecedenceTests(unittest.TestCase):
    """The one per-request override touching this policy's fields: the
    engagement driver's execute gate. orchestrator_chain.py's plan_engagement
    is entered with `execute=` from the /engagement/{host}/run request body
    (server.py), and must AND it with the policy's engagement_driver_execute
    at that same call site -- so a request can ask to execute, but only a
    policy that also has it on will actually do so."""

    def test_driver_execute_gate_source(self):
        import inspect

        from harness import orchestrator_chain

        src = inspect.getsource(orchestrator_chain.ChainMixin.run_engagement)
        self.assertIn(
            "self.engagement_driver_execute", src,
            "run_engagement must still gate execution on the policy's "
            "engagement_driver_execute at the point of use",
        )

    def test_policy_off_means_orchestrator_alias_off(self):
        """The orchestrator's self.engagement_driver_execute (what the gate
        above actually reads) must reflect the policy, so flipping the
        policy off via config keeps the request-time gate closed regardless
        of what a request asks for."""
        from harness.orchestrator import Orchestrator

        config = _load_committed_config()
        policy = EngagementPolicy.from_config(config)
        self.assertFalse(policy.engagement_driver_execute)
        # orchestrator.py assigns: self.engagement_driver_execute =
        # self.engagement_policy.engagement_driver_execute -- verify that
        # wiring directly in source, without constructing a full
        # Orchestrator (which needs a live Ollama/store/config stack).
        import inspect
        init_src = inspect.getsource(Orchestrator.__init__)
        self.assertIn(
            "self.engagement_driver_execute = self.engagement_policy.engagement_driver_execute",
            init_src,
        )


if __name__ == "__main__":
    unittest.main()
