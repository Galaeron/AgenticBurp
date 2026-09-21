"""EngagementPolicy -- P1-6: one place to answer "what is actually on".

Orchestrator.__init__ used to scatter ~10 active/engagement toggle reads
(adaptive_respin.*, iterative_agent.*, engagement.*) across ~75 lines,
each with its own inline default/coercion. This module consolidates those
reads into a single dataclass with one `from_config` constructor, so the
full set of "does this process send extra/active traffic" knobs -- and
their values -- is enumerable and testable in one place.

PURELY BEHAVIOR-PRESERVING: `from_config` reads exactly the same config
keys, with exactly the same defaults and coercion (bool()/int()/float())
that `Orchestrator.__init__` used to apply directly. It takes the
ALREADY-RESOLVED config (post `config_schema.resolve_operating_profile`)
as input -- it does not re-resolve operating profiles, and it does not
implement or duplicate any confirmation-tier / scope-policy logic.

Deliberately OUT of scope (left where they already live, to avoid a
second implementation of the same concern):
- `validators.active_enabled` / `validators.allow_mutating_replay` --
  owned by `ValidatorRegistry` / `config_schema.parse_validators_flags`.
- `autonomous_discovery.enabled` -- owned by the autonomous_discovery
  module itself (see orchestrator_detect.py's own comment).
- `coordinator.cloud_primary` / `coordinator.cloud_reasoning` -- owned by
  `Coordinator.__init__` (harness/coordinator.py); the orchestrator only
  ever reads it back via `getattr(self.coordinator, "cloud_primary", ...)`.
- `retry_budget` -- already its own dataclass, `resource_governor.
  VulnBudgetPolicy`, with its own per-request `merged_with` override.
"""
from __future__ import annotations

from dataclasses import dataclass, fields


@dataclass(frozen=True)
class EngagementPolicy:
    """Active/engagement toggles read by Orchestrator.__init__.

    Each field's default and coercion below matches, exactly, the inline
    read it replaces in orchestrator.py (see the field-level comments and
    `from_config`). No field changes its default or gains new authority --
    this is a refactor, not a feature.
    """

    # -- adaptive_respin.* (SESSION_HANDOVER.md §7). DEFAULT OFF, and
    # additionally a no-op unless coordinator.cloud_primary is also on.
    adaptive_respin_enabled: bool = False
    adaptive_respin_max_rounds: int = 1
    adaptive_respin_min_confidence: float = 0.4

    # -- iterative_agent.* (F4 + F2 active agent). DEFAULT OFF.
    iterative_agent_enabled: bool = False
    iterative_agent_max_steps: int = 250

    # -- engagement.* (closed-loop auto-escalation, driver execution,
    # feature crawling, coverage-matrix driving). All DEFAULT OFF --
    # every one of these sends active traffic as a side effect.
    engagement_auto_escalate: bool = False
    engagement_driver_execute: bool = False
    engagement_max_escalations: int = 10
    engagement_feature_crawl: bool = False
    engagement_coverage_drive: bool = False
    coverage_leg_budget: int = 80
    engagement_coverage_case_drive: bool = False
    coverage_case_budget: int = 8

    @classmethod
    def from_config(cls, config: dict) -> "EngagementPolicy":
        """Build the policy from an ALREADY-RESOLVED config dict (i.e. the
        output of `config_schema.resolve_operating_profile`). Callers must
        not pass a raw, unresolved config -- do not re-resolve here."""
        respin_cfg = config.get("adaptive_respin", {}) or {}
        iter_cfg = config.get("iterative_agent", {}) or {}
        eng_cfg = config.get("engagement", {}) or {}

        return cls(
            adaptive_respin_enabled=bool(respin_cfg.get("enabled", False)),
            adaptive_respin_max_rounds=int(respin_cfg.get("max_rounds", 1)),
            adaptive_respin_min_confidence=float(
                respin_cfg.get("min_actionable_confidence", 0.4)
            ),
            iterative_agent_enabled=bool(iter_cfg.get("enabled", False)),
            iterative_agent_max_steps=int(iter_cfg.get("max_steps", 250)),
            engagement_auto_escalate=bool(eng_cfg.get("auto_escalate", False)),
            engagement_driver_execute=bool(eng_cfg.get("driver_execute", False)),
            engagement_max_escalations=int(eng_cfg.get("max_auto_escalations", 10)),
            engagement_feature_crawl=bool(eng_cfg.get("feature_crawl", False)),
            engagement_coverage_drive=bool(eng_cfg.get("coverage_drive_legs", False)),
            coverage_leg_budget=int(eng_cfg.get("coverage_leg_budget", 80)),
            engagement_coverage_case_drive=bool(
                eng_cfg.get("coverage_drive_cases", False)
            ),
            coverage_case_budget=int(eng_cfg.get("coverage_case_budget", 8)),
        )

    def as_dict(self) -> dict:
        """Every field, by name -> value. For tests/inspection: the full
        answer to "what does this policy hold", in one call."""
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def active_flags(self) -> dict:
        """Just the boolean enable/drive toggles (excludes the numeric
        budgets/rounds/thresholds that accompany them). This is the safe-
        defaults negative control surface: every one of these must be
        False on the committed config."""
        return {
            name: value
            for name, value in self.as_dict().items()
            if isinstance(value, bool)
        }
