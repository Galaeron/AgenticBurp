"""Config schema validation + reproducibility fingerprint (W-20).

The config is layered: config.yaml (safe committed defaults) with an optional
git-ignored config.local.yaml deep-merged over it (local wins). Nothing
previously validated the MERGED result, so a typo'd key or an incoherent
combination (allow_mutating_replay on while active_enabled is off) failed
silently or, worse, changed live behavior unnoticed.

This module:
  - validate_config(cfg): checks types and the safety-critical CROSS-FIELD
    constraints, returning structured errors/warnings. Non-fatal by default so
    it can be logged at startup without breaking a run; pass strict=True to raise.
  - config_fingerprint(cfg): a stable hash of the effective config, so a run's
    manifest can prove WHICH configuration produced it and a silent config change
    is not mistaken for a target change (reproducibility, W-20 / feeds W-24).
  - redacted_effective_config(cfg): the merged config with secrets removed, for
    an effective-config dump.

The pydantic model is deliberately permissive (extra keys allowed): its job is
to validate the knobs that matter, not to reject every config with a field this
module has not enumerated.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict


_SECRET_KEYS = {"auth_token", "bearer_token", "api_key", "cloud_api_key", "token", "password"}
_VALID_FAIL_OPEN_MODES = {"all", "curated"}


@dataclass
class ConfigValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "errors": list(self.errors), "warnings": list(self.warnings)}


class _ServerSection(BaseModel):
    model_config = ConfigDict(extra="allow")
    allowed_hosts: list[str] = []
    trusted_hosts: list[str] | None = None


class _ConcurrencySection(BaseModel):
    model_config = ConfigDict(extra="allow")
    max_parallel_agents: int = 1
    max_concurrent_validations: int = 6
    early_termination_batch_size: int = 3


class _ValidatorsSection(BaseModel):
    model_config = ConfigDict(extra="allow")
    active_enabled: bool = False
    allow_mutating_replay: bool = False


def parse_validators_flags(cfg: dict) -> dict:
    """R01: the ONE place a raw `validators:` config dict is turned into real
    booleans for safety-critical flags. `validate_config` below type-checks
    the merged config through this same pydantic model, but historically
    only used that check to emit warnings -- callers (SafetyGateConfig.from_dict)
    kept reading the ORIGINAL untyped dict and applying Python's `bool(value)`,
    where `bool("false")` is True (any nonempty string is truthy). A quoted
    `active_enabled: "false"` in config.local.yaml was therefore accepted by
    validation and interpreted as enabled by the gate constructor -- exactly
    backwards from the operator's intent.

    Pydantic's own (non-strict) bool coercion is used here instead: real
    bools pass through, and the same string vocabulary YAML authors actually
    write ("true"/"false"/"yes"/"no"/"on"/"off"/"1"/"0", case-insensitive) is
    accepted -- but anything else (e.g. "disabled", "nope") raises rather
    than silently guessing, so a genuinely ambiguous safety flag fails
    startup/settings-update instead of shipping a wrong default.
    """
    try:
        parsed = _ValidatorsSection.model_validate(cfg or {})
    except Exception as e:
        raise ValueError(f"invalid validators config: {e}") from e
    return {"active_enabled": parsed.active_enabled, "allow_mutating_replay": parsed.allow_mutating_replay}


class _CoordinatorSection(BaseModel):
    model_config = ConfigDict(extra="allow")
    model: str = ""
    cloud_reasoning: bool = False
    cloud_model: str | None = None
    fail_open_mode: str = "all"


class ConfigModel(BaseModel):
    """Permissive typed view of the merged config. Extra keys pass through."""
    model_config = ConfigDict(extra="allow")
    server: _ServerSection = _ServerSection()
    concurrency: _ConcurrencySection = _ConcurrencySection()
    validators: _ValidatorsSection = _ValidatorsSection()
    coordinator: _CoordinatorSection = _CoordinatorSection()


def validate_config(cfg: dict, *, strict: bool = False) -> ConfigValidationResult:
    """Validate the merged config. Returns a result with errors + warnings;
    raises ValueError(strict) only when strict=True and there are errors."""
    errors: list[str] = []
    warnings: list[str] = []

    try:
        model = ConfigModel.model_validate(cfg or {})
    except Exception as e:  # a type error in a known knob
        errors.append(f"config does not match schema: {e}")
        result = ConfigValidationResult(ok=False, errors=errors, warnings=warnings)
        if strict:
            raise ValueError("; ".join(errors))
        return result

    v = model.validators
    c = model.coordinator
    conc = model.concurrency

    # --- safety-critical cross-field constraints ---
    if v.allow_mutating_replay and not v.active_enabled:
        errors.append(
            "validators.allow_mutating_replay is true but validators.active_enabled "
            "is false: mutating replay can never run, and the combination signals a "
            "misconfigured active run (enable active_enabled or clear allow_mutating_replay)."
        )
    if c.cloud_reasoning and not c.cloud_model:
        errors.append(
            "coordinator.cloud_reasoning is true but coordinator.cloud_model is unset: "
            "reasoning would silently fall back to the local model instead of the cloud one."
        )
    if c.fail_open_mode not in _VALID_FAIL_OPEN_MODES:
        errors.append(
            f"coordinator.fail_open_mode {c.fail_open_mode!r} is not one of "
            f"{sorted(_VALID_FAIL_OPEN_MODES)}."
        )

    # --- range constraints ---
    for name, val in (("max_parallel_agents", conc.max_parallel_agents),
                      ("max_concurrent_validations", conc.max_concurrent_validations),
                      ("early_termination_batch_size", conc.early_termination_batch_size)):
        if val < 1:
            errors.append(f"concurrency.{name} must be >= 1 (got {val}).")

    # --- warnings (coherent but worth surfacing) ---
    if v.active_enabled and not model.server.allowed_hosts:
        warnings.append(
            "validators.active_enabled is true but server.allowed_hosts is empty: "
            "live validators will fail closed (W-17), so nothing will be confirmed. "
            "Declare the target scope."
        )

    result = ConfigValidationResult(ok=(not errors), errors=errors, warnings=warnings)
    if strict and errors:
        raise ValueError("; ".join(errors))
    return result


def _redact(obj):
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in _SECRET_KEYS else _redact(val)) for k, val in obj.items()}
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj


def redacted_effective_config(cfg: dict) -> dict:
    """The merged config with secret values removed -- for an effective-config dump."""
    return _redact(cfg or {})


def config_fingerprint(cfg: dict) -> str:
    """Stable sha256 over the redacted effective config -- so a run manifest can
    record exactly which configuration produced it (W-20). Redacted first so the
    fingerprint never depends on (or leaks) a secret value."""
    canonical = json.dumps(redacted_effective_config(cfg), sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# P1-4: named operating profiles.
#
# Presets bundle EXISTING config knobs (routing fail-open mode, concurrency,
# active/mutating validator flags, autonomous discovery, the oracle, model
# size) under one selector so an operator doesn't have to remember which of
# the ~10 behavioral toggles orchestrator.__init__ reads need to move
# together for a given situation. Profiles are defined HERE, in Python, not
# as active flags in the committed config.yaml -- the shipped config.yaml
# adds only ONE new key (`operating_profile`, default "none"), so the
# SafeDefaultGuardTests-covered flags in that committed file are untouched
# no matter which profiles exist here.
#
# Composition rule (documented once, here, because it has to be true in
# exactly one place): a profile knob is applied ONLY when the merged
# config's CURRENT value for that dotted path still equals
# _PROFILE_KNOB_DEFAULTS' shipped baseline for that path. If the operator
# already moved a knob away from that baseline -- typically by setting it in
# the git-ignored config.local.yaml overlay, which deep-merges over
# config.yaml before the orchestrator ever sees the result -- their value is
# treated as an explicit override and wins; the profile never clobbers it.
# This makes "explicit user value wins" checkable without threading
# provenance through the config loader: the shipped config.yaml IS the
# baseline, so "differs from baseline" and "the operator touched this" are
# the same test.
# ---------------------------------------------------------------------------

_MISSING = object()


def _get_dotted(d: dict, dotted_path: str):
    node = d
    for part in dotted_path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _set_dotted(d: dict, dotted_path: str, value) -> None:
    parts = dotted_path.split(".")
    node = d
    for part in parts[:-1]:
        nxt = node.setdefault(part, {})
        if not isinstance(nxt, dict):
            raise ValueError(f"cannot set {dotted_path!r}: {part!r} is not a dict")
        node = nxt
    node[parts[-1]] = value


# Shipped config.yaml's baseline value for every dotted path any profile
# below touches. Used only to detect an explicit operator override (see the
# composition rule above); test_operating_profiles.py separately asserts
# these actually match the committed config.yaml so this table can't drift
# silently.
_PROFILE_KNOB_DEFAULTS: dict[str, object] = {
    "coordinator.fail_open_mode": "all",
    "coordinator.model": "qwen3:8b",
    "concurrency.max_parallel_agents": 1,
    "concurrency.max_concurrent_validations": 6,
    "concurrency.early_termination_batch_size": 3,
    "validators.active_enabled": False,
    "validators.allow_mutating_replay": False,
    "autonomous_discovery.enabled": False,
    "oracle.enabled": False,
    "agent_defaults.model": "qwen3:8b",
    "reporting.quarantine_unverified_leads": False,
}


OPERATING_PROFILES: dict[str, dict[str, object]] = {
    # No active testing at all -- pure per-exchange LLM analysis of captured
    # traffic. Every active/mutating/discovery/oracle knob stays OFF; routing
    # stays at "all" (max recall) since that costs no extra TARGET traffic,
    # only local compute.
    "passive-only": {
        "coordinator.fail_open_mode": "all",
        "concurrency.max_parallel_agents": 1,
        "validators.active_enabled": False,
        "validators.allow_mutating_replay": False,
        "autonomous_discovery.enabled": False,
        "oracle.enabled": False,
    },
    # A single consumer GPU / limited-VRAM machine -- the exact situation
    # documented in config.yaml's ollama.timeout_seconds and
    # concurrency.max_parallel_agents comments. Serialize agent dispatch,
    # route through the curated subset to cut LLM call volume, stay passive.
    "laptop": {
        "coordinator.fail_open_mode": "curated",
        "concurrency.max_parallel_agents": 1,
        "concurrency.max_concurrent_validations": 3,
        "concurrency.early_termination_batch_size": 2,
        "validators.active_enabled": False,
        "validators.allow_mutating_replay": False,
        "autonomous_discovery.enabled": False,
        "oracle.enabled": False,
        "agent_defaults.model": "qwen3:8b",
    },
    # A machine with real headroom (more cores / VRAM): raise concurrency and
    # turn on read-only active validation (still scoped to
    # server.allowed_hosts). Mutating replay and autonomous discovery stay
    # opt-in on top of this -- this profile alone never sends a mutating or
    # discovery request.
    "workstation": {
        "coordinator.fail_open_mode": "all",
        "concurrency.max_parallel_agents": 3,
        "concurrency.max_concurrent_validations": 6,
        "concurrency.early_termination_batch_size": 3,
        "validators.active_enabled": True,
        "validators.allow_mutating_replay": False,
        "autonomous_discovery.enabled": False,
        "oracle.enabled": False,
    },
    # Maximum thoroughness for a deliberate, scoped, budgeted engagement:
    # active validation, mutating replay, autonomous discovery, and the
    # verification oracle all on. Every one of these stays gated by its own
    # EXISTING scope/throttle/budget controls (server.allowed_hosts,
    # global_throttle, effort_budget, retry_budget, safety_gate.py's own
    # ceilings) -- this profile only opts the flags in, it does not loosen
    # any of those other ceilings.
    "deep-assessment": {
        "coordinator.fail_open_mode": "all",
        "concurrency.max_parallel_agents": 3,
        "concurrency.max_concurrent_validations": 6,
        "concurrency.early_termination_batch_size": 5,
        "validators.active_enabled": True,
        "validators.allow_mutating_replay": True,
        "autonomous_discovery.enabled": True,
        "oracle.enabled": True,
    },
    # Deterministic, offline-friendly, for repeatable CI/benchmark runs: no
    # live traffic (active validation off), the curated routing subset for a
    # smaller/more stable dispatched-agent set, single-threaded dispatch for
    # reproducible timing, and unverified leads quarantined out of the main
    # findings list (an eval run cares about the confirmed/candidate split).
    "ci-eval": {
        "coordinator.fail_open_mode": "curated",
        "concurrency.max_parallel_agents": 1,
        "validators.active_enabled": False,
        "validators.allow_mutating_replay": False,
        "autonomous_discovery.enabled": False,
        "oracle.enabled": False,
        "reporting.quarantine_unverified_leads": True,
    },
}


def resolve_operating_profile(config: dict, profile_name: str | None) -> dict:
    """Apply a named operating profile (P1-4) to `config`, returning the
    EFFECTIVE config used to build the orchestrator and its sub-components
    (AgentManager, ValidatorRegistry, Coordinator, AnalysisPipeline all read
    straight from this same dict, not just orchestrator instance attributes,
    so the profile must be applied to the dict itself, before construction).

    `profile_name` unset / None / "" / "none" (case-insensitive) is a no-op:
    returns `config` UNCHANGED (the same object, not even copied), so
    behavior is byte-for-byte identical to today's when no profile is
    selected -- this is the required default (config.yaml ships
    `operating_profile: "none"`).

    Otherwise returns a DEEP COPY of `config` with the named preset's knob
    values applied, except where the operator already set that knob
    explicitly away from its shipped baseline -- see _PROFILE_KNOB_DEFAULTS
    and the module comment above for the composition rule: an explicit
    operator value always wins over the profile.

    Raises ValueError for an unrecognized profile name (fails loudly at
    startup rather than silently ignoring a typo'd profile).
    """
    name = (profile_name or "none").strip().lower()
    if name in ("", "none", "unset", "null", "default"):
        return config
    if name not in OPERATING_PROFILES:
        raise ValueError(
            f"Unknown operating_profile {profile_name!r}; valid values are "
            f"{sorted(OPERATING_PROFILES)} or 'none'."
        )

    preset = OPERATING_PROFILES[name]
    result = copy.deepcopy(config)
    for dotted_path, preset_value in preset.items():
        current = _get_dotted(config, dotted_path)
        baseline = _PROFILE_KNOB_DEFAULTS.get(dotted_path, _MISSING)
        if current is not _MISSING and baseline is not _MISSING and current != baseline:
            # Operator already overrode this knob away from the shipped
            # baseline (e.g. via config.local.yaml) -- their explicit value
            # wins; the profile leaves it alone.
            continue
        _set_dotted(result, dotted_path, preset_value)
    return result
