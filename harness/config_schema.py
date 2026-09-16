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
