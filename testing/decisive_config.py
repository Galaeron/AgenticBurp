"""Phase 1.2 -- load, validate and fingerprint the decisive-run config template.

The decisive crAPI run must use ONE committed config (active mode, mutating
replay, exact target scope, burst >= 5, temperature 0, a fixed seed) and record
that config's hash with the results, so a result can never be quietly attributed
to a different configuration than the one that produced it.

``load_decisive_config(path)`` parses the template (an OVERLAY on
harness/config.yaml -- see testing/configs/crapi_decisive_run.yaml), asserts the
armed knobs are present and the scope placeholder has been replaced, and returns
``(overlay_dict, config_hash)``. ``config_hash(path)`` is the sha256 of the raw
template bytes -- the stable fingerprint recorded with the run (Phase 1.3).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

DEFAULT_TEMPLATE = Path(__file__).resolve().parent / "configs" / "crapi_decisive_run.yaml"
SCOPE_PLACEHOLDER = "SET-EXACT-CRAPI-HOST"
MIN_BURST = 5


class DecisiveConfigError(ValueError):
    """The decisive-run template is missing a required armed setting, or its
    target scope was never filled in -- raised so a misconfigured run fails
    before the first exchange rather than silently testing nothing."""


def config_hash(path=DEFAULT_TEMPLATE) -> str:
    """sha256 of the raw template bytes -- the fingerprint recorded with results."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_decisive_config(path=DEFAULT_TEMPLATE) -> tuple[dict, str]:
    """Parse + validate the template; return ``(overlay_dict, config_hash)``.

    Raises ``DecisiveConfigError`` if any armed setting is missing or wrong, or
    the scope is still the placeholder. Apply the returned overlay on top of the
    base config the same way config.local.yaml is layered.
    """
    raw = Path(path).read_bytes()
    cfg = yaml.safe_load(raw) or {}
    assert_decisive_settings(cfg)
    return cfg, hashlib.sha256(raw).hexdigest()


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def assert_decisive_settings(cfg: dict) -> None:
    """Fail loud if the overlay is not a complete, armed, reproducible decisive
    run. Checks identity (``is True``) and type explicitly so a quoted "true" or
    a stray float can't pass, and so a fixed ``seed: 0`` (a valid seed) is
    accepted while a missing seed is not."""
    v = cfg.get("validators") or {}
    if v.get("active_enabled") is not True:
        raise DecisiveConfigError("validators.active_enabled must be true for the decisive run")
    if v.get("allow_mutating_replay") is not True:
        raise DecisiveConfigError("validators.allow_mutating_replay must be true for the decisive run")
    burst = v.get("max_burst_size")
    if not _is_int(burst) or burst < MIN_BURST:
        raise DecisiveConfigError(f"validators.max_burst_size must be an int >= {MIN_BURST}; got {burst!r}")

    hosts = (cfg.get("server") or {}).get("allowed_hosts") or []
    if not hosts:
        raise DecisiveConfigError("server.allowed_hosts must name the exact crAPI host")
    if SCOPE_PLACEHOLDER in hosts:
        raise DecisiveConfigError(
            f"server.allowed_hosts still has the {SCOPE_PLACEHOLDER!r} placeholder -- "
            "set the exact crAPI host (host only, no port) before the run")

    # Reproducibility controls: a fixed integer seed and temperature 0.
    seed = (cfg.get("ollama") or {}).get("seed")
    if not _is_int(seed):
        raise DecisiveConfigError(f"ollama.seed must be a fixed integer; got {seed!r}")
    temp = (cfg.get("coordinator") or {}).get("temperature")
    if temp != 0:  # 0 == 0.0 in Python, so an int or float zero both pass
        raise DecisiveConfigError(f"coordinator.temperature must be 0; got {temp!r}")
