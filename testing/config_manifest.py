"""Regenerable safety-defaults manifest for harness/config.yaml (NC-3, R14 residual).

PR-6 reconciled SAVED benchmark runs against config.yaml (run-vs-config drift). This
module guards a different axis: the shipped config's own safety/profile defaults. It
extracts the safety-critical toggles into a normalized manifest with a content hash,
so a committed snapshot can be regenerated and compared -- a silent flip of a passive
default (active_enabled, allow_mutating_replay, cloud egress, fail-open, quarantine)
fails the drift test rather than shipping unnoticed.

Read-only: never writes config.yaml, never flips a default. `main --write` regenerates
the snapshot deliberately; the default `--check` compares and exits non-zero on drift.

Offline, deterministic, stdlib + pyyaml (already a dependency).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

from reconcile_benchmark import CONFIG_PATH, UNAVAILABLE  # noqa: E402

# The snapshot the drift test compares against. Regenerated only via `--write`.
SNAPSHOT_PATH = _TESTING_DIR / "config_safety_manifest.snapshot.json"

# Safety/profile-relevant config.yaml paths. Each is a toggle that, if flipped,
# changes the tool's safety posture or its local-vs-remote data-egress profile.
# `rationale` documents WHY it is tracked and the safe shipped value it must hold
# (asserted independently of the snapshot in the tests, so regenerating the
# snapshot cannot launder an unsafe flip).
SAFETY_KEYS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("operating_profile",), "profile selector; 'none' = shipped passive defaults"),
    (("validators", "enabled"), "master validator switch"),
    (("validators", "active_enabled"), "PASSIVE DEFAULT: active target probing must ship false"),
    (("validators", "allow_mutating_replay"), "MUTATION GATE: state-changing replay must ship false"),
    (("coordinator", "fail_open_mode"), "fail-open scope for coordinator model failures"),
    (("coordinator", "cloud_primary"), "LOCAL-INFERENCE DEFAULT: cloud primary must ship false"),
    (("coordinator", "cloud_reasoning"), "OFF-HOST EGRESS: cloud reasoning must ship false"),
    (("coordinator", "routing_mode"), "agent routing mode"),
    (("reporting", "quarantine_unverified_leads"), "lead quarantine reporting default"),
    (("reporting", "gate_low_confidence_generic"), "low-confidence generic gating default"),
    (("adaptive_respin", "enabled"), "adaptive respin loop; ships disabled"),
    (("iterative_agent", "enabled"), "iterative agent mode; ships disabled"),
)

# The safe shipped value each key MUST hold. Asserted directly in the tests, so a
# flip is caught even if the snapshot is regenerated to match the flipped config.
REQUIRED_SAFE_VALUES: dict[str, Any] = {
    "validators.active_enabled": False,
    "validators.allow_mutating_replay": False,
    "coordinator.cloud_primary": False,
    "coordinator.cloud_reasoning": False,
    "reporting.quarantine_unverified_leads": False,
}


def _dotted(path: tuple[str, ...]) -> str:
    return ".".join(path)


def _get(raw: dict, path: tuple[str, ...]) -> Any:
    d: Any = raw
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return UNAVAILABLE
        d = d[k]
    return d


def generate_config_manifest(config_path: str | Path = CONFIG_PATH) -> dict[str, Any]:
    """Extract the safety defaults from `config_path` into a normalized manifest
    with a content hash over the (sorted) safety-defaults map. Read-only."""
    import yaml
    raw = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    safety: dict[str, Any] = {}
    rationale: dict[str, str] = {}
    for path, why in SAFETY_KEYS:
        key = _dotted(path)
        safety[key] = _get(raw, path)
        rationale[key] = why
    canonical = json.dumps(safety, sort_keys=True, separators=(",", ":"))
    return {
        "manifest": "config-safety-defaults",
        "config_path": "harness/config.yaml",
        "safety_defaults": safety,
        "rationale": rationale,
        "hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def load_snapshot(path: str | Path = SNAPSHOT_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def diff_against_snapshot(manifest: dict, snapshot: dict) -> list[str]:
    """Human-readable drift lines; empty when the manifests agree on every
    safety default (compared field-by-field, and by hash)."""
    drift: list[str] = []
    cur = manifest.get("safety_defaults", {})
    old = snapshot.get("safety_defaults", {})
    for key in sorted(set(cur) | set(old)):
        if cur.get(key, "<<missing>>") != old.get(key, "<<missing>>"):
            drift.append(f"{key}: snapshot={old.get(key)!r} -> config.yaml={cur.get(key)!r}")
    if not drift and manifest.get("hash") != snapshot.get("hash"):
        drift.append(f"hash: snapshot={snapshot.get('hash')} -> config.yaml={manifest.get('hash')}")
    return drift


def render_manifest(manifest: dict) -> str:
    lines = [f"# Config safety-defaults manifest ({manifest['config_path']})",
             f"hash: {manifest['hash']}", ""]
    for key, val in manifest["safety_defaults"].items():
        lines.append(f"  {key:44s} = {val!r}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Regenerable safety-defaults manifest for harness/config.yaml. "
                    "Read-only; --write updates the committed snapshot deliberately.")
    ap.add_argument("--write", action="store_true",
                    help="regenerate and overwrite the committed snapshot")
    ap.add_argument("--check", action="store_true",
                    help="compare config.yaml against the snapshot; exit 2 on drift (default)")
    args = ap.parse_args(argv)
    manifest = generate_config_manifest()
    if args.write:
        SNAPSHOT_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
        print(f"wrote snapshot: {SNAPSHOT_PATH}")
        return 0
    # default action is --check
    snapshot = load_snapshot()
    drift = diff_against_snapshot(manifest, snapshot)
    print(render_manifest(manifest))
    if drift:
        print("\nDRIFT vs committed snapshot:", file=sys.stderr)
        for d in drift:
            print(f"  {d}", file=sys.stderr)
        return 2
    print("\nno drift: config.yaml safety defaults match the committed snapshot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
