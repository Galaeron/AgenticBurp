"""Bind an HTTP evaluation to the server's identity, not the client's checkout."""
import hashlib
from pathlib import Path

from testing.decisive_config import assert_decisive_settings, load_decisive_config
from testing.run_provenance import run_provenance


def checked_provenance(server_state, overlay_path):
    overlay, overlay_hash = load_decisive_config(overlay_path)
    if server_state.get("schema_version") != 1 or not server_state.get("source_matches_disk"):
        raise ValueError("server provenance unavailable or source changed; restart the intended server")
    controls = server_state["controls"]
    assert_decisive_settings(controls)
    def matches(requested, actual, path=""):
        for key, value in requested.items():
            if isinstance(value, dict):
                matches(value, actual.get(key, {}), path + key + ".")
            elif actual.get(key) != value:
                # Omitted coordinator seed inherits the client's run seed.
                if key == "seed" and actual.get(key) is None and value == controls["ollama"]["seed"]:
                    continue
                raise ValueError(f"server does not match requested {path}{key}")
    matches(overlay, controls)
    if not server_state.get("config_hash") or not server_state.get("source", {}).get("content_id"):
        raise ValueError("server lacks configuration/source identity")
    stamp = run_provenance(model_name=controls["coordinator"].get("model"),
                           config_hash=server_state["config_hash"], seed=controls["ollama"]["seed"],
                           temperature=0, harness_commit=server_state["harness_commit"],
                           model_digest=server_state.get("model_digest"),
                           runtime_version=server_state.get("runtime_version"))
    return {**stamp, **server_state, "overlay_hash": overlay_hash,
            "verification": "server-reported controls and startup source; model digest/runtime may be unavailable"}


def assert_unchanged(before, after):
    for key in ("config_hash", "harness_commit", "source", "source_matches_disk"):
        if before.get(key) != after.get(key):
            raise ValueError(f"server provenance changed during run: {key}")


def driver_identity(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
