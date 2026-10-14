"""Authenticated run identity for HTTP evaluation clients; no secret values."""
import copy
import hashlib
import json

from harness.source_identity import capture_source_snapshot


def describe(config, orchestrator, startup_source):
    effective = copy.deepcopy(config)
    effective.setdefault("validators", {})["active_enabled"] = orchestrator.validator_registry.active_enabled
    effective.setdefault("server", {})["allowed_hosts"] = list(orchestrator.allowed_hosts)
    effective.setdefault("ollama", {})["seed"] = orchestrator.ollama.seed
    effective.setdefault("coordinator", {}).update(
        model=orchestrator.coordinator_model, temperature=orchestrator.coordinator.temperature,
        seed=orchestrator.coordinator.seed)
    agent_controls = {
        name: {"enabled": True, "model": agent.model, "temperature": agent.temperature}
        for name, agent in orchestrator.agent_manager.agents.items()}
    effective.setdefault("agents", {})
    for name, settings in effective["agents"].items():
        settings["enabled"] = name in agent_controls
    for name, settings in agent_controls.items():
        effective["agents"].setdefault(name, {}).update(settings)
    digest = hashlib.sha256(json.dumps(effective, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    current = capture_source_snapshot()
    # Return only the nonsecret controls needed to check the requested overlay.
    controls = {
        "server": {"allowed_hosts": effective["server"]["allowed_hosts"]},
        "validators": {key: effective["validators"].get(key) for key in
                       ("active_enabled", "allow_mutating_replay", "max_burst_size")},
        "ollama": {"seed": effective["ollama"]["seed"]},
        "agents": agent_controls,
    }
    for role in ("coordinator", "agent_defaults", "critique"):
        controls[role] = {key: effective.get(role, {}).get(key) for key in ("model", "temperature")}
        controls[role]["provider"] = effective.get(role, {}).get("provider", "ollama")
        controls[role]["seed"] = effective.get(role, {}).get("seed")
    return {
        "schema_version": 1, "config_hash": digest, "controls": controls,
        "harness_commit": startup_source.head, "source": startup_source.to_dict(),
        "source_matches_disk": startup_source.status == current.status == "captured"
                               and startup_source.content_id == current.content_id
                               and startup_source.head == current.head,
        "model_digest": None, "runtime_version": None,
    }
