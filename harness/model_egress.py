"""SEC-1: which model slots send prompts off-host, and the run-start refusal.

An Ollama model whose name ends in `-cloud` or `:cloud` runs on Ollama's cloud,
not on this machine, so the sanitised but real exchange content in each prompt
leaves the host. That is refused unless `ollama.allow_cloud_models: true`
(default false in config.yaml). Two layers enforce it:

- `OllamaClient._chat` refuses every call to a cloud model before anything is
  sent, whichever slot or live /settings toggle chose it (the backstop);
- `refuse_cloud_models` checks every configured slot when a run starts, so a run
  with a cloud model in a slot fails before its first model call, with the slots
  named, instead of degrading call by call.

`egress_state` is the plain-data record of the same check, for the run manifest
and the authenticated `/health/details`.
"""
from __future__ import annotations

from harness.ollama_client import (OllamaCloudModelRefusedError, cloud_refusal_reason,
                                   is_cloud_model, parse_allow_cloud_models)

# Sections whose `model` key names an Ollama model a call is sent to.
_MODEL_SECTIONS = ("coordinator", "agent_defaults", "critique", "surface_prioritization",
                   "writeups")


def allow_cloud_models(config: dict | None) -> bool:
    """`ollama.allow_cloud_models`, strictly parsed (unset is false)."""
    return parse_allow_cloud_models(((config or {}).get("ollama") or {}).get("allow_cloud_models"))


def _routed_to_ollama(section: dict) -> bool:
    """A role a config moved to another provider is not sent to Ollama."""
    return str(section.get("provider", "ollama") or "ollama") == "ollama"


def model_slots(config: dict | None, agent_models: dict | None = None) -> list[dict]:
    """Every slot that sends prompts to an Ollama model: [{slot, model}].

    - `<section>.model` for the coordinator, agent defaults, critique, surface
      prioritization and writeups;
    - `coordinator.cloud_model` only while `cloud_primary` (routing) or
      `cloud_reasoning` (reasoning and critique) uses it;
    - `agents.<name>.model` for each agent not disabled;
    - `agent_models`, the models live agents resolved: {agent name: model}, or
      a list of models (the run manifest's model_versions.agents).
    """
    if isinstance(agent_models, (list, tuple, set, frozenset)):
        agent_models = {f"resolved[{i}]": m for i, m in enumerate(sorted(
            m for m in agent_models if isinstance(m, str)))}
    config = config or {}
    slots: list[dict] = []

    def add(slot, model):
        if isinstance(model, str) and model.strip():
            slots.append({"slot": slot, "model": model.strip()})

    for name in _MODEL_SECTIONS:
        section = config.get(name) or {}
        if isinstance(section, dict) and _routed_to_ollama(section):
            add(f"{name}.model", section.get("model"))
    coord = config.get("coordinator") or {}
    if isinstance(coord, dict) and (coord.get("cloud_primary") or coord.get("cloud_reasoning")):
        add("coordinator.cloud_model", coord.get("cloud_model"))
    agents = config.get("agents") or {}
    for name, settings in sorted(agents.items()) if isinstance(agents, dict) else ():
        if isinstance(settings, dict) and settings.get("enabled", True) is not False:
            add(f"agents.{name}.model", settings.get("model"))
    for name, model in sorted((agent_models or {}).items()):
        add(f"agent:{name}", model)
    seen, unique = set(), []
    for row in slots:
        key = (row["slot"], row["model"])
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique


def egress_state(config: dict | None, agent_models: dict | None = None) -> dict:
    """{allow_cloud_models, cloud_slots: [{slot, model}], egress, refused}.

    `egress` is true when a run with this config sends prompts off-host (a
    cloud slot and the opt-in set); `refused` when such a run is refused (a
    cloud slot without the opt-in). An invalid opt-in value counts as unset.
    Remote providers (a role with `provider` other than ollama) are listed under
    `remote_providers`."""
    config = config or {}
    try:
        allowed, invalid = allow_cloud_models(config), False
    except ValueError:
        allowed, invalid = False, True
    cloud = [row for row in model_slots(config, agent_models) if is_cloud_model(row["model"])]
    remote = sorted(name for name in ("coordinator", "critique")
                    if isinstance(config.get(name), dict) and not _routed_to_ollama(config[name]))
    state = {"allow_cloud_models": allowed, "cloud_slots": cloud,
             "egress": bool(cloud) and allowed, "refused": bool(cloud) and not allowed,
             "remote_providers": remote}
    if invalid:
        state["allow_cloud_models_invalid"] = True
    return state


def agent_models_of(agent_manager) -> dict:
    """{agent name: model} for an AgentManager's live agents ({} without one)."""
    agents = getattr(agent_manager, "agents", None) or {}
    return {name: getattr(agent, "model", None) for name, agent in agents.items()
            if isinstance(getattr(agent, "model", None), str)}


def refuse_cloud_models(config: dict | None, agent_models: dict | None = None) -> dict:
    """Raise OllamaCloudModelRefusedError, naming each slot, when a slot holds a
    cloud model and `ollama.allow_cloud_models` is not true. Called at run start,
    before any model call. Returns the egress state otherwise."""
    allow_cloud_models(config)  # an invalid opt-in value raises ValueError here
    state = egress_state(config, agent_models)
    if state["refused"]:
        slots = state["cloud_slots"]
        where = "; ".join(f"{row['slot']}={row['model']}" for row in slots)
        raise OllamaCloudModelRefusedError(
            f"{cloud_refusal_reason(row['model'] for row in slots)} Slots: {where}.",
            slots=slots)
    return state
