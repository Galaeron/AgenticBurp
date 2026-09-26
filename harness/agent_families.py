"""AR-1 (LOOP half): opt-in agent-family routing -- the P2-2 collapse
candidate (ablation variant G).

SHIPS OFF: the committed default is `coordinator.routing_mode: "agents"`
(harness/config.yaml), which is today's full per-agent fan-out and IS the
revert state. This module implements the MECHANISM and its REVERTIBILITY
only -- whether collapsing calls retains recall is an owner-reported
ablation (P2-2), never claimed here.

The collapse lives ENTIRELY in the model-call FAN-OUT
(`AgentManager.run_multiple_agents`), NOT in agent SELECTION --
`_choose_agents`/`dispatch` is untouched by this module and stays
byte-for-byte identical in both routing modes. This file only groups the
EXISTING, already-dispatched agent names into families and, when asked,
composes ONE model call for a family instead of one call per member.

- `DEFAULT_FAMILIES`: a reviewable dict grouping existing agent `name`s
  (harness/agents/*.py) into families. This is a SUBSET/GROUPING of
  existing agents -- no new agent module, no new detection class, no new
  prompt content is introduced anywhere in this file. Every member name
  is verified against the live plugin-discovered agent set by
  `verify_family_membership()` (used by harness/test_agent_families.py),
  not just at authoring time.
- `group_dispatched_agents`: splits one exchange's dispatched agent names
  into (routed families, solo fallback agents) -- a family only exists
  for THIS exchange if at least one of its members was actually
  dispatched; a dispatched agent that belongs to no family still runs as
  its own single call, never silently dropped.
- `compose_family_prompt` / `FamilyRunner`: build one system prompt from
  member agents' EXISTING `specialty_prompt`/`tactical_guide` text under
  the shared `_COMMON_RULES`, issue ONE call through the SAME ollama
  client the member agents already use, and parse the findings.

Confirmation parity (hard constraint): downstream routing
(orchestrator_confirm / validators / planner) keys off
`Finding.vulnerability_class` (canonicalized via `categories.canonicalize`),
NEVER off `AgentReport.agent` -- see categories.py's own module docstring
("CANONICAL_CATEGORIES intentionally matches the specialist agent names
... since that mapping (AgentReport.agent) IS reliable ... Category-derived
logic ... should key off this canonical set, not off raw vulnerability_class
strings" -- i.e. the reliable-agent-name property is used for the coverage
ledger, not for finding dispatch). A family call's `AgentReport.agent` is
labeled `"family:<name>"` for observability; each Finding's own
model-authored `vulnerability_class` is preserved verbatim, so a
family-produced finding reaches the identical downstream dispatch as the
same finding produced by its member agent alone.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness.agents.base_agent import BaseAgent
    from harness.models import AgentReport, HttpExchange

log = logging.getLogger("harness.agent_families")


# Reviewable grouping of the EXISTING specialist agents into ~6 families,
# following the scoper's proposed split (injection / access_control /
# server_side / config_headers / api_logic / recon_supply). Every name here
# was checked against each agent module's own `name = "..."` class attribute
# (harness/agents/*.py) when this file was written; every one of the 36
# currently-registered agents appears in exactly one family below, and any
# agent added later that isn't listed here simply falls back to running its
# own solo call (see `group_dispatched_agents`) -- it is never dropped.
DEFAULT_FAMILIES: dict[str, list[str]] = {
    "injection": ["sqli", "nosql", "command_injection", "ssti", "xss", "xxe"],
    "access_control": ["idor", "auth", "csrf", "oauth", "jwt", "race_condition"],
    "server_side": ["ssrf", "deserialization", "http_request_smuggling",
                     "web_cache_poisoning", "open_redirect", "websocket"],
    "config_headers": ["cors", "csp", "header_injection", "misconfig",
                        "info_disclosure", "crypto"],
    "api_logic": ["api_security", "graphql", "business_logic",
                  "business_logic_enhanced", "rate_limit", "ai_security"],
    "recon_supply": ["recon", "subdomain_takeover", "supply_chain",
                      "anomaly", "ai_llm", "file_upload"],
}


def verify_family_membership() -> list[str]:
    """Return a list of problems (empty if none): any `DEFAULT_FAMILIES`
    member name that isn't a currently plugin-discovered agent name. Lets a
    test assert the mapping hasn't drifted from the real agent registry,
    rather than trusting the authoring-time comment above."""
    try:
        from harness.agents.plugin import get_plugin_system
        registered = set(get_plugin_system().list_agents())
    except Exception as exc:  # pragma: no cover - discovery failure is its own problem
        return [f"could not discover registered agents: {exc}"]
    problems = []
    for family, members in DEFAULT_FAMILIES.items():
        for name in members:
            if name not in registered:
                problems.append(f"family {family!r} member {name!r} is not a registered agent")
    return problems


def agent_to_family(families: dict[str, list[str]] | None = None) -> dict[str, str]:
    """Reverse index: agent name -> family name, built fresh each call from
    `families` (defaults to `DEFAULT_FAMILIES`) so a test can pass its own
    mapping without monkeypatching module state."""
    src = DEFAULT_FAMILIES if families is None else families
    out: dict[str, str] = {}
    for family, members in src.items():
        for name in members:
            out[name] = family
    return out


def group_dispatched_agents(
    agent_names: list[str], families: dict[str, list[str]] | None = None,
) -> tuple[dict[str, list[str]], list[str]]:
    """Split one exchange's dispatched `agent_names` into
    (routed_families, solo_agents).

    routed_families: family name -> the subset of its members that are
    actually present in `agent_names` -- a family absent from the dispatch
    never appears here, so a zero-member family costs zero calls.
    solo_agents: dispatched agents that belong to no family (fallback --
    still run as their own single call).

    Order within each family list, and within `solo_agents`, follows
    `agent_names`' own order. This function only classifies; it does not
    dedupe or otherwise alter `agent_names`.
    """
    a2f = agent_to_family(families)
    routed_families: dict[str, list[str]] = {}
    solo_agents: list[str] = []
    for name in agent_names:
        family = a2f.get(name)
        if family is None:
            solo_agents.append(name)
        else:
            routed_families.setdefault(family, []).append(name)
    return routed_families, solo_agents


def compose_family_prompt(members: list["BaseAgent"]) -> str:
    """One system prompt covering every agent in `members`, built ONLY from
    each member's own EXISTING `specialty_prompt`/`tactical_guide` under the
    shared `_COMMON_RULES` -- no new specialty text is authored here. The
    only addition is a short routing instruction telling the model to keep
    each finding's `vulnerability_class` specific to the sub-specialty it
    actually belongs to, which is what preserves confirmation parity."""
    from harness.agents.base_agent import _COMMON_RULES

    parts = [
        _COMMON_RULES,
        "\n\nYou are covering MULTIPLE specialties in this single call. "
        "For EACH finding, set vulnerability_class to the SPECIFIC "
        "sub-specialty it belongs to (e.g. \"sqli\", \"xss\"), exactly as "
        "that specialty's own instructions below would have you name it -- "
        "never a combined or family-level label. Consider every specialty "
        "listed below independently; report findings across all of them, "
        "not just the first.",
    ]
    for member in members:
        parts.append(f"\n\n--- Specialty: {member.name} ---\n" + member.specialty_prompt)
        if member.tactical_guide:
            parts.append(
                f"\n\nTactical guide for {member.name} "
                "(concrete steps to try on THIS exchange):\n" + member.tactical_guide
            )
    return "".join(parts)


class FamilyRunner:
    """Issues ONE composed model call for a routed family's dispatched
    `members` and returns ONE `AgentReport`, preserving each finding's own
    model-authored `vulnerability_class` verbatim (confirmation parity).

    Uses the SAME ollama client / model / temperature as the family's member
    agents -- `members[0]` is the "primary" whose `.ollama`/`.model`/
    `.temperature` drive the call, since one model call can only target one
    model. `AgentManager._create_agent` applies `agent_defaults` uniformly
    per agent, so members of one family share the same model/temperature/
    client in the shipped config; this is documented, not hidden, in case an
    operator later gives one family member a distinct override.
    """

    def __init__(self, family_name: str, members: list["BaseAgent"]):
        if not members:
            raise ValueError(f"FamilyRunner for {family_name!r} needs at least one member")
        self.family_name = family_name
        self.members = members
        self._primary = members[0]

    def _system_prompt(self) -> str:
        return compose_family_prompt(self.members)

    async def run(self, exchange: "HttpExchange", max_body_chars: int,
                  prior_context: str = "", effort_budget=None) -> "AgentReport":
        from harness.models import AgentReport, Finding, ComponentCandidate, sanitize_agent_finding
        from harness.ollama_client import OllamaError

        agent = self._primary
        label = f"family:{self.family_name}"
        try:
            user_prompt = agent._user_prompt(exchange, max_body_chars, prior_context)
            if effort_budget is not None:
                result = await agent.ollama.chat_json_metered(
                    model=agent.model,
                    system_prompt=self._system_prompt(),
                    user_prompt=user_prompt,
                    temperature=agent.temperature,
                )
                from harness.effort import CallKind
                effort_budget.record(CallKind.AGENT_DISPATCH, agent.model,
                                      result.prompt_tokens, result.completion_tokens)
                parsed = result.data
            else:
                parsed = await agent.ollama.chat_json(
                    model=agent.model,
                    system_prompt=self._system_prompt(),
                    user_prompt=user_prompt,
                    temperature=agent.temperature,
                )
            raw_findings = parsed.get("findings", [])
            # W-7/W-24/R02, same as BaseAgent.run: strip harness-owned
            # authority fields from untrusted model output before it
            # becomes a Finding. vulnerability_class itself is preserved
            # verbatim -- this only removes fields like confirmed/proof_id.
            findings = [Finding(**sanitize_agent_finding(f)) for f in raw_findings]
            self._emit_hypotheses(findings)
            raw_components = parsed.get("components", [])
            components = [ComponentCandidate(**c) for c in raw_components]
            return AgentReport(agent=label, model=agent.model,
                                findings=findings, components=components)
        except OllamaError as e:
            return AgentReport(agent=label, model=agent.model, findings=[], raw_error=str(e))
        except Exception as e:  # malformed model output, schema mismatch, etc.
            return AgentReport(
                agent=label, model=agent.model, findings=[],
                raw_error=f"Family call failed to parse model output: {e}",
            )

    def _emit_hypotheses(self, findings: list) -> None:
        """Same instrumentation-only HYPOTHESIS event as
        BaseAgent._emit_hypotheses, attributed to the family label instead
        of a single agent name. Never changes a finding's confidence,
        severity, or vulnerability_class."""
        if not findings:
            return
        try:
            from harness import evidence, evidence_ledger
            label = f"family:{self.family_name}"
            for idx, finding in enumerate(findings):
                if not finding.finding_id:
                    finding.finding_id = evidence._short(
                        label, idx, finding.vulnerability_class, finding.summary,
                        finding.evidence, finding.suggested_test, finding.basis)
                evidence_ledger.emit(
                    evidence_ledger.EventType.HYPOTHESIS, finding.finding_id,
                    f"{label}: {finding.vulnerability_class} -- {finding.summary}"[:500],
                    data={
                        "vulnerability_class": finding.vulnerability_class,
                        "confidence": finding.confidence,
                        "severity": finding.severity,
                        "basis": finding.basis,
                        "evidence": (finding.evidence or "")[:1000],
                    },
                    provenance=evidence_ledger.Provenance.capture(
                        model=self._primary.model, prompt_version=label),
                )
        except Exception:  # evidence-ledger bookkeeping must never break a real finding
            pass
