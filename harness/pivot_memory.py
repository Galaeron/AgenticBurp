"""
F2 -- pause -> validate -> remember (pivot / combine).

The iterative agent (F4, iterative_agent.py) ends a run by HANDING BACK a
structured result: the findings it reached plus a free-text handoff note of what
it tried and what still looks promising. On its own that result just evaporates
-- nothing validates it, nothing stores it, and the "still looks promising"
thread is never picked up. This module is the layer that catches it.

For a finding an active agent produces, it does four things, in order:

  1. PAUSE. An iterative agent's findings are hypotheses, not confirmations --
     the harness's standing rule is that LLM reasoning (even reasoning that
     actively probed) never sets confirmed=True. So they are HELD as unconfirmed
     and never shipped as settled.
  2. VALIDATE. Each held finding is turned into an independent-verification
     TestPlan (planner.plans_for_findings) -- the same declarative, safe
     capability the passive pipeline emits, which the Burp/local execution plane
     runs and reports back through /validation-results (where active_verification
     already handles retries). That is what "ask the orchestrator to validate"
     means concretely: produce the plan, don't self-certify.
  3. REMEMBER. The held findings are persisted into the host's accumulated
     finding history, so they are visible to every later analysis of the same
     host -- the substrate pivoting and combination both read from.
  4. COMBINE + PIVOT. Over the host's full (now-updated) history, run the
     rule-based chain detector for retrospective combinations, AND compute
     forward pivot hints (chaining.pivot_hints): rules where this new finding
     supplies one side and the host lacks the other -- concrete "go look for X
     next to complete chain Y" directions, grounded in the same rule table.
     The agent's own handoff note and a methodology-corpus lookup
     (knowledge.retrieve) round out the grounding text.

Deterministic aside from the store I/O; no LLM call of its own. Off the hot
path -- invoked only when an active agent actually produces a result to
integrate.
"""
from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from harness import chaining
from harness import knowledge
from harness import planner
from harness import store
from harness.models import Finding, HttpExchange, TestPlan

if TYPE_CHECKING:
    from harness.iterative_agent import IterativeResult

log = logging.getLogger("harness.pivot_memory")


@dataclass
class IntegrationOutcome:
    agent: str
    stop_reason: str
    held_findings: list[Finding] = field(default_factory=list)     # unconfirmed, remembered
    validation_plans: list[TestPlan] = field(default_factory=list)  # independent-verification requests
    chains: list[Finding] = field(default_factory=list)             # retrospective combinations
    pivot_hints: list[dict] = field(default_factory=list)           # forward chain-completion directions
    grounding: str = ""                                             # handoff note + methodology grounding
    remembered: bool = False

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "stop_reason": self.stop_reason,
            "held_findings": [f.model_dump() for f in self.held_findings],
            "validation_plans": [p.model_dump() for p in self.validation_plans],
            "chains": [f.model_dump() for f in self.chains],
            "pivot_hints": self.pivot_hints,
            "grounding": self.grounding,
            "remembered": self.remembered,
        }


def _grounding(result: "IterativeResult", exchange: HttpExchange) -> str:
    parts: list[str] = []
    note = (getattr(result, "handoff_note", "") or "").strip()
    if note:
        parts.append(f"Handoff: {note}")
    # Specialty is encoded in the agent name as "iterative:<specialty>".
    agent = getattr(result, "agent", "") or ""
    specialty = agent.split(":", 1)[-1] if ":" in agent else agent
    grounded = knowledge.retrieve(specialty, exchange)
    if grounded:
        parts.append("Methodology grounding:\n" + grounded)
    return "\n\n".join(parts)


async def integrate(
    result: "IterativeResult",
    exchange: HttpExchange,
    *,
    persist: bool = True,
    model: str = "",
) -> IntegrationOutcome:
    """Consume an iterative agent's result: hold its findings, build validation
    plans, remember them, then combine + pivot over the host's history.

    `persist=False` runs the whole pipeline WITHOUT writing to the store (build
    plans, compute chains/pivots against whatever history already exists) -- a
    dry run for preview or testing. `model` labels the remembered findings'
    provenance.
    """
    outcome = IntegrationOutcome(
        agent=getattr(result, "agent", "iterative"),
        stop_reason=getattr(result, "stop_reason", ""),
    )

    # 1. PAUSE -- hold as unconfirmed. An active agent's finding is a hypothesis.
    held: list[Finding] = []
    for f in getattr(result, "findings", []) or []:
        if f.confirmed:
            f = f.model_copy(update={"confirmed": False})
        held.append(f)
    outcome.held_findings = held
    outcome.grounding = _grounding(result, exchange)

    if not held:
        # Nothing to validate/remember, but a pivot hint may still be worth
        # returning from the handoff note; there is no finding to pivot ON,
        # so just surface grounding and stop.
        return outcome

    # 2. VALIDATE -- declarative, safe verification plans for the execution plane.
    outcome.validation_plans = planner.plans_for_findings(exchange, held)

    # 3. REMEMBER -- persist into the host's accumulated history.
    if persist:
        await asyncio.to_thread(
            store.persist_findings, exchange, outcome.agent, held, model, "",
        )
        if outcome.validation_plans:
            await asyncio.to_thread(store.persist_test_plans, exchange, outcome.validation_plans)
        outcome.remembered = True

    # 4. COMBINE + PIVOT over the host's (now-updated) full history.
    host_findings = await asyncio.to_thread(store.all_host_findings, exchange.url)
    non_chain = [f for f in host_findings
                 if not f["vulnerability_class"].startswith("potential-attack-chain:")]

    chains: list[Finding] = []
    for f in chaining.detect(non_chain):
        signature = f.vulnerability_class.split(":", 1)[-1]
        already = await asyncio.to_thread(store.is_chain_already_detected, exchange.url, signature)
        if already:
            continue
        if persist:
            await asyncio.to_thread(store.mark_chain_detected, exchange.url, signature)
        chains.append(f)
    if chains and persist:
        await asyncio.to_thread(store.persist_findings, exchange, "chain_detector", chains)
    outcome.chains = chains

    # Forward pivots: what this finding is now "half of". Computed against the
    # host history EXCLUDING the just-remembered findings themselves, so a
    # finding doesn't count as its own chain partner.
    remembered_urls_classes = {(exchange.url, f.vulnerability_class) for f in held}
    prior = [f for f in non_chain
             if (f["url"], f["vulnerability_class"]) not in remembered_urls_classes]
    hints: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for f in held:
        for h in chaining.pivot_hints(f.vulnerability_class, f.summary, prior):
            key = (h["signature"], h["look_for"])
            if key not in seen:
                seen.add(key)
                hints.append(h)
    outcome.pivot_hints = hints

    log.info("pivot_memory: integrated %s -- held=%d plans=%d chains=%d pivots=%d",
             outcome.agent, len(held), len(outcome.validation_plans),
             len(chains), len(hints))
    return outcome
