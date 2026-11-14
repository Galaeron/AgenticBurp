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
    # Held findings bound to an already proven issue (see attach_to_proven_issues):
    # {"finding_id", "attached_to", "proof_id", "case_id"} each.
    attached: list[dict] = field(default_factory=list)

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
            "attached": self.attached,
        }


def attach_to_proven_issues(held: list[Finding], exchange: HttpExchange, rows: list[dict],
                            *, run_id: str = "") -> list[dict]:
    """Bind each held finding that has no proof of its own to the already proven
    finding of the SAME issue (issues.issue_key: host, endpoint family, method,
    class, affected input, boundary), instead of leaving it an unbound duplicate
    beside the confirmed issue (r5: the iterative agent's login SQLi finding).

    A finding that names no input attaches only when the route holds exactly one
    proven issue of its class -- never a choice among several (an unknown input is
    not a wildcard, R04). The proven row must be confirmed, carry a resolved proof
    of this run (`run_id`, when known), and not be tool-reported. The binding is
    the harness's own proof, never the model's claim: the finding takes that row's
    proof/case pointers, input coordinates and class label, so the store records it
    as a sighting of that issue. A finding with no match, or with its own proof,
    is left exactly as it is. Mutates `held`; returns one record per binding."""
    from harness import issues
    from harness.evidence import is_tool_reported
    proven = [r for r in rows
              if r.get("confirmed") and r.get("proof_id") and r.get("case_id")
              and r.get("proof_status", "resolved") == "resolved" and not is_tool_reported(r)
              and not (r.get("vulnerability_class") or "").startswith("potential-attack-chain:")
              and (not run_id or not r.get("run_id") or r.get("run_id") == run_id)]

    def _route(d: dict) -> tuple:
        return (issues._host_of(d.get("url") or ""), issues.normalize_path(d.get("url") or ""),
                (d.get("method") or "").upper(), issues.issue_class(d.get("vulnerability_class") or ""))

    bound: list[dict] = []
    for f in held:
        if f.confirmed or f.proof_id or f.case_id:
            continue
        d = dict(f.model_dump(), url=exchange.url, method=(exchange.method or "").upper())
        key = issues.issue_key(d, recorded_policy=False)
        # The proof must be of THIS route: a host-wide or dependency class drops the
        # route from issue_key, and a header missing on one route is not proven on
        # another by that route's proof. recorded_policy=False: the key before the
        # report grouped header policies by their recorded value, so binding is unchanged.
        on_route = [r for r in proven if _route(r) == _route(d)]
        same = [r for r in on_route if issues.issue_key(r, recorded_policy=False) == key]
        if not same and not issues._affected_input(d):
            if len({issues.issue_key(r, recorded_policy=False) for r in on_route}) == 1:
                same = on_route
        if not same:
            continue
        e = same[0]
        f.parameter_location = f.parameter_location or e.get("parameter_location") or ""
        f.parameter_name = f.parameter_name or e.get("parameter_name") or ""
        f.vulnerability_class = e.get("vulnerability_class") or f.vulnerability_class
        f.proof_id, f.case_id = e["proof_id"], e["case_id"]
        f.confirmed = True
        f.confirmed_by_leg = e.get("validator") or f.confirmed_by_leg
        f.review_verdict = "validator-confirmed"
        target = e.get("finding_id") or e.get("fingerprint") or ""
        f.review_note = ((f.review_note + " ") if f.review_note else "") + (
            f"Attached to the proven issue of finding {target} (proof {e['proof_id']}).")
        bound.append({"finding_id": f.finding_id, "attached_to": target,
                      "proof_id": e["proof_id"], "case_id": e["case_id"]})
    return bound


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
    review=None,
) -> IntegrationOutcome:
    """Consume an iterative agent's result: hold its findings, build validation
    plans, remember them, then combine + pivot over the host's history.

    `persist=False` runs the whole pipeline WITHOUT writing to the store (build
    plans, compute chains/pivots against whatever history already exists) -- a
    dry run for preview or testing. `model` labels the remembered findings'
    provenance.

    `review`, an async `(findings, plans)` callable, runs after the plans are
    persisted and before the findings are: the orchestrator dispatches the plans
    to its validators and gates the results there, so a remembered finding
    carries its review verdict, case and proof instead of staying a bare
    candidate. A failing review never drops the findings.
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
    # An injection class the model only named in prose ("Authentication Bypass /
    # SQL Injection") gets per-parameter follow-ups, so it is planned too.
    from harness import plan_dispatch
    held.extend(plan_dispatch.injection_followups(held, exchange))
    outcome.validation_plans = planner.plans_for_findings(exchange, held)

    # 3. REMEMBER -- persist into the host's accumulated history.
    if persist:
        # Only the plans whose stored row is THIS capture's are reviewed: a plan id
        # another capture of the request (differing only in a cache-buster
        # parameter) already stored is that capture's row, and dispatching it here
        # would bind this capture's results to it (store.persist_test_plans).
        own_plans = (await asyncio.to_thread(store.persist_test_plans, exchange,
                                             outcome.validation_plans)
                     if outcome.validation_plans else [])
        if review is not None:
            try:
                await review(held, own_plans)
            except Exception as e:  # review is additive -- never lose the findings
                log.warning("pivot_memory: review of %s failed: %s", outcome.agent, e)
        # A held finding the review left unbound, on an issue this run already
        # proved, joins that issue rather than standing beside it as a duplicate.
        try:
            from harness import telemetry
            rows = await asyncio.to_thread(store.all_host_findings, exchange.url)
            outcome.attached = attach_to_proven_issues(
                held, exchange, rows, run_id=telemetry.current_run_id() or "")
        except Exception as e:  # binding is additive -- never lose the findings
            log.warning("pivot_memory: attaching %s to proven issues failed: %s", outcome.agent, e)
        await asyncio.to_thread(
            store.persist_findings, exchange, outcome.agent, held, model, "",
        )
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
