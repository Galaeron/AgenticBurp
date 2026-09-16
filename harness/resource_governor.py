"""
F5 -- per-vulnerability resource governance.

Two problems this solves, both the tester's, not the model's:

  1. "Spin up N agents on this vulnerability and stop when you find it" -- a
     bounded RETRY loop for a single vulnerability class, distinct from the
     adaptive re-spin loop (which spins a *different* specialist). The tester
     sets the ceiling: how many retries, how many distinct agent runs, and a
     hard per-vulnerability token cap.
  2. "I have a fixed budget; spend it where it matters." With 50 trillion tokens
     you run every vulnerability at full policy and never think about it. With
     2 million you can't -- so the governor PRIORITIZES: it grants the full
     retry policy to the highest-impact vulnerabilities, a reduced policy to the
     next tier, and DEFERS the rest, with written guidance on what it chose and
     what it would take to cover the deferred ones. This is the consumer the
     estimate feature (effort.estimate_for_urls) was built to feed.

Everything here is deterministic and inspectable -- a greedy allocation over an
explicit priority, an explicit round-cost model, and explicit caps. No LLM call:
deciding how to spend the budget is exactly the kind of decision that must be
auditable, not narrated.

This module is pure policy + arithmetic. The actual retry loop that consumes a
VulnBudgetPolicy (re-dispatching an agent, recording real tokens, stopping on a
finding or a cap) lives in the orchestrator, which owns the agents and the
ledger; PerVulnSpend below is the tracker it drives.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness.effort import EffortBudget, EffortLedger

# How much impact each severity carries when the budget can't cover everything.
# Impact is the primary allocation signal: a fixed budget should buy down the
# most serious risk first. These are deliberately spread so one severity tier
# outranks the next even before confidence is considered.
_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.4,
    "low": 0.2,
    "info": 0.05,
}


def severity_weight(severity: str) -> float:
    return _SEVERITY_WEIGHT.get((severity or "").lower(), _SEVERITY_WEIGHT["info"])


@dataclass
class VulnBudgetPolicy:
    """The tester-selectable ceiling for testing ONE vulnerability.

    max_retries is the number of EXTRA re-dispatches after the first pass, so
    max_retries=0 means "one pass, no retries" and max_retries=3 means up to 4
    total passes. max_agents caps distinct agent runs across the whole loop
    (retries included). max_tokens_per_vuln is a hard token ceiling for the one
    vulnerability, independent of the global budget (None = no per-vuln cap,
    only the global budget and the count caps apply)."""
    max_retries: int = 2
    max_agents: int = 3
    max_tokens_per_vuln: int | None = None
    stop_on_found: bool = True
    min_actionable_confidence: float = 0.4

    @classmethod
    def from_dict(cls, cfg: dict | None) -> "VulnBudgetPolicy":
        cfg = cfg or {}
        cap = cfg.get("max_tokens_per_vuln")
        return cls(
            max_retries=int(cfg.get("max_retries", 2)),
            max_agents=int(cfg.get("max_agents", 3)),
            max_tokens_per_vuln=int(cap) if cap else None,
            stop_on_found=bool(cfg.get("stop_on_found", True)),
            min_actionable_confidence=float(cfg.get("min_actionable_confidence", 0.4)),
        )

    def merged_with(self, overrides: dict | None) -> "VulnBudgetPolicy":
        """Return a copy with any provided (non-None) fields overridden -- how a
        single request tightens/loosens the configured default without mutating
        it."""
        if not overrides:
            return self
        merged = {**self.__dict__}
        for k in ("max_retries", "max_agents", "max_tokens_per_vuln",
                  "stop_on_found", "min_actionable_confidence"):
            if overrides.get(k) is not None:
                merged[k] = overrides[k]
        return VulnBudgetPolicy(**merged)

    @property
    def max_passes(self) -> int:
        return self.max_retries + 1


@dataclass
class PerVulnSpend:
    """Tracks spend against a VulnBudgetPolicy for one vulnerability, AND against
    the shared global budget. The retry loop asks can_start_round() before each
    pass and record_round() after; the loop stops the moment either the per-vuln
    policy or the global budget says no."""
    policy: VulnBudgetPolicy
    global_budget: "EffortBudget | None" = None
    granted_tokens: int | None = None   # optional allocator-granted sub-cap (<= per-vuln cap)
    passes_used: int = 0
    agents_used: int = 0
    tokens_used: int = 0
    found: bool = False

    def _token_ceiling(self) -> int | None:
        caps = [c for c in (self.policy.max_tokens_per_vuln, self.granted_tokens) if c is not None]
        return min(caps) if caps else None

    def can_start_round(self, planned_agents: int = 1) -> tuple[bool, str]:
        if self.policy.stop_on_found and self.found:
            return False, "an actionable finding was already produced (stop_on_found)"
        if self.passes_used >= self.policy.max_passes:
            return False, f"retry cap reached ({self.passes_used}/{self.policy.max_passes} passes)"
        if self.agents_used + planned_agents > self.policy.max_agents:
            return False, (f"agent cap reached ({self.agents_used}/{self.policy.max_agents} agent runs; "
                           f"next round would add {planned_agents})")
        ceiling = self._token_ceiling()
        if ceiling is not None and self.tokens_used >= ceiling:
            return False, f"per-vulnerability token cap reached ({self.tokens_used}/{ceiling})"
        if self.global_budget is not None:
            allowed, reason = self.global_budget.allow()
            if not allowed:
                return False, f"global budget: {reason}"
        return True, ""

    def record_round(self, agents_run: int, tokens_spent: int, found: bool = False) -> None:
        self.passes_used += 1
        self.agents_used += agents_run
        self.tokens_used += max(0, tokens_spent)
        if found:
            self.found = True

    def to_dict(self) -> dict:
        return {
            "passes_used": self.passes_used,
            "agents_used": self.agents_used,
            "tokens_used": self.tokens_used,
            "found": self.found,
            "token_ceiling": self._token_ceiling(),
        }


@dataclass
class AllocationCandidate:
    """One vulnerability competing for the shared budget."""
    id: str
    vulnerability_class: str
    url: str
    severity: str = "info"
    confidence: float = 0.0
    # Optional explicit priority; when None it's computed from severity (primary)
    # and confidence (secondary). Callers with their own ranking (a Burp
    # PathScorer tier, an operator hand-ordering) can pass it directly.
    priority: float | None = None

    def effective_priority(self) -> float:
        if self.priority is not None:
            return self.priority
        # Severity dominates; confidence only breaks ties within a tier (scaled
        # small so it never lifts a low-severity item over a higher one).
        return severity_weight(self.severity) + 0.05 * max(0.0, min(1.0, self.confidence))


@dataclass
class Allocation:
    candidate: AllocationCandidate
    action: str                 # "full" | "reduced" | "deferred"
    granted_retries: int
    granted_tokens: int
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.candidate.id,
            "vulnerability_class": self.candidate.vulnerability_class,
            "url": self.candidate.url,
            "severity": self.candidate.severity,
            "priority": round(self.candidate.effective_priority(), 4),
            "action": self.action,
            "granted_retries": self.granted_retries,
            "granted_tokens": self.granted_tokens,
            "note": self.note,
        }


@dataclass
class AllocationPlan:
    allocations: list[Allocation] = field(default_factory=list)
    total_budget: int | None = None
    planned_tokens: int = 0
    round_cost_tokens: int = 0
    guidance: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict:
        c = {"full": 0, "reduced": 0, "deferred": 0}
        for a in self.allocations:
            c[a.action] = c.get(a.action, 0) + 1
        return c

    def to_dict(self) -> dict:
        return {
            "total_budget": self.total_budget,
            "planned_tokens": self.planned_tokens,
            "round_cost_tokens": self.round_cost_tokens,
            "counts": self.counts,
            "allocations": [a.to_dict() for a in self.allocations],
            "guidance": self.guidance,
        }


def estimate_round_cost(
    ledger: "EffortLedger",
    avg_agents_per_round: float = 1.0,
    critique_fraction: float = 0.4,
) -> int:
    """Estimated token cost of ONE retry round (dispatch + its share of
    critique), calibrated from the ledger's real observed averages when
    available (falls back to effort.py's labeled priors otherwise). One round =
    `avg_agents_per_round` agent dispatches plus a `critique_fraction` share of a
    critique pass."""
    from harness.effort import CallKind
    agent = ledger.average_tokens(CallKind.AGENT_DISPATCH)
    critique = ledger.average_tokens(CallKind.CRITIQUE)
    return int(avg_agents_per_round * agent + critique_fraction * critique)


def _full_cost(policy: VulnBudgetPolicy, round_cost: int) -> int:
    """Tokens a single vulnerability costs at full policy, capped by its own
    per-vuln ceiling."""
    cost = policy.max_passes * round_cost
    if policy.max_tokens_per_vuln is not None:
        cost = min(cost, policy.max_tokens_per_vuln)
    return cost


def plan_allocation(
    candidates: list[AllocationCandidate],
    remaining_total_tokens: int | None,
    policy: VulnBudgetPolicy,
    round_cost_tokens: int,
) -> AllocationPlan:
    """Decide how a shared token budget is spread across competing
    vulnerabilities.

    `remaining_total_tokens=None` means "no shared cap" -- every candidate gets
    the full policy and the plan is trivially generous. Otherwise this is a
    greedy allocation in priority order: each candidate is granted the full
    policy while the budget can afford it, a REDUCED policy (as many retries as
    fit, minimum one pass) when only part of the full cost fits, and DEFERRED
    once the budget can't fund even one pass. The plan carries written guidance
    so the operator sees what was funded, what was cut, and what raising the
    budget would buy -- the prioritization is a recommendation to act on, not a
    silent internal choice."""
    round_cost = max(1, int(round_cost_tokens))
    plan = AllocationPlan(total_budget=remaining_total_tokens, round_cost_tokens=round_cost)
    ordered = sorted(candidates, key=lambda c: c.effective_priority(), reverse=True)

    if remaining_total_tokens is None:
        for cand in ordered:
            granted = _full_cost(policy, round_cost)
            plan.allocations.append(Allocation(cand, "full", policy.max_retries, granted,
                                               "no shared budget cap -- full policy"))
            plan.planned_tokens += granted
        plan.guidance.append(
            f"No shared token cap set: all {len(ordered)} vulnerability(ies) run at full policy "
            f"(up to {policy.max_passes} passes each). Set a budget to have the governor prioritize.")
        return plan

    full_cost = _full_cost(policy, round_cost)
    remaining = max(0, int(remaining_total_tokens))
    for cand in ordered:
        if remaining >= full_cost and full_cost > 0:
            plan.allocations.append(Allocation(cand, "full", policy.max_retries, full_cost,
                                               "full policy"))
            plan.planned_tokens += full_cost
            remaining -= full_cost
        elif remaining >= round_cost:
            # Fund as many passes as fit, at least one; retries = passes - 1.
            passes = min(policy.max_passes, remaining // round_cost)
            granted = passes * round_cost
            if policy.max_tokens_per_vuln is not None:
                granted = min(granted, policy.max_tokens_per_vuln)
                passes = max(1, granted // round_cost)
            plan.allocations.append(Allocation(
                cand, "reduced", max(0, passes - 1), granted,
                f"budget only funds {passes} of {policy.max_passes} passes"))
            plan.planned_tokens += granted
            remaining -= granted
        else:
            plan.allocations.append(Allocation(
                cand, "deferred", 0, 0,
                "insufficient remaining budget to fund even one pass"))

    _add_guidance(plan, ordered, policy, full_cost, remaining_total_tokens)
    return plan


def _add_guidance(plan: AllocationPlan, ordered: list[AllocationCandidate],
                  policy: VulnBudgetPolicy, full_cost: int, budget: int) -> None:
    counts = plan.counts
    plan.guidance.append(
        f"Budget {budget} tokens: {counts['full']} vulnerability(ies) funded at full policy, "
        f"{counts['reduced']} reduced, {counts['deferred']} deferred "
        f"(planned spend ~{plan.planned_tokens} tokens).")

    deferred = [a for a in plan.allocations if a.action == "deferred"]
    if deferred:
        names = ", ".join(f"{a.candidate.vulnerability_class}@{a.candidate.url}" for a in deferred[:5])
        more = "" if len(deferred) <= 5 else f" (+{len(deferred) - 5} more)"
        needed = len(deferred) * full_cost
        plan.guidance.append(
            f"Deferred (lowest priority, budget exhausted first): {names}{more}. "
            f"Raising the budget by ~{needed} tokens would fund them at full policy, "
            f"or narrow scope to the {counts['full'] + counts['reduced']} funded item(s).")
    reduced = [a for a in plan.allocations if a.action == "reduced"]
    if reduced:
        plan.guidance.append(
            f"{len(reduced)} vulnerability(ies) got a reduced retry budget; the highest-impact "
            f"items kept their full retry count. Increase max_tokens_per_vuln only if you'd rather "
            f"spend more per vulnerability and cover fewer.")
