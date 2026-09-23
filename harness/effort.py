from __future__ import annotations
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class BudgetMode(str, Enum):
    """
    Operator-selected, not inferred: this project has no way to know
    whether a given Ollama model is running on the analyst's own hardware
    (today's only integrated backend -- see config.yaml, everything is
    local Ollama) or a metered/paid backend a future session might add.
    The distinction that matters is cost-of-overspend, and only the
    operator knows that for their deployment.
    """
    SOFT = "soft"  # warn when the budget is spent; require explicit confirmation to keep going past it
    HARD = "hard"  # stop dispatching new calls once the budget is spent, no silent overspend


class CallKind(str, Enum):
    ROUTING = "routing"
    AGENT_DISPATCH = "agent_dispatch"
    CRITIQUE = "critique"
    VALIDATION_RETRY = "validation_retry"
    ESCALATION = "escalation"
    PAYLOAD_LLM_FALLBACK = "payload_llm_fallback"
    REDISCOVERY = "rediscovery"


# Rough priors, used ONLY until at least one real call of a given kind has
# been recorded (see EffortLedger.average_tokens). Derived from this
# project's own actual prompt shapes (base_agent._COMMON_RULES + a
# specialty prompt for AGENT_DISPATCH; the routing/critique system prompts
# in orchestrator.py) plus a typical captured-exchange body size -- not
# measured, and explicitly labeled as not measured everywhere they're used.
_DEFAULT_TOKEN_ESTIMATE: dict[CallKind, int] = {
    CallKind.ROUTING: 900,
    CallKind.AGENT_DISPATCH: 1600,
    CallKind.CRITIQUE: 1400,
    CallKind.VALIDATION_RETRY: 1200,
    CallKind.ESCALATION: 1800,
    CallKind.PAYLOAD_LLM_FALLBACK: 1000,
    CallKind.REDISCOVERY: 1500,
}


@dataclass
class CallRecord:
    kind: CallKind
    model: str
    prompt_tokens: int
    completion_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass
class EffortLedger:
    """
    Accumulates REAL token usage. Ollama's /api/chat response includes
    prompt_eval_count and eval_count (input/output token counts) alongside
    the message body -- verified against Ollama's own API behavior, not
    assumed; see ollama_client.OllamaClient.chat_json_metered, which is
    the only place these numbers should originate. Every number in this
    ledger traces back to an actual API response field, never a guess --
    the guesses live in _DEFAULT_TOKEN_ESTIMATE and are only used before
    any real call of that kind exists.
    """
    records: list[CallRecord] = field(default_factory=list)

    def record(self, kind: CallKind, model: str, prompt_tokens: int, completion_tokens: int) -> None:
        self.records.append(CallRecord(kind, model, prompt_tokens, completion_tokens))

    @property
    def total_tokens(self) -> int:
        return sum(r.total_tokens for r in self.records)

    def average_tokens(self, kind: CallKind) -> float:
        """Real observed average for `kind` if any calls of that kind have
        happened yet, else the labeled-as-unmeasured prior."""
        matching = [r.total_tokens for r in self.records if r.kind == kind]
        if matching:
            return sum(matching) / len(matching)
        return float(_DEFAULT_TOKEN_ESTIMATE[kind])

    def has_real_data_for(self, kind: CallKind) -> bool:
        return any(r.kind == kind for r in self.records)

    def breakdown(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.records:
            out[r.kind.value] = out.get(r.kind.value, 0) + r.total_tokens
        return out


@dataclass
class EffortBudget:
    """
    Gates further spend. `total_tokens=None` means "track but never
    block" (still useful for visibility even with no cap set), and
    `max_duration_s=None` is the same no-op default for wall-clock: with
    both left unset this class behaves exactly as it did before the
    duration dimension was added.
    """
    mode: BudgetMode
    total_tokens: int | None = None
    max_duration_s: int | None = None
    ledger: EffortLedger = field(default_factory=EffortLedger)
    # Injectable monotonic-clock seam so tests can drive elapsed time
    # deterministically (a fake incrementing counter) instead of relying
    # on real sleeps. Defaults to the real clock in production.
    clock: Callable[[], float] = field(default=time.monotonic, repr=False)
    _overspend_confirmed: bool = field(default=False, repr=False)
    # Set on the FIRST call to record(), not at construction, so an
    # unused budget with max_duration_s set never trips just from time
    # passing before any work was dispatched.
    _deadline: float | None = field(default=None, repr=False)

    @property
    def spent(self) -> int:
        return self.ledger.total_tokens

    @property
    def remaining(self) -> int | None:
        if self.total_tokens is None:
            return None
        return max(0, self.total_tokens - self.spent)

    def exhausted(self) -> bool:
        """Token-only, deliberately -- duration is folded into `allow()`
        separately so this stays a pure token predicate."""
        return self.total_tokens is not None and self.spent >= self.total_tokens

    def _deadline_passed(self) -> bool:
        if self.max_duration_s is None or self._deadline is None:
            return False
        return self.clock() >= self._deadline

    def allow(self) -> tuple[bool, str]:
        """
        Call before spending more (i.e. before dispatching another LLM
        call). Returns (allowed, reason) -- reason is always populated
        when allowed=False, and populated with a softer note when
        allowed=True but over budget under operator confirmation, so a
        caller can log/display it either way rather than silently
        proceeding.

        Folds in both token exhaustion (`exhausted()`) and the duration
        deadline (`_deadline_passed()`), reusing the same SOFT/HARD
        semantics for both: HARD stops dispatch outright and cannot be
        talked past; SOFT blocks until `confirm_overspend()` is called,
        after which it allows further spend regardless of which limit
        (token or duration) triggered it.
        """
        token_exhausted = self.exhausted()
        duration_passed = self._deadline_passed()
        if not token_exhausted and not duration_passed:
            return True, ""
        if token_exhausted:
            limit_desc = f"({self.spent}/{self.total_tokens} tokens)"
        else:
            limit_desc = f"(duration limit {self.max_duration_s}s reached)"
        if self.mode == BudgetMode.HARD:
            return False, (
                f"effort budget exhausted {limit_desc} in hard mode -- "
                f"dispatch stopped. Raise the budget or switch to soft mode to continue."
            )
        if self._overspend_confirmed:
            return True, f"over budget {limit_desc} -- continuing on operator confirmation"
        return False, (
            f"effort budget exhausted {limit_desc} in soft mode -- "
            f"awaiting operator confirmation to continue past it (see confirm_overspend)"
        )

    def confirm_overspend(self) -> None:
        """Soft mode only, in practice -- hard mode's `allow()` never
        checks this flag, by design: hard mode cannot be talked past.
        Applies to either limit (token or duration)."""
        self._overspend_confirmed = True

    def record(self, kind: CallKind, model: str, prompt_tokens: int, completion_tokens: int) -> None:
        if self.max_duration_s is not None and self._deadline is None:
            self._deadline = self.clock() + self.max_duration_s
        self.ledger.record(kind, model, prompt_tokens, completion_tokens)


@dataclass
class UrlEstimateInput:
    url: str
    # 0.0-1.0 triage/risk score if the URL has already been scored (e.g.
    # Burp's PathScorer tier, or an agent's post-dispatch confidence).
    # None if it's only been spidered, not yet walked through.
    risk_score: float | None = None
    category: str | None = None


def estimate_for_urls(
    urls: list[UrlEstimateInput],
    ledger: EffortLedger,
    *,
    avg_agents_per_dispatch: float = 3.0,
    critique_fraction: float = 0.4,
    retry_rounds_high_risk: int = 3,
    retry_rounds_low_risk: int = 1,
    high_risk_threshold: float = 0.6,
    escalation_rate_among_high_risk: float = 1.0 / 3.0,
) -> dict:
    """
    Projects total token cost for running the full assessment across
    `urls`. This is meant to be called after the analyst has spidered the
    target and sent at least one real exchange through the harness (so
    `ledger` has real per-call-kind averages to calibrate against, per
    EffortLedger.average_tokens) -- calling it before that still works,
    it just falls back to the unmeasured priors and says so explicitly
    via `calibrated_from_real_calls`.

    This is a projection with named, adjustable assumptions, not a
    guarantee -- the breakdown and assumptions are returned alongside the
    total specifically so the operator can see what's driving the number
    (usually agent_dispatch, since it scales with both URL count and
    average agents dispatched per URL) rather than a single opaque
    figure, and can override any assumption that doesn't match their own
    target (e.g. a target where every endpoint plausibly touches 6+
    categories should raise avg_agents_per_dispatch above the default).
    """
    routing_cost = ledger.average_tokens(CallKind.ROUTING)
    agent_cost = ledger.average_tokens(CallKind.AGENT_DISPATCH)
    critique_cost = ledger.average_tokens(CallKind.CRITIQUE)
    retry_cost = ledger.average_tokens(CallKind.VALIDATION_RETRY)
    escalation_cost = ledger.average_tokens(CallKind.ESCALATION)

    n_scored = sum(1 for u in urls if u.risk_score is not None)
    n_high = sum(1 for u in urls if (u.risk_score or 0.0) >= high_risk_threshold)
    n_rest = len(urls) - n_high

    routing_total = len(urls) * routing_cost
    agent_total = len(urls) * avg_agents_per_dispatch * agent_cost
    critique_total = len(urls) * avg_agents_per_dispatch * critique_fraction * critique_cost
    retry_total = n_high * retry_rounds_high_risk * retry_cost + n_rest * retry_rounds_low_risk * retry_cost
    escalation_total = round(n_high * escalation_rate_among_high_risk) * escalation_cost

    grand_total = routing_total + agent_total + critique_total + retry_total + escalation_total

    return {
        "urls_total": len(urls),
        "urls_scored": n_scored,
        "urls_unscored": len(urls) - n_scored,
        "urls_high_risk": n_high,
        "estimated_total_tokens": int(grand_total),
        "calibrated_from_real_calls": bool(ledger.records),
        "breakdown": {
            "routing": int(routing_total),
            "agent_dispatch": int(agent_total),
            "critique": int(critique_total),
            "validation_retries": int(retry_total),
            "escalation": int(escalation_total),
        },
        "assumptions": {
            "avg_agents_per_dispatch": avg_agents_per_dispatch,
            "critique_fraction": critique_fraction,
            "retry_rounds_high_risk": retry_rounds_high_risk,
            "retry_rounds_low_risk": retry_rounds_low_risk,
            "high_risk_threshold": high_risk_threshold,
            "escalation_rate_among_high_risk": escalation_rate_among_high_risk,
        },
    }
