"""
Retry rounds: spend what is left of an engagement's time budget on the work it left.

The 10-hour Juice Shop run r3 (2026-11-03, job 0574e29a0799) stopped on its own at
T+5 h 52 min of a 9 h 35 min deadline. Every phase ran once and nothing went back:
262 shape-warranted worklist nodes were skipped as budget_exhausted (the 24
precondition legs were spent), 28 of 44 agent probes stopped on a model error, and
the captures whose model review failed were never reviewed again.
`investigation_seconds` bounded the run, but nothing used the time it had left.

With `engagement.retry_rounds.enabled`, the engagement goes round again after the
coverage drive, until `reserve_seconds` before its deadline. Round r multiplies the
worklist budgets (max_nodes, step_budget, max_precondition_legs) and the capture
review limit by `growth ** r`, with step_budget capped at `max_step_budget`. Each
round:

- sweeps the worklist again. A settled node is not probed again: it was confirmed,
  or its agent reached a verdict. A node whose probe raised, or ended `error` or
  `exhausted_steps`, is probed again with the larger step budget. A node an earlier
  budget skipped now gets its turn. Shape-driven legs already attempted are not
  sent again, because they are deterministic.
- reviews again each capture whose model review failed, and any captures the
  earlier review left.

If the Ollama circuit breaker is open before a round, the round first waits for it
to let calls through: up to `breaker_wait_seconds`, and never past the deadline.

The rounds stop:
- at the deadline;
- on cancellation;
- after `max_rounds` (0 means no limit);
- when a round has nothing left to run;
- after `max_idle_rounds` rounds in a row that settle nothing and find nothing
  (0 means never). An idle round is usually a model failure that repeats on every
  call (r3's prompts were cut at Ollama's 4096-token default context).

The coverage matrix is built before these rounds. Their findings go into the state,
the findings and the final chain re-link; the `retry_rounds` result block records
them.

OFF by default, because it sends active traffic. With it off, or with no
`investigation_seconds` (the deadline it fills), the engagement runs as before.
"""
from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass, field

__all__ = ["RETRYABLE_STOPS", "RetryLedger", "RetryRoundsConfig", "is_settled",
           "round_budgets", "run_retry_rounds"]

# Agent stop reasons a larger step budget or a recovered model can change. Any other
# verdict (found, refused, gave_up, no_progress, repeated_duplicates, target_distress,
# budget) is final for the run.
RETRYABLE_STOPS = frozenset({"error", "exhausted_steps"})

_MAX_FACTOR = 1e6  # growth ** round never overflows a budget


@dataclass(frozen=True)
class RetryRoundsConfig:
    enabled: bool = False
    growth: float = 2.0             # budget multiplier per round (>= 1)
    max_rounds: int = 0             # 0: until the deadline
    reserve_seconds: float = 300.0  # left before the deadline for the final passes
    max_step_budget: int = 1024     # ceiling for the escalated per-probe step budget
    breaker_wait_seconds: float = 120.0
    max_idle_rounds: int = 3        # 0: never stop for idleness

    @classmethod
    def from_config(cls, config: dict | None) -> "RetryRoundsConfig":
        raw = ((config or {}).get("engagement", {}) or {}).get("retry_rounds") or {}
        if not isinstance(raw, dict):
            return cls()
        return cls(enabled=bool(raw.get("enabled", False)),
                   growth=max(1.0, float(raw.get("growth", 2.0))),
                   max_rounds=max(0, int(raw.get("max_rounds", 0))),
                   reserve_seconds=max(0.0, float(raw.get("reserve_seconds", 300.0))),
                   max_step_budget=max(1, int(raw.get("max_step_budget", 1024))),
                   breaker_wait_seconds=max(0.0, float(raw.get("breaker_wait_seconds", 120.0))),
                   max_idle_rounds=max(0, int(raw.get("max_idle_rounds", 3))))


def is_settled(outcome: dict) -> bool:
    """Whether a worklist outcome needs no more attempts in this run."""
    if outcome.get("confirmed"):
        return True
    if outcome.get("error"):
        return False
    stop = outcome.get("stop_reason")
    if stop is None:
        # No agent verdict: only the node's legs ran (its agent was over budget),
        # unless it never had an agent hypothesis at all.
        return not outcome.get("specialty")
    return stop not in RETRYABLE_STOPS


def round_budgets(base: dict, cfg: RetryRoundsConfig, round_no: int) -> dict:
    """`base` budgets scaled for `round_no` (1 = the first retry round). A budget of 0
    (that stage turned off) stays 0, and None (no bound) stays None."""
    factor = min(cfg.growth ** round_no, _MAX_FACTOR)

    def scale(value):
        if value is None:
            return None
        value = int(value)
        return int(math.ceil(value * factor)) if value > 0 else 0

    out = {name: scale(value) for name, value in base.items()}
    if "step_budget" in out:
        out["step_budget"] = min(out["step_budget"], max(cfg.max_step_budget, int(base["step_budget"])))
    return out


@dataclass
class RetryLedger:
    """What the engagement's worklist sweeps and capture reviews settled, and what
    they left. `wire` puts it in the worklist kwargs every sweep of the run uses."""
    outcomes: dict = field(default_factory=dict)      # node_key -> latest outcome
    legs_done: set = field(default_factory=set)       # node_keys whose legs were attempted
    review_failed: set = field(default_factory=set)   # capture keys whose model review failed
    capped: set = field(default_factory=set)          # node_keys out of steps at the cap
    step_capped: bool = False                         # the current sweep runs at the cap
    _chained: object = None

    def wire(self, worklist_kwargs: dict) -> dict:
        """`worklist_kwargs` (the E7 journal's, or {}) with this ledger recording."""
        for key, outcome in (worklist_kwargs.get("completed") or {}).items():
            self.outcomes.setdefault(key, outcome)
        self._chained = worklist_kwargs.get("on_outcome")
        return {**worklist_kwargs, "on_outcome": self.record, "legs_done": self.legs_done}

    def record(self, key: str, outcome: dict) -> None:
        self.outcomes[key] = outcome
        if self.step_capped and outcome.get("stop_reason") == "exhausted_steps":
            self.capped.add(key)  # more steps cannot be given; the verdict stands
        if self._chained is not None:
            self._chained(key, outcome)

    def settled(self) -> dict:
        return {key: outcome for key, outcome in self.outcomes.items()
                if key in self.capped or is_settled(outcome)}

    def sweep_kwargs(self) -> dict:
        """investigate_worklist kwargs for a retry sweep: settled nodes are resumed."""
        return {"completed": self.settled(), "on_outcome": self.record,
                "legs_done": self.legs_done}

    def reopen_reviews(self, seen: set) -> int:
        """Take each capture whose model review failed out of `seen`, so it is
        reviewed again. Returns how many."""
        reopened = len(self.review_failed)
        for key in self.review_failed:
            seen.discard(key)
        self.review_failed.clear()
        return reopened


def _breaker_retry_after() -> float:
    from harness.circuit_breaker import get_ollama_circuit_breaker
    return get_ollama_circuit_breaker("ollama").seconds_until_retry()


async def run_retry_rounds(cfg: RetryRoundsConfig, ledger: RetryLedger, *, deadline: float | None,
                           base_budgets: dict, sweep, review, reviewed: set, cancelled=lambda: False,
                           retry_after=None, clock=time.monotonic, sleep=asyncio.sleep) -> dict:
    """Run retry rounds until a stop condition (module docstring). Returns the report.

    `sweep(budgets, deadline) -> (fresh outcomes, worklist summary)` runs one retry
    sweep, with `ledger.sweep_kwargs()`, and returns only the outcomes it did not
    resume. `review(budgets, deadline) -> (captures reviewed, captures with findings)`
    reviews the captures not in `reviewed` (the run's review `seen` set), after the
    ones whose model review failed are taken out of it. `base_budgets` has
    max_nodes, step_budget, max_precondition_legs and max_reviews. `retry_after()`
    gives the seconds until the model can be called again (default: the Ollama
    circuit breaker's)."""
    retry_after = retry_after or _breaker_retry_after
    report: dict = {"enabled": True, "growth": cfg.growth, "reserve_seconds": cfg.reserve_seconds,
                    "rounds": [], "stopped_by": None, "findings": 0, "confirmed": 0,
                    "reviews_with_findings": 0}
    if deadline is None:
        report["stopped_by"] = "no_deadline"
        return report
    stop_at = deadline - cfg.reserve_seconds
    idle = 0
    round_no = 0
    while True:
        if cancelled():
            report["stopped_by"] = "cancelled"
            break
        if cfg.max_rounds and round_no >= cfg.max_rounds:
            report["stopped_by"] = "max_rounds"
            break
        if clock() >= stop_at:
            report["stopped_by"] = "deadline"
            break
        wait = left = min(max(0.0, retry_after()), cfg.breaker_wait_seconds,
                          max(0.0, stop_at - clock()))
        while left > 0 and not cancelled():
            step = min(5.0, left)
            await sleep(step)
            left -= step
        waited = wait - max(0.0, left)
        if cancelled() or clock() >= stop_at:
            continue  # reported by the checks above
        round_no += 1
        started = clock()
        budgets = round_budgets(base_budgets, cfg, round_no)
        ledger.step_capped = budgets["step_budget"] >= cfg.max_step_budget
        fresh, summary = await sweep(budgets, stop_at)
        for outcome in fresh:
            outcome["retry_round"] = round_no
        reopened = ledger.reopen_reviews(reviewed)
        review_count, review_findings = await review(budgets, stop_at)
        by_reason = (summary or {}).get("skipped_by_reason") or {}
        entry = {
            "round": round_no,
            "budgets": budgets,
            "waited_s": round(waited, 3),
            "ran": len(fresh),
            "settled": sum(1 for o in fresh if is_settled(o)),
            "findings": sum(len(o.get("findings_detail") or []) for o in fresh),
            "confirmed": sum(1 for o in fresh for f in o.get("findings_detail") or []
                             if f.get("confirmed")),
            "budget_exhausted": by_reason.get("budget_exhausted", 0),
            "time_budget": by_reason.get("time_budget", 0),
            "reviews_reopened": reopened,
            "reviewed": review_count,
            "review_failed": len(ledger.review_failed),
            "reviews_with_findings": review_findings,
            "elapsed_s": round(clock() - started, 3),
        }
        report["rounds"].append(entry)
        report["findings"] += entry["findings"]
        report["confirmed"] += entry["confirmed"]
        report["reviews_with_findings"] += entry["reviews_with_findings"]
        if not entry["ran"] and not entry["reviewed"] and (
                not entry["budget_exhausted"] or cfg.growth <= 1.0):
            report["stopped_by"] = "nothing_left"
            break
        progress = (entry["settled"] + entry["findings"] + entry["reviews_with_findings"]
                    + max(0, entry["reviewed"] - entry["review_failed"]))
        idle = 0 if progress else idle + 1
        if cfg.max_idle_rounds and idle >= cfg.max_idle_rounds:
            report["stopped_by"] = "no_progress"
            break
    return report
