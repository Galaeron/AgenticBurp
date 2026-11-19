"""
Final pass: spend the time left before the engagement's deadline on the work its
phase budgets set aside (R11-4).

r11 (24 h Juice Shop run, 2026-11-18) reached `done` 51 min before its hard stop. The
retry rounds stopped at `reserve_seconds` (20 min) before the investigation deadline,
and the finalise phase took 2 s of that reserve. Work was still left:
- 176 worklist nodes skipped as budget_exhausted;
- 283 coverage-drive legs queued and never attempted (the drive stopped at its fixed
  `coverage_drive_seconds`);
- 47 captured replays held by the per-endpoint check time share
  (`endpoint_check_time_share`).

With `engagement.final_pass.enabled`, after the retry rounds and before the final
experiment pass, the engagement runs one pass over that work, in priority order:

1. `worklist_nodes`: one worklist sweep for the nodes an earlier budget skipped.
   Settled nodes are resumed, and shape-driven legs already attempted are not sent
   again (the retry ledger). The sweep uses the budgets the next retry round would
   use (retry_rounds.round_budgets), so it adds no budget rule of its own.
2. `drive_legs`: the coverage drive goes on over the cells it queued and never
   attempted, on the same tracker, with the leg budget the drive has left.
3. `held_replays`: the captured replays the per-endpoint time share held. Each
   (endpoint, check) gets the same share again, for this pass; a replay that
   already ran is not sent again.

Every leg goes through the same dispatch as before: the same validators, safety gate,
write rules, per-leg caps and run request budget. The pass only reuses time. It adds
no new kind of request.

A step starts only while the clock is before `deadline - reserve_seconds` (reserve
for finalise), and each step is given that time as its own deadline. No step starts
after the deadline or on cancellation. Without an investigation deadline the pass
does nothing.

OFF by default, because it sends active traffic.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

__all__ = ["FinalPassConfig", "STEPS", "run_final_pass"]

# The steps in priority order (module docstring).
STEPS = ("worklist_nodes", "drive_legs", "held_replays")


@dataclass(frozen=True)
class FinalPassConfig:
    enabled: bool = False
    reserve_seconds: float = 60.0   # left before the deadline for the finalise phase

    @classmethod
    def from_config(cls, config: dict | None) -> "FinalPassConfig":
        raw = ((config or {}).get("engagement", {}) or {}).get("final_pass") or {}
        if not isinstance(raw, dict):
            return cls()
        try:
            reserve = max(0.0, float(raw.get("reserve_seconds", 60.0)))
        except (TypeError, ValueError):
            reserve = 60.0
        return cls(enabled=bool(raw.get("enabled", False)), reserve_seconds=reserve)


async def run_final_pass(cfg: FinalPassConfig, *, deadline: float | None, steps: dict,
                         cancelled=lambda: False, clock=time.monotonic) -> dict:
    """Run the `steps` (name -> async fn(stop_at) -> dict | None) in STEPS order.

    A step returning None had nothing to do. A step that raises is recorded with its
    error and the pass goes on to the next one. Returns the report:
    {enabled, reserve_seconds, stop_at_s (seconds from the start), stopped_by,
    steps: [{step, started_s, elapsed_s, result | error}], skipped: [names]}."""
    report: dict = {"enabled": True, "reserve_seconds": cfg.reserve_seconds,
                    "stop_at_s": None, "stopped_by": None, "steps": [], "skipped": []}
    if deadline is None:
        report["stopped_by"] = "no_deadline"
        return report
    t0 = clock()
    stop_at = deadline - cfg.reserve_seconds
    report["stop_at_s"] = round(stop_at - t0, 3)
    ordered = [name for name in STEPS if name in steps]
    for i, name in enumerate(ordered):
        if cancelled():
            report["stopped_by"] = "cancelled"
        elif clock() >= stop_at:
            report["stopped_by"] = "deadline"
        if report["stopped_by"]:
            report["skipped"] = ordered[i:]
            break
        started = clock()
        entry: dict = {"step": name, "started_s": round(started - t0, 3)}
        try:
            entry["result"] = await steps[name](stop_at)
        except Exception as e:  # the pass is a bonus -- one step never sinks the run
            entry["error"] = f"{type(e).__name__}: {e}"
        entry["elapsed_s"] = round(clock() - started, 3)
        report["steps"].append(entry)
    else:
        report["stopped_by"] = "done"
    return report
