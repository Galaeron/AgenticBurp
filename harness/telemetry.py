"""Process-wide observability counters (W-11).

The harness swallows exceptions in ~177 places. Most are legitimately defensive
-- one validator, crawl step, or advisory lookup failing must not kill a whole
run. The danger is that a swallowed exception is INVISIBLE: a run can produce
zero (or very few) findings for a concrete reason -- every agent's prompt
rejected, a validator crashing on every exchange, scope denials, the coordinator
firing all agents -- that today only appears in server logs, if at all. That is
exactly the "green tests, dead pipeline" failure mode one channel over.

This module makes those events COUNTABLE and surfaces them at /telemetry, so the
question "why did this target produce zero/few findings?" is answerable without
reading logs. It is deliberately tiny and dependency-free: a thread-safe counter
registry plus a snapshot() that composes the answer.

Invocation binding (W-11): counters are bucketed by an invocation/run id, held in
a contextvar so concurrent asyncio Tasks never blend each other's counts -- each
Task gets its own copy of the context, and `bind_current_run` re-sets the value
fresh at the top of every top-level call (Orchestrator.analyze), so sequential
reuse of one Task across runs is also self-correcting. Call sites that never bind
a run (most unit tests, ad-hoc scripts) land in the "" bucket, which is what
`reset()`/`snapshot()` with no run_id operate on for backward compatibility --
that IS the old process-global behavior, kept as the default so existing callers
are unaffected. Passing an explicit run_id gets true per-invocation isolation.
"""
from __future__ import annotations

import contextvars
import threading
from collections import Counter

_LOCK = threading.Lock()
_swallowed: dict[str, Counter] = {}   # run_id ("" = unscoped) -> {"site:ExcType": count, "__total__": count}
_events: dict[str, Counter] = {}      # run_id ("" = unscoped) -> {category: count}

_TOTAL = "__total__"

# The invocation currently bound in THIS asyncio Task / thread of execution.
# Never shared across concurrently-running Tasks -- see module docstring.
_current_run: contextvars.ContextVar[str] = contextvars.ContextVar("telemetry_run_id", default="")


def bind_current_run(run_id: str | None) -> None:
    """Bind subsequent record_*() calls made from this Task/thread to `run_id`.

    Not a context manager: called once at the top of a top-level invocation
    (Orchestrator.analyze), it re-sets the contextvar unconditionally, so a
    second call on the same Task (sequential reuse) or a fresh copy of the
    context handed to a sibling asyncio Task (concurrent reuse, e.g.
    asyncio.gather) both end up scoped correctly without needing a matching
    "unbind" on every exit path.
    """
    _current_run.set(run_id or "")


def current_run_id() -> str:
    return _current_run.get()


def record_swallowed_exception(site: str, exc: BaseException | None = None) -> None:
    """Count one swallowed exception at `site`, in the currently-bound run's
    bucket. Never raises -- observability must not itself break the defensive
    handler it lives in."""
    try:
        key = f"{site}:{type(exc).__name__}" if exc is not None else str(site)
        run_id = _current_run.get()
        with _LOCK:
            bucket = _swallowed.setdefault(run_id, Counter())
            bucket[key] += 1
            bucket[_TOTAL] += 1
    except Exception:
        pass


def record_event(category: str, n: int = 1) -> None:
    """Count a diagnostic event (e.g. a scope denial, a route fallback), in the
    currently-bound run's bucket."""
    try:
        run_id = _current_run.get()
        with _LOCK:
            _events.setdefault(run_id, Counter())[category] += n
    except Exception:
        pass


def swallowed_exceptions(run_id: str | None = None) -> dict:
    with _LOCK:
        if run_id is not None:
            return dict(_swallowed.get(run_id, {}))
        merged: Counter = Counter()
        for bucket in _swallowed.values():
            merged.update(bucket)
        return dict(merged)


def events(run_id: str | None = None) -> dict:
    with _LOCK:
        if run_id is not None:
            return dict(_events.get(run_id, {}))
        merged: Counter = Counter()
        for bucket in _events.values():
            merged.update(bucket)
        return dict(merged)


def total_swallowed(run_id: str | None = None) -> int:
    return swallowed_exceptions(run_id).get(_TOTAL, 0)


def known_run_ids() -> list[str]:
    """Every run_id with recorded diagnostics (excluding the unscoped ""
    bucket), for a caller that wants to know what it can ask for."""
    with _LOCK:
        ids = set(_swallowed.keys()) | set(_events.keys())
    ids.discard("")
    return sorted(ids)


def snapshot(run_id: str | None = None) -> dict:
    """Everything the "why zero/few findings?" question needs, in one place.

    Pulls the coordinator fail-open counters (the historically-silent
    "fired all agents" state) in alongside the swallowed-exception and event
    counts, so a single /telemetry read explains a disappointing run.

    With `run_id`, the snapshot is scoped to exactly that invocation --
    "scope": "run" -- and is silent about every other run. Without it, the
    snapshot aggregates every bucket this process has ever recorded --
    "scope": "process" -- and says so explicitly, plus how many distinct
    invocations contributed, so a process-wide number is never mistaken for
    one run's explanation.
    """
    swallowed = swallowed_exceptions(run_id)
    ev = events(run_id)
    fail_open = {}
    try:
        from harness import coordinator
        fail_open = coordinator.fail_open_stats()
    except Exception:
        pass
    result = {
        "swallowed_exceptions": {
            "total": swallowed.get(_TOTAL, 0),
            "by_site": {k: v for k, v in swallowed.items() if k != _TOTAL},
        },
        "events": ev,
        "coordinator_fail_open": fail_open,
    }
    if run_id is not None:
        result["scope"] = "run"
        result["run_id"] = run_id
    else:
        result["scope"] = "process"
        result["runs_observed"] = len(known_run_ids())
        result["note"] = ("process-wide aggregate across all bound invocations plus any "
                          "unscoped call sites -- pass run_id for one invocation's own "
                          "diagnostics")
    return result


def reset(run_id: str | None = None) -> None:
    """Clear counters. With no run_id, this is the old process-wide reset (used
    by test setUp and the server's own full-reset paths); with a run_id, only
    that invocation's bucket is cleared -- a concurrent or later run is
    untouched."""
    with _LOCK:
        if run_id is None:
            _swallowed.clear()
            _events.clear()
        else:
            _swallowed.pop(run_id, None)
            _events.pop(run_id, None)
