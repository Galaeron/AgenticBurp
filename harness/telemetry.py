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

Counters are process-global and reset per run (server on a new investigate job,
tests in setUp). record_swallowed_exception() is the seam to wire into any
`except Exception:` that log-and-drops; the key diagnostic sites are wired now.
"""
from __future__ import annotations

import threading
from collections import Counter

_LOCK = threading.Lock()
_swallowed: Counter = Counter()   # "site:ExcType" -> count (plus "__total__")
_events: Counter = Counter()      # generic diagnostic category -> count

_TOTAL = "__total__"


def record_swallowed_exception(site: str, exc: BaseException | None = None) -> None:
    """Count one swallowed exception at `site`. Never raises -- observability
    must not itself break the defensive handler it lives in."""
    try:
        key = f"{site}:{type(exc).__name__}" if exc is not None else str(site)
        with _LOCK:
            _swallowed[key] += 1
            _swallowed[_TOTAL] += 1
    except Exception:
        pass


def record_event(category: str, n: int = 1) -> None:
    """Count a diagnostic event (e.g. a scope denial, a route fallback)."""
    try:
        with _LOCK:
            _events[category] += n
    except Exception:
        pass


def swallowed_exceptions() -> dict:
    with _LOCK:
        return dict(_swallowed)


def events() -> dict:
    with _LOCK:
        return dict(_events)


def total_swallowed() -> int:
    with _LOCK:
        return _swallowed.get(_TOTAL, 0)


def snapshot() -> dict:
    """Everything the "why zero/few findings?" question needs, in one place.

    Pulls the coordinator fail-open counters (the historically-silent
    "fired all agents" state) in alongside the swallowed-exception and event
    counts, so a single /telemetry read explains a disappointing run.
    """
    with _LOCK:
        swallowed = dict(_swallowed)
        ev = dict(_events)
    fail_open = {}
    try:
        from harness import coordinator
        fail_open = coordinator.fail_open_stats()
    except Exception:
        pass
    return {
        "swallowed_exceptions": {
            "total": swallowed.get(_TOTAL, 0),
            "by_site": {k: v for k, v in swallowed.items() if k != _TOTAL},
        },
        "events": ev,
        "coordinator_fail_open": fail_open,
    }


def reset() -> None:
    with _LOCK:
        _swallowed.clear()
        _events.clear()
