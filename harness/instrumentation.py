"""E9 run instrumentation: phase timings and the job result's `instrumentation` block.

Pure observation. Nothing here sends a request, changes an ordering, or feeds a
verdict: it reads counters the model client, the tool runner, the store and the
run budget already keep, and times the phases `investigate_engagement` already
runs. Measured gaps this closes (job 383f0ebff8e8): the manifest `model_metrics`
was null, phase walls had to be rebuilt from log gaps, the tool lifecycle and the
store's per-connection cost were unknown.
"""
from __future__ import annotations

import contextlib
import itertools
import logging
import time

log = logging.getLogger("harness.instrumentation")


def _count(source) -> int | None:
    """Current value of a counter callable, or None when it cannot be read."""
    if source is None:
        return None
    try:
        value = source()
    except Exception:
        return None
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _delta(before, after):
    return None if before is None or after is None else after - before


class PhaseRecorder:
    """Times named phases into `phase_timings`.

    `phase(name)` is a context manager. It keeps no "current phase" state, so
    overlapping or nested use from different tasks cannot corrupt a record: each
    record is built from the locals of its own entry and exit. `begin(name)` is the
    sequential form for a function whose phases follow one another: it ends the
    phase that is open and starts the next, so each boundary is a single line.

    A record is {phase, started_s (since this recorder was created), elapsed_s,
    requests_used_delta, model_calls_delta}; a delta is None when its counter is
    unavailable. Each finished phase is announced on the activity feed
    ("phase X finished in Ns")."""

    def __init__(self, *, requests=None, model_calls=None, announce=True, clock=time.monotonic):
        self._requests = requests
        self._model_calls = model_calls
        self._announce = announce
        self._clock = clock
        self._t0 = clock()
        self._records: list[tuple[int, dict]] = []     # (entry order, record)
        self._entries = itertools.count()
        self._open = None

    @contextlib.contextmanager
    def phase(self, name: str):
        entry = next(self._entries)
        started = self._clock()
        requests_before, calls_before = _count(self._requests), _count(self._model_calls)
        try:
            yield
        finally:
            elapsed = max(0.0, self._clock() - started)
            self._records.append((entry, {
                "phase": name,
                "started_s": round(started - self._t0, 3),
                "elapsed_s": round(elapsed, 3),
                "requests_used_delta": _delta(requests_before, _count(self._requests)),
                "model_calls_delta": _delta(calls_before, _count(self._model_calls)),
            }))
            if self._announce:
                try:
                    from harness import activity_feed
                    activity_feed.publish("note", f"phase {name} finished in {elapsed:.1f}s",
                                          phase=name, elapsed_s=round(elapsed, 3))
                except Exception:   # the feed is observability; it never sinks the run
                    log.debug("phase announcement failed", exc_info=True)

    def begin(self, name: str) -> None:
        """End the open phase (if any) and start `name`."""
        self.finish()
        cm = self.phase(name)
        cm.__enter__()
        self._open = cm

    def finish(self) -> None:
        """End the open phase, if any. Safe to call repeatedly."""
        cm, self._open = self._open, None
        if cm is not None:
            cm.__exit__(None, None, None)

    def timings(self) -> list[dict]:
        """The finished phases in entry order (nested phases finish before the
        phase that holds them, so the list is re-sorted by when each began)."""
        self.finish()
        return [dict(record) for _, record in sorted(self._records, key=lambda pair: pair[0])]


def numeric_delta(before, after):
    """`after` with every numeric leaf reduced by the matching leaf of `before`
    (missing => 0). A key starting "max_" is a high-water mark, not a counter, and
    keeps its `after` value."""
    if isinstance(after, dict):
        before = before if isinstance(before, dict) else {}
        return {k: (v if k.startswith("max_") else numeric_delta(before.get(k), v))
                for k, v in after.items()}
    if isinstance(after, (int, float)) and not isinstance(after, bool):
        base = before if isinstance(before, (int, float)) and not isinstance(before, bool) else 0
        diff = after - base
        return round(diff, 3) if isinstance(diff, float) else diff
    return after


class RunInstrumentation:
    """The instrumentation of ONE `investigate_engagement` call.

    Created at the start: it takes a baseline of the process-wide counters (model
    client, store) so the result reports this run's share, and owns the phase
    recorder. `snapshot()` builds the `instrumentation` block for the job result:
    {model_metrics, phase_timings, tool_lifecycle, store_timing[, health]}.

    The counters are process-wide, so a second engagement running at the same time
    in the same process is counted in both; one engagement at a time is exact."""

    def __init__(self, orchestrator=None, run_context=None, budget=None):
        self._client = getattr(orchestrator, "ollama", None)
        self._run_context = run_context
        self._started_wall = time.time()
        self._model_baseline = self._model_snapshot()
        self._store_baseline = self._store_snapshot()
        self.phases = PhaseRecorder(
            requests=(lambda: budget.used) if budget is not None else None,
            model_calls=(lambda: self._client.model_completed_count) if self._client is not None else None)

    def _model_snapshot(self) -> dict | None:
        snapshot = getattr(self._client, "metrics_snapshot", None)
        try:
            return snapshot() if callable(snapshot) else None
        except Exception:
            return None

    @staticmethod
    def _store_snapshot() -> dict | None:
        try:
            from harness import store
            return store.timing_snapshot()
        except Exception:
            return None

    def snapshot(self) -> dict:
        out: dict = {"phase_timings": self.phases.timings()}
        model = self._model_snapshot()
        if model is not None:
            model = numeric_delta(self._model_baseline, model)
            model["stages"] = {label: row for label, row in model.get("stages", {}).items()
                               if row.get("calls") or row.get("completed")}
        out["model_metrics"] = model
        try:
            from harness import tool_runner
            out["tool_lifecycle"] = tool_runner.lifecycle_snapshot(since=self._started_wall)
        except Exception:
            out["tool_lifecycle"] = None
        store_now = self._store_snapshot()
        out["store_timing"] = (numeric_delta(self._store_baseline, store_now)
                               if store_now is not None else None)
        health = getattr(self._run_context, "health_report", None)
        if callable(health):
            try:
                out["health"] = health()
            except Exception:
                log.debug("health_report failed", exc_info=True)
        return out
