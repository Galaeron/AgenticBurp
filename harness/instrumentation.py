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


class _PhaseInterrupted(BaseException):
    """Thrown into an open `begin` phase by PhaseRecorder.abort(); never escapes."""


class PhaseRecorder:
    """Times named phases into `phase_timings`.

    `phase(name)` is a context manager. It keeps no "current phase" state, so
    overlapping or nested use from different tasks cannot corrupt a record: each
    record is built from the locals of its own entry and exit. `begin(name)` is the
    sequential form for a function whose phases follow one another: it ends the
    phase that is open and starts the next, so each boundary is a single line.

    A record is {phase, started_s (since this recorder was created), ended_s,
    elapsed_s, budget_s, unused_s, requests_used_delta, model_calls_delta}; a delta
    is None when its counter is unavailable. `budget_s` is the wall time the phase
    was allowed (`set_budget`, or `begin(name, budget_s=...)`), None when nothing
    bounded it; `unused_s` is what it left of that budget (R11-4: r11's records
    had no budget, so time a phase left could not be read from the manifest).
    Each finished phase is announced on the activity feed ("phase X finished in Ns")."""

    def __init__(self, *, requests=None, model_calls=None, announce=True, clock=time.monotonic,
                 on_event=None):
        # HU-5: on_event(event, name) with event "begin", "end" or "abort" (the
        # phase was left by an exception, e.g. a cancellation). Observation only.
        self._on_event = on_event
        self._requests = requests
        self._model_calls = model_calls
        self._announce = announce
        self._clock = clock
        self._t0 = clock()
        self._records: list[tuple[int, dict]] = []     # (entry order, record)
        self._entries = itertools.count()
        self._open = None
        self._open_name = None
        self._open_entry_id = None
        self._last_entry = None
        self._budgets: dict[int, float] = {}   # entry -> budget seconds

    @contextlib.contextmanager
    def phase(self, name: str, budget_s: float | None = None):
        entry = next(self._entries)
        self._last_entry = entry
        if budget_s is not None:
            self._budgets[entry] = budget_s
        started = self._clock()
        requests_before, calls_before = _count(self._requests), _count(self._model_calls)
        self._notify("begin", name)
        aborted = False
        try:
            yield
        except BaseException:
            aborted = True
            raise
        finally:
            self._notify("abort" if aborted else "end", name)
            ended = self._clock()
            elapsed = max(0.0, ended - started)
            budget = self._budgets.pop(entry, None)
            record = {
                "phase": name,
                "started_s": round(started - self._t0, 3),
                "ended_s": round(ended - self._t0, 3),
                "elapsed_s": round(elapsed, 3),
                "budget_s": None if budget is None else round(budget, 3),
                "unused_s": None if budget is None else round(max(0.0, budget - elapsed), 3),
                "requests_used_delta": _delta(requests_before, _count(self._requests)),
                "model_calls_delta": _delta(calls_before, _count(self._model_calls)),
            }
            if aborted:
                record["interrupted"] = True
            self._records.append((entry, record))
            if self._announce:
                try:
                    from harness import activity_feed
                    activity_feed.publish("note", f"phase {name} finished in {elapsed:.1f}s",
                                          phase=name, elapsed_s=round(elapsed, 3))
                except Exception:   # the feed is observability; it never sinks the run
                    log.debug("phase announcement failed", exc_info=True)

    def _notify(self, event: str, name: str) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(event, name)
        except Exception:   # bookkeeping never sinks the run
            log.debug("phase event hook failed", exc_info=True)

    def begin(self, name: str, budget_s: float | None = None) -> None:
        """End the open phase (if any) and start `name`."""
        self.finish()
        cm = self.phase(name, budget_s)
        cm.__enter__()
        self._open = cm
        self._open_name = name
        self._open_entry_id = self._last_entry

    def set_budget(self, name: str, budget_s: float | None) -> None:
        """Record the wall-time budget of the open `begin` phase `name`, decided
        after it began (a slice is computed when the phase starts its work). A
        name that is not the open phase, or a None budget, changes nothing."""
        if budget_s is None or self._open is None or self._open_name != name:
            return
        self._budgets[self._open_entry_id] = max(0.0, float(budget_s))

    def abort(self) -> None:
        """End the open `begin` phase as interrupted, if any: a cancellation that left
        the caller without closing it (R11-4b: the server's cancelled-job result).
        Its record carries `interrupted: true` and the hook gets "abort", as when
        an exception leaves a `phase()` block. Safe to call repeatedly."""
        cm, self._open = self._open, None
        self._open_name = None
        if cm is not None:
            cm.__exit__(_PhaseInterrupted, _PhaseInterrupted(), None)

    def finish(self) -> None:
        """End the open phase, if any. Safe to call repeatedly."""
        cm, self._open = self._open, None
        self._open_name = None
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


def run_costs(instrumentation: dict | None, wall_seconds) -> dict:
    """The job result's top-level `costs` block (AR-10 P3, spec 3.4/4.4), read from
    this run's model-client counters in its `instrumentation` block. model_calls is
    every call started (failed ones included; a transient retry is not a new call,
    it is counted in retries). A counter the client did not report is None, never 0."""
    client = ((instrumentation or {}).get("model_metrics") or {}).get("client") or {}

    def counter(key):
        value = client.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    return {"model_calls": counter("attempted"), "model_errors": counter("errors"),
            "retries": counter("retries"), "wall_seconds": wall_seconds}


def ollama_models(orchestrator) -> list[str]:
    """The models an engagement sends to Ollama: the coordinator, reasoning and
    critique models (a role a config moves to another provider is left out) and
    every agent's model."""
    config = getattr(orchestrator, "config", None) or {}
    coord = config.get("coordinator") or {}
    critique = config.get("critique") or {}
    models = set()
    if coord.get("provider", "ollama") == "ollama":
        models.add(getattr(orchestrator, "coordinator_model", None) or coord.get("model"))
    if critique.get("provider", "ollama") == "ollama":
        from harness.coordinator import reasoning_model
        models.update((reasoning_model(config), critique.get("model")))
    agents = getattr(getattr(orchestrator, "agent_manager", None), "agents", None) or {}
    models.update(getattr(agent, "model", None) for agent in agents.values())
    return sorted(m for m in models if isinstance(m, str) and m.strip())


class RunInstrumentation:
    """The instrumentation of ONE `investigate_engagement` call.

    Created at the start: it takes a baseline of the process-wide counters (model
    client, store) so the result reports this run's share, and owns the phase
    recorder. `snapshot()` builds the `instrumentation` block for the job result:
    {model_metrics, phase_timings, tool_lifecycle, store_timing, sqlmap_targeting[, health]}.

    The counters are process-wide, so a second engagement running at the same time
    in the same process is counted in both; one engagement at a time is exact."""

    def __init__(self, orchestrator=None, run_context=None, budget=None):
        self._client = getattr(orchestrator, "ollama", None)
        self._run_context = run_context
        self._started_wall = time.time()
        self._started_monotonic = time.monotonic()
        self._model_baseline = self._model_snapshot()
        self._store_baseline = self._store_snapshot()
        # The context-window preflight report for this run, set by
        # investigate_engagement (ollama_client.run_context_preflight); reported only.
        self.context_preflight: dict | None = None
        self.phases = PhaseRecorder(
            requests=(lambda: budget.used) if budget is not None else None,
            model_calls=(lambda: self._client.model_completed_count) if self._client is not None else None,
            on_event=self._phase_event)

    def _phase_event(self, event: str, name: str) -> None:
        """HU-5: forward a phase boundary to the run's handoff, when it has one."""
        from harness import run_handoff
        handoff = run_handoff.for_run(self._run_context)
        if handoff is not None:
            handoff.phase_event(event, name)

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
        if self.context_preflight is not None:
            out["context_preflight"] = self.context_preflight
        # R11-3/R11-4: sqlmap's held targets per endpoint family and the transport
        # endpoints it skipped, beside the phase walls (None: sqlmap never asked).
        try:
            from harness import sqlmap_targeting
            out["sqlmap_targeting"] = sqlmap_targeting.run_report(self._run_context)
        except Exception:
            log.debug("sqlmap targeting report failed", exc_info=True)
            out["sqlmap_targeting"] = None
        return out

    def result_blocks(self) -> dict:
        """{instrumentation, costs} for the job result, from one snapshot so the two
        blocks agree. wall_seconds runs from this object's creation."""
        block = self.snapshot()
        wall = round(max(0.0, time.monotonic() - self._started_monotonic), 1)
        return {"instrumentation": block, "costs": run_costs(block, wall)}
