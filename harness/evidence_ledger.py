"""Append-only evidence ledger (W-24).

The review's strongest-differentiator proposal: a finding should be a complete,
audit-grade reconstruction of the causal chain that produced it -- answerable
WITHOUT reading server logs. Five questions: why was this tested, what was sent,
what came back, why was it concluded vulnerable (or not), and what was never
tested.

This is the ledger those events live in. It composes the provenance slices that
already exist -- W-9 (store.finding_fingerprint, the structural finding identity)
and W-20 (config_schema.config_fingerprint, which configuration produced the run)
-- plus code/model/prompt versions, onto every event.

Design invariants:
  - APPEND-ONLY: events are never mutated or deleted. A correction is a NEW
    FINDING_REVISION event, so the record of what was believed, and when, is
    preserved. append() enforces this.
  - Every event carries a Provenance envelope, so a re-run is comparable and a
    silent model/config swap is not mistaken for a target change.
  - reconstruct(finding_ref) answers the five audit questions from the events
    alone; reproduction_recipe(finding_ref) is the minimal "how to see it again".

Scope of this slice: the ledger + reconstruction are complete and tested. The
record_* API is the integration seam; wiring each pipeline stage to emit its
event (agent hypothesis -> PLANNED_ACTION from the validator plan -> the gate's
AUTHORIZATION_DECISION -> EXECUTION -> VALIDATION_DECISION -> FINDING_REVISION)
and persisting the stream are the follow-on that makes every live finding
answer the five questions.
"""
from __future__ import annotations

import functools
import os
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum

EVIDENCE_SCHEMA_VERSION = "1.0"


class EventType(str, Enum):
    OBSERVATION = "observation"                        # something noticed in an exchange
    HYPOTHESIS = "hypothesis"                          # an agent's vuln claim (why we suspect)
    PLANNED_ACTION = "planned_action"                  # a validator plan (what we intend to send)
    AUTHORIZATION_DECISION = "authorization_decision"  # the gate / scope decision
    EXECUTION = "execution"                            # the actual send: request/response/tool io
    VALIDATION_DECISION = "validation_decision"        # confirmed / refuted / inconclusive
    FINDING_REVISION = "finding_revision"              # a lifecycle/severity change to the finding
    RUN_SUMMARY = "run_summary"                        # ER-2: one canonical per-run trace summary


# Canonical order for reconstructing a chain when timestamps tie.
_ORDER = {t: i for i, t in enumerate(EventType)}


@functools.lru_cache(maxsize=1)
def _code_version() -> str:
    """Short git commit of the running code, or 'unknown' outside a checkout."""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5, cwd=here)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return "unknown"


@dataclass(frozen=True)
class Provenance:
    code_version: str = ""
    config_fingerprint: str = ""
    model: str = ""
    prompt_version: str = ""
    evidence_schema_version: str = EVIDENCE_SCHEMA_VERSION

    @classmethod
    def capture(cls, *, config: dict | None = None, model: str = "",
                prompt_version: str = "", config_fingerprint: str = "") -> "Provenance":
        fp = config_fingerprint
        if not fp and config is not None:
            try:
                from harness import config_schema
                fp = config_schema.config_fingerprint(config)
            except Exception:
                fp = ""
        return cls(code_version=_code_version(), config_fingerprint=fp,
                   model=model, prompt_version=prompt_version)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class LedgerEvent:
    event_type: EventType
    finding_ref: str
    summary: str
    data: dict = field(default_factory=dict)
    provenance: Provenance = field(default_factory=Provenance)
    case_ref: str = ""
    event_id: str = ""
    created_at: float = 0.0

    def __post_init__(self) -> None:
        if isinstance(self.event_type, str) and not isinstance(self.event_type, EventType):
            object.__setattr__(self, "event_type", EventType(self.event_type))
        if not self.event_id:
            object.__setattr__(self, "event_id", uuid.uuid4().hex)
        if not self.created_at:
            object.__setattr__(self, "created_at", time.time())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d


class AppendOnlyViolation(Exception):
    """Raised on any attempt to re-append or otherwise mutate a ledger event."""


DEFAULT_MAX_EVENTS = 5000


class EvidenceLedger:
    """An append-only stream of LedgerEvents, queryable per finding.

    The in-memory stream is bounded to `max_events`: once the cap is
    exceeded, the oldest events are evicted (FIFO). This is purely a
    memory-footprint guard on the process-local copy -- the durable record
    lives in store.py's ledger_events table (see persist_ledger_event /
    ledger_events_for / reconstruct_persisted below), which is never
    truncated and is what report_generator.py / server.py actually read for
    a finding's evidence. Evicting an old in-memory event therefore never
    changes what reconstruct_persisted() can answer.
    """

    def __init__(self, max_events: int = DEFAULT_MAX_EVENTS) -> None:
        self._events: list[LedgerEvent] = []
        self._ids: set[str] = set()
        self.max_events = max_events

    def append(self, event: LedgerEvent) -> LedgerEvent:
        if event.event_id in self._ids:
            raise AppendOnlyViolation(
                f"event {event.event_id} is already in the ledger; the ledger is "
                f"append-only -- record a new FINDING_REVISION instead of editing.")
        self._ids.add(event.event_id)
        self._events.append(event)
        while self.max_events > 0 and len(self._events) > self.max_events:
            evicted = self._events.pop(0)
            self._ids.discard(evicted.event_id)
        return event

    def record(self, event_type, finding_ref: str, summary: str, *,
               data: dict | None = None, provenance: Provenance | None = None,
               case_ref: str = "") -> LedgerEvent:
        return self.append(LedgerEvent(
            event_type=event_type, finding_ref=finding_ref, summary=summary,
            data=dict(data or {}), provenance=provenance or Provenance(), case_ref=case_ref))

    def events_for(self, finding_ref: str) -> list[LedgerEvent]:
        return sorted(
            [e for e in self._events if e.finding_ref == finding_ref],
            key=lambda e: (e.created_at, _ORDER.get(e.event_type, 99)))

    def reconstruct(self, finding_ref: str) -> dict:
        """Answer the five audit questions for one finding from its events alone."""
        evs = self.events_for(finding_ref)
        by_type: dict[EventType, list[LedgerEvent]] = {}
        for e in evs:
            by_type.setdefault(e.event_type, []).append(e)

        def summaries(t):
            return [e.summary for e in by_type.get(t, [])]

        executions = by_type.get(EventType.EXECUTION, [])
        return {
            "finding_ref": finding_ref,
            "why_tested": summaries(EventType.OBSERVATION) + summaries(EventType.HYPOTHESIS),
            "what_sent": summaries(EventType.PLANNED_ACTION)
            + [e.data.get("request", "") for e in executions if e.data.get("request")],
            "what_came_back": [e.data.get("response", "") or e.summary for e in executions],
            "why_concluded": summaries(EventType.VALIDATION_DECISION)
            + summaries(EventType.FINDING_REVISION),
            "authorization": summaries(EventType.AUTHORIZATION_DECISION),
            "what_was_never_tested": [e.data["not_tested"] for e in evs if e.data.get("not_tested")],
            "event_count": len(evs),
            "provenance": evs[0].provenance.to_dict() if evs else {},
            "complete": bool(by_type.get(EventType.VALIDATION_DECISION)
                             or by_type.get(EventType.FINDING_REVISION)),
        }

    def reproduction_recipe(self, finding_ref: str) -> dict:
        """The minimal, provenance-stamped recipe to reproduce a finding."""
        evs = self.events_for(finding_ref)
        executions = [e for e in evs if e.event_type == EventType.EXECUTION]
        prov = evs[0].provenance if evs else Provenance()
        return {
            "finding_ref": finding_ref,
            "code_version": prov.code_version,
            "config_fingerprint": prov.config_fingerprint,
            "evidence_schema_version": prov.evidence_schema_version,
            "steps": [
                {"request": e.data.get("request", ""), "expected": e.data.get("expected", "")}
                for e in executions
            ],
        }

    def to_dicts(self) -> list[dict]:
        return [e.to_dict() for e in self._events]

    def __len__(self) -> int:
        return len(self._events)


# ---------------------------------------------------------------------------
# Wiring seam (P0-1): a process-wide default ledger every pipeline stage
# emits onto, plus a persistence bridge to store.py so the stream survives a
# process restart and the findings API / report can reconstruct a finding
# without needing the in-memory singleton. INSTRUMENTATION ONLY: emit()
# never raises into and never returns anything a caller branches on -- a
# store failure is swallowed (logged) so a persistence hiccup can never
# affect a finding's verdict, severity, or the send it is recording.
# ---------------------------------------------------------------------------

import logging as _logging

_log = _logging.getLogger("harness.evidence_ledger")

_DEFAULT_LEDGER = EvidenceLedger(max_events=DEFAULT_MAX_EVENTS)


def get_default_ledger() -> EvidenceLedger:
    """The process-wide ledger every live pipeline stage emits onto."""
    return _DEFAULT_LEDGER


def reset_default_ledger(max_events: int = DEFAULT_MAX_EVENTS) -> EvidenceLedger:
    """Replace the process-wide default ledger with a fresh, empty one.

    A seam for callers/tests that need to clear accumulated in-memory state
    between runs; it never touches the durable store, so anything already
    persisted via emit() remains reconstructable through reconstruct_persisted().
    """
    global _DEFAULT_LEDGER
    _DEFAULT_LEDGER = EvidenceLedger(max_events=max_events)
    return _DEFAULT_LEDGER


def emit(event_type, finding_ref: str, summary: str, *, data: dict | None = None,
          provenance: Provenance | None = None, case_ref: str = "",
          ledger: "EvidenceLedger | None" = None) -> LedgerEvent | None:
    """Record one event onto `ledger` (default: the process-wide default
    ledger) AND best-effort persist it to store.py's ledger_events table.

    Returns None (recording nothing) when `finding_ref` is empty -- an event
    with no finding to attach to is not useful and would only pollute the
    stream. This is the single seam every pipeline stage (agents, transport,
    confirmation, the suppression gate) calls through; it is read/record-only
    and never influences the caller's own decision.
    """
    if not finding_ref:
        return None
    led = ledger if ledger is not None else _DEFAULT_LEDGER
    ev = led.record(event_type, finding_ref, summary, data=data,
                    provenance=provenance, case_ref=case_ref)
    try:
        from harness import store
        store.persist_ledger_event(ev.to_dict())
    except Exception as e:  # persistence is best-effort; never break the live pipeline
        _log.debug("failed to persist ledger event %s for %s: %s", event_type, finding_ref, e)
    return ev


def ledger_from_store(finding_ref: str) -> EvidenceLedger:
    """Replay this finding's persisted events (store.py) into a fresh ledger.

    Lets the findings API / report reconstruct a finding independent of the
    in-memory singleton (e.g. after a restart, or from a different process),
    while reconstruct()/reproduction_recipe() themselves stay pure functions
    of whatever events a ledger holds."""
    # Unbounded replay: the durable read path must never evict a finding's own
    # persisted events, even in the pathological case of a single finding with
    # more than DEFAULT_MAX_EVENTS records. The cap is only a memory guard on
    # the long-lived in-memory singleton, not on a fresh per-finding replay.
    led = EvidenceLedger(max_events=0)
    try:
        from harness import store
        rows = store.ledger_events_for(finding_ref)
    except Exception as e:
        _log.debug("failed to load persisted ledger events for %s: %s", finding_ref, e)
        return led
    for row in rows:
        try:
            prov = Provenance(**row.get("provenance", {}))
            event = LedgerEvent(
                event_type=EventType(row["event_type"]), finding_ref=row["finding_ref"],
                summary=row.get("summary", ""), data=row.get("data", {}),
                provenance=prov, case_ref=row.get("case_ref", ""),
                event_id=row.get("event_id", ""), created_at=row.get("created_at", 0.0))
            led.append(event)
        except AppendOnlyViolation:
            pass  # duplicate row (e.g. re-persisted); the first copy already holds
        except Exception as e:
            _log.debug("skipping malformed persisted ledger event for %s: %s", finding_ref, e)
    return led


def reconstruct_persisted(finding_ref: str) -> dict:
    """reconstruct(), reading from the durable store instead of memory."""
    return ledger_from_store(finding_ref).reconstruct(finding_ref)


def reproduction_recipe_persisted(finding_ref: str) -> dict:
    """reproduction_recipe(), reading from the durable store instead of memory."""
    return ledger_from_store(finding_ref).reproduction_recipe(finding_ref)
