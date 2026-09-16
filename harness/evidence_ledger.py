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
                import config_schema
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


class EvidenceLedger:
    """An append-only stream of LedgerEvents, queryable per finding."""

    def __init__(self) -> None:
        self._events: list[LedgerEvent] = []
        self._ids: set[str] = set()

    def append(self, event: LedgerEvent) -> LedgerEvent:
        if event.event_id in self._ids:
            raise AppendOnlyViolation(
                f"event {event.event_id} is already in the ledger; the ledger is "
                f"append-only -- record a new FINDING_REVISION instead of editing.")
        self._ids.add(event.event_id)
        self._events.append(event)
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
