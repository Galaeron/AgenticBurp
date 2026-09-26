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


def _nonempty(s) -> bool:
    return bool((s or "").strip()) if isinstance(s, str) else bool(s)


def _resolved_blob_hash(executions: list, field: str, *, resolver=None) -> str | None:
    """The first hash under `field` (``request_blob``/``response_blob``) on any
    EXECUTION event that actually STORAGE-RESOLVES (harness.store.
    evidence_blob_resolves): present in the blob store AND its bytes still
    hash to that value. Returns None if no such hash resolves -- whether
    because no hash was ever recorded, or because the one recorded is
    missing/corrupted. Imported lazily (like the rest of this module's store
    access) to avoid a hard import-time dependency on store.py.

    `resolver`: optional ``hash -> bool`` override for the default
    ``store.evidence_blob_resolves`` lookup (RA-4 batched-report perf). A
    caller reconstructing many findings in one report can pass a memoizing
    resolver so the SAME hash is only ever checked once across the whole
    batch, instead of once per finding that happens to reference it. Omitted
    (the default, and what every existing caller gets) preserves the exact
    prior behavior: one fresh `store.evidence_blob_resolves` call per hash."""
    if resolver is None:
        try:
            from harness import store
        except Exception:
            return None
        resolver = store.evidence_blob_resolves
    for e in executions:
        h = e.data.get(field)
        if _nonempty(h):
            try:
                if resolver(h):
                    return h
            except Exception:
                pass
    return None


def _blob_resolves(h) -> bool:
    """True iff a single hash `h` is present and storage-resolves (harness.
    store.evidence_blob_resolves). Same semantics/try-except-swallow pattern
    as `_resolved_blob_hash` above, but checked against ONE specific hash
    (e.g. one EXECUTION step's own request_blob/response_blob) rather than
    "the first resolving hash across every EXECUTION" -- reproduction_recipe
    needs PER-STEP replayability, not the pooled-across-executions check
    `_assess_completeness` uses for its own resolvable flag. Imported lazily
    to avoid a hard import-time dependency on store.py; any store error
    (including no store available) is treated as unresolved."""
    if not _nonempty(h):
        return False
    try:
        from harness import store
    except Exception:
        return False
    try:
        return bool(store.evidence_blob_resolves(h))
    except Exception:
        return False


def _assess_completeness(by_type: "dict[EventType, list[LedgerEvent]]", *, resolver=None) -> dict:
    """Honest reproducibility assessment for a finding (P0-6 / R10; FR-2 / F03).

    `complete` (elsewhere) only says a verdict was reached. That is NOT the same
    as a tester being able to reproduce the finding. FR-2 tightens this further:
    a nonempty `request`/`response` STRING (e.g. a bare URL, or ``HTTP 200``) is
    a human-readable reference, not reproducible evidence -- it proves nothing
    was hashed or stored, only that someone wrote a label. `resolvable` now
    requires a REAL, content-addressed, hash-verified blob for BOTH the request
    and the response (see run_context.TargetTransport._artifact, which stores
    them, already redacted, only at the successful-send call site). A blob hash
    that was recorded but no longer resolves (deleted/corrupted) is reported
    exactly like one that was never recorded -- resolvability is storage-backed,
    never a nonempty-string illusion. Computed only from the events on hand, so
    a durable record whose EXECUTION event failed to persist reconstructs as NOT
    resolvable (never a silent ``complete`` durable record for un-persisted
    evidence).
    """
    executions = by_type.get(EventType.EXECUTION, [])
    observations = by_type.get(EventType.OBSERVATION, []) + by_type.get(EventType.HYPOTHESIS, [])

    has_conclusion = bool(by_type.get(EventType.VALIDATION_DECISION)
                          or by_type.get(EventType.FINDING_REVISION))
    has_execution = bool(executions)
    has_request = any(_nonempty(e.data.get("request")) for e in executions)
    has_response = any(_nonempty(e.data.get("response")) for e in executions)
    has_captured_observation = any(_nonempty(e.summary) for e in observations)

    has_request_blob_ref = any(_nonempty(e.data.get("request_blob")) for e in executions)
    has_response_blob_ref = any(_nonempty(e.data.get("response_blob")) for e in executions)
    request_blob_hash = _resolved_blob_hash(executions, "request_blob", resolver=resolver)
    response_blob_hash = _resolved_blob_hash(executions, "response_blob", resolver=resolver)
    evidence_blob_degraded = any(e.data.get("evidence_blob_degraded") for e in executions)

    missing: list[str] = []
    if not has_conclusion:
        missing.append("no verdict (validation decision / finding revision) recorded")
    if has_execution:
        if not has_request:
            missing.append("execution recorded but the request reference is empty")
        if not has_response:
            missing.append("execution recorded but the response capture is empty")
        # FR-2: an independently re-runnable step needs a STORED, HASH-VERIFIED
        # blob for both the request and the response -- the legacy `request`/
        # `response` strings above are display-only references and are never,
        # by themselves, sufficient.
        resolvable = bool(request_blob_hash and response_blob_hash)
        if not resolvable:
            if not has_request_blob_ref and not has_response_blob_ref:
                missing.append(
                    "request/response recorded only as a reference (e.g. 'HTTP 200'), "
                    "not a stored hash-verified artifact")
            else:
                if has_request_blob_ref and not request_blob_hash:
                    missing.append("referenced request blob is missing or failed hash verification")
                elif not has_request_blob_ref:
                    missing.append("no request blob recorded -- reference only")
                if has_response_blob_ref and not response_blob_hash:
                    missing.append("referenced response blob is missing or failed hash verification")
                elif not has_response_blob_ref:
                    missing.append("no response blob recorded -- reference only")
            if evidence_blob_degraded:
                missing.append(
                    "evidence blob store failed durably at capture time; the request/response "
                    "were not archived (evidence health degraded)")
    else:
        if not has_captured_observation:
            missing.append("no execution and no captured observation to reproduce from")
        # No active send was recorded: nothing independently re-runnable exists in
        # the ledger (a passive finding's evidence is the original captured
        # exchange, re-read, not a step this ledger can replay).
        resolvable = False

    return {
        "resolvable": resolvable,
        "has_conclusion": has_conclusion,
        "has_execution": has_execution,
        "has_request": has_request,
        "has_response": has_response,
        "has_captured_observation": has_captured_observation,
        "has_request_blob": bool(request_blob_hash),
        "has_response_blob": bool(response_blob_hash),
        "evidence_blob_degraded": evidence_blob_degraded,
        "missing": missing,
    }


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

    def reconstruct(self, finding_ref: str, *, resolver=None) -> dict:
        """Answer the five audit questions for one finding from its events alone.

        `resolver`: optional override threaded straight through to
        _assess_completeness's blob-hash resolution (RA-4 batched-report
        memoization) -- see _resolved_blob_hash's docstring. Omitted (the
        default, and what every existing caller gets) resolves each blob
        hash via a fresh harness.store.evidence_blob_resolves() call, exactly
        as before this parameter existed."""
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
            # `complete` = a verdict (confirmed/refuted/revised) was reached. This is
            # the "was it concluded?" axis and is deliberately SEPARATE from whether
            # a tester can independently reproduce it -- see `completeness` (P0-6/R10).
            "complete": bool(by_type.get(EventType.VALIDATION_DECISION)
                             or by_type.get(EventType.FINDING_REVISION)),
            "completeness": _assess_completeness(by_type, resolver=resolver),
        }

    def reproduction_recipe(self, finding_ref: str) -> dict:
        """The minimal, provenance-stamped recipe to reproduce a finding.

        RA-1: the old shape only ever surfaced `request`/`expected` -- the
        human-readable reference strings -- and `expected` is never even set
        by the live EXECUTION producer (run_context.TargetTransport._artifact).
        That let a recipe claim to be a "reproducible finding" while pointing
        at none of the actual replayable evidence, even when `completeness.
        resolvable` (see _assess_completeness) was True beside it. Each
        EXECUTION step now also surfaces `method` and the request/response
        blob HASHES -- but only when they storage-resolve (_blob_resolves,
        same check `_resolved_blob_hash` uses, applied per-step rather than
        pooled across executions) -- plus a `replayable` flag so a caller
        never has to re-derive resolvability itself. The legacy `request`/
        `expected` keys are kept for back-compat; nothing existing is removed.
        """
        evs = self.events_for(finding_ref)
        executions = [e for e in evs if e.event_type == EventType.EXECUTION]
        prov = evs[0].provenance if evs else Provenance()

        steps = []
        for e in executions:
            request_blob = e.data.get("request_blob")
            response_blob = e.data.get("response_blob")
            request_resolves = _blob_resolves(request_blob)
            response_resolves = _blob_resolves(response_blob)
            replayable = request_resolves and response_resolves
            step = {
                "request": e.data.get("request", ""),
                "expected": e.data.get("expected", ""),
                "method": e.data.get("method"),
                "response": e.data.get("response", ""),
                "status": e.data.get("response", ""),
                "request_blob": request_blob if request_resolves else None,
                "response_blob": response_blob if response_resolves else None,
                "replayable": replayable,
            }
            if not replayable:
                step["note"] = "reference-only, not replayable"
            steps.append(step)

        # Top-level `resolvable`: reuse `_resolved_blob_hash` -- the EXACT
        # same helper `_assess_completeness` calls to compute `completeness.
        # resolvable` -- over the SAME `executions` list, rather than folding
        # the per-step `replayable` flags above (which are individually
        # stricter: a per-step flag requires ONE execution's own pair to both
        # resolve, whereas `_assess_completeness` accepts a resolving request
        # blob from any execution and a resolving response blob from any
        # other). Calling the identical function on the identical input is
        # the only way to GUARANTEE this recipe's resolvability never drifts
        # from `reconstruct(...)["completeness"]["resolvable"]" for the same
        # finding -- which is the whole point of this fix.
        resolvable = bool(_resolved_blob_hash(executions, "request_blob")
                          and _resolved_blob_hash(executions, "response_blob"))

        return {
            "finding_ref": finding_ref,
            "code_version": prov.code_version,
            "config_fingerprint": prov.config_fingerprint,
            "evidence_schema_version": prov.evidence_schema_version,
            "resolvable": resolvable,
            "steps": steps,
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


def _ledger_from_rows(finding_ref: str, rows: "list[dict]") -> EvidenceLedger:
    """Replay already-fetched persisted-event rows (each shaped like one of
    store.ledger_events_for's row dicts) into a fresh, unbounded ledger for
    one finding_ref. The shared per-row construction ledger_from_store (one
    ref, one query) and reconstruct_persisted_many (RA-4: many refs, one
    batched query) both build on -- so there is exactly one place that turns
    a persisted row back into a LedgerEvent.

    Unbounded (max_events=0): the durable read path must never evict a
    finding's own persisted events, even in the pathological case of a
    single finding with more than DEFAULT_MAX_EVENTS records. The cap is
    only a memory guard on the long-lived in-memory singleton, not on a
    fresh per-finding replay."""
    led = EvidenceLedger(max_events=0)
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


def ledger_from_store(finding_ref: str) -> EvidenceLedger:
    """Replay this finding's persisted events (store.py) into a fresh ledger.

    Lets the findings API / report reconstruct a finding independent of the
    in-memory singleton (e.g. after a restart, or from a different process),
    while reconstruct()/reproduction_recipe() themselves stay pure functions
    of whatever events a ledger holds."""
    try:
        from harness import store
        rows = store.ledger_events_for(finding_ref)
    except Exception as e:
        _log.debug("failed to load persisted ledger events for %s: %s", finding_ref, e)
        return EvidenceLedger(max_events=0)
    return _ledger_from_rows(finding_ref, rows)


def reconstruct_persisted(finding_ref: str) -> dict:
    """reconstruct(), reading from the durable store instead of memory."""
    return ledger_from_store(finding_ref).reconstruct(finding_ref)


def reconstruct_persisted_many(finding_refs: "list[str]") -> "dict[str, dict]":
    """Batched form of reconstruct_persisted (RA-4 perf fix).

    The report generator used to call reconstruct_persisted(ref) once PER
    FINDING. Each of those calls did its own ledger_events_for(ref) fresh
    connection+query, plus one MORE fresh connection per blob field
    (evidence_blob_resolves) on every EXECUTION event it found -- an
    N findings x E events-per-finding pile of serial SQLite connections for
    one report. This does ONE batched events fetch for every ref
    (store.ledger_events_for_many), builds each ref's EvidenceLedger from its
    own slice of that single fetch (never re-querying per ref), and resolves
    each blob hash AT MOST ONCE across the whole batch via a shared
    {hash: bool} memo -- so a report over many findings still does a small,
    bounded number of store reads, not one per finding times its event count.

    Returns a dict keyed by finding_ref. Every ref passed in (after dropping
    empty/duplicate entries) is present in the result -- including a ref with
    zero persisted events, which reconstructs to the same all-defaults dict
    reconstruct_persisted would give it -- and each value is IDENTICAL, field
    for field, to what reconstruct_persisted(ref) returns today. This
    function only changes HOW MANY TIMES the store is read, never what is
    computed; reconstruct_persisted itself is untouched and still what
    server.py's per-finding endpoint calls."""
    refs = [r for r in dict.fromkeys(finding_refs) if r]
    if not refs:
        return {}
    try:
        from harness import store
    except Exception:
        return {}
    try:
        events_by_ref = store.ledger_events_for_many(refs)
    except Exception as e:
        _log.debug("failed to batch-load persisted ledger events for %d ref(s): %s", len(refs), e)
        return {}

    blob_cache: "dict[str, bool]" = {}
    # One shared connection for EVERY blob-hash resolution in this batch,
    # instead of evidence_blob_resolves' own default of a fresh _connect()
    # per call -- this is what keeps the connection count bounded even when
    # every finding's execution carries its OWN distinct request/response
    # hashes (so the {hash: bool} memo above alone wouldn't help): the memo
    # avoids re-resolving the SAME hash twice, this shared connection avoids
    # a new connection for each DIFFERENT hash. Best-effort: if opening it
    # fails, fall back to evidence_blob_resolves' own per-call connection
    # (correct, just not batched) rather than losing resolvability entirely.
    try:
        shared_conn = store._connect()
    except Exception:
        shared_conn = None

    def _memoized_resolver(h: str) -> bool:
        cached = blob_cache.get(h)
        if cached is None:
            try:
                cached = bool(store.evidence_blob_resolves(h, conn=shared_conn))
            except Exception:
                cached = False
            blob_cache[h] = cached
        return cached

    try:
        out: "dict[str, dict]" = {}
        for ref in refs:
            led = _ledger_from_rows(ref, events_by_ref.get(ref, []))
            out[ref] = led.reconstruct(ref, resolver=_memoized_resolver)
        return out
    finally:
        if shared_conn is not None:
            shared_conn.close()


def reproduction_recipe_persisted(finding_ref: str) -> dict:
    """reproduction_recipe(), reading from the durable store instead of memory."""
    return ledger_from_store(finding_ref).reproduction_recipe(finding_ref)
