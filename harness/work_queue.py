"""SC-12: durable WorkItem queue behind the existing engagement graph.

A ``WorkItem`` is one bounded unit of proposed/pending work in the pipeline's
lifecycle -- a detection candidate, a planned bounded probe, an execution, an
independent verification, a reporting read. The queue makes that work *durable*:
it survives a process crash and can be replayed without re-running an external
mutation twice and without silently losing work.

This module is the higher-level API over the ``work_items`` table (the SQL lives
in :mod:`harness.store`, exactly as :mod:`harness.evidence_ledger` sits over the
ledger tables). It owns three things the raw table does not:

* **Stable proof identity.** ``compute_item_id`` derives an item's id from a
  content hash of ``(engagement_id, case_ref, capability, principal, payload)``.
  The id never changes across a retry, so *a failed task is retryable without
  changing its proof identity*, and an external effect can dedupe on the id.
  ``attempt`` / ``priority`` / ``depends_on`` / lease / status are deliberately
  NOT part of it -- they are scheduling state, not the identity of the work.
* **Engagement isolation.** A :class:`WorkQueue` is bound to one
  ``engagement_id``. Leasing, dependency resolution and budget accounting are
  all scoped to that engagement, so *two concurrent engagements cannot lease
  each other's items or share a budget*.
* **Retry / lease policy.** ``lease`` reclaims a crashed peer's expired leases
  first, hands out the highest-priority runnable item, and increments
  ``attempt``; ``fail`` returns an item to ``pending`` until ``max_attempts``,
  then ``dead``; ``complete`` records a durable result and makes the item
  terminal, so replay never re-dispatches finished work.

The queue is a substrate: nothing in the default pipeline dispatches through it
yet, so importing or constructing it sends no traffic and changes no verdict.
API and Burp UI are meant to be adapters over it (SC-12), added later.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from harness import store as _store_module


def compute_item_id(engagement_id: str, case_ref: str, capability: str,
                    principal: str, payload: "dict | None") -> str:
    """Stable content-addressed identity for a unit of work == its proof
    identity. Two enqueues with the same engagement/case/capability/principal/
    payload collapse to the same id (idempotent), while changing what the work
    *does* (payload) or *who/what* it targets changes the id. Scheduling knobs
    (priority, dependencies, attempt, lease) are intentionally excluded so a
    retry or a reprioritisation keeps the same identity."""
    canonical = json.dumps(
        {
            "engagement_id": engagement_id or "",
            "case_ref": case_ref or "",
            "capability": capability or "",
            "principal": principal or "",
            "payload": payload or {},
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return "wi:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


@dataclass
class WorkItem:
    """One durable unit of work. ``item_id`` is the stable proof identity;
    everything below the identity block is mutable scheduling/result state."""

    item_id: str
    engagement_id: str
    case_ref: str = ""
    capability: str = ""
    principal: str = ""
    payload: dict = field(default_factory=dict)
    # scheduling / lifecycle state (never part of item_id)
    priority: int = 0
    depends_on: list = field(default_factory=list)
    budget_reservation: float = 0.0
    status: str = "pending"
    attempt: int = 0
    max_attempts: int = 3
    lease_owner: str = ""
    lease_expiry: float = 0.0
    result_ref: str = ""
    last_error: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0

    def to_row(self) -> dict:
        """Plain dict for harness.store.enqueue_work_item (python-native
        depends_on/payload; the store owns JSON serialisation)."""
        return {
            "item_id": self.item_id,
            "engagement_id": self.engagement_id,
            "case_ref": self.case_ref,
            "capability": self.capability,
            "principal": self.principal,
            "payload": dict(self.payload or {}),
            "priority": int(self.priority),
            "depends_on": list(self.depends_on or []),
            "budget_reservation": float(self.budget_reservation or 0.0),
            "status": self.status,
            "attempt": int(self.attempt),
            "max_attempts": int(self.max_attempts),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_row(cls, row: dict) -> "WorkItem":
        return cls(
            item_id=row["item_id"],
            engagement_id=row["engagement_id"],
            case_ref=row.get("case_ref", ""),
            capability=row.get("capability", ""),
            principal=row.get("principal", ""),
            payload=dict(row.get("payload", {}) or {}),
            priority=int(row.get("priority", 0)),
            depends_on=list(row.get("depends_on", []) or []),
            budget_reservation=float(row.get("budget_reservation", 0.0) or 0.0),
            status=row.get("status", "pending"),
            attempt=int(row.get("attempt", 0)),
            max_attempts=int(row.get("max_attempts", 3)),
            lease_owner=row.get("lease_owner", ""),
            lease_expiry=float(row.get("lease_expiry", 0.0) or 0.0),
            result_ref=row.get("result_ref", ""),
            last_error=row.get("last_error", ""),
            created_at=float(row.get("created_at", 0.0) or 0.0),
            updated_at=float(row.get("updated_at", 0.0) or 0.0),
        )


def _item_id_of(item: "WorkItem | str") -> str:
    return item.item_id if isinstance(item, WorkItem) else str(item)


class WorkQueue:
    """Durable work queue bound to ONE engagement.

    All operations are scoped to ``engagement_id`` -- the queue never reads or
    hands out another engagement's items, and its budget accounting is
    per-engagement. ``store`` (defaulting to :mod:`harness.store`) and ``clock``
    are injectable so tests can drive a temp DB and a controllable clock; the
    store is referenced by module so monkeypatching ``store._DB_PATH`` in tests
    reaches these calls.
    """

    def __init__(self, engagement_id: str, *, store=None, worker: str = "worker",
                 lease_seconds: float = 300.0, default_max_attempts: int = 3,
                 budget_cap: "float | None" = None, clock=time.time):
        if not engagement_id:
            raise ValueError("WorkQueue requires a non-empty engagement_id")
        self.engagement_id = engagement_id
        self._store = store if store is not None else _store_module
        self.worker = worker
        self.lease_seconds = float(lease_seconds)
        self.default_max_attempts = int(default_max_attempts)
        self.budget_cap = budget_cap
        self._clock = clock

    # -- producer side ------------------------------------------------------
    def enqueue(self, capability: str, *, case_ref: str = "", principal: str = "",
                payload: "dict | None" = None, priority: int = 0,
                depends_on=(), budget_reservation: float = 0.0,
                max_attempts: "int | None" = None) -> "WorkItem | None":
        """Idempotently propose a unit of work. Returns the stored WorkItem
        (the existing one on a duplicate enqueue -- same proof identity), or
        None if a budget cap is set and this reservation would exceed it. Never
        writes a duplicate row and never double-counts a re-enqueue's budget."""
        payload = dict(payload or {})
        item_id = compute_item_id(self.engagement_id, case_ref, capability,
                                  principal, payload)
        now = self._clock()
        item = WorkItem(
            item_id=item_id, engagement_id=self.engagement_id, case_ref=case_ref,
            capability=capability, principal=principal, payload=payload,
            priority=priority, depends_on=list(depends_on),
            budget_reservation=float(budget_reservation), status="pending",
            attempt=0, max_attempts=int(max_attempts if max_attempts is not None
                                        else self.default_max_attempts),
            created_at=now, updated_at=now,
        )
        outcome = self._store.enqueue_work_item(item.to_row(), budget_cap=self.budget_cap)
        if outcome == "budget_exceeded":
            return None
        # 'inserted' or 'duplicate': return the authoritative stored row so the
        # caller always sees the canonical item (a duplicate keeps the original).
        return self.get(item_id)

    # -- consumer side ------------------------------------------------------
    def lease(self) -> "WorkItem | None":
        """Claim the highest-priority runnable item for this engagement, or None.
        Reclaims this engagement's expired leases first (crash recovery)."""
        row = self._store.lease_next_work_item(
            self.engagement_id, worker=self.worker, now=self._clock(),
            lease_seconds=self.lease_seconds)
        return WorkItem.from_row(row) if row else None

    def complete(self, item: "WorkItem | str", result_ref: str = "") -> bool:
        """Mark a leased item done with its result reference. True on the
        leased->done transition; False if it was not leased (already done, or
        reclaimed under a stale worker). A done item is never re-dispatched."""
        return self._store.complete_work_item(
            _item_id_of(item), result_ref=result_ref, now=self._clock())

    def fail(self, item: "WorkItem | str", error: str = "") -> str:
        """Record a failed attempt. Returns the resulting status: 'pending'
        (will retry, identity unchanged) or 'dead' (attempts exhausted)."""
        return self._store.fail_work_item(
            _item_id_of(item), error=str(error), now=self._clock())

    def reclaim(self) -> int:
        """Return this engagement's expired-lease items to pending (explicit
        crash recovery / replay entry point). Returns the count reclaimed."""
        return self._store.reclaim_expired_leases(
            now=self._clock(), engagement_id=self.engagement_id)

    # -- reads --------------------------------------------------------------
    def get(self, item_id: str) -> "WorkItem | None":
        row = self._store.get_work_item(item_id)
        return WorkItem.from_row(row) if row else None

    def items(self, *, status: "str | None" = None) -> "list[WorkItem]":
        """This engagement's items (optionally filtered by status), best-first."""
        return [WorkItem.from_row(r)
                for r in self._store.list_work_items(self.engagement_id, status=status)]

    def remaining_budget(self) -> "float | None":
        """Budget left for this engagement, or None when no cap is set. Never
        reflects another engagement's reservations."""
        if self.budget_cap is None:
            return None
        return float(self.budget_cap) - self._store.engagement_budget_reserved(
            self.engagement_id)
