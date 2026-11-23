"""Evidence-ledger repository of the harness state store.

ledger_events and the ARC-13 ledger_chain side table, written together in
one transaction by persist_ledger_event.

Part of the ARC-9 split of harness.store. Import these names from harness.store, the facade,
not from this module. A function here reads every store-level name through the facade at
call time (`_store.<name>`), so a patch or assignment on harness.store (`store._DB_PATH = ...`,
`patch.object(store, "_connect")`) reaches it. The facade owns the mutable state; this
module defines functions and constants only.
"""
from __future__ import annotations
import time
import json


# ---------------------------------------------------------------------------
# P0-1: EvidenceLedger persistence -- the durable stream behind
# reconstruct()/reproduction_recipe(). Read-only from every other module's
# perspective: nothing here is consulted by any verdict, severity, scope, or
# gate decision -- it is purely a record of what already happened.
# ---------------------------------------------------------------------------

def persist_ledger_event(event: dict) -> None:
    """Append one harness.evidence_ledger.LedgerEvent.to_dict() to the durable
    stream. INSERT OR IGNORE keyed on event_id keeps this append-only: a
    caller that persists the same event twice (e.g. a retried emit) is a
    no-op, never an overwrite. Best-effort by design -- callers (evidence_
    ledger.emit) already swallow any exception this raises, so a storage
    hiccup here can never surface as a pipeline failure.

    ARC-13: the event is hash-chained in ledger_chain (see _LEDGER_CHAIN_SCHEMA).
    Reading the finding's chain head, taking the next `seq` and inserting both rows
    happen inside ONE `BEGIN IMMEDIATE` transaction: SQLite grants the write lock to
    one connection at a time, across threads and processes, so two appends can
    never read the same head and fork the chain, and no event is stored without
    its chain row."""
    from harness.evidence_ledger import ledger_row_hash
    fields = {
        "event_id": event.get("event_id", ""), "event_type": event.get("event_type", ""),
        "finding_ref": event.get("finding_ref", ""), "case_ref": event.get("case_ref", ""),
        "summary": event.get("summary", ""),
        "data_json": json.dumps(event.get("data", {}) or {}),
        "provenance_json": json.dumps(event.get("provenance", {}) or {}),
        "engagement_id": _store._CURRENT_ENGAGEMENT.get(),
        "captured_principal_id": _store._CURRENT_CAPTURED_PRINCIPAL.get(),
        # float() first: the column is REAL, so the hash must cover the value read back.
        "created_at": float(event.get("created_at", time.time())),
    }
    conn = _store._connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM ledger_events WHERE event_id = ?",
                        (fields["event_id"],)).fetchone():
            conn.rollback()          # a re-persisted event is a no-op, never an overwrite
            return
        head = conn.execute(
            "SELECT c.row_hash FROM ledger_chain c JOIN ledger_events e ON e.event_id = c.event_id "
            "WHERE e.finding_ref = ? ORDER BY c.seq DESC LIMIT 1", (fields["finding_ref"],)).fetchone()
        prev_hash = head[0] if head else ""
        seq = conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM ledger_chain").fetchone()[0]
        row_hash = ledger_row_hash(prev_hash=prev_hash, seq=seq, **fields)
        conn.execute(
            "INSERT INTO ledger_events "
            "(event_id, event_type, finding_ref, case_ref, summary, data_json, "
            "provenance_json, engagement_id, captured_principal_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (fields["event_id"], fields["event_type"], fields["finding_ref"], fields["case_ref"],
             fields["summary"], fields["data_json"], fields["provenance_json"],
             fields["engagement_id"], fields["captured_principal_id"], fields["created_at"]))
        conn.execute("INSERT INTO ledger_chain (event_id, seq, prev_hash, row_hash) VALUES (?, ?, ?, ?)",
                     (fields["event_id"], seq, prev_hash, row_hash))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


_LEDGER_CHAIN_COLUMNS = ("event_id", "event_type", "finding_ref", "case_ref", "summary", "data_json",
                         "provenance_json", "engagement_id", "captured_principal_id", "created_at",
                         "seq", "prev_hash", "row_hash")


_LEDGER_CHAIN_LINK = ("seq", "prev_hash", "row_hash")


def iter_ledger_chain_rows(db_path=None):
    """Every ledger_events row, joined to its ledger_chain row, as a dict of
    _LEDGER_CHAIN_COLUMNS in append order (`seq`, then insertion order), for
    harness.evidence_ledger.verify_ledger_rows.

    Reads the file at `db_path` (default: the live store) read-only and tolerates a
    store written before ARC-13: an event without a chain row (or a store without
    ledger_chain, or a column an older build never added) reads as the legacy
    defaults, so it verifies as "unchained legacy"."""
    conn = _store._open_read_only(db_path)
    try:
        present = {row[1] for row in conn.execute("PRAGMA table_info(ledger_events)")}
        if not present:
            return
        chained = bool(conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ledger_chain'").fetchone())
        columns = []
        for c in _store._LEDGER_CHAIN_COLUMNS:
            default = "0" if c == "seq" else "''"
            if c in _store._LEDGER_CHAIN_LINK:
                columns.append(f"COALESCE(c.{c}, {default}) AS {c}" if chained else f"{default} AS {c}")
            else:
                columns.append(f"e.{c}" if c in present else f"{default} AS {c}")
        join = " LEFT JOIN ledger_chain c ON c.event_id = e.event_id" if chained else ""
        order = "COALESCE(c.seq, 0), e.rowid" if chained else "e.rowid"
        for row in conn.execute(f"SELECT {', '.join(columns)} FROM ledger_events e{join} ORDER BY {order}"):
            yield dict(zip(_store._LEDGER_CHAIN_COLUMNS, row))
    finally:
        conn.close()


def ledger_events_for(finding_ref: str, *, engagement_id: str | None = None,
                      captured_principal: str | None = None) -> list[dict]:
    """All persisted ledger events for one finding, oldest first, as plain
    dicts shaped like LedgerEvent.to_dict() (ready for
    harness.evidence_ledger.ledger_from_store to replay)."""
    conn = _store._connect()
    try:
        ownership = " AND engagement_id = ?" if engagement_id is not None else ""
        params = (finding_ref, _store._engagement_partition(engagement_id)) if engagement_id is not None else (finding_ref,)
        if captured_principal is not None:
            ownership += " AND captured_principal_id = ?"
            params += (captured_principal,)
        rows = conn.execute(
            "SELECT event_id, event_type, finding_ref, case_ref, summary, data_json, "
            "provenance_json, created_at FROM ledger_events WHERE finding_ref = ? "
            + ownership + " ORDER BY created_at ASC", params).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        out.append({
            "event_id": r[0], "event_type": r[1], "finding_ref": r[2], "case_ref": r[3],
            "summary": r[4], "data": json.loads(r[5] or "{}"),
            "provenance": json.loads(r[6] or "{}"), "created_at": r[7],
        })
    return out


def ledger_events_for_many(finding_refs: "list[str]", *, engagement_id: str | None = None,
                           captured_principal: str | None = None) -> "dict[str, list[dict]]":
    """Batched form of ledger_events_for (RA-4): every persisted ledger event
    for MANY findings in ONE query/connection, instead of one fresh
    connection+query per finding_ref. Grouped by finding_ref; each ref's own
    list is in the SAME oldest-first order (`ORDER BY created_at ASC`, the
    identical clause ledger_events_for uses) and the SAME row shape --
    calling this with `[ref]` and reading `result.get(ref, [])` gives exactly
    what `ledger_events_for(ref)` would.

    A `finding_ref` with no persisted events is simply ABSENT from the
    result (never an empty-list placeholder) -- the same "no rows" outcome
    ledger_events_for reports for that ref alone. Falsy/duplicate entries in
    `finding_refs` are dropped before querying; an empty/all-falsy
    `finding_refs` short-circuits to `{}` WITHOUT opening a connection at
    all, since there is nothing to fetch."""
    refs = [r for r in dict.fromkeys(finding_refs) if r]
    if not refs:
        return {}
    conn = _store._connect()
    try:
        placeholders = ",".join("?" for _ in refs)
        ownership = " AND engagement_id = ?" if engagement_id is not None else ""
        params = refs + [_store._engagement_partition(engagement_id)] if engagement_id is not None else refs
        if captured_principal is not None:
            ownership += " AND captured_principal_id = ?"
            params = params + [captured_principal]
        rows = conn.execute(
            "SELECT event_id, event_type, finding_ref, case_ref, summary, data_json, "
            "provenance_json, created_at FROM ledger_events WHERE finding_ref IN "
            f"({placeholders})" + ownership + " ORDER BY created_at ASC", params).fetchall()
    finally:
        conn.close()
    out: "dict[str, list[dict]]" = {}
    for r in rows:
        out.setdefault(r[2], []).append({
            "event_id": r[0], "event_type": r[1], "finding_ref": r[2], "case_ref": r[3],
            "summary": r[4], "data": json.loads(r[5] or "{}"),
            "provenance": json.loads(r[6] or "{}"), "created_at": r[7],
        })
    return out


# The facade, bound last: the functions above read harness.store names through it at call
# time, and binding it here lets this module be imported before harness.store.
from harness import store as _store  # noqa: E402
