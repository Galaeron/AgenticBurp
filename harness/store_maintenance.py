"""Retention, wipe and engagement-close paths of the harness state store.

Evidence-blob retention, the host-scoped wipe, and listing, closing and
expiring per-engagement stores.

Part of the ARC-9 split of harness.store. Import these names from harness.store, the facade,
not from this module. A function here reads every store-level name through the facade at
call time (`_store.<name>`), so a patch or assignment on harness.store (`store._DB_PATH = ...`,
`patch.object(store, "_connect")`) reaches it. The facade owns the mutable state; this
module defines functions and constants only.
"""
from __future__ import annotations
import sqlite3
import time
import json
import os
import secrets
from pathlib import Path


# ---------------------------------------------------------------------------
# P3-1 (partial): retention/expiry for evidence_blobs. Config-gated, OFF by
# default (evidence_retention_days=0 => keep-forever, today's current
# behavior, byte-identical). Purging is safe because evidence_blob_resolves()
# (store_proofs) already reports a deleted (or corrupted) blob as unresolved, and
# blobs are read-only w.r.t. every verdict/severity/scope decision (see the
# _EVIDENCE_BLOB_SCHEMA comment). Nothing calls these automatically yet --
# wiring this to a scheduler/endpoint, and a "wipe engagement" action, are
# later P3-1 slices.
# ---------------------------------------------------------------------------

def purge_evidence_blobs_older_than(max_age_seconds: float, *, now: float | None = None) -> int:
    """Delete evidence blobs whose created_at is older than `max_age_seconds`
    before `now` (defaults to time.time()). Returns the number of rows deleted.
    A max_age_seconds <= 0 is a no-op returning 0 (retention disabled)."""
    if max_age_seconds <= 0:
        return 0
    cutoff = (now if now is not None else time.time()) - max_age_seconds
    conn = _store._connect()
    try:
        cur = conn.execute("DELETE FROM evidence_blobs WHERE created_at < ?", (cutoff,))
        conn.commit()
    finally:
        conn.close()
    return cur.rowcount


def apply_retention_policy(retention_days: float, *, now: float | None = None) -> int:
    """Explicit maintenance seam: purge evidence blobs older than
    `retention_days`. retention_days <= 0 (the shipped default) => disabled,
    no-op returning 0. Returns rows deleted. Wiring this to a scheduler/endpoint
    is a later P3-1 slice."""
    if retention_days <= 0:
        return 0
    return _store.purge_evidence_blobs_older_than(retention_days * 86400.0, now=now)


def apply_retention_from_config(cfg: dict, *, now: float | None = None) -> int:
    """Read store.evidence_retention_days (default 0 = disabled) from a config
    dict and apply it. This is the config->mechanism consumer, so the config
    key is not dead; the default 0 makes it a no-op (byte-identical to today)."""
    days = float((cfg.get("store") or {}).get("evidence_retention_days", 0) or 0)
    return _store.apply_retention_policy(days, now=now)


# ---------------------------------------------------------------------------
# P3-1 (partial): the explicit "wipe engagement" action -- host-scoped
# deletion of a host's persisted evidence. Callable-only: nothing in this
# codebase invokes it automatically (no server endpoint/startup wiring --
# that wiring, if ever wanted, is a later P3-1 slice), mirroring the already-
# landed retention functions above.
#
# Table inventory (every CREATE TABLE in store_schema was checked; each is
# either touched below via a column CONFIRMED to exist on it, or deliberately
# left out and documented here rather than guessed at):
#
#   Touched, by confirmed column:
#     findings              -- host
#     test_plans             -- host
#     chains_detected        -- host
#     coverage_overrides     -- host
#     sessions               -- host
#     issue_merges           -- host
#     engagement_state       -- host
#     finding_suppressions   -- fingerprint (structurally host-scoped: `host`
#                                is the first component hashed into
#                                finding_fingerprint(), so two different
#                                hosts never share a fingerprint)
#     finding_observations   -- fingerprint (the SAME fingerprint persist_
#                                findings() computes and writes there)
#     exchange_observations  -- host (I02-C; every pile on that host); its
#                                evidence_sha256 joins the blob guard below
#     observation_attributions -- observation_id of those observations
#     proof_records          -- case_id / finding_ref / proof_id (all three
#                                are real columns on this table; a row
#                                matching any of them belongs to one of the
#                                target host's findings)
#     proof_identity         -- proof_id no longer in proof_records (AR-08a)
#     finding_inputs         -- fingerprint (finding dedup; same fingerprints
#                                as finding_observations)
#     engagement_declarations -- host, or host:port (I16 persistence)
#     ledger_events          -- finding_ref (sizes case_ids UNION finding_ids
#                                of the target host's findings -- see the
#                                blob-guard comment below for why)
#     ledger_chain           -- event_id of those ledger_events (ARC-13),
#                                deleted just before them
#     evidence_blobs         -- sha256, but ONLY the `candidate -
#                                other_referenced` subset (see below); this
#                                table has no host column at all -- it is
#                                content-addressed, so a column-based filter
#                                would be actively wrong here.
#
#     plane_dispatches / plan_dispatch_notes -- plan_id into test_plans.host,
#                          deleted the same way as validation_runs below; the
#                          plane's "plan:<plan_id>" ledger events (and their
#                          ledger_chain rows) go with them
#
#     validation_runs  -- no host column of its own; scoped via `plan_id` FK
#                          into test_plans.host and wiped with the correlated
#                          subquery `plan_id IN (SELECT plan_id FROM test_plans
#                          WHERE host=?)` BEFORE the test_plans delete (there is
#                          no ON DELETE CASCADE and _connect() leaves PRAGMA
#                          foreign_keys off, so this explicit delete is required
#                          to avoid orphaned rows).
#
#   Deliberately LEFT OUT (no confirmed host/finding_ref/case_id/fingerprint
#   column on the table itself -- a documented follow-on, not a guess):
#     identities       -- no host column; identities are not engagement-
#                          scoped in this schema (an identity/session label
#                          can outlive any one engagement).
#     ownership_facts  -- keyed by `object_ref`, not host/finding_ref/case_id/
#                          fingerprint; whether an object_ref belongs to one
#                          host is not decidable from a confirmed column.
#     knowledge_notes  -- its `fingerprint` is a DIFFERENT identity space
#                          (sha256 of tags+note+engagement_id, computed in
#                          save_knowledge_note -- see that function) than
#                          findings.fingerprint, so it cannot be joined to a
#                          host via that column; notes are also explicitly
#                          engagement_id-scoped (private) or globally shared
#                          (engagement_id==''), a different scoping axis than
#                          `host` entirely.
#
# THE LOAD-BEARING CORRECTNESS RULE: evidence_blobs is content-addressed
# (sha256(bytes) is the primary key), so the SAME bytes referenced by two
# different hosts is ONE shared row. Blanket-deleting every blob hash the
# target host's ledger_events reference would silently destroy evidence a
# DIFFERENT, unrelated host still needs. So we compute, from a single
# connection/transaction and BEFORE any DELETE below:
#   candidate        = blob hashes referenced by the TARGET host's
#                       ledger_events (finding_ref IN target case_ids UNION
#                       target finding_ids)
#   other_referenced = blob hashes referenced by ANY OTHER host's
#                       ledger_events, from a SNAPSHOT of every other host's
#                       case_ids/finding_ids taken before this call deletes
#                       anything -- so the "other host" set can never be
#                       corrupted mid-wipe by our own deletes.
# and only ever delete `candidate - other_referenced`. A blob shared by two
# hosts therefore survives exactly as long as at least one host still
# references it.
# ---------------------------------------------------------------------------

def _ledger_blob_hashes(conn: sqlite3.Connection, refs: set[str]) -> set[str]:
    """The set of evidence_blobs sha256 hashes referenced (as `request_blob`
    or `response_blob` inside data_json -- see run_context._artifact) by
    ledger_events whose finding_ref is in `refs`. Empty `refs` short-circuits
    to an empty set rather than issuing `IN ()`."""
    if not refs:
        return set()
    placeholders = ",".join("?" for _ in refs)
    rows = conn.execute(
        f"SELECT data_json FROM ledger_events WHERE finding_ref IN ({placeholders})",
        list(refs),
    ).fetchall()
    hashes: set[str] = set()
    for (data_json,) in rows:
        try:
            data = json.loads(data_json or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        for key in ("request_blob", "response_blob"):
            h = data.get(key)
            if h:
                hashes.add(h)
    return hashes


def wipe_engagement(host: str) -> dict:
    """Explicit, callable-only "wipe engagement" action: permanently delete
    every row this store persisted for `host`, across every table where a
    CONFIRMED column ties a row back to it (see the table inventory in the
    module comment directly above this function). Nothing auto-invokes this;
    it exists to be called deliberately (e.g. a future explicit operator
    action), not wired to any server endpoint or startup path here.

    Returns {table_name: rows_deleted} for every table this function knows
    how to scope to a host -- including 0 for ones with nothing to delete,
    so a caller can always tell "ran and found nothing" from "didn't run".
    An unknown/empty host is a clean no-op: every count is 0 and nothing is
    deleted (every IN-clause below is guarded against an empty set, so an
    empty identity set skips the DELETE entirely rather than issuing SQL
    `IN ()`, which SQLite would accept anyway but which is not what an empty
    set should mean here).

    All deletes run inside ONE connection/transaction (a single commit at
    the end), so a shared evidence blob can never be dropped mid-wipe while
    another host still references it -- see the blob-guard comment above.
    """
    conn = _store._connect()
    try:
        # (a) The target host's identity sets, read from `findings` -- the
        # only table where `host` is a directly-owned column tying every
        # other identity (case_id/finding_id/fingerprint/proof_id) back to
        # one engagement.
        target_rows = conn.execute(
            "SELECT case_id, finding_id, fingerprint, proof_id FROM findings WHERE host = ?",
            (host,),
        ).fetchall()
        target_case_ids = {r[0] for r in target_rows if r[0]}
        target_finding_ids = {r[1] for r in target_rows if r[1]}
        target_fingerprints = {r[2] for r in target_rows if r[2]}
        target_proof_ids = {r[3] for r in target_rows if r[3]}
        target_refs = target_case_ids | target_finding_ids

        # (b) Snapshot every OTHER host's identity space now, before any
        # delete below -- so the blob-sharing guard can never be corrupted
        # mid-wipe by our own deletes of the target host's rows.
        other_rows = conn.execute(
            "SELECT case_id, finding_id FROM findings WHERE host != ?", (host,)
        ).fetchall()
        other_refs = {r[0] for r in other_rows if r[0]} | {r[1] for r in other_rows if r[1]}

        candidate = _store._ledger_blob_hashes(conn, target_refs)
        other_referenced = _store._ledger_blob_hashes(conn, other_refs)
        # I02-C: observation evidence follows the same shared-blob rule -- the
        # target host's observation blobs are candidates, and any blob another
        # host's observation names is protected.
        target_observations = conn.execute(
            "SELECT observation_id, evidence_sha256 FROM exchange_observations WHERE host = ?",
            (host,)).fetchall()
        target_observation_ids = {r[0] for r in target_observations}
        candidate |= {r[1] for r in target_observations if r[1]}
        other_referenced |= {r[0] for r in conn.execute(
            "SELECT evidence_sha256 FROM exchange_observations WHERE host != ? AND evidence_sha256 != ''",
            (host,))}
        blobs_to_delete = candidate - other_referenced

        counts: dict[str, int] = {}

        if target_observation_ids:
            placeholders = ",".join("?" for _ in target_observation_ids)
            cur = conn.execute(
                f"DELETE FROM observation_attributions WHERE observation_id IN ({placeholders})",
                list(target_observation_ids))
            counts["observation_attributions"] = cur.rowcount
        else:
            counts["observation_attributions"] = 0
        cur = conn.execute("DELETE FROM exchange_observations WHERE host = ?", (host,))
        counts["exchange_observations"] = cur.rowcount

        # (c) evidence_blobs -- ONLY the target-only subset computed above.
        if blobs_to_delete:
            placeholders = ",".join("?" for _ in blobs_to_delete)
            cur = conn.execute(
                f"DELETE FROM evidence_blobs WHERE sha256 IN ({placeholders})",
                list(blobs_to_delete),
            )
            counts["evidence_blobs"] = cur.rowcount
        else:
            counts["evidence_blobs"] = 0

        # (d) ledger_events -- finding_ref IN (case_ids UNION finding_ids). ARC-13:
        # their ledger_chain rows go first (the subquery needs the events).
        if target_refs:
            placeholders = ",".join("?" for _ in target_refs)
            counts["ledger_chain"] = conn.execute(
                "DELETE FROM ledger_chain WHERE event_id IN (SELECT event_id FROM ledger_events "
                f"WHERE finding_ref IN ({placeholders}))", list(target_refs)).rowcount
            cur = conn.execute(
                f"DELETE FROM ledger_events WHERE finding_ref IN ({placeholders})",
                list(target_refs),
            )
            counts["ledger_events"] = cur.rowcount
        else:
            counts["ledger_chain"] = counts["ledger_events"] = 0

        # (e) proof_records -- case_id, finding_ref, and proof_id are all
        # real, confirmed columns on this table; a row matching any of them
        # belongs to one of the target host's findings.
        if target_refs or target_proof_ids:
            clauses = []
            params: list[str] = []
            if target_refs:
                clauses.append(f"case_id IN ({','.join('?' for _ in target_refs)})")
                params.extend(target_refs)
                clauses.append(f"finding_ref IN ({','.join('?' for _ in target_refs)})")
                params.extend(target_refs)
            if target_proof_ids:
                clauses.append(f"proof_id IN ({','.join('?' for _ in target_proof_ids)})")
                params.extend(target_proof_ids)
            cur = conn.execute(
                f"DELETE FROM proof_records WHERE {' OR '.join(clauses)}", params
            )
            counts["proof_records"] = cur.rowcount
        else:
            counts["proof_records"] = 0
        # AR-08a: a proof's persisted fingerprint goes with the proof.
        counts["proof_identity"] = conn.execute(
            "DELETE FROM proof_identity WHERE proof_id NOT IN (SELECT proof_id FROM proof_records)"
        ).rowcount
        conn.execute("DELETE FROM proof_evidence_source "
                     "WHERE proof_id NOT IN (SELECT proof_id FROM proof_records)")

        # (f) finding_observations -- fingerprint IN fingerprints.
        if target_fingerprints:
            placeholders = ",".join("?" for _ in target_fingerprints)
            cur = conn.execute(
                f"DELETE FROM finding_observations WHERE fingerprint IN ({placeholders})",
                list(target_fingerprints),
            )
            counts["finding_observations"] = cur.rowcount
        else:
            counts["finding_observations"] = 0
        # Finding dedup: the inputs the target host's findings named.
        if target_fingerprints:
            placeholders = ",".join("?" for _ in target_fingerprints)
            counts["finding_inputs"] = conn.execute(
                f"DELETE FROM finding_inputs WHERE fingerprint IN ({placeholders})",
                list(target_fingerprints)).rowcount
        else:
            counts["finding_inputs"] = 0

        # (g) every other confirmed host/fingerprint-scoped table.
        # validation_runs has no host column and no ON DELETE CASCADE (and
        # _connect() does not enable PRAGMA foreign_keys), so it must be wiped
        # via its plan_id FK into test_plans BEFORE test_plans is deleted --
        # otherwise the subquery finds no plan_ids and the rows orphan. The
        # correlated subquery makes an unknown/empty host a clean 0-row no-op.
        cur = conn.execute(
            "DELETE FROM validation_runs WHERE plan_id IN "
            "(SELECT plan_id FROM test_plans WHERE host = ?)",
            (host,),
        )
        counts["validation_runs"] = cur.rowcount

        conn.execute("DELETE FROM plan_dispatch_notes WHERE plan_id IN "
                     "(SELECT plan_id FROM test_plans WHERE host = ?)", (host,))
        # ARC-4: the plane's dispatch nonces, and the dispatch/submission/refusal
        # ledger events the server keys on "plan:<plan_id>".
        conn.execute("DELETE FROM plane_dispatches WHERE plan_id IN "
                     "(SELECT plan_id FROM test_plans WHERE host = ?)", (host,))
        counts["ledger_chain"] += conn.execute(
            "DELETE FROM ledger_chain WHERE event_id IN (SELECT event_id FROM ledger_events "
            "WHERE finding_ref IN (SELECT 'plan:' || plan_id FROM test_plans WHERE host = ?))",
            (host,)).rowcount
        counts["ledger_events"] += conn.execute(
            "DELETE FROM ledger_events WHERE finding_ref IN "
            "(SELECT 'plan:' || plan_id FROM test_plans WHERE host = ?)", (host,)).rowcount
        cur = conn.execute("DELETE FROM test_plans WHERE host = ?", (host,))
        counts["test_plans"] = cur.rowcount

        cur = conn.execute("DELETE FROM chains_detected WHERE host = ?", (host,))
        counts["chains_detected"] = cur.rowcount

        cur = conn.execute("DELETE FROM coverage_overrides WHERE host = ?", (host,))
        counts["coverage_overrides"] = cur.rowcount

        cur = conn.execute("DELETE FROM sessions WHERE host = ?", (host,))
        counts["sessions"] = cur.rowcount

        cur = conn.execute("DELETE FROM issue_merges WHERE host = ?", (host,))
        counts["issue_merges"] = cur.rowcount

        if target_fingerprints:
            placeholders = ",".join("?" for _ in target_fingerprints)
            cur = conn.execute(
                f"DELETE FROM finding_suppressions WHERE fingerprint IN ({placeholders})",
                list(target_fingerprints),
            )
            counts["finding_suppressions"] = cur.rowcount
        else:
            counts["finding_suppressions"] = 0

        # (h) findings itself -- last, since (a) above already captured
        # every identity this call needs from it.
        cur = conn.execute("DELETE FROM findings WHERE host = ?", (host,))
        counts["findings"] = cur.rowcount

        # (i) engagement_state.
        cur = conn.execute("DELETE FROM engagement_state WHERE host = ?", (host,))
        counts["engagement_state"] = cur.rowcount
        cur = conn.execute("DELETE FROM scoped_engagement_state WHERE host = ?", (host,))
        counts["scoped_engagement_state"] = cur.rowcount
        # I16: the operator's saved declarations for this host (any port when the
        # caller names the bare host, one port when it names host:port).
        cur = conn.execute(
            "DELETE FROM engagement_declarations WHERE host = lower(?) OR host || ':' || port = lower(?)",
            (host, host))
        counts["engagement_declarations"] = cur.rowcount
        # HU-1: the operator's access-matrix answers for this host, every
        # engagement (the bare host covers every port, host:port only that one).
        # The table is created on first save, so a store without it has none.
        try:
            cur = conn.execute(
                "DELETE FROM access_matrix_answers WHERE host = lower(?) "
                "OR substr(host, 1, length(?) + 1) = lower(?) || ':'", (host, host, host))
            counts["access_matrix_answers"] = cur.rowcount
        except sqlite3.OperationalError:
            counts["access_matrix_answers"] = 0

        conn.commit()
        return counts
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# OPS-5: list, close and expire engagement stores (layout in store_layout).
# Close is the one destructive path: it always exports first, and
# data_maintenance.close_engagement_store does the file work.
# ---------------------------------------------------------------------------

def list_engagement_stores() -> list[dict]:
    """Every engagement store under engagements_root() whose manifest names the
    engagement its directory is keyed by. Reads metadata only, never rows."""
    root = _store.engagements_root()
    if not root.is_dir():
        return []
    stores = []
    active = _store.active_engagement()
    for directory in sorted(root.iterdir()):
        if directory.name.startswith(".") or directory.is_symlink() or not directory.is_dir():
            continue
        engagement_id = _store._manifest_engagement(directory)
        try:
            if engagement_id is None or _store.engagement_store_key(engagement_id) != directory.name:
                continue
        except ValueError:
            continue
        mtimes = []
        for entry in directory.iterdir():
            try:
                if entry.is_file():
                    mtimes.append(entry.stat().st_mtime)
            except OSError:   # removed by a concurrent close
                continue
        stores.append({"engagement_id": engagement_id, "key": directory.name, "path": str(directory),
                       "active": engagement_id == active, "last_write": max(mtimes, default=0.0)})
    return stores


def close_engagement(engagement_id: str, *, export_root: Path | str | None = None,
                     now: float | None = None) -> dict:
    """Close one engagement: export, then remove, its own store and the rows the
    legacy single store attributes to it (engagement_id column). Other
    engagements' stores, unattributed legacy rows and evidence blobs another
    engagement still references are untouched.

    Refuses the engagement this process is storing into (EngagementStoreActive)
    and raises LookupError when nothing is stored for it. The export goes to a
    new directory under `export_root` (default: engagement_exports/ beside the
    legacy store) and is complete before anything is removed. Removal deletes
    files and rows; it is not secure erasure (the disk must be encrypted)."""
    from harness import data_maintenance
    engagement_id = _store._named_engagement_id(engagement_id)
    if _store.active_engagement() == engagement_id:
        raise _store.EngagementStoreActive("this process is storing into that engagement; select another "
                                    "engagement (or none) before closing it")
    legacy = _store.legacy_store_path()
    directory = _store.engagement_store_dir(engagement_id)
    leftovers = _store.interrupted_closes(engagement_id)
    if leftovers:
        # Recover an interrupted close: put the set-aside store back, then close it.
        if len(leftovers) > 1 or directory.exists() or _store._manifest_engagement(leftovers[0]) != engagement_id:
            raise ValueError("an interrupted close left data aside that needs manual review")
        os.rename(leftovers[0], directory)
    store_dir = None
    if directory.exists() or directory.is_symlink():
        if directory.is_symlink() or not directory.is_dir() or _store._manifest_engagement(directory) != engagement_id:
            raise ValueError("engagement store directory does not belong to this engagement")
        store_dir = directory
    legacy_db = legacy if data_maintenance.context_row_count(legacy, engagement_id) else None
    if store_dir is None and legacy_db is None:
        raise LookupError("nothing is stored for this engagement")
    root = Path(export_root) if export_root is not None else legacy.parent / _store._EXPORTS_DIRNAME
    if root.resolve().is_relative_to(_store.engagements_root().resolve()):
        raise ValueError("the export directory must not be inside the engagement stores")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now if now is not None else time.time()))
    export_dir = root / f"{_store.engagement_store_key(engagement_id)}-{stamp}-{secrets.token_hex(3)}"
    try:
        receipt = data_maintenance.close_engagement_store(
            engagement_id, store_dir=store_dir, legacy_db=legacy_db, export_dir=export_dir)
    except data_maintenance.StoreInUse:
        raise _store.EngagementStoreActive("another process is storing into that engagement; stop it "
                                    "(or select another engagement there) before closing") from None
    for path in list(_store._INITIALISED):
        if store_dir is not None and Path(path).parent == Path(os.path.abspath(store_dir)):
            with _store._INIT_LOCK:
                _store._INITIALISED.pop(path, None)
    return receipt


def engagement_retention_days(cfg: dict) -> float:
    """store.engagement_retention_days from a config dict: 0 (the shipped
    default) or absent means engagement stores never expire."""
    raw = (cfg.get("store") or {}).get("engagement_retention_days", 0)
    if raw is None:
        return 0.0
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not 0 <= raw < float("inf"):
        raise ValueError("store.engagement_retention_days must be a finite number >= 0")
    return float(raw)


def expired_engagement_stores(retention_days: float, *, now: float | None = None) -> list[dict]:
    """Engagement stores not written for `retention_days` days, excluding the one
    this process stores into. retention_days <= 0 means none ever expire."""
    if retention_days <= 0:
        return []
    cutoff = (now if now is not None else time.time()) - retention_days * 86400.0
    return [entry for entry in _store.list_engagement_stores()
            if not entry["active"] and entry["last_write"] < cutoff]


def apply_engagement_retention(retention_days: float, *, apply: bool = False,
                               export_root: Path | str | None = None,
                               now: float | None = None) -> dict:
    """The optional retention TTL. Lists expired engagement stores; only with
    apply=True does it close each one (export first, as close_engagement)."""
    expired = _store.expired_engagement_stores(retention_days, now=now)
    result = {"retention_days": retention_days, "applied": bool(apply),
              "expired": [entry["engagement_id"] for entry in expired], "closed": []}
    if apply:
        result["failed"] = []
        for entry in expired:
            # One store that cannot close (in use, a locked file) must not hide
            # the receipts of the stores already closed.
            try:
                result["closed"].append(_store.close_engagement(entry["engagement_id"], export_root=export_root,
                                                         now=now))
            except (LookupError, ValueError, OSError, sqlite3.Error) as exc:
                result["failed"].append({"engagement_id": entry["engagement_id"],
                                         "error_type": type(exc).__name__})
    return result


# The facade, bound last: the functions above read harness.store names through it at call
# time, and binding it here lets this module be imported before harness.store.
from harness import store as _store  # noqa: E402
