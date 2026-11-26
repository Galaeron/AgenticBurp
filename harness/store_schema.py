"""Connection, schema and migrations of the harness state store.

Every DDL string and schema marker, run in one fixed order by
_initialise_connection, plus the connect path (E9 one-time setup per file).

Part of the ARC-9 split of harness.store. Import these names from harness.store, the facade,
not from this module. A function here reads every store-level name through the facade at
call time (`_store.<name>`), so a patch or assignment on harness.store (`store._DB_PATH = ...`,
`patch.object(store, "_connect")`) reaches it. The facade owns the mutable state; this
module defines functions and constants only.
"""
from __future__ import annotations
import sqlite3
import time
import random
import os
import secrets
from pathlib import Path


_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    agent TEXT NOT NULL,
    vulnerability_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    summary TEXT NOT NULL,
    basis TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    suggested_test TEXT NOT NULL DEFAULT '',
    owasp_category TEXT,
    review_verdict TEXT,
    confirmed INTEGER NOT NULL DEFAULT 0,
    fingerprint TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    prompt_version TEXT NOT NULL DEFAULT '',
    finding_id TEXT NOT NULL DEFAULT '',
    case_id TEXT NOT NULL DEFAULT '',
    proof_id TEXT NOT NULL DEFAULT '',
    oracle_verified INTEGER NOT NULL DEFAULT 0,
    verification_state TEXT NOT NULL DEFAULT 'candidate',
    oracle_capsule_id TEXT NOT NULL DEFAULT '',
    exchange_id TEXT NOT NULL DEFAULT '',
    run_id TEXT NOT NULL DEFAULT '',
    engagement_id TEXT NOT NULL DEFAULT '',
    captured_principal_id TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
"""


_PLAN_SCHEMA = """
CREATE TABLE IF NOT EXISTS test_plans (
    plan_id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    capability TEXT NOT NULL,
    finding_class TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    execution_plane TEXT NOT NULL DEFAULT 'burp',
    status TEXT NOT NULL DEFAULT 'proposed',
    source_exchange_hash TEXT NOT NULL DEFAULT '',
    mutation_json TEXT NOT NULL DEFAULT '{}',
    success_signals_json TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.0,
    escalated INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS validation_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence REAL NOT NULL,
    confirmed INTEGER NOT NULL,
    summary TEXT NOT NULL,
    evidence TEXT NOT NULL,
    created_at REAL NOT NULL,
    FOREIGN KEY(plan_id) REFERENCES test_plans(plan_id)
);
CREATE INDEX IF NOT EXISTS idx_validation_runs_plan ON validation_runs(plan_id);
"""

_CHAIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS chains_detected (
    host TEXT NOT NULL,
    chain_signature TEXT NOT NULL,
    detected_at REAL NOT NULL,
    PRIMARY KEY (host, chain_signature)
);
"""

_COVERAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS coverage_overrides (
    host TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    PRIMARY KEY (host, category)
);
"""

_IDENTITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    notes TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    host TEXT NOT NULL,
    exchange_hash TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    FOREIGN KEY(identity_id) REFERENCES identities(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_identity ON sessions(identity_id);
CREATE INDEX IF NOT EXISTS idx_sessions_host ON sessions(host);
"""

# Astra T01: case-bound structured proof records. Additive -- a new table, so a
# database created by an earlier build gets it via CREATE TABLE IF NOT EXISTS on
# the next _connect() (legacy rows in other tables are untouched and stay readable).
# Append-only: proof_id is unique per attempt, so a later re-run never overwrites an
# earlier confirmed proof of the same case (best_proof_for_case picks the strongest).
_EVIDENCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS proof_records (
    proof_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    principal_id TEXT NOT NULL DEFAULT '',
    request_template_id TEXT NOT NULL DEFAULT '',
    check_id TEXT NOT NULL DEFAULT '',
    parameter_location TEXT NOT NULL DEFAULT '',
    parameter_name TEXT NOT NULL DEFAULT '',
    workflow_state_id TEXT NOT NULL DEFAULT '',
    finding_ref TEXT NOT NULL DEFAULT '',
    validator TEXT NOT NULL DEFAULT '',
    validator_version TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL DEFAULT 'inconclusive',
    executed INTEGER NOT NULL DEFAULT 0,
    legacy INTEGER NOT NULL DEFAULT 0,
    baseline_artifact_id TEXT NOT NULL DEFAULT '',
    attack_artifact_id TEXT NOT NULL DEFAULT '',
    control_artifact_ids_json TEXT NOT NULL DEFAULT '[]',
    expected_invariant TEXT NOT NULL DEFAULT '',
    observed_result TEXT NOT NULL DEFAULT '',
    limitation TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_proof_case ON proof_records(case_id);
CREATE INDEX IF NOT EXISTS idx_proof_run ON proof_records(run_id);
"""

# AR-08a: the policy fingerprint a proof was decided under (ProofRecord.
# policy_fingerprint), so proofs read back from the store group exactly as in-run
# proofs do. Versioned additive migration: a NEW side table keyed on proof_id plus
# the 'proof-identity-schema' marker in state_metadata. proof_records itself is not
# altered and PRAGMA user_version stays the finding-fingerprint re-key's, so the
# legacy schema is unchanged (test_observation_migration). Nothing is backfilled:
# a proof without a row here (written before this table, or by a validator with no
# policy) reads as policy "" -- unknown, which never merges routes. A row of
# another identity_version also reads as "". Rollback: DROP TABLE proof_identity
# and delete the marker; the previous build never reads either.
_PROOF_IDENTITY_VERSION = 1
_PROOF_IDENTITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS proof_identity (
    proof_id TEXT PRIMARY KEY,
    policy_fingerprint TEXT NOT NULL,
    identity_version INTEGER NOT NULL,
    created_at REAL NOT NULL
);
"""

# ProofRecord.evidence_source ("tool_reported": an external tool's detection the
# harness did not reproduce), so a stored proof is accounted like the in-run one.
# Additive side table keyed on proof_id, in proof_identity's pattern: proof_records
# is not altered, nothing is backfilled, and a proof without a row reads as "" (the
# validator's own exchanges). Rollback: DROP TABLE proof_evidence_source; the
# previous build never reads it.
_PROOF_EVIDENCE_SOURCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS proof_evidence_source (
    proof_id TEXT PRIMARY KEY,
    evidence_source TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""

# I16 persistence: the operator's per-target declarations (protected_paths and
# authz.owners-shaped entries), saved only by an explicit save and read only when a
# request opts in (server: PUT /engagement/{host}/declarations, investigate's
# use_saved_declarations). Paths and identity labels only -- entries are validated
# against the RV-S/RV-T grammars before they are written, so no header, cookie,
# token or body can be stored. Versioned additive migration in AR-08a's pattern: a
# NEW side table plus the 'engagement-declarations-schema' marker in state_metadata;
# no legacy table is altered and PRAGMA user_version stays the fingerprint re-key's.
# Keyed on (lower-cased host, effective port), so two services on one host never
# share declarations. A row of another declarations_version reads as nothing saved.
# Rollback: DROP TABLE engagement_declarations and delete the marker; the previous
# build never reads either.
_DECLARATIONS_VERSION = 1
_DECLARATIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement_declarations (
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protected_paths_json TEXT NOT NULL DEFAULT '[]',
    owners_json TEXT NOT NULL DEFAULT '[]',
    declarations_version INTEGER NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (host, port)
);
"""

# Finding dedup (2026-11-03): the input a finding names (parameter_location/
# parameter_name), so a finding with no proof record still reports it -- the
# fingerprint always hashed it, but nothing read it back. Versioned additive
# migration in AR-08a's pattern: a NEW side table keyed on the findings row's
# unique key (fingerprint, case_id) plus the 'finding-inputs-schema' marker in
# state_metadata; findings itself is not altered. Nothing is backfilled: a finding
# with no row here and no proof record was written before this table and reads as
# input_recorded=False ("unknown", never "no input"). '' in both columns is a
# finding that named no input. Rollback: DROP TABLE finding_inputs and delete the
# marker; the previous build never reads either.
_FINDING_INPUTS_VERSION = 1
_FINDING_INPUTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS finding_inputs (
    fingerprint TEXT NOT NULL,
    case_id TEXT NOT NULL,
    parameter_location TEXT NOT NULL,
    parameter_name TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (fingerprint, case_id)
);
"""

# Plan dispatch (2026-11-03): why the harness bound, ran or could not run a
# planner plan (plan_dispatch). Versioned additive side table keyed on
# test_plans.plan_id plus the 'plan-dispatch-schema' marker; test_plans itself is
# not altered. Rollback: DROP TABLE plan_dispatch_notes and delete the marker; the
# previous build never reads either.
_PLAN_DISPATCH_VERSION = 1
_PLAN_DISPATCH_SCHEMA = """
CREATE TABLE IF NOT EXISTS plan_dispatch_notes (
    plan_id TEXT PRIMARY KEY,
    note TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""

# ARC-4 (2026-11-21): the Burp plane's single-use dispatch nonce. One row per
# plan holds the sha256 of the nonce POST /test-plans/{id}/dispatch last issued
# (never the nonce itself), the policy handed to the plane, and when a
# /validation-results submission consumed it. Versioned additive side table
# keyed on test_plans.plan_id plus the 'plane-dispatch-schema' marker. Rollback:
# DROP TABLE plane_dispatches and delete the marker; the previous build never
# reads either, and its /validation-results ignores the extra nonce field.
_PLANE_DISPATCH_VERSION = 1
_PLANE_DISPATCH_SCHEMA = """
CREATE TABLE IF NOT EXISTS plane_dispatches (
    plan_id TEXT PRIMARY KEY,
    nonce_sha256 TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    issued_at REAL NOT NULL,
    consumed_at REAL
);
"""

# P0-1: the durable stream for harness.evidence_ledger.EvidenceLedger. Append-only
# (event_id is the primary key and every write is INSERT OR IGNORE -- a caller
# re-persisting the same event, e.g. after a retry, is a no-op, never an overwrite)
# so the audit trail behind reconstruct()/reproduction_recipe() survives a process
# restart, independent of the in-memory singleton. Purely additive: nothing else
# reads or writes this table, so it cannot change any verdict/severity/scope logic.
_LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    finding_ref TEXT NOT NULL,
    case_ref TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    engagement_id TEXT NOT NULL DEFAULT '',
    captured_principal_id TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_finding_ref ON ledger_events(finding_ref);
"""
# ARC-13 (2026-11-23): tamper evidence for ledger_events. One ledger_chain row per
# chained event (keyed on ledger_events.event_id) holds `seq` (a store-wide,
# increasing append number), `prev_hash` (the `row_hash` of the previous chained
# event of the SAME finding_ref; '' for the first) and `row_hash` (sha256 over the
# event's canonical content and prev_hash -- see evidence_ledger.ledger_row_hash).
# The chain is per finding_ref, not store-wide, because the wipe paths delete a
# finding_ref's events as a whole: a store-wide chain would break at every
# legitimate wipe. Events written before this change have no ledger_chain row and
# read as "unchained legacy". Versioned additive side table plus the
# 'ledger-chain-schema' marker; ledger_events itself is unchanged. Rollback: DROP
# TABLE ledger_chain and delete the marker; the previous build never reads either.
_LEDGER_CHAIN_VERSION = 1
_LEDGER_CHAIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_chain (
    event_id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_chain_seq ON ledger_chain(seq);
"""

# FR-2 (F03): content-addressed, ALREADY-REDACTED request/response evidence blobs.
# This is a NEW persistence sink for exchange bodies/headers (today only a URL and
# an "HTTP {status}" string are ever stored) -- callers (run_context._artifact) MUST
# redact with harness.security before calling put_evidence_blob; this table stores
# bytes verbatim and does not know how to redact. Keyed by sha256(data) so writing
# the same bytes twice is a no-op (INSERT OR IGNORE) and a hash IS the durable proof
# of content identity: evidence_blob_resolves() recomputes the hash of whatever is on
# disk and compares, so a corrupted/truncated row is honestly reported as unresolved
# rather than silently served. Purely additive and read-only from every verdict/
# severity/scope decision's perspective -- only the P0-6 resolvability assessment
# (evidence_ledger._assess_completeness) and report/API display consult it.
_EVIDENCE_BLOB_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_blobs (
    sha256 TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    created_at REAL NOT NULL
);
"""

# Astra T02: observed object-ownership facts (who owns / can reach an object), with
# provenance. Additive; unknown ownership is simply absent (never guessed). The
# principal metadata (tenant/permissions/trust) is added to the existing identities
# table via migration in _connect() -- reusing that storage, not a second registry.
_PRINCIPAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS ownership_facts (
    object_ref TEXT PRIMARY KEY,
    owner_principal_id TEXT NOT NULL DEFAULT '',
    tenant TEXT,
    shared_with_json TEXT NOT NULL DEFAULT '[]',
    public INTEGER NOT NULL DEFAULT 0,
    provenance TEXT NOT NULL DEFAULT '',
    observed_at REAL NOT NULL
);
"""

# P1.8: operator-declared, REVERSIBLE issue-merge overrides (issues.py's
# automatic grouping stays untouched; this is a separate, removable layer on
# top of it). Keyed by (host, source_id) so unmerging is just DELETEing the
# row -- group_findings_into_issues()'s output is recomputed from the
# underlying findings every time, so removing the override row restores the
# original split exactly, with no destructive mutation ever applied to a
# finding or an Issue.
_ISSUE_MERGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS issue_merges (
    host TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (host, source_id)
);
"""

# SC-12: durable WorkItem queue behind the existing engagement graph. A WorkItem
# is one bounded unit of proposed/pending work (detection candidate -> planned
# probe -> execution -> verification -> report) that must survive a crash and be
# replayed WITHOUT re-running an external mutation twice and WITHOUT losing work.
#
# Design invariants (each has a caller-level test + negative control in
# test_work_queue.py):
#   * item_id is the STABLE proof identity -- a content hash of
#     (engagement_id, case_ref, capability, principal, payload). It never
#     changes across a retry, so a failed task is retryable without changing its
#     identity, and an external effect can dedupe on it. attempt / priority /
#     lease / status are deliberately NOT part of it.
#   * INSERT OR IGNORE on item_id makes enqueue idempotent: proposing the same
#     logical work twice is a no-op, never a duplicate row.
#   * engagement_id partitions everything. Leasing, budget reservation and
#     dependency resolution are all scoped to one engagement, so two concurrent
#     engagements can never lease each other's items or share a budget.
#   * status is durable: pending -> leased -> done|dead. A `done` item is never
#     leased again (no duplicate dispatch on replay); a crashed `leased` item
#     whose lease expired is reclaimed to `pending` (no lost work); a failed
#     `leased` item goes back to `pending` until max_attempts, then `dead`.
# One process + SQLite transactions (BEGIN IMMEDIATE) first, per SC-12; no Redis
# / external broker. This table is inert until a caller dispatches through it --
# nothing in the default pipeline writes it, so it sends no traffic on its own.
_WORK_ITEM_SCHEMA = """
CREATE TABLE IF NOT EXISTS work_items (
    item_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    case_ref TEXT NOT NULL DEFAULT '',
    capability TEXT NOT NULL DEFAULT '',
    principal TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0,
    depends_on_json TEXT NOT NULL DEFAULT '[]',
    payload_json TEXT NOT NULL DEFAULT '{}',
    budget_reservation REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_expiry REAL NOT NULL DEFAULT 0,
    result_ref TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_work_items_lease
    ON work_items(engagement_id, status, priority);
"""

# I02-C: supplied observations, retained whether or not they produced a finding,
# so a later analysis of the same endpoint can compare against them. Immutable
# capture facts live in exchange_observations (only the deletion tombstone ever
# updates a row); correctable analyst attribution is an append-only revision
# stream in observation_attributions (the highest revision is current). Scope is
# (host, engagement_id): '' is the site's shared pile, a nonempty id a named
# pile. exchange_id is the same value persist_findings records, so
# finding_observations remains the finding<->exchange link. Additive: an older
# database gains both empty tables on its next _connect(); nothing is backfilled
# from findings, because a finding summary is not a captured observation.
_OBSERVATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS exchange_observations (
    observation_id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    engagement_id TEXT NOT NULL DEFAULT '',
    exchange_id TEXT NOT NULL,
    id_source TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    captured_principal_id TEXT NOT NULL,
    method TEXT NOT NULL,
    url_redacted TEXT NOT NULL DEFAULT '',
    normalized_endpoint TEXT NOT NULL,
    captured_at REAL,
    ingested_at REAL NOT NULL,
    capture_source TEXT NOT NULL DEFAULT 'unknown',
    completeness TEXT NOT NULL DEFAULT 'unknown',
    state_version TEXT,
    facts_json TEXT NOT NULL DEFAULT '{}',
    evidence_sha256 TEXT NOT NULL DEFAULT '',
    evidence_truncated INTEGER NOT NULL DEFAULT 0,
    first_run_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    deleted_at REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_exchange_observations_scope
    ON exchange_observations(host, engagement_id, exchange_id);
CREATE INDEX IF NOT EXISTS idx_exchange_observations_endpoint
    ON exchange_observations(host, engagement_id, normalized_endpoint);
CREATE TABLE IF NOT EXISTS observation_attributions (
    observation_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    engagement_id TEXT NOT NULL DEFAULT '',
    principal_ref TEXT,
    role TEXT,
    tenant TEXT,
    session_ref TEXT,
    source TEXT NOT NULL DEFAULT 'unknown',
    reason TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    PRIMARY KEY (observation_id, revision)
);
"""


# Concurrent first callers on a fresh on-disk DB race on schema setup: switching
# to WAL and the check-then-act migrations below all take a write lock, and SQLite
# returns SQLITE_BUSY *immediately* -- bypassing busy_timeout -- when a connection
# holding a read lock from a PRAGMA table_info() must upgrade to write while a peer
# already holds one (its deadlock-avoidance path). So busy_timeout alone does not
# save the losers; they fail fast with "database is locked" and, unclosed, go on to
# lock the DB file (a Windows teardown error in the test). The whole setup is
# idempotent (CREATE IF NOT EXISTS, guarded ALTERs, DROP/CREATE INDEX IF EXISTS,
# user_version guard), so on a lock error we close and retry: once any caller wins,
# the losers reopen an already-migrated DB and sail through.
_CONNECT_MAX_ATTEMPTS = 12
_CONNECT_RETRY_BASE_SLEEP = 0.02


def _db_identity(conn: sqlite3.Connection) -> tuple[str, tuple] | None:
    """(absolute path, file identity) for the database `conn` is open on, or None
    when it cannot be read (no file yet, in-memory, or locked mid-setup)."""
    try:
        st = os.stat(_store._DB_PATH)
        version = conn.execute("PRAGMA schema_version").fetchone()[0]
    except (OSError, sqlite3.Error):
        return None
    # A creation time tells a recreated file from the original. Windows reports it
    # as st_ctime; macOS/BSD as st_birthtime. Linux has neither (st_ctime there is
    # the inode CHANGE time, which moves on every write and would make the file
    # look new on each connect); a recreated file still differs by inode or by
    # schema_version (a fresh file reads 0).
    born = (st.st_ctime_ns if os.name == "nt"
            else getattr(st, "st_birthtime_ns", None) or int(getattr(st, "st_birthtime", 0) * 1e9))
    return os.path.abspath(_store._DB_PATH), (st.st_dev, st.st_ino, born, version)


def timing_snapshot() -> dict:
    """Plain-data view of connection and snapshot-write timing (E9)."""
    with _store._STATS_LOCK:
        connect = {k: (round(v, 3) if isinstance(v, float) else v) for k, v in _store._CONNECT_STATS.items()}
        save = {k: (round(v, 3) if isinstance(v, float) else v) for k, v in _store._SAVE_ENGAGEMENT_STATS.items()}
    return {**connect, "save_engagement": save}


def _connect() -> sqlite3.Connection:
    started = time.perf_counter()
    try:
        return _store._connect_counted()
    finally:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        with _store._STATS_LOCK:
            _store._CONNECT_STATS["connects"] += 1
            _store._CONNECT_STATS["connect_ms"] += elapsed_ms
            _store._CONNECT_STATS["max_connect_ms"] = max(_store._CONNECT_STATS["max_connect_ms"], elapsed_ms)


def _connect_counted() -> sqlite3.Connection:
    last_exc: sqlite3.OperationalError | None = None
    for attempt in range(_store._CONNECT_MAX_ATTEMPTS):
        conn = sqlite3.connect(_store._DB_PATH, timeout=10.0)
        try:
            identity = _store._db_identity(conn)
            if identity is not None and _store._INITIALISED.get(identity[0]) == identity[1]:
                conn.execute("PRAGMA busy_timeout=10000")
                with _store._STATS_LOCK:
                    _store._CONNECT_STATS["skipped_initialisations"] += 1
                return conn
            init_started = time.perf_counter()
            _store._initialise_connection(conn)
            after = _store._db_identity(conn)
            if after is not None:
                with _store._INIT_LOCK:
                    _store._INITIALISED[after[0]] = after[1]
            with _store._STATS_LOCK:
                _store._CONNECT_STATS["initialisations"] += 1
                _store._CONNECT_STATS["init_ms"] += (time.perf_counter() - init_started) * 1000.0
            return conn
        except sqlite3.OperationalError as exc:
            conn.close()
            if "locked" not in str(exc).lower():
                raise
            last_exc = exc
            time.sleep(_store._CONNECT_RETRY_BASE_SLEEP * (attempt + 1) + random.random() * 0.01)
        except BaseException:
            # Setup can fail outside SQLite's OperationalError class too.
            # Ownership transfers to the caller only after successful setup.
            conn.close()
            raise
    assert last_exc is not None  # loop only exits early via return/raise
    raise last_exc


def _initialise_connection(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript(_store._SCHEMA)
    conn.executescript(_store._PLAN_SCHEMA)
    conn.executescript(_store._CHAIN_SCHEMA)
    conn.executescript(_store._COVERAGE_SCHEMA)
    conn.executescript(_store._IDENTITY_SCHEMA)
    conn.executescript(_store._EVIDENCE_SCHEMA)
    conn.executescript(_store._PROOF_IDENTITY_SCHEMA)
    conn.executescript(_store._PROOF_EVIDENCE_SOURCE_SCHEMA)
    conn.executescript(_store._DECLARATIONS_SCHEMA)
    conn.executescript(_store._FINDING_INPUTS_SCHEMA)
    conn.executescript(_store._PLAN_DISPATCH_SCHEMA)
    conn.executescript(_store._PLANE_DISPATCH_SCHEMA)
    conn.executescript(_store._PRINCIPAL_SCHEMA)
    conn.executescript(_store._ISSUE_MERGE_SCHEMA)
    conn.executescript(_store._LEDGER_SCHEMA)
    conn.executescript(_store._LEDGER_CHAIN_SCHEMA)
    conn.executescript(_store._EVIDENCE_BLOB_SCHEMA)
    conn.executescript(_store._WORK_ITEM_SCHEMA)
    conn.executescript(_store._OBSERVATION_SCHEMA)
    conn.execute("CREATE TABLE IF NOT EXISTS state_metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT OR IGNORE INTO state_metadata VALUES ('principal-hmac-v1', ?)", (secrets.token_hex(32),))
    # I02-C schema marker. PRAGMA user_version is reserved for the fingerprint
    # re-key below; bumping it here would make a future re-key skip.
    conn.execute("INSERT OR IGNORE INTO state_metadata VALUES ('observation-schema', '1')")
    conn.execute("INSERT OR IGNORE INTO state_metadata VALUES ('proof-identity-schema', ?)",
                 (str(_store._PROOF_IDENTITY_VERSION),))
    conn.execute("INSERT OR IGNORE INTO state_metadata VALUES ('engagement-declarations-schema', ?)",
                 (str(_store._DECLARATIONS_VERSION),))
    conn.execute("INSERT OR IGNORE INTO state_metadata VALUES ('finding-inputs-schema', ?)",
                 (str(_store._FINDING_INPUTS_VERSION),))
    conn.execute("INSERT OR IGNORE INTO state_metadata VALUES ('plan-dispatch-schema', ?)",
                 (str(_store._PLAN_DISPATCH_VERSION),))
    conn.execute("INSERT OR IGNORE INTO state_metadata VALUES ('plane-dispatch-schema', ?)",
                 (str(_store._PLANE_DISPATCH_VERSION),))
    conn.execute("INSERT OR IGNORE INTO state_metadata VALUES ('ledger-chain-schema', ?)",
                 (str(_store._LEDGER_CHAIN_VERSION),))
    ledger_cols ={row[1] for row in conn.execute("PRAGMA table_info(ledger_events)")}
    if "engagement_id" not in ledger_cols:
        try:
            conn.execute("ALTER TABLE ledger_events ADD COLUMN engagement_id TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc):
                raise
    if "captured_principal_id" not in ledger_cols:
        try:
            conn.execute("ALTER TABLE ledger_events ADD COLUMN captured_principal_id TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc):
                raise
    # Lightweight migration for databases created by earlier builds.
    plan_cols = {row[1] for row in conn.execute("PRAGMA table_info(test_plans)")}
    for col, ddl in [
        ("source_exchange_hash", "ALTER TABLE test_plans ADD COLUMN source_exchange_hash TEXT NOT NULL DEFAULT ''"),
        ("mutation_json", "ALTER TABLE test_plans ADD COLUMN mutation_json TEXT NOT NULL DEFAULT '{}'"),
        ("success_signals_json", "ALTER TABLE test_plans ADD COLUMN success_signals_json TEXT NOT NULL DEFAULT '[]'"),
        ("category", "ALTER TABLE test_plans ADD COLUMN category TEXT NOT NULL DEFAULT ''"),
        ("execution_plane", "ALTER TABLE test_plans ADD COLUMN execution_plane TEXT NOT NULL DEFAULT 'burp'"),
        ("severity", "ALTER TABLE test_plans ADD COLUMN severity TEXT NOT NULL DEFAULT ''"),
        ("confidence", "ALTER TABLE test_plans ADD COLUMN confidence REAL NOT NULL DEFAULT 0.0"),
        ("escalated", "ALTER TABLE test_plans ADD COLUMN escalated INTEGER NOT NULL DEFAULT 0"),
    ]:
        if col not in plan_cols:
            conn.execute(ddl)

    proof_cols = {row[1] for row in conn.execute("PRAGMA table_info(proof_records)")}
    if "finding_ref" not in proof_cols:
        conn.execute("ALTER TABLE proof_records ADD COLUMN finding_ref TEXT NOT NULL DEFAULT ''")

    cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    if "confirmed" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 0")
    if "fingerprint" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
        rows = conn.execute("SELECT id, host, method, url, vulnerability_class FROM findings WHERE fingerprint = ''").fetchall()
        for row in rows:
            fid = _store.finding_fingerprint(row[1], row[2], row[3], row[4])
            conn.execute("UPDATE findings SET fingerprint = ? WHERE id = ?", (fid, row[0]))
    if "model" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN model TEXT NOT NULL DEFAULT ''")
    if "prompt_version" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN prompt_version TEXT NOT NULL DEFAULT ''")
    if "evidence" not in cols:
        # Added for report generation: a submission-ready report needs the
        # "why we believe this" detail, not just the one-line summary that
        # was the only thing persisted before. Existing rows get an empty
        # string, same fallback pattern as the other migrated columns above.
        conn.execute("ALTER TABLE findings ADD COLUMN evidence TEXT NOT NULL DEFAULT ''")
    if "suggested_test" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN suggested_test TEXT NOT NULL DEFAULT ''")
    if "owasp_category" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN owasp_category TEXT")
    for col in ("finding_id", "case_id", "proof_id"):
        if col not in cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
    if "engagement_id" not in cols:
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN engagement_id TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc):
                raise
    if "captured_principal_id" not in cols:
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN captured_principal_id TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc):
                raise
    # Oracle-verification axis (precision items #1/#2): the stricter verified/candidate
    # state and the id of the proof capsule that earned it. Additive, defaults keep
    # every legacy row a "candidate" (no oracle ever ran on it).
    if "oracle_verified" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN oracle_verified INTEGER NOT NULL DEFAULT 0")
    if "verification_state" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN verification_state TEXT NOT NULL DEFAULT 'candidate'")
    if "oracle_capsule_id" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN oracle_capsule_id TEXT NOT NULL DEFAULT ''")
    # AR-3 (LOOP half): exact finding->exchange provenance, additive. `exchange_id`
    # is the capture-driver-supplied HttpExchange.capture_id (or, when absent, a
    # stable content hash -- see persist_findings) and `run_id` the run that
    # produced the finding (from telemetry's ambient current-run binding). Neither
    # column feeds finding_fingerprint or the unique dedup index below -- they are
    # provenance metadata only. Legacy rows default to '' and stay valid/readable.
    if "exchange_id" not in cols:
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN exchange_id TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc):
                raise
    if "run_id" not in cols:
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN run_id TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc):
                raise
    # T06/R08: dedup on (fingerprint, case_id), not fingerprint alone, so a
    # patched-fixture RETEST -- same coordinates, a NEW case identity -- is retained
    # as its own row (append-only retest history) instead of being IGNORE'd. Legacy
    # findings (empty case_id) still dedup by fingerprint. Suppression is unchanged:
    # it keys on `fingerprint` alone, so suppressing a finding still suppresses every
    # case-variant that shares its coordinates across runs. The old fingerprint-only
    # unique index is dropped first so the composite key takes effect on old DBs.
    conn.execute("DROP INDEX IF EXISTS idx_findings_fingerprint")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint_case "
                 "ON findings(fingerprint, case_id)")

    # W-9: re-fingerprint rows written by the old summary-based formula so they
    # dedup consistently with new writes. Guarded by PRAGMA user_version so it
    # runs once per DB, and after the unique index exists. UPDATE OR IGNORE: if a
    # recomputed (fingerprint, case_id) would collide with an existing row, skip
    # it (it keeps its old fingerprint) rather than erroring on the unique index.
    # Old rows are re-keyed structurally (host/method/endpoint/class); parameter
    # and identity coordinates live in proof_records, not the findings table, so
    # migrated rows use the coordinate-free structure -- enough to drop the
    # summary volatility this migration exists to remove.
    if conn.execute("PRAGMA user_version").fetchone()[0] < _store._FINGERPRINT_ALGO_VERSION:
        for row in conn.execute(
            "SELECT id, host, method, url, vulnerability_class, engagement_id, captured_principal_id FROM findings"
        ).fetchall():
            new_fp = _store.finding_fingerprint(row[1], row[2], row[3], row[4], engagement_id=row[5],
                                         principal_id=row[6] if row[5] else "")
            conn.execute("UPDATE OR IGNORE findings SET fingerprint = ? WHERE id = ?",
                         (new_fp, row[0]))
        conn.execute(f"PRAGMA user_version = {_store._FINGERPRINT_ALGO_VERSION}")

    # T02: additive principal metadata on the existing identities table (reuse the
    # store, don't fork a second identity registry). Old rows default to unknown
    # tenant / no declared permissions / trust=1.
    ident_cols = {row[1] for row in conn.execute("PRAGMA table_info(identities)")}
    for col, ddl in [
        ("tenant", "ALTER TABLE identities ADD COLUMN tenant TEXT"),
        ("permissions_json", "ALTER TABLE identities ADD COLUMN permissions_json TEXT NOT NULL DEFAULT '[]'"),
        ("trust", "ALTER TABLE identities ADD COLUMN trust INTEGER NOT NULL DEFAULT 1"),
    ]:
        if col not in ident_cols:
            # Concurrent _connect() callers can all see `col` missing before any of
            # them commits the ALTER (check-then-act race, not a single-writer
            # invariant here). Swallow only the "already added it" outcome so a
            # loser of the race doesn't raise; any other OperationalError is real.
            try:
                conn.execute(ddl)
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc):
                    raise

    # Cross-run finding suppression -- see suppress_finding()'s docstring
    # for the workflow this exists for. Keyed on the same `fingerprint`
    # persist_findings() already computes, not a new identity scheme.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_suppressions (
            fingerprint TEXT PRIMARY KEY,
            reason TEXT NOT NULL DEFAULT '',
            suppressed_at REAL NOT NULL
        )
    """)
    # Engagement state (engagement.py) -- the per-host shared surface/identity
    # model, persisted as a JSON snapshot so the fused worklist survives across
    # requests and restarts. One row per host; the whole state is rewritten on
    # save (it's small: endpoint metadata, not bodies).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS engagement_state (
            host TEXT PRIMARY KEY,
            state_json TEXT NOT NULL,
            updated_at REAL NOT NULL
        )
    """)
    # Explicit engagement ownership; legacy host-only rows remain readable
    # only in the empty-id compatibility partition.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scoped_engagement_state (
            engagement_id TEXT NOT NULL,
            host TEXT NOT NULL,
            revision INTEGER NOT NULL,
            state_json TEXT NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (engagement_id, host)
        )
    """)
    # Retrievable knowledge notes (knowledge.py's Memory Retriever) -- tester-
    # authored methodology writeups and auto-remembered confirmed findings,
    # merged with the built-in corpus at decision time. `source` distinguishes
    # them (manual | finding); `fingerprint` de-dupes. `engagement_id` (P2.3):
    # '' means globally shared (every legacy row, and every note saved without
    # an explicit scope -- unchanged prior behaviour); a non-empty value is a
    # PRIVATE note visible only when that same engagement_id is queried --
    # never to a different engagement (see list_knowledge_notes).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS knowledge_notes (
            fingerprint TEXT PRIMARY KEY,
            tags_json TEXT NOT NULL DEFAULT '[]',
            note TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'manual',
            created_at REAL NOT NULL,
            engagement_id TEXT NOT NULL DEFAULT ''
        )
    """)
    knowledge_cols = {row[1] for row in conn.execute("PRAGMA table_info(knowledge_notes)")}
    if "engagement_id" not in knowledge_cols:
        conn.execute("ALTER TABLE knowledge_notes ADD COLUMN engagement_id TEXT NOT NULL DEFAULT ''")

    # AR-3 (LOOP half): finding -> exchange provenance link table. One row per
    # (finding, exchange) OBSERVATION -- so a finding that is deduped by the
    # findings table's (fingerprint, case_id) unique index (INSERT OR IGNORE)
    # still records every distinct exchange that produced it, not just the
    # first-seen one. Scored/read by exchange-first attribution (see
    # testing/blind-target-2/run_blind_eval.py's build_scorecard); never used
    # for dedup itself.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_observations (
            fingerprint TEXT NOT NULL,
            run_id TEXT NOT NULL DEFAULT '',
            exchange_id TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_observations_unique
        ON finding_observations(fingerprint, run_id, exchange_id)
    """)
    conn.commit()

_PROOF_COLUMNS = (
    "proof_id, run_id, case_id, principal_id, request_template_id, check_id, "
    "parameter_location, parameter_name, workflow_state_id, finding_ref, validator, validator_version, "
    "verdict, executed, legacy, baseline_artifact_id, attack_artifact_id, "
    "control_artifact_ids_json, expected_invariant, observed_result, limitation, created_at"
)
# AR-08a: every proof read joins its persisted policy fingerprint ("" when absent).
_PROOF_SELECT = (
    ", ".join(f"p.{col.strip()}" for col in _PROOF_COLUMNS.split(","))
    + ", COALESCE(i.policy_fingerprint, ''), COALESCE(es.evidence_source, '')"
    " FROM proof_records p LEFT JOIN proof_identity i"
    f" ON i.proof_id = p.proof_id AND i.identity_version = {_PROOF_IDENTITY_VERSION}"
    " LEFT JOIN proof_evidence_source es ON es.proof_id = p.proof_id"
)


def _open_read_only(db_path) -> sqlite3.Connection:
    """A read-only connection that never creates, migrates or locks the file --
    what a verifier run against a delivered copy of the store needs."""
    path = Path(db_path if db_path is not None else _store._DB_PATH)
    if not path.is_file():
        raise FileNotFoundError(f"no store at {path}")
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=10.0)


# The facade, bound last: the functions above read harness.store names through it at call
# time, and binding it here lets this module be imported before harness.store.
from harness import store as _store  # noqa: E402
