"""Engagement-state repository of the harness state store.

Engagement snapshots, knowledge notes, chain markers, the coverage ledger,
identities, sessions, ownership facts and I16 declarations.

Part of the ARC-9 split of harness.store. Import these names from harness.store, the facade,
not from this module. A function here reads every store-level name through the facade at
call time (`_store.<name>`), so a patch or assignment on harness.store (`store._DB_PATH = ...`,
`patch.object(store, "_connect")`) reaches it. The facade owns the mutable state; this
module defines functions and constants only.
"""
from __future__ import annotations
import time
import hashlib
import json

from harness.categories import CANONICAL_CATEGORIES


class EngagementRevisionConflict(ValueError):
    """A caller tried to replace an engagement snapshot using a stale revision."""


def _read_engagement(conn, host: str, engagement_id: str) -> tuple[dict | None, int]:
    row = conn.execute(
        "SELECT state_json, revision FROM scoped_engagement_state WHERE engagement_id=? AND host=?",
        (engagement_id, host)).fetchone()
    if row is None and not engagement_id:
        legacy = conn.execute("SELECT state_json FROM engagement_state WHERE host=?", (host,)).fetchone()
        row = (legacy[0], 0) if legacy else None
    if row is None:
        return None, 0
    state = json.loads(row[0])
    if not isinstance(state, dict):
        raise ValueError("invalid engagement snapshot")
    return state, row[1]


def _write_engagement(conn, host, engagement_id, state, revision):
    snapshot = dict(state)
    snapshot.update(host=host, _engagement_id=engagement_id, _snapshot_revision=revision)
    state_json = json.dumps(snapshot)
    _store._ENGAGEMENT_WRITE.bytes = len(state_json)   # ensure_ascii: one byte per char
    conn.execute(
        "INSERT INTO scoped_engagement_state (engagement_id,host,revision,state_json,updated_at) "
        "VALUES (?,?,?,?,?) ON CONFLICT(engagement_id,host) DO UPDATE SET "
        "revision=excluded.revision,state_json=excluded.state_json,updated_at=excluded.updated_at",
        (engagement_id, host, revision, state_json, time.time()))
    return snapshot


def save_engagement(host: str, state: dict, *, engagement_id: str = "",
                    expected_revision: int | None = None) -> dict:
    """Replace a snapshot, rejecting stale revisions when provided/loaded.

    New read/modify/write callers should use mutate_engagement. Legacy callers
    supplying an unversioned whole snapshot retain replacement semantics.
    """
    engagement_id = _store._engagement_partition(engagement_id)
    if "_engagement_id" in state and state["_engagement_id"] != engagement_id:
        raise _store.EngagementRevisionConflict("engagement snapshot belongs to another partition")
    if expected_revision is None:
        expected_revision = state.get("_snapshot_revision")
    started = time.perf_counter()
    _store._ENGAGEMENT_WRITE.bytes = 0
    conn = _store._connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        _, revision = _store._read_engagement(conn, host, engagement_id)
        if expected_revision is not None and expected_revision != revision:
            raise _store.EngagementRevisionConflict("stale engagement snapshot revision")
        out = _store._write_engagement(conn, host, engagement_id, state, revision + 1)
        conn.commit()
        return out
    finally:
        if conn.in_transaction:
            conn.rollback()
        conn.close()
        elapsed_ms, written = (time.perf_counter() - started) * 1000.0, _store._ENGAGEMENT_WRITE.bytes
        with _store._STATS_LOCK:
            _store._SAVE_ENGAGEMENT_STATS["calls"] += 1
            _store._SAVE_ENGAGEMENT_STATS["bytes"] += written
            _store._SAVE_ENGAGEMENT_STATS["ms"] += elapsed_ms
            _store._SAVE_ENGAGEMENT_STATS["max_bytes"] = max(_store._SAVE_ENGAGEMENT_STATS["max_bytes"], written)
            _store._SAVE_ENGAGEMENT_STATS["max_ms"] = max(_store._SAVE_ENGAGEMENT_STATS["max_ms"], elapsed_ms)


def load_engagement(host: str, *, engagement_id: str = "") -> dict | None:
    """Read only the requested (engagement_id, host) partition, with revision."""
    engagement_id = _store._engagement_partition(engagement_id)
    conn = _store._connect()
    try:
        state, revision = _store._read_engagement(conn, host, engagement_id)
        if state is not None:
            state.update(_engagement_id=engagement_id, _snapshot_revision=revision)
        return state
    finally:
        conn.close()


def mutate_engagement(host: str, mutator, *, engagement_id: str = "",
                      expected_revision: int | None = None) -> dict:
    """Atomically read/apply/save a benign snapshot mutation.

    The callback is synchronous and must perform no network/model/store I/O.
    BEGIN IMMEDIATE serializes writers across connections/processes. Errors
    roll back without publishing a partial snapshot; revisions are monotonic.
    """
    engagement_id = _store._engagement_partition(engagement_id)
    conn = _store._connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        state, revision = _store._read_engagement(conn, host, engagement_id)
        if expected_revision is not None and expected_revision != revision:
            raise _store.EngagementRevisionConflict("stale engagement snapshot revision")
        updated = mutator(state or {"host": host})
        if not isinstance(updated, dict):
            raise ValueError("engagement mutator must return a snapshot dictionary")
        out = _store._write_engagement(conn, host, engagement_id, updated, revision + 1)
        conn.commit()
        return out
    finally:
        if conn.in_transaction:
            conn.rollback()
        conn.close()


def save_knowledge_note(tags: list, note: str, source: str = "manual", engagement_id: str = "") -> bool:
    """Persist a retrievable knowledge note (idempotent by content WITHIN a
    scope -- the fingerprint folds in engagement_id so the same note text
    saved privately for two different engagements is two distinct rows, never
    a collision that silently drops the second one). `engagement_id=""`
    (default, unchanged prior behaviour) is the globally-shared scope; a
    non-empty value marks the note PRIVATE to that engagement (P2.3). Returns
    whether a new row was inserted."""
    note = (note or "").strip()
    if not note:
        return False
    fp = hashlib.sha256(
        ("|".join(sorted(tags)) + "\x1f" + note + "\x1f" + (engagement_id or "")).encode("utf-8")
    ).hexdigest()[:24]
    conn = _store._connect()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO knowledge_notes "
            "(fingerprint, tags_json, note, source, created_at, engagement_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (fp, json.dumps(list(tags)), note, source, time.time(), engagement_id or ""))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def list_knowledge_notes(limit: int = 500, engagement_id: str | None = None) -> list[dict]:
    """Stored knowledge notes, newest first, scoped for cross-engagement
    privacy (P2.3):

      - `engagement_id=None` (default, unchanged prior behaviour): only the
        globally-shared notes (engagement_id == '').
      - `engagement_id="some-id"`: the globally-shared notes PLUS that
        engagement's own private notes -- never another engagement's private
        notes. A private note saved under one engagement_id is therefore
        structurally unreachable from any other engagement_id or from the
        global-only default."""
    conn = _store._connect()
    try:
        if engagement_id is None:
            rows = conn.execute(
                "SELECT tags_json, note, source, created_at, engagement_id FROM knowledge_notes "
                "WHERE engagement_id = '' ORDER BY created_at DESC LIMIT ?", (int(limit),)).fetchall()
        else:
            rows = conn.execute(
                "SELECT tags_json, note, source, created_at, engagement_id FROM knowledge_notes "
                "WHERE engagement_id = '' OR engagement_id = ? "
                "ORDER BY created_at DESC LIMIT ?", (engagement_id, int(limit))).fetchall()
    finally:
        conn.close()
    out = []
    for tags_json, note, source, ts, eng_id in rows:
        try:
            tags = json.loads(tags_json)
        except (json.JSONDecodeError, TypeError):
            tags = []
        out.append({"tags": tags, "note": note, "source": source, "created_at": ts,
                    "engagement_id": eng_id})
    return out


def is_chain_already_detected(url: str, signature: str, *, engagement_id: str = "") -> bool:
    if engagement_id:
        signature = json.dumps([_store._engagement_partition(engagement_id), signature])
    host = _store.host_of(url)
    conn = _store._connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM chains_detected WHERE host = ? AND chain_signature = ?",
            (host, signature),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def mark_chain_detected(url: str, signature: str, *, engagement_id: str = "") -> None:
    if engagement_id:
        signature = json.dumps([_store._engagement_partition(engagement_id), signature])
    host = _store.host_of(url)
    conn = _store._connect()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO chains_detected (host, chain_signature, detected_at) VALUES (?, ?, ?)",
            (host, signature, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


# --- Coverage ledger --------------------------------------------------
#
# A per-category status derived PURELY from stored evidence (findings,
# test_plans, validation_runs) -- never from a free-text or LLM-settable
# field. This is the whole point: an agent (or a careless human) writing
# "confirmed" directly into a status column would recreate exactly the
# checkbox-theater problem this exists to solve. The only human-settable
# input is coverage_overrides, and it is restricted to a single value,
# 'not_applicable', so it can be used to say "this doesn't apply here"
# but never to assert that something was tested when it wasn't.
#
# Status vocabulary:
#   confirmed       - a validation_runs row with confirmed=1 exists
#   supported       - positive evidence exists, but nothing independently confirmed it
#                     (a validation_runs row of status "supported", or "observed": an
#                     evidence-only capability's result, which can never confirm)
#   blocked         - the only validation attempt errored out (tool missing, timeout, etc.)
#   tested_clean    - independently tested and no evidence found
#   not_tested      - a specialist flagged this category but no validation was ever run
#   not_dispatched  - no exchange on this host ever triggered this specialist at all
#   not_applicable  - analyst override; see set_coverage_override


_NO_ACTIVE_VALIDATOR = {"misconfig", "ai_llm", "supply_chain",
                        "insecure_transport", "missing_headers", "bfla"}


def set_coverage_override(host: str, category: str, reason: str) -> None:
    """Analyst-only annotation that a category doesn't apply to this
    target. Deliberately cannot express anything except NOT_APPLICABLE --
    see module docstring above for why that restriction is load-bearing."""
    if category not in CANONICAL_CATEGORIES:
        raise ValueError(f"unknown category: {category!r}")
    conn = _store._connect()
    try:
        conn.execute(
            """INSERT INTO coverage_overrides (host, category, status, reason, created_at)
               VALUES (?, ?, 'not_applicable', ?, ?)
               ON CONFLICT(host, category) DO UPDATE SET
                   reason = excluded.reason, created_at = excluded.created_at""",
            (host, category, reason, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def clear_coverage_override(host: str, category: str) -> None:
    conn = _store._connect()
    try:
        conn.execute(
            "DELETE FROM coverage_overrides WHERE host = ? AND category = ?",
            (host, category),
        )
        conn.commit()
    finally:
        conn.close()


def coverage_report(host: str) -> list[dict]:
    """Derive the per-category coverage ledger for a host. Returns a list
    with one entry per category in categories.CANONICAL_CATEGORIES, each
    carrying a status and (where applicable) a pointer to the specific
    evidence row that produced it -- so the status is auditable, not just
    asserted."""
    conn = _store._connect()
    try:
        overrides = dict(
            conn.execute(
                "SELECT category, reason FROM coverage_overrides WHERE host = ?", (host,)
            ).fetchall()
        )
        dispatched = {
            row[0] for row in
            conn.execute("SELECT DISTINCT agent FROM findings WHERE host = ?", (host,))
        }
        rows = conn.execute(
            """SELECT tp.category, tp.plan_id, vr.status, vr.confirmed, vr.summary, vr.id
               FROM test_plans tp
               LEFT JOIN validation_runs vr ON vr.plan_id = tp.plan_id
               WHERE tp.host = ? AND tp.category != ''
               ORDER BY vr.created_at DESC""",
            (host,),
        ).fetchall()
    finally:
        conn.close()

    by_category: dict[str, list[tuple]] = {}
    for category, plan_id, status, confirmed, summary, run_id in rows:
        by_category.setdefault(category, []).append((plan_id, status, confirmed, summary, run_id))

    report = []
    for category in CANONICAL_CATEGORIES:
        if category in overrides:
            report.append({"category": category, "status": "not_applicable",
                            "reason": overrides[category], "evidence": None})
            continue

        runs = by_category.get(category, [])
        confirmed_run = next((r for r in runs if r[2]), None)
        supported_run = next((r for r in runs if r[1] in ("supported", "observed")), None)
        error_run = next((r for r in runs if r[1] == "error"), None)
        clean_run = next((r for r in runs if r[1] in ("rejected", "not_confirmed")), None)

        if confirmed_run:
            report.append({"category": category, "status": "confirmed", "evidence":
                            {"plan_id": confirmed_run[0], "validation_run_id": confirmed_run[4], "summary": confirmed_run[3]}})
        elif supported_run:
            report.append({"category": category, "status": "supported", "evidence":
                            {"plan_id": supported_run[0], "validation_run_id": supported_run[4], "summary": supported_run[3]}})
        elif error_run:
            report.append({"category": category, "status": "blocked", "reason": error_run[3], "evidence":
                            {"plan_id": error_run[0], "validation_run_id": error_run[4]}})
        elif clean_run:
            report.append({"category": category, "status": "tested_clean", "evidence":
                            {"plan_id": clean_run[0], "validation_run_id": clean_run[4], "summary": clean_run[3]}})
        elif category in dispatched:
            note = ("no active validation capability exists for this category yet"
                    if category in _store._NO_ACTIVE_VALIDATOR else
                    "flagged by a specialist agent but no validation was executed")
            report.append({"category": category, "status": "not_tested", "reason": note, "evidence": None})
        else:
            report.append({"category": category, "status": "not_dispatched",
                            "reason": "no exchange on this host triggered this specialist", "evidence": None})
    return report


def save_identity(identity) -> None:
    """`identity` is an identity.Identity -- imported lazily by callers to
    avoid a store<->identity circular import; store.py stays the only
    module that knows SQL."""
    conn = _store._connect()
    try:
        conn.execute(
            """INSERT INTO identities (id, name, role, notes, created_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 name=excluded.name, role=excluded.role, notes=excluded.notes,
                 created_at=excluded.created_at""",
            (
                identity.id, identity.name,
                # `hasattr(..., "value")` fallback: defensive, not currently
                # load-bearing. Checked during audit -- the only production
                # call site (server.py's POST /identities) always constructs
                # `identity.role` via `IdentityRole(req.role)`, which raises
                # (turned into a 400) on any value that isn't a real enum
                # member, before an Identity object ever reaches this
                # function. This fallback exists for callers that might
                # someday pass a raw string directly (e.g. a future internal
                # helper that skips the HTTP layer's validation), not because
                # any current caller does. If you add such a caller, prefer
                # validating at that new call site over relying on this
                # fallback silently accepting an unvalidated string.
                identity.role.value if hasattr(identity.role, "value") else identity.role,
                identity.notes, identity.created_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def list_identities() -> list[dict]:
    conn = _store._connect()
    try:
        rows = conn.execute("SELECT id, name, role, notes, created_at FROM identities ORDER BY created_at").fetchall()
        return [{"id": r[0], "name": r[1], "role": r[2], "notes": r[3], "created_at": r[4]} for r in rows]
    finally:
        conn.close()


def get_identity(identity_id: str) -> dict | None:
    conn = _store._connect()
    try:
        row = conn.execute("SELECT id, name, role, notes, created_at FROM identities WHERE id = ?", (identity_id,)).fetchone()
        if not row:
            return None
        return {"id": row[0], "name": row[1], "role": row[2], "notes": row[3], "created_at": row[4]}
    finally:
        conn.close()


def save_session(session) -> None:
    """`session` is an identity.Session."""
    conn = _store._connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, identity_id, host, exchange_hash, label, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session.id, session.identity_id, session.host, session.exchange_hash, session.label, session.created_at),
        )
        conn.commit()
    finally:
        conn.close()


def sessions_for_host(host: str) -> list[dict]:
    """All sessions captured for a host, joined with the identity name --
    this is what replaces manually picking a captured exchange out of a
    JOptionPane list with no persistent identity label attached to it."""
    conn = _store._connect()
    try:
        rows = conn.execute(
            """SELECT s.id, s.identity_id, i.name, i.role, s.host, s.exchange_hash, s.label, s.created_at
               FROM sessions s JOIN identities i ON s.identity_id = i.id
               WHERE s.host = ? ORDER BY s.created_at DESC""", (host,)
        ).fetchall()
        return [{"session_id": r[0], "identity_id": r[1], "identity_name": r[2], "identity_role": r[3],
                 "host": r[4], "exchange_hash": r[5], "label": r[6], "created_at": r[7]} for r in rows]
    finally:
        conn.close()


# --- T02: object-ownership facts + identity principal metadata --------------

def save_ownership_fact(fact) -> None:
    """Persist an observed OwnershipFact (T02). `fact` is a principals.OwnershipFact.
    INSERT OR REPLACE by object_ref: the latest observation of an object's ownership
    supersedes an earlier one (ownership can change as the crawl learns more)."""
    conn = _store._connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO ownership_facts "
            "(object_ref, owner_principal_id, tenant, shared_with_json, public, provenance, observed_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (fact.object_ref, fact.owner_principal_id, fact.tenant,
             json.dumps(sorted(fact.shared_with)), int(fact.public), fact.provenance, fact.observed_at))
        conn.commit()
    finally:
        conn.close()


def _ownership_row_to_dict(row) -> dict:
    return {"object_ref": row[0], "owner_principal_id": row[1], "tenant": row[2],
            "shared_with": json.loads(row[3] or "[]"), "public": bool(row[4]),
            "provenance": row[5], "observed_at": row[6]}


def get_ownership_fact(object_ref: str) -> dict | None:
    conn = _store._connect()
    try:
        row = conn.execute(
            "SELECT object_ref, owner_principal_id, tenant, shared_with_json, public, provenance, "
            "observed_at FROM ownership_facts WHERE object_ref = ?", (object_ref,)).fetchone()
        return _store._ownership_row_to_dict(row) if row else None
    finally:
        conn.close()


def ownership_facts_all() -> list[dict]:
    conn = _store._connect()
    try:
        rows = conn.execute(
            "SELECT object_ref, owner_principal_id, tenant, shared_with_json, public, provenance, "
            "observed_at FROM ownership_facts").fetchall()
        return [_store._ownership_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def set_identity_principal_meta(identity_id: str, *, tenant: str | None = None,
                                permissions=None, trust: int = 1) -> None:
    """Attach T02 principal metadata (tenant / declared permissions / trust) to an
    existing identity row -- additive, reusing the identities table. Permissions and
    tenant are operator-supplied facts, never inferred from role rank or URL."""
    conn = _store._connect()
    try:
        conn.execute("UPDATE identities SET tenant = ?, permissions_json = ?, trust = ? WHERE id = ?",
                     (tenant, json.dumps(sorted(permissions or [])), int(trust), identity_id))
        conn.commit()
    finally:
        conn.close()


def get_identity_principal_meta(identity_id: str) -> dict | None:
    conn = _store._connect()
    try:
        row = conn.execute("SELECT tenant, permissions_json, trust FROM identities WHERE id = ?",
                           (identity_id,)).fetchone()
        if not row:
            return None
        return {"tenant": row[0], "permissions": json.loads(row[1] or "[]"), "trust": row[2]}
    finally:
        conn.close()


def save_engagement_declarations(host: str, port: int, *, protected_paths: list[str],
                                 owners: list[dict]) -> None:
    """Replace the saved declarations for one target (I16). Callers validate the
    entries first (server.py does, against the RV-S/RV-T grammars); empty lists
    for both delete the row, so "save nothing" leaves nothing to opt in to."""
    host = (host or "").lower()
    if not host or not isinstance(port, int) or not 0 < port < 65536:
        raise ValueError("a declarations target needs a host and a port")
    conn = _store._connect()
    try:
        if not protected_paths and not owners:
            conn.execute("DELETE FROM engagement_declarations WHERE host = ? AND port = ?", (host, port))
        else:
            conn.execute(
                "INSERT OR REPLACE INTO engagement_declarations (host, port, protected_paths_json, "
                "owners_json, declarations_version, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (host, port, json.dumps(list(protected_paths)), json.dumps(list(owners)),
                 _store._DECLARATIONS_VERSION, time.time()))
        conn.commit()
    finally:
        conn.close()


def load_engagement_declarations(host: str, port: int) -> dict | None:
    """The saved declarations for exactly this (host, port), or None when nothing
    of this version is saved. Never consulted unless a request opts in."""
    conn = _store._connect()
    try:
        row = conn.execute(
            "SELECT protected_paths_json, owners_json, updated_at FROM engagement_declarations "
            "WHERE host = ? AND port = ? AND declarations_version = ?",
            ((host or "").lower(), port, _store._DECLARATIONS_VERSION)).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return {"protected_paths": json.loads(row[0]), "owners": json.loads(row[1]), "updated_at": row[2]}


# The facade, bound last: the functions above read harness.store names through it at call
# time, and binding it here lets this module be imported before harness.store.
from harness import store as _store  # noqa: E402
