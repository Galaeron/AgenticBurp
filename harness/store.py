from __future__ import annotations
import sqlite3
import time
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

from harness.models import HttpExchange, Finding, TestPlan, ValidationSubmission

_DB_PATH = Path(__file__).parent / "harness_state.db"

# W-9: bump when finding_fingerprint's formula changes, so _connect re-fingerprints
# existing rows once (guarded by PRAGMA user_version).
_FINGERPRINT_ALGO_VERSION = 3


def _normalize_endpoint(url: str) -> str:
    """Endpoint identity with volatile query VALUES stripped but structure kept:
    scheme://netloc/path plus the sorted set of query PARAM NAMES. So ?id=1 and
    ?id=2 collapse to the same endpoint, while ?a= and ?b= stay distinct."""
    from urllib.parse import urlsplit, parse_qsl
    parts = urlsplit(url or "")
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query = ("?" + ",".join(names)) if names else ""
    return f"{parts.scheme}://{parts.netloc}{parts.path}{query}"


def finding_fingerprint(host: str, method: str, url: str, vulnerability_class: str,
                        *, parameter_location: str = "", parameter_name: str = "",
                        principal_id: str = "") -> str:
    """Stable STRUCTURAL identity for a finding (W-9).

    Keyed on canonical vulnerability class + host + normalized endpoint +
    parameter/object + identity context -- deliberately NOT the LLM-written
    summary. The old formula hashed `summary`, so re-running with differently
    worded prose for the same underlying issue produced a different
    fingerprint, defeating suppression and duplicating findings. Two runs that
    word the same issue differently now hash identically.
    """
    from harness.categories import canonicalize
    check = canonicalize(vulnerability_class) or (vulnerability_class or "").lower()
    return hashlib.sha256("\x1f".join([
        host or "",
        (method or "").upper(),
        _normalize_endpoint(url),
        check,
        (parameter_location or "").lower(),
        # W-9: parameter_name is a case-sensitive input identity (e.g. `userId`
        # vs `userid` are distinct fields on many APIs) -- do not fold its case,
        # unlike parameter_location which is a fixed, case-irrelevant enum.
        parameter_name or "",
        principal_id or "",
    ]).encode("utf-8")).hexdigest()

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


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript(_SCHEMA)
    conn.executescript(_PLAN_SCHEMA)
    conn.executescript(_CHAIN_SCHEMA)
    conn.executescript(_COVERAGE_SCHEMA)
    conn.executescript(_IDENTITY_SCHEMA)
    conn.executescript(_EVIDENCE_SCHEMA)
    conn.executescript(_PRINCIPAL_SCHEMA)
    conn.executescript(_ISSUE_MERGE_SCHEMA)
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
            fid = finding_fingerprint(row[1], row[2], row[3], row[4])
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
    # Oracle-verification axis (precision items #1/#2): the stricter verified/candidate
    # state and the id of the proof capsule that earned it. Additive, defaults keep
    # every legacy row a "candidate" (no oracle ever ran on it).
    if "oracle_verified" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN oracle_verified INTEGER NOT NULL DEFAULT 0")
    if "verification_state" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN verification_state TEXT NOT NULL DEFAULT 'candidate'")
    if "oracle_capsule_id" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN oracle_capsule_id TEXT NOT NULL DEFAULT ''")
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
    if conn.execute("PRAGMA user_version").fetchone()[0] < _FINGERPRINT_ALGO_VERSION:
        for row in conn.execute(
            "SELECT id, host, method, url, vulnerability_class FROM findings"
        ).fetchall():
            new_fp = finding_fingerprint(row[1], row[2], row[3], row[4])
            conn.execute("UPDATE OR IGNORE findings SET fingerprint = ? WHERE id = ?",
                         (new_fp, row[0]))
        conn.execute(f"PRAGMA user_version = {_FINGERPRINT_ALGO_VERSION}")

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
    # Retrievable knowledge notes (knowledge.py's Memory Retriever) -- tester-
    # authored methodology writeups and auto-remembered confirmed findings,
    # merged with the built-in corpus at decision time. `source` distinguishes
    # them (manual | finding); `fingerprint` de-dupes.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS knowledge_notes (
            fingerprint TEXT PRIMARY KEY,
            tags_json TEXT NOT NULL DEFAULT '[]',
            note TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'manual',
            created_at REAL NOT NULL
        )
    """)
    conn.commit()
    return conn


def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def persist_findings(exchange: HttpExchange, agent_name: str, findings: list[Finding],
                      model: str = "", prompt_version: str = "") -> None:
    if not findings:
        return
    host = host_of(exchange.url)
    now = time.time()
    conn = _connect()
    try:
        rows = []
        for f in findings:
            fingerprint = finding_fingerprint(
                host, exchange.method, exchange.url, f.vulnerability_class,
                parameter_location=getattr(f, "parameter_location", "") or "",
                parameter_name=getattr(f, "parameter_name", "") or "",
                principal_id=getattr(f, "principal_id", "") or "",
            )
            rows.append((host, exchange.url, exchange.method, agent_name, f.vulnerability_class,
                         f.severity, f.confidence, f.summary, f.basis, f.evidence, f.suggested_test,
                         f.owasp_category, f.review_verdict, int(f.confirmed), fingerprint,
                         model, prompt_version, f.finding_id, f.case_id, f.proof_id,
                         int(getattr(f, "oracle_verified", False)),
                         getattr(f, "verification_state", "candidate") or "candidate",
                         getattr(f, "oracle_capsule_id", "") or "", now))
        conn.executemany(
            """INSERT OR IGNORE INTO findings
               (host, url, method, agent, vulnerability_class, severity,
                confidence, summary, basis, evidence, suggested_test, owasp_category,
                review_verdict, confirmed, fingerprint, model, prompt_version,
                finding_id, case_id, proof_id, oracle_verified, verification_state,
                oracle_capsule_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", rows)
        conn.commit()
    finally:
        conn.close()



def _persist_test_plans_for(host: str, url: str, plans: list[TestPlan]) -> None:
    if not plans:
        return
    conn = _connect()
    try:
        conn.executemany(
            """INSERT OR IGNORE INTO test_plans
               (plan_id, host, url, capability, finding_class, category, execution_plane, status,
                source_exchange_hash, mutation_json, success_signals_json, severity, confidence,
                escalated, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(p.id, host, url, p.capability, p.finding_class,
              p.category or "", p.execution_plane or "burp", "proposed",
              p.source_exchange_hash, json.dumps(p.mutation, sort_keys=True),
              json.dumps(p.success_signals), p.severity, p.confidence,
              int(p.escalated), time.time()) for p in plans],
        )
        conn.commit()
    finally:
        conn.close()


def persist_test_plans(exchange: HttpExchange, plans: list[TestPlan]) -> None:
    _persist_test_plans_for(host_of(exchange.url), exchange.url, plans)


def persist_retry_plan(plan: TestPlan) -> None:
    """Persist a single follow-up TestPlan built by active_verification.py.
    Unlike persist_test_plans, there is no original HttpExchange in hand at
    this call site (only the plan itself, built from a stored plan row) --
    host is derived the same way persist_test_plans derives it."""
    _persist_test_plans_for(host_of(plan.source_exchange_url), plan.source_exchange_url, [plan])


def get_test_plan(plan_id: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute(
            """SELECT plan_id, host, url, capability, finding_class, status,
                      source_exchange_hash, mutation_json, success_signals_json,
                      category, execution_plane, severity, confidence, escalated
               FROM test_plans WHERE plan_id = ?""", (plan_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {"plan_id": row[0], "host": row[1], "url": row[2], "capability": row[3],
            "finding_class": row[4], "status": row[5], "source_exchange_hash": row[6],
            "mutation": json.loads(row[7] or "{}"), "success_signals": json.loads(row[8] or "[]"),
            "category": row[9], "execution_plane": row[10], "severity": row[11],
            "confidence": row[12], "escalated": bool(row[13])}


def get_lineage_attempts(category: str, source_exchange_hash: str) -> list[dict]:
    """
    Every plan in the same retry lineage -- same category, same captured
    exchange -- that has an observed result, ordered oldest first, plus
    the plan-level fields (severity/confidence/escalated/mutation) needed
    to reconstruct retry_policy.Attempt objects and to know which payload
    values have already been tried (see payload_library.next_candidate's
    `tried` argument). Plans with no validation_runs row yet (proposed but
    not yet executed by the Burp extension) are excluded on purpose: an
    outstanding plan is not a completed attempt, and counting it would let
    a slow/never-responding execution plane silently exhaust the retry
    budget without ever supplying real evidence.
    """
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT tp.mutation_json, tp.severity, tp.confidence, tp.escalated,
                      vr.status, vr.confidence, vr.confirmed
               FROM test_plans tp
               JOIN validation_runs vr ON vr.plan_id = tp.plan_id
               WHERE tp.category = ? AND tp.source_exchange_hash = ?
               ORDER BY vr.created_at ASC""",
            (category, source_exchange_hash),
        ).fetchall()
    finally:
        conn.close()
    return [
        {"mutation": json.loads(r[0] or "{}"), "severity": r[1], "confidence": r[2],
         "escalated": bool(r[3]), "status": r[4], "result_confidence": r[5], "confirmed": bool(r[6])}
        for r in rows
    ]

def persist_validation_submission(submission: ValidationSubmission) -> tuple[bool, str]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT source_exchange_hash, status, capability, execution_plane FROM test_plans WHERE plan_id = ?",
            (submission.plan_id,)).fetchone()
        if not row:
            return False, "unknown test plan"
        if submission.source_exchange_hash != row[0]:
            return False, "binding_mismatch"
        # The executor prefix must match the plan's OWN execution plane,
        # not a hardcoded "burp:" -- this previously rejected every
        # legitimate local_tool (sqlmap) submission outright, silently,
        # since no local_tool result could ever satisfy an executor
        # string of the form "burp:<capability>". Caught by a test that
        # tried to persist a real sqlmap-shaped submission and found it
        # rejected for a reason that had nothing to do with the test's
        # actual assertion.
        expected_executor = f"{row[3]}:{row[2]}"
        if submission.executor != expected_executor:
            return False, "executor does not match the registered capability"
        # sqlmap is a deterministic tool whose entire purpose is to
        # independently confirm SQL injection -- excluding it here
        # directly contradicts the project's own "known vs rediscover"
        # principle (trust deterministic tools over LLM reasoning) for
        # the one capability that is MOST deterministic. Verified live:
        # sqlmap genuinely confirmed a real SQLi on OWASP Juice Shop's
        # login endpoint in this session: excluding it from ever setting
        # confirmed=True would have silently discarded that result.
        #
        # Expanded this session after a real, live audit of every OTHER
        # active/Burp-plane capability's actual confirmation rigor (not a
        # decision folded into an unrelated bugfix -- this is exactly the
        # audit HANDOVER.md's §5i/§6.9 said had to happen before touching
        # this list). Each addition below independently replays a real
        # request/probe against the real target and compares it against a
        # real observed response -- the same deterministic shape as the
        # three original entries, not an LLM guess:
        # - cors_misconfiguration_detection: already found live, this
        #   session, to be exactly this deterministic -- a real Juice Shop
        #   run produced 10 genuine CORS confirmations (foreign Origin
        #   replayed, ACAO reflection + credentials checked in the real
        #   response) that this allowlist was silently discarding.
        # - reflection_context_validation (XSS): XssPayloadLogic.classify()
        #   requires the exact random canary string to survive unescaped in
        #   a live replayed response -- a real proof of execution context.
        # - open_redirect_validation: requires an exact Location header
        #   match to the injected external URL on a live replay.
        # - jwt_validation: requires a forged token to be accepted with a
        #   materially matching response to the original authenticated
        #   request.
        # command_injection_validation deliberately NOT added: its
        # differential-timing design (CommandInjectionTimingLogic) is
        # already calibrated to a lower confidence ceiling (0.75, vs 0.85+
        # elsewhere) specifically because timing evidence is inherently
        # noisier than content evidence -- left off pending a live
        # false-positive check this pass didn't have time for, not
        # forgotten.
        confirmation_capabilities = {
            "cross_identity_compare", "authorization_boundary_compare",
            "sql_injection_validation",
            "cors_misconfiguration_detection",
            "reflection_context_validation",
            "open_redirect_validation",
            "jwt_validation",
        }
        if submission.confirmed and row[2] not in confirmation_capabilities:
            return False, "this capability may provide evidence but cannot mark the vulnerability confirmed"
        if submission.confirmed and submission.status != "confirmed":
            return False, "confirmed result has invalid status"
        conn.execute(
            """INSERT INTO validation_runs
               (plan_id, status, confidence, confirmed, summary, evidence, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (submission.plan_id, submission.status, submission.confidence, int(submission.confirmed),
             submission.summary, submission.evidence, time.time()),
        )
        conn.execute("UPDATE test_plans SET status = ? WHERE plan_id = ?", (submission.status, submission.plan_id))
        conn.commit()
        return True, "accepted"
    finally:
        conn.close()


_PROOF_COLUMNS = (
    "proof_id, run_id, case_id, principal_id, request_template_id, check_id, "
    "parameter_location, parameter_name, workflow_state_id, finding_ref, validator, validator_version, "
    "verdict, executed, legacy, baseline_artifact_id, attack_artifact_id, "
    "control_artifact_ids_json, expected_invariant, observed_result, limitation, created_at"
)


def persist_proof_record(proof) -> tuple[bool, str]:
    """Persist one structured proof attempt (Astra T01), append-only.

    Rejects a proof whose case ref is inconsistent -- a forged/unknown case whose
    case_id does not match its own identity-bearing fields. Uses INSERT OR IGNORE
    keyed on the per-attempt proof_id, so re-persisting is idempotent and a later
    weaker attempt never overwrites an earlier stronger proof of the same case
    (best_proof_for_case selects the strongest)."""
    from harness.evidence import ProofRecord  # local import: evidence has no store dependency
    if not isinstance(proof, ProofRecord):
        return False, "not a ProofRecord"
    if not proof.case.consistent:
        return False, "unknown_or_forged_case"
    c = proof.case
    conn = _connect()
    try:
        conn.execute(
            f"INSERT OR IGNORE INTO proof_records ({_PROOF_COLUMNS}) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (proof.proof_id, c.run_id, c.case_id, c.principal_id, c.request_template_id,
             c.check_id, c.parameter_location, c.parameter_name, c.workflow_state_id, c.finding_ref,
             proof.validator, proof.validator_version, proof.verdict.value,
             int(proof.executed), int(proof.legacy), proof.baseline_artifact_id,
             proof.attack_artifact_id, json.dumps(list(proof.control_artifact_ids)),
             proof.expected_invariant, proof.observed_result, proof.limitation,
             proof.created_at),
        )
        conn.commit()
        return True, "accepted"
    finally:
        conn.close()


def _proof_row_to_dict(row) -> dict:
    """Reconstruct a ProofRecord.to_dict()-shaped dict (nested case) from a row."""
    (proof_id, run_id, case_id, principal_id, request_template_id, check_id,
     parameter_location, parameter_name, workflow_state_id, finding_ref, validator, validator_version,
     verdict, executed, legacy, baseline_artifact_id, attack_artifact_id,
     control_artifact_ids_json, expected_invariant, observed_result, limitation, created_at) = row
    return {
        "proof_id": proof_id,
        "case": {"run_id": run_id, "case_id": case_id, "principal_id": principal_id,
                 "request_template_id": request_template_id, "check_id": check_id,
                 "parameter_location": parameter_location, "parameter_name": parameter_name,
                 "workflow_state_id": workflow_state_id, "finding_ref": finding_ref},
        "validator": validator, "validator_version": validator_version, "verdict": verdict,
        "executed": bool(executed), "legacy": bool(legacy),
        "baseline_artifact_id": baseline_artifact_id, "attack_artifact_id": attack_artifact_id,
        "control_artifact_ids": json.loads(control_artifact_ids_json or "[]"),
        "expected_invariant": expected_invariant, "observed_result": observed_result,
        "limitation": limitation, "created_at": created_at,
    }


def proofs_for_case(case_id: str) -> list[dict]:
    """All proof attempts for one case, oldest first (append-only history)."""
    conn = _connect()
    try:
        rows = conn.execute(
            f"SELECT {_PROOF_COLUMNS} FROM proof_records WHERE case_id = ? ORDER BY created_at ASC",
            (case_id,)).fetchall()
        return [_proof_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def best_proof_for_case(case_id: str) -> dict | None:
    """The strongest proof attempt for a case (confirmed > controlled_negative >
    inconclusive/blocked > error; ties break to the most recent). A later weaker
    attempt never displaces an earlier stronger one."""
    from harness.evidence import Verdict
    proofs = proofs_for_case(case_id)
    if not proofs:
        return None
    return max(proofs, key=lambda d: (Verdict(d["verdict"]).rank(), d["created_at"]))


def _strip_backticks(text: str) -> str:
    return text.replace("`", "'")


def prior_findings_summary(url: str, exclude_url: str | None = None, limit: int = 8) -> str:
    """
    Compact, prompt-ready summary of what's already been found on this
    host, most recent first. Intentionally small and lossy (a prior, not
    a full record) -- its job is to let an agent notice "this finding is
    more significant given what else is on this host", not to
    reconstruct full history.
    """
    host = host_of(url)
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT url, vulnerability_class, severity, confidence, summary
               FROM findings WHERE host = ? AND url != COALESCE(?, '')
               ORDER BY created_at DESC LIMIT ?""",
            (host, exclude_url, limit),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return ""
    # Found live, during this project's first real (non-substituted)
    # Ollama run: a model wrote a completely ordinary finding summary
    # using Markdown code-formatting for a path -- "The `/api/avatar`
    # endpoint returns potentially sensitive data..." -- which got
    # persisted, then fed back verbatim into every SUBSEQUENT exchange's
    # prompt for the same host via this function. prompt_validator.py's
    # backtick-command-substitution pattern (`` `[^`\n]{1,200}` ``,
    # deliberately broad -- see its own comment) matched the backtick-
    # quoted path, failing prompt validation for every agent on every
    # remaining exchange for that host for the rest of the run. Unlike
    # raw exchange data (genuinely untrusted, and validated for good
    # reason), this text is the harness's OWN prior model output; the
    # only value backticks add here is Markdown styling, which nothing
    # downstream renders anyway. Stripping them breaks the propagation
    # at its source rather than trying to special-case every blocked
    # pattern this text might one day happen to also contain.
    lines = [
        f"- [{sev}, confidence {conf:.2f}] {vclass} at {u}: {_strip_backticks(summary)}"
        for (u, vclass, sev, conf, summary) in rows
    ]
    return "\n".join(lines)


def all_host_findings(url: str, include_suppressed: bool = False) -> list[dict]:
    """
    Full (not summarized) finding records for a host, for chain detection
    and report generation.

    `include_suppressed`: if False (the default), findings whose
    fingerprint has been suppressed (see `suppress_finding`) are left out
    entirely. Each returned dict always includes `fingerprint` and
    `suppressed` regardless of this flag, so a caller that DOES want to
    see suppressed findings (e.g. an "show dismissed findings" view) can
    still tell which ones they are -- this flag controls whether they're
    in the list at all, not whether the suppressed status is visible.
    """
    host = host_of(url)
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT f.url, f.vulnerability_class, f.severity, f.confidence, f.summary,
                      f.evidence, f.suggested_test, f.owasp_category, f.basis, f.confirmed,
                      f.agent, f.fingerprint, f.finding_id, f.case_id, f.proof_id,
                      f.method, f.review_verdict,
                      (SELECT parameter_location FROM proof_records WHERE case_id = f.case_id LIMIT 1),
                      (SELECT parameter_name FROM proof_records WHERE case_id = f.case_id LIMIT 1),
                      (SELECT principal_id FROM proof_records WHERE case_id = f.case_id LIMIT 1),
                      s.fingerprint IS NOT NULL AS suppressed,
                      f.oracle_verified, f.verification_state, f.oracle_capsule_id
               FROM findings f
               LEFT JOIN finding_suppressions s ON s.fingerprint = f.fingerprint
               WHERE f.host = ?
               ORDER BY f.created_at ASC""",
            (host,),
        ).fetchall()
    finally:
        conn.close()
    # method + the finding's case coordinates (parameter_location/parameter_name/
    # principal_id, from its linked proof) are surfaced for T06 issue grouping and
    # export -- additive keys; existing consumers read by name and are unaffected.
    from harness import confirmation_gate
    results = [
        {"url": u, "vulnerability_class": vc, "severity": sev, "confidence": conf, "summary": s,
         "evidence": ev, "suggested_test": st, "owasp_category": oc, "basis": basis,
         "confirmed": bool(confirmed), "agent": agent, "fingerprint": fp,
         "finding_id": finding_id, "case_id": case_id, "proof_id": proof_id,
         "method": method or "", "review_verdict": rv or "",
         # W-7: explicit CONFIRMED/SUSPECTED/LEAD state so the findings API, the
         # report and the Burp tab can show status at a glance rather than a raw
         # confidence number.
         "lifecycle_state": confirmation_gate.lifecycle_state(bool(confirmed), rv),
         "parameter_location": ploc or "", "parameter_name": pname or "",
         "principal_id": principal or "", "suppressed": bool(suppressed),
         # P0.2-API: the oracle's verdict (item #1/#2) must be readable from the
         # SAME dict the report/API/Burp panel all consume -- previously this
         # query never selected these columns, so `oracle_verified` was always
         # absent here and `derive_verification_state()` silently defaulted
         # every finding to "candidate" regardless of what was persisted.
         "oracle_verified": bool(oracle_verified), "verification_state": vstate or "candidate",
         "oracle_capsule_id": capsule_id or ""}
        for (u, vc, sev, conf, s, ev, st, oc, basis, confirmed, agent, fp,
             finding_id, case_id, proof_id, method, rv, ploc, pname, principal, suppressed,
             oracle_verified, vstate, capsule_id) in rows
    ]
    if not include_suppressed:
        results = [r for r in results if not r["suppressed"]]
    return results


def suppress_finding(fingerprint: str, reason: str = "") -> None:
    """
    Marks a finding fingerprint as suppressed (a false positive, or
    otherwise not worth re-surfacing) so a future scan of the same host
    doesn't make the analyst re-triage it from scratch. This is the
    workflow gap named in this project's own milestones list: without
    it, re-running the harness against a target re-surfaces every
    previously-dismissed finding with no memory of the dismissal --
    undercutting the tool's whole point of not making the analyst
    re-verify things it's already told them about.

    Idempotent: suppressing an already-suppressed fingerprint just
    updates the reason/timestamp, via INSERT OR REPLACE, rather than
    erroring on the primary key collision.

    Known limitation, stated plainly rather than silently accepted:
    `fingerprint` (computed in `persist_findings`) includes the agent's
    free-text `summary`, not just host/method/url/category. If a re-run
    produces a differently-worded summary for the exact same underlying
    issue, its fingerprint won't match a previously-suppressed one, and
    it will resurface. This suppression feature is built on the
    fingerprint scheme that already existed for same-run deduplication,
    not a new, more stable cross-run identity scheme -- reworking
    fingerprint computation to be summary-independent would be a more
    invasive change to `persist_findings`'s existing behavior and is a
    separate, deliberately-not-bundled decision for a future session.
    """
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO finding_suppressions (fingerprint, reason, suppressed_at) VALUES (?, ?, ?)",
            (fingerprint, reason, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def unsuppress_finding(fingerprint: str) -> bool:
    """Removes a suppression. Returns True if a row was actually removed."""
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM finding_suppressions WHERE fingerprint = ?", (fingerprint,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def is_suppressed(fingerprint: str) -> bool:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM finding_suppressions WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def list_suppressions() -> list[dict]:
    """All active suppressions, most recently suppressed first."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT fingerprint, reason, suppressed_at FROM finding_suppressions ORDER BY suppressed_at DESC"
        ).fetchall()
    finally:
        conn.close()
    return [{"fingerprint": fp, "reason": reason, "suppressed_at": ts} for (fp, reason, ts) in rows]


def record_issue_merge(host: str, source_id: str, target_id: str) -> None:
    """Operator override (P1.8): fold issue `source_id` into `target_id` for
    `host`. Idempotent (INSERT OR REPLACE), like suppress_finding. Reversible
    by remove_issue_merge -- this is a separate override table, never a
    mutation of the underlying findings or the deterministic issue_key
    grouping, so removing the row exactly restores the automatic split."""
    if source_id == target_id:
        raise ValueError("cannot merge an issue into itself")
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO issue_merges (host, source_id, target_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (host, source_id, target_id, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def remove_issue_merge(host: str, source_id: str) -> bool:
    """Reverses a prior record_issue_merge. Returns True if a row was removed."""
    conn = _connect()
    try:
        cur = conn.execute(
            "DELETE FROM issue_merges WHERE host = ? AND source_id = ?", (host, source_id))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def all_issue_merges(host: str) -> dict[str, str]:
    """{source_id: target_id} for every active merge override on `host`."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT source_id, target_id FROM issue_merges WHERE host = ?", (host,)
        ).fetchall()
    finally:
        conn.close()
    return {source_id: target_id for (source_id, target_id) in rows}


def save_engagement(host: str, state: dict) -> None:
    """Upsert the per-host engagement snapshot (engagement.EngagementState.to_dict())."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO engagement_state (host, state_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(host) DO UPDATE SET state_json=excluded.state_json, updated_at=excluded.updated_at",
            (host, json.dumps(state), time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def load_engagement(host: str) -> dict | None:
    """The stored engagement snapshot for `host`, or None if none saved yet."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT state_json FROM engagement_state WHERE host = ?", (host,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return None


def save_knowledge_note(tags: list, note: str, source: str = "manual") -> bool:
    """Persist a retrievable knowledge note (idempotent by content). Returns
    whether a new row was inserted."""
    note = (note or "").strip()
    if not note:
        return False
    fp = hashlib.sha256(("|".join(sorted(tags)) + "\x1f" + note).encode("utf-8")).hexdigest()[:24]
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO knowledge_notes (fingerprint, tags_json, note, source, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (fp, json.dumps(list(tags)), note, source, time.time()))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def list_knowledge_notes(limit: int = 500) -> list[dict]:
    """All stored knowledge notes, newest first."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT tags_json, note, source, created_at FROM knowledge_notes "
            "ORDER BY created_at DESC LIMIT ?", (int(limit),)).fetchall()
    finally:
        conn.close()
    out = []
    for tags_json, note, source, ts in rows:
        try:
            tags = json.loads(tags_json)
        except (json.JSONDecodeError, TypeError):
            tags = []
        out.append({"tags": tags, "note": note, "source": source, "created_at": ts})
    return out


def is_chain_already_detected(url: str, signature: str) -> bool:
    host = host_of(url)
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM chains_detected WHERE host = ? AND chain_signature = ?",
            (host, signature),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def mark_chain_detected(url: str, signature: str) -> None:
    host = host_of(url)
    conn = _connect()
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
#   blocked         - the only validation attempt errored out (tool missing, timeout, etc.)
#   tested_clean    - independently tested and no evidence found
#   not_tested      - a specialist flagged this category but no validation was ever run
#   not_dispatched  - no exchange on this host ever triggered this specialist at all
#   not_applicable  - analyst override; see set_coverage_override

from harness.categories import CANONICAL_CATEGORIES  # noqa: E402  (kept near point of use)

_NO_ACTIVE_VALIDATOR = {"misconfig", "ai_llm", "supply_chain"}


def set_coverage_override(host: str, category: str, reason: str) -> None:
    """Analyst-only annotation that a category doesn't apply to this
    target. Deliberately cannot express anything except NOT_APPLICABLE --
    see module docstring above for why that restriction is load-bearing."""
    if category not in CANONICAL_CATEGORIES:
        raise ValueError(f"unknown category: {category!r}")
    conn = _connect()
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
    conn = _connect()
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
    conn = _connect()
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
        supported_run = next((r for r in runs if r[1] == "supported"), None)
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
                    if category in _NO_ACTIVE_VALIDATOR else
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
    conn = _connect()
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
    conn = _connect()
    try:
        rows = conn.execute("SELECT id, name, role, notes, created_at FROM identities ORDER BY created_at").fetchall()
        return [{"id": r[0], "name": r[1], "role": r[2], "notes": r[3], "created_at": r[4]} for r in rows]
    finally:
        conn.close()


def get_identity(identity_id: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute("SELECT id, name, role, notes, created_at FROM identities WHERE id = ?", (identity_id,)).fetchone()
        if not row:
            return None
        return {"id": row[0], "name": row[1], "role": row[2], "notes": row[3], "created_at": row[4]}
    finally:
        conn.close()


def save_session(session) -> None:
    """`session` is an identity.Session."""
    conn = _connect()
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
    conn = _connect()
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
    conn = _connect()
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
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT object_ref, owner_principal_id, tenant, shared_with_json, public, provenance, "
            "observed_at FROM ownership_facts WHERE object_ref = ?", (object_ref,)).fetchone()
        return _ownership_row_to_dict(row) if row else None
    finally:
        conn.close()


def ownership_facts_all() -> list[dict]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT object_ref, owner_principal_id, tenant, shared_with_json, public, provenance, "
            "observed_at FROM ownership_facts").fetchall()
        return [_ownership_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def set_identity_principal_meta(identity_id: str, *, tenant: str | None = None,
                                permissions=None, trust: int = 1) -> None:
    """Attach T02 principal metadata (tenant / declared permissions / trust) to an
    existing identity row -- additive, reusing the identities table. Permissions and
    tenant are operator-supplied facts, never inferred from role rank or URL."""
    conn = _connect()
    try:
        conn.execute("UPDATE identities SET tenant = ?, permissions_json = ?, trust = ? WHERE id = ?",
                     (tenant, json.dumps(sorted(permissions or [])), int(trust), identity_id))
        conn.commit()
    finally:
        conn.close()


def get_identity_principal_meta(identity_id: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute("SELECT tenant, permissions_json, trust FROM identities WHERE id = ?",
                           (identity_id,)).fetchone()
        if not row:
            return None
        return {"tenant": row[0], "permissions": json.loads(row[1] or "[]"), "trust": row[2]}
    finally:
        conn.close()
