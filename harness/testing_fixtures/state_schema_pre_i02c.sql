-- Main-store schema as harness/store.py created it at 1431602 (before I02-C),
-- dumped from sqlite_master. Frozen input for test_observation_migration.py:
-- it stands in for a database written by the previous build. Do not regenerate.
PRAGMA user_version = 3;
CREATE TABLE findings (
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
CREATE INDEX idx_findings_host ON findings(host);
CREATE TABLE test_plans (
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
CREATE TABLE validation_runs (
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
CREATE INDEX idx_validation_runs_plan ON validation_runs(plan_id);
CREATE TABLE chains_detected (
    host TEXT NOT NULL,
    chain_signature TEXT NOT NULL,
    detected_at REAL NOT NULL,
    PRIMARY KEY (host, chain_signature)
);
CREATE TABLE coverage_overrides (
    host TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    PRIMARY KEY (host, category)
);
CREATE TABLE identities (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    notes TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
, tenant TEXT, permissions_json TEXT NOT NULL DEFAULT '[]', trust INTEGER NOT NULL DEFAULT 1);
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    host TEXT NOT NULL,
    exchange_hash TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    FOREIGN KEY(identity_id) REFERENCES identities(id)
);
CREATE INDEX idx_sessions_identity ON sessions(identity_id);
CREATE INDEX idx_sessions_host ON sessions(host);
CREATE TABLE proof_records (
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
CREATE INDEX idx_proof_case ON proof_records(case_id);
CREATE INDEX idx_proof_run ON proof_records(run_id);
CREATE TABLE ownership_facts (
    object_ref TEXT PRIMARY KEY,
    owner_principal_id TEXT NOT NULL DEFAULT '',
    tenant TEXT,
    shared_with_json TEXT NOT NULL DEFAULT '[]',
    public INTEGER NOT NULL DEFAULT 0,
    provenance TEXT NOT NULL DEFAULT '',
    observed_at REAL NOT NULL
);
CREATE TABLE issue_merges (
    host TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (host, source_id)
);
CREATE TABLE ledger_events (
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
CREATE INDEX idx_ledger_finding_ref ON ledger_events(finding_ref);
CREATE TABLE evidence_blobs (
    sha256 TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE work_items (
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
CREATE INDEX idx_work_items_lease
    ON work_items(engagement_id, status, priority);
CREATE TABLE state_metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE UNIQUE INDEX idx_findings_fingerprint_case ON findings(fingerprint, case_id);
CREATE TABLE finding_suppressions (
            fingerprint TEXT PRIMARY KEY,
            reason TEXT NOT NULL DEFAULT '',
            suppressed_at REAL NOT NULL
        );
CREATE TABLE engagement_state (
            host TEXT PRIMARY KEY,
            state_json TEXT NOT NULL,
            updated_at REAL NOT NULL
        );
CREATE TABLE scoped_engagement_state (
            engagement_id TEXT NOT NULL,
            host TEXT NOT NULL,
            revision INTEGER NOT NULL,
            state_json TEXT NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (engagement_id, host)
        );
CREATE TABLE knowledge_notes (
            fingerprint TEXT PRIMARY KEY,
            tags_json TEXT NOT NULL DEFAULT '[]',
            note TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'manual',
            created_at REAL NOT NULL,
            engagement_id TEXT NOT NULL DEFAULT ''
        );
CREATE TABLE finding_observations (
            fingerprint TEXT NOT NULL,
            run_id TEXT NOT NULL DEFAULT '',
            exchange_id TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
CREATE UNIQUE INDEX idx_finding_observations_unique
        ON finding_observations(fingerprint, run_id, exchange_id);
