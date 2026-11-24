"""harness.store: the SQLite state store, as a facade over its repository modules (ARC-9).

Callers keep importing from here: every store name (functions, classes, constants, and the
private helpers tests patch) is bound on this module. The code lives in nine repositories:

    store_schema        connection, DDL and migrations (one init path, fixed order)
    store_layout        OPS-5 engagement store selection; engagement/principal context
    store_findings      findings, fingerprints, suppressions, issue merges
    store_observations  I02-C exchange observations
    store_plans         test plans, submissions, plane/plan dispatch, SC-12 work items
    store_proofs        proof records and the content-addressed evidence blobs
    store_ledger        ledger_events plus the ARC-13 ledger_chain side table
    store_engagement    engagement snapshots, knowledge, coverage, identities, I16 declarations
    store_maintenance   blob retention, the host wipe, engagement close and retention

The contract that keeps patching working (harness.test_store_facade checks it):
- This module owns the mutable state below. Repositories define none of it.
- A repository function reads every store-level name through this module at call time
  (`_store.<name>`), never through a copy bound at import. So `store._DB_PATH = path`,
  `patch.object(store, "_db_identity")` or `patch("harness.store.captured_principal_id")`
  reaches every caller, exactly as when this was one module.
- A function that rebinds state assigns it here (`_store._DB_PATH = ...`).
"""
from __future__ import annotations
import contextvars
import os
import sys
import threading
from pathlib import Path

# ---------------------------------------------------------------------------
# Mutable process state. Repository functions read and rebind these here.
# ---------------------------------------------------------------------------
# The database every repository connects to (tests point it at a temp file).
_DB_PATH = Path(__file__).parent / "harness_state.db"
_CURRENT_ENGAGEMENT = contextvars.ContextVar("passive_engagement_owner", default="")
_CURRENT_CAPTURED_PRINCIPAL = contextvars.ContextVar("passive_captured_auth_context", default="")
# OPS-5 store selection; store_layout.select_engagement_store rebinds these.
_ACTIVE_ENGAGEMENT = ""
_ACTIVE_STORE_PATH: Path | None = None
_LEGACY_DB_PATH = Path(_DB_PATH)
_HELD_STORE_LOCK = None   # open engagement.lock of the selected store, held while selected

# E9: the connection setup (store_schema._initialise_connection) is about 58
# statements, several of them write-lock takers (+0.33 ms per connection), and it
# re-ran on EVERY _connect(). This process now runs it once per database file. The
# key is the absolute path plus the file's identity after setup -- (st_dev, st_ino,
# st_ctime_ns) so a deleted or recreated file never matches, and PRAGMA
# schema_version so any DDL since (a table dropped by a test, a migration by another
# process) makes the next connect run the idempotent setup again. busy_timeout is
# per connection and is set every time; WAL mode persists in the file.
_INITIALISED: dict[str, tuple] = {}
_INIT_LOCK = threading.Lock()
_STATS_LOCK = threading.Lock()
_CONNECT_STATS = {"connects": 0, "initialisations": 0, "skipped_initialisations": 0,
                  "connect_ms": 0.0, "init_ms": 0.0, "max_connect_ms": 0.0}
_SAVE_ENGAGEMENT_STATS = {"calls": 0, "bytes": 0, "ms": 0.0, "max_bytes": 0, "max_ms": 0.0}
_ENGAGEMENT_WRITE = threading.local()   # bytes of the snapshot _write_engagement just stored
# ARC-13: blobs stored under the "flag" policy that the redactors would still change.
_UNREDACTED_BLOB_FLAGS = 0


# ---------------------------------------------------------------------------
# The repositories. They bind this module last, so importing them here is safe.
# ---------------------------------------------------------------------------
from harness.store_schema import (  # noqa: E402
    _SCHEMA, _PLAN_SCHEMA, _CHAIN_SCHEMA, _COVERAGE_SCHEMA, _IDENTITY_SCHEMA, _EVIDENCE_SCHEMA,
    _PROOF_IDENTITY_VERSION, _PROOF_IDENTITY_SCHEMA, _PROOF_EVIDENCE_SOURCE_SCHEMA,
    _DECLARATIONS_VERSION, _DECLARATIONS_SCHEMA, _FINDING_INPUTS_VERSION, _FINDING_INPUTS_SCHEMA,
    _PLAN_DISPATCH_VERSION, _PLAN_DISPATCH_SCHEMA, _PLANE_DISPATCH_VERSION, _PLANE_DISPATCH_SCHEMA,
    _LEDGER_SCHEMA, _LEDGER_CHAIN_VERSION, _LEDGER_CHAIN_SCHEMA, _EVIDENCE_BLOB_SCHEMA,
    _PRINCIPAL_SCHEMA, _ISSUE_MERGE_SCHEMA, _WORK_ITEM_SCHEMA, _OBSERVATION_SCHEMA,
    _CONNECT_MAX_ATTEMPTS, _CONNECT_RETRY_BASE_SLEEP, _db_identity, timing_snapshot, _connect,
    _connect_counted, _initialise_connection, _PROOF_COLUMNS, _PROOF_SELECT, _open_read_only,
)
from harness.store_layout import (  # noqa: E402
    ENGAGEMENT_ENV_VAR, _ENGAGEMENTS_DIRNAME, _EXPORTS_DIRNAME, _ENGAGEMENT_DB_NAME,
    _ENGAGEMENT_MANIFEST, _ENGAGEMENT_LOCK, _CLOSING_PREFIX, _STORE_LAYOUT_VERSION,
    EngagementStoreActive, _named_engagement_id, engagement_store_key, active_engagement,
    legacy_store_path, engagements_root, engagement_store_dir, engagement_store_path,
    _manifest_engagement, _claim_engagement_dir, _hold_store_lock, _release_store_lock,
    interrupted_closes, select_engagement_store, isolate_engagement_context,
    bind_engagement_context, bind_captured_principal_context, captured_principal_id,
    _engagement_partition,
)
from harness.store_findings import (  # noqa: E402
    _FINGERPRINT_ALGO_VERSION, _normalize_endpoint, finding_fingerprint, host_of, persist_findings,
    bind_confirmation_proof, finding_observations, _strip_backticks, prior_findings_summary,
    all_host_findings, _resolve_confirmation_proofs, suppress_finding, unsuppress_finding,
    is_suppressed, list_suppressions, record_issue_merge, remove_issue_merge, all_issue_merges,
)
from harness.store_observations import (  # noqa: E402
    _OBSERVATION_FACTS_MAX_BYTES, _OBSERVATION_EVIDENCE_MAX_BYTES, _OBSERVATION_KEYS_MAX,
    _OBSERVATION_LABEL_MAX, _ATTRIBUTION_FIELDS, _CAPTURE_FIELD_DEFAULTS, _UNSAFE_STRUCTURAL,
    _UNSAFE_ATTRIBUTION, _CREDENTIAL_SHAPED, ObservationRevisionConflict, ObservationDeleted,
    _supplied_capture_fields, exchange_identity, _observation_host, _observation_endpoint,
    _observation_id, _structural_label, _store_key, _observation_digest, _observation_facts,
    _observation_evidence, clean_observation_attribution, _unknown_attribution,
    _current_attributions, record_observation, _attribution_join, select_observations,
    observation_context_block, _blob_still_referenced, correct_observation_attribution,
    delete_observation, resolve_observation_refs, get_observation,
)
from harness.store_plans import (  # noqa: E402
    _persist_test_plans_for, persist_test_plans, persist_retry_plan, get_test_plan,
    get_lineage_attempts, _CONFIRMATION_CAPABILITIES, capability_can_confirm,
    _CONTENT_REFUSAL_MESSAGES, _submission_content_refusal, persist_validation_submission,
    _PLANE_DISPATCHABLE_STATUSES, PLANE_REFUSAL_REASONS, _nonce_digest, issue_plane_dispatch,
    persist_plane_submission, record_plan_dispatch, mark_plan_not_dispatchable, plan_dispatch_notes,
    _WORK_ITEM_COLUMNS, _WORK_ITEM_BUDGET_STATUSES, _work_item_row_to_dict, _begin_immediate,
    enqueue_work_item, get_work_item, list_work_items, reclaim_expired_leases, lease_next_work_item,
    complete_work_item, fail_work_item, engagement_budget_reserved,
)
from harness.store_proofs import (  # noqa: E402
    persist_proof_record, _proof_row_to_dict, proofs_for_case, best_proof_for_case,
    EVIDENCE_BLOB_UNREDACTED_POLICY, UnredactedEvidenceError, evidence_blob_redaction_status,
    put_evidence_blob, iter_evidence_blobs, get_evidence_blob, evidence_blob_resolves,
    proofs_for_run,
)
from harness.store_ledger import (  # noqa: E402
    persist_ledger_event, _LEDGER_CHAIN_COLUMNS, _LEDGER_CHAIN_LINK, iter_ledger_chain_rows,
    ledger_events_for, ledger_events_for_many,
)
from harness.store_engagement import (  # noqa: E402
    EngagementRevisionConflict, _read_engagement, _write_engagement, save_engagement,
    load_engagement, mutate_engagement, save_knowledge_note, list_knowledge_notes,
    is_chain_already_detected, mark_chain_detected, _NO_ACTIVE_VALIDATOR, set_coverage_override,
    clear_coverage_override, coverage_report, save_identity, list_identities, get_identity,
    save_session, sessions_for_host, save_ownership_fact, _ownership_row_to_dict,
    get_ownership_fact, ownership_facts_all, set_identity_principal_meta,
    get_identity_principal_meta, save_engagement_declarations, load_engagement_declarations,
)
from harness.store_maintenance import (  # noqa: E402
    purge_evidence_blobs_older_than, apply_retention_policy, apply_retention_from_config,
    _ledger_blob_hashes, wipe_engagement, list_engagement_stores, close_engagement,
    engagement_retention_days, expired_engagement_stores, apply_engagement_retention,
)

# OPS-5: a store named in the environment is selected at import. If that fails, Python drops
# this module from sys.modules but the repositories stay loaded, bound to it; forget them too,
# so a retried import builds a facade they read through instead of this discarded one.
try:
    if os.environ.get(ENGAGEMENT_ENV_VAR):
        try:
            select_engagement_store(os.environ[ENGAGEMENT_ENV_VAR])
        except ValueError as exc:
            raise ValueError(f"{ENGAGEMENT_ENV_VAR}: {exc}") from None
except BaseException:
    for _repository in [name for name in sys.modules if name.startswith("harness.store_")]:
        del sys.modules[_repository]
        sys.modules["harness"].__dict__.pop(_repository.rpartition(".")[2], None)
    raise
