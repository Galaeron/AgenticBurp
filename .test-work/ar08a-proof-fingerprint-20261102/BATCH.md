# Batch AR-08a — persist the proof identity fingerprint (2026-11-02)

Backlog: `IMPROVEMENT_BACKLOG.md` "AR-08a — Persist the proof identity fingerprint on proof
records". Base: `ff6f7a0` (main). Branch: `claude/ar-08a-proof-fingerprint-0706ca`.
Mode: offline LOOP; the migration needs reviewer sign-off (see HANDOFF.md).

## Problem
Batch 08 (`56c04dc`) groups equivalent route-independent proofs (`jwt_forge`) on host,
mechanism, boundary, check family and the policy fingerprint. That fingerprint lived only
on the in-run `Finding.header_fingerprint`. `store.all_host_findings` has no such column,
so `confirmed_issue_accounting` over store-only data saw policy "" and split one flaw into
one issue per route.

## Scope
- In: persisting the fingerprint with the proof, a versioned additive migration, the
  store read and grouping path, legacy-read and rollback tests, and a caller-level
  regression with a legacy control.
- Out: AR-08b (more route-independent mechanisms; `issues.py` `issue_key`), any backfill
  of old proofs, live runs, config defaults.
- Not touched (parallel streams): `orchestrator_chain.py`, `experiment.py`,
  `iterative_agent.py`, `orchestrator_confirm.py`, `engagement_builder.py`, redaction.

## Design
- `ProofRecord.policy_fingerprint` (default ""), set through
  `validators.base.proof_artifact_kwargs` from `ValidationResult.header_fingerprint`.
  Every confirm-path `from_validation_result` call already spreads those kwargs, so no
  orchestrator file changes.
- New side table `proof_identity(proof_id PK, policy_fingerprint, identity_version,
  created_at)` plus the `state_metadata` marker `proof-identity-schema = 1`.
  `proof_records` is not altered and `PRAGMA user_version` is not bumped.
- Written in the same transaction as the proof row (INSERT OR IGNORE, only when non-empty).
- Read through a LEFT JOIN in `proofs_for_case` and `proofs_for_run`, filtered on
  `identity_version = 1`. A missing row or a row of another version reads as "".
- `confirmed_issue_accounting` prefers the proof's persisted fingerprint and falls back to
  the finding's. "" never merges routes (unchanged batch-08 rule).
- `wipe_engagement` deletes `proof_identity` rows whose proof is gone (count key
  `proof_identity`).

## Tests
- `harness/test_proof_identity.py` (caller level, real JwtForgeValidator, real confirm path,
  findings persisted with `store.persist_findings` and read back with
  `store.all_host_findings`, as server.py does):
  `test_store_only_proofs_group_exactly_as_in_run_proofs` (same policy → 1 issue; distinct
  policies → 2; groups, ids, identity and counts equal to the in-run accounting) and
  `test_legacy_proof_without_fingerprint_degrades_and_never_merges` (control).
  Both failed before the fix (store-only split into 2; the control had no table).
- `harness/test_proof_identity_migration.py`: legacy fixture DB, additive/no backfill,
  legacy read as "", legacy proofs never merged, round trip and idempotent reopen, no row
  for an empty policy, unknown version reads "", rollback restores the legacy schema exactly,
  and the wipe removes the fingerprint.
- `harness/test_observation_migration.py`: `proof_identity` and its marker added to the
  set of known new objects. The legacy-identity and user_version checks are unchanged.
- Defect injection: ignoring the stored fingerprint in `assessment_health` makes the two
  caller tests fail (2 failures). Restored.

## Gates
`run_gates.sh <label> <python>` writes `<label>.status` (exit codes only) and logs under
`logs/` (not committed). Results: HANDOFF.md.
