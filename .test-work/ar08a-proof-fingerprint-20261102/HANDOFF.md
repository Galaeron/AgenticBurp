# HANDOFF — AR-08a proof identity fingerprint (2026-11-02)

Status: implemented and committed locally (not pushed). Design and tests: BATCH.md.

## ⚠ Reviewer sign-off required: schema migration
This adds a table to the state DB. The legacy-schema invariant says no new column or table
without a reviewed migration. The reviewer must check and sign off on:

1. **Shape.** A new side table `proof_identity(proof_id TEXT PRIMARY KEY, policy_fingerprint
   TEXT NOT NULL, identity_version INTEGER NOT NULL, created_at REAL NOT NULL)`
   (`store._PROOF_IDENTITY_SCHEMA`). It is used instead of `ALTER TABLE proof_records`, so the
   legacy `proof_records` DDL stays byte-identical. Confirm a side table keyed on `proof_id`
   (no FOREIGN KEY, matching the rest of the store) is acceptable.
2. **Versioning.** The `state_metadata` row `proof-identity-schema = '1'` is the marker.
   `PRAGMA user_version` stays at 3 because it is reserved for the finding-fingerprint re-key.
   Reads join only `identity_version = 1` (`store._PROOF_IDENTITY_VERSION`). A future
   fingerprint-formula change must bump the version: old rows then read as unknown, never
   as a stale match.
3. **No backfill.** Proofs written before this change have no row and read with
   `policy_fingerprint = ""`. They keep splitting per route, which is the safe direction
   (never merged on a guess). A backfill is impossible: the findings table never stored
   `header_fingerprint`. Confirm that historical runs staying split is acceptable.
4. **Write atomicity and immutability.** The identity row is written in the same
   transaction as the proof row, with INSERT OR IGNORE, only when the fingerprint is
   non-empty. Re-persisting the same `proof_id` keeps the first value, consistent with
   append-only proofs.
5. **Precedence.** `confirmed_issue_accounting` prefers the proof's persisted fingerprint
   and falls back to the finding's `header_fingerprint`. On the confirm path both come from
   the same `ValidationResult`, so they agree. Check that you agree the proof should win.
6. **Scope of what gets stored.** Any validator result with `header_fingerprint` and
   executed artifacts now stores one: jwt_forge, and also csp/cors. csp/cors grouping is
   unchanged (hardening groups on origin/validator/class). Experiment-path proofs
   (`experiment.py`, untouched) store none.
7. **Wipe.** `wipe_engagement` runs
   `DELETE FROM proof_identity WHERE proof_id NOT IN (SELECT proof_id FROM proof_records)`
   after its proof delete. This deletes orphans store-wide, not only for the wiped host.
   Orphans can only come from proof deletes. New count key: `proof_identity`.
8. **API shape.** Proof dicts (`ProofRecord.to_dict`, `store.proofs_for_*`) gain the key
   `policy_fingerprint`, a sha-256-based hash of alg/kid/typ/iss/aud. It holds no token or
   secret.
9. **Rollback** (tested in `test_rollback_restores_the_legacy_store_and_degrades_safely`):
   ```sql
   DROP TABLE proof_identity;
   DELETE FROM state_metadata WHERE name = 'proof-identity-schema';
   ```
   The previous build never reads either object. If the new build reopens the file, it
   recreates the table empty, and earlier proofs read as unknown (split, not an error).

## Changed files
- `harness/store.py`: schema, marker, persist, joined reads, wipe.
- `harness/evidence.py`: `ProofRecord.policy_fingerprint`, `from_validation_result`,
  `to_dict`/`from_dict`.
- `harness/validators/base.py`: `proof_artifact_kwargs` carries the fingerprint.
- `harness/assessment_health.py`: the proof fingerprint wins over the finding's.
- Tests: `test_proof_identity.py` (caller level plus the legacy control),
  `test_proof_identity_migration.py` (new), `test_observation_migration.py` (known new
  objects).

## Gates (this worktree, `PYTHONPATH=<worktree>`)
Both runs were on the uncommitted tree over base `ff6f7a0`, with the same sources as the
commit. The two runs were concurrent. Exit codes are in `py312.status` and `py314.status`;
logs (not committed) are under `logs/`.

| Gate | venv 3.12.14 | system 3.14.7 |
|---|---|---|
| `unittest harness.test_orchestrator_precondition` | 0 (74 OK) | 0 (74 OK) |
| `harness.suite smoke` | 0 (149 OK) | 0 (149 OK) |
| `harness.suite full` | 0: harness 5024 OK, native 38 passed, evaluation 440 OK / 17 skips, integrity 59 OK | 0: same counts |
| `git diff --check` | clean | — |

Harness 5024 = main's 5014 + 10 new tests (2 caller-level + 8 migration).

## Next
- Reviewer sign-off on the migration (above).
- AR-08b (route-independent identity beyond jwt_forge, `issues.py` `issue_key`) depends on
  this item and is not started.
