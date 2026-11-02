# HANDOFF — AR-08b route-independent issue identity (2026-11-02)

Status: implemented and committed locally (not pushed). Built on AR-08a (`37bcb62`), which
is not yet reviewed or merged: review/merge AR-08a first. The AR-08a migration is
unchanged. Design, per-mechanism decisions and tests: BATCH.md.

## What changed
- `harness/issues.py`: `ROUTE_INDEPENDENT_MECHANISMS` (moved here from assessment_health),
  `_policy_of` (persisted proof fingerprint wins over `header_fingerprint`),
  `_route_independent_identity`, and a new `issue_key` branch: host + class + carrier +
  read/write boundary + (mechanism, policy, principal, workflow state); no endpoint
  family/method. csp/cors E2 now also reads the persisted fingerprint. The export emits
  `affected_routes` for route-independent issues.
- `harness/store.py`: `all_host_findings` gains read-only additive keys `validator`,
  `workflow_state_id`, `policy_fingerprint` (joins on the finding's exact proof id and
  `proof_identity` version 1). No schema change.
- `harness/report_generator.py`: `ReportFinding` carries the same fields, `_dedup_key`
  passes them (Markdown collapse = export key), and a collapsed route-independent finding
  lists all its locations.
- `harness/assessment_health.py`: imports the shared set (behavior unchanged).
- New test: `harness/test_issue_identity_routes.py` (8 tests).

## Reviewer attention
1. **Read/write boundary.** The report key keeps read vs write apart; the accounting key
   (`confirmed_issue_accounting`) does not. So GET and POST routes of one JWT policy are
   two report issues but one accounting group. Chosen as the conservative direction;
   relax it only if you agree a token-verifier flaw is boundary-independent.
2. **`_ISSUE_VERSION` not bumped.** A bump would re-key every issue and break retest
   linkage. The new key shape cannot collide with v2 keys. jwt issues whose proofs carry a
   fingerprint get a new (now route-independent) id; older jwt proofs keep the old id.
3. **E2 store-path change.** Stored csp/cors findings whose proof has a persisted
   fingerprint now group across routes (previously only in-run findings did).

## Gates (this worktree, `PYTHONPATH=<worktree>`, uncommitted tree over `66e7724`, same sources as the commit; runs concurrent)
| Gate | venv 3.12.14 | system 3.14.7 |
|---|---|---|
| `unittest harness.test_orchestrator_precondition` | 0 (74 OK) | 0 (74 OK) |
| `harness.suite smoke` | 0 (149 OK) | 0 (149 OK) |
| `harness.suite full` | 0: harness 5032 OK, native 38 passed, evaluation 440 OK / 17 skips, integrity 59 OK | 0: same counts |
| `git diff --check` | clean | — |

Harness 5032 = AR-08a's 5024 + 8 new. Exit codes in `py312.status` / `py314.status`; logs
under `logs/` (gitignored).

## Follow-ups (not done)
- `crypto_validator` (TLS) is host:port-level by nature but persists no policy
  fingerprint; it stays route-scoped until it records one (protocol/cipher/cert).
