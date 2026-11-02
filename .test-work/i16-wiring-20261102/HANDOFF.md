# I16 wiring (Python side) — handoff

Branch `claude/i16-wiring-2a18d0`, base `ff6f7a0`. Not pushed. Offline only (owned loopback
fixtures); no live target, no config default change, no answer keys read.
Scope and sources: BATCH.md.

## What was wired

1. **Protected routes** — `POST /engagement/{host}/investigate` takes
   `protected_paths: list[str]` (max 1000) → `investigate_engagement(protected_paths=...)` →
   merged into `state.protected_paths` after discovery (built or journal-restored) → read by
   the chain's missing-auth branch (RV-S, source "engagement").
2. **Ownership** — same path for `owners: list[dict]` → `state.owners` → `_configure_ownership`
   / `_experiment_ownership` (RV-T). Entry validation stays in `ownership_declarations`.
3. **`suggested_test`**
   - Unlisted route (RV-S residual 4): when the anonymous replay served data on a route that
     is not declared, the candidate's `suggested_test` now begins with a declaration hint
     (route, `authz.protected_paths['<host[:port]>']`, the request's `protected_paths` field).
     Summary and evidence are untouched (RV-M M1 assertions unchanged).
     `ProtectedRoutes.declaration_hint` builds it.
   - Export parity (I04 note): `issues.export_issue` carries `suggested_test` (redacted, 1200
     chars), SARIF results carry `properties.suggestedTest`, and SARIF import reads it back
     (still advisory, never confirmed).

Passive defaults: an absent or empty list is not forwarded, sets nothing, and leaves the E7
journal context key byte-identical to before (the new fields are excluded from the key unless
non-empty; a declared list is part of the key, so resuming needs the same declarations).

## Files (minimal edits in files owned by unmerged branches)

- `harness/orchestrator_chain.py` (PR #3's file): two kwargs + docstring, one 6-line merge
  block after discovery, one `elif` in the missing-auth branch. No other change.
- `harness/issues.py` (AR-08 file): one key at the END of `export_issue`'s dict, clear of
  AR-08b's `affected_routes` hunk.
- `harness/server.py`: `Field` import, two request fields, two forwarded kwargs, journal key.
- `harness/protected_routes.py`, `harness/sarif_adapter.py`, `docs/PROTECTED_ROUTES.md`.
- `engagement_builder.py`, `store.py`, `evidence.py`: not touched.
- New: `harness/test_i16_wiring.py` (14 tests).

## Evidence

- Before the change (3.14): 14 tests, failures=7, errors=11 (`repro/before-fix.log`).
- After: 14 OK (`repro/after-fix.log`).
- Controls: unlisted route stays a candidate (one anonymous request, not confirmed);
  `protected_paths=[]`/`owners=[]` give the same requests and findings as no kwargs;
  a listed route that answers 401 gives no finding and no hint; `owners=[]` confirms nothing.
- Fault injection: `fault/run_faults.py` → 8 of 8 caught, sources restored byte for byte
  (`fault/summary.txt`).
- Related suites (3.14): protected_routes_rvs, chain_coverage_rvm, cross_request_decisions_rvt,
  job_status_passive, csrf_label_storage_export, missing_auth_probe, config_schema and the
  sarif/issue/export modules → Ran 240, OK (`repro/related-314.log`).
- Gates: see "Gate results" below.

## What remains

- **Java-only (out of scope, needs JDK + I01 W-split / RV-K):** HarnessPanel fields and
  HarnessClient sending `protected_paths`/`owners` with the investigate request; the Burp
  "Probe missing auth" panel baseline (RV-S interim choice).
- **Persistence:** lists are per request, not stored per host. Storing them needs store.py
  (AR-08 owns it) plus an owner decision on whether a stored list should apply to later runs.
- `/probe-missing-auth` (server route) does not consult `protected_paths` from requests;
  it keeps its own `expected_protected` input. Not changed.
- RV-S residuals 2 (custom-header-only auth) and 3 (probe `_strip_auth`) remain open.
- The X2/loopback tests are caller-level offline tests, not a live check.

## Gate results

VERIFIED NOW, `run_gates.sh` from the worktree root with `PYTHONPATH=<worktree>` and the
untracked `sitecustomize.py`, head `ff6f7a0` plus this working tree (source hash
`6ea3d332daee1008` identical before and after each run; `py312.status`, `py314.status`).

| Interpreter | Precondition | test_i16_wiring | Smoke | Full (harness / native / evaluation / integrity) |
| --- | --- | --- | --- | --- |
| 3.14.7 (system) | 74 OK | 14 OK | 149 OK | exit 0: 5028 OK / 38 passed / 440 OK, 17 skipped / 59 OK |
| 3.12.14 (venv) | 74 OK | 14 OK | 149 OK | exit 0: 5028 OK / 38 passed / 440 OK, 17 skipped / 59 OK |

ResourceWarning count 0 in both full logs. `git diff --check` clean.

`attempt1/` is the first run, not counted: smoke and full each failed only
`test_no_orphan_test_files.test_every_definition_has_a_runner`. The guard proves TestCase
ancestry statically and did not follow `rvs._ChainCase`. Fix: list `unittest.TestCase` as an
explicit second base of `ProtectedPathsReachTheChainTests`. The 3.14 attempt-1 run spans
that edit (its after-hash differs).
