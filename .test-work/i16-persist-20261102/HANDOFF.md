# I16 rebase + persistence — handoff (2026-11-02)

Branch `claude/i16-persist-77da6a` (I16 wiring rebased onto `origin/main` 9b02511, PRs #3-#7).
Not pushed. Offline only: synthetic store, owned loopback fixture, no live target, no config
default change, no answer keys or blind material read.

## Part 1 — rebase

`git rebase origin/main` applied the three I16 commits with **no conflicts** (the expected
`orchestrator_chain.py` / `engagement_builder.py` conflicts did not occur: I16 never touched
`engagement_builder.py`, and its `orchestrator_chain.py` hunks sit clear of AR-09/AR-FP).
Both behaviours present: I16 kwargs + merge block + hint `elif` alongside main's AR-09/AR-FP.
Rebased commits: 96ace29, b858217, 1446237; record commit c9dee9a.

Gates after rebase (`rebase-py312.status`, `rebase-py314.status`): precondition 0,
test_i16_wiring 0, smoke 0 on 3.12.14 and 3.14.7.

## Part 2 — persistence (owner decision 2026-11-02)

Saved per target, **never loaded by default**.

- **Save (explicit):** `PUT /engagement/{host}/declarations` `{base_url, protected_paths, owners}`
  replaces both lists for the target. Auth required; route host must match `base_url` (400);
  `base_url` must be in pre-authorized scope (403). Every entry must parse under the RV-S
  pattern grammar (`protected_routes.parse_pattern`) or the RV-T entry grammar
  (`ownership_declarations._entry`: keys path/owner/shared_with/public/authenticated only),
  else 422 and nothing is stored — so only paths and identity labels are ever written.
  Two empty lists delete the row. Saving starts nothing.
- **Read:** `GET /engagement/{host}/declarations?base_url=` (auth + read auth).
- **Opt-in load:** `InvestigateRequest.use_saved_declarations: StrictBool = False`. Resolved
  at the start of the investigate route (after scope checks, before the journal key), so an
  opted-in run is identical to one that sent the same lists.
- **Rule (request vs saved), per field:** a non-empty request list **replaces** the saved list
  for that field (never merged); an empty request field takes the saved list. The job result
  carries `declarations_source` = {field: `request` | `saved` | `none`} only when opted in.
- **Target key:** (lower-cased host, effective port) via `protected_routes._target_of`, so
  `https://h`, `https://h:8443` and `http://h` are three targets.
- **Passive default:** no flag → no load, no new result key, journal key byte-identical
  (`use_saved_declarations` is excluded from the key's `limits`).
- `wipe_engagement(host)` deletes the host's rows (bare host: every port; `host:port`: that one).

## Files

- `harness/store.py`: `_DECLARATIONS_SCHEMA` / `_DECLARATIONS_VERSION`, marker, init,
  `save_engagement_declarations`, `load_engagement_declarations`, wipe + inventory comment.
- `harness/server.py`: `use_saved_declarations`, `DeclarationsRequest`, `_declarations_target`,
  `_validated_declarations`, PUT/GET routes, opt-in resolution, journal-key exclusion.
- `harness/test_i16_persist.py` (new, 15 tests P1-P8).
- `harness/test_observation_migration.py`, `harness/test_proof_identity_migration.py`: new
  object/marker added to their legacy-identity sets and rollback SQL.
- `harness/test_i16_wiring.py`: journal-key "before" reconstruction excludes the new flag.
- `docs/PROTECTED_ROUTES.md`: saved-lists section.

## Migration review points (owner sign-off needed)

1. **New table** `engagement_declarations(host TEXT, port INTEGER, protected_paths_json,
   owners_json, declarations_version INTEGER, updated_at REAL, PK(host, port))`, created by
   `CREATE TABLE IF NOT EXISTS` on connect. No legacy table altered.
2. **Marker** `state_metadata('engagement-declarations-schema', '1')`. `PRAGMA user_version`
   unchanged (still 3, the fingerprint re-key's).
3. **Version semantics:** a row of another `declarations_version` reads as nothing saved
   (never applied). No backfill.
4. **Rollback SQL** (tested in `test_rollback_restores_the_legacy_store`):
   ```sql
   DROP TABLE engagement_declarations;
   DELETE FROM state_metadata WHERE name = 'engagement-declarations-schema';
   ```
   The previous build never reads either. Re-migrating recreates an empty table.
5. **Legacy read:** frozen pre-I02-C schema opened by this build — schema, rows and
   user_version unchanged; load returns None (`test_migration_is_additive_and_versioned`).
6. **Content:** paths and identity labels only; validated before write; no headers, cookies,
   tokens or bodies (entry with an `authorization` key → 422). Not engagement_id-partitioned
   (owner said "per host"); confirm that is wanted.
7. **Wipe:** included in `wipe_engagement` (host or host:port).
8. **Scope on save:** save requires the target to be in `server.allowed_hosts`; GET does not.

## Tests (caller level)

- Route (real FastAPI app, synthetic store, recorder at `investigate_engagement`): P1 control
  (saved, no opt-in → kwargs absent, no result key), P2 opt-in, opt-in with nothing saved,
  P3 request replaces per field, P4 host/port/scheme isolation, P5 validation/403/400/401,
  empty-save clears, P6 journal-key equality.
- P7 end to end: PUT → investigate route → real `investigate_engagement` on RV-S's loopback
  (production `_confirm` + missing-auth probe, run in a worker thread). `/reports/q3` stays a
  candidate without opt-in and confirms (source "engagement") with it. Limitation: the route's
  `base_url` is the synthetic captured.example; the loopback chain runs on its own origin
  (the bridge forwards only the resolved kwargs).
- P8 store migration/rollback/version/wipe.
- **Fails on base** (store.py + server.py reverted, 3.14): `before-fix.log` — 14 of 15 tests
  fail (failures=13, errors=10 incl. subtests). The P6 journal-key test passes on base
  trivially (pydantic ignores the unknown flag); it guards the key, not the feature.

## Gate results

VERIFIED NOW with `run_gates.sh <label> <python> full`, `PYTHONPATH=<worktree>`, head c9dee9a
plus the Part 2 working tree (diff hash `2ac96b0ceadf4833` identical before and after each run;
`persist-py312.status`, `persist-py314.status`; logs under `logs/`, not committed).

| Interpreter | Precondition | i16_wiring | i16_persist | Smoke | Full (harness / native / evaluation / integrity) |
| --- | --- | --- | --- | --- | --- |
| 3.14.7 (system) | 74 OK | OK | 15 OK | 149 OK | exit 0: 5085 OK / 38 passed / 440 OK, 17 skipped / 59 OK |
| 3.12.14 (venv) | 74 OK | OK | 15 OK | 149 OK | exit 0: 5085 OK / 38 passed / 440 OK, 17 skipped / 59 OK |

ResourceWarning count 0 in both full logs. `git diff --check` clean. Redaction/secret canary
suites are part of `full` and pass.

## Next step

- Owner sign-off on the migration review points above, then merge.
- **Java follow-up (not done):** `HarnessClient` PUT/GET `/engagement/{host}/declarations`
  and the `use_saved_declarations` flag on investigate; `HarnessPanel` fields to edit the two
  lists, a "Save for this target" action and an explicit "Use saved declarations" checkbox
  (default off). Needs JDK + I01 W-split / RV-K.
- Unchanged: `/probe-missing-auth` still uses its own `expected_protected`; the
  `identity_headers._STORE` leak in `investigate_engagement` is untouched (queued separately).
