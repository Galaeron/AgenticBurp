# LB-6 (LOOP half) — runner objective-completion wiring — HANDOFF

Branch `claude/lb6-objective-69375f`, base `origin/main` `9b02511`. Not pushed.

## What landed
- `2026b8c` — `harness/objective_profiles.py`: `ObjectiveDeclaration`, the typed profile
  (required end state, action class, mutation level, oracle adapter, request ceiling).
  It may narrow a registered profile but never widen it. New fields: `mutation_level`
  (`read_only`/`destructive`) and `ObjectiveTask.destructive_opt_in` (default False).
  `attempt_completion` returns `objective_not_attempted` for a destructive profile without
  opt-in, and when the ceiling cannot cover the action plus its oracle. The existing SSTI
  file-delete tests now pass `destructive_opt_in=True`.
- `5c9c086` — `run_web_objective_smoke.py`: `--objective-profile` (JSON file/inline) and
  `--allow-destructive-objective`. The task goes on `RunContext.objective_task` (new field
  and `create()` kwarg); `investigate_engagement` falls back to it (4 lines in
  `orchestrator_chain.py`). `attempt.json` gains an `objective` block, default
  `objective_not_attempted`.
- Tests: `testing/test_run_web_objective_profile.py` (11 tests). They run the real runner
  against an in-process loopback fixture (vulnerable / arithmetic-only / fixed).
  SSTI confirmation is the real validator; the IDOR cross-identity proof is stubbed
  because the fixture has no second identity.

## Defect injection (venv 3.12, VERIFIED)
| Removed | New-test result |
|---|---|
| RunContext fallback in `investigate_engagement` | 5 FAIL |
| Runner passes `objective_task=None` to `RunContext.create` | 5 FAIL |
| Destructive opt-in check in `attempt_completion` | 1 FAIL |
| (restored) | 11 OK |
There is also an in-suite control that strips the task on its way into RunContext.

## Gates (head `5c9c086`, PYTHONPATH=worktree; `py312.status`, `py314.status`)
| Gate | venv 3.12.14 | system 3.14.7 |
|---|---|---|
| test_orchestrator_precondition | 0 | 0 |
| new tests (profile + completion + wiring, 33) | 0 | 0 |
| suite smoke | 0 | 0 |
| suite full (harness 5056; eval 451/17 skips; integrity 59) | 0 | 0 |
| git diff --check origin/main HEAD | 0 | 0 |
The backlog note and this file were committed after the gate run; they are docs only.

## Owner questions
1. Should `--allow-destructive-objective` also need a config key (for example
   `objectives.allow_destructive`), or is the CLI flag enough? Today it is CLI only.
2. Which labs get a declared profile? ssrf-basic has no registered profile yet;
   access-admin maps to `access_admin_read`; ssti-basic to `ssti_file_delete` (destructive).
3. Should the runner refuse an objective target or oracle URL outside `--target`'s host?
   Today the RunContext scope blocks off-scope sends, so the result is POLICY_BLOCKED.

## Stays OWNER/LIVE
- Any run against a live lab or benchmark with a profile declared. LB-6 stays `[ ]`.
- Destructive (`ssti_file_delete`) completion on a real target.
- A registered SSRF objective profile and its oracle adapter.
