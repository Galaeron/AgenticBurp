# AR-10 — integrated acceptance and model-evaluation specification

Status: specification only (2026-11-02). Nothing here is accepted, and no live target run
or model A/B has been performed. Source: "Batch 10" in
`.test-work/assessment-integration-20261023/architecture-repair/IMPLEMENTATION_TASK.md`
(main checkout), plus REVIEWER_BRIEF.md in the same folder. IMPLEMENTATION_TASK.md names no
output path for batch 10, so this file is the spec. Backlog item: AR-10 in
IMPROVEMENT_BACKLOG.md.

The work has three parts, each its own task:

| Part | Mode | Section |
|---|---|---|
| A. Merge the open branches, then run the integrated offline acceptance | LOOP (merge: owner approval) | 1, 2 |
| B. One live acceptance run on the owned target | OWNER/LIVE, separate execution task | 3 |
| C. Model evaluation (supplied plan, unaided discovery, model A/B) | OWNER/LIVE, separate execution task | 4 |

B and C cannot start until A is green on the frozen merged tree. C also needs the
prerequisites in section 4.1.

## 1. Merge order for the open branches

All five lines branch from `main` `ff6f7a0`. Not one of them is merged.

| # | Line | Commits over ff6f7a0 | Harness files touched |
|---|---|---|---|
| 1 | AR-09 + AR-FP, PR Galaeron/AgenticBurp#3, `codex/ar-09-worker-mechanisms` | dd179bb, 74b44cf, 662ba61 | experiment.py, iterative_agent.py, orchestrator_chain.py, orchestrator_confirm.py; tests: test_experiment_final_pass (new), test_iterative_worker_mechanisms (new), test_instrumentation, test_iterative_probe_run_context |
| 2 | AR-08a, PR Galaeron/AgenticBurp#4, `ar-08a-proof-fingerprint` | 37bcb62, 66e7724 | store.py, evidence.py, validators/base.py, assessment_health.py; tests: test_proof_identity, test_proof_identity_migration (new), test_observation_migration |
| 3 | AR-08b, `ar-08b-issue-identity` (contains 2) | + aaf166f, 6254897 | issues.py, report_generator.py, store.py, assessment_health.py; test_issue_identity_routes (new) |
| 4 | AR-08c, `ar-08c-audit-procedures` | a219659, c73f261 | none (replay_audit.py and its tests are under `.test-work/ar08c-audit-procedures-20261102/`) |
| 5 | AR-ID + redaction false positive, `arid-redaction` | c327796, dec3828, 7da1cd9 | engagement_builder.py, security.py; test_seed_capture_identity (new), test_secret_canary_sinks; CURRENT_STATE.md |

The `claude/...` branches with the same names point at the same commits (checked with
`git log ff6f7a0..<branch>`).

**Textual conflicts: none expected.** No two lines share a harness file. 2 is an ancestor of 3.
The only shared file is IMPROVEMENT_BACKLOG.md (and CURRENT_STATE.md in 5), in separate hunks.
Checked offline on 2026-11-02 with `git merge-tree --write-tree`: all six pairs of lines 1/3/4/5
merge cleanly, and so does the sequence 1 → 3 → 4 → 5 (probe commit `7d1549e`, branch
`ar10-merge-probe`, worktree `.test-work/wt-ar10-merge-probe` in the main checkout; not for merging).

**Recommended order** (dependency order first, then reviewer gates):

1. PR #3 (AR-09 + AR-FP). Part C depends on it, and the I16 wiring session rebases onto it
   (both change `orchestrator_chain.py`).
2. PR #4 (AR-08a), **only after the reviewer signs off on the `proof_identity` migration**
   (nine points in its HANDOFF.md). If sign-off is withheld, 3 is blocked too.
3. `ar-08b-issue-identity` (fast-forwards over 2). Reviewer note: the read/write boundary stays
   split in the report key.
4. `ar-08c-audit-procedures`.
5. `arid-redaction`. On the CURRENT_STATE.md hunk, take the branch's item-4 text, then
   rewrite CURRENT_STATE for the merged main (part A, step 6).

**Expected semantic interactions to check after merging** (not conflicts):

- AR-08b changes issue keys for proofs that carry a persisted fingerprint. AR-FP's final
  pass adds experiment proofs. Experiment-path proofs store no fingerprint (AR-08a item 6),
  so their issue keys should be unchanged. `test_experiment_exports` and
  `test_experiment_final_pass` must pass together.
- AR-ID changes `build_engagement` seed binding. Previously unbound cookie captures can now
  bind to a declared role and become inputs to experiments and the iterative worker.
  `test_seed_capture_identity` must pass beside `test_iterative_worker_mechanisms` and
  `test_experiment_cycle`.
- Parallel sessions that will need rebasing: **I16 wiring** (likely `orchestrator_chain.py`,
  `engagement_builder.py`; overlaps lines 1 and 5) and **DET-JWT-SCOPE** (likely
  `orchestrator_helpers.py`; no overlap seen). They rebase after these merges; they don't
  block part A. If they land first, rerun part A.

## 2. Part A — integrated offline acceptance (LOOP)

Run on the merged tree with source frozen. It runs in a fresh batch folder
`.test-work/ar10-integrated-acceptance-<date>/` with BATCH.md, FREEZE.json, SUMMARY.json and
HANDOFF.md, following the batch protocol (steps 1–8 of IMPLEMENTATION_TASK.md).

### 2.1 Freeze and attestation

- Record `git rev-parse HEAD`, `git status --short` (must be clean apart from the batch folder),
  interpreter versions, and `harness.__file__` per interpreter. The import must resolve inside
  the checkout: use `PYTHONPATH=<checkout>` and the untracked `sitecustomize.py` that drops
  the editable finder (copy from `.test-work/wt-ar09/`).
- Hash every `harness/**/*.py`, `harness/config.yaml` and the two `.test-work` scripts used
  below, before and after each stage. Any change invalidates the run.
- `harness/config.yaml` must be byte-identical to `main`. No `config.local.yaml` in the checkout.

### 2.2 Required checks (all must pass together, on both 3.12 and 3.14)

Interpreters: system `C:\Users\arthu\AppData\Local\Python\pythoncore-3.14-64\python.exe`
(3.14.7, matches CI) and the venv `.venv-rationalisation\Scripts\python.exe` (3.12.14). A missing
interpreter makes the gate unverified, not passed.

| Stage | Command (from checkout root) | Pass rule |
|---|---|---|
| A1 cross-batch caller set | `python -m unittest harness.test_iterative_worker_mechanisms harness.test_experiment_final_pass harness.test_instrumentation harness.test_iterative_probe_run_context harness.test_iterative_experiments harness.test_experiment_termination harness.test_experiment_cycle harness.test_experiment_exports harness.test_browser_experiments harness.test_proof_identity harness.test_proof_identity_migration harness.test_observation_migration harness.test_issue_identity_routes harness.test_seed_capture_identity harness.test_secret_canary_sinks harness.test_target_transport harness.test_attempt_facts harness.test_execution_registry harness.test_cors_transport harness.test_coverage_cases harness.test_job_status_passive harness.test_pipeline_gate harness.test_no_orphan_test_files` | exit 0, 0 skips in the browser modules (Playwright + Chromium present) |
| A2 audit procedures | `python -W error::ResourceWarning -m unittest discover -s .test-work/ar08c-audit-procedures-20261102 -t .test-work/ar08c-audit-procedures-20261102 -p test_replay_audit.py` | 14 OK |
| A3 D0 diagnostics | copy `diagnostics.py` (sha256 `2fbf574f…3e2d`) from `.test-work/wt-cors-r1/.test-work/architecture-d0-20261029/` into the batch folder, check the hash, run `python .test-work/<batch>/diagnostics.py` | **8/8 IDs pass**, 0 skips, 0 `unresolved_required_proofs`, in the RESULTS.json it writes next to itself |
| A4 precondition | `python -m unittest harness.test_orchestrator_precondition` | 74 OK (or the merged count) |
| A5 smoke | `python -m harness.suite smoke` | exit 0 |
| A6 full | `python -m harness.suite full` | exit 0; counts recorded per tier |
| A7 hygiene | `git diff --check`; config.yaml hash equal to main | clean |

The D0 driver writes RESULTS.json and T*.log beside itself. Never run it in its historical
folder: that would overwrite the recorded v2/v3 results.

What the stages cover, per batch:

| Batch / item | Caller-level evidence in A1–A3 |
|---|---|
| R1, 01 | T1; test_cors_transport, test_target_transport (decoded-response contract) |
| R2, 04 | T2; test_execution_registry (incomplete recovery, conditional reuse) |
| R3, 02 | T3; test_coverage_cases, test_job_status_passive, test_attempt_facts |
| 00, 03 | T4; test_no_orphan_test_files, dispatch/readiness via test_experiment_cycle |
| 05 | T5; test_experiment_cycle, test_experiment_exports |
| 06 | T6, T7; test_browser_experiments (real Chromium) |
| I0, 07 | T8; test_iterative_experiments, test_experiment_termination |
| 08, AR-08a, AR-08b | test_proof_identity, test_proof_identity_migration, test_observation_migration, test_issue_identity_routes |
| AR-08c | A2 |
| AR-09 | test_iterative_worker_mechanisms (includes its unplug control) |
| AR-FP | test_experiment_final_pass (includes its unplug control), test_instrumentation |
| AR-ID, redaction | test_seed_capture_identity, test_secret_canary_sinks |
| pipeline gate | test_pipeline_gate (defect-injection controls) |

Partial evidence already gathered (probe tree `7d1549e`, 3.14.7 only, not frozen, not a pass of
this part): A1 subset of 12 new or changed modules plus precondition, 197 OK; A2, 14 OK. The
full-suite result for the probe tree is in `.test-work/wt-ar10-merge-probe/.test-work/ar10-probe/`
in the main checkout, if that run finished.

### 2.3 Deliverables of part A

1. SUMMARY.json with each stage's command, cwd, interpreter, exit code, counts, skips, duration
   and source hash.
2. **ISSUE_MATRIX.md**: one row for each of A–U in REVIEWER_BRIEF.md, linking the implementing
   commit and test, or an explicit deferred limitation. Start from the 2026-10-29
   `final-integrated-20261029/ISSUE_MATRIX.md` (wt-cors-r1). Update rows O, P (AR-09), N
   (AR-FP), R (AR-08a/b) and S (AR-08c). Row T stays "no expected-positive mapping" until part C.
   No row may claim complete vulnerability coverage.
3. HANDOFF.md, and CURRENT_STATE.md rewritten for the merged main (under 100 lines).

Part A fails if any stage fails, any required skip appears, the source hash changes, or a row in
the matrix cites only a helper test.

## 3. Part B — live acceptance run (OWNER/LIVE, separate execution task)

This defines the run. It does not authorize it. The owner writes an execution task (a
`RUN_INSTRUCTIONS-ar10-*.md` modelled on `RUN_INSTRUCTIONS-v10-full.md`) and starts it. Part A
must be green first, and AR-PKG must be done (the server is proven to run the committed source).

### 3.1 Target and authority

- Only the owned container `av-eval-js-daybreak-20261021` at `http://127.0.0.1:3002`
  (Ticket 8 authorization). Port 3000 and every other service stay untouched.
- Record the container image digest and the target's self-reported version **read at run
  time**. Don't infer it from notes or the tag. If no version can be read, record "unverified".
- Two fresh ordinary accounts registered through the target's UI (`accounts.py`). No
  administrator. Credentials stay in `*-private.json`, unread.
- sqlmap only via the Docker image `harness/sqlmap:1.10.9`. Callback origin
  `http://host.docker.internal:<port>` with a passing container-callback preflight.

### 3.2 Run shape

- Package: a snapshot of the frozen part-A tree. prepare compares its harness hashes against
  part A's FREEZE.json and refuses on mismatch.
- Same shape as v10, so results can be compared: max_nodes 100, step_budget 64, chain rounds 10,
  active discovery, leg budget 2000, 8 h outer wall cap, no request cap, review 7200 s,
  investigation 15000 s, coverage 7200 s.
- Live toggles only in the snapshot's ignored `config.local.yaml`. Engagement experiments and
  planner enabled, with their effective values recorded in an **enabled-feature manifest**
  (active testing, mutating replay, experiments, planner, browser, each mechanism ID/version,
  each unavailable or container-disabled mechanism with its reason).
- Model: local `gemma4:latest` for every stage, cloud off, `ollama.seed` fixed and recorded.
- One run. A failure after prepare reruns with a new suffix; evidence is never deleted.

### 3.3 Pass/fail criteria

Pass means the integrated pipeline behaves honestly live. It is not a recall target.

| # | Criterion | Artifact |
|---|---|---|
| L1 | Job reaches `done`; export integrity passes | job-status.json, result-integrity.json |
| L2 | Every required pin and manifest present | live-settings.json, effective-config.json, loaded-package.txt, the feature manifest |
| L3 | Every experiment task has a final disposition with a typed `blocked_on` where not completed; none left `advisory` when it was READY | `result.json` → `task_dispositions` (schema 2), `experiment_final_pass` |
| L4 | Final pass ran, or the reason it didn't is recorded | `result.json` → `experiment_final_pass` |
| L5 | Every proof link shown in the issue export resolves; orphaned proof links (batch 08) are listed for repair, never silently dropped | issue export pages, store `proof_records` + `proof_identity` |
| L6 | JWT alg:none (if confirmed) is one route-independent issue with `affected_routes`, not one per route (v10: 19 groups) | issue export, `affected_routes` |
| L7 | Replay audit reports each claim as audited, not audited or `unsupported_audit` with reason; no class counted as zero false positives without a procedure | replay-audit.json from the AR-08c `replay_audit.py` |
| L8 | Replay-audit false positives = 0 | replay-audit.json |
| L9 | No cookie-bearing seed capture silently dropped: each binds or is reported unbound by header names | `result.json` engagement errors |
| L10 | No credential, token or secret in exports; csrf/auth metric counts not redacted | export pages (canary scan by script, names only) |
| L11 | Login SQLi on `/rest/user/login` still confirmed with replay verdict confirmed (v10 regression check) | replay-audit.json |

L1–L5 and L7–L10 are hard failures. L6 and L11 failing is a regression to investigate. It is
reported, not hidden. It doesn't count as a pass.

### 3.4 Reported metrics and their sources

| Metric | Source |
|---|---|
| Coverage funnel, terminal reasons, sent by check | `result.json` → `coverage_funnel`, `terminal_reasons` (analyze_live.py) |
| Requests, model calls, errors, retries, phase durations | `result.json` costs, network.jsonl (counts only) |
| Proof instances, proof-bound cases, vulnerability groups (three separate counts) | store proofs, issue export |
| Experiment dispositions and final-pass outcome | `task_dispositions`, `experiment_final_pass`, `experiment_preflight` |
| Iterative steps, duplicate share, stop reasons | worklist outcomes `stop_reason`; per-probe `iterative_result.diagnostics` (see 4.1 P1) |
| Audit states | replay-audit.json |
| First failing boundary per migrated mechanism | dispositions + attempt records |

Report marginal independently verified mechanisms against v10, not raw finding count.

## 4. Part C — model-evaluation protocol (OWNER/LIVE, separate execution task)

### 4.1 Prerequisites (LOOP items, file before part C)

- **P1. Run-level iterative diagnostics.** AR-09 records `diagnostics` (parse_errors, refusals,
  rejected_proposals, unavailable_selections, duplicate_proposals, blocked_attempts,
  useful_unique_actions, evidence_attempt_ids) on each probe's `iterative_result`. But
  `worklist_investigator` keeps only `stop_reason` in its outcomes, so the counts never reach
  `result.json`. P1 sums them per run (and per stop reason) into the job result. It needs a
  caller-level test through `investigate_worklist` → job result. Without P1, part C has no
  attributable worker metrics.
- **P2. Thinking mode is fixed off.** `ollama_client` sends `"think": False` on every call. A
  "reasoning model" therefore runs here without its reasoning trace. The default A/B compares
  models with thinking off. A think-on arm needs a new config key whose default stays off (not
  a default change), with a test that the payload is unchanged when it is unset. Until then, no
  result may be described as measuring reasoning mode.
- **P3. Sealed scoring.** A scorer script that reads the exported artifacts and a sealed mapping
  file (4.4) and writes per-repeat metrics. It is tested offline on a synthetic mapping and a
  fixture export only.

### 4.2 Three evaluations, kept apart

| Eval | Question | Inputs supplied | Never supplied |
|---|---|---|---|
| C1 supplied-plan execution | Can the pipeline execute a correct plan to proof? | the owner's declared facts: mechanism, binding, principal references, privacy expectation | anything the run should discover |
| C2 unaided discovery | What does the system find alone? | scope, goal, account references | positives, routes, bindings, public solutions, the mapping |
| C3 model A/B | Does the model change the result, everything else equal? | identical C2 inputs per arm | as C2 |

C1 runs on owned fixtures (the D0 set plus the AR-09/AR-FP scripted plans) and may be extended to
the live target with declared facts. C1 is model-independent: a scripted model or a supplied
plan, so it measures execution ability, not the model.

### 4.3 C3 design

- **Arms.** A = `gemma4:latest` (baseline: v8/v10 ran it for every stage). B = `qwen3:8b`
  (already the committed coordinator and agent default, thinking-capable, think off per P2).
  Record each model's resolved digest (`ollama list` ID) at run time. A cloud arm
  (`gemma4:31b-cloud`) sends target-derived content off the host. It is excluded unless the
  owner authorizes it in writing for this run.
- **What changes.** Only the model tag/digest, applied to every model stage. Identical: target
  image digest and fresh target state, part-A source snapshot, enabled-feature manifest,
  prompts, accounts' roles, validator/oracle versions, scheduling policy, request/dispatch/
  experiment/worker-step budgets, wall and stage ceilings, temperature.
- **Repetitions.** At least 3 independent repeats per arm, each with a fresh target container,
  store, cache and run namespace, and a distinct recorded `ollama.seed` drawn before the first
  run. The same seed list is used for both arms. Interleave arms (A1 B1 A2 B2 A3 B3), so drift
  in the host or target isn't confounded with the arm.
- **Shape.** The live-run shape (3.2) costs ~3–8 h per repeat. The owner may choose a reduced
  shape (for example a 2 h wall cap) for all six repeats. The shape is fixed before the first
  repeat and identical across arms.

### 4.4 Metrics, artifacts and leakage controls

Primary metric (per repeat): **marginal independently verified mechanisms**. These are distinct
mechanism groups with a proof that replay audit verdicts confirmed, which the sealed mapping (below)
marks as expected. Also measured: first failing boundary per expected mechanism.

Secondary metrics (per repeat, from P1 and `result.json`):

- useful_unique_actions per model call;
- duplicate share = duplicate_proposals / steps;
- parse_errors / steps;
- refusals: only explicit `refused` verdicts. An empty result or a failed tool call never counts;
- rejected and unavailable selections;
- stop-reason distribution;
- evidence attempt IDs that reach a proof;
- model calls, errors, retries, wall time.

Never used as a primary metric: raw finding count, API completion, duplicate rate alone.

Leakage controls:

- The **expected-mechanism mapping** is written by the owner (or an evaluator who doesn't develop
  or run the harness). It lives outside the repo, the run namespace and every agent-readable
  folder. Only its sha256 is recorded in the run manifest before repeat 1. It is opened by the
  P3 scorer only after all six repeats' exports are frozen and hashed.
- No agent session ever reads it, answer keys, blind labels, or the target's implementation.
  Prompts are saved (secrets removed) and checked by script to contain no mapping entry.
- Container-disabled challenges are marked unavailable in the mapping and excluded from the
  denominator. A proof via a different safe execution marker counts when the mapping records
  that equivalence explicitly. Scoreboard completion is not required.
- No challenge-recall percentage is reported unless the mapping supplies the denominator.

### 4.5 Decision rule

Pre-registered before repeat 1:

- B is **better** than A only if B's median primary metric exceeds A's, B's worst repeat is ≥ A's
  median, and B has no hard part-B failure (L1–L5, L7–L10) in any repeat.
- B is **worse** under the mirror condition.
- Anything else is **no difference shown**. With n=3 per arm this is a screening result, not a
  significance claim. Report every repeat's values, the range, and any disagreement among the
  secondary metrics.
- A model change in a committed default is a separate owner decision after the result. Part C
  changes no config default.
- No claim about Gemma or any model's causal role is made from any other evidence (per
  REVIEWER_BRIEF.md).

### 4.6 Report

For each repeat: manifests, hashes, saved prompts (secrets removed), budgets, attempt/proof IDs,
artifact resolution, dispositions, metrics table. Then per arm: median and range. Then the
decision under 4.5 and the next action. Supplied facts are listed apart from discoveries.

## 5. What remains after this spec

- Part A: merge (owner approval, AR-08a migration sign-off), then the frozen gate run and the
  A–U matrix.
- P1–P3: LOOP items to file in IMPROVEMENT_BACKLOG.md.
- Parts B and C: owner-authored execution tasks. Not started.

AR-10 stays open until parts A–C are executed or explicitly deferred.
