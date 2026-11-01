# I01–I17 implementation guide for a less experienced coding agent

Prepared 2026-10-17. This is an execution manual, not a claim that the work is complete or authorization to start scans, install software, commit, or publish. The user's current request is to create this guide. Future implementation must stay within that future task's authorization.

Use one ticket and one small batch at a time. Do not attempt all seventeen in one patch. Preserve working code, tests and existing user edits. When uncertain about a security invariant or a schema migration, prepare the failing example and a small proposed change for a stronger reviewer; do not guess.

## 1. Read this first

Read these three files before implementing anything:

1. [AGENTS.md](../AGENTS.md): repository safeguards.
2. [CURRENT_STATE.md](../CURRENT_STATE.md): reported state, which must be checked against Git.
3. [Canonical I01–I17 plan](REMAINING_IMPLEMENTATION_PLAN_2026-10-17.md): existing ticket ownership and acceptance.

Then read only the section for your assigned ticket below. Use these supporting documents when that section points to them:

* [Candidate manifest](I01_CANDIDATE_MANIFEST_2026-10-17.md).
* [Audit decision report](../reviews/2026-10-17-dual-mode-audit-01/DECISION_REPORT.md).
* [Audit evidence index](../reviews/2026-10-17-dual-mode-audit-01/evidence-index.md).
* [Cross-request acceptance cases C01–C15](../reviews/2026-10-17-dual-mode-audit-01/ACCEPTANCE_SPEC.md).
* [Proposed amendments and aliases](../reviews/2026-10-17-dual-mode-audit-01/WORKLIST.md), with [complete ticket records](../reviews/2026-10-17-dual-mode-audit-01/worklist.json).
* [Testing instructions](TESTING.md).

The audit's observation-memory and advisory-UI additions extend I02/I07/I16. They do not erase the canonical proof-binding, request-shape or installed-operator requirements. Use them as explicitly identified additional sub-scopes. Do not change canonical dependencies or close tickets merely because this guide describes a proposed extension. The owner should resolve actual scope conflicts; ordinary implementation details do not require repeated approval.

### What was observed when this guide was written

Git HEAD was `1be5ed040229b47796803045b3a85ad2e03d08c9` on `reconciliation-backlog`:

| Commit | Observed contents | What you must not assume |
|---|---|---|
| `64e09ed6` | Standalone context/ceiling hardening | Does not certify every engagement caller. |
| `ba080691` | Committed SPA/browser capture and catch-all changes | Do not apply the old I01 overlay again. |
| `1715022a` | I01 manifest/tracker documentation | Documentation is not fresh verification. |
| `1be5ed04` | Sixteen regression modules added to Git | Do not blindly follow the older instruction to commit eighteen modules. Reconcile exact filenames. |

The working tree still contained substantial WIP. `test_engagement_transport_callers.py` and `test_csrf_reflection_control.py` were present. Presence and descriptive test names are not a pass or proof of committed status. Current source must be rechecked before implementing I03/I04.

The audit used an older isolated candidate (`64e09ed6` plus its discovery overlay). It reproduced a narrow default-history attribution defect and a missing nonfinding-observation path. Those results are historical for a later candidate. Its `candidate/` folder is a reduced audit export, not an implementation workspace or complete release tree.

## 2. Non-negotiable working rules

* Never read answer-key files, case variants, blind labels, or blind-target implementations. Do not bulk-read `testing/`, `archive/`, `reviews/`, runtime databases or captures. The specific audit documents above are allowed references; this is not permission to ingest all reviews.
* Leave `harness/config.yaml` safe. Do not copy `config.local.yaml`, pairing tokens, production databases or captured credentials into your candidate or commits.
* Do not reset, clean, stash or overwrite another person's changes. Do not run `git add .` or `git add -A` on this repository.
* Do not install sqlmap on Windows. Use only the approved container route when that activity is authorized. Never disable security software to make a build pass.
* Do not delete or weaken an existing regression because your change fails it. Understand the contract first. Preserve `test_pipeline_gate.py` and its fault controls.
* Tests involving an actual model, target, browser, tool or vulnerable fixture have different permissions from a passive source check. Inspect before running. Existing authorization persists; do not ask again for already-authorized work.
* Do not silently switch interpreter, model, corpus, flags or budgets when a test fails. Record the failure and its cause.
* A mock model can prove that context reaches a model call. It cannot prove that a real model uses the context correctly.
* A helper test cannot prove its caller uses the helper. A Java source review cannot prove the JAR builds. An HTTP 200 cannot prove protected-object access. Empty results cannot prove safety.

### Words to use precisely

| Word | Meaning |
|---|---|
| Observation | A supplied or authorized captured exchange, including one with no finding. |
| Finding | A hypothesis or justified claim derived from evidence; not the evidence itself. |
| Principal | An attributed identity; role, tenant and session are separate coordinates. Unknown stays unknown. |
| Caller test | Starts at the public API/orchestrator/UI entry that users actually invoke and keeps the important production path real. |
| Negative control | A similar case where the claimed result must not occur. |
| Fault injection | Deliberately disable the relevant reader/guard/forwarding in an isolated test and prove the test notices. |
| Implemented | Code is present. |
| Caller-verified | Positive and negative caller cases pass on a recorded candidate. |
| Live-validated | Separately authorized realistic evaluation has current evidence. |
| Released | The exact artifact passed its applicable release gates and was actually released. |

Track those four completion states separately. “Implemented” is not “done.”

## 3. Start every implementation batch this way

Run these read-only commands from the repository root:

```powershell
Get-Location
git branch --show-current
git rev-parse HEAD
git status --short
git diff --stat
git log -6 --oneline
git worktree list --porcelain
```

Read only the files needed for your ticket. `git status` may show restricted filenames; do not open them. Do not print environment variables, local config values or traffic bodies. Record branch, full HEAD, explicit base, relevant modified/untracked paths and the authorization scope.

Work in an isolated, complete candidate approved for the task. Prefer a suitable existing owned workspace. Do not use another agent's worktree. If a new one is needed, select an exact full commit SHA before creating it; do not assume `HEAD` remains unchanged. A new worktree does not copy WIP. Include an existing WIP hunk only after reviewing its ownership and recording it in the candidate manifest. Stop if the required fix cannot be separated from unrelated edits without risking them.

Before changing code, write a small batch note in a new uniquely named evidence directory, for example `.test-work/i02-attribution-<unique-id>/`:

```text
Ticket/sub-scope:
Candidate base and included overlays:
User-visible defect or evidence gap:
Production entry point -> affected boundary -> operator output:
Files expected to change:
Positive example:
Negative example:
Fault injection:
Authorized tests / prohibited activities:
Expected evidence artifacts:
```

Use a real unique ID, not the literal placeholder. Runtime artifacts stay untracked. Durable reviewed explanations belong in the ticket's existing docs. Never overwrite previous evidence.

### The repeatable change loop

1. **Locate:** use `rg -n` on the named files and function names. Verify both the caller and callee. Do not rely on stale line numbers.
2. **Reproduce:** add or adapt the smallest caller test that exposes the gap. Verify the failure is the intended contract failure, not an import/environment error.
3. **Control:** add the similar case that must not trigger the result. Keep real storage/decisions where those are being tested.
4. **Implement:** change only what the failing contract requires. Avoid unrelated renames, new frameworks, new agents or a new database.
5. **Challenge:** inject the specific missing reader/guard/context fault in a test. If the test still passes, improve the test before claiming integration.
6. **Verify:** run focused tests, then the required full checks for the completed batch when authorized. Save command, cwd, interpreter, duration, exit code, failures and skips.
7. **Review:** inspect the diff and source identity again. If unrelated source changed during testing, explain whether it was outside the frozen candidate; otherwise invalidate and re-run affected checks.
8. **Report:** use the handoff template at the end. Stop before unrelated next-ticket changes unless that next scope is already assigned.

Do not hard-code a successful result into production code, mock the function whose integration you are claiming, or change expected output just to make a failing test green.

### Standard verification commands

Read `harness/suite.py`, relevant test modules and TESTING.md first. With the intended environment already available, record interpreter identity and dependency health:

```powershell
python -c "import sys; print(sys.executable); print(sys.version)"
python -m pip check
python -m harness.suite full --list
```

From the isolated candidate root, the repository checks are:

```powershell
python -m harness.suite smoke
python -m harness.suite full
python -m unittest harness.test_orchestrator_precondition
```

Capture `$LASTEXITCODE` immediately after each command. Do not report the shell's final successful command as the suite exit. Full already includes native and evaluation subprocesses; do not rerun everything without a reason.

**Scope distinction:** the preceding audit prohibited vulnerability reproduction, so smoke/full were blocked there. A future implementation task may authorize those fixtures. Check the actual task scope rather than permanently disabling the suites or automatically running them. If prohibited or prerequisites are missing, leave the corresponding gate **BLOCKED**, name the minimal prerequisite, and do not claim a green full suite. Do not “solve” missing dependencies with fake imports. The observed Python 3.12 mitmproxy/typing-extensions conflict needs supported-environment disposition, not silent package replacement.

## 4. Execution order and checkpoints

Keep the canonical order:

```text
I01
  -> I02, I03, I04; I11 can progress independently
  -> I05
  -> I06 -> I07 -> I09 -> I10
     I08 follows I03
Prepare I12 specification and I15 packaging independently where inputs permit
I13 only after its scope-specific prerequisites and live authorization
I14 comparative evaluation
I16 installed operator acceptance
I17 separate mode/release decisions
```

The audit proposes allowing **supplied-only I07 contract work** and **I16 design/API work** after I02, before live discovery/installed acceptance. Do not silently change the canonical dependency graph. Identify that proposal in the batch note; an assigned passive workstream may proceed under existing owner direction. Final I07/I16 closure still requires their applicable dependencies.

Stronger-review checkpoints: W2 ownership compatibility decision; new observation schema/migration; confirmation authority changes; process/network containment; benchmark threshold freeze; external release. Bring a concrete proposal and test evidence. Do not turn every routine edit into an approval question.

## I01 — Freeze the candidate and reconcile work already done

**Outcome:** every later result refers to exact code, resources and tests. **Owner/aliases:** I01; R01 and R28 prerequisite. **Non-goal:** recreating committed discovery fixes or automatically committing all WIP.

**Inspect:** candidate manifest, current plan, `git log`, relevant diff/status; `docs/ARCH_RECONCILIATION_TRACKING.md` and the relevant backlog entries only.

**Steps:**

1. Verify `ba080691` and later commits are in the selected candidate. If discovery fixes are already there, record that and do not reapply the old patch.
2. Compare the manifest's eighteen test filenames with `git ls-files` and commit `1be5ed04`. Record each as tracked-in-candidate, untracked, WIP-dependent or absent. The commit added sixteen; do not assume which two remain without comparing names.
3. Classify W1 cache trust, W2 evidence/ownership/export, W3 health, W4 label routing. For every included file/hunk, record its owner. Leave unrelated WIP untouched.
4. Create a complete candidate manifest: full base SHA, exact included patch/commit identities, SHA256s, interpreter/dependency identities, test resources, exclusions and remaining WIP. Never include secrets or local overrides.
5. Run authorized candidate checks. Historical 74/93/3164 counts are context, not assertions for a newer candidate. Explain changed collection and skips.
6. Amend only stale acceptance/status wording in the existing trackers when assigned. Preserve completed discovery/ARCH-3 scope and old evidence links. Keep remaining caller/live/release gates open.

**Tests/control:** changing one manifest-listed file must invalidate identity verification. An untracked test not included in the candidate cannot count toward that candidate's result. Compare before/after hashes for files outside the batch.

**Done artifact:** manifest, dispositions, commands/logs and accurate scope statuses. **Stop:** candidate source drifts, required files are missing, or a hunk's ownership is unclear. Ask for a disposition only after inventory is concrete. Focused commits require appropriate authorization, exact staged paths/hunks and a `Co-Authored-By` trailer.

## I02 — Trustworthy proof binding, observation retention and retrieval

**Outcome:** claims retain the right proof; supplied observations remain available for later comparison. **Depends:** I01. **Aliases:** false-confirmation follow-up, R15 proof scope, W1/W2. **Non-goal:** new graph database or disabling principal isolation.

**Inspect:** `harness/store.py` (`persist_findings`, `prior_findings_summary`, identity helpers), `orchestrator_detect.py` (`analyze`, persistence/context), `orchestrator_confirm.py`, `evidence_ledger.py`, `confirmation_gate.py`, `issues.py`, `report_generator.py`, `sarif_adapter.py`; relevant tests below. Treat the audit source diagnosis as something to reproduce on the new candidate.

Implement separate batches; do not combine all of these into one unreviewable migration:

### I02 batch A: preserve canonical claim/proof acceptance

1. Trace original finding/class -> selected validator -> case/proof -> stored finding -> API/Markdown/SARIF. Write down the identifiers at each edge.
2. Adapt `test_confirmation_class_binding_caller.py`; inspect which boundaries it mocks. Add a case using real proof storage and export, not a mocked oracle/store.
3. Use two synthetic claims on one exchange. Only claim A has matching evidence. A may acquire the allowed verified state; B must not borrow its proof, confidence or confirmation.
4. Test missing, stale and unresolvable proof after reopening the database/export. A dangling reference must not resurrect confirmation.
5. Fix the narrow binding decision if necessary. Any supported class equivalence must be explicit and tested; a routing alias alone is not proof equivalence.
6. Inject removal of the binding check in a test double at the decision seam. The caller assertion must catch false confirmation. Do not leave a production bypass flag.

### I02 batch B: reproduce and fix the default-history seam

1. Read the audit's `controlled_trace.py` as an experiment description. It pins its old candidate; do not blindly run it and claim results for your current code. Adapt the case into the current candidate's test module.
2. Run two benign analyses, A then B, using canned model output, real persistence and real retrieval. A's output includes a unique nonsecret marker; record whether B's model input contains it.
3. Compare default/no-explicit-engagement, explicit-shared-engagement and severed-reader cases. Count target sends independently; all must be zero for advisory tests.
4. Inspect the actual writer/reader coordinates. If default writes empty principal while reads request a computed principal, fix that mismatch under the agreed ownership contract. Never remove the principal filter as the shortcut.
5. Record the W2 design decision: how an operator creates/reuses an engagement, what happens with absent ID, how legacy reports remain inspectable, and how concurrent selections share it. A per-call UUID by itself does not make a shared review.
6. Add cross-engagement/tenant/identity negative controls. Preserve visibility through the intended API, not an ad hoc SQL query.

### I02 batch C: retain observations that produce no finding

1. Define the contract with I07 before schema edits. Suggested fields below are a design sketch, **not existing API names**:

```text
observation_id, engagement_id, capture_id, content_digest
captured_at or unknown, ingested_at, provenance
principal/role/tenant/session references plus explicit unknowns
method, normalized_route, original_shape_reference
sanitized_response_facts, completeness, state_version
attribution_revision, retention/deletion state
```

2. Check existing evidence/blob facilities before adding tables. Retain one observation even when findings are empty. Separate immutable capture facts from correctable attribution. Do not store real credentials as identity labels.
3. Define duplicate behavior: same scoped capture ID + same digest is idempotent; same ID + changed content is rejected/versioned explicitly; same URL + different observation remains distinct. Scope the uniqueness constraint correctly.
4. Write a backward-compatible migration against temporary old/new databases. Test reopening. Do not silently reinterpret legacy unknown principal/tenant as verified ownership.
5. Add one bounded retrieval path returning selected observation IDs, facts and reasons. Include same-URL history when relevant. Join using explicit scope and supported relationship evidence; equal object IDs are insufficient.
6. Wire ingestion and retrieval at the actual advisory caller. Keep the existing finding-summary reader as legacy context if needed, but do not call it complete observation memory.
7. C01/C03/C04: two nonfinding observations must change a qualified advisory comparison; either alone is insufficient; different tenants do not join. Test with a canned consumer first, then leave real-model usefulness to I14.
8. C08/C09: reopen persistence, correct attribution, delete evidence, invalidate retrieval/advice. Resolvable citations survive reopen; deleted citations become visibly unavailable. Do not erase unrelated evidence or silently reuse old cache authority.

**Existing tests to inspect:** `test_confirmation_class_binding_caller.py`, `test_issues.py`, `test_serialization_roundtrip.py`, `test_cache_hypothesis_reuse.py`, `test_engagement_atomic_passive.py`; check tracked/WIP status first.

**Done artifact:** caller tests, migration/rollback evidence, proof/export matrix and selected-evidence trace. **Stop:** schema compatibility or W2 default ownership is unresolved; prepare options/test consequences for review. Batch B passing does not close A or C. Unknown/failed model output must never become a secure result.

## I03 — Verify shared limits at real engagement callers

**Outcome:** iterative and second-order work uses the owning run's scope, budget, cancellation and TLS. **Depends:** I01. **Aliases:** ARCH-1/2, SC-7/R7. **Non-goal:** replacing already-correct transport helpers or running destructive objectives.

**Inspect:** `orchestrator_chain.py` (`investigate_engagement`, closures passed to probing/second-order work), `orchestrator_helpers.py`, `run_context.py`, `safety_gate.py`; `test_engagement_transport_callers.py`, `test_iterative_probe_run_context.py`, `test_second_order_transport.py`, `test_run_context.py`. New caller tests may already cover this: inspect and classify them before adding duplicates.

**Steps:**

1. Draw the exact call chain to each send. Identify who owns and closes the context, and how borrowed contexts are passed.
2. Use a benign owned responder and an independent received-request counter. Keep the real closure and transport; replace only unrelated model/discovery choices as required.
3. Allowed request: owning count increases by exactly one. Zero/exhausted ceiling: zero sends. Cancellation before step: zero sends. Denied scope/gate: zero sends.
4. Benign two-step workflow: cancel after first step; second step must not send or claim completion. Missing readback is inconclusive.
5. Concurrent admissions: give a small shared budget and assert actual received requests never exceed it. Use events/barriers rather than timing-dependent sleeps.
6. TLS: untrusted certificate fails under normal trust; any fixture exception is restricted to its explicit owned origin. Do not globally set verification false.
7. Fault: omit owning-context forwarding at the caller seam. The relevant count/cancellation test must fail. A helper-only passing test is insufficient.

**Done artifact:** per-caller allow/deny/cancel/concurrency/TLS table plus count logs. **Stop:** fixture sends outside owned scope, borrowed context is closed by the wrong owner, or tests cannot distinguish the old bug. Fix only demonstrated gaps; retain helpers' regressions.

## I04 — Disposition non-browser CSRF replay

**Outcome:** reflection alone never confirms browser-deliverable CSRF. **Depends:** I01; align proof semantics with I02. **Alias:** LB-CSRF-REPLAY. **Non-goal:** adding new exploit techniques or equating attached cookies with browser behavior.

**Inspect:** current `validators/csrf_validator.py`, dispatcher/caller, `test_csrf_reflection_control.py`, relevant `test_deferred_legs.py` cases, and the named backlog branch/WIP. Do not overwrite concurrent edits.

**Steps:**

1. Determine whether the reported branch still exists and what current tests prove. If already fixed, verify the exact candidate and document remaining acceptance instead of rewriting it.
2. Use a benign reflector that returns submitted text but does not change protected state. With mutation permission off, assert no prohibited send. Where authorized, reflection with the relevant flag on still must not confirm.
3. Trace the positive confirmation contract separately: actual relevant state change/readback plus browser credential-delivery semantics are required for that claim. HTTP response reflection is insufficient.
4. If evidence is insufficient, remove confirmation authority or return an explicit inconclusive/suspected state at the narrow decision. Preserve useful observation text.
5. Test caller -> storage -> export labels. Inject the old reflection-based decision in the isolated test and ensure the negative control catches it.

**Done artifact:** current-branch disposition, default-off control, reflection control and evidence for any retained confirmation scope. **Stop:** proving a positive requires unauthorized vulnerability reproduction. Record that gate blocked; do not call a reflection-only test complete CSRF validation.

## I05 — Contain network and external-tool work

**Outcome:** denied/cancelled work cannot continue sending or leaking credentials/output. **Depends:** I01/I03. **Aliases:** P1-10, PR-10/11, NC-O1/O2/O3, SC-9. **Non-goal:** adding new tools or installing sqlmap on the host.

**Inspect:** `run_context.py`, browser routing in `browser_driver.py`, `tool_runner.py`, `validators/sqlmap.py`, job cancellation in `server.py`, existing transport tests.

**Steps:**

1. Split work into HTTP destination checks, browser credential isolation, and external-process lifecycle. Test each boundary separately; shared Python transport does not govern arbitrary tool traffic automatically.
2. Redirect/destination fixture: an allowed origin redirects to a denied one. Verify zero denied-origin requests, not just a returned error. Check connect-time destination policy and HTTPS hostname/SNI behavior together.
3. Browser fixture: two owned origins with distinct synthetic secret sentinels. Navigation and subresources must obey scope; origin B must never receive origin A credentials. Test cancellation while work is pending.
4. External-process fixture: start a harmless owned worker that waits, emits bounded synthetic output and never attacks a target. Cancel **after launch**. Track the exact owned process/container ID.
5. If cancellation only checks before `subprocess.run`, propose an owned process handle with bounded monitoring, termination and final wait/cleanup. Account for children/containers. `asyncio.to_thread` cancellation alone does not terminate the underlying worker.
6. Limit stdout/stderr while reading, not after collecting unlimited output. Use a bounded tail or explicit truncation metadata; avoid pipe deadlock. Test a noisy benign worker.
7. Do not mark a job terminal until cleanup is proved, or expose a distinct cleanup-failed state. Never kill a process by generic name or touch unrelated containers.
8. Tool traffic needs independently verified accounting/egress enforcement or must remain unsupported/disabled. Test policy removal/forwarding loss as a fault.

**Done artifact:** observed destination/request counts, credential sentinel assertions, cancellation-to-stop time, output bounds and zero owned survivors. **Stop:** unable to distinguish owned from unrelated process, no enforceable egress/accounting boundary, or required network test is unauthorized. This ticket needs stronger review before broad rollout.

## I06 — Bounded declared browser journeys

**Outcome:** APIs reached after an operator-declared interaction enter the worklist with the correct identity. **Depends:** I03/I05 for live acceptance. **Aliases:** LB-2 SPA remainder, R22. **Non-goal:** free-form autonomous browsing or replacing the existing capture adapter.

**Inspect:** `driver_capture.py`, `browser_driver.py`, `engagement_builder.py`, `role_crawl.py`, `orchestrator_chain.py`, `test_driver_capture.py` and `docs/SPA_DISCOVERY_FIXES.md`.

**Steps:**

1. Preserve existing page-load capture. Define a small validated journey schema: declared start URL and bounded supported interactions, with per-step timeout/count and stop conditions. No arbitrary model-generated script execution.
2. Create a benign owned page where a declared interaction causes an ordinary API request. Page-load-only control must not observe that API.
3. Run the journey through engagement construction, not only the browser helper. Assert original method/body/content type and declared principal/session reach the worklist.
4. Share the owning scope/budget/cancel context across navigation, assets and interactions. Count all actual traffic at an independent boundary.
5. Represent each step as completed, blocked, failed or unattempted. Expired/wrong session must not become authenticated coverage or another role's capture.
6. Faults: drop captured exchanges before builder ingestion, omit identity, cancel before the interaction. Each relevant caller assertion must detect the loss.

**Done artifact:** fixture journey, caller worklist trace, independent counts and expiry/negative controls. **Stop:** browser prerequisites missing; report blocked rather than skipped-as-pass. No real login journey without authorization and protected session handling.

## I07 — Capture fidelity and observation metadata

**Outcome:** later reasoning/execution receives the supplied request and its limits, not a guessed replacement. **Depends:** canonical I02/I06; supplied-only contract work may be separately assigned earlier. **Alias:** LB-2 shape/multipart remainder. **Non-goal:** automatic owner inference from URLs or making incomplete bodies replayable.

**Inspect:** `models.py` (`HttpExchange`), Java `AnalysisModels.java`/capture conversion, `engagement.py` (`template_from_exchange`, `record_template`), builder/role crawl and actual validator caller. Coordinate schema changes with I02.

**Steps:**

1. Record the current Java -> JSON -> Python -> template -> caller mapping. Add optional backward-compatible metadata only after deciding unknown/default semantics.
2. Preserve capture timestamp separately from ingest time, provenance, principal/role/tenant/session attribution, completeness and state/version. Missing old-client fields remain unknown, never fabricated.
3. Make benign fixtures for JSON, XML, multipart boundary/content, query versus body, binary and oversized captures. Use harmless data, not exploit payloads.
4. Assert exact method/content type/parameter location/body at the consumer. Preserve original bytes or an explicit evidence reference where text representation is insufficient; do not pretend arbitrary bytes round-trip through a string.
5. Unsupported/truncated input is not executable evidence: mark affected checks untested/inconclusive with a reason. Keep the original observation inspectable under retention policy.
6. Add same-ID/different-tenant, same-URL/different-time and out-of-order cases. Keep I02 responsible for persistence/retrieval; I07 owns faithful conversion.
7. Fault: lose body/content type or silently truncate. Caller test must fail or produce the required incomplete state. Keep completed XML cases; close multipart only with its own evidence.

**Done artifact:** field mapping, compatibility tests and shape/completeness matrix through the real consumer. **Stop:** schema conflicts with I02 or old-client behavior is ambiguous; prepare the specific compatibility choice for review.

## I08 — Measure catch-all discrimination

**Outcome:** wildcard fallbacks do not overwhelm work, and real routes are not silently lost. **Depends:** I03. **Non-goal:** rewriting the committed catch-all fix from scratch or optimizing only the rejection count.

**Inspect:** `api_surface_discovery.py`, `crawler.py`, `test_discovery_spa_wildcards.py`, `test_api_surface_discovery.py`, SPA discovery doc.

**Steps:**

1. Establish current behavior on root/nested HTML fallbacks, redirects, auth walls and bodies with variable IDs/timestamps.
2. In every relevant prefix, include at least one real distinct route and several known fake routes. An indistinguishable route must remain inconclusive rather than confidently absent.
3. Measure fake admissions, true routes retained, true routes missed, calibration requests and total requests. Freeze fixture identities before tuning.
4. Correct only demonstrated classifier/scheduling defects. Preserve per-prefix calibration and descendant-pruning regressions.
5. Check all calibration spends the shared budget. Exhaustion must leave visible untested coverage; it cannot mean “no more endpoints.”
6. Fault: bypass calibration/pruning. Verify false-route workload control detects it; separately ensure a classifier rejecting everything fails the true-route control.

**Done artifact:** before/after confusion table, counts and failure states. **Stop:** only the old 7,460-request report exists; do not call it a current measurement or launch its workload without authorization.

## I09 — Verify deterministic dispatch, do not duplicate it

**Outcome:** captured body/JWT shapes reach the intended supported validator without a helpful model label. **Depends:** I02/I07. **Aliases:** DET-SQLI-POST, DET-JWT-DETECT, W4. **Non-goal:** new validator capabilities or treating a shape-routing pass as confirmed vulnerability accuracy.

**Inspect:** `orchestrator_helpers.py`/orchestrator exported `shape_precondition_legs` and `shape_precondition_findings`, chain/confirmation caller, `validators/base.py`, `test_orchestrator_precondition.py`, `test_validator_routing.py`.

**Steps:**

1. Inventory already-supported method/header/cookie/body cases. The old “no precondition” diagnosis is stale; verify before coding.
2. Use a silent model and benign captured body-only request. Spy at the actual validator invocation and assert correct parameter location and original request shape; do not execute an attack merely to test routing.
3. Use a synthetic structurally valid credential shape for supported JWT cases. Specify exactly which headers/cookies/methods are in scope.
4. Negative controls: empty/unrelated body, absent/non-JWT value. No unrelated leg should be scheduled.
5. Fault: disable the shape precondition or lose captured body. The caller test must fail. The helper-only precondition suite remains useful but insufficient.
6. Review W4 label-normalization hunks separately. Enumerate accepted aliases and nonmatching controls; arbitrary text must not route to unrelated confirmation authority.

**Done artifact:** supported-case dispatch matrix, silent-model caller logs and alias controls. **Stop:** relevant shape lost upstream; route that fix to I07 rather than synthesizing a convenient request in the validator.

## I10 — Separate genuine cases from secure controls

**Outcome:** secure/failed controls never become confirmed findings, while supported positives remain detectable. **Depends:** I02/I09. **Alias:** BM-2. **Non-goal:** raising model confidence thresholds to conceal false confirmations.

**Inspect:** `confirmation_gate.py`, actual affected validators/oracles and storage/export, relevant `test_oracle_*`/confirmation tests. Identify the already-listed BM-2 classes before selecting cases.

**Steps:**

1. Ask the independent fixture/corpus custodian for permitted paired cases. Do not open blind labels or target implementations. For development, use explicitly nonblind owned fixtures only within authorization.
2. Freeze each pair's expected supported behavior and principal/case identity before running the candidate. Do not give one arm extra evidence secretly.
3. Track applicability -> attempted -> inconclusive/refuted/confirmed. Failed transport or failed control is not a successful negative result.
4. Test the real caller and persistence/export states. A secure twin must not confirm; a positive needs its own bound evidence. Keep hypotheses distinguishable from confirmed errors.
5. Inject a control failure and a proof mismatch. Neither may inherit confirmation. Repair only the unsound decision the pair demonstrates.

**Done artifact:** paired outcomes with independent adjudication and proof references. **Stop:** positive reproduction exceeds authorized scope, custodian/labels are unavailable or the result depends on a mocked oracle. Leave the relevant acceptance open.

## I11 — Make verification trustworthy

**Outcome:** tests collect correctly, clocks/resources are deterministic, and gaps are honestly classified. **Depends:** I01; can progress independently. **Aliases:** LB-FLAKE/R18 and missing requirement evidence. **Non-goal:** lowering coverage requirements or deleting old tests.

**Inspect:** `suite.py`, `coverage_manifest.py`, `test_coverage_manifest.py`, `test_no_orphan_test_files.py`, `test_async_test_hygiene.py`; the particular report-clock/resource test referenced by the issue. Do not bulk-read evaluation artifacts.

**Steps:**

1. Reconcile committed/untracked tests after `1be5ed04`. Verify collection by the actual runner; a file existing or importing is insufficient.
2. Obtain the current coverage report. Classify each unresolved item as missing implementation, missing caller evidence, manual prerequisite or residual unsupported scope. The historical count 36 is not fixed truth.
3. Bind declared requirement IDs to real runnable tests, preserving exact identity checks. A passing helper cannot close caller acceptance.
4. For report-clock flakiness, inspect existing fixed-clock work first. Control the clock dependency, not the expected output after the fact. Same input/clock must be stable; content changes must still change output.
5. For resource warnings, trace who owns sockets/clients/processes/temp directories. Close them in all paths. Do not hide warnings or globally suppress cleanup errors.
6. Preserve all pipeline-gate faults. A removed integration must still be detected. Keep native pytest tests in the declared native runner.

**Done artifact:** old-to-new test mapping if reorganized, current gap classification, deterministic/resource controls and required suite logs. **Stop:** a dependency/scope failure prevents full execution; report it as blocked, never covered.

## I12 — Freeze evaluation before measuring improvement

**Outcome:** an independent evaluator can reproduce the comparison and detect missing acquisition/evidence. **Depends:** I01/I02/I03/I11 for complete acceptance; specification preparation can start earlier. **Aliases:** P1-3, R08/R17, Part B prerequisites. **Non-goal:** choosing thresholds after seeing outcomes.

**Inspect:** acceptance spec C01–C15, maintained captured-analysis/evaluation runner selected by the current plan, provenance/usage/counting/export code. Read runner source and metadata only; never blind keys/labels.

**Steps:**

1. Write a run manifest containing candidate/config/model/prompt/corpus hashes, target state, identity references, seed, cache state, budget, permissions, stage schema and exclusions. Redact secrets; do not publish local config values.
2. Freeze separate fixed-corpus and acquisition studies. Fixed corpus has identical supplied observations; acquisition starts from identical authorized access and counts missed cases.
3. Define five arms: single exchange; bounded multiple exchanges; same context plus relevant graph/matrix reader; deterministic-only; model-assisted candidate. Compare graph reader versus the same amount of context, not privileged extra captures.
4. Add targeted ablations: earlier observation dropped, reader severed, identity discarded, stale retrieval reused. Each case must depend on the disabled component; do not force every graph into every result.
5. Add independent request counting at the owned boundary and separate model usage/latency counts. Detect dropped and double-counted events using synthetic accounting inputs.
6. Predeclare denominators and failed-run treatment. Report end-to-end recall and acquired-case recall separately. Repeats measure stability, not new independent cases.
7. Have the product/security owner and independent custodian freeze thresholds, including zero false confirmations. The audit's numeric targets are proposals, not approved business policy or achieved results.
8. Ensure incomplete manifests/stages fail eligibility. A cached historical score cannot masquerade as a fresh run.

**Done artifact:** versioned/hash-frozen specification, run schema, synthetic accounting/eligibility controls and adjudication procedure. **Stop:** no independent custodian, unknown model/config identity, changing denominators or threshold approval. Prepare the missing field/decision precisely; do not run an unscorable experiment.

## I13 — Run authorized Part B, not an unscheduled scan

**Outcome:** current automated efficacy is independently measured. **Depends:** applicable I02–I10, I12 and usable authorized environment. **Aliases:** DET-SSRF, NC-O4/PR-13 live scope, BM-3. **Non-goal:** exploitation outside the approved experiment, expanding targets, or implementing new features mid-run.

**This ticket is a live-evaluation gate.** A request to write or implement code does not by itself authorize a target scan. Do not put runnable attack commands/payloads into this guide.

**Steps:**

1. Obtain/verify existing authorization: exact target/owner, actions, identities, time/request limits, data handling, stop conditions and cleanup ownership. Do not ask again if these are already explicit and sufficient.
2. Verify current services/tools/model tag/digest, target version/state, session validity and fresh cache from the frozen manifest. Do not trust old “running” notes.
3. Independently verify any required callback infrastructure before interpreting missing callbacks. Missing infrastructure is inconclusive, not a refutation.
4. Have the authorized operator/custodian execute the frozen runner. The reviewing agent does not read blind labels or change target implementation.
5. Record the full funnel: available -> acquired -> attributed -> retained -> related -> retrieved -> consumed -> checked -> persisted -> inspectable. Missing stage counts remain unknown.
6. Adjudicate every confirmation independently. Apply zero-false-confirmation no-go immediately to the declared scope. Preserve failed/incomplete runs and independent request counts.
7. If source/config/target state changes, stop that comparison and record an invalid/incomplete arm. Do not silently repair it and combine results.

**Done artifact:** sanitized manifests/results, counts, adjudication and stop/go decision. **Stop:** any prerequisite absent or scope changes. Publish the blocker and next required input; offline tests cannot replace this gate.

## I14 — Measure model, graph and analyst value

**Outcome:** claimed improvements survive matched baselines and independent assessment. **Depends:** I12/I13 for automated claims; I15/I16 for installed analyst claims. **Aliases:** PR-B/D/E, R21/R25, NC-O4 generalization. **Non-goal:** competitor parity features or self-grading by the producing model.

**Steps:**

1. Obtain independently annotated sanitized scenarios beyond development fixtures, from multiple application contexts. Custodian retains blind labels; record contamination exclusions.
2. Run the frozen arms and relevant ablations with matched evidence/model/config and budgets. Report any privileged inputs instead of hiding them.
3. Score cross-request correctness, unsupported claims, citation support/completeness, useful abstention and next-step relevance using independent adjudicators. Preserve disagreements.
4. For analyst claims, use a paired/counterbalanced human baseline. Measure justified-decision time, corrections and report preparation; a faster wrong answer fails.
5. For compression/retrieval optimization, preserve identity, timestamps, contradictory facts and citations. Measure tokens, latency, retries, memory and money separately. Unknown provider usage is not zero; local caching does not automatically save money.
6. Report sample size, intervals, per-context results and failed runs. Do not count repeated runs of one case as independent cases.
7. Accept/reject the predeclared improvement hypothesis. If E2 adds no benefit over E1, report it; do not move the threshold or add more features as proof.

**Done artifact:** independent scores and uncertainty, matched-arm provenance, human study evidence where claimed. **Stop:** producing model is the grader, no baseline, or outcome/arm identity cannot be established. No “better than anticipated” claim without the frozen threshold.

## I15 — Build and install the exact candidate

**Outcome:** intact Python/Java artifacts work outside the source checkout with a supported environment. **Depends:** I01; final release candidate must include relevant accepted changes. **Aliases:** P3-2, PR-C, SC-6/14, NC-O5 build, R15/R19 installed scope. **Non-goal:** excluding source or disabling protection to manufacture a build.

**Inspect:** `pyproject.toml`, `harness/requirements.lock`, `burp-extension/build.gradle`, resource declarations and existing packaging tests/CI. The inspected Gradle file targets Java 17; verify the actual build environment and compatible Gradle rather than guessing from that declaration.

**Steps:**

1. Record candidate hashes, supported runtime matrix and dependency resolution. `pip check` must be clean for a claimed supported environment or explicitly unresolved. Installs require the task's authorization and an isolated environment.
2. Build the complete wheel using the supported existing build workflow. Inspect archive contents for package modules, safe config and workflow resources; ensure local overrides, tokens, databases and logs are absent.
3. Verify Java/JDK/Gradle availability. No Gradle wrapper was present in the inspected root; do not invent `gradlew.bat`. If a wrapper is later added, verify it before use.
4. In the candidate's `burp-extension` directory, when prerequisites/dependency access are authorized, run:

```powershell
gradle --version
gradle test shadowJar
```

5. Record actual discovered tests, exit codes and JAR hash. Compilation with zero meaningful tests is not full Java verification.
6. Install the wheel into a new authorized environment outside the checkout. Check `harness.__file__` points into that environment, then verify startup/resources/failure behavior and the intended API contract with synthetic data. Do not let PYTHONPATH import the source tree accidentally.
7. Produce SBOM/dependency identity. Verify upgrade and rollback using owned temporary state. Include schema compatibility from I02; never downgrade a production database blindly.

**Done artifact:** wheel/JAR/SBOM hashes, clean-install paths/logs, tested runtime/dependencies and rollback rehearsal. **Stop:** missing build tool, blocked dependency access, unresolved detection or incompatible environment. Report build unverified; source review and old CI are not substitutes.

## I16 — Make the operator workflow real

**Outcome:** an operator selects evidence, understands the answer and can correct/resume without hidden API stitching. **Depends:** I02/I15 for canonical installed acceptance; I07 for added metadata. **Aliases:** P1-5/P2-3, PR-A, NC-O5 operator, R02/R20, W2 UI/W3. **Non-goal:** conversational claims based only on a backend helper.

**Inspect:** Java `HarnessContextMenu.java`, `HarnessClient.java`, `model/AnalysisModels.java`, `ui/HarnessPanel.java`, `ui/HarnessToolsPanel.java`, `FindingPresentation.java`; Python analyze/health/pairing/report/job endpoints. Review existing W2/W3 hunks before changing them.

**Steps:**

1. Agree the I02 session contract and show it in the UI. Multiple selected captures must share the intended review ID explicitly, with captured principals kept separate. Do not create a fresh group for every item or depend on completion order of concurrent submissions.
2. Implement the smallest supplied-only flow: select captures -> assign/correct scope/identity -> ask a supported question -> inspect comparison and both evidence links -> supply missing evidence -> resume.
3. Answer fields must distinguish observation, inference, assumption, contradiction, missing evidence and proposed next step. Proposed actions are not executed actions. Unsupported questions get an explicit limit.
4. Corrections persist and invalidate dependent advice/retrieval. Deleted/stale evidence is visibly unavailable. Never hide all findings by changing partition defaults without updating reports/operator selection.
5. W3 health: verify exact configured model tag, safe public URL/error representation and Java degraded classification. Use synthetic secret sentinels only. Family-name availability is insufficient.
6. Test wrong/rotated pairing tokens, origin changes, restart, cancellation, timeout, malformed response and partial model failure. Separate “no finding,” “insufficient evidence” and “analysis failed.”
7. Assert Python/Java serialization compatibility, returned IDs and API/Markdown/SARIF labels. Complete any existing reproduction-recipe presentation without rebuilding working exports.
8. Use the built JAR and installed package for a new-operator walkthrough. Independently observe zero target traffic in advisory mode; inference traffic is separately declared. A Java unit test alone cannot close the walkthrough.
9. Fault: drop shared engagement from the Java request or reuse stale advice after correction. Relevant installed/caller test must detect the defect.

**Done artifact:** contract tests, installed walkthrough, sanitized screenshots/outputs and updated manual reflecting actual limits. **Stop:** no JDK/Burp/session contract or user-visible workflow is still manual API stitching. Mark only the backend sub-scope complete.

## I17 — Make a scoped release decision

**Outcome:** release claims match evidence for each mode and deployment context. **Depends:** all applicable acceptance above. **Alias:** R28 / Priority-5 adjudication. **Non-goal:** treating a green suite as proof of efficacy or distributing automatically.

**Steps:**

1. Freeze the exact delivery candidate and artifacts. Inventory included/deferred tickets and unresolved conditions. Historical evidence is labelled historical, never silently refreshed.
2. Build a gate table: source reproducibility; proof integrity; scope/cancellation; capture/retrieval; model failure; efficacy; operator workflow; packaging/upgrade/rollback; privacy/retention. Link each verdict to its current artifact.
3. Give separate READY / READY WITH CONDITIONS / NOT READY / INSUFFICIENT EVIDENCE decisions for advisory and automated modes, each for local research, supervised pilot, routine professional use and distribution.
4. State supported scope, manual work, residual risks and measurable next gates. Advisory readiness does not clear automated execution gates.
5. Prepare release notes and rollback instructions. A stronger/release owner reviews the concrete decision package. Do not claim a person signed it when they did not.
6. Publish/push/deploy only if that action is actually authorized. Preparing a release decision is not publishing a release.

**Negative control:** remove a required proof/manifest or insert a failed false-confirmation gate; the decision must become blocked/not ready for that scope. **Done artifact:** exact signed/scoped decision and, only if authorized and performed, actual release record. **Stop:** any no-go gate is bypassed, artifacts do not match candidate, or release scope exceeds evaluated scope.

## 5. Common failure patterns and what to do instead

| Tempting shortcut | Correct response |
|---|---|
| “The helper exists, so close the ticket.” | Find its production caller; test observable output and a disconnected-reader control. |
| “The new branch already has a test with that name.” | Inspect assertions/mocks, check tracked status, run it on the frozen candidate when permitted. |
| “Make all queries host-wide so history appears.” | Preserve isolation; align explicit ownership coordinates and UI reuse. |
| “Retain only useful findings.” | Retain permitted observations, including nonfindings, with bounded redaction/retention. |
| “Same ID means the same owner.” | Require scoped identity/resource relationship evidence; otherwise show unknown. |
| “A 200 or reflected value confirms impact.” | Require claim-specific content/state and authority evidence. |
| “Cancelled asyncio task means the tool stopped.” | Verify the owned process/container and actual traffic stopped. |
| “Skip missing browser/dependency tests and call full green.” | Record missing prerequisite; gate remains blocked. |
| “Old crAPI runs prove the current graph is broken.” | Use old metadata as a hypothesis; reproduce a narrow current caller case. |
| “An audit threshold is an approved business target.” | Freeze owner-approved thresholds before outcomes; retain zero-false-confirmation no-go. |
| “Current HEAD is close enough to the tested one.” | Record exact source identity and rerun affected checks after changes. |

## 6. Handoff template for every small batch

Copy this into the ticket's new evidence summary; replace every placeholder with observed facts or UNKNOWN/BLOCKED. Do not fill gaps with guesses.

```text
Ticket and exact sub-scope:
Status: implemented / caller-verified / live-validated / released (separate values)
Candidate: full base SHA + included changes + hashes
Authorization used; activities not authorized:
Problem reproduced before change:
Production caller and real boundaries preserved:
Change and why it is the smallest sufficient change:
Changed files; pre-existing edits preserved:
Positive control result:
Negative control result:
Fault injection result:
Commands, cwd, interpreter, durations, exit codes, failures/skips:
Storage/API/UI/export evidence actually exercised:
Source identity after verification:
Residual gaps / blocked prerequisites:
Migration, rollout and rollback implications:
Artifacts:
Next single batch and its prerequisites:
```

Use claim labels: VERIFIED NOW, SOURCE-SUPPORTED, HISTORICAL/REPORTED, INFERRED, UNKNOWN/BLOCKED. If updating CURRENT_STATE is part of the task, overwrite it with concise current facts and pointers under 100 lines; do not append a session diary. Do not overwrite canonical status as complete until its named acceptance is actually met.

## 7. Ready-to-paste assignment for a smaller agent

```text
Work only on ticket Ixx, batch <name>, in the assigned isolated candidate.
Read AGENTS.md, CURRENT_STATE.md, the canonical ticket and the matching section of
docs/I01_I17_IMPLEMENTATION_GUIDE_2026-10-17.md. Check Git/source state rather than
assuming historical notes are current. Preserve all unrelated edits and controls.

First produce the small batch note (caller, defect, files, positive/negative case,
fault control, allowed tests). Then carry out the assigned authorized work.
Keep the relevant production path real. Change the smallest necessary scope.
Do not inspect blind keys/implementations, change safe defaults, launch live work,
install dependencies, commit or publish unless the actual task authorizes it.

If a real design/permission prerequisite is missing, finish independent read-only
work and present the concrete blocker/options. Do not invent approval or silently
weaken a gate. Report using the guide's handoff template. Do not start the next
ticket merely because this batch has green helper tests.
```

Before sending that assignment, replace `Ixx` and `<name>`, name the actual candidate, and state the permitted implementation/test scope. This guide is deliberately not a blanket “implement everything” prompt.
