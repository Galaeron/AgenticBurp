# Coding plan: make active assessments execute and report reliably

## Objective

Repair the production discovery → capture → worklist → validation → proof → report
path. Success is a reproducible, bounded assessment with accountable coverage and
reproducible vulnerabilities, not a larger count of model-generated findings.

Read AGENTS.md and CURRENT_STATE.md first. Preserve the dirty checkout and existing
regression controls. Work one ticket/batch at a time with BATCH.md and HANDOFF.md.
Do not read answer keys or blind-target implementations. Keep config.yaml safe;
active settings belong in ignored local configuration. Do not install host sqlmap.
Do not start another live run until the offline readiness gate below passes.

## Execution dependencies — 2026-10-22

### Integration checkpoint — 2026-10-24

Implementation is combined in `.test-work/wt-assessment-integration` on
`codex/assessment-integration`, based on `9866784`. Assessment-only port `b4bf1fb`
preserves the completed repairs; RV-T/RV-U/Ticket 5 follow through `4234506`.
Tickets 1-7 are committed (`d975bfc`, `e213f4b`); `b116c42` and `bc87804` add
review and stage bounds. Combined gates passed on `bc87804` on 3.12 and 3.14.
The live acceptance run left the assessment incomplete; see Ticket 8.

- Ticket 1: shared history/report contract, named/principal isolation, and selected
  cache/knowledge privacy dependencies. `tickets-1-7.md` records caller evidence.
- Ticket 2: explicit snapshot inventory, dependency preflight and isolated imports;
  `harness/verification_snapshot.py`, `docs/VERIFICATION_SNAPSHOTS.md`.
- Ticket 3: persisted capture variants, identity-safe replay and actionable skip
  reasons; `test_assessment_capture_repair.py` and pipeline defect controls.
- Ticket 4: fair coverage queue, per-task observed sends, phase ledger and managed
  `resume_job_id` checkpoints; `test_assessment_coverage_repair.py` and job callers.
- Ticket 5: approved callback configuration also reaches chain-created validators.
- Ticket 6: structured artifact-resolved vulnerability accounting, retained proof
  instances and SQL error-only negative controls. See the integrated checkout's
  `docs/CONFIRMATION_ACCOUNTING_AUDIT_2026-10-24.md` for historical case audits.
- Ticket 7: transactional managed results, authenticated bounded retrieval,
  hash verification, restart recovery and cancellation partial evidence.
- Ticket 8: run 2026-10-26 on `bc87804` (gates green on 3.12 and 3.14). The job
  was terminal but the assessment INCOMPLETE; 2 unique vulnerabilities survived
  the replay audit. See the Ticket 8 section below.

Batch evidence: `.test-work/assessment-integration-20261023/`. The dependency
description below records the original starting constraints; main WIP is preserved.

Preserve the main checkout's uncommitted assessment repairs by separating them
from older W1–W4 work and reconciling them onto PR #1's tip first. Tickets 1–4,
6 and 7 depend on that catch-up branch; do not implement them on the stale main
checkout or discard the repairs by starting from the PR alone.

- Tickets 1 and 2 come first after catch-up; Ticket 1 retains the already-decided
  shared unnamed history contract, rather than reopening that product decision.
- Ticket 3 also waits for RV-T; then Ticket 4; Ticket 6 follows Ticket 4.
- Ticket 7 follows Ticket 1 because both change the history/report API.
- Ticket 5 is isolated on `repair-t5-callbacks` in `.test-work/wt-t5`.
  Commit `9dd4531` passed full verification on Python 3.12 and callback-only container
  controls. See `.test-work/repair-t5-callbacks-20261021/HANDOFF.md` for evidence
  limits and the exact next step. Do not treat this as integrated readiness.
- Ticket 8 stays last. Owner authorized a full local Juice Shop assessment on
  2026-10-22 after repairs, including discovery, variation and all applicable
  features. Use the owned port 3002 target; integration and offline gates still apply.

Related batches: RV-U is committed as `d74889c`, with both interpreter gates green;
RV-T is committed as `c0c8787` + `ad2466d`, with final Python 3.14 and 3.12 gates green
(3980 harness, 38 pytest, 381 evaluation/17 skips, 59 integrity; smoke 147 and
precondition 74 on both). None was pushed by this session. Use their batch handoffs
for precise integration and verification. These are separate branch results.

## Evidence and current limits

Artifacts are under `.test-work/active-eval-repair-20261021/`.
Final inspected live job: `fd558601b325`, `live-ready/`.
Source hash: `b59d4027a3c4f5a6c1e74d644533db7f3c1fd96c33c621455c2d6190449df480`.

- The job finished after approximately 151 minutes and 23,643 requests.
- Assessment is **incomplete**: 169/4,433 applicable checks recorded execution
  (3.8%); 4,264 did not. Investigated worklist: 7 eligible / 7 investigated;
  74 entries labelled `missing_template`, 22 labelled `unreachable`.
- Do not assume every `missing_template` label proves an absent capture:
  `_skip_reason` currently uses it as its fallback reason.
- Manifest counts 51 proof-bound cases. These include 20 missing-CSP cases and
  eight reconnaissance observations, as well as SQLi/JWT/access-control cases.
  These are not 51 independently verified exploitable vulnerabilities. Case IDs,
  raw proof counts, persisted findings and manifest references do not all count
  the same population; reconcile them before reporting efficacy.
- Recorded SQLi evidence includes product search `q` and login `email`; product
  search includes error-based confirmation and login includes boolean-differential
  and sqlmap evidence. Audit controls before accepting error-only confirmation.
- Durable polling reports `done` but `result_available=false`, with error:
  `job result exceeds durable polling limit; see preserved artifacts`.
- Launcher sets an approved Docker-reachable callback origin, but collaborator.py
  ignores those settings and advertises ephemeral localhost. The fix was identified
  but **not implemented**. The container cannot reach the host through that URL.
- Final-source gates: precondition 74 passed; smoke 146 passed; focused 55 passed.
  **Full failed**: 3,885 harness tests with 10 failures; evaluation 435 tests with
  two errors and 17 skips; integrity 59 passed. See ready-gates-summary.json and
  bounded FAIL/ERROR sections of ready-full.log; never ingest the full log.

## Preserve completed repairs

Keep shared exact-port scope matching, capture review deduplication/interleaving,
execution of inferred coverage cells, bounded failed coverage attempts, explicit
assessment incompleteness, proof/run-bound case inventories, source hashes, model
metadata and the three-action iterative no-progress stop. Their caller controls
must survive subsequent refactoring. Keep all existing pipeline defect injections.

## Ticket 1 — Establish one coherent history/report contract (P0)

Files: harness/server.py, store.py, test_default_history_caller.py,
test_observation_memory_caller.py, test_engagement_atomic_passive.py,
test_pairing_contract.py and its inherited caller suites.

The last repair restored the owner-approved unnamed shared-history default and
fixed observation-memory tests. It exposed contradictory tests expecting a fresh,
nonempty engagement ID on every /analyze response. Do not flip between behaviors
to make whichever suite ran last pass.

1. Trace persistence, response identifiers, report retrieval and observation
   selection together. Retain the documented shared default and named isolation.
2. Decide whether response/report identity needs its own stable handle, separate
   from history partition identity. Do not change named-engagement semantics.
3. Update tests to the explicit product contract, retaining actual authenticated
   report reads, privacy boundaries, token permissions and atomic concurrent writes.
   Do not merely remove the failing assertions.

Acceptance: default history survives separate API calls and process restart;
named partitions remain isolated; returned/default report references retrieve the
correct persisted findings; unauthorized reads still fail; concurrent updates do
not overwrite one another. Run all related/inherited caller suites together.

## Ticket 2 — Repair reproducible verification snapshots (P0)

The verification copy omitted `testing/passive_study_summary.py` and
`testing/web-objective-benchmark/manifest.json`. These caused the two evaluation
errors. Inspect fixture dependencies by filename and import paths, not target
labels. Preserve the no-answer-key rule; if a manifest contains scoring labels,
copy required test assets opaquely without reading their contents.

Make snapshot creation explicit and repeatable: source/dependency inventory,
exclusions, interpreter, source hash, isolated imports and fresh runtime databases.
Do not make broad directory exclusions that silently drop evaluation dependencies.

Acceptance: required modules/assets exist in the snapshot; editable imports cannot
fall back to the parent checkout; full includes unittest, native pytest and evals.
Missing dependencies fail preflight with a useful filename before a 22-minute run.

## Ticket 3 — Restore discovered requests to executable work (P0)

Files: engagement_builder.py, role_crawl.py, engagement.py
(`template_from_exchange`, `record_template`, merge/serialization),
orchestrator_chain.py, worklist_investigator.py.

1. Trace a small sample of the 74 skipped routes through discovery, captured
   exchanges, identity attribution, graph merge, persistence and worklist eligibility.
2. Split the overloaded `missing_template` reason into actual missing capture,
   unsupported method/body, no applicable hypothesis/check, missing principal,
   scope/policy rejection and exhausted budget. Include a concrete next action.
3. Retain real method, query, body, content type, response and principal-specific
   credentials. Do not fabricate a POST body or attach another user's credential.
4. Ensure rich observed captures survive graph normalization/merging and restarts.
   Preserve distinct parameter/body/principal variants rather than one URL winner.
5. Route captured endpoints to deterministic applicable checks without requiring
   a model-generated hypothesis. Unsupported work remains explicitly unsupported.

Acceptance: caller fixture discovers multiple JSON/query/form/object endpoints
under two identities, persists/reloads them, and sends the expected validations.
Negative controls: absent body, foreign identity, adjacent port and unsupported
endpoint cannot be promoted to executable/clean. Inject a dropped-template defect
and require the caller test to fail. Explain each sampled live skip with evidence.

## Ticket 4 — Make coverage applicability and budgets accountable (P0)

Files: coverage_tracker.py, orchestrator_chain.py coverage driver,
validators/registry.py, assessment_health.py, run_context.py.

Audit why 4,433 cells were considered applicable and only 169 executed. Separate
shape applicability from implemented capability, policy authorization, prerequisites
and available budget. Investigate repeated precondition/coverage dispatch across
the same request, identity and check; do not remove necessary controls or retries.

Implement a phase ledger: discovered → captured → eligible → queued → attempted →
sent → conclusive, with one explicit terminal reason per remaining cell. Allocate
fair work across routes, identities and check classes; do not let a repeated cheap
check consume the run. Persist checkpoints and remaining work for bounded resume.

Acceptance: a deliberately small budget produces explicit resumable remainder;
resume does not duplicate completed cases; no unsent attempt is counted executed;
policy blocks/manual checks stay visible. A synthetic fully supported fixture
executes every eligible authorized cell within a budget derived from its workload.
Do not force 100% by shrinking applicability after seeing results.

## Ticket 5 — Wire approved container-reachable callbacks (P0)

Files: collaborator.py, validator construction/configuration and OOB validators;
run-local launcher settings are in live-ready/launch.py.

Separate bind address from advertised origin and accept an explicit port. Default
remains ephemeral loopback. Consume documented config/environment through one
validated construction path. Require an explicit matching approved origin for
non-loopback advertisement; malformed/mismatched config fails before probes.
Bind failure must not silently fall back to an unreachable callback URL.

Preflight reachability from the owned target's container/network. Record capability
health; unreachable callbacks produce incomplete/unavailable, not clean negatives.
Ensure ownership, shutdown and socket release; parallel runs cannot steal listeners.

Acceptance: caller-level SSRF/command-injection fixture reaches the advertised
listener from a container and resolves the exact token. Negative controls cover no
callback, wrong token, occupied port, denied configuration and unrelated hits.
Do not widen target scope to authorize callback dependencies.

## Ticket 6 — Audit confirmation and distinct issue accounting (P0)

Files: validators/jwt_forge_validator.py, cross_identity_validator.py, sqlmap.py,
recon/csp validators, evidence_ledger.py, assessment_health.py, run_manifest.py.

Sample every confirmed validator family from the saved run before trusting totals.
Check JWT acceptance against missing/invalid credentials and a genuinely protected
resource; a public 200 response is not bypass evidence. Cross-identity confirmation
must establish ownership/protected action and compare equivalent principals and
request state. Error-only SQL responses establish an anomaly, not necessarily
exploitable injection; require suitable differential/control or independent evidence.

Separate vulnerabilities, hardening observations, reconnaissance and candidates.
Deduplicate issue/root-cause presentation while retaining all route/principal proof
instances. Do not merge different authorization boundaries merely because class
and path match. Reconcile manifest refs, persisted records and proof ledger totals;
use consistent units and explain why any proof is excluded.

Acceptance: patched/benign public endpoint controls cannot confirm bypass/injection;
repeated CSP across routes does not inflate exploitable vulnerability totals;
proofs resolve to the exact run, case, request and controls. Report sample audited
cases with verdicts and reproducible evidence, never a scoreboard/recall claim.

## Ticket 7 — Deliver large results durably (P0)

Files: job_status.py, server.py investigation polling/report routes, store/export
code, test_job_status_passive.py and authenticated report caller tests.

Keep polling small, but persist the complete result as a managed artifact or
paginated resource. Return authenticated result location, size/hash, summary and
availability. Completion must not produce an unavailable result merely because
inline JSON exceeded its limit. Write atomically and make restart recovery work.
Do not expose arbitrary filesystem paths or bypass existing access controls.

Acceptance: a production caller generates an oversized result, polls completion,
restarts the server and retrieves all pages/artifact with identical counts/hash.
Negative controls cover missing/corrupt artifact and unauthorized access. Preserve
partial evidence on cancellation and distinguish execution error from delivery error.

## Ticket 8 — Run the integrated acceptance test (P1, depends on 1–7)

1. Run focused caller/negative controls, then from the isolated repository root:
   `python -m harness.suite smoke`, `python -m harness.suite full`, and
   `python -m unittest harness.test_orchestrator_precondition`.
2. Require full exit 0 before declaring readiness; document skips without treating
   them as proof. Preserve log summaries and exact tested source hash.
3. Verify current Docker/model/listener health; no reliance on old running notes.
   Use one owned disposable target on port 3002; leave unrelated port 3000 alone.
   Restart the owned Python server with reload=False and fresh cache/state.
4. First run a bounded diagnostic across representative observed request shapes.
   Verify captures reach validators, callback controls work and results are retrievable.
   Stop and repair a dead stage before spending another multi-hour full budget.
5. Run the full authorized workload. Report coverage funnel, skips by reason,
   per-phase request/model/time cost, proof-backed unique issues, and remaining work.
   Distinguish terminal job status from complete assessment status.

Status 2026-10-26 (evidence `.test-work/assessment-integration-20261023/`, HANDOFF.md):
- Steps 1-2 done: v7 gates on `bc87804` passed on 3.12 and 3.14 (full 4196 + 440,
  17 skipped, + 59). Step 3 rechecked live health and callback controls (exact
  token recorded, wrong token rejected).
- Step 4: diagnostics 3 and 4. Diagnostic 3 found a dead coverage drive, fixed by
  `bc87804`; diagnostic 4 sent coverage legs.
- Step 5 (job 383f0ebff8e8, gemma4:latest only, 9534.6 s):
  - The job reached terminal status, but the assessment is incomplete: 155
    captures were left unreviewed at the review time bound.
  - Funnel: discovered 12882 → captured 10944 → applicable 5022 → queued 1343 →
    attempted 1343 → sent 89 → conclusive 89.
  - Terminal reasons: not_applicable 7860, unsupported_or_manual 3507,
    incomplete_attempt 1254.
  - Cost: 39,314 requests and 937 model calls, 24 of which failed with HTTP 500.
  - Delivery: paged export verified by SHA256; recovery after restart returned an
    identical result.
- Issues:
  - 617 raw findings and 164 ledger-confirmed proof instances. The strict
    vulnerability count is 0, because every proof is legacy (no artifact ids).
  - A replay audit re-ran all 149 distinct confirmed claims against the owned
    target. Two unique vulnerabilities were confirmed:
    - SQL injection on the login email returns an admin token.
    - The JWT alg:none token is accepted on 10 routes.
  - The other claims: 39 observations, 31 false positives, 52 not applicable,
    12 not supported, 1 not reproduced and 3 inconclusive.
- Not done:
  - A complete assessment.
  - Proof artifact ids.
  - Stopping csp/recon over-confirmation.
  - Storing full sqlmap evidence.

## Definition of done / agent delivery

- All eight tickets have implementation pointers and caller-level evidence.
- Full verification is green on the same attested source used for the live run.
- No supported, captured, authorized fixture check is silently dropped.
- Docker callback capability is demonstrated; unavailable checks remain incomplete.
- Live results survive polling limits and process restart; counters reconcile.
- Final report separates unique vulnerabilities from observations and candidates,
  with reproducible evidence and explicit coverage limitations.
- HANDOFF.md records commands, source/config fingerprints, process ownership,
  artifact locations, open defects and the exact next step. Update CURRENT_STATE.md
  concisely without erasing unrelated work. No unsolicited deployment or PR merge.

Do not set an arbitrary findings quota. A lower honest count with proven coverage
is better evidence than duplicated or weakly confirmed findings. If the live
assessment remains incomplete, say so and give the concrete blockers and resumable
worklist; do not call successful process termination a full successful test.
