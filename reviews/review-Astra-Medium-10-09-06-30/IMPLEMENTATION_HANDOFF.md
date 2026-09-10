# Astra Medium review — 10/09 06:30

Requested label: `review-Astra-Medium-10/09-06:30`. Directory punctuation is normalized for Windows. The label is user-supplied, not a measured execution timestamp.

## Purpose and evidence boundary

Improve this Burp copilot's trustworthy confirmation, identity-aware workflows, live effectiveness, and operator usability. This is an executable implementation plan, not a claim that the changes are implemented.

Review baseline: HEAD `8b5c6e1`, inspected on 2026-09-10. Source inspection covered onboarding, oracle retirements, and selected models, coverage, reporting, workflow, identity, transport, and investigation paths. No suite or live target run was performed for this review. CURRENT_STATE.md reports 1,505 passing tests from the previous implementation session; that number was not independently verified here. The working tree contains pre-existing untracked files; preserve them.

The primary product milestone is: capture an authenticated object workflow, replay it across distinct principals, demonstrate unauthorized access with controlled evidence, export a reproducible issue, and show the same test does not confirm on the patched fixture.

## Instructions for the implementing agent

1. Read AGENTS.md and CURRENT_STATE.md. Do not reconstruct onboarding from archived handovers. Read this plan and ORACLE_RETIREMENTS.md before implementation.
2. Check actual HEAD and working-tree changes. Re-resolve function names below if code has moved. File references are relative to repository root.
3. Implement one ticket at a time in the dependency order below. Keep existing public APIs working through adapters. Do not replace the whole orchestrator in one commit.
4. Each ticket needs a production caller and a test through that caller. A new helper with only its own unit tests is incomplete.
5. Preserve safe config defaults. Live settings belong in ignored harness/config.local.yaml; never commit it or flip committed defaults. Never read any ANSWER_KEY file or a blind target's app.py. Do not install sqlmap on the host.
6. Run the focused checks, then the full suite after each change. Use fresh isolated cache/store databases for integration tests. After Python changes, restart any server used for live verification; reload is disabled.
7. Record observed commands, exit codes, evidence paths, and limitations. Never label socket-mocked tests as live transport or fixture recall as blind-target recall.
8. Make focused commits ending with the repository-required Co-Authored-By trailer. Do not stage unrelated WIP. Do not push or launch external engagements as part of this plan.
9. Use the defaults specified below for routine schema decisions. If existing APIs make a default incompatible, document the smallest compatible adaptation; do not pause simply because the old review called a topic an architecture decision.
10. On completion or handoff, update CURRENT_STATE.md in place. Keep stable architectural facts in AGENTS.md. Do not mark this entire plan complete when only the first milestone passes.

## Verified source observations behind the priorities

| Observation | Source entry point | Implication |
|---|---|---|
| Confirmation result has status, boolean, confidence, and mostly free-text evidence | harness/validators/base.py: ValidationResult | Introduce typed proof references and exact test-case binding |
| RoleSession has role, headers, name; fallback principal identity hashes credentials | harness/role_crawl.py: RoleSession.principal_id | Separate durable principal identity from renewable sessions |
| Coverage cell key is identity + endpoint + check | harness/coverage_model.py: CoverageMatrix | Different input parameters and states can share a cell |
| Report grouping uses normalized endpoint family + canonical class | harness/report_generator.py: _dedup_key, _collapse_duplicates | Independent bugs can be grouped too broadly |
| Workflow fetch creates clients per request; read methods use direct httpx and writes use GatedAsyncClient | harness/feature_workflow.py: default_fetch_fn | Centralize policy and persistent sessions incrementally |
| Agent probe derivation returns IDOR or auth hypotheses | harness/worklist_investigator.py: _derive_probe | Broaden hypothesis selection only with runtime measurements |
| Existing investigate smoke stubs socket responses and discovery | harness/test_smoke_investigate.py | Keep it, but add actual local HTTP transport coverage |
| Recent fix batch has no fresh live max-coverage measurement | CURRENT_STATE.md | Establish effectiveness before claiming improvement |

These observations are not proof of an exploitable project vulnerability. Validate each suspected failure mode before calling it a defect.

## Delivery order

Priority and implementation order differ: schema and transport foundations are needed before the workflow milestone.

1. T00 baseline and evidence ledger.
2. T01 additive case/proof schema.
3. T02 explicit principal/session/ownership model.
4. T03 run-scoped executor for the authorization path.
5. T04 complete authorization vertical slice with real transport.
6. T05 parameter/state coverage; T06 issue identity and export.
7. T07 stateful workflow engine.
8. T08 remaining transport migration and oracle qualification.
9. T09 model scheduling and T10 release gates/operator flow.

Deliver T00–T04 before broadening capability classes. T06 export is also required to declare the full product milestone complete. Proposed filenames and schemas below are implementation targets, not existing APIs.

## T00 — Establish an honest baseline

**Read:** CURRENT_STATE.md; harness/test_smoke_detection.py; harness/test_smoke_investigate.py; harness/test_smoke_shape_precondition.py. Inspect safe run scripts under testing/vulncorp-helpdesk/maxrun/ without reading blind implementation or answer keys.

**Implement:** a versioned run manifest and results ledger under a dedicated run-output directory. Record run ID, git revision/dirty state, config fingerprint with secrets removed, cache namespace, target identifier, model and tool versions, start/end time, request count, confirmed issues, operational errors, and completion status. Record model metrics as unavailable when not observed; do not invent them.

**Measurement rules:** calculate precision/recall only when an independent expected-case mapping exists. Report unknown for blind recall without authorized independent scoring. Separate vulnerable-fixture recall, patched-control false confirmations, and blind results. Do not read protected answer keys to calculate scores. Preserve timed-out/failed runs in the ledger; never silently drop them from comparisons.

**Tests:** manifest serialization/redaction; interrupted run remains incomplete; unavailable dependencies create a degraded result. Run existing suite as a baseline and preserve output. A full live max-coverage run is still needed for target-effectiveness claims; if unavailable, retain that limitation and continue with local fixture implementation.

**Done:** another agent can identify exactly which code/config produced each recorded result. No performance or recall improvement is claimed yet.

## T01 — Add case-bound structured proof

**Read:** harness/models.py: Finding, TestPlan, ValidationSubmission; harness/validators/base.py: ValidationResult; harness/store.py: persist_findings, persist_validation_submission; harness/orchestrator.py: _cached_validate, _confirm; harness/confirmation_gate.py.

**Add models** in an appropriate shared module, preferably harness/evidence.py:

- TestCaseRef: run_id, case_id, principal_id, request_template_id, check_id, optional parameter_location/parameter_name, optional workflow_state_id.
- ExchangeArtifact: artifact_id, request/response references, timestamp, session reference, actual destination, transport outcome. Preserve raw local replay data separately from redacted export views. Do not put live credentials in IDs or model prompts.
- ProofRecord: proof_id, case reference, validator name/version, baseline/attack/control artifact references, expected invariant, observed result, verdict, limitation/reason, execution flag.
- Verdict enum: confirmed, controlled_negative, inconclusive, blocked, error. A not-applicable capability is an applicability decision, not a negative security verdict.

Keep existing result fields as compatibility views during migration. A legacy unstructured result must not acquire a fabricated proof. Do not downgrade an existing confirmed record merely because it predates the schema: retain it with explicit legacy provenance. New migrated confirmations require the capability's proof contract.

Case IDs identify one concrete test scenario within a run; proof IDs identify attempts. Keep issue IDs separate so retesting does not create a new issue automatically. Persistence migrations must read old databases, preserve old records, and round-trip new fields. Do not bind results by vulnerability-class synonym alone when case IDs are available.

**Tests:** two same-class findings receive only their own proof; serialization/store round-trip; unknown case rejected; an error cannot become controlled_negative; later inconclusive attempt preserves earlier proof; legacy data remains readable.

**Done:** one production confirmation path persists structured evidence and returns it through report/API data. Fields existing only in a dataclass are insufficient.

## T02 — Separate principals, sessions, and ownership

**Read:** harness/role_crawl.py; harness/models.py identity/session models; harness/store.py identity/session functions; harness/server.py: _register_role_identities and session endpoints; harness/validators/cross_identity_validator.py; harness/engagement.py.

Reuse existing identity/session storage rather than creating a second registry. Add stable principal ID, role/permission metadata, tenant memberships, and session references. Store object ownership as observed facts with provenance: object reference, owner principal, tenant if known, creation/read artifact. Unknown ownership must remain unknown.

Keep RoleSession as an adapter. Explicit principal IDs survive cookie/token renewal. Legacy credential-derived identifiers remain clearly provisional; do not assume two different cookies are different people or merge them merely because roles match. Do not infer authoritative tenant membership from URL spelling or role labels.

**Test matrix:** Alice and Bob in tenant A, Carol in tenant B, an explicitly permitted privileged principal, and anonymous. Include own-object success, same-tenant unauthorized access, cross-tenant unauthorized access, public/shared objects, and refreshed Alice credentials. Expected permissions must be declared by the fixture/operator, not invented from role rank.

**Done:** refresh leaves Alice's identity stable; sessions remain isolated; authorized sharing does not confirm BOLA; ownership provenance is available to the validator.

## T03 — Introduce a run-scoped policy executor

**Read:** harness/safety_gate.py: SafetyGate, GatedAsyncClient; harness/feature_workflow.py: default_fetch_fn; harness/role_crawl.py: _probe; direct clients in harness/orchestrator.py; harness/tool_runner.py; existing scope/throttle helpers.

Create a RunContext containing run ID, scoped config, cancellation, request budget, gate, artifact sink, and session manager. Introduce an executor interface accepting a typed request, capability ID, session reference, and case reference. Reuse the gate's decisions; do not create contradictory authorization rules. Delegate request execution through this interface and capture outcome artifacts even for errors/blocks.

Initial migration scope is role crawl + cross-identity confirmation + the T04 workflow. Maintain separate persistent cookie jars per session; do not share cookie state across principals. Enforce scope before each request and redirect hop, explicit credential forwarding rules, existing mutation ceilings, bounded timeouts, and cancellation. Do not treat GET as universally harmless; use capability/action policy. Reserve budget atomically before sending, including retries and controls. Denied sends do not count as executed requests.

Retain backward-compatible constructors with optional context while production callers pass an explicit context. Legacy defaults must not be used to share mutable engagement state in the migrated path. Executor adapters for browser/container work are completed in T08, not falsely claimed here.

**Tests:** separate simultaneous runs with conflicting settings do not contaminate each other; cookies do not cross sessions; off-scope redirect is blocked before destination access; credentials are not forwarded to an unauthorized origin; budget/cancel stops further dispatch; gate denial produces blocked evidence. Use an actual local HTTP fixture for at least cookie and redirect checks.

**Done:** migrated production calls use the executor, and tests assert target-side request counters rather than merely mocking executor calls.

## T04 — Authorization vertical slice over actual HTTP

Add a new non-blind fixture, preferably harness/testing_fixtures/authorization_workflow.py, and harness/test_smoke_authorization_workflow.py. New fixture source is intentionally readable; never reuse a protected blind target implementation. Bind an ephemeral loopback port, use isolated temporary data, and stop the owned server in cleanup.

Fixture behavior: authenticate two known users, create one private object as Alice, independently read it as Alice, attempt Bob and anonymous reads. Provide vulnerable and patched modes differing only in the authorization enforcement. Add same-tenant and cross-tenant cases plus a deliberately public object. Use unique object markers so a login page, generic success, or unrelated object cannot satisfy the oracle.

Exercise the real investigate_engagement path, real executor, real cross-identity validator, finding ingestion, and persistence. A deterministic fake model is acceptable for this tier; mark it model-stubbed. Do not mock socket transport, the validator, dispatcher, or final finding insertion. If discovery is constrained through a supported seed interface, identify the test as seeded rather than a complete discovery benchmark.

**Required assertions:**

1. Vulnerable mode emits a case-bound confirmed authorization issue containing the exact unauthorized private-object evidence.
2. Patched mode attempts the corresponding request and emits no confirmation; its controlled negative is limited to that case.
3. Public objects, identical principals, login redirects, empty bodies, timeouts, and generic 200 responses cannot confirm.
4. Target-side request counters show the baseline, unauthorized attempt, and required controls actually ran.
5. Stored proof round-trips and remains linked to the finding after API/report conversion.
6. Re-run uses isolated caches/state and reproduces the result. Failed cleanup is recorded and cannot be represented as successful teardown.

**Done:** focused real-transport smoke and full suite pass. This proves the authorization slice only, not broad target recall or real-model performance.

## T05 — Expand coverage to concrete inputs and states

**Read:** harness/coverage_model.py; harness/coverage_tracker.py; harness/engagement.py: template_from_exchange; harness/orchestrator.py coverage dispatch.

Add a versioned case key: principal + request template + check + optional input location/name + optional workflow state. For nested JSON use JSON Pointer; for repeated query parameters preserve occurrence identity. Domain/endpoint checks use an explicit no-parameter value. Identify headers case-insensitively and preserve original replay representation.

Derive testable inputs from actual captured requests and available schema, not invented parameters. Generate cases lazily within a recorded budget. Untested or budget-exhausted cases remain visible; do not count them as executed. Keep summary output compatible but aggregate from child cases: one confirmed child can mark endpoint risk, never endpoint-wide testing completion. Add blocked/inconclusive/controlled-negative semantics without interpreting old not_detected records as controlled negatives.

**Tests:** query search vs sort; nested body fields; duplicate query names; two workflow states; two principals; skipped-required cases; old matrix deserialization; counts agree with actual attempts. A check of one input cannot mark its sibling tested.

**Done:** production coverage-driven execution passes case IDs to T01 proofs and reports pending cases honestly.

## T06 — Stable issues, retained cases, usable exports

**Read:** harness/report_generator.py: _dedup_key, _collapse_duplicates, _render_finding; harness/store.py; harness/models.py; existing TestPlan/validation endpoints; burp-extension/ source only as needed.

Use stable issue IDs plus linked case/proof IDs. Default conservative grouping includes endpoint family, method, canonical class, affected input, and authorization boundary. Unknown values must not cause unrelated findings to collapse. Merge proven common root causes only with explicit evidence or operator action. Keep all affected cases/evidence when grouping; do not retain just a winning finding and duplicate count.

Export prerequisites, principal aliases, request sequence, expected vs observed security behavior, impact, proof references, limitations, and retest instructions. Produce a redacted shareable report plus a local replay representation with credential placeholders/session references. A reader must not need secret values embedded in the report to understand impact.

**Tests:** two SQLi inputs on the same endpoint remain distinct; repeated object IDs for the same proven authorization defect group without losing cases; read/write boundaries remain distinct; exports reference available artifacts; secrets are redacted; patched retest links to the original issue rather than deleting history.

**Done:** T04 issue exports a reproducible sequence. Burp UI integration may follow T10; do not claim one-click Burp replay before it is wired and verified.

## T07 — Stateful authenticated workflow engine

**Read:** harness/feature_workflow.py; harness/feature_workflow tests; harness/burp_sitemap.py; harness/second_order.py; harness/task_graph.py; harness/engagement_builder.py.

Extend existing capture/crawl support with versioned Workflow and Step records. Each step declares a request template, principal/session, prerequisites, bounded extractors, assertions, state transition, and optional cleanup. Initial extractors: JSON Pointer, Location, and HTML hidden form fields. Bind tokens and newly created object IDs at execution time. Missing extraction blocks dependent steps; never substitute a guessed ID and call the workflow complete.

Initial misuse variants: skip prerequisite, repeat a single-use action, and switch principal before a protected transition. Define expected business invariants in fixture/operator metadata. LLM-suggested invariants remain hypotheses until reviewed or grounded in observed/declared behavior. Bound refresh retries; distinguish session expiry from access denial. Preserve dependency requirements on resume and register cleanup immediately after creating an object.

Use a new readable fixture for create -> approve -> export. Confirm misuse only after an independent state read or protected-data proof. A successful HTTP status alone is insufficient. OWASP background: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows

**Tests:** token renewal, missing token, legitimate reauthentication, forbidden step skip, vulnerable step skip, idempotent repeat, cross-principal transition, failure/cancel cleanup. At least one complete vulnerable/patched workflow pair must use real local transport.

## T08 — Complete transport migration and qualify oracles individually

Inventory remaining direct HTTP/browser/container sends using targeted rg searches. Route them through executor adapters or document a specific remaining exception with an owner and test. Include discovery, tools, callback interactions, second-order legs, and credential-feedback loops. Propagate run cancellation and evidence references. Preserve container timeout cleanup and existing mutation gates.

Do not alter every validator verdict together. For each retired oracle, read ORACLE_RETIREMENTS.md, implement its stated control, add a paired actual-transport fixture, wire its proof contract, then update qualification metadata only with recorded evidence. Prioritize CSRF and method authorization because they reuse the workflow/identity foundations. Passive deserialization format detection stays informational.

For CSRF require actual cross-site browser behavior with ambient credentials and independent state verification. For method authorization compare the same protected action/data under the same unauthorized principal. Keep rate-limit/token pattern observations non-confirming until their documented exploitability controls exist. Smuggling requires its own raw protocol adapter/fixture; ordinary HTTP response anomalies do not qualify it.

**Done per leg:** observed commands, vulnerable/patched results, proof artifacts, and registry/tier updates agree. No automatic promotion from a unit test to LIVE_VERIFIED_MARKERS.

## T09 — Allocate LLM effort to unresolved hypotheses

**Read:** harness/worklist_investigator.py: _derive_probe; harness/iterative_agent.py; harness/planner.py; harness/analysis_pipeline.py; harness/ollama_client.py.

Introduce bounded hypothesis candidates with grounded evidence, required capability, expected information gained, and estimated cost. Broaden beyond auth/IDOR using captured shape and workflow facts. Run applicable deterministic checks first where useful; skip redundant model work only for the exact satisfied case. Preserve explicit operator requests for deeper analysis. Stop retries that add no new evidence and report the stopping reason.

**Evaluate:** same target snapshot, run manifest, budgets, model settings, and fixed case set; separate cold-cache experiments from warm-cache experiments. Compare request counts, model calls, actual latency, time to first confirmed issue, and precision/recall where scoring exists. State sample size and variability; do not promise an arbitrary speedup. A scheduler change fails acceptance if it silently loses required cases.

## T10 — Release gates and complete operator flow

Provide explicit tiers:

- Unit/hermetic: existing full suite and regression tests; fast logic validation.
- Real transport: seeded/local vulnerable and patched fixtures through production pipeline, no transport/validator mocks.
- Tool/browser: actual Chromium and container adapters with paired fixtures and clean teardown.
- Real model: bounded local Ollama run with recorded configuration and isolated cache.
- Blind engagement: independently scored authorized target, outside ordinary unit CI.

Required-tier dependency failures must fail or mark the run blocked; they must not silently skip and make the release appear qualified. A fully patched fixture suite must produce zero confirmations; mixed suites use explicit expected-case assertions. Real-model variance needs repeated observations and a recorded acceptance baseline, not an invented universal recall threshold.

Build the operator path on existing server job APIs: select scope and identities -> capture/seed workflow -> inspect prerequisites and budget -> run/cancel -> inspect issue proof -> replay/retest -> export. Display blocked/degraded cases and incomplete coverage. Preserve scope and mutation policy for replay. Do not implement a second job API if the current cancellable investigate job can be extended.

For Burp Java changes, add a JDK-enabled CI build gate. This machine has no host javac; local self-review is not a successful compile. Record the user's/CI gradle shadowJar result before claiming Java validation.

## Verification commands and execution log

Run commands from PowerShell. Existing tests:

```powershell
Set-Location C:\Users\arthu\Documents\AgenticVibe\harness
python -m unittest test_smoke_detection test_smoke_investigate test_smoke_shape_precondition
python -m unittest test_identity test_identity_compare test_cross_identity_validator
python -m unittest test_coverage_model test_coverage_tracker test_feature_workflow
python -m unittest test_report_generator test_safety_gate test_oracle_retirements
python -m unittest discover -p "test_*.py"
```

After creating the proposed real-transport smoke:

```powershell
python -m unittest test_smoke_authorization_workflow
```

These are required commands, not recorded successes. If python/dependencies are unavailable, resolve the configured runtime without installing offensive host tools; preserve the original failure. Do not replace failing tests with mocks to make a gate green.

Append actual results to EXECUTION_LOG.md in this directory as work proceeds. For each ticket record commit, changed production caller, exact commands/exit codes, artifact paths, test tier, negative control, and remaining limitations. Add new test module names to this section only once those modules exist.

## Completion checklist

- [x] T00 baseline and run ledger (focused tests pass; full-suite dependency gate is recorded in `EXECUTION_LOG.md`)
- [ ] T01 proof/case schema wired to persistence and production confirmation
- [ ] T02 stable principals, sessions, ownership
- [ ] T03 run-scoped executor on authorization path
- [ ] T04 real-transport vulnerable/patched authorization smoke
- [x] T05 case-level coverage (branch `astra-t05-t08`: concrete case keys + case-granular
      driving wired to T01 proofs, default-OFF flags; per-validator PARAMETER attribution
      deferred to T08 oracle work. Focused + full suite green — 1,625 tests OK.)
- [x] T06 issue identity and reproducible export (branch `astra-t05-t08`: stable run-independent
      issue IDs, conservative grouping, redacted export + replay view; operator root-cause MERGE
      and Burp one-click replay deferred to T10.)
- [x] T07 stateful workflow engine
- [ ] T08 transport migration and individually qualified oracle improvements (branch
      `astra-t05-t08`: INVENTORY + routing-gap AUDIT + enforcement test done — 32 sites, 23
      target gaps owned/named; the actual per-site executor migration and per-oracle
      re-qualification with paired live fixtures remain OPEN.)
- [ ] T09 measured model scheduling
- [ ] T10 release tiers and operator run/replay/export flow

The first product milestone is complete only when T04 evidence survives T06 export and the patched control stays unconfirmed. The full roadmap remains open until every ticket has its own production wiring and verification record.
