# Implementation execution log

## T00 — run manifest and results ledger

- Baseline: HEAD `8b5c6e19140dafe75d23155b499446e160663737`; tracked tree already
  contained a `CURRENT_STATE.md` review addendum and numerous unrelated untracked files.
- Production caller: `POST /engagement/{host}/investigate` in `harness/server.py`.
- Artifacts: per-run `harness/run-output/<run_id>.json` plus append-only
  `harness/run-output/ledger.jsonl` (ignored by Git); tests use isolated temporary directories.
- Test tier: hermetic/unit and HTTP API caller. Negative controls cover unavailable metrics,
  dependency failure/degraded status, interrupted runs remaining incomplete, and secret redaction.
- `python -m unittest test_run_manifest test_server.InvestigateJobEndpointTests` — exit 1,
  not executed because `python` was absent from PATH.
- Bundled Python with repository `.review-deps`, focused 9-test suite — exit 0, 9 tests OK.
- Bundled Python with repository `.review-deps`, full `test_*.py` discovery — exit 1,
  1,489 tests run in 270.550s; 2 errors and 2 skips. Both errors were environment/import
  failures before test execution: missing `pytest` in `test_plugin_system` and missing
  `mitmproxy` in `test_safety_proxy_addon`. No T00 test failed. This is not recorded as a
  green full-suite baseline.
- Limitations: no live engagement or model run was performed; request counts, model metrics,
  precision, and recall remain explicitly unavailable unless supplied by an observing pipeline.
  T01–T10 remain open.

### Dependency-gate repair (same T00 baseline)

- Installed the already-declared pins `pytest==9.1.1` and `mitmproxy==12.2.3` into the
  existing untracked `.review-deps` test environment. No dependency declaration changed.
- Pip reported a metadata conflict: mitmproxy 12.2.3 caps `typing-extensions` at 4.14.0,
  while the bundled Pydantic stack requires a newer release. Verification therefore keeps
  the bundled core runtime first on `sys.path` and appends the optional proxy/test environment.
- `pytest harness/test_plugin_system.py -q` through the configured runtime — exit 0,
  **26 passed in 0.35s**.
- Full stdlib `test_*.py` discovery through the configured runtime — exit 0,
  **1,509 tests passed, 2 skipped, in 272.821s**. The previously missing mitmproxy module
  contributed 22 executed tests; the pytest-native plugin suite is recorded separately above.

## T01 F02/F06 — proof verdict qualification

- Baseline: `9fdbb11`; branch `codex/astra-review-fixes`. Commit subject:
  `fix(t01): require qualified controlled-negative evidence` (this focused commit).
- Production path: `ProofRecord.from_validation_result`, consumed by
  `Orchestrator._validate_findings`. Bare legacy `not_confirmed` results now remain
  inconclusive. Controlled negatives require `controlled=True`, explicit
  `executed=True`, and control-artifact references. Artifact-free compatibility
  results carry `legacy=True` plus a `legacy/unstructured` limitation.
- Negative controls: retired CSRF observation cannot become a secure-boundary proof;
  blocked/error/skipped mappings remain non-negative; direct controlled-negative
  construction without a control artifact is rejected.
- `python -m unittest test_evidence` — exit 1 before execution because `python` is not
  on PATH. Bundled Python first attempt — exit 1 before tests because sandbox access
  to repository `.review-deps` was denied. Both are environment failures, not passes.
- Bundled Python with existing `.review-deps`, `test_evidence test_oracle_retirements
  test_smoke_authorization_workflow` after persistence-failure coverage — exit 0,
  **37 tests OK in 5.292s**.
- First full discovery — exit 1, **1,577 tests, 8 failures, 2 errors, 2 skipped in
  315.015s**. This exposed a pre-existing test-order leak: `test_ollama_client`
  permanently replaced the shared `httpx.AsyncClient`, poisoning later T03/T04 socket
  tests. A per-test cleanup regression was added without changing production transport.
- Ordered `test_ollama_client test_run_context test_smoke_authorization_workflow` —
  exit 0, **28 tests OK in 45.345s**.
- A quiet full-discovery diagnostic that globally disabled logging — exit 1,
  **1,577 tests, 10 audit-logger failures, 2 skipped in 309.005s**. The wrapper caused
  those failures and is not a valid gate.
- Definitive full stdlib discovery after persistence-failure coverage, with normal
  logging — exit 0, **1,578 tests OK, 2 skipped, in 314.586s**.
- Test tier: hermetic/unit plus the existing local real-transport authorization slice.
  No model, browser/container, blind target, or live engagement run was performed.
- Remaining T01 work: F03 exact originating-case binding and removal of class-wide
  confirmation assignment. No T01-complete claim is made by this commit.

## T01 F03 — exact originating-case binding

- Baseline: `21f6580`; commit subject: `fix(t01): bind proofs to originating findings`
  (this focused commit).
- Production path: `Orchestrator._validate_findings` creates the case before dispatch
  and carries `(finding, validator, case)` together through result handling. Durable
  confirmations update only that exact finding and attach its case/proof IDs; the
  class-wide confirmation map and class-wide cross-identity downgrade were removed.
- Case coordinates now include a stable finding discriminator plus explicit principal,
  request-template, input, and workflow fields when supplied. The captured request
  fallback template distinguishes body variants as well as method/URL.
- Persistence: `proof_records.finding_ref` and finding-level `finding_id`, `case_id`,
  and `proof_id` are additive migrations and are returned by `all_host_findings`.
  Legacy proof rows without `finding_ref` retain their original deterministic case hash.
- Regression/negative control: two same-class findings return confirmed and skipped;
  only the former is updated and linked. Separate principal/request variants receive
  distinct case IDs. The exact linkage round-trips through finding persistence.
- Bundled Python with existing `.review-deps`, `test_evidence` — exit 0,
  **31 tests OK in 1.147s**.
- Bundled Python with existing `.review-deps`, `test_evidence test_engagement
  test_smoke_authorization_workflow` — exit 0, **79 tests OK in 6.160s**.
- Full stdlib discovery — exit 0, **1,581 tests OK, 2 skipped, in 314.376s**.
- No model, browser/container, blind target, or live engagement run was performed.
  T01 is complete for review findings F02/F03/F06; T03 F07 is next.

## Parallel track (Opus) — T05, T06, T08 on branch `astra-t05-t08`

Branched from `codex/astra-review-fixes` @ `e24ca7f` in worktree
`.worktrees/astra-t05-t08`, so the identity track (F07 etc.) and this coverage/
issue/transport track do not collide; later reconciled by merge. The identity
contracts (evidence.TestCaseRef / ProofRecord / Verdict) and case/proof identity
(T01 F02/F03/F06) were treated as settled per the codex log above.

### Test environment (reconciliation)

- The prior sessions' env (CPython 3.12 + `.review-deps`) was NOT reproducible on
  this machine: only Python 3.14 was installed, and `.review-deps` ships cp312
  compiled extensions (`pydantic_core`), so 3.14 could not import the stack.
  Installed CPython **3.12.10** via `py install 3.12`. `.review-deps` then loaded,
  except its `typing_extensions` (mitmproxy-capped) lacks `sentinel` for the newer
  anyio → installed `typing_extensions==4.16.0` into a scratchpad shim prepended on
  PYTHONPATH. Runner: `pythoncore-3.12-64\python.exe` with `PYTHONPATH=<shim>;<.review-deps>`.
- **Baseline reconciled:** full stdlib discovery on the `e24ca7f` tree — exit 0,
  **1,581 tests OK, 2 skipped**, 312.466s — an exact match to the codex log's count.

### T05/R26 — concrete per-input/per-state coverage case keys

- Commits `fdc50bb` (case-key layer) + `e9a9d76` (case-granular driving + T01 proof wiring).
- Production path: `coverage_model.CaseKey`/child-case layer/aggregation/new statuses;
  `coverage_tracker.expand_parameter_cases`/`drive_coverage_cases`/`build_coverage_cases_driven`;
  `orchestrator._coverage_proof` persists a case-bound `ProofRecord` per driven leg; two
  default-OFF config flags (`coverage_drive_cases`/`coverage_case_budget`) select the path.
- Case key aligns field-for-field with `evidence.TestCaseRef` (occurrence folds into the
  proof parameter name so repeated `?id=&id=` get distinct case_ids). CaseKey drives NO
  live behavior unless the flags are on — live coverage semantics unchanged by default.
- Tests: `test_coverage_cases` (35), `test_coverage_tracker` CasesDrivenTests (+4),
  `test_smoke_investigate` case-driven end-to-end (+5, incl. persisted-proof + parameter-coord
  + secure-server negative control). Focused runs exit 0. Full stdlib discovery — exit 0,
  **1,625 tests OK, 2 skipped**, 313.902s (+44 over baseline; no failures).
- Not done here: per-validator PARAMETER attribution (a leg still tests the whole request;
  the case layer records honest pending siblings). Left to T08 oracle re-qualification.

### T06 — stable issue IDs + reproducible export

- Commit `04f6d32`. New `issues.py`: run-independent `issue_id` over a conservative key
  (endpoint family + method + canonical class + affected input + read/write boundary);
  an `Issue` keeps ALL members; `export_issue`/`replay_view` render prerequisites, principal
  aliases (P1/P2, never a raw credential), request sequence, expected-vs-observed, impact,
  proof references, limitations, retest — with `redact()` masking Bearer/Cookie/JWT/secret
  query values and `<<SESSION:Pn>>` placeholders in the replay view.
- `store.all_host_findings` now surfaces `method` + the finding's case coordinates
  (parameter_location/parameter_name/principal_id via proof subqueries; additive keys).
  `report_generator._dedup_key` is now `issues.issue_key`; findings render their stable
  issue id; `export_issues_for_host` returns the reproducible exports.
- Tests: `test_issues` (18 + a store round-trip that exports a persisted finding's linked
  proof). Existing `test_report_generator` (31) + `test_store` (16) unchanged. Focused exit 0.
- Not done here: operator-driven root-cause MERGE of distinct issues (kept conservative,
  no auto-merge); Burp UI one-click replay (T10).

### T08 — transport-adapter inventory + routing-gap audit

- Commit `e1ac8e9`. `transport_inventory.py` registers all 32 outbound sites (29 http,
  1 container, 1 browser, 1 raw-socket) with scope/routing/owner/gap;
  `test_transport_inventory` (10) enforces MODULE-granularly that a new module opening an
  httpx client cannot be added un-inventoried (`test_scan_matches_registry`) and that each
  of the **23 target-directed routing gaps** is owned+named (guard limits pinned by
  `test_inventory_is_module_granular` after review R11). Audit doc: `T08_TRANSPORT_INVENTORY.md`.
- Inventory + audit only — no transport behavior changed. Per-leg oracle re-qualification
  (paired live fixtures, proof contracts) is named as deferred follow-on, not claimed.
- Highest-value gaps feed the identity track: `role_crawl.py` (F01) and
  `cross_identity_validator.py` session isolation (F04).

### Combined verification (T05+T06+T08 on the branch tip)

- Full stdlib discovery after all three tickets — exit 0, **1,653 tests OK, 2 skipped**,
  315.016s (1,581 baseline + 72 new: 44 T05, 19 T06, 9 T08). Zero real failures/errors
  (the `ERROR:`-prefixed lines in the log are audit records emitted by tests that
  deliberately exercise LLM/model error paths; the run ends `OK`).
- No model, browser/container, blind-target, or live engagement run performed — all
  hermetic. New live coverage behavior is flag-gated OFF by default, so target recall is
  unchanged until a run enables `coverage_drive_cases`. Not yet merged into `WorkingSunday`.

### Review response — IMPLEMENTATION_REVIEW_T05_T08.md (11 findings)

Reviewer's offline diagnostics (`review_t05_t08_checks.py`) all now return the corrected
values. Each fix has a paired regression:

- **R01 (P1) per-input attribution fabricated** — the case driver now drives a leg ONCE
  PER CELL on the request-level (no-parameter) representative and binds the verdict + its
  proof there; enumerated parameter inputs are recorded INCONCLUSIVE ("no per-parameter
  attribution"), never credited with the request-level verdict/proof/execution.
  `test_coverage_tracker.test_request_level_confirm_does_not_credit_parameter_siblings`.
- **R02 (P1) principals collapsed to role** — coverage now keys on the durable
  `RoleSession.principal_id()` (identity track's scheme), mapping principal→role only for
  reachability/trust; `_role_headers` keyed by principal id.
  `test_coverage_tracker.PrincipalIdentityTests` (Alice/Bob/anon stay 3 identities).
- **R03 (P1) export/replay retained secrets** — `redact()` now masks JSON secret keys;
  `redact_url()` masks userinfo + secret query params; every exported field, all
  `affected_instances`, and the replay view are redacted. `test_issues.ReviewRegressionTests`
  (url/json/replay secret markers gone).
- **R04 (P1) issue id omitted application + over-grouped unknowns** — `issue_key` now
  includes the scheme+host namespace and, for an UNKNOWN input, a per-finding disambiguator
  so distinct unattributed findings stay separate (attributed inputs / repeated object ids
  still group). `test_issues` (different targets distinct; two unknown-input findings → 2).
- **R05 (P1) errors vanished / no budget** — `drive_coverage_cases` budget now bounds
  DISPATCH ATTEMPTS; a raising callback records ERROR (visible), None records INCONCLUSIVE.
  `test_coverage_tracker.test_failing_callback_is_recorded_as_error_and_consumes_budget`.
- **R06 (P1) negative+error read as "all tested"** — aggregation now claims completion only
  when EVERY child is a conclusive negative; an errored/blocked/inconclusive child forbids
  it; unknown status maps to INCONCLUSIVE not NOT_DETECTED.
  `test_coverage_cases.test_negative_plus_error_child_is_not_completion`.
- **R07 (P2) occurrence name collision** — occurrence folds as `<name>[occ:<n>]`, which
  cannot collide with a literal `<name>[<n>]`. `test_coverage_cases.test_occurrence_encoding_*`.
- **R08 (P1) retest history discarded by storage** — findings dedup index is now
  `(fingerprint, case_id)`, so a retest (new case identity) is its own row; suppression is
  unchanged (keys on `fingerprint` alone). `export_issues_for_host` surfaces the FULL
  append-only proof-attempt history per case. `test_issues.test_retest_survives_storage_as_one_issue_with_both_attempts`.
- **R09 (P2) proof id/verdict mismatch** — proof references resolve each verdict by the
  EXACT proof id and list every recorded attempt; a member pointer with no ledger attempt
  carries no fabricated verdict. `test_issues.test_proof_verdict_resolved_by_exact_id`.
- **R10 (P2) generic export** — expected invariant is class-keyed (not a blanket
  read/write); per-member evidence is preserved; an `artifacts` block marks what is/ isn't
  replayable. `export_issues_for_host` is the operator entry point.
- **R11 (P2) inventory guard weaker than claimed** — reworded to a MODULE-granular guard;
  `test_inventory_is_module_granular` pins that a second site in a registered module / an
  aliased constructor is not caught, and the doc no longer overstates enforcement.

Documented, NOT fixed here (review "additional gaps"):
child cases are enumerated only for pending cells (a prior confirmed/detected finding hides
its untested sibling inputs); production case derivation omits headers/workflow-state (the
standalone CaseKey supports them); `_coverage_proof` does not yet forward execution/control
artifact metadata. The singleton run-id dependency is now resolved by the merged F07
`RunContext`; coverage proofs consume that invocation's `run_id`. The remaining items are
visibility/contract refinements, not correctness fabrications.

## Reconciliation — identity track through `5f0522a` + T05/T06/T08

- Merged `codex/astra-review-fixes` through `5f0522a` into `astra-t05-t08`, preserving
  both the reviewed coverage/issue/transport behavior and F07/session/ownership fixes.
- Conflict resolution: removed the obsolete process-wide `Orchestrator._run_id` path;
  `_coverage_proof` now consumes the caller's invocation-local `RunContext.run_id`.
  Direct helper callers create a fresh fallback context instead of mutating the
  orchestrator. The occurrence regression reuses one explicit context, proving distinct
  cases arise from the input coordinate rather than accidentally from different runs.
- Reviewer's offline `review_t05_t08_checks.py` — exit 0; all eight diagnostic failure
  markers corrected.
- Combined focused matrix (`test_run_context`, principals/evidence/authorization/API,
  coverage/issues/transport/report/store, investigation smoke) — exit 0,
  **279 tests OK in 22.833s**.
- Full stdlib discovery using CPython 3.12.10 with the recorded shim + `.review-deps` —
  exit 0, **1,685 tests OK, 2 skipped, in 317.988s**.
- No external target, real model, browser, or container run was performed.

## T07a/T07b — explicit workflow contracts and RunContext execution (in progress)

- Commits `ec19ed8` and `cbbc192` add versioned workflow/step/result records,
  dependency validation, strict template binding, JSON Pointer/Location/hidden-field
  extraction, assertions, cleanup registration, bounded refresh, and deterministic
  skip/repeat/switch-principal variant plans.
- Production caller: `Orchestrator.investigate_engagement` reads
  `engagement.declared_workflows`, passes the invocation-local `RunContext` through
  `engagement_builder.execute_declared_workflows`, and returns serialized outcomes.
- Real-transport tier: readable loopback fixture creates as Alice, attempts approval
  as Bob, independently reads state as Alice, and cleans up. Vulnerable mode passes
  only after the state read; patched mode returns 403, blocks verification, and still
  cleans up. Target calls are asserted; transport/executor are not mocked.
- Invalid environment attempt with a mistyped dependency path failed imports and is not
  counted. Valid focused workflow + production-caller smoke: exit 0, **30 tests OK**.
- Full stdlib discovery: exit 0, **1,702 tests OK, 2 skipped, in 324.669s**.
- T07 completion: `execute_misuse_variant` sends bounded skip/repeat/switch-principal
  variants through the same executor; resume accepts only the same workflow/version and
  preserves passed dependencies and extracted values without replay; cleanup failures
  remain visible. The readable loopback fixture adds vulnerable/patched prerequisite-skip
  controls and proves repeat dispatch is exactly two target sends.
- Final T07 focused workflow/identity/production/transport matrix — exit 0,
  **102 tests OK in 21.300s**. Full stdlib discovery — exit 0,
  **1,708 tests OK, 2 skipped, in 320.729s**.
## T03 F07 — invocation-local run identity

- Baseline: `e24ca7f`; commit subject: `fix(t03): isolate run identity per invocation`
  (this focused commit).
- Production caller: `POST /engagement/{host}/investigate` creates one `RunContext`
  whose run ID matches the persisted manifest, passes it into
  `investigate_engagement`, and closes it with the job lifecycle. Cancellation signals
  the same context before cancelling the asyncio task.
- Proof path: `analyze`, recursive captured/discovered exchange analysis, and
  `_validate_findings` accept the invocation context. The process-wide orchestrator no
  longer lazily stores or reuses a run ID.
- Isolation: configuration is deep-copied at context creation; cache keys accept a
  namespace and API-created namespaces combine the configured label with the manifest
  run ID. Request budgets, cancellation tokens, gates, sessions, and cache/proof
  namespaces remain distinct across sequential and overlapping jobs.
- Regression/negative control: back-to-back and concurrent proof construction retains
  different case namespaces without mutating the orchestrator; mutating the source
  configuration after context creation does not affect the earlier run; two API jobs
  pass distinct manifest-matching contexts.
- Initial focused run after the server edit — exit 1: **55 tests run**, with server job
  endpoint errors caused by a misplaced local `urlsplit` import. Corrected before any
  pass was recorded.
- Focused `test_run_context test_evidence test_run_manifest` plus investigation API
  endpoint tests — exit 0, **55 tests OK in 7.021s**.
- First expanded focused run including `test_cache` — exit 1, **80 tests run in
  7.825s**. The concurrent proof test raced on its shared temporary SQLite persistence
  and produced `database is locked`; persistence was replaced with the existing seam
  because that test targets concurrent case construction, not SQLite concurrency.
- Corrected expanded focused run — exit 0, **80 tests OK in 8.025s**.
- Full stdlib discovery — exit 0, **1,585 tests OK, 2 skipped, in 291.453s**.
- After enforcing a fresh context before every top-level captured-exchange cache lookup,
  final focused cache/context/proof/smoke/API checks — exit 0, **80 tests OK in
  149.575s**; definitive full stdlib discovery — exit 0, **1,585 tests OK, 2 skipped,
  in 287.529s**.
- Test tier: hermetic/unit, local executor transport inherited from `test_run_context`,
  and HTTP API production-boundary tests. No model, browser/container, blind target, or
  live engagement run was performed. T03 F04/F05 credential isolation is next; broad
  executor wiring remains intentionally assigned to F01.

## T03 F04/F05 — session and credential isolation

- Baseline: `d077c74`; commit subject: `fix(t03): isolate sessions and credentials`
  (this focused commit).
- Production path: `investigate_engagement` registers each supplied role plus anonymous
  in the invocation's `SessionManager` and constructs its cross-identity validator with
  that context. The validator uses those run-local sessions rather than the global
  identity-header registry.
- Transport policy: session references are mandatory for credential-bearing requests
  and unknown references fail closed before a send. Credential sessions require an
  explicit allowed-origin set. Default HTTP/HTTPS ports normalize consistently while
  different ports remain different origins. Unauthorized initial destinations are
  blocked; cross-origin redirect hops use the anonymous/default cookie jar and drop
  retained bodies as well as credential headers.
- Regression/negative controls use loopback target counters: cookies remain isolated
  across principals; an authenticated cookie cannot reach a different origin; a session
  cannot start at an unauthorized origin; unknown sessions and unbound credentials send
  nothing; and a 307 cross-origin hop receives no original body.
- Initial focused authorization run — exit 1, **73 tests run in 12.445s**, 16 failures.
  Existing validator test doubles accepted the legacy two-argument probe signature, and
  the T04 smoke still seeded the retired global identity registry. The compatibility
  adapter now calls legacy test seams with two arguments, while the T04 smoke explicitly
  registers run sessions.
- Corrected focused authorization/investigation/T04 run — exit 0, **73 tests OK in
  12.516s**. Focused actual-transport executor run after redirect-body coverage — exit 0,
  **18 tests OK in 8.783s**.
- Full stdlib discovery — exit 0, **1,591 tests OK, 2 skipped, in 289.004s**.
- No external target, model, browser, or container run was performed. Broad role-crawl,
  registry, and remaining validator transport wiring belongs to T03 F01/T08 and is not
  claimed here.

## T02 F08/F09/F10 — principal metadata and ownership semantics

- Baseline: `792f6b9`; commit subject: `fix(t02): preserve principal ownership cases`
  (this focused commit).
- Persistence: `save_identity` now uses `INSERT ... ON CONFLICT DO UPDATE` for legacy
  identity fields rather than replacing the row, so tenant, permissions JSON, and trust
  metadata survive credential/profile updates.
- Production identity path: API role inputs retain tenant and declared permissions;
  engagement session registration attaches the authoritative `RoleSession.to_principal`
  result. Cross-identity ownership checks consume that object rather than rebuilding a
  name/role-only principal.
- Ownership identity: `principals.object_reference` namespaces concrete selections by
  run ID, normalized application origin, explicit tenant state, path, and raw query.
  Query order/repetition remains part of the selection, preventing `/item?id=1` and
  `/item?id=2`, different targets, or different runs from sharing an ownership fact.
- Aggregation: an explicitly authorized owner/share/public/permission case increments a
  per-principal outcome and evaluation continues. A later unauthorized principal can
  still confirm the crossing; the final observation states how many configured
  principals were evaluated instead of claiming all were denied.
- First focused run — exit 1, **78 tests run in 13.837s**, 8 errors from an incorrectly
  scoped `authorized` accumulator. Second run — exit 1, **78 tests run in 13.850s**, one
  wording assertion failure. Both were corrected before a pass was recorded.
- Final focused principal/identity/cross-identity/T04/transport/API run — exit 0,
  **84 tests OK in 14.901s**.
- Full stdlib discovery — exit 0, **1,595 tests OK, 2 skipped, in 294.398s**.
- Negative controls: identity metadata survives a second save; raw query selection,
  run, and target variants produce distinct references; a declared permission survives
  the validator adapter; Bob's authorized share does not prevent Carol's unauthorized
  case from running and confirming.
- No external target, real model, browser, or container run was performed. Ownership
  facts are still supplied by fixture/operator provenance; the harness does not infer
  ownership or tenant membership from URL or role labels.
## 2026-09-10 — T08 executor migration pause checkpoint

- Commits `693b4c8` through `546def9` route the production role access matrix,
  crawler, API surface discovery, feature workflow crawl, autonomous scope
  expansion, CSRF replay, and verb-tamper probes through invocation-local
  `RunContext` sessions. The already-reviewed cross-identity route is reconciled
  as executor-routed.
- Actual-loopback controls verify credential isolation/binding and shared request
  budget consumption. Negative controls verify missing session mappings and
  unregistered credentials fail closed with zero sends. Redirect behavior inherits
  the executor's per-hop scope checks.
- Focused results: 39 OK (role/engagement), 105 OK (CSRF/verb/context), 88 OK
  (discovery/context), 47 OK (crawler/surface), 29 OK (feature workflow), 30 OK
  (scope/context), and 10 OK (inventory). All final focused invocations exited 0.
- Inventory: 32 sites, 17 remaining target routing gaps (previously 23).
- No external target/model/browser/container run. The latest full discovery remains
  the post-T07 result: 1,708 OK, 2 skipped; a post-T08 full suite is still owed.
- Resume: migrate `missing_auth_probe.py` next, then capability validators and the
  residual orchestrator/agent paths one at a time with actual and negative controls.
## 2026-09-11 — T08g–i and live-run reconciliation

- `ec450a3`: missing-auth API probing uses bounded RunContexts; anonymous and
  garbage-token requests have distinct session state. Actual negative control
  confirms blocked mutation sends zero requests and consumes zero budget.
- `6d99cd1`: JWT garbage/forge variants use isolated ephemeral sessions through
  the executor. Actual vulnerable `kid` fixture confirms; fixed-secret control
  remains silent.
- `ddfa95f`: rate-limit replay uses the invocation gate, session, budget and
  executor. Three-send actual transport control passed; oracle remains explicitly
  observation-only.
- Final focused gates: 39 OK; 6 OK (plus 92 OK, 2 skipped broader confirmation);
  75 OK; inventory 10 OK. Inventory now 14 target routing gaps.
- S19 live run is not complete: pass 1 finished 37/37 in 5,946.5s, while pass 2
  remains active. Its intermediate JSON has `investigate: null`; final coverage
  and recall are therefore not yet reconciled.

## 2026-09-11 — T08j TOCTOU transport

- Graph TOCTOU validation now routes baseline/verify reads and the concurrent
  authority-write burst through the invocation RunContext. Credential headers
  bind to the matching session; the run gate, budget, cancellation, and evidence
  policy apply to every request. Legacy registry invocation remains compatible.
- Added real loopback controls: the permitted path performs exactly 4 POSTs plus
  2 reads, preserves the bound bearer identity, and consumes exactly 6 requests;
  the denied-mutation path performs zero POSTs and consumes only its baseline GET.
- Focused TOCTOU + inventory run: exit 0, **19 tests OK in 1.249s**.
- First broad command: exit 1, **67 tests run**, solely because the named module
  `test_confirmation_routing` does not exist. Corrected broad confirmation,
  cache, precondition, smoke, TOCTOU, and inventory matrix: exit 0,
  **108 tests OK in 6.171s**. Existing ResourceWarnings from two smoke fixture
  sockets were emitted; no assertion failed.
- Inventory reconciliation: 32 sites, **13 target routing gaps** (down from 14).
  No new live/model/browser/container run was started; active S19 was untouched.

## 2026-09-11 — T08k race-condition transport

- Registry race-condition bursts route through the invocation gate, bound
  session, budget, cancellation, and executor. The shared registry validator is
  never mutated: `bind_run_context` returns shallow per-dispatch copies.
- Preserved the original two-argument `for_finding` interface for lightweight
  registries/plugins. The first broad run exposed this compatibility requirement:
  exit 1, **155 tests run, 12 errors**, all from test registries rejecting the
  initially-added keyword argument. Moving binding to the optional hook fixed it.
- Actual-loopback controls verify exactly 3 authenticated sends and budget units;
  mutating-replay denial verifies zero sends and zero budget. A separate control
  proves two contexts bind to distinct copies while the registry object remains
  context-free.
- Initial focused matrix: exit 0, **56 tests OK in 2.899s**. Corrected broader
  registry/evidence/confirmation/smoke matrix: exit 0, **155 tests OK in 7.296s**.
  Existing smoke-fixture socket ResourceWarnings remain non-failing.
- Inventory reconciliation: 32 sites, **12 target routing gaps**. Active S19 was
  untouched and no new live/model/browser/container run was started.

## 2026-09-11 — T08l SQLMap fallback transport

- Preserved the pinned SQLMap container/tool-runner adapter exactly as-is. The
  dependency-free boolean/error differential fallback now sends through the
  invocation executor with matching-session credential binding; non-GET
  preflight authorization uses the invocation gate rather than the singleton.
- Actual loopback control verifies two GET variants, two budget units, and the
  bound bearer credential. The denied POST control verifies the first executor
  decision blocks before transport, with zero requests and zero budget used.
- Focused SQLMap/safety/inventory/validator matrix: exit 0, **117 tests OK in
  7.918s**. Broader SQLMap, safety, evidence, confirmation, cache, and smoke
  matrix: exit 0, **187 tests OK in 13.481s**. Existing asyncio timing notices
  and smoke-fixture socket ResourceWarnings were non-failing.
- Inventory reconciliation: 32 sites, **11 target routing gaps**. Active S19 was
  untouched; no new live/model/browser/container run was started.

## 2026-09-11 — T08m CORS transport

- Registry CORS requests now route through the invocation executor, including
  per-hop scope, request budget, cancellation, and configured redirect limits.
  Existing direct transport remains only for standalone calls without context.
- Actual loopback control verifies one GET and one budget unit. The off-scope
  negative control verifies no target request and zero budget consumption.
- Focused CORS/inventory/registry/evidence/confirmation matrix: exit 0,
  **77 tests OK in 3.916s**. Broader executor/cache/smoke matrix: exit 0,
  **120 tests OK in 16.136s**. Existing smoke socket ResourceWarnings were
  non-failing.
- Inventory reconciliation: 32 sites, **10 target routing gaps**. CORS oracle
  behavior was not promoted or otherwise changed; active S19 was untouched.

## 2026-09-11 — T08n CSP/clickjacking transport

- Fresh CSP/framing header requests now route through the invocation executor,
  carrying per-hop scope enforcement, budget, cancellation, and the validator's
  redirect limit. Standalone context-free calls retain the direct compatibility
  path; CSP and framing oracles are unchanged.
- Actual loopback control verifies one request and one budget unit. Off-scope
  control verifies no request and zero budget use.
- Combined CSP/CORS/inventory/executor/evidence/confirmation/smoke matrix:
  exit 0, **122 tests OK in 16.892s**. Existing smoke socket ResourceWarnings
  were non-failing.
- Inventory reconciliation: 32 sites, **9 target routing gaps**. Active S19 was
  untouched and no new live/model/browser/container run was started.

## 2026-09-11 — T08o OAuth/OIDC transport

- The one active OAuth redirect_uri exact-match probe now routes through the
  invocation executor with scope, request budget, cancellation, and configured
  redirect policy. Passive state/PKCE/token checks and oracle behavior are
  unchanged; standalone context-free use retains compatibility transport.
- Actual loopback control verifies one request and one budget unit. The
  off-scope negative control verifies no request and zero budget use.
- OAuth/inventory/executor/evidence/confirmation/smoke matrix: exit 0,
  **120 tests OK in 15.742s**. Existing smoke socket ResourceWarnings were
  non-failing.
- Inventory reconciliation: 32 sites, **8 target routing gaps**. Concurrent
  coverage-model/CI changes were explicitly left untouched; active S19 was not
  altered and no new live/model/browser/container run was started.

## 2026-09-11 — T08p header-injection transport

- Bounded CRLF query probes now route through the invocation executor with
  scope enforcement, request budget, cancellation, and configured redirect
  policy. The marker-header confirmation oracle and standalone compatibility
  path are unchanged.
- Actual loopback control verifies one request and one budget unit. Off-scope
  negative control verifies no request and zero budget use.
- Header/OAuth/inventory/executor/evidence/confirmation/smoke matrix: exit 0,
  **122 tests OK in 16.899s**. Existing smoke socket ResourceWarnings were
  non-failing.
- Inventory reconciliation: 32 sites, **7 target routing gaps**. Concurrent
  coverage files and active S19 were untouched.

## 2026-09-11 — T08q request-smuggling sampler transport

- The existing ordinary-httpx anomaly sampler now routes through invocation
  scope, mutation authorization, budget, cancellation, and executor policy.
  This does not add raw framing: CL/TE desync remains unqualified and the
  validator continues to emit candidate/not-confirmed only. A framing-capable
  adapter plus paired front-end/back-end fixture is still required for proof.
- Actual loopback control verifies one POST and one budget unit. Denied-mutation
  negative control verifies no request and zero budget use.
- First invocation's full test body passed, but an accidental PowerShell `$?`
  assignment emitted a shell setup error; it is not the canonical result. Clean
  rerun: exit 0, **166 tests OK in 16.982s**. Existing smoke socket warnings were
  non-failing.
- Inventory reconciliation: 32 sites, **6 target routing gaps**. Concurrent
  coverage files and active S19 were untouched.

## 2026-09-11 — T08r recon transport

- Recon's central fetch seam now routes crawl pages, common discovery files,
  and technology fingerprints through invocation scope, request budget,
  cancellation, and redirect policy. Standalone context-free use retains the
  direct compatibility path; recon result semantics are unchanged.
- Actual loopback control verifies one request and one budget unit. Off-scope
  negative control verifies no request and zero budget use.
- Recon/smuggling/inventory/safety/evidence/confirmation/smoke matrix: exit 0,
  **168 tests OK in 17.808s**. Existing smoke socket ResourceWarnings were
  non-failing.
- Inventory reconciliation: 32 sites, **5 target routing gaps**. Concurrent
  coverage files and active S19 were untouched.

## 2026-09-11 — T08s subdomain-takeover transport

- Provider fingerprint fetches now route through the invocation executor.
  Referenced third-party hosts therefore require explicit run scope and obey
  request budget, cancellation, and redirect policy. The provider fingerprint
  list and confirmation oracle are unchanged.
- Actual loopback control verifies one request and one budget unit. Off-scope
  negative control verifies no request and zero budget use.
- Static compilation passed. Takeover/inventory/executor/evidence/confirmation/
  smoke matrix: exit 0, **120 tests OK in 16.396s**. Existing smoke socket
  ResourceWarnings were non-failing.
- Inventory reconciliation: 32 sites, **4 target routing gaps**. Concurrent
  coverage files and active S19 were untouched.
