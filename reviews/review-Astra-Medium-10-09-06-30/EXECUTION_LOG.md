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
