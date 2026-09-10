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
  `test_transport_inventory` (9) enforces that a new direct httpx site cannot be added
  un-inventoried (`test_scan_matches_registry`) and that each of the **23 target-directed
  routing gaps** is owned+named. Audit doc: `T08_TRANSPORT_INVENTORY.md`.
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
