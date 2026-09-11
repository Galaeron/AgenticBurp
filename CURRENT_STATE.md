# Current state

The single rolling per-session delta. Stable context (architecture, hazards, environment,
file map) is in [`CLAUDE.md`](CLAUDE.md) — read that first, then this.

**Update this file in place at session end. Do not create a new numbered handover.**
Older session narratives are in git history / `archive/`; this file is deliberately short
(review weakness #18: it had become the archived chain again).

---

## ►► PARALLEL TRACK — Opus, branch `astra-wstg-coverage-slice` (WSTG requirement coverage) ◄◄

Branched off `astra-integration`. Adds a **requirement-coverage manifest** kept
deliberately SEPARATE from the per-run `CoverageMatrix`, plus two deterministic
vertical slices. **Not merged.** Commits: `294162c` (scaffold), `1052149` (review
fixes), + a catalog-expansion commit.

- **New modules:** `harness/coverage_manifest.py` (security-requirement ⇄
  regression-test ledger: WSTG/OWASP refs, applicability+rationale, per-aspect
  status, run-bound evidence, `--check` gate) and `harness/coverage_evidence_case.py`
  (`EvidenceCase` records pass/fail/skip THROUGH the runner into a git-ignored,
  run-id-bound `harness/.coverage_runs/<run_id>/`). `coverage_model.Check` gained
  `external_refs` + `is_wstg()`/`reference_label()`.
- **Two slices** (local fixture + REAL validator + evidence, over loopback HTTP):
  mass assignment (`AV-MASSASSIGN-01`, `SequenceValidator`) and open redirect
  (`WSTG-INPV-17`, `OpenRedirectValidator`). Each has 3 labelled aspects:
  patched-fixture invariant, harness confirmation on vulnerable, harness controlled
  negative on patched. Report: 38 requirements, 2 `covered_partial` (6 passing
  aspects), 3 `gap_manual`, 33 `gap_unimplemented` — all gaps flagged.
- **The #0 trap this closes:** a committed passing artifact previously satisfied the
  gate WITHOUT the test running. Now evidence is written fresh per run, bound to the
  commit/run id, and the gate FAILS with no fresh evidence; a failed/skipped run
  records that. Identity/schema/duplicate are validated; every declared automated
  aspect is gated INDEPENDENTLY.
- **WSTG-CONF-09 correction:** it is "Test File Permission" (manual, WSTG v4.2 ref),
  NOT mass assignment — the reviewer's catch. Mass assignment now carries the
  internal id `AV-MASSASSIGN-01` with OWASP-API/Academy `external_refs`.
- **CI (`.github/workflows/ci.yml`):** PR runs the SMOKE SUBSET only (full suite →
  new nightly job — the real per-PR saving); coverage report + evidence uploaded
  with `always()`; the `--check` gate enforces fresh passing evidence.
- **Verify:** `cd harness && python -m unittest test_coverage_manifest
  test_mass_assignment_slice test_open_redirect_slice` then `python
  coverage_manifest.py --check`. Full stdlib discovery: **1,782 OK**, exit 0
  (hermetic; no model/live run). All 8 reviewer findings addressed with regressions.
- **Owed:** merge decision; broaden the catalog with more slices.

---

## ►► PARALLEL TRACK — Opus, branch `astra-t05-t08` (T05/T06/T08) ◄◄

Branched off `codex/astra-review-fixes` @ `e24ca7f` in worktree
`.worktrees/astra-t05-t08`; the identity track through `5f0522a` (F07 run identity,
session/credential isolation, and ownership preservation) is now reconciled here.
Treated the identity contracts
(`evidence.TestCaseRef`/`ProofRecord`/`Verdict`) + case/proof identity (T01
F02/F03/F06) as settled. **Not yet merged into `WorkingSunday`.**

- **Env reconciliation (READ if tests won't run):** the prior env (CPython 3.12 +
  `.review-deps`) was not reproducible — only 3.14 was installed and `.review-deps`
  is cp312. Installed 3.12.10 (`py install 3.12`) + a `typing_extensions==4.16.0`
  scratchpad shim (the bundled one lacks `sentinel` for the newer anyio). Runner:
  `pythoncore-3.12-64\python.exe`, `PYTHONPATH=<shim>;<.review-deps>`, from `harness/`.
  Baseline on `e24ca7f` reconciled to the codex count: **1,581 OK, 2 skipped**.
- **T05/R26 (`fdc50bb`,`e9a9d76`) — DONE.** Concrete per-input/per-state coverage
  case keys aligned to `TestCaseRef` (`coverage_model.CaseKey` + child-case layer +
  aggregation "one confirmed child marks risk, never endpoint completion" + new
  controlled_negative/blocked/inconclusive statuses); `coverage_tracker`
  case-granular driving; `orchestrator._coverage_proof` persists a case-bound proof
  per driven leg. Default-OFF flags `coverage_drive_cases`/`coverage_case_budget`
  gate the new live path (existing coverage semantics unchanged). Per-validator
  PARAMETER attribution left to T08 oracle work.
- **T06 (`04f6d32`) — DONE.** `issues.py`: run-independent stable issue IDs over a
  conservative key (family+method+class+affected-input+read/write boundary), issues
  keep ALL members, redacted `export_issue`/`replay_view`. `store.all_host_findings`
  surfaces method+case coords; `report_generator` uses the issue key + renders issue
  IDs + `export_issues_for_host`. Operator root-cause merge + Burp replay = T10.
- **T08 in progress (`e1ac8e9`, `693b4c8`..`546def9`).** The enforced inventory
  remains 32 sites and is down from **23 to 17 target routing gaps**. Production
  role-matrix, crawler, API-surface, feature-workflow, scope-expansion,
  cross-identity, CSRF, and verb-tamper sends now use invocation-local executor
  sessions. Legacy standalone paths remain compatible. CSRF/verb oracles remain
  observation-only; transport qualification did not promote confirmation claims.
- **Review round (IMPLEMENTATION_REVIEW_T05_T08.md) — all 11 findings addressed**, each
  with a paired regression; reviewer's `review_t05_t08_checks.py` diagnostics all corrected.
  Key fixes: R01 per-input attribution no longer fabricated (leg drives once per cell at
  request level; parameter siblings inconclusive); R02 coverage keys on durable
  `principal_id`; R03 URL/JSON redaction across export+replay; R04 issue id adds host +
  unknown-input disambiguator; R05 errors recorded + budget bounds attempts; R06 error/
  blocked child forbids completion; R07 occurrence encoding `[occ:n]`; R08 findings dedup
  now `(fingerprint,case_id)` so retests persist + export shows full proof history; R09
  verdict by exact proof id; R10 class-keyed invariant + honest artifacts; R11 guard
  reworded module-granular. See EXECUTION_LOG "Review response".
- **Verification:** pre-reconciliation full discovery was **1,671 tests OK, 2 skipped**.
  After merging the identity track through `5f0522a` and binding coverage proofs to its
  invocation-local `RunContext`, the combined focused matrix is **279 tests OK** and full
  stdlib discovery is **1,685 tests OK, 2 skipped**, exit 0, 317.988s. No model / browser /
  container / blind-target / live run performed — all hermetic.
- **Still owed:** merge the reconciled branch into `WorkingSunday`; a fresh live
  max-coverage VulnCorp run to move any
  numbers. New live behavior is flag-gated OFF, so live recall is unchanged until enabled.

- **T07 complete (`ec19ed8`, `cbbc192`, `2b9110a` + final transport controls):** added versioned Workflow/Step/Result
  records; strict prerequisite and placeholder blocking; JSON Pointer, Location, and
  hidden-field extractors; bounded 401 refresh distinct from 403 denial; eager cleanup
  registration and cleanup-after-cancel through the run-scoped executor; declarative
  production wiring in `investigate_engagement`; and an actual-loopback vulnerable/
  patched cross-principal create→approve→independent-read control. Focused T07 caller/
  transport matrix: **102 OK**. Full suite: **1,708 OK, 2 skipped**, 320.729s.
  Skip/repeat/switch variants execute through policy; resume preserves prerequisites;
  failure/cancel cleanup is explicit; actual transport has vulnerable/patched skip,
  exact-two-send repeat, and cross-principal independent-read controls.

- **Pause checkpoint (2026-09-10):** clean focused commits through `546def9`.
  Latest focused gates: role/engagement/investigation **39 OK**; CSRF/verb/context
  **105 OK**; discovery/context **88 OK** plus added actual crawler/surface controls
  **47 OK**; feature workflow **29 OK**; scope/context **30 OK**; inventory **10 OK**.
  The last full suite remains the post-T07 **1,708 OK, 2 skipped** result above;
  no full-suite claim has been made after T08a–f. Resume sequentially at
  `missing_auth_probe.py`, then remaining validator/orchestrator transports.

- **2026-09-11 continuation on `astra-integration`:** T08g–i (`ec450a3`,
  `6d99cd1`, `ddfa95f`) migrate missing-auth anonymous/garbage controls, JWT
  forge/control probes, and rate-limit bursts to invocation-local executor
  sessions. Inventory is now **14 target routing gaps** (from 23 initially).
  Focused final gates: missing-auth/API/context **39 OK**, JWT actual+negative
  controls **6 OK** (broader confirmation matrix **92 OK, 2 skipped**), rate-limit
  matrix **75 OK**, inventory **10 OK** after each slice. The rate-limit oracle
  remains observation-only/provisional.
- **Live S19 status:** `testing/vulncorp-helpdesk/maxrun/` contains the live run.
  Pass 1 completed all **37/37** captured exchanges and wrote the intermediate
  result after **5,946.5s**; Pass 2 `investigate_engagement` is still running as
  of this checkpoint, so `investigate` is null and no final coverage/recall claim
  is reconciled yet. Do not stop or restart its Python/target processes.
- **T08j implemented:** graph TOCTOU authority
  reads and concurrent writes now use the invocation-local gate, bound session,
  request budget, and executor; standalone registry callers retain the legacy
  compatibility path. Real loopback positive and denied-mutation controls pass.
  Corrected focused confirmation/smoke matrix: **108 OK**; inventory is **13**
  target routing gaps. One earlier broad invocation reported 67 tests with one
  loader error because `test_confirmation_routing` does not exist; no product
  failure was hidden, and the corrected named-module run exited 0.
- **T08k implemented:** registry race-condition bursts use invocation-local
  transport. Context is attached to per-dispatch validator copies, preserving
  shared-registry concurrency isolation and the public two-argument registry
  seam. Real loopback session/budget and denied zero-send controls pass. Final
  broader matrix: **155 OK**; inventory is **12** target routing gaps. An initial
  broader run exposed 12 compatibility-seam errors and was corrected before this
  result; no live claim changed.
- **T08l implemented:** SQLMap's Docker/tool-runner path remains unchanged;
  only its direct boolean-differential fallback now uses invocation-bound
  sessions and executor policy. The validator's preflight mutation decision
  also uses the invocation gate. Real loopback identity/budget and denied POST
  zero-send controls pass. Focused matrix: **117 OK**; broader SQLMap,
  safety, evidence, confirmation, and smoke matrix: **187 OK**. Inventory is
  **11** target routing gaps. No live result was inferred from these tests.
- **T08m implemented:** registry CORS probes now use per-dispatch run scope,
  budget, cancellation, redirect policy, and executor routing. Real loopback
  one-send/one-budget and off-scope zero-send controls pass. Focused matrix:
  **77 OK**; broader executor/evidence/confirmation/smoke matrix: **120 OK**.
  Inventory is **10** target routing gaps; CORS oracle semantics were unchanged.
- **T08n implemented:** CSP/clickjacking fresh-header fetches now use the
  per-dispatch executor with run scope, budget, cancellation, and bounded manual
  redirects. Real loopback one-send and off-scope zero-send controls pass. The
  combined CSP/CORS/executor/evidence/confirmation/smoke matrix is **122 OK**;
  inventory is **9** target routing gaps. Header oracle semantics were unchanged.
- **T08o implemented:** OAuth/OIDC redirect-uri exact-match probes now use the
  per-dispatch executor with run scope, budget, cancellation, and redirect
  policy. Real loopback one-send and off-scope zero-send controls pass. Broader
  executor/evidence/confirmation/smoke matrix: **120 OK**. Inventory is **8**
  target routing gaps; passive OAuth checks and oracle semantics are unchanged.
- **T08p implemented:** bounded CRLF/header-injection query probes now use the
  per-dispatch executor with run scope, budget, cancellation, and redirect
  policy. Actual one-send and off-scope zero-send controls pass. Combined
  validator/executor/evidence/confirmation/smoke matrix: **122 OK**. Inventory
  is **7** target routing gaps; the marker-header oracle is unchanged.
- **T08q implemented:** the HTTP-smuggling validator's existing ordinary-HTTP
  anomaly sampler now uses invocation scope, mutation gate, budget, cancellation,
  and executor routing. It remains explicitly **not confirmed** because this is
  not raw-framing transport or paired-proxy proof. Real loopback one-send and
  denied-mutation zero-send controls pass. Clean matrix: **166 OK**; inventory
  is **6** routing gaps. An earlier identical test body passed but its shell
  preamble emitted a read-only-variable error; the clean rerun is canonical.
- **T08r implemented:** recon crawl, common-file, and technology-fingerprint
  fetches now share the per-dispatch run executor, scope, budget, cancellation,
  and redirect policy. Actual loopback one-send and off-scope zero-send controls
  pass. Combined transport/safety/evidence/confirmation/smoke matrix: **168 OK**;
  inventory is **5** routing gaps. Recon result semantics were unchanged.
- **T08s implemented:** subdomain-provider fingerprint fetches now use the
  per-dispatch executor, so referenced third-party hosts must be explicitly in
  run scope and obey budget, cancellation, and redirect policy. Compilation and
  **120 tests OK**; real loopback one-send and off-scope zero-send controls pass.
  Inventory is **4** routing gaps; fingerprint/oracle semantics are unchanged.
- **T08t implemented:** cacheability, unkeyed-header, follow-up, and deceptive-
  path probes now use per-dispatch executor policy. Real loopback one-send and
  off-scope zero-send controls pass; compilation plus **122 tests OK**. The
  validator remains candidate/not-confirmed because it still lacks a distinct
  second-client retrieval proof. Inventory is **3** routing gaps.

---

## ►► SESSION-17 STATE (READ FIRST) ◄◄

**2026-09-10 implementation continuation from `9fdbb11`:** Work continues on
`codex/astra-review-fixes` in an isolated worktree so the occupied
`impl/astra-tickets` worktree and dirty `WorkingSunday` checkout remain untouched.
T01 F02/F06 is complete: legacy `not_confirmed` maps to inconclusive; a controlled
negative requires explicit execution plus a control artifact; artifact-free results
are labelled `legacy/unstructured`. A pre-existing `test_ollama_client` global-httpx
leak was also contained per test so real-transport tests survive full discovery.
Focused verdict/oracle/authorization checks: **37 tests OK**. Ordered transport
isolation regression: **28 tests OK**. Full stdlib discovery: **1,578 tests OK,
2 skipped**, 314.586s.

**T01 F03 complete:** `Finding` now carries originating finding/principal/request/input
coordinates and exact `case_id`/`proof_id` links. `_validate_findings` binds each job,
proof, persistence write, confirmation, and cross-identity downgrade to that concrete
finding; the class-wide assignment was removed. Old proof rows retain their pre-F03
case hash. Focused evidence/engagement/transport checks: **79 tests OK**. Full stdlib
discovery: **1,581 tests OK, 2 skipped**, 314.376s. T01 is now complete against the
reviewed F02/F03/F06 requirements; invocation-local run identity (T03 F07) is next.

**T03 F07 complete:** the server job manifest now owns an invocation-local
`RunContext`, and that immutable run ID is passed into engagement/captured-exchange
analysis and exact proof construction. The singleton lazy run ID was removed.
Configuration is deep-snapshotted, cache namespaces are salted by run ID, request
budgets/cancellation are per context, API cancellation signals the context, and owned
clients close with the job lifecycle. Focused cache/context/proof/manifest/API checks:
**80 tests OK**. Full stdlib discovery: **1,585 tests OK, 2 skipped**, 287.529s.
T03 F04/F05 session and credential isolation is next.

**T03 F04/F05 complete:** graph authorization now registers every principal and an
explicit anonymous session in its invocation context; cross-identity probes no longer
read process-global identities on that path. Unknown session references and credential
headers without a session fail before transport. Credential-bearing sessions require
declared normalized origins; unauthorized initial destinations are blocked, and
cross-origin redirects receive neither session cookies nor retained request bodies.
Focused authorization integration: **73 tests OK**; focused real transport: **18 tests
OK**. Full stdlib discovery: **1,591 tests OK, 2 skipped**, 289.004s. T02 F08–F10
principal metadata and ownership semantics are next.

**T02 F08–F10 complete:** identity re-save uses an additive UPSERT and preserves
tenant, permissions, and trust metadata. Run sessions carry authoritative `Principal`
objects into ownership checks. Object references include run, normalized application
origin, explicit tenant state, path, and the unmodified query selection. Authorized
access is recorded per principal and evaluation continues, so it cannot suppress a
later unauthorized case. Focused principal/ownership/transport/API checks: **84 tests
OK**. Full stdlib discovery: **1,595 tests OK, 2 skipped**, 294.398s. T03 F01
production wiring and transport behavior is next.

**2026-09-10 review-only addendum:** Source inspected at HEAD `8b5c6e1`;
implementation handoff saved to
[`reviews/review-Astra-Medium-10-09-06-30/IMPLEMENTATION_HANDOFF.md`](reviews/review-Astra-Medium-10-09-06-30/IMPLEMENTATION_HANDOFF.md).
It defines T00–T10, beginning with a real-transport authorization proof milestone.
No implementation changes, tests, or live runs were performed for this review;
the suite result below remains the previous session's reported result.

**2026-09-10 T00 implementation:** Added a versioned, redacted run manifest and
append-only lifecycle ledger to the existing investigation job API. Focused suite:
9 tests OK. The missing local `pytest` and `mitmproxy` dependencies were subsequently
installed from their existing pins: the pytest-native plugin suite is 26/26 green and
full stdlib discovery is **1,509 tests OK, 2 skipped**, 272.821s. The optional proxy's
`typing-extensions` metadata conflicts with the bundled Pydantic stack, so verification
uses the bundled core runtime first and appends `.review-deps`; details are in the review
directory's `EXECUTION_LOG.md`. T01–T10 remain open.

Branch `WorkingSunday`, **HEAD `f36d454`** (+ any later doc commit). Suite green
(`cd harness && python -m unittest discover -p "test_*.py"`) — **1505 tests OK**,
~277 s, on the committed tree. `config.yaml` at safe defaults;
`config.local.yaml` untouched; hazard #1 intact.

### What session 17 did — implemented the 2026-09-09 project review

Worked [`reviews/2026-09-09/PROJECT_REVIEW.md`](reviews/2026-09-09/PROJECT_REVIEW.md)
top-to-bottom. That file's **IMPLEMENTATION PROGRESS** section is the authoritative
per-item status + the test that verifies each; this is just the summary.

**Closed, each with an offline test + negative control (all HERMETIC — no fresh live run):**

- **All P0 correctness findings:** R01/R02 (coverage stops inventing executed checks;
  honest counts), R03 (cache key includes identity+subtype), R04 (upload uses the real
  `GatedAsyncClient.request()`), R06 (coverage-driven confirmations enter the finding
  pipeline), R07 (monotonic confirmation — a proof is never downgraded), R08
  (execution-aware suppression — REFUTED needs a real controlled negative), R09 (exact
  leg tiers, no substring inheritance), R10 (reject self-comparison + distinct principal
  ids), R12 (second-order SQLi masks reflected payload), R14 (typed discovery-chain
  routing), R16 (per-finding mutation ceiling enforced).
- **Graph/flow:** R05 (replay captured request templates), R18 (`investigate_engagement`
  exposed as a cancellable job API in `server.py`), R19 (credential-feedback map + merge
  derived state), R20 (chain provenance), R21 (per-case completion), R23 (attempt-budget),
  R25 (browser drives AS the identity), R29 (bounded validation fan-out), R30 (operational
  failures surfaced as `result.errors`/`degraded`).
- **Oracle retirements (Phase 5)** — 8 overconfirming verdicts stood down to
  observations/candidates, detectors kept: passive-deserialization, rate_limit,
  reset_token, csrf, verb_tamper, request_smuggling, web_cache; file_upload tightened.
  csrf/verb_tamper removed from `LIVE_VERIFIED_MARKERS`. **See
  [`ORACLE_RETIREMENTS.md`](ORACLE_RETIREMENTS.md)** — the record of what was stood down
  and how to re-qualify each (search code for `RETIRED (review 2026-09-09)`).
- **Precision:** R11 (BFLA needs a privileged-data match), R13 (authenticated
  second-order plant + distinct-identity read).
- **Weaknesses:** #1 (prompt validator observes injection-shaped evidence instead of
  skipping analysis; hard-block opt-in), #5 (repro field isn't remediation), #6 (recall
  UNKNOWN provenance + best-proof), #7 (CSRF WSTG SESS-05), #9 (sitemap header
  multiplicity), #10 (strict ffuf fallback), #11 (tool container force-remove on timeout),
  #13 (high-signal excerpt beyond truncation), #14 (DAG: skipped-required ≠ satisfied),
  #18 (this file trimmed), #19 (removed fabricated token-savings %).

### The honest frontier — NOT done (needs operator direction, per the review's L-phases)

These are the review's dedicated architecture phases or need a schema/design decision;
they were deliberately **not** rewritten unilaterally:

- **Schema / issue-ID model:** R28 per-finding/case-ID binding (synonym match IS done),
  #4 root-cause dedup.
- **Architecture rebuilds:** R15 (one policy-aware executor / registry-only construction),
  R17 (centralized scope/transport + redirect/credential handling), R24 (stateful
  authenticated workflow engine), R26 (per-parameter coverage matrix), R27
  (principal/tenant/session/ownership model), #3 (per-run isolation of global state),
  #8 (OpenAPI schema-driven request construction), #20 (single operator run→export flow).
- **Tuning:** R22 (broaden agent derivation — affects runtime cost), #12 (session reuse
  across raw clients), #2 (cache manifest — over-invalidation risk).
- **Infra/CI:** #15/#16 (packaging/deps), #17 (scored CI tier + Java/browser gates),
  and the **deletion/consolidation table** (Phase 9 — gated on the rebuilds above).
- **The one measurement still owed:** a fresh live max-coverage VulnCorp run. Everything
  above is hermetic; target-recall numbers are unchanged. Use `testing/vulncorp-helpdesk/maxrun/`,
  a FRESH cache DB, toggles in `config.local.yaml` (never a committed flip).

### Environment

Ollama `qwen3:8b` + Docker (`harness/sqlmap:1.10.9`, `harness/ffuf:2.1.0`),
Playwright/Chromium — as CLAUDE.md § Environment. No host `javac` (Burp panel is
self-review only; the review's fixes are all Python).

### Commit shape

Focused commits on `WorkingSunday`, one finding-group each, suite green at the batch
boundary. Nothing pushed. The pre-existing session-17 discovery-breadth WIP was
snapshotted first (`33031f9`) before the review fixes landed on top.
