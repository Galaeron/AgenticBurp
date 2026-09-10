# Current state

The single rolling per-session delta. Stable context (architecture, hazards, environment,
file map) is in [`CLAUDE.md`](CLAUDE.md) — read that first, then this.

**Update this file in place at session end. Do not create a new numbered handover.**
Older session narratives are in git history / `archive/`; this file is deliberately short
(review weakness #18: it had become the archived chain again).

---

## ►► PARALLEL TRACK — Opus, branch `astra-t05-t08` (T05/T06/T08) ◄◄

Branched off `codex/astra-review-fixes` @ `e24ca7f` in worktree
`.worktrees/astra-t05-t08`, so this coverage/issue/transport track and the identity
track below do not collide (reconcile by merge). Treated the identity contracts
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
- **T08 (`e1ac8e9`) — inventory + audit only.** `transport_inventory.py` (32 sites,
  **23 target routing gaps** owned/named) + `test_transport_inventory` (module-granular)
  + `T08_TRANSPORT_INVENTORY.md`. The actual per-site executor migration and per-oracle
  re-qualification remain OPEN (feeds identity F01 role_crawl, F04 cross_identity).
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
- **Verification:** full stdlib discovery after all three tickets — **1,653 tests OK,
  2 skipped**, exit 0 (1,581 baseline + 72 new; zero real failures). No model / browser /
  container / blind-target / live run performed — all hermetic.
- **Still owed:** merge into `WorkingSunday` (reconcile with the identity track's
  orchestrator/run-context edits); a fresh live max-coverage VulnCorp run to move any
  numbers. New live behavior is flag-gated OFF, so live recall is unchanged until enabled.

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
