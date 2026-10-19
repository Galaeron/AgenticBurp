# Remaining implementation plan — 2026-10-17

This is an ordered execution list, not authorization to run live experiments or a
claim that every historical issue still reproduces. Base: `1644dc58` plus the
reviewed working tree. Assessment: ../reviews/2026-10-17-project-assessment/ASSESSMENT.md.

Existing lifecycle, browser-capture integration and catch-all fixes have passing
tests; retain them. Reproduce older backlog diagnoses against current source before
changing code. Preserve unrelated WIP and the existing regression/negative controls.
The historical crAPI no-go remains unresolved until new adjudicated evidence exists.

## Completion rules

- Track **implemented**, **caller-verified**, **live-validated**, and **released**
  separately. A checkbox closes only the acceptance scope named by that ticket.
- Each code change needs a production-caller positive case and a negative control;
  use fault injection where disconnecting the integration is a plausible failure.
- Run smoke, full and orchestrator-precondition from the repository root on the
  completed code batch. Record source identity, commands, exit codes and skips.
- Do not count missing dependencies, skipped tests, helper-only tests or old builds
  as completion. Requirements with missing evidence remain explicitly open.
- Keep committed defaults safe. Live validation uses separately authorized scope
  and ignored local configuration. Never access blind answer keys/implementations.
- Work on isolated, reviewed changes; do not stage or commit unrelated WIP.

## Priority 0 — trustworthy findings and execution boundaries

### [~] I01 — Freeze the candidate and reconcile the trackers
- **Status 2026-10-17:** the candidate is frozen and reproduces precondition, smoke and full
  in isolation; dispositions and canonical owners are recorded in
  [the I01 manifest](I01_CANDIDATE_MANIFEST_2026-10-17.md). The candidate is committed as
  `ba080691` (pushed with PR #1). Of the 18 untracked tests that pass alone, 14 are committed.
  The other four import W-dependent test modules and stay with W2: `test_captured_shapes_passive`,
  `test_data_maintenance`, `test_data_lifecycle_callers` and
  `test_unverified_priority_consistency`. The last two were found by CI and untracked again. Remaining: split W1–W4 into reviewed commits (W2 needs an owner
  decision first).
- **Type:** integration / bookkeeping. **Depends on:** none.
- Inventory tracked and untracked files required by the current fixes. Record a
  complete candidate manifest, including resources, dependencies and test fixtures.
- Reconcile ARCH tracking, LB-2 and stale DET descriptions with current source.
  Split component completion from remaining caller/live acceptance; retain aliases
  and historical evidence. Do not mark the 36 coverage-evidence gaps as 36 absent features.
- **Done:** an isolated candidate reproduces the required suites; every included
  file has a disposition and every open item has one canonical owner/ticket.
- **Maps to:** R01/R28, ARCH follow-ups, backlog status drift.

### [~] I02 — Bind confirmation evidence through storage and exports
- **Status 2026-10-17 — batch B (default history) done:** owner decision: one shared pile per
  site by default, `engagement_id` = optional named pile. Reproduced the audit's defect on
  committed code. The writer stored an empty captured principal in the default pile while the
  reader filtered by the computed one, so a later analysis never saw earlier findings. Fixed in
  `store.persist_findings` (principal always recorded; default-pile fingerprint unchanged).
  `harness/test_default_history_caller.py` drives `analyze()` twice with real storage: same
  identity sees it; another identity, another named pile and a severed reader do not; zero
  target sends. Legacy default-pile rows (empty principal) stay out of prior context, as before.
- **Status 2026-10-19 — batch A (proof binding through storage/export) done:** implemented +
  caller-verified (commits `8edf5a9`, `04b3dea`). Class binding already held at the decision
  seam: claim B, reached only through the agent fallback, never borrowed claim A's sqli proof,
  confidence or confirmation on the API, stored rows, issue export, SARIF or Markdown.
  Reproduced defect: after a restart, a confirmed row whose proof was deleted, stale (verdict no
  longer confirmed), unresolvable or re-pointed to another case still exported as confirmed.
  `store.all_host_findings` now resolves the (proof_id, case_id) pair against confirmed proof
  records; an unresolved row is downgraded and marked `proof_status: unavailable`, and
  pointer-only issue references are marked unavailable rather than counted as proof.
  `harness/test_proof_binding_storage_export.py` drives `analyze()` with real SQLite storage
  (7 tests). Disabling the extracted `_fallback_result_binds` seam or the verdict filter is
  detected. Batch C (non-finding observations) remains open.
- **Type:** implementation if reproduced + integration verification. **Depends on:** I01.
- Trace original finding identity/class, validator result, proof/case reference,
  stored finding and API/Markdown/SARIF output. Define explicit supported class
  equivalences rather than treating a routing token as universal evidence.
- Exercise actual persistence and export paths, without mocking the proof store
  or the relevant confirmation decision. Check siblings sharing an exchange.
- **Done:** matching evidence confirms the intended claim; claim-A evidence cannot
  confirm claim B or borrow its proof; missing/stale/unresolvable evidence cannot
  restore confirmation after restart/export. A guard-removal control is detected.
- **Maps to:** false-confirmation follow-up, R15, confirmation/evidence gates.

### [~] I03 — Verify budget, cancellation and TLS at actual engagement callers
- **Status 2026-10-17:** implemented + caller-verified (commit `2a883761`, local); awaiting the
  owner approved (2026-10-17), including two writes for the second-order SQLi pair.
  Caller-verified by `harness/test_engagement_transport_callers.py`.
  The tests found and fixed real bypasses: header-audit, XSS, sequence and mass-assignment
  legs sent outside the run (budget, TLS), and the browser ignored run cancellation. See
  `docs/ARCH_RECONCILIATION_TRACKING.md`. Open: plain-client validators outside these call
  sites are I05.
- **Type:** integration verification; fix only demonstrated bypasses. **Depends on:** I01.
- Drive `investigate_engagement` into its iterative probe and second-order plant/read
  closures using owned fixtures, instead of calling their transport helpers alone.
- Assert shared budget/count, scope, cancellation, case references and TLS policy.
  Include concurrent admission and cancellation between plant and read.
- **Done:** exhausted budget/cancelled/out-of-scope/gate-denied cases send nothing;
  allowed traffic increments the owning count; invalid certificates are rejected
  under normal trust; removing context forwarding makes a test fail.
- **Maps to:** ARCH-1/ARCH-2, SC-7/R7, request-accounting acceptance.

### [~] I04 — Resolve the reported non-browser CSRF replay branch
- **Status 2026-10-17:** reproduced (a reflecting endpoint confirmed at 0.95) and retired (commit
  `fe9b8f3`), owner approved with a request for operator guidance. Production callers do not
  enable the LB-5 PoC, so real-target CSRF is manual-verification only. Unconfirmed
  cookie-authenticated candidates now show as low-severity "NEEDS MANUAL CHECK" items with
  copy-ready steps and a test form (analyze caller test). Validator-level controls and a fault
  injection restoring the retired decision are in `harness/test_csrf_reflection_control.py`.
  Open: caller -> storage -> export label check (with I02).
- **Type:** reproduce historical issue, then correct or close with evidence.
  **Depends on:** I01; coordinate confirmation expectations with I02.
- Inspect the current WIP branch named by LB-CSRF-REPLAY. Use a benign reflecting
  fixture to establish whether it still falsely confirms or changes flag-off behavior.
- If reproduced, retire the unsound confirmation path, or restrict it to its
  explicitly supported semantics with independent state evidence. Manually attaching
  a cookie and observing reflected input must not prove browser-deliverable CSRF.
- **Done:** default-off behavior stays passive; reflection-only control never
  confirms; any retained confirmation has independent state/readback and browser
  credential-delivery evidence appropriate to the claim, through the real caller.
- **Maps to:** LB-CSRF-REPLAY. Treat as a release blocker until dispositioned.

### [~] I05 — Close remaining network and external-tool containment gaps
- **Status 2026-10-19 — batch A (sends escaping their run) done:** implemented +
  caller-verified (commit `2ba91da`, local; push awaits owner review per the guide).
  Reproduced and fixed three escapes:
  - the coverage drive's unbound registry sqlmap preflight (opt-in `coverage_drive_legs`);
  - auto-escalation's credential probe and re-crawl outside `analyze()`'s run (opt-in
    `auto_escalate`);
  - `api_security`'s raw-client limit probe.

  Guards: an unbound validator, or `transport_for(None)`, inside an entered run now uses
  that run. `harness/test_run_escape_callers.py` (14 tests) includes two fault injections.
  **Owner decision open:** a standalone `analyze()` creates its run but never enters it, so
  gated validators there do not spend `analyze.max_requests`. Entering it would turn on TLS
  verification for those sends. Next: batch B (redirect/rebinding destination policy),
  C (external-process lifecycle), D (browser credential isolation), plus the no-run routes
  `/crawl`, `/crawl-roles` and `/engagement/{host}/advance`.
- **Type:** implementation + isolated environment proof. **Depends on:** I01/I03.
- Reconcile connect-time address pinning with redirect handling and approved
  destination policy. Verify browser credential isolation across two origins.
- Route supported external tools through bounded execution with time/process/output
  limits, cancellation, credential handling and recorded request accounting or an
  explicitly independent counter. Keep unsupported unaccountable paths disabled.
- **Done:** controlled rebinding/redirect/cross-origin cases cannot escape scope or
  leak credentials; cancelled/timed-out tool execution leaves no owned process or
  network activity; evidence identifies the actual enforcement boundary.
- **Maps to:** P1-10/NC-O2, PR-10/NC-O3, PR-11/NC-O1/SC-9.

## Priority 1 — reach real application traffic without inventing coverage

### [ ] I06 — Extend SPA discovery to declared authenticated workflows
- **Type:** implementation. **Depends on:** I03/I05 for live acceptance.
- Add bounded, operator-declared page/interaction sequences to the existing browser
  adapter. Reuse supplied sessions; preserve principal/tenant attribution and report
  session expiry rather than silently treating a login page as application coverage.
- Apply run limits to navigation, subresources and interactions. Report which steps
  ran, were blocked, timed out or were never attempted. Keep arbitrary exploration off.
- **Done:** an API reached only after a benign fixture interaction enters the worklist;
  the page-load-only control misses it; expired/wrong identity, cancellation and
  exhausted budget cannot produce successful coverage or cross-role attribution.
- **Maps to:** LB-2 remaining SPA scope, R22 integration follow-up.

### [ ] I07 — Complete captured request-shape integration
- **Type:** implementation if needed + caller verification. **Depends on:** I02/I06.
- Preserve JSON, XML, multipart boundaries/content and query/body distinctions from
  capture through templates and supported validators. Handle binary/oversized bodies
  explicitly; do not silently truncate them into apparently replayable requests.
- **Done:** owned benign shape fixtures reach the intended caller with the correct
  method/body/content type; unsupported or incomplete captures are marked untested;
  negative controls prevent a generic synthesized request from counting as success.
  Complete the originally deferred multipart acceptance or keep it explicitly open.
- **Maps to:** LB-2 XML/multipart acceptance; captured-data contracts.

### [ ] I08 — Harden and measure catch-all discrimination
- **Type:** implementation as demonstrated by fixtures + measurement. **Depends on:** I03.
- Extend fixtures to root/nested fallbacks, HTML shells, redirects, auth walls and
  bodies with varying IDs/timestamps. Include genuine routes beneath the same prefix.
- Preserve an inconclusive outcome where existence cannot be distinguished. Make
  calibration cost, suppression and budget-limited coverage visible to operators.
- **Done:** known fake routes do not enter the worklist or trigger repeated expansion;
  distinct genuine references survive. Measure false admissions AND missed genuine
  routes. All calibration spends budget; budget exhaustion is not complete coverage.
- **Maps to:** reported /health explosion and current wildcard limitations.

### [~] I09 — Close deterministic SQLi/JWT caller acceptance gaps
- **Status 2026-10-17:** caller evidence committed (`d5802ec`,
  `harness/test_det_shape_dispatch_callers.py`): body-only SQLi and cookie-JWT dispatch with no
  label, negative controls, and a fault injection that removes both precondition routes. Not
  closed: depends on I02/I07; the W4 label-normalization review is outstanding; DET-JWT-SCOPE is open.
- **Type:** verification first; avoid duplicating existing preconditions.
  **Depends on:** I02/I07.
- DET-SQLI-POST: prove a body-only captured request reaches the correct validator
  caller with the intended parameter location, without relying on a model label.
- DET-JWT-DETECT: specify supported header/cookie and method cases, then prove the
  real dispatcher reaches the intended leg. Source already has JWT-driven GET and
  body-aware injection scheduling; re-file only uncovered cases.
- **Done:** positive caller cases dispatch correctly; empty-body/non-JWT controls
  do not; disabling the precondition or losing the request shape fails the test.
- **Maps to:** DET-SQLI-POST, DET-JWT-DETECT.

### [ ] I10 — Distinguish genuine findings from same-class secure controls
- **Type:** evidence/oracle correction guided by failing cases. **Depends on:** I02/I09.
- Build paired vulnerable/fixed synthetic cases for the classes already identified
  by BM-2. Separate applicability, attempt, inconclusive, refuted and confirmed states.
- Bind each control to the exact case and principal. A failed control cannot count
  as a successful negative result; raising model confidence thresholds is insufficient.
- **Done:** fixed twins never confirm; genuine twins still confirm with appropriate
  evidence; transport/control failures remain inconclusive through persistence/export.
- **Maps to:** BM-2; residual precision and confirmation soundness.

## Priority 2 — reproducible verification and measured efficacy

### [~] I11 — Remove test flakiness and reconcile requirement evidence
- **Status 2026-10-17:** LB-FLAKE closed (fixed clock committed; controls added). The audit
  logger file-handle leak is fixed. The 36 gaps are classified in
  `docs/COVERAGE_GAP_CLASSIFICATION_2026-10-17.md`. Remaining: wire evidence for the 14
  caller-tested requirements, and trace the 3 unclosed loopback sockets.
- **Type:** verification infrastructure. **Depends on:** I01; can start alongside I02.
- Reproduce LB-FLAKE and reconcile it with the existing deterministic report-clock
  work before changing it. Inject a fixed clock; retain a content-change negative control.
- Investigate the full-run socket ResourceWarning with resource ownership evidence.
- Classify all 36 coverage gaps: missing implementation, missing caller evidence,
  manual prerequisite or residual scope. Add exact runnable test IDs where justified.
- **Done:** time-boundary tests are deterministic; owned fixture resources close;
  the coverage report accurately exposes unresolved requirements. Do not weaken
  assertions or redefine missing evidence as covered to obtain green output.
- **Maps to:** LB-FLAKE/R18, test-resource warning, coverage manifest.

### [ ] I12 — Freeze the efficacy protocol and independent measurements
- **Type:** offline tooling + evaluation specification. **Depends on:** I01/I02/I03/I11.
- Reconcile the maintained runner with remaining P1-3 work. Record source/config/model
  identities, capture provenance, target state, seeds, cache state and stage health.
- Add independent request counts at the authorized target/proxy boundary; account
  separately for browser assets, discovery, validation, model usage and retries.
- Freeze denominators, adjudication rules, negative controls and decision thresholds
  before runs. Retain the existing rule that any false confirmation is a no-go.
- **Done:** synthetic accounting detects dropped/double-counted requests, incomplete
  runs and missing evidence; reports cannot equate repeated cases with independent
  cases or hide unreachable endpoints. Historical results remain clearly labelled.
- **Maps to:** P1-3, Part B prerequisites, PR-13, R08/R17.

### [ ] I13 — Execute Part B and adjudicate current efficacy
- **Type:** live validation, not an offline implementation ticket.
  **Depends on:** I02–I10 as applicable to declared scope, I12 and usable lab services.
- Supply authorized scope, frozen target state, working model service, declared
  identities and an adjudicator. For DET-SSRF, establish collaborator reachability
  independently; missing callbacks alone do not refute a vulnerability.
- Run matched-budget, fresh-cache repeats. Compare previous/candidate behavior only
  where target, corpus and configuration permit a valid comparison. Retain secure controls.
- **Done:** publish adjudicated findings, false confirmations, precision/recall with
  denominators, discovery coverage, request/time cost and incomplete stages. Apply
  the predeclared stop/go rules; file concrete failures before expanding capability.
- **Maps to:** Part B, DET-SSRF, NC-O4/PR-13 live scope, BM-3 measurement.

### [ ] I14 — Establish generalization, model value and analyst efficiency
- **Type:** study inputs + measurement. **Depends on:** I12/I13; installed-candidate
  analyst work also requires I15/I16.
- Obtain independently annotated, sanitized cases beyond the development fixtures.
  Keep answer keys with an independent custodian and report contamination exclusions.
- Run planned model/architecture ablations with matched budgets. Measure tokens,
  latency and analyst correction/reporting time against defined baselines; preserve
  quality tolerances when considering optimization/default changes.
- **Done:** report results by application/context and uncertainty; no superiority,
  general recall or cost-saving claim rests on a single target or repeated same cases.
- **Maps to:** PR-D/NC-O4, PR-B, PR-E, R21/R25, BM-3.

## Priority 3 — reproducible release and operator workflow

### [ ] I15 — Build and verify the intact release outside the checkout
- **Type:** packaging / build; independent work can start after I01.
- Build the complete wheel and Java artifact from a recorded candidate; test clean
  installation/import/startup/resources outside the repository. Verify installed
  source provenance and explicit startup/authentication failure behavior.
- Recheck the historical security-product detection through the package/security
  owner if still present. Do not disable protection or omit source to force a pass.
- Pin supported dependencies/tool images, produce an SBOM and document the tested
  runtime matrix. Run actual Java tests and `gradle shadowJar` with a JDK.
- **Done:** package/JAR hashes, dependency identity and commands reproduce the intact
  candidate; unsupported configurations fail clearly; install/upgrade/rollback work.
- **Maps to:** SC-6/SC-14, P3-2, PR-C/NC-O5, R15 installed proof/R19.

### [ ] I16 — Validate Burp pairing, evidence presentation and documentation
- **Type:** integration / UI / operator verification. **Depends on:** I02/I15.
- Verify actual Burp capture → API → analysis → evidence → export with returned
  engagement identities. Exercise wrong/rotated tokens, origin changes, restart,
  cancellation, degraded model service and stale findings.
- Finish the remaining Burp reproduction-recipe presentation; verify API/Markdown/
  SARIF parity rather than rebuilding already-completed export plumbing.
- **Done:** a new operator completes the documented workflow on the supported
  candidate; uncertain/unconfirmed findings stay labelled correctly; release notes
  state actual limitations and compatible versions.
- **Maps to:** P1-5/P2-3, PR-A/NC-O5, R02 live pairing/R20.

### [ ] I17 — Adjudicate release readiness
- **Type:** release decision. **Depends on:** applicable I01–I16 acceptance.
- Publish the exact candidate, included/deferred tickets, test/evaluation artifacts,
  known limitations, installation and rollback instructions.
- **Done:** each release gate has evidence or an explicit unresolved blocker; the
  claimed deployment/use context matches the evidence. A technical test pass alone
  cannot overturn failed efficacy or operator gates.
- **Maps to:** R28 and Priority-5 release adjudication.

## Explicitly deferred work and duplicate aliases

These stay visible without blocking the bounded fixes or safe-proof evaluation:

| Existing item | Disposition |
|---|---|
| BM-1 | Superseded by FR-4; do not implement a duplicate gate. Remaining same-class precision goes to I10. |
| ER-3 / ER-5 | Already deprioritized. Reconsider only after I14 shows an evidence-backed need. |
| P3-3 team mode | Separate product scope after single-user trust/release acceptance. |
| SC-10 new ToolAdapter | Do necessary containment in I05; defer adding adapters until measured value justifies them. |
| LB-6 objective completion | Optional benchmark-oracle wiring, not required for safe-proof efficacy. If retained, preserve explicit unattempted states and bounded non-destructive fixture acceptance. |
| LB-7 race dispatch | Separate capability expansion; not required to close the assessed discovery/trust defects. |

All 31 unchecked and four partial backlog headings map to I01–I17 or the explicit
deferrals above. The five externally blocked register items map to I02/I15 (R15),
I15 (R19), I16 (R20), I14 (R21/R25); R28 maps to I17. These are dependencies and
acceptance scopes, not claims that the blockers have been removed.

## Recommended execution order

Start I01, then I02/I03/I04 and I11. Complete I05 before claiming live containment.
Proceed through I06–I10, while preparing I12 and the I15 packaging work independently.
Run I13 only when its acceptance prerequisites and authorized environment exist.
Use I14 to justify subsequent model/architecture/performance changes. Finish I16
and make the scoped release decision in I17. No new agents, validators or competitor
features are needed merely to begin this sequence.
