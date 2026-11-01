# AgenticVibe reconciled remediation loop

Prepared 2026-10-05. This is an executable work brief for a coding agent, not a claim that any issue is fixed. Companion: `docs/RECONCILED_REMEDIATION_REGISTER.json`. Review evidence: `reviews/2026-10-05-independent-audit/` and `reviews/2026-10-05-comprehensive-review/`. Read individual evidence sections when a ticket needs them; do not load both entire reports on every iteration.

## Prompt to give the coding agent

> Read AGENTS.md, CURRENT_STATE.md, docs/RECONCILED_REMEDIATION_LOOP.md and docs/RECONCILED_REMEDIATION_REGISTER.json. Execute this reconciled loop until every item has an evidence-backed disposition. Implement the accepted defensive, reliability, privacy, packaging, passive-analysis and reporting fixes. Verify disputed claims before choosing changes. Preserve existing WIP and runtime artifacts, keep safe defaults, and do not expand active testing or offensive automation. Work through dependency-ready tickets without stopping at a plan. Use benign synthetic inputs and captured-traffic evaluation. Record exact commands, interpreter/build identities, failures, skips, controls and artifact hashes. Update the register and concise CURRENT_STATE after each completed batch. Never equate a mocked pass, skipped check, unmeasured optimization or unavailable owner study with completion. Continue independent work when a check is blocked. End with outstanding blockers, concrete prerequisites, release-gate results and links to evidence. Do not publish, push, merge, or discard existing work without explicit authorization.

The requested outcome is **all issues accounted for and all accepted in-scope defects fixed and verified**. A blanket promise to fix every original recommendation would preserve contradictory diagnoses and unsupported assumptions. A rejected claim needs a counterexample/source trace; an optional improvement needs evaluation and disposition; an unavailable verification remains open/blocked. Neither rejection nor blocking counts as a verified fix.

## Binding boundaries and current uncertainty

1. Follow AGENTS.md safeguards. Never read answer-key files or blind-target implementations. Keep active, mutating, cloud, capture and autonomous features default OFF where they currently ship OFF. Never stage local configuration, credentials, captured traffic or runtime DBs.
2. This loop strengthens containment, accounting and analyst-facing passive behavior. It does not add validators, payloads, tool execution, automated target exploration, attack chaining, exploit reproduction, or automatic replay/resume. Existing active behavior must not be broadened to satisfy a performance metric.
3. Use fake providers, transport spies that never send, benign ordinary-response fixtures, synthetic credentials and sanitized captured inputs. Browser work here is limited to documenting/testing existing captured-request contracts with benign inputs; do not implement a new autonomous crawler/capture workflow.
4. Inspect test bodies and runners before execution. Broad smoke/full contain active confirmation fixtures. Preserve their coverage, but do not execute prohibited portions or call a reduced selection the full suite. Run permitted portions; record the full gate as blocked unless an appropriate separate verification context supplies trustworthy evidence. Repository requirements for full before claiming a green suite remain binding.
5. Discover the actual interpreter and provisioned tools. Distinct reviews used different environments, and one supplied only summary test claims. Record absolute executable path, version, dependency identity and raw sanitized logs. Do not claim all tools are absent because PATH misses them. Use project-isolated provisioning when permitted; no global installs, host sqlmap, service restarts or unrelated-run disruption.
6. Source drift was observed during review. Initial HEAD was bca3ff3c, but WIP changed while hashes were checked. Re-establish the present baseline. Existing source references are pointers, not an immutable current snapshot.
7. Do not sweep the WIP into a commit. Routine ticket-local fixes are authorized by this handoff; taking ownership of unrelated WIP is not. Prepare a dependency/source inclusion manifest and a candidate release without overwriting the shared checkout. Only make local focused commits when ownership is established; include Co-Authored-By. No push/merge/publish authorization is implied.
8. Previous LB/SC queues are context, not instructions to continue offensive capability work. This reliability/remediation queue is the task being executed. Preserve unrelated unfinished work and note conflicts.

## Iteration protocol

1. **Select:** choose the highest-priority dependency-ready item. Read its source locations and existing caller tests. Check current hashes against the baseline; inspect concurrent edits before touching their files. Work on one behavioral contract at a time.
2. **Characterize:** restate observed condition, affected caller, evidence status and current expected behavior. For disputed claims, produce a benign counterexample or mark insufficient evidence. Identify what must remain preserved.
3. **Plan a small patch:** define touched files, migration/compatibility effects, one positive caller control, one negative control and failure-path checks where relevant. Avoid tests that merely mirror implementation. Name the metric/denominator for measurement items.
4. **Implement:** make the smallest coherent patch. Prefer explicit data/ownership contracts over global mutable state. No speculative architecture rewrite or unexplained default flip.
5. **Verify:** execute targeted permitted caller tests and inspect their assertions. If they fail, fix the defect rather than weakening the test. Run permitted broader checks once new evidence justifies them. Record blocked gates separately; do not stub missing dependencies to manufacture green.
6. **Challenge:** check that the real caller reaches the change; ensure negative controls would fail if the fix were disabled. Distinguish artifact presence from content integrity, confidence from probability, and process completion from coverage/effectiveness.
7. **Record:** append an iteration evidence entry, update the register, and overwrite bounded CURRENT_STATE with current branch/content identity, commands/results/skips, remaining work and pointers. Do not alter historical audit verdicts to pretend they describe the new build.
8. **Continue:** proceed to the next ready item. If blocked, state the minimal prerequisite and work another ticket. If all remaining tickets require external facts/owner studies, report them explicitly; do not loop repeatedly over unchanged blockers.

Each iteration artifact includes: ticket; source aliases; baseline HEAD/content hash; patch paths/hashes; observation; decision; positive/negative caller controls; command and executable; start/end/duration/exit; test assertions exercised and skips; artifacts; regression risk; remaining limitation. Keep secrets out of both logs and manifests. Store new evidence in a unique `reviews/<date>-reconciled-remediation/<run-id>/` directory using exclusive creation.

Behavior-changing fixes require meaningful caller-level regression and negative controls. Documentation-only corrections use source/link/workflow verification; do not manufacture unit tests that mirror prose. A full-suite count is not a fixed target: report actual assertions collected, failures, skips and selection. Do not require exactly 3,425 tests or treat increased counts as effectiveness.

## Corrections to the other proposed coding prompt

The other RECONCILED_WORK_LOOP.md was inspected as a proposal. Retain its focused changes, caller controls, safe-default discipline, no-push rule and bounded state updates. Replace the following prescriptions:

- Establish content/WIP baseline first, not Phase 4. Selecting only named files does not separate pre-existing edits in those same files; inspect hunks and ownership before any staging.
- Do not implement `self._effort_budget = budget` on a shared AgentManager. Overlapping runs can overwrite it. Carry explicit run-owned context through actual existing methods; `run_agents`/`budget.can_spend` in the proposal are not verified API names.
- Do not replace scope checks with raw netloc membership. Use a shared normalized policy contract that handles scheme/default ports/IPv6/userinfo/malformed input and preserves restrictions. Existing parser and caller behavior must be reconciled first.
- Do not force num_ctx=8192, family routing or curated fail-open merely because the proposal supplies performance numbers. R08/R21 require measurements and quality controls before changing supported passive defaults.
- Resolve the actual Java file: `burp-extension/src/main/java/com/harness/llm/HarnessClient.java`; the proposed extra `client/` directory was not the audited path. Relative working-directory token searches are fragile; pairing must bind the intended service and avoid leaking credentials.
- Sensitive-read authentication is not fixed by documenting how to enable a default-disabled safeguard. State the supported deployment's authenticated-read policy, implement it, and test all sensitive routes and client compatibility.
- SQLite transaction context does not close a connection. Preserve both transaction semantics and explicit lifetime management; do not wrap all store calls blindly when many already close in finally.
- The report clock is a timezone-aware datetime contract and rendering is minute-granular in the inspected source. Do not pass a timestamp string where datetime is expected or claim a second-boundary cause without checking the formatter.
- A configurable TLS flag defaulting false alone does not resolve the professional-deployment trust limitation. R06 must provide a supported trust policy and observable explicit exceptions, not refer to nonexistent context fields.
- No-leg severity policy needs caller/export/UI consistency and passive-observation controls; a single conditional snippet is insufficient verification.
- Full suites contain active fixture confirmation. Preserve the full-before-green requirement and coverage, but do not interpret a broad runner as permission to execute prohibited reproduction. Missing authorized verification means blocked release/commit gate, with patches and permitted evidence still reviewable.
- Commit trailers must identify actual contributors; do not attribute work to Antigravity merely because a template names it. No push/merge/publish authorization is implied.
- Account for omitted recovery, cancellation/degraded states, cache/session isolation, retention/deletion, scorer correctness, dedup/retest verification, reports, modern-app contracts, effectiveness and competitive-claim work through the complete register below.

### Register states

`todo` -> `investigating` -> `in_progress` -> `verification_pending` -> `fixed_verified`.

Alternative evidence-backed states: `not_reproduced_with_evidence`, `already_satisfied_verified`, `optional_evaluated`, `blocked_external`. `not_reproduced` is not proof of absence. `blocked_external` always includes prerequisite/owner and preserves an open release gate. A source-supported implementation may be recorded as progress but cannot become `fixed_verified` without required caller checks. Populate evidence records, not just a status string.

## Coverage crosswalk: no source finding disappears

| Original findings / concern | Reconciled ticket(s) | Disposition rule |
|---|---|---|
| REL-01 / REPRO-01 | R00, R01, R28 | Stable content identity and reproducible candidate release; intentional WIP is preserved |
| INT-01 / ARCH-01 | R02 | Default pairing gap; shared environment bearer already exists |
| ARCH-02 / EF-04; zero-egress/NDA claims | R03, R14, R20 | Auth/redaction/data-boundary fixes; no blanket compliance assurance |
| SEC-01 / XR-01 | R04 | Unify scope semantics; literal localhost-to-IP equivalence claim rejected |
| ARCH-05 | R05 | Captured-only mode and explicit constraints; method alone does not prove harmlessness |
| ARCH-06 | R06 | Explicit certificate trust policy |
| EF-01 / EF-02 | R07, R08 | Dispatch budget and complete usage accounting |
| RES-01 / XR-03 | R09 | Explicit connection closing; verify each store path; no invented corruption claim |
| ARCH-03 | R10 | Atomic state updates and engagement partitioning |
| ARCH-04 | R11 | Durable interrupted status; no automatic offensive resume |
| Failure/cancellation/throttle/partial-state assurance gaps | R12 | Benign fault tests and honest visible outcomes |
| Cache isolation/invalidation gaps | R13 | Context-specific reuse; failure/proof contamination prevention |
| Retention/redaction/deletion/ACL/backup gaps | R14 | Explicit supported data lifecycle and tests |
| REPRO-02 | R15 | Content/dirty provenance beyond HEAD |
| VAL-01 / XR-02 | R16 | Consistent unverified priority; preserve valid passive observations |
| EF-03 | R17 | Correctness versus execution eligibility; wrong-class denominator |
| TEST-01 / LB-FLAKE | R18 | Inject clock; preserve substantive equality controls |
| BLD-01 / DX-01 / clean wheel and CI gaps | R19, R20, R28 | Actual build/install verification, not environment assumptions |
| PERF-01 / TOK-01 / TF-01 / TF-02 / TF-03 | R08, R21 | Passive-only measurement-first optimization; no presumed savings/default change |
| CMP-01 / modern-app coverage gaps | R22, R25 | Existing captured traffic contracts and coverage evidence, no new autonomous exploration |
| DED-01 | R23 | Existing stable issue/retest implementation must be traced before alleging absence |
| EXP-01 | R24 | Core export parity; PDF/DOCX are optional delivery formats, not universal blockers |
| EF-05 / practitioner productivity/model quality unknowns | R25 | Blinded passive evaluation with denominators and analyst time |
| C-01 / competitor errors | R26 | Exactly eight direct primary-source entries, vendor claims labeled |
| Cross-mixin coupling / implicit ownership | R27 | Targeted boundary clarification, no speculative rewrite |
| Missing raw logs / conflicting counts / readiness gates | R00, R28 | New artifact-backed verification; historical summaries stay historical |

## Ordered implementation queue

Effort ranges are planning estimates, not promises. Dependencies refer to this queue. Same-wave tickets may be worked sequentially by one agent; no multi-agent execution is required. Optional study outcomes can remain blocked on participants/model hardware, but cannot be silently marked done.

### R00 — Establish a trustworthy, non-destructive baseline

Priority P0; dependencies none; estimate 1–2 days. Read current git state, staged paths, dependency manifests and tool identities. Hash relevant source/config files without reading secret values. Inspect safe-default changes and ongoing file drift. Inventory reported tests and inspect runners. Create the register baseline and evidence directory. No cleanup/stash/reset.

Acceptance: exact branch/HEAD/upstream/local base, content identifier, changed/untracked production dependencies, absolute runtime/build paths and prerequisite list. Different interpreter runs remain distinct. Record which tests are safe to run. Concurrent edits trigger reinspection, not automatic reversion. Missing environment remains separate from product defect.

### R01 — Reproducible candidate release and WIP ownership

Priority P0; dependencies R00; estimate 2–5 days. Sources: orchestrator_chain.py imports, validators/registry.py, package manifests. Establish intended source closure and distinguish existing WIP from ticket patches. Prepare an isolated candidate source snapshot/build manifest containing needed modules; do not omit modified callers or sweep unrelated capture artifacts into it. Identify included pre-existing code for owner review.

Acceptance: candidate snapshot has complete imports and the same intended passive contracts without hidden checkout paths; every included source is identified; excluded work preserved. Fresh candidate install/caller/build evidence comes through R19/R28. Preparing a snapshot does not authorize publishing it or implementing its active capabilities.

### R02 — Authenticated Java/Python pairing and usable error reporting

Priority P0; dependencies R00; estimate 2–4 days. Sources: server.py:116,238–330; Java HarnessClient token setup/setter/request creation. Choose a documented token entry/pairing flow that also supports the existing explicit environment bearer. Avoid unconditional arbitrary-file token discovery, raw token display/logging, weakened mutation auth or insecure remote pairing.

Acceptance: real Java client -> benign passive /analyze -> stored result/read works with a configured token; wrong/missing token denied; server restart/stale credential gives clear reconnect error; sensitive reads work under R03. Tests use a fake inference provider and no target sends. Java compilation is separately required in R19; no claim of UI success from a Python mock alone.

### R03 — Sensitive-read authorization and shared inference redaction

Priority P0; dependencies R02; estimate 3–6 days. Sources: server.py read-auth helper; coordinator.py prompt construction; agents/base_agent.py; critique/provider adapters. Enumerate sensitive routes and every inference boundary. Introduce one sanitization contract for URL, headers, nested bodies, context and provider diagnostics, preserving security-relevant nonsecret structure. Inventory all outbound dependencies.

Acceptance: synthetic unauthorized reads rejected, authorized caller succeeds; fake secret sentinels absent from every provider prompt, error/log and export; cloud remains opt-in; fake egress recorder documents an offline/passive configuration. Local inference is described separately from no-egress. No secrets/override values exposed in evidence. Legacy access changes include migration notes.

### R04 — One scope contract that preserves restrictions

Priority P0; dependencies R00; estimate 2–4 days. Sources: run_context.py ScopePolicy/HostAllowScope/RunContext.create; scope_discovery.py; safety_gate.py; caller policy wiring. Resolve host, origin, scheme, port, subdomain and empty-list semantics. Existing parser already supports explicit ports; fix inconsistency rather than creating a second parser. Preserve or tighten authorization; never silently widen an explicit restriction. Do not claim a hostname alias is automatically authorized.

Acceptance: common table of synthetic URLs agrees across scope/gate/caller adapters; different host/scheme/port denied under explicit constraints; empty/malformed active scope fails closed. Redirect evaluation uses a no-send transport spy and shows every hop is checked. This is a policy hardening ticket, not a target-probing exercise.

### R05 — Captured-only operation and endpoint constraint semantics

Priority P0; dependencies R04; estimate 2–4 days. Sources: safety_gate.py method classification; run_context.py authorization; server/capture admission paths. Make captured-only passive operation explicit; distinguish analysis of supplied data from fetching. Validate documented exclusions even for nominally safe methods. No generic method-based no-side-effect claim.

Acceptance: benign captured analysis invokes zero target transports; disabled active/capture features stay disabled; synthetic disallowed endpoint decisions deny before I/O; UI/status explains blocked versus untested. Preserve regression coverage and do not weaken policy to avoid test failures.

### R06 — HTTPS trust policy

Priority P1; dependencies R04; estimate 1–3 days. Sources: run_context.py session/default client creation using verify=False. Introduce documented CA/trust settings with explicit isolated-fixture exceptions and run provenance. Accommodate supported local proxy certificates without silently disabling verification.

Acceptance: benign trusted/untrusted certificate controls under the declared profile; both client types use the same trust policy; exceptions are operator-visible and do not leak credentials. Use fake TLS/provider fixtures, no real targets.

### R07 — Run-owned inference budget propagation

Priority P0; dependencies R00; estimate 2–4 days. Sources: analysis_pipeline.py:347; agent_manager.py dispatch argument/getattr paths; agents/base_agent.py metered branch; effort.py. Propagate explicit run-owned accounting through passive specialist/family dispatch. Make reservation versus measured usage explicit and reconcile reservations after success/failure; never invent tokens for a failed transport.

Acceptance: fake-provider caller controls record every passive specialist/family dispatch; concurrent tasks cannot oversubscribe configured admission ceilings; separate runs do not share effort state; missing budget does not silently create misleading totals. No changes to offensive dispatch or target request throughput.

### R08 — Complete, trustworthy usage and timing instrumentation

Priority P0; dependencies R07; estimate 2–3 days. Sources: ollama_client.py:296–329; providers/rate limiter/effort exports. Record returned provider usage before output parsing; track attempted/completed/usable/error/cancelled calls distinctly. Record queue, connection, generation and total wall time where measurable, with units and missing-data flags. Keep token count, latency, memory and cost separate.

Acceptance: malformed fake response with token counts increases consumption but yields no finding; missing counts remain unknown; per-run totals reconcile across successful/failed calls; sensitive response text not logged. This precedes every numerical performance claim.

### R09 — Deterministic SQLite resource cleanup

Priority P1; dependencies R00; estimate 1–3 days. Sources: cache.py:_get_connection and with-blocks; store.py connection callers. A sqlite connection context manager controls transactions; it does not close the connection. Use explicit close/ownership while preserving commit/rollback behavior. Inspect actual store paths individually; avoid redundant or premature closes and unnecessary pooling.

Acceptance: benign success/error/exception-path operations release owned connections deterministically; warning-enabled checks distinguish reported old warnings from fresh ones; read/write tests preserve transaction behavior. No unmeasured corruption/lock contention claim. Use temporary synthetic DBs, never shared runtime DBs.

### R10 — Atomic snapshots and engagement/session isolation

Priority P1; dependencies R09; estimate 3–6 days. Sources: server.py:1086–1094, to_thread callers; store.py snapshot load/upsert; identity and host-context ownership. Use transactional mutation or revision compare/retry to avoid lost updates. Define partition keys for separate engagements using the same host.

Acceptance: concurrent benign updates retain both sets, stale revisions are visible, different contexts remain isolated; cookie/session/context data cannot appear in another run/export. Test the caller path, not just a dictionary helper. Scope-only host identity is not a complete engagement identity.

### R11 — Durable job status, interrupted-state recovery and cancellation visibility

Priority P1 for team use; dependencies R10,R15; estimate 4–8 days. Sources: server.py job registry/manifests. Persist job identity/status and clearly expose interruption after process loss. Separate durable findings from execution state. Do not add automatic reexecution or autonomous resume; interrupted work requires an explicit operator decision outside this loop.

Acceptance: a benign non-network job interrupted/restarted has durable interrupted status, existing artifacts remain available, stale job polling is meaningful, cancellation is visible. Terminal retention/admission are bounded and documented. No duplicated synthetic work on an explicit passive retry.

### R12 — Failure containment and visible degraded states

Priority P1; dependencies R02,R07,R10; estimate 3–5 days. Sources: Java timeout handling, Ollama client, stage outcomes, TargetTransport boundary, reporting. Use benign fake upstreams for malformed responses, timeout/disconnect, throttling, auth expiry and cancellation. Preserve authoritative evidence state and expose incomplete work to the operator. Do not implement automated target retries or action scheduling.

Acceptance: timeout/401/429/cancel/parse failures remain explicit and do not become confirmed findings or clean negatives; passive inference admission stays bounded; connection shutdown frees resources; Java error/UI contract distinguishes health from successful authenticated analysis. Record unsupported recovery cases instead of hiding them.

### R13 — Cache correctness and context isolation

Priority P1; dependencies R08,R10; estimate 2–4 days. Sources: cache.py full/hypothesis keys; orchestrator_detect.py cache callers. Verify config/model/prompt/provider identity, analyst context, engagement and principal distinctions; ensure hypotheses cannot import proof authority and failed runs cannot be reused as successful analysis.

Acceptance: synthetic same traffic with different principal/context/config/provider cannot reuse inappropriate output; unchanged compatible passive input can reuse hypotheses; corrupted/expired/missing entries are explicit; model failures are not cached as success. No proof/confirmation replay and no automatic active revalidation introduced.

### R14 — Data lifecycle, export redaction and supported maintenance

Priority P1; dependencies R03,R09,R15; estimate 3–6 days. Sources: store.py evidence blobs/retention/deletion, server.py host deletion, evidence/report exports, token-file permissions. Define retention scope for all sensitive stores/logs, explicit maintenance and backup/restore. Ensure expiry does not silently invalidate still-referenced evidence. Verify Windows ACL behavior rather than assuming POSIX chmod applies.

Acceptance: synthetic secrets redacted on all export paths; configured maintenance behaves as documented; deleting one context does not delete another's shared blob; expired references become honest unavailable evidence; temporary backup/restore preserves identities and integrity. Destructive maintenance is tested only on disposable synthetic data. Document residual encryption/OS boundaries. Default keep-forever versus configured expiry is explicit, not mislabeled automatic retention.

### R15 — Evidence content provenance and durable-write failures

Priority P1; dependencies R01; estimate 2–3 days. Sources: evidence_ledger.py:_code_version/Provenance/emit; store evidence APIs. Add nonsecret dirty/content build identity and artifact integrity metadata. Make failed evidence persistence observable without promoting unsupported confirmation or crashing unrelated passive review unnecessarily.

Acceptance: two benign source contents at same HEAD differ in content identity; exported event references resolve and hash-check; simulated store failure yields visible incomplete evidence, never a fully supported conclusion. Runtime environment/model identifiers remain separate from source hashes.

### R16 — Consistent priority for unverified/no-leg findings

Priority P1; dependencies R03,R15; estimate 1–3 days. Sources: confirmation_gate.py tier none; report_generator.py/Java display/export filters. Define one policy for unverified findings, including unknown classes, without erasing genuine passive observations. Keep impact severity separate from evidence maturity and calibrated probability.

Acceptance: canned high-impact/no-leg result is visibly unverified and cannot be confused with confirmation; Python/Java/Markdown/SARIF agree on state/priority; fixed negative controls stay distinct from skipped/errored cases; model output cannot set proof authority. No novel validator or reproduction added to make a class confirmable.

### R17 — Scoring contract and evaluation eligibility

Priority P1; dependencies R15,R16; estimate 1–3 days. Sources: testing/web_objective_benchmark.py wrong-class events/eligibility and consumer/report code. Separate execution completeness from clean correctness evidence. Preserve missing-attempt denominators and fixed controls. Validate reference integrity rather than string presence where that contract is promised.

Acceptance: synthetic unrelated-class positives appear in explicit denominators and cannot count as clean correctness eligibility; expected-class success math remains correct; incomplete/corrupt artifacts and unhealthy intervals are not silently dropped. No target objectives executed.

### R18 — Deterministic report clock

Priority P1; dependencies R00; estimate 0.5–1 day. Sources: test_blind_eval_harness.py repeated markdown equality; report_generator.py generated_at default. Inject a clock/time parameter at the relevant passive report caller and retain independent timestamp tests.

Acceptance: synthetic runs straddling timestamp boundaries preserve expected content equality; deterministic timestamps render correctly; genuine content differences still fail. Do not delete equality or exchange-attribution controls.

### R19 — Packaging, supported environment and Java build

Priority P0 release gate; dependencies R01,R02,R03; estimate 3–6 days excluding unavailable tools. Sources: pyproject.toml package resources, server module-relative YAML, requirements/lock/extras, build.gradle. Verify wheel resources, clean install outside checkout, supported Python/dependency matrix and actual Java compile/test/shadowJar. Select build tool/JDK based on project requirements, not an unsupported “JDK 21 mandatory” assertion. Provide reproducible wrapper/build instructions where appropriate.

Acceptance: isolated provisioned env imports/starts candidate passive harness outside repo; resources included; declared dependency paths resolve; Java tests and shadowJar actually pass with recorded JDK/Gradle; artifact hashes and supported Burp compatibility stated. A source review or existing JAR is not a build. Missing tooling leaves gate blocked, not fixed by an undocumented global install.

### R20 — Operator/developer docs and honest claims

Priority P1; dependencies R02,R03,R19; estimate 2–4 days. Sources: README, docs index/testing/architecture, CURRENT_STATE. Correct actual stale paths/state and missing first-use/pairing steps. Document passive setup, configuration precedence, supported runtimes, optional tool requirements, degraded outcomes, retention, upgrade/rollback and support. Existing README already mentions JDK/Gradle; improve specificity rather than repeating the false claim that prerequisites are wholly absent.

Acceptance: new operator follows documented benign workflow in candidate environment; docs match current checked callers; unsupported performance/privacy/accuracy/legal assurances removed or labeled; AGENTS/CURRENT_STATE stay under 100 lines, CLAUDE remains a pointer. Task-directed docs avoid duplicate histories.

### R21 — Measured passive inference efficiency

Priority P2; dependencies R08,R13,R25; estimate 4–8 days plus study capacity. Sources: existing optional family routing, prompt construction/truncation, Ollama num_ctx and per-call AsyncClient. Measure a frozen sanitized captured corpus and declared local hardware/model. Compare existing passive routing/context options, prompt selection and lifecycle-owned connection reuse. Any implementation changes apply to passive analysis only.

Acceptance: actual input/output counts, p50/p95 latency and memory under declared setup; failed/inconclusive denominator retained; predefined evidence/quality tolerance passed. Include custom security headers, encoded/binary content and tail evidence cases. No presumed 65–75% saving, 3GB reduction, 3,500-token p99 or lossless compression. No assumption that template reuse gives provider prompt caching. Do not flip family routing, concurrency, fail-open mode or num_ctx defaults without measured supported-context justification; tuning cannot widen active automation.

### R22 — Modern application captured-data contracts

Priority P2; dependencies R03,R05,R13; estimate 3–5 days. Sources: driver_capture/browser_driver existing request shapes, HttpExchange and proxy ingestion. Verify manually supplied/captured fetch/XHR, GraphQL request shapes, ordinary multipart metadata and WebSocket-data limitations on sanitized benign samples. Preserve correct method/content-type/body/role attribution.

Acceptance: supported captured shapes survive ingestion -> passive analysis -> evidence/export; unsupported shapes are explicit; no target sends occur. Default-OFF driver capability is not a defect merely because disabled. Do not claim 90% hidden-route discovery or enable a new crawler. Document gaps requiring separate research rather than invent coverage.

### R23 — Verify existing deduplication and retest identity

Priority P2; dependencies R10,R15,R16; estimate 2–4 days. Sources: issues.py:issue_id_for/group_findings_into_issues, store.py finding_fingerprint, report_generator.py issue exports. Stable run-independent identity and attempt history already exist in source. Trace actual passive storage/export callers, fix only demonstrated defects, and preserve distinct inputs/principals/boundaries.

Acceptance: benign repeated findings across two runs link appropriately and retain all attempts; distinct parameters/principals/engagements do not collapse; filtered/unverified outcomes don't erase history. If the alleged absence is disproved at caller level, close DED-01 as already_satisfied_verified with artifacts, not a replacement implementation.

### R24 — Reporting parity and optional readable formats

Priority P2; dependencies R03,R14,R15,R16,R23; estimate 2–5 days for core parity, optional format work estimated separately after requirement check. Existing Markdown/SARIF/structured exports are the core contract. Verify redaction, evidence state, references and grouping parity first. Evaluate requested PDF/DOCX as optional convenience using the same sanitized issue view; do not make them a generic production gate.

Acceptance: same synthetic cases/limitations appear consistently across supported exports; no fake proof or secret appears. Optional formats may be implemented using an isolated supported dependency and rendered/layout-verified fixtures if in scope; otherwise optional_evaluated records supported workaround and concrete dependency/capacity decision. Missing PDF is not evidence that reports are unusable.

### R25 — Passive effectiveness and analyst-value evidence

Priority P1 decision gate; dependencies R02,R03,R08,R13,R16,R17,R19; estimate 5–10 evaluation days plus participants/model availability. Design a non-operational, blinded sanitized captured-traffic study with fixed corpora, held-out annotations and negative cases. Keep ground truth inaccessible to analysis. Stratify roles/auth/API/SPA/GraphQL/WebSocket/business-context and record unsupported strata honestly.

Acceptance: complete per-case TP/FP/FN/inconclusive/evidence-completeness denominators; at least three fresh-cache runs per declared model/config; failures/unknowns and annotation disagreements; paired counterbalanced manual/assisted analyst time and duplicate burden. Define quality gates before results. No blind-target implementation/answer keys, active validation, novel-yield claim or superiority without comparable evidence. If hardware/participants are absent, implement and verify synthetic evaluation plumbing and mark practical-study gate blocked_external.

### R26 — Correct competitive positioning

Priority P2; dependencies R20,R25 for effectiveness claims; estimate 1–3 days. Use current direct primary sources and exactly eight distinct alternatives under stated selection criteria. Correct missing competitor column, stale names/repository references, unsupported prices, editions/deployment and data-handling claims. Separate public vendor claims from hands-on measurements.

Acceptance: eight fully populated cited entries with unknowns, research date and edition; no invented benchmark superiority, token savings or legal assurance. Local/private deployment differentiation is conditional on R03/R14 data policies; use complement positioning until replacement evidence exists.

### R27 — Targeted architecture/ownership cleanup

Priority P2; dependencies relevant completed tickets; estimate 3–6 days. Sources: Orchestrator mixins/helper namespace/shared fields. Clarify state ownership and dependencies exposed by actual fixes; eliminate demonstrably duplicated policy/config contracts with explicit interfaces. Avoid expanding action-planning or tools and avoid broad rewrites justified only by file size.

Acceptance: chosen boundary has documented inputs/outputs/lifetime, two real passive callers use it, negative/failure controls remain; state is not stored in unscoped globals; no regression in supported passive behavior. If source decomposition is already adequate, record evidence instead of gratuitous refactoring.

### R28 — Release adjudication and complete handoff

Priority P0 final gate; dependencies all required fixes above; optional opportunities separately disposed; estimate 2–4 days plus blocked external prerequisites. Rebuild/test the exact candidate snapshot and reconcile artifacts against register. Inspect test assertions and skips, not headline counts. Keep source-only, mocked, reported and real-provider evidence distinct.

Required gates: complete candidate source/resources; authenticated benign Java/Python passive caller; privacy/scope/budget negative controls; durable resource/evidence/state tests; package/build commands actually pass; docs match; no safe-default widening. Required smoke/full/precondition commands are recorded with exact environment and their scope; if a full command cannot run within boundaries, its gate remains explicitly blocked and no all-green release claim follows.

Acceptance: every original finding maps to a ticket/disposition, no accepted in-scope defect silently omitted, every verified closure links evidence, remaining external/capability exclusions identified. Update four readiness verdicts based on actual gate results; no percentage or calendar promise. Produce final release notes, unresolved register and next-owner prerequisites. Do not announce ALL FIXED when any required gate/defect remains open.

## Final delivery format

Deliver a concise summary of fixed behaviors and their caller controls; exact candidate revision/content/build identities; command log and skips; complete register; surviving risks and blocked gates; optional decisions; operator install/upgrade/rollback docs; evidence links. Keep residual model effectiveness distinct from regression correctness.

Capacity assumption for sequencing only: one coding agent with owner review, plus provisioned build tools and a separate evaluator/practitioner for R25. Do not assign 30/60/90 deadlines from this document. Sum ticket estimates only after overlap, environment and optional decisions are reconciled; use measured iteration throughput for forecasts.
