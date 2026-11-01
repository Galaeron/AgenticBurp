# Mission: verify and improve AgenticVibe as an automated tester and evidence-grounded advisor

Review `C:\Users\arthu\Documents\AgenticVibe` and produce an executable,
prioritized improvement plan. This is an audit and planning task, not authorization
to implement fixes, change defaults, launch scans, or publish changes.

The product must support two useful workflows:

1. **Automated testing:** discover or ingest relevant traffic, assemble application
   context, select applicable checks, execute only authorized actions within shared
   limits, and report justified findings and explicit coverage gaps.
2. **Advisory review:** use supplied traffic and retained engagement evidence to
   explain relationships across requests, compare identities and application state,
   identify contradictions or missing evidence, and propose useful next analyst
   steps. This must work without sending new target traffic. Model unavailability
   must produce an explicit degraded result, not silently empty success.

Both modes must share trustworthy application evidence while retaining different
execution permissions. Neither a graph visualization nor a large finding count is
proof of usefulness. “Better than anticipated” means measured improvement over
predeclared baselines, not a promised result or a moving acceptance threshold.

## 1. Establish the evidence boundary first

Read AGENTS.md and CURRENT_STATE.md. Treat state documents as claims to verify.
Then read only task-relevant material, including docs/TESTING.md,
docs/REMAINING_IMPLEMENTATION_PLAN_2026-10-17.md and its candidate-manifest pointer.
Do not bulk-ingest archive/, reviews/, or runtime artifacts. Follow specific
references when investigating a particular historical claim.

Record date, branch, HEAD, upstream/base, candidate manifest and hashes, relevant
dirty/untracked files, runtime/dependency versions, model/configuration identity
and available tools. Distinguish committed code, candidate overlays and other WIP.
Verify from an isolated, reproducible candidate under current repository rules.
Never attribute a mixed-working-tree test pass to a committed release.

Preserve existing edits and artifacts. Do not reset, clean, stash, commit, install
dependencies, restart services or change configuration. Keep safe defaults intact;
do not print secrets, local override values or sensitive captured traffic.
Never read `*ANSWER_KEY*` (case-insensitive) or blind-target implementations,
including their `app.py`. The VulnCorp README is permitted, its implementation is not.

Use source inspection, passive checks, sanitized captures and benign owned
fixtures. Inspect tests before running them. Do not run live exploitation,
destructive objectives or vulnerability reproduction as part of this audit.
Specify separately authorized live evaluation as future work with prerequisites.
Do not include exploit payloads or operational attack instructions in outputs.

Label each substantive claim VERIFIED NOW, SOURCE-SUPPORTED,
HISTORICAL/REPORTED, INFERRED, or UNKNOWN/BLOCKED. A mocked boundary establishes
only the behavior exercised. Separate observed defects, evidence gaps and product
opportunities. Never invent results, credentials, measurements or citations.

## 2. Review method and priorities

Start with a short coverage map, then perform the review. Use separate architecture,
reliability, enterprise pentester, bug bounty practitioner, LLM-efficiency and
product perspectives. If subagents are available, delegate bounded independent
areas with these safeguards; coordinate tests and shared files. Otherwise perform
separate passes without claiming independent reviewers.

Prioritize the dual-mode production paths and the cross-request problem before
general cleanup or competitor research. Maintain one evidence index, challenge
unsupported diagnoses, consolidate duplicates and retain meaningful disagreements.

## 3. Investigate the crAPI failure without assuming its cause

Owner-reported hypothesis: the tested workflow could not compare evidence from
multiple requests and therefore did not benefit from the graph and matrices.
Do not convert this into a verified root cause without tracing the actual run.

Locate the specific run and establish its source/configuration/model identity,
entry point, mode, engagement/session identifiers, supplied captures/identities,
target state, budgets, cache state and stage completion. If unavailable, mark the
historical cause unresolved and demonstrate only a present-day controlled case.

Build a failure funnel with counts and references at each boundary:

capture available → ingested → correctly attributed → retained → related to other
exchanges → graph/matrix updated → relevant evidence retrieved → analysis/planning
consumes it → check/advice produced → evidence persisted → operator can inspect it.

Distinguish missing observations from lost observations, incorrect entity joins,
isolated engagement IDs, stale state/cache, disconnected consumers, inapplicable
validators, inference failure and missing presentation. Investigate alternative
explanations including discovery, authentication, request shape and budget limits.
Identify the earliest proven break and any independent downstream failures.

Show one sanitized expected-versus-actual trace. Name which graph and which matrix
was relevant; do not treat all structures as interchangeable or assume an active
investigation result proves the passive `/analyze` workflow works.

## 4. Trace both modes through real product entry points

Resolve actual source paths from AGENTS.md. Trace Burp UI/capture → API →
orchestration → context retrieval → inference/deterministic checks → storage →
API/UI/export. Include engagement investigation, not just standalone analysis.
Produce a compact architecture diagram and a mode-capability table.

For each mode record entry point, session ownership, inputs, retained observations,
graph/matrix producers and consumers, permissions, outputs and current evidence.
Cover single captured exchange, multiple selected exchanges, incremental history,
role comparison, resumed engagement and automated investigation. Label unsupported
workflows explicitly. Product workflows must not require manual database editing
or undocumented API stitching to expose an advertised capability.

Inspect contract compatibility between Java and Python, cancellation, concurrency,
timeouts/retries, pooling, persistence/recovery, idempotency, malformed responses,
configuration precedence and error propagation. Trace callers rather than infer
integration from names, registries or helper tests.

## 5. Cross-request evidence is a first-class acceptance requirement

Determine whether the system retains **observations**, including non-findings,
not merely summaries of previous alerts. Test cases where neither request is
interesting alone but their relationship supports useful advice. Prior finding
text is not a substitute for inspectable request/response evidence.

Specify and inspect the minimum evidence contract:

- Stable exchange/evidence references, capture time and provenance.
- Engagement, principal, role, tenant and session attribution, including unknowns.
- Method, normalized route, concrete object identifiers and original request shape.
- Relevant response facts, application state/version and temporal relationships.
- Explicit observed, inferred, conflicting, stale and unavailable states.
- Bounded retention/retrieval, redaction, deletion and cache invalidation behavior.

Check entity resolution across endpoints and repeated observations. A matching ID
or URL alone must not establish common ownership, identity or unauthorized access.
An HTTP 200 alone must not prove access to a protected object. Missing observations
must not become a denial, secure result or completed check.

Determine whether these distinct structures exist and are used:

| Structure | Required question |
|---|---|
| Application/evidence relationships | Which observed entities, exchanges and states are related, and why? |
| Task/dependency graph | Which review/test tasks depend on other tasks or missing evidence? |
| Role/access matrix | What was actually observed for each principal/resource/action, under which session and time? |
| Coverage matrix | Which applicable checks were attempted, blocked, inconclusive, refuted, confirmed or untested? |

For every relevant structure trace producer → storage → reader → decision → UI.
Do not prescribe a new graph database or architecture merely because the existing
feature is disconnected. Prefer the smallest justified integration change.

## 6. Require causal tests, not decorative integration

Design benign sanitized fixtures, exercised through public production callers:

- Two observations whose comparison changes an advisory conclusion, with citations
  to both; either observation alone must remain insufficient.
- Same-role/different-owner and different-role comparisons with explicit access
  expectations; a legitimate shared/public-resource control must not be flagged.
- A sequence with relevant earlier state and a contradictory later observation;
  timestamps and known workflow order must govern the interpretation.
- Identical-looking object IDs in different tenants/engagements; never merge them.
- Missing identity, expired session, incomplete/truncated capture, duplicate input,
  out-of-order arrival, restart/resume, stale cache and deleted evidence.
- Equivalent supplied evidence in advisory and automated modes; facts/provenance
  should agree even when permitted actions and resulting new observations differ.

Assert useful output, evidence references and uncertainty through persistence and
operator-facing output. In advisory mode independently assert zero new target
requests; configured inference calls are a separate boundary to account for.

Inject targeted defects: drop the earlier exchange, sever the relation lookup,
disable the graph/matrix reader, discard identity, or reuse stale retrieval.
The corresponding acceptance test must fail or expose the precise degraded state.
Use cases for which each disabled component is actually relevant; do not force
every graph/matrix to influence every decision. Preserve existing pipeline-gate
controls and do not replace caller tests with helper assertions.

## 7. Define useful advisory behavior explicitly

For supported questions, the advisor must show: the question answered, relevant
observations with resolvable references, the relationship/comparison, assumptions,
contradictions, uncertainty, missing evidence and a ranked next review step with
its expected information value. Separate proposed actions from executed actions.

Evaluate whether an analyst can select related captures, assign/correct identity
and scope, inspect a comparison, challenge a conclusion, supply missing evidence
and resume work. Determine whether corrections persist and invalidate stale advice.
Do not claim conversational or interactive support that exists only as a backend
helper. Assess whether reports distinguish suspicion from confirmation consistently.

The advisor should explain what it cannot determine. “No finding” must be
distinguishable from “not enough relevant evidence” and “analysis failed.”
Do not reward generic checklists, unsupported specificity or confident summaries
that cannot be traced back to supplied observations.

## 8. Measure automatic testing and advisory value separately

Freeze an evaluation specification before improvement work. Use the same sanitized
inputs, model/configuration, candidate identities and matched resource budgets.
Separate fixed-corpus reasoning experiments from end-to-end acquisition experiments.
Do not give one arm privileged captures or labels without reporting that advantage.

Compare at least: single-exchange baseline; bounded multi-exchange context;
context plus relevant graph/matrix consumers; deterministic baseline; model-assisted
candidate. Add a human-only workflow baseline for analyst-effort claims where feasible.
Use targeted ablations to determine whether the graph/matrix contributes beyond
simply providing more context. Repeats measure stability, not independent sample size.

Automated metrics: acquisition and applicability funnel, precision/recall with
explicit denominators, false confirmations, inconclusive/untested rates, valid
evidence completeness, stage failures, independent request counts, time and tokens.
Report both conditional performance on acquired cases and end-to-end coverage;
do not hide missed acquisition by shrinking the denominator.

Advisory metrics: correct cross-request conclusions, unsupported-claim rate,
citation correctness/completeness, useful abstention, relevance of proposed next
steps, analyst corrections, time to a justified decision and report preparation.
Define a scoring rubric and independent adjudication; do not let the producing
model grade itself. Separate uncertain hypotheses from false confirmed findings.

Predeclare minimum acceptable quality, precision/recall tradeoffs, maximum cost,
and minimum meaningful improvement. State who must choose business thresholds.
Keep existing zero-false-confirmation no-go rules; zero in a finite sample is not
proof of a zero population rate. Report sample sizes, uncertainty, failed runs,
contamination exclusions and per-context results. Do not generalize from crAPI alone.
Keep blind labels with an independent custodian, outside the reviewing agent's view.

## 9. Reliability, safety, privacy and inference efficiency

Verify shared scope/budget/cancellation enforcement in automated paths, redirects,
browser traffic and external tools. Verify advisory analysis does not silently
enable execution. Inspect auth expiry, throttling, partial failures, secret handling,
local-service exposure, redaction/retention, provenance and untrusted-content handling.
HTTP method alone does not establish safety. Model output must not override policy.

Map inference call sites, retrieval selection, context limits, repeated prompts,
retry overhead, concurrency and actual usage instrumentation. Measure costs of
relational context, not just prompt length. Test that compression retains decisive
cross-request facts, identities, timing and contradictions. Separate token counts,
latency, memory, utilization and monetary cost; label estimates accurately.
For optimizations give source, observed cost, expected benefit/assumptions, quality
risk and validation gate. Do not presume local prompt caching produces savings.

## 10. Verification, packaging and operator readiness

Inspect relevant runners and test behavior. Within audit boundaries, run smoke,
full and orchestrator-precondition from the isolated candidate's repository root
with existing dependencies. Record exact commands, source identity, durations,
exit codes, failures and skips. Do not rerun broad suites without a reason.
If a check requires prohibited behavior or absent prerequisites, report it blocked
with the minimal prerequisite and limited conclusion; do not weaken the check.

Inspect dependency/build reproducibility and clean installed behavior. A Java
source review is not `gradle shadowJar`; claim a build only if actually executed
with a JDK. Verify documentation against source and operator behavior, including
installation, first useful result, pairing, mode selection, session reuse,
degraded states, exports, upgrades/rollback and current limitations.

Give separate readiness verdicts for each mode and for local research, supervised
pilot, routine professional use and external distribution: READY, READY WITH
CONDITIONS, NOT READY or INSUFFICIENT EVIDENCE. State supported scope, blockers,
residual risks and measurable gates. A safe advisory mode may be useful before
automation is ready; do not transfer readiness from one mode to the other.

## 11. Practitioner and competitive assessment

Give separate enterprise-pentester and bug-bounty-practitioner assessments of both
modes: appropriate users, demonstrated utility, remaining manual work, dealbreakers,
adoption verdict and evidence that would change it. Do not claim actual credentials.

After the core integration assessment, research exactly eight relevant alternatives
using current primary sources. Declare selection criteria; identify adjacent tools.
Record research date, edition, deployment, licensing/pricing where verifiable and
source links. Compare automatic testing and advisory/multi-request workflows
separately, including session context, provenance, proxy integration, oversight,
privacy, reporting and switching costs. Mark unknowns and vendor claims explicitly.
No superiority claim without a shared evaluation. If browsing is unavailable,
mark this section provisional without blocking the engineering work list.

## 12. Deliver an executable plan, not another disconnected backlog

Save new outputs in a uniquely named dated review directory. Do not overwrite
existing trackers during this audit. Deliver:

1. Decision report: five consequential findings, architecture/mode map, crAPI
   failure funnel, source/reproducibility limits, separate readiness verdicts.
2. Evidence index: findings linked to exact source locations, commands, sanitized
   artifacts and candidate identity; historical evidence clearly separated.
3. Cross-request acceptance specification: fixtures, expected results, negative
   controls, fault injections, evaluation arms, metrics and proposed thresholds.
4. Prioritized work list with a proposed reconciliation against I01–I17 and older
   aliases; one canonical owner per gap. Preserve valid completed work and reopen
   only the specific unverified acceptance scope. Distinguish candidate freeze,
   code fix, caller verification, live validation and release.
5. Practitioner assessments and sourced eight-alternative comparison.

Every ticket must include ID, defect/evidence-gap/opportunity type, affected mode,
user-visible outcome, evidence status, source/caller boundaries, root-cause confidence,
smallest proposed change, dependencies, effort range/assumptions, acceptance case,
negative control, fault injection where relevant, metric, completion artifact,
regression risk and rollout/rollback implications. Include an explicit non-goal.
Do not mark complete because a helper exists or a mocked test passes.

Sequence work by dependencies and user value: reproducible candidate and trustworthy
evidence; cross-request attribution/retrieval and real consumers; usable advisory
workflow and bounded automated integration; comparative efficacy; release/operator
proof. Preserve existing trust blockers. Parallelize only independent work.
Propose exact amendments to existing tickets before proposing new IDs; do not
silently replace the canonical dispatch order. Supply a short first executable
batch and explain what can proceed without live authorization. Give 30/60/90-day
estimates only with explicit staffing assumptions.

Conclude with what each mode can support now, the earliest verified break in the
cross-request path, the smallest next improvement, and the experiment that could
falsify its claimed benefit. Success is a reproducible improvement in useful,
justified outcomes—not more features, more tests, or a more optimistic report.
