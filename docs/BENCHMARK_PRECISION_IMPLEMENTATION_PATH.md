# Benchmark precision implementation path

Date: 2026-09-24. Planning baseline: `reconciliation-backlog`, HEAD `ca4ee15`.
Status: implementation tasks pending; this document is not a benchmark result.

## Objective and scope

Make the benchmark distinguish correct, supported detections from noisy alerts,
then reduce false positives without hiding true findings. BP-0 through BP-5 are
offline work. BP-1a and BP-1b are separate reviewable changes. BP-5C is mandatory
corpus expansion and evaluation-design work before BP-6 real-model evaluation;
BP-7 is the promotion decision. Additional owned captures, if needed for BP-5C,
are a separate data-collection step, not an implicit active-validator run.
This plan does not start the improvement-loop automation or change its dispatch.
Each task should be a focused reviewable change; split BP-5 by diagnosed cause.

Read AGENTS.md and CURRENT_STATE.md before implementation. Preserve existing
edits, regression coverage, and benchmark artifacts. Never read answer-key files
or blind target implementations. Keep passive defaults and active validators off.
Use the allowed captured exchanges and existing public labels for retrospective
analysis; create genuinely new cases for holdout evaluation. Labels and reviewer
annotations must never enter the detector's prompts or request metadata.

## Evidence motivating the work

Sources: `reviews/2026-09-23/benchmark/BENCHMARK_REPORT.md`, its five saved
`*_default_3x.json` artifacts, `testing/score.py`, and
`testing/blind-target-2/run_blind_eval.py`, inspected on 2026-09-24.
The run outcomes themselves are historical/reported, not freshly reproduced.

- Four corpora use any-finding coverage as recall; it does not require a correct
  vulnerability class. PixelMart checks broad OWASP categories, so SQLi and XSS
  can match the same Injection bucket. Neither proves supported vulnerability recall.
- Fair issue-level control counts are zero clean in all saved repeats:
  blind-target-2 0/5, Juice Shop 0/5, DVWA 0/4, WebGoat 0/2. The six secure
  blind-target-2 exchanges are not the same denominator as five scored controls.
- PixelMart mean wall time is 1138.631 seconds, versus ~1330 in the report.
  Blind-target-2 totals are 62/60/68 findings for ten exchanges, inconsistent
  with the report's ~4 findings/exchange unless another counting unit was intended.
- The reproduction command references `scratchpad/bench_blindstyle.py`, which
  is absent from this checkout. Historical output alone cannot reconstruct it.
- PixelMart's saved log records two breaker failures in repeats 1 and 3, plus
  a critique HTTP 500 in repeat 1 that shipped findings unreviewed. Its footer
  nevertheless calls every measurement clean and breaker-healthy. No starvation
  is not equivalent to no failures or a fully executed critique stage.
- Existing B2-3/B2-3b/AR-3 attribution, B2-5 gating, and AR-1 family routing
  should be reused. Do not reopen completed implementation tickets merely
  because their efficacy remains unproven. Saved runs record curated fail-open;
  establish actual config provenance before calling them shipped-default runs.

## BP-0 — Produce the seed labeling manifest

Depends on: none. Mode: offline annotation. Deliverable: a small versioned,
hand-labeled development manifest and a labeling rubric, alongside synthetic
fixtures. This is a required input task, not an assumed property of the corpora.

Begin with permitted captured SQLi and IDOR benign/vulnerable pairs. Assign
exact classes only where request/response evidence supports them; coarse OWASP
labels and `confirmed_vuln` alone cannot supply exact-class truth. Record stable
exchange IDs, source artifact hashes, evidence locations, reviewer, rationale,
label scope, uncertainty and annotation version. Annotate without using detector
predictions as truth. Keep ambiguous cases inconclusive; do not force a label
to complete a pair. Never read answer keys or blind target implementations.

Acceptance: at least one evidence-adjudicated positive/negative pair is usable
by BP-1a, with explicitly bounded negative-class scope. If the saved artifacts
cannot support even that, record the missing capture requirement; synthetic
scorer work can proceed, but historical exact-class scoring stays unavailable.
Synthetic fixtures cover additional class distinctions without pretending to
validate real applications. BP-4 later expands/corrects this seed with versioned
changes; it is not a prerequisite for the first scorer implementation.

## BP-1a — Land the strict scorer and its fixtures

Depends on: BP-0 for real-data acceptance; synthetic implementation can start
independently. Mode: offline. Primary files: `testing/score.py`,
`testing/test_score.py`; add a versioned strict scorer module if required to
preserve legacy output contracts. Reuse existing taxonomy/provenance facilities.

Implement:
- A scoring-only manifest with corpus/version/hash, stable exchange IDs,
  expected vulnerability classes, explicitly tested-negative classes, label
  scope, and `positive|negative|inconclusive|setup` status. Support multiple
  expected classes. A benign SQL query is not automatically proof that the
  endpoint is secure against every other vulnerability.
- Explicit exact-class aliases, distinct from OWASP reporting buckets. Unknown
  classes and unresolved labels remain visible and unscored, not silently dropped
  or treated as secure. Separate SQLi, XSS, SSTI, command injection, SSRF and CSRF.
- Separate any-alert coverage from exact-class precision/recall. Define matching and deduplication units
  explicitly. Missing predictions for known positives count as misses; missing
  labels do not imply negatives. Report counts and scoring coverage with rates.

Acceptance: synthetic fixtures prove a wrong-class alert is not a TP, SQLi cannot
satisfy XSS, CSRF cannot satisfy SSRF, duplicates do not inflate recall, absent
predictions become FN, and unknown/setup cases do not become false positives.
Include always-alert, all-classes-on-every-exchange, and silent baselines. On a
balanced labeled fixture the indiscriminate baselines must fail the precision
gate even when coverage/recall is perfect; the silent baseline fails recall.

## BP-1b — Add evidence grading as a separate layer

Depends on: BP-1a. Mode: offline. Primary entry point:
`evaluation_integrity/evidence_audit.py`, its tests, and the strict scorer adapter.

Distinguish captured support, differential/reproduced support, unsupported and
insufficient artifacts using a versioned adjudication rubric. Reuse the existing
confirmation-claim audit within its contract; a proof reference existing does
not establish vulnerability validity. Add evidence-supported precision/recall
with explicit eligible denominators and unresolved counts, separately from raw
exact-class metrics. Missing instrumentation/evidence yields unavailable or
unresolved results, not fabricated zeros. Do not equate passive support with
active exploit confirmation.

Acceptance: fixtures distinguish a correct-class unsupported claim from a
supported claim, and reject wrong-exchange or broken evidence links. Missing
artifacts cannot create a confirmed TP. BP-1a scores remain unchanged by this
layer. This task need not block BP-2's strict-scoring integration.

## BP-2 — Wire one reproducible evaluation path

Depends on: BP-1a; integrate BP-1b when available. Mode: offline. Primary files:
`testing/blind-target-2/run_blind_eval.py`, `testing/test_blind_eval_harness.py`,
`testing/test-target/run_ablation_live.py`, `harness/ablation_harness.py`,
`harness/score_provenance.py`; add a maintained shared CLI under `testing/`.

Implement a shared adapter/schema used by both drivers. Preserve legacy fields
with explicit legacy names/scope rather than silently changing their meaning.
Attribute findings using exchange observations; mark legacy ambiguous attribution
unresolved instead of assigning a finding to all requests sharing a URL.
Export the exact finding IDs/classes at raw, surfaced, and lead stages. Derive
visibility from the real report decision, including the generic-confidence gate,
so scoring and rendered reports cannot disagree.

Record checkout/dirty state, corpus and scorer hashes, effective config and its
overrides, model identity/settings, run IDs, cache freshness, calls/tokens, elapsed
time, failures, starvation, and exclusions. Missing token instrumentation means
unavailable, not zero cost. Strip scoring annotations before calling analyze().
Support read-only historical rescoring without invoking models or target traffic.

Acceptance: caller-level tests go through the actual driver, orchestrator boundary,
store and report path with synthetic exchanges and controlled model output.
Negative controls detect label leakage, dropped findings, wrong-exchange joins,
and report/scorer visibility disagreement. A synthetic CLI run produces valid
artifacts without Docker, Ollama, network requests, or target implementation reads.

## BP-3 — Re-score and correct the historical report

Depends on: BP-2. Mode: offline. Outputs: a new versioned assessment under
`reviews/2026-09-23/benchmark/`, reproducible commands and a corrected summary.

Keep original JSON/logs unchanged. Recompute what the artifacts support; list
missing evidence and exact-class annotations that prevent stricter scoring.
Generate numerical tables from artifacts, including denominators and per-run
values. Mark rescoring historical, never fresh inference. Preserve the original
report with a dated correction pointer rather than erasing historical claims.
Remove unsupported claims that recall is solved, quarantine has no benefit, or
these results establish commercial-tool parity. External comparisons stay out of
the decision gate unless their measurement definitions can actually be aligned.

Acceptance: generated totals reconcile with each input; strict scores are never
inferred from broad categories alone. Document whether controls are exchange,
method/URL, or issue units. Reconcile PixelMart's logged critique HTTP 500,
unreviewed output and breaker failures against the healthy footer and JSON.
Distinguish no starvation, recovered/degraded execution and failure-free execution.
Do not infer that every recorded failure had the same cause. Evidence-supported
rescoring depends on BP-1b and remains unavailable where artifacts are missing.

## BP-4 — Audit and rank false-positive causes

Depends on: BP-0, BP-1b and BP-2; use BP-3 outputs. Mode: offline evidence review.
Outputs: machine-readable adjudication records and a short ranked audit report.

Start with WebGoat benign/vulnerable SQLi and own/other-user IDOR pairs, then
cover every scored control in the four blind-style corpora and PixelMart's
available scored cases. Record finding/exchange IDs, exact class, evidence
references, label scope, observed vs inferred claims, disposition and rationale.
Distinguish unsupported claims, duplicates, host-wide observations, attribution
errors and incomplete labels. Unresolved findings stay unresolved.
Expand/correct the BP-0 exact-class manifest using captured evidence, recording
each annotation revision and its rationale. Audit the label independently of the
detector claim; disagreement does not justify changing truth to match output.
Re-score both baseline and candidates against the same frozen label version.

Daybreak may provide a second review using captured evidence with expected labels
withheld for the initial judgment. Record disagreements and resolve against the
evidence/rubric; model agreement is not ground truth. Daybreak review is optional
and does not block the deterministic scoring work or imply a backend migration.

Acceptance: rank causes by unique unsupported surfaced issues and affected
controls, with counts and examples. Every reviewed decision is traceable.
Select the top two or three causes for BP-5; do not choose fixes in advance.

## BP-5 — Fix the measured causes and reporting trade-offs

Depends on: BP-4. Mode: offline implementation, one change per diagnosed cause.
Likely entry points, selected only after attribution: `harness/coordinator.py`,
`harness/orchestrator_detect.py`, `harness/orchestrator_confirm.py`,
`harness/confirmation_gate.py`, `harness/report_generator.py`, `harness/issues.py`.

Prefer evidence requirements and correct attribution over blanket class bans or
confidence thresholds. Reuse existing gates. Keep uncertain leads accessible.
For each fix retain a paired vulnerable case and benign control through the real
caller path; test that disabling/breaking the fix reintroduces the diagnosed error.
Add bounded failure/missing-evidence cases. New behavior ships opt-in where it
changes recall; flag-off behavior remains compatible. No active traffic is added.

Acceptance: the benign false claim is removed/demoted as intended, its supported
vulnerable counterpart remains correctly classified and visible, and the scorecard
matches the report. Report surfaced FP counts and surfaced supported TP counts
alongside clean-control rate; quarantine cannot claim success by hiding both.

## BP-5C — Expand labeled cases and establish evaluation adequacy

Depends on: BP-0/BP-1a for schema and rubric; BP-4 for development coverage gaps.
Begin planning early; completion is mandatory before BP-6's confirmatory runs.
Outputs: expanded development manifest, separately maintained untouched holdout,
and a frozen evaluation-design document. This is on the critical path, not a
fallback after an inconclusive experiment.

Add independently meaningful positive/negative cases across classes, endpoints,
authorization contexts and applications. Repeating the same exchange or making
cosmetic variants does not increase independent corpus size. Declare the sampling
unit and group related sessions/endpoints/pairs to prevent split leakage.
An independent curator should label and retain the holdout; expose only its
coverage inventory to implementers until fixes and decision rules are frozen.
If that separation cannot be maintained, call it development data and acquire
another holdout. Track collection/annotation provenance and unresolved cases.

Specify supported-recall noninferiority margin, false-positive improvement target,
confidence level, anticipated baseline/paired disagreement assumptions, clustering,
and required independent counts per claimed corpus/class stratum. Use a documented
sample-size calculation or simulation with sensitivity ranges before evaluation;
do not select counts by repeatedly checking holdout results. A 5pp margin needs
more than numerical granularity: 20 positives give 5pp steps, not adequate power.
Eleven positives give ~9.1pp steps; two controls give 50pp clean-control steps.
Control counts affect precision/control-rate resolution, not recall's denominator.

Acceptance: an inventory demonstrates that collected, adjudicated independent
cases meet the frozen design for each proposed claim. If collection is infeasible,
narrow the declared claim or keep promotion blocked before spending GPU on a
confirmatory run. Five model repeats cannot substitute for corpus expansion.

## BP-6 — Controlled live evaluation

Depends on: BP-5, BP-5C and a working reproducible driver. Mode: real-model
evaluation on owned captured corpora, separate from offline completion.

Freeze and hash a development corpus and a genuinely untouched holdout before
tuning. Previously reviewed cases are development data, not holdout. Group related
endpoints/sessions/pairs together to avoid leakage. Keep holdout annotations out
of detector inputs and tuning. Resolve missing labels via permitted independent
capture review, never by reading blind keys or target implementations.

Experiment order:
1. Fixed qwen3:8b/settings/routing: baseline versus each fix, then combined fixes.
2. With fixes held constant: full-agent versus existing family routing.
3. Optional separate stronger-model comparison only after a supported integration
   and its effective config/cost recording are established. Having Daybreak enabled
   for review does not establish that the harness can call it as a backend.

Use short development pilots, then at least five paired repeats for baseline and
final candidate on holdout. Alternate execution order, serialize GPU runs, use
fresh isolated caches and per-run breaker state. Count failures and report healthy
and all-attempt results separately; no silent exclusion of bad runs.

Acceptance: report per-corpus/per-class counts, exact and supported recall,
surfaced/lead precision, unsupported issues per scored control, unknown/unscored
coverage, clean controls, latency, calls and tokens. Repeats estimate model
variability, not independent applications; avoid treating them as new samples.

## BP-7 — Promotion decision

Depends on: BP-6. Freeze the decision rule before inspecting holdout results.
Suggested conservative starting gate: no new supported misses in the fixed paired
regression cases; reduced unsupported surfaced issues on holdout; at most a
five-percentage-point supported surfaced-recall loss per corpus, assessed with
counts and the BP-5C uncertainty/design criteria. Corpus adequacy must already
have passed BP-5C; do not enter this decision expecting tiny legacy denominators
to resolve the margin. An inconclusive result can still occur despite adequate
design. In that event leave promotion blocked; any further sample collection
requires a new or pre-specified sequential evaluation design, not post-hoc
sampling until the result passes.
Publish latency/cost deltas and any accepted trade-off explicitly.

Promote only candidates that pass the frozen efficacy rule and regression checks.
Leave config defaults unchanged in this workstream; record a separate reviewed
default-change decision with rollback settings. A green offline suite alone
cannot close BP-6 or BP-7. Reuse RB-2b's existing default-change gate where relevant.

## Verification and handoff

For code tasks, use the project's installed test environment from repository root:

```text
python -m harness.suite smoke
python -m harness.suite full
python -m unittest harness.test_orchestrator_precondition
```

Run focused scorer/driver tests first, then the required checks after changes.
Ensure new evaluation tests are collected by `harness/suite.py`. Preserve
`harness/test_pipeline_gate.py` and its defect-injection cases. Record actual
commands, runtime, exits and skips; never carry forward old green claims.

Each task handoff names changed files, tests, artifacts, unresolved limitations,
and the next dependency. Update CURRENT_STATE.md after implementation, replacing
stale status rather than appending history, and keep it under 100 lines. If making
commits, keep them focused and end messages with a Co-Authored-By trailer.

Execution path: BP-0 seed labels -> BP-1a strict scorer -> BP-2 caller integration
-> BP-3 historical correction -> BP-4 audit -> BP-5 targeted fixes -> BP-6 -> BP-7.
BP-1b evidence grading can follow BP-1a independently of BP-2; it must finish
before BP-4. Plan BP-5C corpus expansion early and complete it before BP-6.
First implementation slice: BP-0 seed manifest plus BP-1a scorer/fixtures as
separate reviewable deliverables. Neither requires a GPU run.
