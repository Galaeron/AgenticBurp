# Improvement backlog

A prioritized, loop-consumable list of improvements derived from the 2026-09-20
architecture/security/product review. Each item is self-contained: an agent can
pick the top unchecked item in the highest-priority tier and act on it without
re-reading the whole review.

## How the loop should use this file

**2026-09-24 benchmark follow-up:** The BP-0 through BP-7 implementation
path is in [Benchmark precision implementation path](docs/BENCHMARK_PRECISION_IMPLEMENTATION_PATH.md).
Start with provenance-tracked seed labels, then BP-1a strict scoring and BP-1b
separate evidence grading, caller integration, historical rescoring, adjudication
and targeted fixes. BP-5C corpus expansion/evaluation adequacy is mandatory before
confirmatory live validation; model repeats cannot replace independent cases.
This is a planning pointer, not an automation dispatch or a completion claim;
it preserves existing queue rules and completed B2/AR work.

**Evaluation correction (2026-09-20):** Read
[the reassessment](docs/EVALUATION_REASSESSMENT_2026-09-20.md) when interpreting
the original review. Completed items' original Evidence/Problem paragraphs are
historical motivation, not current defects. Real-model benchmarks already exist;
P0-3 concerns reproducibility and measuring subsequent changes. Ledger wiring is
implemented but audit completeness remains P0-6; prompt fencing is not injection
immunity; P1-2 does not establish allowed-host DNS-rebinding protection (P1-9).
This correction preserves the paused-item and INV dispatch order below.

**2026-09-20 investigation dispatch (user-requested):** Finish the already-paused
item first. Then select INV-1, INV-2, INV-3, INV-4 below, in that order, before
resuming the ordinary priority queue. These are bounded OFFLINE investigations;
do not skip them merely because their eventual efficacy checks need a live run.
Opus reviews/selects; Sonnet investigates one item per iteration. Read
[docs/INVESTIGATION_DISPATCH_2026-09-20.md](docs/INVESTIGATION_DISPATCH_2026-09-20.md)
for exact scope, deliverables, evidence rules, and review criteria. This dispatch
does not start an automation or authorize live execution. Preserve existing work.

**2026-09-21 consensus dispatch (reopens the LOOP_DONE hold for OFFLINE work):** A
four-way review reconciliation (`reviews/2026-09-21/REVIEW_RECONCILIATION_AND_PLAN.md`
+ `PRINCIPAL_REVIEW.md`) reached consensus. The efficacy *runs* — a real-model blind
scorecard and the A–F ablation — stay **OWNER/LIVE** and out of loop scope, but the loop
can now BUILD the instruments those runs need and land the trust-completeness fixes. The
INV-1..4 diagnoses promised "production fixes as separate tickets"; those are now filed
below. Select from **Consensus batch — 2026-09-21** (end of file), in this order, before
resuming the ordinary queue: **RB-1 → RB-4 → RB-8 → RB-3 → RB-5 → RB-2 → RB-7 → RB-6**.
Items tagged `Mode: OWNER/LIVE` are NOT loop-consumable — leave them `[ ]` and skip.
Do NOT flip a `config.yaml` default that carries a documented recall trade-off (the
`fail_open_mode: curated` flip is owner-gated on RB-8's measured delta, not a loop freebie).
Every RB item names a caller-level test + negative control; honour the non-negotiables below.

**2026-09-25 founder-review + FP dispatch (offline batch; reopens loop work):** The founder
decision review (`reviews/2026-09-25/founder-review/REVIEW.md`) plus an offline re-score of the
2026-09-25 captured benchmark findings produced the **Founder-review batch — FR-*** (end of file).
The review's safety-enforcement, live-proof, adjudication and build findings
(F01/F02/F05/F06/F07/F08/F14) are already filed as OWNER/LIVE `PR-A..E` / `NC-O1..O5` / `P1-10`;
the review only reinforces them — do NOT re-file or attempt them (they are cross-referenced as
skip-only `FR-O*`). Select the loop-consumable FR items in this order before resuming the ordinary
queue: **FR-4 → FR-3 → FR-1 → FR-2 → FR-5 → FR-6 → FR-7 → FR-8**. **BM-1 is superseded by FR-4** —
an offline re-score showed BM-1's confidence-floor half is near-useless (the catch-all noise is
emitted at confidence ≥ 0.5); the effective lever is an evidence/confirming-leg requirement scoped
to the two catch-all classes, never a global one. Honour the non-negotiables: keep `config.yaml`
safe (new gates ship OFF; a default flip that trades recall stays owner-gated on a measured delta),
a caller test + negative control per item, `full` green before close.

**2026-09-26 re-analysis batch (offline; reopens loop work after the filed offline
pool was exhausted):** With P1-3's offline consolidation and all of P3-1 landed, an
Opus re-analysis pass over the production pipeline (evidence ledger, server auth,
SARIF adapter, report generator) surfaced four new evidence-based, mostly
offline-loop-consumable items — the **Re-analysis batch — RA-*** at the end of this
file. Each is grounded in a `file:line` observation verified against the checkout.
Select them in this order before resuming any older queue work: **RA-1 → RA-2 →
RA-3 → RA-4**. Honour the non-negotiables (safe `config.yaml` defaults; a caller test
+ negative control per item; `full` green before close). RA-3 is the offline SARIF
slice of P2-3 (cross-referenced, not a duplicate); the Burp-tab half stays under P1-5.

**2026-09-27 swarm-comparison batch (offline; reopens loop work):** A source-inspected
comparison against `Armur-Ai/Pentest-Swarm-AI`
(`reviews/2026-09-27/swarm-comparison/REVIEW.md` + `VERIFICATION.md`) reproduced nine local
verification/shipping defects and proposed six borrowable architectural patterns — the
**Swarm-comparison batch — SC-*** at the end of this file. The review's A1–A9 findings are
re-grounded there against current source (each `file:line` re-read this session); several are
follow-ons to already-closed items and are scoped to the *remaining* gap, NOT a re-file:
**SC-2 ⊃ FR-6**, **SC-3 ⊃ FR-5**, **SC-5 ⊃ RA-6/R07/RA-5**, **SC-9 ⊃ PR-11/NC-O1**. Select the
loop-consumable items in this order before resuming older queue work:
**SC-1 → SC-2 → SC-3 → SC-4 → SC-5 → SC-6 → SC-7 → SC-8**. SC-9 folds into PR-11's offline
half (reinforcement, not a new dup). SC-10..SC-15 are larger architecture/product items whose
**retention is gated on a matched-budget measurement** (keep only if it adds verified coverage
without new false positives / scope violations) — treat their efficacy runs as OWNER/LIVE.
Honour the non-negotiables: safe `config.yaml` defaults (new gates ship OFF), a caller-level
test + negative control per item, `full` green before close. Do NOT import upstream code
(**AGPL-3.0**) — reimplement patterns and document provenance.

**2026-09-28 swarm-refresh reconciliation (offline; do this before selecting new work):** A
delta-focused refresh (`reviews/2026-09-28/swarm-refresh/REVIEW.md` + `VERIFICATION.md`)
re-tested the SC-1..SC-8/FR-7/RA-7/RA-8 batches against the checkout and reproduced seven
residual/new counterexamples — **R1..R7**, filed as **Swarm-refresh batch — 2026-09-28 (R-\*)**
at the end of this file. By the time this note was reconciled against the working tree
(same day), **R1, R3, R4 (admission arithmetic only), R5 and R6 already had uncommitted
production fixes on disk** — re-verified this session by re-running the review's own
`probes.py` plus one isolated follow-up probe against the current working tree (both retained
under the same review directory). **None of the five has a dedicated regression test or a
commit yet** — that is the actual next step, not re-diagnosing them. R2 is genuinely partial
(the `control_outcome` field and gate logic are correct when a validator populates it, but the
exact site the review named has no caller-level test and an omitting validator still defaults
to the legacy/negative reading). R7 is untouched. See CURRENT_STATE.md for the fresh full-suite
result on this working tree and R-item-by-item status. Select **R1 → R3 → R5 → R6 → R4 → R2 →
R7** (write the missing test + commit for the first five; finish R2's caller test and the
analyze()-level site; then R7's caller wiring) before resuming older queue work.

1. Work top-down: finish all `P0` items before `P1`, etc. Within a tier, respect
   `Depends on`.
2. Pick the first item whose checkbox is `[ ]` and whose dependencies are all `[x]`.
3. Implement it on a focused branch/commit. Honour the project's non-negotiables:
   - Keep `harness/config.yaml` at **safe defaults**; new capabilities ship OFF.
     Live toggles go in the git-ignored `config.local.yaml`.
   - Every new pipeline behavior needs a **caller-level test AND a negative
     control** (AGENTS.md). Do not delete `test_pipeline_gate.py` or its
     defect-injection controls.
   - Never read `*ANSWER_KEY*` or a blind target's `app.py`.
   - Run `python -m harness.suite full` (from repo root, isolated venv) before
     marking an item done; label any accuracy/recall claim **owner-reported**
     unless produced by a real-model/blind run in the same session.
4. When done, flip the checkbox to `[x]`, add a one-line `Result:` under the item
   (commit SHA + what was verified, with the VERIFIED/SUPPORTED/CLAIMED tag), and
   update `CURRENT_STATE.md`.
5. If an item is partially done, leave it `[ ]` and record progress in `Result:`.

Evidence tags: **VERIFIED** (ran/read directly), **SUPPORTED**, **CLAIMED**,
**INFERRED**. Do not promote a tag without new evidence.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked (say why).

---

## P0 — Trust blockers (nothing should be relied on until these land)

### [x] P0-1 — Wire the EvidenceLedger into the live detection/confirmation path
- **Result (VERIFIED):** `25a737a` — EvidenceLedger wired into the live pipeline:
  HYPOTHESIS (base_agent), PLANNED_ACTION/AUTHORIZATION_DECISION/EXECUTION
  (TargetTransport), VALIDATION_DECISION (orchestrator_confirm), FINDING_REVISION
  (confirmation_gate), OBSERVATION "never-tested" (not counted toward completeness);
  append-only `ledger_events` store table (INSERT OR IGNORE) + `GET
  /findings/{ref}/evidence` + report line. Instrumentation-only (verdict/severity/
  scope/control-flow unchanged; all emits wrapped). 4 new caller-level tests
  (positive complete=True incl. persisted replay, negative control complete=False
  via a distinct no-validator path, provenance, no-case_ref no-op). Full suite
  2325 OK / 2 skip, exit 0. Follow-on nit filed: P3-4.
- **Domain:** Architecture / Trust · **Effort:** M · **Depends on:** none
- **Evidence (VERIFIED):** `EvidenceLedger` / `EventType.EXECUTION` /
  `record_execution` appear only in [harness/evidence_ledger.py](harness/evidence_ledger.py)
  and its tests; no production module records into it. The ledger docstring itself
  says pipeline wiring is "the follow-on."
- **Problem:** The append-only, provenance-stamped record that lets a finding be
  reconstructed without server logs (the review's strongest-differentiator
  proposal) is inert. A live finding cannot answer: what was sent, what came back,
  which model/version/prompt, how to reproduce.
- **Recommendation:**
  - Emit `HYPOTHESIS` from `agents/base_agent.py` when an agent produces a finding.
  - Emit `PLANNED_ACTION` + `AUTHORIZATION_DECISION` + `EXECUTION` from
    `run_context.TargetTransport.execute` (it already builds an `ExchangeArtifact`
    — attach the ledger event at the same point, carrying request/response refs).
  - Emit `VALIDATION_DECISION` from `orchestrator_confirm._validate_findings`.
  - Emit `FINDING_REVISION` from `confirmation_gate.apply_confirmation_suppression`
    (severity/verdict changes are already computed there).
  - Persist the per-run stream in `store.py`; expose `reconstruct(finding_ref)` and
    `reproduction_recipe(finding_ref)` via the findings API and report.
  - Stamp `Provenance.capture(config=..., model=..., prompt_version=...)` on every
    event.
- **Acceptance criteria:**
  - A caller-level test drives one exchange end-to-end and asserts
    `ledger.reconstruct(finding_ref)["complete"] is True` with non-empty
    `what_sent`/`what_came_back`/`why_concluded`.
  - Negative control: a finding whose validator never ran has `complete=False` and
    an honest `what_was_never_tested` entry.
  - `reproduction_recipe` returns runnable steps + a config fingerprint.
- **Impact:** Transformational.

### [x] P0-2 — Run-derived confirmation trust tiers (retire the static table)
- **Result (VERIFIED):** `533928c` — `harness/leg_self_test.py` fires each active
  leg against the owned loopback fixture + paired negative control and returns the
  run's live set, threaded through the existing `live_verified_markers` override.
  Demotion-only (never promotes), OFF by default (`leg_self_test.enabled`, not in
  config.yaml → shipped behavior byte-for-byte unchanged, static
  `LIVE_VERIFIED_MARKERS` stays the offline default). Fail-safe: unavailable leg /
  fixture-startup failure / crashed self-test all yield an empty set (demote-all),
  never silent stay-live; self-test runs under a 127.0.0.1-scoped SafetyGate. +8
  tests (healthy-leg negative control, defect-injection demotion, 3 fail-safe
  paths, off-by-default no-op). Full suite 2333 OK / 2 skip, exit 0. To measure/
  retire the static table on a run, set `leg_self_test.enabled: true` per-run/CI.
- **Domain:** Reliability / Trust · **Effort:** M · **Depends on:** none
- **Evidence (VERIFIED):** `LIVE_VERIFIED_MARKERS` / `PROVISIONAL_MARKERS` in
  [harness/confirmation_gate.py:202-270](harness/confirmation_gate.py) are hand-maintained
  frozensets seeded from historical "session-11" / "Phase 2" fixture runs.
- **Problem:** "live-verified" is asserted, not measured. If a leg silently
  regresses, the gate keeps stamping its class as trustworthy → false confidence.
- **Recommendation:** Add a per-run (or CI-gated) **leg self-test** that fires each
  active confirmation leg against a local vulnerable fixture AND a paired negative
  control, and emits the set of classes that actually confirmed-true-and-refuted-
  false this run. Feed it via the existing `live_verified_markers` override seam in
  `leg_tier()` / `apply_confirmation_suppression()` (already designed for this).
  Keep the static frozenset only as the offline default; the override wins.
- **Acceptance criteria:**
  - A class not passing its self-test this run is treated as `provisional`
    (capped at medium), never `live`.
  - Test: injecting a broken leg (defect injection) drops its class from the live
    set and demotes its findings; negative control: a healthy leg stays live.
- **Impact:** High.

### [x] P0-3 — Reconcile existing benchmarks and measure subsequent changes reproducibly
- **Result (owner-reported/VERIFIED-in-run, 2026-09-22):** ran RB-8's fixed
  `run_blind_eval.py` live against real `qwen3:8b` Ollama at HEAD `0f047e8`
  (`.venv-rationalisation` venv, defaults: `fail_open_mode=curated`,
  `quarantine_leads=1`, `cross_identity_reject=0`). 2/2 `confirmed_vuln`
  exchanges detected; 0/5 unique control URLs clean by raw count (a URL-reuse
  artifact inflates this slightly — see report caveat); config fingerprint
  `514b4afd650ae1103f0c1621df2351ec111b2fcc72e3823426344c68d6e60e83`. Full
  metrics, exact command, checkout state and caveats:
  [reviews/2026-09-22/BLIND_SCORECARD_P0-3.md](reviews/2026-09-22/BLIND_SCORECARD_P0-3.md).
  This satisfies the acceptance criterion (re-runnable command + results file
  with the metrics + config fingerprint) as a single-sample measurement. NOT
  done: the `run_eval_n_times` variance pass (n≥5) RB-8 also built — one
  pass took ~24 min, so 5 would be ~2h of local compute; RB-2b's `curated`
  default flip should be gated on that variance run, not this single sample.
- **Status correction (2026-09-20, source inspected; results historical/reported):**
  Real-model runs already exist in `testing/SCORECARD.md`, dated 2026-09-20,
  committed by `95b124a` and revision-pinned by `02de8bf`. The original absence
  claim below is superseded. Do not create a first benchmark from scratch or use
  root `SCORECARD.md` to dismiss this evidence. INV-1 inventories remaining
  reproducibility/metric gaps and prepares measurement of subsequent changes.
- **Domain:** Efficacy / Evaluation · **Effort:** M · **Depends on:** P0-1 (nice), else none
- **Evidence (VERIFIED):** [SCORECARD.md](SCORECARD.md) is `model=stubbed/none`
  (a plumbing check); [CURRENT_STATE.md](CURRENT_STATE.md) states no real-model or
  blind run was performed. There is no current precision/recall/FP number.
- **Problem:** The product's core claim (it finds/confirms real vulns) is
  unmeasured. This blocks trust and any go-to-market.
- **Recommendation:** Stand up ONE labeled corpus (e.g. a local known-vulnerable
  target the license permits) and a single driver that runs a real Ollama model,
  records precision, recall, FP rate, confirmation rate, latency, token cost, and a
  `config_schema.config_fingerprint`. Publish under `reviews/<date>/` as
  owner-reported with the exact command and model tag.
- **Acceptance criteria:** A re-runnable command + a results file with the metrics
  above and a config fingerprint. Numbers labeled **owner-reported/VERIFIED-in-run**,
  never promoted from stubbed results.
- **Impact:** High.

### [x] P0-4 — Revert committed scope + add a safe-default CI guard
- **Result (VERIFIED):** `0e993da` — committed `server.allowed_hosts` reverted to
  `[]` (live scope moved to the git-ignored `harness/config.local.yaml`); fixed the
  interleaved `pattern_memory`/`reporting` comments (comments only). Added
  `SafeDefaultGuardTests` (harness/test_config_schema.py): loads the real committed
  config, asserts safe defaults, and as a negative control mutates a fresh reload
  one flag at a time to its unsafe value and asserts each is caught — covering
  non-empty allowed_hosts, `validators.active_enabled`, `allow_mutating_replay`,
  `autonomous_discovery.enabled`, `oracle.enabled`, the engagement toggles, and
  `coordinator.cloud_*`. No test weakened (scope-dependent tests self-provide
  scope). Full suite green, exit 0.
- **Domain:** Safety hygiene · **Effort:** S · **Depends on:** none
- **Evidence (VERIFIED):** [harness/config.yaml](harness/config.yaml) ships
  `allowed_hosts: ["localhost","127.0.0.1"]` (its own comment says revert to `[]`);
  contradicts CLAUDE.md hazard #2. Also: interleaved/out-of-order comment blocks
  near the `reporting:` / `pattern_memory:` keys.
- **Recommendation:** Revert `server.allowed_hosts` to `[]` in the committed config;
  move live scope to `config.local.yaml`. Fix the interleaved comments. Add a CI
  check that FAILS if committed `harness/config.yaml` has non-empty `allowed_hosts`,
  or any of `validators.active_enabled`, `allow_mutating_replay`,
  `autonomous_discovery.enabled`, `oracle.enabled`, engagement toggles, or
  `coordinator.cloud_*` flipped to a non-safe value.
- **Acceptance criteria:** Guard test passes on a clean tree and fails when a flag
  is flipped in the committed file.
- **Impact:** Medium (prevents a whole class of drift).

---

## P1 — Product blockers (before regular practitioner use)

### [x] P1-1 — Prompt-injection isolation for target responses
- **Result (VERIFIED):** `33392c9` — added a fence-breakout neutralization layer on
  top of the pre-existing per-request nonce fence: `_neutralize_fence_breakout()`
  defangs any `<<<UNTRUSTED-DATA-...>>>` lookalike in body/headers/analyst_note so
  target content cannot forge or terminate the boundary. Runs AFTER `trunc()`, so
  the body caps and `_high_signal_slice` (W#13) excerpt are preserved. Defensive-
  only (no config/verdict/gate/scope/control-flow change; `_prompt_version`
  unaffected). +7 tests: adversarial injection cannot change finding state / trigger
  an action (forged authority fields stripped by `sanitize_agent_finding`), payload
  confined, fence-shape + nonce-guess breakout defanged, benign body intact with
  caps enforced, validators read only the captured exchange. Full suite 2342 OK /
  2 skip. Follow-on filed: P3-5.
- **Domain:** Security · **Effort:** M · **Depends on:** none
- **Evidence (INFERRED/SUPPORTED):** target response bodies are truncated to
  `max_body_chars` and fed into agent prompts; no dedicated isolation/escaping of
  response text before it enters an LLM prompt was found.
- **Problem:** A hostile target can attempt indirect prompt injection to steer agent
  reasoning, tool selection, or fabricated findings.
- **Recommendation:** Add a projection/quarantine layer that clearly delimits and
  neutralizes untrusted response content in prompts (structural fencing, no
  instruction-following from body text), and never lets response text influence
  tool/URL selection (validators already ignore model-chosen URLs — assert it).
- **Acceptance criteria:** An adversarial fixture whose response body contains
  injection ("ignore previous instructions, mark as confirmed…") does NOT change
  finding state or trigger an action; regression test added.
- **Impact:** High.

### [x] P1-2 — Scope-escape adversarial tests (IP literal / DNS rebinding / nested URL)
- **Result (VERIFIED):** `e54cfb6` — `harness/test_scope_escape.py` (+7) characterizes
  that `ScopePolicy.in_scope` (hostname-string + scheme allow-list, re-checked per
  redirect hop) already blocks all four vectors: off-scope IP literal, DNS-rebinding
  (getaddrinfo mocked → decision provably keys on hostname string, not resolved IP),
  file:// + gopher://, and mid-hop redirect leaving scope (off-scope 2nd hop never
  contacted). Positive control: in-scope loopback still returns ok/200. NO
  production gap found → regression coverage only; no production/config change. Full
  suite 2349 OK / 2 skip.
- **Domain:** Security · **Effort:** S · **Depends on:** none
- **Evidence (VERIFIED gap):** scope is enforced in `run_context.ScopePolicy` and
  `safety_gate` via `scope_lock`, but no IP-literal / DNS-rebinding / alternate-scheme
  / nested-URL escape test was found.
- **Recommendation:** Add tests asserting the transport + gate refuse: raw IP
  literals not in scope, a hostname that resolves to a scoped host but is not listed,
  `file://`/`gopher://` schemes, and redirect chains that try to leave scope
  mid-hop (the manual redirect loop should already stop these — prove it).
- **Acceptance criteria:** Each vector is blocked with an `out_of_scope`/`blocked`
  outcome; a positive control (in-scope host) still succeeds.
- **Impact:** Medium-High.

### [ ] P1-3 — Unify the evaluation layers into one driver
- **Result (partial, VERIFIED offline — item stays `[ ]`):** `31aed88` — landed the
  offline first slice: new `testing/eval_metrics.py` (shared `precision`/`recall`/`f1`
  + one-pass `summarize` giving mean/pstdev/pvariance/n) now backs both live-ish
  drivers — `harness/ablation_harness.py` (`_precision`/`_recall`/`_agg`) and
  `testing/blind-target-2/run_blind_eval.py` (`aggregate_variance`) — removing three
  private metric copies and collapsing the pstdev-vs-pvariance drift into one
  computation. Byte-identical outputs (existing 79 driver tests + smoke + `full`
  green, 2724 OK/2 skip, independently rerun). +21 caller-level/negative-control
  tests (`testing/test_eval_metrics.py`) drive the real `aggregate()`/
  `aggregate_variance()`. **Slice 2 landed `491b982`:** rerouted the canonical
  `testing/strict_score.py` (both scorers' per-class + micro precision/recall/F1)
  onto the shared primitives, byte-identical (golden captured from the pre-reroute
  scorer via git-stash diff; +9 tests in `test_strict_score_eval_metrics_reroute.py`).
  **Slice 3 landed `80b9050`:** rerouted `testing/score.py`'s scalar precision/recall/F1
  (per-category + micro) onto the shared primitives, byte-identical (+6 golden/negative-
  control tests; `full` green 2724/38/221/42, exit 0); `nightly_precision.py` is covered
  transitively (it delegates to `score.score`). **Offline metric-consolidation is now
  complete:** grep-verified that the remaining older layers (`eval_health.py`,
  `score_provenance.py`, `evidence_audit.py`, `coverage_summary.py`,
  `evaluation_integrity/`) carry NO precision/recall/F1 arithmetic — they answer
  different questions (provenance, stage health, coverage buckets, evidence
  resolvability) and are correctly NOT rerouted. **Remaining (why still `[ ]`):** only the
  single-command scorecard that emits scorecard+provenance+health+coverage in one run —
  needs a live model run, OWNER/LIVE, out of offline loop scope. Map:
  [reviews/2026-09-26/P1-3_METRICS_CONSOLIDATION.md](reviews/2026-09-26/P1-3_METRICS_CONSOLIDATION.md).
- **Domain:** Evaluation / Maintainability · **Effort:** M · **Depends on:** P0-3
- **Evidence (VERIFIED):** overlapping layers — `testing/score.py`,
  `testing/nightly_precision.py`, standalone `evaluation_integrity/`, and
  `harness/{score_provenance,evidence_audit,coverage_summary,eval_health}.py`.
- **Update (2026-09-22, VERIFIED by source inspection):** the layers now also include
  `testing/blind-target-2/run_blind_eval.py` (`build_scorecard`, `_VARIANCE_METRICS`) and
  `harness/ablation_harness.py` (per-arm tp/fp/fn, see ER-2's evidence), each recomputing
  precision/controls metrics its own way. Concrete cost: B2-3's metric landed in one driver only,
  shipped a url-only attribution bug (B2-3b) and never reached the variance aggregation. P0-3 is
  `[x]`, so the dependency is met. Suggested first slice: one shared metrics module (controls-clean
  raw + issue-level, precision/recall, variance) imported by both `run_blind_eval.py` and
  `ablation_harness.py`, before touching the older layers.
- **Recommendation:** Consolidate to one evaluation entry point that consumes the
  provenance/health helpers as libraries, with a single documented output schema.
- **Acceptance criteria:** One command produces the scorecard + provenance + health
  + coverage summary; the old layers either call it or are removed with a mapping
  note in `reviews/<date>/`.
- **Impact:** Medium.

### [x] P1-4 — Named operating profiles
- **Result (VERIFIED):** `1e084e1` — 5 presets (passive-only/laptop/workstation/
  deep-assessment/ci-eval) in `config_schema.OPERATING_PROFILES` bundle existing
  knobs, selected via one opt-in `operating_profile` key (ships "none" → unset is a
  byte-for-byte no-op, returns the same object). Composition rule: a profile knob
  applies only where the value still equals the shipped baseline; an explicit
  operator value wins. Resolved config flows into all orchestrator sub-components.
  passive-only asserted to leave every active/mutating/discovery/engagement/cloud
  flag off. Profiles are Python-defined so P0-4 SafeDefaultGuardTests still passes
  with the new key. +16 tests; full suite 2365 OK / 2 skip.
- **Domain:** UX / Performance · **Effort:** S · **Depends on:** none
- **Evidence (VERIFIED):** `orchestrator.__init__` reads 10+ behavioral toggles;
  config comments document a real perf cliff (38 agents × serialized inference on
  one GPU tripping the circuit breaker).
- **Recommendation:** Ship presets — `passive-only`, `laptop`, `workstation`,
  `deep-assessment`, `ci-eval` — each a named bundle of the existing knobs
  (routing fail-open mode, concurrency, active flags, model sizes). Select via one
  config key / one API param.
- **Acceptance criteria:** Selecting a profile sets the documented knob values; a
  test asserts `passive-only` leaves every active/mutating/discovery flag OFF.
- **Impact:** Medium.

### [ ] P1-5 — Verify and document the Burp UX end-to-end
- **Domain:** UX / DX · **Effort:** M · **Depends on:** none
- **Evidence (UNKNOWN):** the Java extension (`burp-extension/`) was not built or
  run in review; AGENTS.md forbids claiming a `gradle shadowJar` build without a JDK.
- **Recommendation:** With JDK 17+, build the JAR, load it in Burp, and document
  (with screenshots) the real workflow: set harness URL, analyze, view findings +
  lifecycle state, inspect exact traffic sent, stop a run, mark FP/retest, export.
  File any gaps as new backlog items.
- **Acceptance criteria:** A `docs/BURP_UX.md` with a verified walkthrough and the
  build command actually run (label VERIFIED with the JDK/Gradle versions).
- **Impact:** Medium-High.

### [x] P1-6 — Extract active/engagement flags into one policy object
- **Result (VERIFIED):** `4054135` — new `harness/engagement_policy.py`
  (`EngagementPolicy.from_config`) extracts the 13 active/engagement toggles from
  `Orchestrator.__init__`; purely behavior-preserving (same keys/defaults/coercion/
  None-guard), fed the already-resolved config, each `self.<attr>` a thin alias so
  downstream readers are untouched; per-request driver_execute gate unchanged. Flags
  owned elsewhere (validators active/mutating, autonomous_discovery, coordinator.cloud_*,
  retry_budget) deliberately not folded in (confirmed never read in __init__). config.yaml
  unchanged; SafeDefaultGuardTests green. +15 tests (safe-defaults enumeration + parity
  vs reconstructed old inline reads). Full suite 2398 OK / 2 skip. Gate verified parity
  field-by-field and re-ran the test subsets.
- **Domain:** Maintainability · **Effort:** S · **Depends on:** none
- **Evidence (VERIFIED):** [harness/orchestrator.py:199-274](harness/orchestrator.py).
- **Recommendation:** Introduce `EngagementPolicy`/`ActivePolicy` dataclasses with
  `from_config`, so the orchestrator holds one policy object and "what is actually
  on" is answerable and testable in one place.
- **Acceptance criteria:** Behavior-preserving refactor; a test enumerates the
  policy and asserts safe defaults; `full` suite stays green.
- **Impact:** Medium.

---

## P2 — Differentiators (create competitive advantage)

### [ ] P2-1 — Business-reasoning agent feeding the chaining loop  ★ (requested)
- **Review gate (2026-09-20):** Complete INV-3 before implementation; inventory
  existing business-logic/workflow context and reuse its consumers. Zero observed
  chains does not by itself prove a missing semantic model. Prefer one bounded
  application-context planning pass over another per-exchange specialist. Require
  ON/OFF measurement of distinct proof-linked chains, false chains, requests,
  model cost and operator time before claiming an improvement.
- **Domain:** AI / Product / Efficacy · **Effort:** L · **Depends on:** P0-1 (ledger),
  benefits from P0-3
- **Problem it solves:** Today routing and detection are largely *per-exchange* and
  *class-shaped* (fast_path + specialist agents). The engagement/chaining machinery
  (`orchestrator_chain.py`, `engagement_builder.py`, `worklist_investigator.py`,
  `chain_linker.py`, `second_order.py`) can link findings→capabilities, but it has
  **no model of what the application is for** — its roles, business objects,
  value-bearing workflows, and state transitions. That is exactly the context a
  human pentester uses to build high-value chains (e.g. "this is checkout → a price
  field is client-trusted → chain IDOR on the order object into a discount →
  privilege escalation to fulfilment"). Without it, chaining is mechanical and
  business-logic/authorization flaws (the highest-severity, lowest-DAST-coverage
  classes) are under-found.
- **What to build:** A **BusinessContextAgent** that consumes the discovered
  surface + captured exchanges (and, when available, OpenAPI via `openapi_ingest.py`
  and role crawl output via `role_crawl.py`) and produces a structured, host-scoped
  **Application Semantic Model (ASM)**:
  - `roles`/`principals` and their apparent privilege ordering
  - `business_objects` (e.g. order, invoice, user, cart) with their identifiers and
    which endpoints read/write them
  - `workflows` (ordered multi-step flows: e.g. add-to-cart → checkout → pay →
    fulfil) and their state transitions
  - `value_flows` / trust assumptions (client-supplied fields the server appears to
    trust: price, quantity, role, is_admin, account_id)
  - `sensitive_sinks` (payment, PII export, admin config, file store)
  - `chaining_hypotheses`: ranked candidate chains linking a plausible weakness on
    object/workflow A to impact on B, each with the concrete endpoints involved.
- **How it feeds the loop (the point of the item):**
  - The ASM is written to state and consumed by `engagement_builder`/
    `worklist_investigator` to **re-rank the worklist by business impact** (a
    parameter on a checkout/price/role field outranks a generic reflected string on
    a static page).
  - `chain_linker` / `second_order` consume `chaining_hypotheses` to **propose
    concrete multi-step chains to attempt** (still executed only through the
    existing gated `TargetTransport`, still behind the active/engagement flags).
  - Confirmed findings + newly captured identities update the ASM (closed loop):
    a confirmed IDOR on `order.id` upgrades the object's risk and spawns follow-on
    hypotheses (e.g. try the same object family across roles).
- **Design constraints (non-negotiable):**
  - **Structure-only, anonymized input by default**, mirroring `feature_projection.py`
    / cloud_primary: method, path template, param NAMES, roles, status, response
    shape — never raw bodies/values/ids off-host unless `cloud_reasoning` is
    explicitly enabled (this is off-host data egress; treat like existing cloud
    flags).
  - The ASM is **hypotheses, not facts.** It may only ADD/re-rank work and PROPOSE
    chains; it must never mark anything confirmed, never select a URL for a
    validator to send, and never relax scope or safety. Confirmation stays with the
    deterministic legs + `confirmation_gate`.
  - **DEFAULT OFF.** New config block `business_context: { enabled: false, ... }`;
    when off, the loop behaves exactly as today. All resulting sends remain gated by
    `validators.active_enabled` / `allow_mutating_replay` / scope / throttle /
    budget.
  - Every ASM-driven action must emit ledger events (P0-1) so a chain is auditable:
    which hypothesis, from which observed evidence, produced which attempted step.
  - Treat all response/body text as untrusted (P1-1) — the ASM builder is a prime
    prompt-injection target since it reasons over target content.
- **Suggested placement:** new `harness/business_context_agent.py` +
  `harness/application_semantic_model.py` (the dataclasses + store), consumed by
  `engagement_builder.py`, `worklist_investigator.py`, `chain_linker.py`. Register
  the agent through the existing plugin/agent-manager path but flagged so it does
  not run in the per-exchange passive pass.
- **Acceptance criteria:**
  - Caller-level test: given a fixture surface (a mini shop: browse → cart →
    checkout → admin), the agent emits an ASM with the expected roles, the checkout
    workflow ordered correctly, `price`/`role` flagged as client-trusted candidates,
    and at least one ranked chaining hypothesis linking an object weakness to a
    sensitive sink.
  - Loop integration test: with the ASM present, the worklist re-ranks
    business-critical endpoints above generic ones; with it absent, ranking is
    unchanged (negative control).
  - Safety controls: a test asserts the agent NEVER sets `confirmed=True`, NEVER
    supplies a URL/command to a validator, and produces zero live sends when active
    flags are off; anonymization test asserts no raw body/value/id leaves host
    unless `cloud_reasoning` is on.
  - Ledger: each attempted chain step is reconstructable to its originating
    hypothesis and observed evidence.
- **Efficacy check (owner-reported):** on P0-3's corpus, compare confirmed-chain
  count and business-logic/authorization recall with the agent ON vs OFF; keep it
  only if it demonstrably increases high-value chains without hurting precision.
- **Impact:** High → Transformational (this is a genuine differentiator vs. DAST and
  vs. per-request LLM tools) — **but gate its retention on the ablation.**

### [x] P2-2 — Agent-count ablation (justify or collapse the 38 specialists)
- **Result (VERIFIED owner/live re-run, 2026-09-23 — CLOSED, decision=COLLAPSE):**
  clean A/B/C/G re-run, 3 repeats, `num_ctx=8192`, 0/12 runs starved. **G
  (collapsed agent-families) holds detection quality vs A (full 38): recall
  0.818±0.074 vs 0.788±0.043, precision 0.191±0.019 vs 0.176±0.004** — parity
  within noise — at ~10% fewer model calls (142.7 vs 157.7), ~6% fewer tokens,
  ~15% less wall. Ladder A≈G ≫ B (single agent, recall 0.394) ≫ C (0 agents,
  0.182) shows the quality lives in the *routed multi-specialist* behavior, which
  G preserves and B destroys → the right collapse is agents→families, not
  agents→one. Acceptance met (results table + decision + numbers):
  [reviews/2026-09-23/ABLATION_P2-2_RERUN.md](reviews/2026-09-23/ABLATION_P2-2_RERUN.md)
  + [ablation_results_A-B-C-G.json](reviews/2026-09-23/ablation_results_A-B-C-G.json).
  Cost win is MODEST (fixed coordinator+critique floor + larger family prompts
  offset the fan-out collapse — do not oversell families as a big efficiency
  gain; the win is quality-parity + fewer serial round-trips + smaller
  starvation surface). Enabled via `coordinator.routing_mode: "families"` in
  `config.local.yaml`; committed default stays `"agents"` (byte-for-byte revert,
  AR-1). Residuals: E (minus-graph) still not run (needs engagement corpus,
  `NO_GRAPH_RESIDUAL`); single corpus/model/3-repeats — parity, not a proven
  improvement; low absolute precision is orthogonal (B2-3/B2-5/RB-2b).
- **Why this supersedes the 2026-09-22 attempt:** that run was invalidated by a
  circuit-breaker starvation cascade (qwen3:8b at its 32768 default context =
  10GB/41%-CPU → 80-100s calls → 3×240s timeouts trip the shared breaker →
  silent zeroing). Root-caused to VRAM spill (harness prompts p99 <4k tokens, so
  the 32k window is waste): `num_ctx=8192` → 6.2GB/100% GPU/~3s per call. A's
  recall recovered 0.182 (degraded) → 0.788 (healthy) from that fix alone, so
  the old A/B/D/F numbers measured a broken pipeline and are not comparable.
- **Result (SUPERSEDED — owner-reported, 2026-09-22, INCONCLUSIVE):** ran RB-7's ablation harness live (`testing/test-target/
  run_ablation_live.py`, new owner-run driver) against the PixelMart corpus,
  real `qwen3:8b`. Does NOT answer keep/collapse: D (minus-critique) and F
  (curated-routing) each independently hit the SAME reproduced failure — 3
  sequential agent calls timed out at 240s (720s total), tripping
  `harness.circuit_breaker`'s shared "ollama" breaker OPEN, which silently
  zeroed every remaining agent call for the rest of that run (0 error
  surfaced) — exactly the failure mode `harness/config.yaml`'s own comments
  already document from a prior incident on this hardware; the existing
  mitigation (`max_parallel_agents: 1`, 240s timeout) is evidently not
  sufficient here. Both degenerated to C's exact zero-agent numbers;
  reproduced independently twice (separate processes), so this is systematic.
  A ran but with ~5/22 exchanges critique-unreviewed (milder version of the
  same issue, later in its run). One clean data point: B (single forced
  agent, 0 errors) hit recall 0.364 vs A/C's degraded 0.182 — not strong
  enough alone to decide anything. Full diagnosis + a single-exchange log
  trace proving the mechanism + concrete next steps before re-attempting:
  [reviews/2026-09-22/ABLATION_P2-2.md](reviews/2026-09-22/ABLATION_P2-2.md).
  E (minus-graph-loop) not run — residual, needs an owner engagement corpus
  (see `NO_GRAPH_RESIDUAL`). **This item stays `[ ]`**: the harness (RB-7) is
  built and correct; what's missing is a trustworthy real-model run, which
  needs the reliability fix in the report first.
- **Domain:** AI / Architecture · **Effort:** L · **Depends on:** P0-3
- **Evidence (VERIFIED):** ~38 agent modules, mostly narrow LLM classifiers; config
  comments repeatedly cite "LLM label variance" as the main detection risk; no
  ablation exists.
- **Recommendation:** Run the ablation set — (A) current, (B) one strong model +
  tools, (C) rules+validators only, (D) no critique, (E) no graph, (F) stronger
  single model + reduced orchestration — measuring precision, recall, confirmed
  count, FP, latency, model calls, tokens, VRAM. If a small set of agent "families"
  + the deterministic router matches recall, collapse to them.
- **Acceptance criteria:** A results table under `reviews/<date>/`; a decision
  recorded (keep/collapse) with the numbers behind it.
- **Impact:** High (may REMOVE complexity).

### [ ] P2-3 — Surface the reproduction recipe in Burp + export (SARIF/markdown)
- **Progress (2026-09-26):** the offline SARIF-export half landed as **RA-3 (`fbf43d1`)** —
  `GET /report/sarif`. Remaining (keeps this `[ ]`): surfacing the reproduction recipe in the Burp
  tab, which needs the P1-5 (OWNER/LIVE) Burp build.
- **Domain:** UX / Trust · **Effort:** M · **Depends on:** P0-1, P1-5
- **Recommendation:** Once the ledger is wired, expose `reproduction_recipe` in the
  findings API, the report, and the Burp tab; add SARIF + markdown export so
  findings are portable into common reporting/triage systems.
- **Acceptance criteria:** A confirmed finding exports with its request/response
  steps + config fingerprint; SARIF validates against schema.
- **Impact:** High.

---

## P3 — Scale / commercialization (only once adoption + efficacy exist)

### [x] P3-1 — Captured-data retention & redaction policy for the SQLite store
- **Result (VERIFIED offline — DONE):** all three recommended capabilities delivered and
  tested: **redaction** already satisfied for the sensitive byte path by FR-2/PR-9
  (`run_context._artifact` redacts before `put_evidence_blob`); **retention/expiry**
  (`f45f979`, config-gated OFF); **wipe-engagement** as a callable (`81050fd`) with the
  `validation_runs` orphan cascade (`4b3fab0`) and an opt-in auth-gated
  `DELETE /engagement/{host}/evidence` endpoint (`3b83f0e`, `server.enable_wipe_endpoint`
  ships false, tracked in the NC-3 drift manifest). Full suite green throughout (harness
  2738 OK/2 skip, exit 0). **Optional non-blocking follow-on (not in the P3-1 recommendation):**
  a background retention *scheduler* / a symmetric retention-apply endpoint — retention is
  operator-callable today (`apply_retention_from_config`); auto-triggering it is a deployment
  concern a future session or the owner can add if wanted.
- **Result (partial, VERIFIED offline — superseded by DONE above):** `f45f979` — landed the
  retention/expiry deliverable, config-gated OFF by default: `store.py` gains
  `purge_evidence_blobs_older_than` / `apply_retention_policy` / `apply_retention_from_config`,
  and `config.yaml` gains `store.evidence_retention_days: 0` (0 = keep forever =
  current behavior, byte-identical; nothing auto-invokes it yet). +4 caller-level
  tests (real temp DB): selective purge, a default-OFF no-op negative control,
  non-positive rejection, config consumer. Safety drift manifest unchanged (retention
  is not a traffic/egress toggle) and SafeDefaultGuardTests green. Full suite green
  (harness 2728 OK/2 skip, exit 0).
- **Result (partial 2, VERIFIED offline — item stays `[ ]`):** `81050fd` — landed the
  explicit **`store.wipe_engagement(host)`** action: deletes a host's persisted
  evidence across every confirmed host/finding/case/fingerprint-scoped table
  (findings/test_plans/chains_detected/coverage_overrides/sessions/issue_merges/
  engagement_state by host, ledger_events by finding_ref, proof_records by
  case_id/finding_ref/proof_id, finding_observations/finding_suppressions by
  fingerprint) plus `evidence_blobs`. Content-addressed blob guard: a blob is deleted
  only if in (target-referenced − any-other-host-referenced), the other-host set
  snapshotted before any delete, all in one transaction — so a shared blob can't be
  dropped. Callable-only (no auto-invocation). +4 caller-level tests incl. the
  load-bearing shared-blob-survives control. Full suite green (harness 2732 OK/2 skip,
  exit 0).
- **Result (partial 3, VERIFIED offline — item stays `[ ]`):** `4b3fab0` — `wipe_engagement`
  now cascades into `validation_runs` (deletes rows whose `plan_id` belongs to the host's
  `test_plans`, BEFORE the test_plans delete, in the same transaction), closing the
  orphaned-row gap the prior slice documented (no FK cascade; `PRAGMA foreign_keys` off).
  +1 defect-injection caller test (A's row cleaned, B's survives, `counts["validation_runs"]`
  reported). Full suite green (harness 2733 OK/2 skip, exit 0). **Remaining (why still `[ ]`):**
  header redaction is ALREADY done (FR-2/PR-9); the only open piece is auto-wiring
  retention/wipe to a scheduler or auth-gated endpoint — a separate server-integration slice
  (if it exposes a data-deleting endpoint it must reuse the FR-8 read-auth pattern and ship OFF).
- **Domain:** Security / Privacy · **Effort:** M · **Depends on:** none
- **Evidence (SUPPORTED):** identity headers are in-memory only, but `store.py`
  persists requests/responses that can contain Authorization/Cookie values.
- **Recommendation:** Add configurable at-rest redaction of credential headers,
  retention/expiry, and an explicit "wipe engagement" action.
- **Impact:** Medium (blocks enterprise/consultancy use).

### [ ] P3-2 — Supply-chain hardening (lockfile audit, SBOM, pinned tool/image digests)
- **Domain:** Security / Enterprise · **Effort:** M · **Depends on:** none
- **Recommendation:** Emit an SBOM, pin the sqlmap/browser image by digest, and add
  a dependency-vulnerability check to CI.
- **Impact:** Medium.

### [ ] P3-3 — Team mode groundwork (shared findings DB, RBAC, audit log, resume)
- **Domain:** Product / Enterprise · **Effort:** XL · **Depends on:** P0-1, P3-1
- **Recommendation:** Only after the single-user product is proven. Multi-user
  findings store, role-based access, centralized audit log (the ledger is the seed),
  and resumable engagements.
- **Impact:** High for commercialization; premature before efficacy is proven.

### [x] P3-5 — Extend fence isolation to prior-context / knowledge blocks
- **Result (VERIFIED):** `349a51a` — prior-context and knowledge-block text now
  defanged via `_neutralize_fence_breakout` at the fence interpolation point
  (`base_agent.py:250,260`), mirroring body/headers/analyst_note. Behavior-preserving
  (`_prompt_version`, control flow, config untouched). +3 caller-level tests (positive
  defang for both blocks asserting exactly one genuine assembly nonce survives +
  benign byte-identical negative control); module 10/10, full suite 2414 OK / 2 skip,
  exit 0, offline/deterministic.
- **Domain:** Security · **Effort:** S · **Depends on:** P1-1 [x]
- **Evidence (VERIFIED):** filed during P1-1 review. P1-1 fences body/headers/
  analyst_note, but `prior_context` / `knowledge_block` in `base_agent._user_prompt`
  are not run through `_neutralize_fence_breakout`. They are harness-derived
  (sanitized prior findings, methodology notes) so this is low-risk today, but a
  prior finding can echo untrusted body content.
- **Recommendation:** Apply the same fence-shape neutralization to prior-context /
  knowledge blocks that can carry echoed target content.
- **Acceptance criteria:** A test injects a fence-shaped token via prior-finding
  text and asserts it is defanged before entering the prompt; benign prior context
  is unchanged (negative control).
- **Impact:** Low-Medium (defense-in-depth).

### [x] P3-4 — Bound/rotate the in-memory ledger singleton
- **Result (VERIFIED):** `6d1950c` — `EvidenceLedger` bounded to
  `DEFAULT_MAX_EVENTS=5000` with FIFO eviction at the single append point
  (id-index kept consistent); added `reset_default_ledger()` seam; durable replay
  (`ledger_from_store`) constructed unbounded so `reconstruct_persisted` is provably
  unaffected by in-memory eviction. emit/persistence/reconstruction behavior
  unchanged; no config change. +4 tests (bound+eviction+id-consistency, reset,
  real-pipeline negative control: durable reconstruction stays complete after the
  in-memory ledger evicts). Modules 15/15; full suite 2418 OK / 2 skip, exit 0.
- **Domain:** Reliability · **Effort:** S · **Depends on:** none
- **Evidence (VERIFIED):** filed during P0-1 review. `evidence_ledger._DEFAULT_LEDGER`
  is a module-level singleton that grows unbounded in a long-lived server process.
  Production reconstruction reads `reconstruct_persisted` from the durable store, so
  the in-memory copy is effectively test-only today, but it should not accumulate.
- **Recommendation:** Add a per-run scoping / size cap / rotation seam for the
  in-memory ledger; production paths keep reading the persisted store.
- **Acceptance criteria:** A test asserts the in-memory ledger does not grow past a
  bound (or is reset per run); persisted reconstruction still returns complete.
- **Impact:** Low-Medium (hygiene; prevents slow memory growth in a long session).

---

## Explicitly NOT to build yet

- Distributed execution workers / multi-user server mode (before P0-3 efficacy).
- More validators or specialist agents (before P2-2 ablation).
- Additional overlapping engagement concepts (consolidate first).

Rationale: the review found the leverage is in **proving and auditing** what exists,
not adding surface area. Prefer changes that reduce components over ones that add a
new one.

---

## Follow-up recommendations — 2026-09-20 (after the paused item)

Scheduling: finish the already-started/paused item before selecting from this
addendum, even where a new item has higher priority. Then select these items by
their stated priority alongside the existing queue. Existing checkboxes, Result
lines, and CURRENT_STATE.md are preserved; this is not an implementation handoff
or a claim that the paused work is complete.

Review basis: source inspection at `c1133d5` on `reconciliation-backlog`, with no
tracked edits in that checkout before this addition. P0-1/P0-2/P0-4 and
P1-1/P1-2/P1-4 are already recorded as landed. Their suite results remain
historical/reported here; no tests or live runs were performed for this addendum.
Other worktrees have unfinished changes, including transport/session/per-hop
artifact work in `.worktrees/astra-review-fixes` and evidence work in
`../AgenticVibe-impl`. Do not overwrite, cherry-pick, or restart those efforts as
part of backlog selection. Recheck their integration status before implementing
an overlapping recommendation, and reuse applicable work rather than duplicating it.

### [x] P0-5 — Preserve explicit safety overrides when resolving operating profiles
- **Result (VERIFIED):** `c7e0ce4` — `passive-only` is now safety-authoritative:
  all ten active/mutating/discovery/engagement/cloud knobs are force-set False
  unconditionally, applied AFTER the preset merge and even over a supplied
  `explicit_keys` (safety wins over provenance), with a logged warning — it can no
  longer leave an active flag on. Added an `explicit_keys` provenance seam:
  `server.load_config` returns `(cfg, explicit_keys)` where explicit_keys =
  `flatten_explicit_keys(pre-merge config.local.yaml overlay)`, threaded through
  `Orchestrator` into `resolve_operating_profile`, so an enabling profile
  (deep-assessment/workstation) no longer overrides an explicit operator disable.
  none/unset no-op (same object) preserved; committed config.yaml unchanged; P0-4
  SafeDefaultGuardTests still passes; all `load_config` callers updated (keyword-only
  optional kwarg). +16 tests incl. the all-True→passive-only→all-False control.
  Full suite 2375 OK / 2 skip. **Residual limitation:** without provenance
  (`explicit_keys=None`, ad-hoc callers) an explicit-but-baseline-equal disable is
  still indistinguishable from a default under an enabling profile — never less safe
  than pre-P0-5.
- **Domain:** Safety / Configuration · **Effort:** M · **Depends on:** P1-4
- **Evidence (VERIFIED by source inspection):**
  `config_schema.resolve_operating_profile` infers explicit overrides by comparing
  values with `_PROFILE_KNOB_DEFAULTS`. An explicit `false` equal to the baseline
  cannot be distinguished from an inherited default; an existing `true` differs
  from the baseline and survives `passive-only`. Existing profile tests cover
  passive configurations and non-default overrides, not this safety contract.
- **Recommendation:** Preserve explicit configuration-source information through
  profile composition. Define `passive-only` as a strict no-active-traffic profile:
  either disable conflicting active settings or reject the conflict clearly.
  Coordinate with P1-6's policy object if that refactor has started; do not create
  a second policy implementation.
- **Acceptance criteria:** Caller-level configuration/analysis tests show that an
  explicit disable survives `deep-assessment`, and `passive-only` with previously
  enabled active/engagement flags sends no target traffic or rejects startup.
  Negative controls show intentionally enabled scoped validation still works and
  profile `none` preserves existing behavior. Keep shipped defaults safe.
- **Impact:** High.

### [x] P0-6 — Require resolvable evidence for ledger completeness and reproduction
- **Result (VERIFIED):** `5b41eec` — `reconstruct()` now returns a `completeness` block reporting
  reproducibility honestly (`resolvable` = an EXECUTION with BOTH a real request AND response; plus
  `has_conclusion`/`has_execution`/`has_request`/`has_response`/`has_captured_observation`/`missing[]`),
  computed only from events on hand so a durable record whose EXECUTION event failed to persist
  reconstructs as verdict-but-NOT-resolvable (never a silent reproducible record). `complete` kept its
  "a verdict was reached" meaning (separate axis, unchanged — passive path + existing assertions
  untouched). `report_generator` states it at the export boundary ("complete verdict; NOT independently
  reproducible (<missing>)"). 6 tests incl. verdict-only + empty-response + persistence-failure negative
  controls. **Offline-complete; the fuller durable per-hop request/response capture (thin `request_ref`/
  `response_ref`) stays as follow-on evidence-richness work.** Suite: harness 2651 OK (skip 2) /
  evaluation_integrity 42 OK (testing tier's lone failure was a pre-existing timestamp flake, unrelated).
- **Domain:** Trust / Evidence · **Effort:** M · **Depends on:** P0-1
- **Evidence (VERIFIED by source inspection):** `TargetTransport._artifact` records
  the URL as `request_ref` and an HTTP status summary as `response_ref`.
  `EvidenceLedger.reconstruct` sets `complete` from a validation or revision event
  alone. The current redirect loop continues before emitting an intermediate-hop
  artifact. These establish event wiring, not a fully reconstructable exchange.
- **Recommendation:** Link each attempted hop to durable request/response evidence
  and its authorization/session reference. Define completeness against the evidence
  required for that finding type, including passive findings; report missing,
  redacted, or expired material honestly. Reuse pending per-hop artifact work after
  reconciliation. Resolve P3-1's redaction/retention requirements before expanding
  stored sensitive content; do not persist live credential values in recipes.
- **Acceptance criteria:** Through the production caller and a fresh store reader,
  reconstruct a multi-hop validation with method, safe request data, response
  evidence, and required session placeholders. A redirect followed by denial still
  records the sent first hop and the denied next step. Negative controls with a
  missing evidence record or only a revision event cannot claim reproducibility.
  Persistence failures must not silently produce a complete durable record.
- **Impact:** High; strengthens P0-1 without discarding its completed wiring.

### [x] P1-7 — Make investigation target selection and scope authorization explicit
- **Result (VERIFIED):** `912df45` — `/engagement/{host}/investigate` now enforces a
  pre-admission contract BEFORE any job allocation: route `{host}` must match the
  normalized `base_url` hostname (else 400), and the destination must already be in
  `orchestrator.allowed_hosts` (else 403). Removed the implicit
  `allowed_hosts.add(target_host)` self-grant, so a request can no longer widen scope
  (empty allowed_hosts = fail-closed). Reuses the existing scope set (no parallel
  mechanism); host normalization via `urlsplit().hostname` strips port/userinfo, and
  bypass vectors (case/port/userinfo/trailing-dot) are fail-closed. Positive path
  unchanged. config.yaml unchanged. +3 tests (unauthorized→403 with no job
  side-effect, mismatch→400, authorized+consistent still starts). Full suite 2401 OK
  / 2 skip. Server admission only — no P0-6/P1-8/P1-9 change.
- **Domain:** Safety / API · **Effort:** M · **Depends on:** none
- **Evidence (VERIFIED by source inspection):**
  `server.engagement_investigate` adds the submitted `base_url` hostname to the
  run's `allowed_hosts`. The route `host` is separately used for job association.
  This is an implicit scope-granting contract, not proof of an exploitable bypass.
- **Recommendation:** Define whether an authenticated start request may grant
  scope or must use pre-authorized scope. Enforce that contract explicitly and
  validate route-host/base-URL consistency before allocating a job. Coordinate
  with existing transport/policy work; do not add a competing scope mechanism.
- **Acceptance criteria:** API caller tests reject an unauthorized destination and
  inconsistent target identity before any send. A positive control starts an
  authorized investigation. If explicit per-run scope grants are supported, test
  and record that grant separately from ordinary target selection; redirects
  remain subject to the same policy.
- **Impact:** High.

### [x] P1-8 — Bound investigation admission and release completed job resources
- **Result (VERIFIED-tests):** `6a42cc6` — `/investigate` admission bounded at
  `_MAX_RUNNING_JOBS=4` (503 + Retry-After when saturated, layered strictly AFTER
  P1-7's 400/403 checks); terminal jobs retained `_JOB_RETENTION_SECONDS=900` /
  `_MAX_RETAINED_TERMINAL_JOBS=50` (oldest-first), evicted/expired id → 404;
  `_evict_expired_jobs` iterates ONLY terminal states so a running job is never
  evicted; on terminal, task/run_context refs released while result/manifest persist.
  In-limit happy path unchanged. Module constants only (no config.yaml key). +6
  deterministic caller-level tests (saturation-no-excess, capacity release on
  completion+cancel, expiry→404, retained cap, positive control, never-evict-running).
  An earlier revision hung the suite on an orphaned OS-thread stub; fixed (cooperative
  asyncio stub + portal-pinned TestClient + teardown cancels all jobs). Full suite
  2407 OK / 2 skip, exit 0 — independently re-run to confirm clean termination.
- **Domain:** Reliability · **Effort:** M · **Depends on:** none
- **Evidence (VERIFIED by source inspection):** `_INVESTIGATE_JOBS` retains job
  dictionaries, results, tasks, and run contexts; the start endpoint creates a
  task for each accepted request without a job admission limit. Per-run request
  budgets do not bound aggregate job count.
- **Recommendation:** Add bounded concurrent admission, a bounded queue or clear
  rejection response, and completed-job retention/eviction. Release task/context
  references after termination while preserving the documented result-access
  window and durable manifest. This is separate from P3-4's ledger singleton cap.
- **Acceptance criteria:** Caller-level tests saturate admission and prove no
  excess job starts; completion, error, and cancellation release capacity.
  Expiry bounds retained jobs and returns a documented response for expired IDs.
  Positive control: an admitted job completes and remains readable during its
  retention window. Do not evict running jobs as a memory-management shortcut.
- **Impact:** Medium-High.

### [x] P1-9 — Define and test the allowed-host DNS resolution boundary
- **Result (VERIFIED):** `bd96d9b` — documented the scope-authorization contract
  honestly (hostname-string membership, decided before DNS, does NOT pin the resolved
  address; NOT an address-level rebinding defense) in `ScopePolicy`/`scope_lock`
  docstrings; corrected P1-2's rebinding-test overclaim (wording only — the 7
  scope-escape assertions are byte-identical). Added
  `harness/test_dns_resolution_boundary.py` (+4: stable-resolution positive control,
  changing-resolution characterization asserting scope does NOT refuse an allowed
  host's changed address, unlisted-host negative control, authorized-loopback). The
  actual address-bound *enforcement* is deferred to P1-10 (behavior-changing).
  Behavior-preserving (docstrings/comments + tests only; config.yaml untouched). Full
  suite 2411 OK / 2 skip; affected files 11 OK, exit 0, offline/deterministic.
- **Domain:** Safety / Verification · **Effort:** M · **Depends on:** P1-2
- **Evidence (VERIFIED by source inspection):** P1-2's rebinding-named test rejects
  a hostname absent from the allow-list before DNS resolution. It does not test
  an allowed hostname whose resolved address changes. Its coverage remains useful,
  but does not establish protection against that different scenario.
- **Recommendation:** Define whether authorization covers a hostname alone or also
  destination addresses. Correct the test/documentation assurance to match that
  contract and add controlled changing-resolution coverage. If address restrictions
  are required, enforce them at connection time without a separate check/use race.
  Preserve explicitly authorized loopback/private targets and legitimate DNS use.
- **Acceptance criteria:** Tests exercise an allowed hostname with changing
  resolution against the chosen contract, with a stable authorized destination as
  a positive control. For an address-bound policy, assert the disallowed endpoint
  receives zero requests, including on redirects. Do not claim address-level
  rebinding protection from an unlisted-host rejection test.
- **Impact:** Medium-High.

### [~] P1-10 — Address-bound connect-time resolution pin (DNS-rebinding enforcement)
- **Result (offline half VERIFIED):** `aad2dce` — opt-in `security.pin_connect_address` (OFF by default;
  config.local.yaml live toggle, never committed). `TargetTransport.execute` resolves each hop's host
  ONCE via an injectable resolver seam and directs the connect to that pinned address, preserving Host +
  TLS SNI, so a later/alternate resolution can't redirect it; applied per hop (redirects re-pin); resolver
  failure → honest error, never an unpinned send; IP literals untouched; credential/scope/gate logic
  still keys on the hostname (only the CONNECT target pins). Default/off path keeps the exact original
  `client.request` signature. 7 caller-level tests (mock resolver + mock transport recording the connect
  target): pinned IP used never a later resolution's, https sni_hostname, redirect re-pin, resolver-fail
  sends nothing, OFF-by-default connects to hostname with resolver never called. Suite: harness 2658 OK
  (skip 2) / testing 163 OK / evaluation_integrity 42 OK. **OWNER/LIVE half remains:** two-origin /
  real-HTTPS DNS-rebinding proof (why it ships OFF); also the socket-level pin vs httpx's own re-resolution
  under real TLS is validated live, not by the mock transport.
- **Domain:** Security · **Effort:** M · **Depends on:** P1-9 [x]
- **Evidence (VERIFIED-by-inspection):** filed from the P1-9 review. P1-9 documented
  that scope is hostname-string only and does NOT pin the resolved address, so an
  already-allowed hostname whose resolution changes between the scope check and the
  connect is not blocked at the address level (true DNS rebinding). This is the
  behavior-changing *enforcement* P1-9 deliberately deferred.
- **Recommendation:** In `TargetTransport.execute` (harness/run_context.py), inside
  the per-hop loop after the existing scope/gate/budget checks, resolve the hop's
  hostname ONCE and connect directly to that pinned address for that hop (custom
  httpx transport / httpcore pool keyed on the pinned address), preserving the
  original `Host` header and TLS SNI so virtual hosting and cert validation are
  unaffected. Pin-and-connect must be atomic (no resolve → decide → re-resolve-by-name
  race). Apply on every redirect hop too.
- **Acceptance criteria:** Caller-level test with a mocked resolver returning address
  A at pin time and address B on a later resolution asserts the request reaches ZERO
  requests at B (including on redirects); positive control: a stable authorized host
  still succeeds; explicitly authorized loopback/private targets and legitimate DNS
  use preserved. `full` suite green. Ship any new toggle OFF/safe.
- **Impact:** Medium-High (closes the rebinding gap P1-9 characterized).

### Priority adjustment proposed — P3-1 redaction/retention

Treat the existing P3-1 as P1 work when scheduling after the paused item; retain its
ID and existing entry to avoid duplicate implementation or broken references.
Its controls should precede expanded sensitive evidence storage in P0-6 and export
in P2-3. Completeness diagnostics in P0-6 can proceed without storing more data.
No existing priority heading or dependency list was rewritten by this addendum.

---

## Investigation queue — measured failures, before further feature expansion

### [x] P0-7 — Require executed negative controls for leg qualification
- **Result (VERIFIED):** `ec03060` — leg qualification now requires an EXECUTED pair:
  `_is_executed_confirmation` (confirmed/True) AND `_is_executed_refutation` (executed
  `not_confirmed`). Skipped/errored/blocked/unavailable/inconclusive negatives no
  longer qualify (was: accept-any-non-confirmed). Throttle isolation moved off the
  process-wide singleton to a `_SCOPED_THROTTLE` contextvar + scoped
  `global_throttle.acquire` dispatch restored in `finally`, so concurrent engagements
  keep their real throttle through execution and cleanup. Per-run lifetime documented;
  fail-safe empty-frozenset preserved; config.yaml unchanged (OFF by default). Only
  `leg_self_test.py` + tests changed (no transport/ledger/store touch). +11 tests
  (5 non-executed refusals, 1 healthy positive control, 2 throttle-isolation). Full
  suite 2383 OK / 2 skip (independently re-run after the coder's background run was
  killed mid-suite). Corrects an earlier-loop gap in P0-2.
- **Domain:** Trust / Reliability · **Effort:** M · **Depends on:** P0-2
- **Evidence (VERIFIED-by-inspection at c1133d5):**
  `harness/leg_self_test.py::_case_passes` accepts any negative result except
  `status == "confirmed"` or `confirmed == True`; skipped/error/inconclusive
  negative controls can therefore qualify a leg. `run_self_test` temporarily
  disables the process-wide throttle. No live failure was reproduced here.
- **Recommendation:** Require evidence that both positive and negative probes
  actually executed with valid outcomes; distinguish a controlled negative from
  an unavailable or failed probe. Isolate fixture rate policy from concurrent
  engagements. State the qualification cache's lifetime explicitly.
- **Acceptance criteria:** Caller-level controls refuse qualification for skipped,
  errored, blocked and inconclusive negative probes even when the positive
  confirms; a healthy executed pair qualifies. Concurrent production contexts
  retain their throttle policy throughout self-test execution and cleanup.
- **Scheduling:** After the existing paused-item and INV-1..4 dispatch; do not
  reopen completed implementation items or silently enable self-tests by default.
- **Impact:** High.

These items follow the dispatch override at the top of this file. Closing an
investigation means its evidence package passed review, not that model accuracy
improved or that a live rerun happened. Live measurements remain separately open.

### [x] INV-1 — Reconcile the live baseline and prepare a controlled comparison
- **Result (VERIFIED-by-inspection @c1133d5):** `e0ba0aa` —
  `docs/investigations/INV-1-baseline.md`: revision table for the 3 historical runs,
  config-consumer map, same-revision 2x2 comparison plan (fingerprints + fresh cache
  namespaces), metrics spec, exact un-executed run recipe, P0-3 gap analysis + a
  separate owner-run measurement ticket. Key finding: `run_blind_eval.py` sets
  `reporting.quarantine_unverified_leads` but never calls
  `report_generator.generate_markdown_report` (sole caller of
  `should_quarantine_as_lead`), so the quarantine knob is a no-op on that driver's
  output — the quarantine axis is unmeasurable there until a small blocking
  sub-ticket (wire the report generator into the blind driver + paired test) lands.
  Routing axis unaffected. No live run; no code/worktree change; no precision/recall
  delta claimed. Opus gate independently re-verified the no-op finding.
- **Domain:** Evaluation · **Effort:** S · **Depends on:** none
- **Mode:** Offline investigation; eventual live comparison is owner-run.
- **Deliverable:** `docs/investigations/INV-1-baseline.md`, following the dispatch
  guide's INV-1 steps, with revision table, metric definitions, driver/config
  audit, comparison matrix, exact run recipe and unresolved prerequisites.
- **Acceptance:** Opus can identify what actually ran, what changed afterward,
  and how the next comparison avoids stale caches and misleading quarantine gains.

### [x] INV-2 — Trace the raw-confirmed versus proof-linked confirmation gap
- **Result (VERIFIED-by-inspection @b3d40a2; artifacts VERIFIED-in-run @eb70210):**
  `40104a9` — `docs/investigations/INV-2-proof-gap.md`. Two confirmation paths
  diverge: `orchestrator_confirm._validate_findings` (PASS1) persists a `ProofRecord`
  + stamps `case_id`/`proof_id`; `orchestrator_chain._apply` (PASS2 graph loop) stamps
  `confirmed_by_leg` only and never persists a proof. `active_confirmation_is_unproven`
  OR-logic lets the proof-less confirmation pass the honesty backstop. The historical
  9/13→6/13 proof-linked gap = exactly {GT04,GT05,GT06} (idor/cross_identity), audited
  read-only against `recall_report_integrated_full.json` + `maxcov_state_integrated_full.db`
  (mode=ro). "Complete proof link" defined (case_id+proof_id+matching row+verdict
  confirmed+validator==leg). 3 bounded, sequenced tickets filed; P0-6 linked (no 2nd
  ledger). No code/worktree/DB change; Opus gate re-verified _apply vs _validate_findings
  and the {GT04,05,06} delta at source.
- **Domain:** Evidence / Trust · **Effort:** M · **Depends on:** INV-1
- **Mode:** Offline investigation; unavailable artifacts are explicit limitations.
- **Deliverable:** `docs/investigations/INV-2-proof-gap.md`, with proof lifecycle
  map, run-isolated read-only audit recipe, supported causes and bounded fix tickets.
- **Acceptance:** Distinguish the reported 9/13 versus 6/13 gap from demonstrated
  current-code defects; specify caller-level positive and missing/wrong-proof controls.
  Coordinate resulting fixes with P0-6 and pending evidence work.

### [x] INV-3 — Locate where the chaining pipeline loses candidates
- **Result (VERIFIED-by-inspection @9cbb70b; artifacts VERIFIED-in-run @eb70210):**
  `cc8e817` — `docs/investigations/INV-3-chain-funnel.md`. Two distinct chain paths:
  the per-exchange path (`orchestrator_detect.py:736-772`) persisted 5 `chain_detector`
  rows in the reported run; the graph path (`orchestrator_chain.investigate_engagement`)
  computes its returned `chains` from a snapshot taken at link time (`:657`/`:687`)
  and never re-links after the later second-order (`:691-813`) and coverage
  (`:837-928`) phases append confirmations (`:770`/`:905`), so the empty `chains` is
  a stale-snapshot reporting-order artifact — NOT a bare regression. Failure mode
  classified as dropped/late-reporting (disabled/no-evidence/budget/rejected/
  failed-step ruled out at source). Test spec (positive + scope-negative +
  inactive-config zero-request controls). One additive fix ticket (final relink
  before return). No code/worktree/DB write; Opus gate reproduced the artifact counts
  read-only.
- **Domain:** Pipeline / Efficacy · **Effort:** M · **Depends on:** INV-1, INV-2
- **Mode:** Offline investigation; no new agent or live probing.
- **Deliverable:** `docs/investigations/INV-3-chain-funnel.md`, with the production
  caller map, per-stage evidence/unknowns, first demonstrated loss point, and one
  minimal fixture proposal with a broken-prerequisite negative control.
- **Acceptance:** Explain the difference between zero opportunities, disabled
  execution, failed execution and missing reporting; do not infer a regression
  solely from an older run's reported one-chain count.

### [x] INV-4 — Attribute duplicate findings and runtime before optimizing
- **Result (VERIFIED-by-inspection @21f9b37; artifacts VERIFIED-in-run @eb70210):**
  `a6e125f` — `docs/investigations/INV-4-noise-runtime.md`. `host_dep_dedup.py` is
  severity-capping, not dedup; real keys mapped per layer (`finding_fingerprint`
  tuple under UNIQUE (fingerprint, case_id) INSERT OR IGNORE — coarseness intentional
  T06/R08; surfaced `issue_key`; leads predicate; case_id/proof_id). The 1914/641/107
  counts trace to a driver-side un-deduped `_all_findings()` union (1914==union len;
  store.findings=1108), NOT a store.py defect — distinct object/principal identity
  preserved. Runtime: no timing instrumentation anywhere (telemetry counters only,
  effort axis tokens-only, PASS2 elapsed UNKNOWN residual) → "8.3h = model time"
  unsupported; missing instrumentation named. 3 instrumentation/counting-only tickets,
  no concurrency/threshold change, no speedup promised. No code/worktree/DB write.
- **Domain:** Precision / Performance · **Effort:** M · **Depends on:** INV-1, INV-3
- **Mode:** Offline investigation; no fresh model run or raw-volume efficacy claim.
- **Deliverable:** `docs/investigations/INV-4-noise-runtime.md`, with existing
  dedup/cost instrumentation map, artifact-supported breakdown or explicit unknowns,
  and at most three narrowly scoped remediation tickets.
- **Acceptance:** Separate repeated evidence from distinct vulnerabilities and
  exposed findings from leads; preserve distinct principal/object cases. Each
  proposed optimization names a metric and caller-level regression control.

## Consensus batch — 2026-09-21 (multi-review reconciliation)

Derived from `reviews/2026-09-21/`. These file the INV-1..4 production fixes and the new
items the reconciliation surfaced. **Loop pick order:** RB-1 → RB-4 → RB-8 → RB-3 → RB-5
→ RB-2 → RB-7 → RB-6. `Mode: LOOP` = offline, testable, Sonnet-implementable. `Mode:
OWNER/LIVE` = needs a real model / JDK-Burp / GPU and is out of loop scope (leave `[ ]`).
Fact-check note for the loop: two "obvious" fixes proposed in review were WRONG against
source — the coordinator fail-open is already telemetried with a `curated` mode (do not
"add" it), and per-`(host,component)` advisory dedup already exists in
`_resolve_known_vulnerabilities`; the real duplication is the driver-side union (RB-3).
Verify every proposed diff against the code before implementing.

### [x] RB-1 — Local-API origin/CSRF defense (ephemeral token + origin check)
- **Result (VERIFIED):** `f24ff8e` — ephemeral bearer token (`secrets.token_urlsafe(32)`)
  generated at startup when no operator token (`auth_token`/`HARNESS_BEARER_TOKEN`) is set,
  written to a 0600 `harness/.harness_token.lock` (git-ignored; `os.chmod` best-effort/
  non-fatal — Windows only toggles read-only, so the token, not the file mode, is the
  boundary). `_csrf_defense_middleware` rejects `Sec-Fetch-Site: cross-site` and any
  cross-site `Origin` (hostname compare via the new `urlparse` import) with 403 BEFORE the
  token check (so a leaked token cannot rescue a cross-site call), then requires
  `Authorization: Bearer` on POST/PUT/PATCH/DELETE (401) even on loopback; a MISSING Origin
  (curl/extension) is allowed; GET stays governed by the pre-existing `_require_auth`. Python
  side only — `burp-extension/` and `config.yaml` untouched; the extension reading the token
  is **RB-1b (OWNER/JDK)** and until it lands the packaged extension will not authenticate.
  +8 caller-level tests (`harness/test_local_api_csrf.py`): no-token→401, cross-site
  Origin/`Sec-Fetch-Site`→403, token+no-Origin→200, and the no-Origin+token NEGATIVE CONTROL
  still succeeds; 7 existing server `TestClient` suites updated to attach the now-required
  token (mechanical header only — their route-level 403 tests still fire, proving coverage
  preserved, not masked). Full suite **2426 OK / 2 skip, exit 0**. Opus-reviewed APPROVE.
  Non-blocking follow-ups (documented, not separately filed — all low risk): middleware
  docstring says "after TrustedHost" but a decorator middleware runs outermost (cosmetic);
  Windows lockfile is `-rw-r--r--` (ACL hardening only if local-account isolation is ever
  needed); read-only GET routes remain reachable by a same-host/different-port local origin
  (browser labels it same-site; mutations stay token-gated); a non-ASCII `Authorization`
  header raises in `compare_digest`→500 not a clean 401 (fail-closed, pre-existing in
  `_require_auth`). **Owner next:** land RB-1b before shipping a token-enabled server.
- **Domain:** Security / Trust · **Effort:** S · **Depends on:** none · **Mode:** LOOP
  (Python side; the Burp extension reading the token is RB-1b, OWNER/JDK)
- **Evidence (VERIFIED):** `server.py:146` allows unauthenticated requests on loopback
  when no `auth_token`/`HARNESS_BEARER_TOKEN` is set; the file's own comment (~`:125`)
  concedes JSON endpoints are "protected only by accidental CORS-preflight". `urlparse`
  is NOT currently imported in `server.py`.
- **Problem:** A page the tester visits in a browser can `fetch()` loopback endpoints
  (exfiltrate findings, or drive the harness) via CSRF-shaped requests. GET routes and
  any `text/plain` route are reachable cross-origin.
- **Recommendation:** Generate an ephemeral bearer token at startup, write it to a
  `0600` lockfile the extension reads, and require it on every state-changing route even
  on loopback (primary control). Add an `Origin`/`Sec-Fetch-Site` reject-cross-site
  middleware as defense-in-depth (add the `urllib.parse.urlparse` import). Do not break
  no-Origin local callers (curl / the extension).
- **Acceptance:** TestClient — state-changing route without the token → 401; a
  cross-site `Origin` (or `Sec-Fetch-Site: cross-site`) → 403; a loopback call with the
  token and no Origin → 200. Negative control: an existing same-origin/no-Origin call
  the extension makes still succeeds (regression guard).
- **Impact:** High (a real, cheap trust/safety win).

### [x] RB-2 — Surface a `degraded: routing_failed_open` signal (do NOT flip the default)
- **Result (VERIFIED):** `35e5f4f` — the production wiring was ALREADY shipped pre-session
  (`bea437a`, "P0.9"): `AnalysisResponse.coordinator_fallback` (models.py:274) is set in
  `analyze()` via `coordinator_fallback=coordinator.is_fallback_reason(reason)`
  (orchestrator_detect.py:904). The genuine gap (per RB-2's own "not distinguishable by a
  caller reading the response") was that NO test asserted it through the real caller —
  `test_coordinator.py` only exercised `is_fallback_reason()`/`choose_agents()` directly. Added
  the missing caller-level leg (`harness/test_orchestrator_detect.py`, +2, offline: stubbed
  ollama, isolated temp store/cache, no network/answer-key): POSITIVE — a forced coordinator
  routing failure → `resp.coordinator_fallback is True` AND `fail_open_stats()["count"]==1`;
  NEGATIVE CONTROL — healthy routing → `False` and count 0. Would fail if line 904 regressed
  (drives real `analyze()`, not a tautology). **No production/config change** —
  `coordinator.fail_open_mode` NOT flipped (the `curated` default flip stays owner-gated as
  **RB-2b**, on RB-8's measured recall delta). Full suite **2438 OK / 2 skip, exit 0**.
  Opus-reviewed APPROVE. (Note: a reconciliation gap — P0.9 shipped the flag but the RB-2
  entry stayed open; this closes it, with the test that was actually missing.)
- **Domain:** Reliability / Observability · **Effort:** S · **Depends on:** none · **Mode:** LOOP
- **Evidence (VERIFIED):** `coordinator._record_fail_open` already logs + increments
  `fail_open_stats()` + publishes to the activity feed (not silent); `_curated_fallback`
  and `fail_open_mode` already exist. `config.yaml:88` states the `curated` flip is "a
  recall trade-off that should be gated on the repeated/blind eval (W-23)". Fail-open is
  already bounded by `concurrency.max_parallel_agents`.
- **Problem:** An all-agent fail-open is observable in telemetry but not in the analysis
  *result*, so a degraded run (routing failed → ~36 agents, minutes of latency) is not
  distinguishable from a healthy one by a caller/UI reading the response.
- **Recommendation:** Add a `degraded`/`routing_fallback` flag to the analysis response
  when `is_fallback_reason` is true. **Do NOT change the committed `fail_open_mode`
  default** — the `curated` flip is RB-2b, owner-gated on RB-8's measured recall delta.
- **Acceptance:** caller-level test — force a coordinator error → response carries the
  degraded flag AND `fail_open_stats` incremented. Negative control: healthy routing →
  no degraded flag.
- **Impact:** Medium (kills the "silent all-36" ambiguity without a recall change).

### [x] RB-3 — Dedupe dependency/banner findings at the aggregation layer (INV-4 fix)
- **Result (VERIFIED):** `3028cf7` — confirmed a real HARNESS-CORE surfacing-layer gap
  (distinct from INV-4's untracked driver-union count, which stays owner/eval): a
  dependency/banner advisory (`known-vulnerable-dependency:<comp>` /
  `recently-published-dependency:<comp>` from `orchestrator_detect`) has no
  parameter → `issues._affected_input` is always `""` → `issue_key`'s R04 branch appended
  the per-occurrence `finding_id`, so the SAME advisory across N exchanges surfaced as N
  issues (empirically 3→3 before). Fix: `issue_key` now keys a dependency-class finding on
  `(host, "", "", canon, "", "read", "")` — host + canonical class/component only
  (`endpoint_family`/`method` dropped as a host-wide banner isn't endpoint-scoped; no
  disambiguator, since `canonicalize()` returns None for these compound strings so `canon`
  keeps the component identity → Werkzeug ≠ Flask stay distinct). Every non-dependency
  finding falls through the ORIGINAL path — key byte-identical (verified vs pre-fix output
  on 7 fixtures; all 37 existing `test_issues` incl. the R04 regression pass unmodified). NO
  second detection-layer dedup added (that logic already runs); nothing under
  `testing/vulncorp-helpdesk/` or any untracked eval driver touched. +6 tests
  (`DependencyBannerDedupTests`): N identical banners→1 (positive); distinct components→2
  (neg #1); two distinct unattributed non-dependency findings→2 (neg #2, R04). Full suite
  **2434 OK / 2 skip, exit 0**. Opus-reviewed APPROVE (branch isolation confirmed at source).
  **Residual (owner/eval):** INV-4 Ticket 1 — the raw 1914 count is the untracked
  `run_maxcov_integrated.py` `_all_findings()` three-way union; deduping that driver is
  owner/eval territory, not loop-consumable.
- **Domain:** Precision · **Effort:** S · **Depends on:** none · **Mode:** LOOP
- **Evidence (VERIFIED):** per-`(host,component)` advisory dedup ALREADY exists in
  `orchestrator_detect._resolve_known_vulnerabilities` (`_reported_banner_components`,
  initialized `orchestrator.py:157`) and `host_dep_dedup.py` predates the 2026-09-20
  SCORECARD base — yet 9× Werkzeug still appeared. INV-4 (`@a6e125f`) attributes the
  count to a **driver-side un-deduped `_all_findings()` union** (1914 == union len vs
  `store.findings` 1108), NOT a detection-layer gap. `issues.py:268` already does
  root-cause grouping.
- **Problem:** Identical dependency-banner findings collapse per analysis call but are
  re-introduced when the engagement/eval driver unions findings across phases/exchanges,
  flooding the report (the dominant blind-negative FP driver).
- **Recommendation:** Group/dedupe at the `_all_findings()` union / `issues.py` surfacing
  layer, keyed on the existing `issue_key`/fingerprint (host, canonical class/component).
  Do NOT add a second detection-layer check — that logic already runs.
- **Acceptance:** feed N identical Werkzeug-banner findings across multiple exchanges/
  phases through the driver union → 1 surfaced issue. Negative control: two genuinely
  distinct components on the same host → 2 issues; distinct principal/object cases
  preserved (per INV-4).
- **Impact:** Medium (directly lifts the measured blind-negative precision).

### [x] RB-4 — Persist ProofRecord + ledger events on the engagement confirm path (INV-2 fix)
- **Result (VERIFIED):** `301d848` — extracted `ConfirmMixin._persist_confirmation_proof`
  as the ONE place a case-bound `ProofRecord` is built/persisted and the matching
  `evidence_ledger` `VALIDATION_DECISION` is emitted; PASS1 (`orchestrator_confirm._validate_findings`)
  now calls it with behavior byte-for-byte preserved, and PASS2 (`orchestrator_chain._apply`,
  the engagement/graph loop) is wired through the SAME helper — reused, not reimplemented
  (no 2nd ledger, per INV-2). Persistence sits strictly inside the `res.confirmed is True`
  block so a suppressed/not-confirmed leg persists nothing (no orphan proofs); it also emits
  one summary `EXECUTION` event (the shape legs don't thread `case_ref` through
  `TargetTransport`) so `reconstruct_persisted` returns non-empty `what_sent`/`what_came_back`.
  All bookkeeping is best-effort/try-excepted and never alters the already-decided verdict;
  `_apply` is now `async` and every dispatch call site awaits it. **Tests:** `test_pipeline_gate`
  gained a `run_live()` context manager so store/ledger assertions read the run's OWN temp DB
  while live — the initial failures were a test-harness DB-lifecycle bug (assertions ran after
  `.run()` teardown had reset `store._DB_PATH` to the shared, pollution-laden dev DB), NOT a
  production gap; verified by reading the wiring + deterministic pass. +2 caller-level tests:
  positive (engagement-path confirmed IDOR → persisted `ProofRecord` + `reconstruct_persisted`
  complete, non-empty what_sent/what_came_back) and defect-injection negative control
  (suppressed cross-identity leg → `confirmed=False` AND zero confirmed-idor proofs in the run
  DB). `test_pipeline_gate` 8/8 OK on two consecutive runs (determinism); full suite **2428 OK
  / 2 skip, exit 0**. Opus-reviewed APPROVE (production audit: PASS1 parity, confirmed-only
  gating, all `_apply` callers awaited). Coordinates with P0-6 (single ledger).
- **Domain:** Trust / Evidence · **Effort:** M · **Depends on:** P0-1 · **Mode:** LOOP
- **Evidence (VERIFIED):** `CURRENT_STATE` INV-2 and `testing/SCORECARD.md`: the
  proof-linked audit drops confirmations 9/13 → 6/13 because the active engagement
  confirm path (`orchestrator_chain`) stamps `confirmed=True` without persisting a
  `ProofRecord`/ledger `VALIDATION_DECISION`, unlike `orchestrator_confirm._validate_findings`.
- **Problem:** A finding shown as CONFIRMED in an engagement run may have no reproducible
  proof — the worst possible outcome for a tool whose value is evidence-grade confirmation.
- **Recommendation:** Route the engagement-loop confirmation through the SAME proof
  persistence + `evidence_ledger` emission as `orchestrator_confirm`, so every
  `confirmed=True` in `investigate_engagement` resolves to a persisted proof.
- **Acceptance:** extend `test_pipeline_gate` (real loopback discovery→confirm): the
  confirmed IDOR has a persisted `ProofRecord` and `reconstruct_persisted(...)["complete"]
  is True` with non-empty `what_sent`/`what_came_back`. Negative control (defect
  injection): a suppressed leg → `confirmed=False` AND no orphan proof persisted.
- **Impact:** High (the single most important trust fix in this batch).

### [x] RB-5 — Re-link attack chains after second-order + coverage phases (INV-3 fix)
- **Result (VERIFIED):** `4c78f2d` — `investigate_engagement` computed `chains` (via
  `chain_linker.link_findings`) BEFORE the second-order auto-confirm (~782-897) and
  coverage-driven (~921-1012) phases, both of which append NEW confirmed findings into
  `all_findings`/`state` without re-linking → a chain whose second constituent only confirms
  in a later phase was returned stale/absent (INV-3, SCORECARD "0 chains … did not reproduce").
  Added ONE final re-link after the coverage phase, before the return, via a new pure-recompute
  seam `Orchestrator._relink_chains` (no verdict/severity/scope decision). Append-only across
  phases → only ADDS newly-enabled chains, never drops/mutates the ~752/782-linked ones (kept
  as-is). Best-effort: a late linking error is logged + recorded in `errors` (→
  `result["degraded"]`) and the prior snapshot kept, never sinking the run. +2 tests
  (`test_engagement_chain_relink.py`, offline/stubbed model + synthetic discovery/worklist +
  canned second-order confirmation): POSITIVE — chain from a pre-existing finding + a
  second-order-phase-confirmed finding IS present in `result["chains"]`; NEGATIVE CONTROL —
  `_relink_chains` patched to raise → same chain ABSENT + run `degraded` + `final_chain_relink`
  error (genuine defect injection via the seam). Full suite **2436 OK / 2 skip, exit 0**.
  Opus-reviewed APPROVE (best-effort + append-only reasoning confirmed at source).
- **Domain:** Pipeline / Efficacy · **Effort:** S · **Depends on:** RB-4 · **Mode:** LOOP
- **Evidence (VERIFIED):** `CURRENT_STATE` INV-3 and SCORECARD "0 chains ... did not
  reproduce": chains are computed on a pre-confirmation snapshot and never recomputed
  after the second-order/coverage phases confirm new findings.
- **Problem:** Multi-step chains whose constituents only confirm in a later phase are
  silently absent from the engagement report.
- **Recommendation:** Add a second `chain_linker.link_findings` pass after the
  second-order and coverage phases, before returning the engagement result.
- **Acceptance:** fixture where a later-phase confirmation composes with an earlier
  finding → chain present in the result. Negative control / defect injection: remove the
  re-link → chain absent (the assertion goes red).
- **Impact:** Medium.

### [x] RB-6 (LOOP half) — Reconcile the two active-traffic execution planes by capability
- **Result (VERIFIED):** `5fa1a57` — LOOP-half acceptance met: committed capability-ownership
  matrix `harness/execution_planes.py` over 41 canonical capabilities (25 dual-plane, 4
  Java-only, 12 Python-only) mapping each to which planes can execute it + the ONE authoritative
  plane (dual-plane → Python-authoritative, since that plane carries SafetyGate/TargetTransport/
  two-flag mutating opt-in/budget/evidence ledger vs Java's `isInScope` only). +23-test enforced
  contract `test_execution_planes.py` that PARSES the real source at test time (no snapshot):
  `ValidationExecutor.java`'s switch labels + `registry.py`/`_val_by_conf` keys, asserting
  EXACTLY ONE authoritative plane per capability (the RB-6 acceptance) + bidirectional coverage
  + non-triviality guards. No Java/config change; matrix module is a contract artifact, not
  imported by production. Full suite **2482 OK / 2 skip, exit 0**. Opus-reviewed APPROVE.
  Surfaced a real discrepancy: `HarnessPanel.IMPLEMENTED_BURP_CAPABILITIES` is a stale 22-of-30
  subset so `runnableHere` under-reports Java's capabilities.
  **OWNER/JDK residual (out of loop scope):** make the Java plane emit its scope/gate decision
  into the shared evidence trail; fix the stale HarnessPanel subset; RB-7's owner-run ablation
  may revise the authoritative assignments. Do NOT delete the Java path pre-ablation.
- **Domain:** Architecture / Safety · **Effort:** M (matrix) / L (reconciliation)
  · **Depends on:** RB-7 (ablation informs which plane wins) · **Mode:** LOOP for the
  capability matrix + Python evidence contract; **OWNER/JDK** for Java edits + build
- **Evidence (VERIFIED):** `ValidationExecutor.java` (1,690 LOC) sends live traffic — 38
  `api.http().sendRequest()` sites (XSS injection, rate-limit replay, identity replays) —
  gated only by Burp's configured scope (`isInScope`, line 93), i.e. OUTSIDE the Python
  `SafetyGate`/`TargetTransport`/two-flag mutating opt-in/budget. `*Logic.java` classes
  are pure unit-tested helpers, not duplicate executors. `HarnessPanel.runnableHere`
  already routes plans Java-vs-Python.
- **Problem:** The SAME capability existing in both planes causes logic drift and
  divergent results, and the Java plane's active traffic is invisible to the Python
  evidence/safety trail. This is a maintainability + consistency hazard, NOT "unauthorized
  requests" (it is operator-triggered and Burp-scope-gated).
- **Recommendation (staged; NOT a rewrite):** (a) LOOP: produce the capability matrix of
  which classes execute in each plane (from grep) + define one shared evidence/gate
  contract; (b) assign each capability ONE authoritative plane; (c) OWNER/JDK: make the
  Java plane emit its scope/gate decision into the shared trail. Do NOT delete the Java
  execution path before RB-7's ablation shows Python-plane execution is strictly better.
- **Acceptance (LOOP half):** a committed capability-ownership matrix + a test asserting
  no capability is authoritative in both planes. Java behavioural changes are OWNER.
- **Impact:** Medium.

### [x] RB-7 — Build the A–F ablation harness (instrument for P2-2)
- **Result (VERIFIED):** `fa3dd95` — COMPLETED the pre-existing W-22 scaffold
  `harness/ablation_harness.py` (which had A–F variants + an injectable `variant_runner` +
  `RunMetrics`/table but B/C/E/F were `needs_implementation` stubs) rather than adding a
  parallel module (a first draft that duplicated it was removed in review, per "reduce
  components, don't add"). Wired the real seams: B `force_agents=[single_agent]` → dispatch
  exactly 1; C disables every agent by name in the RUNTIME config → dispatch 0 (legs/validators
  still run); D `critique.enabled=False`; F `coordinator.fail_open_mode="curated"`. E stays a
  documented residual (`needs_implementation` kept + `NO_GRAPH_RESIDUAL`: the graph loop is
  only reachable via `investigate_engagement`, never `analyze()`, so it needs an owner-run
  engagement corpus; the runner refuses to present E's row as a measurement). Runner drives
  synthetic exchanges through the real `analyze()` with a stubbed model, scores via
  `testing.score.score()` (no second schema), and `render_table` exposes RB-7's schema
  (precision/recall/FP/tokens/wall-clock, derived from tp/fp/fn) — NO accuracy claim;
  confirmed/coverage left at defaults not fabricated. RUNTIME overrides only; committed
  `config.yaml` untouched; import-safe. +tests: B→1, C→0 (strong-signal + signal-free),
  negative controls (A→≥1 same exchange, `force_agents=[]` does NOT force-empty, D→critique off),
  all six variants render the schema. Module 29 OK; full suite **2459 OK / 2 skip, exit 0**.
  Opus-reviewed APPROVE (revised from a duplicate module onto the W-22 scaffold). **The
  real-model RUN stays OWNER/LIVE → feeds P2-2 (the 36-agent keep/collapse decision).**
- **Domain:** Evaluation · **Effort:** M · **Depends on:** none · **Mode:** LOOP builds
  the harness (stubbed-model testable); **OWNER/LIVE** runs it with a real model
- **Evidence (VERIFIED):** P2-2 exists but is owner/live; `POSITIONING_DRAFT.md` says the
  agent count "waits on the W-22 ablation". The seams already exist (`fail_open_mode`,
  agent enable flags, `critique.enabled`, the graph path) to wire arms.
- **Problem:** The central strategic question (do ~36 agents beat 1 model + tools / legs
  only?) cannot be answered without a runnable ablation; today there is no harness.
- **Recommendation:** Build a config-selectable arm set — A current, B single-agent +
  tools, C legs-only/no-LLM, D no-critique, E no-graph, F curated-routing — emitting one
  metrics table (precision/recall/FP/tokens/wall-clock) per arm. Real numbers are
  OWNER/LIVE; the loop delivers the runnable, stubbed-model-verified instrument.
- **Acceptance:** each arm selectable via config; a stubbed-model dry-run emits the
  metrics schema; a test asserts arm selection deterministically changes the dispatched
  set (e.g. B dispatches 1, C dispatches 0 agents). No accuracy claim from the loop.
- **Impact:** High (unblocks the #1 architectural decision). Feeds P2-2.

### [x] RB-8 — Fix the blind-eval harness so an owner run yields a valid scorecard (INV-1 fix)
- **Result (VERIFIED):** `dd104f9` — INV-1 no-op fixed: `testing/blind-target-2/run_blind_eval.py`
  refactored into importable functions with the live path (fresh `C:\tmp` DBs, live Ollama, real
  curated corpus) gated behind `if __name__ == "__main__":` → importing now runs nothing and
  mutates no global `store`/`cache` (independently verified). `build_scorecard` round-trips
  `store.all_host_findings` → `report_generator.generate_markdown_report(quarantine_leads=...)`
  (the sole caller of `should_quarantine_as_lead`), so the quarantine path is ACTUALLY exercised,
  mirroring the report generator's own branch (nothing quarantined when the knob is off). Added
  `controls_clean` (dirty controls listed) + timing (total/mean/max elapsed, token deltas) +
  `run_eval_n_times(n≥5)`/`aggregate_variance` (pvariance). Cross-identity REJECT is injected at
  RUNTIME only (`HARNESS_CROSS_IDENTITY_REJECT`); committed `config.yaml` untouched (asserted).
  +14 OFFLINE tests (`testing/test_blind_eval_harness.py`): a canned-finding stub + synthetic
  `eval-fixture.invalid` fixtures (NO answer-key/real-corpus read) prove the quarantine path is
  invoked, the knob gates it, `controls_clean` discriminates a dirty control (basis="derived"
  not quarantine-eligible), and import triggers no live run. testing tier 13→27; full suite
  green (harness 2434 OK / 2 skip), exit 0. Diff is testing-only (no `harness/` core change).
  Opus-reviewed APPROVE (safeguards + import-safety re-verified). **The RUN with a real model
  stays OWNER/LIVE → feeds P0-3.** Documented residual: this harness has no narrower "just
  REJECT" toggle (cross_identity needs `active_enabled`), so that axis is owner/live-only.
- **Domain:** Evaluation · **Effort:** M · **Depends on:** RB-3 (dedupe first) · **Mode:**
  LOOP builds/repairs the harness (stubbed-model testable); **OWNER/LIVE** runs it
- **Evidence (VERIFIED):** INV-1 — `run_blind_eval.py` set `quarantine_unverified_leads`
  but never called `generate_markdown_report()`, so the quarantine path never ran. SCORECARD
  root-causes the 0/6→1/6 controls-clean to (a) the RB-3 dependency union and (b)
  cross-identity REJECT being OFF in the blind config. INV-4: no timing instrumentation.
- **Problem:** The blind scorecard the whole plan is gated on cannot be trusted until its
  harness actually exercises quarantine + REJECT and reports variance + a controls-clean
  metric with timing/token cost.
- **Recommendation (LOOP):** make `run_blind_eval` exercise the quarantine path; wire
  cross-identity REJECT into the blind config; add ≥5-run variance aggregation, a
  controls-clean metric, and timing/token instrumentation. The RUN with a real model is
  OWNER/LIVE (feeds P0-3).
- **Acceptance:** an offline stubbed-model dry-run emits a scorecard with controls-clean +
  variance + timing fields AND provably invokes the quarantine path. Negative control: a
  synthetic secure fixture is quarantined (routed to leads), not reported as a finding.
- **Impact:** High (makes the gating measurement trustworthy).

> **OWNER/LIVE runs that the above instruments unblock (NOT loop-consumable):** the
> real-model blind scorecard single pass is done (P0-3, 2026-09-22,
> [reviews/2026-09-22/BLIND_SCORECARD_P0-3.md](reviews/2026-09-22/BLIND_SCORECARD_P0-3.md));
> the ≥5-run variance pass and cross-identity REJECT-on live run remain open.
> The A–F ablation run (P2-2, via RB-7) was attempted 2026-09-22 and is
> INCONCLUSIVE — a reproduced circuit-breaker starvation issue on this
> hardware invalidated the D/F rows; see
> [reviews/2026-09-22/ABLATION_P2-2.md](reviews/2026-09-22/ABLATION_P2-2.md)
> for the reliability fix needed before re-attempting. Also open: P1-10
> (connect-time IP pinning — needs a custom resolver), and RB-2b (the
> `fail_open_mode: curated` default flip, gated on RB-8's measured recall delta —
> the single-sample P0-3 run is not yet that basis).

## Batch 2 — 2026-09-22 (post-live-run findings)

Filed from the two owner/live runs at HEAD `0f047e8`: the P0-3 blind scorecard
([reviews/2026-09-22/BLIND_SCORECARD_P0-3.md](reviews/2026-09-22/BLIND_SCORECARD_P0-3.md))
and the P2-2 ablation attempt
([reviews/2026-09-22/ABLATION_P2-2.md](reviews/2026-09-22/ABLATION_P2-2.md)). The RB batch is
closed; these are the next loop-consumable items the live runs surfaced. **Loop pick order:**
B2-1 -> B2-2 -> B2-3 -> B2-4 -> B2-5. `Mode: LOOP` = offline, stubbed-model-testable,
Sonnet-implementable. The `OWNER/LIVE` portions (a real-model re-run, live active-validator
traffic, hardware timeout tuning) are NOT loop-consumable -- leave them for the owner. The
non-negotiables at the top of this file apply (safe config defaults, a caller-test + negative
control per item, never read `*ANSWER_KEY*`/a blind `app.py`, `python -m harness.suite full`
before closing). **Fact-check reminder for the loop:** the circuit breaker ALREADY exposes
`.is_open`/`.state` (`circuit_breaker.py:112-124`) and RB-2 already added the
`coordinator_fallback`/`degraded` response pattern -- REUSE both; do not build a parallel
breaker or a second degraded mechanism. **Reliability prerequisite:** B2-1 + B2-2 must land
before a trustworthy P2-2 ablation re-run (prioritise the A-vs-B comparison on that re-run --
B ran clean and is the P2-2 crux).

### [x] B2-1 -- Surface circuit-breaker-OPEN as a `degraded` signal on the analysis/engagement result
- **Result (VERIFIED):** `345fcf8` -- `AnalysisResponse` gained `agents_circuit_open`
  (mirrors RB-2's `coordinator_fallback`), set in `orchestrator_detect.analyze()` at
  response assembly from the SHARED breaker's `.is_open` via
  `get_ollama_circuit_breaker("ollama")` (read-only; never a directly-constructed
  always-CLOSED breaker). Engagement path REUSES the existing `_errors`->`degraded`
  contract: a best-effort/try-excepted breaker-open error entry flips
  `result["degraded"]` True (no new field). Observability only -- NO breaker trip/reset
  threshold logic touched (`circuit_breaker.py` not in diff); `config.yaml` unchanged.
  +2 caller-level tests (`harness/test_degraded_circuit.py`): POSITIVE -- breaker forced
  OPEN via `_force_open_async()` -> real `analyze()` -> `agents_circuit_open is True`;
  NEGATIVE CONTROL -- healthy CLOSED breaker -> `False`; singleton `.reset()` in
  setUp/tearDown so OPEN state cannot leak into the full suite (verified no leak). smoke
  92 OK; full **2484 OK / 2 skip, exit 0**. Opus-reviewed APPROVE (read-only shared-accessor
  read + no-threshold-change + non-tautological test confirmed at source). Non-blocking:
  the budget-blocked early-return path leaves the flag False (agents not dispatched there).
- **Domain:** Reliability / Observability / Trust - **Effort:** S - **Depends on:** none - **Mode:** LOOP
- **Evidence (VERIFIED):** `reviews/2026-09-22/ABLATION_P2-2.md` -- the process-wide shared
  `"ollama"` breaker (`circuit_breaker.get_ollama_circuit_breaker("ollama")`) trips CLOSED->OPEN
  after 3 sequential 240s stalls (~720s) and then returns zero real findings for the rest of the
  run "with no error surfaced anywhere in the response -- empty findings that looked identical to
  'the model found nothing'" (`config.yaml` lines ~24-33 already document this mode). Reproduced
  twice independently (D/F, 723.5s/723.9s -> the zero-LLM floor). The breaker exposes
  `.is_open`/`.state` (`circuit_breaker.py:112-124`); nothing reads it onto the response.
- **Problem:** a breaker-tripped run yields a silent, degraded, false-negative-shaped result
  (agents starved -> "found nothing") that a caller/UI cannot distinguish from a healthy clean run
  -- the same hazard class as RB-2's coordinator fail-open, but this mechanism is unsurfaced.
- **Recommendation:** at `AnalysisResponse` assembly (`orchestrator_detect.analyze`) and the
  engagement result, read the shared ollama breaker's `is_open` (and/or count agent calls
  short-circuited by OPEN during the run) and set a `degraded`/`agents_circuit_open` flag -- REUSE
  RB-2's `coordinator_fallback` pattern; for the engagement path record it in `errors` so
  `result["degraded"]` is already True. Observability only -- do NOT change the breaker's trip
  thresholds/logic (that is B2-2).
- **Acceptance:** caller-level test -- force the ollama breaker OPEN (inject) around `analyze()` ->
  the response carries the circuit-open/degraded flag and the empty-agent result is attributed to
  it, not silent; negative control -- a healthy run (breaker CLOSED) -> flag False.
- **Impact:** High (closes a silent false-negative path; the report's own recommendation #3).

### [x] B2-2 (LOOP half) -- Isolate the circuit breaker per run + fail a starvation cascade loudly
- **Result (VERIFIED):** `7927d7e` -- OFF/opt-in offline seam added to
  `harness/circuit_breaker.py` (pure append, +172 / 0 deletions; no existing line,
  threshold, `_should_trip`/`_should_reset`, `__init__` default, registry, or
  `get_ollama_circuit_breaker` touched): `reset_ollama_circuit_breaker()`,
  `scoped_ollama_breaker()` CM (snapshot->reset-CLOSED->restore-on-exit incl. on
  exception), `raise_if_ollama_starved()` -> `CircuitStarvationError` when OPEN
  (loud-fail), internal `_set_state()` mutating only the state fields the existing
  async reset/force-open own. The new API is invoked from NO committed run path
  (grep-verified: symbols appear only in their defs + the test) -> default behavior
  byte-for-byte unchanged, the deliberate process-wide singleton sharing preserved.
  Scoping + loud-fail ONLY; `config.yaml` unchanged; untracked owner driver
  `run_ablation_live.py` left untouched. +6 caller-level tests
  (`harness/test_circuit_isolation.py`): isolation positive x2 (run-1 forces OPEN ->
  scoped/reset run-2 sees CLOSED), loud-fail positive, 2 negative controls (healthy
  CLOSED -> no raise/no side-effect), 1 asserting the default unscoped path still
  shares the singleton; setUp/tearDown `.reset()` so no OPEN leaks (fresh-subprocess
  CLOSED check confirms). smoke exit 0; full **2490 OK / 2 skip, exit 0**.
  Opus-reviewed APPROVE (additive-only, no-run-path-invocation, sound CM restore-on-
  exception, non-tautological loud-fail confirmed at source). **OWNER half (out of loop
  scope, stays open):** raise `ollama.timeout_seconds`, GPU-headroom preflight, or bound
  per-exchange routing width, and wire the seam into the owner's live ablation re-run.
- **Domain:** Reliability - **Effort:** M - **Depends on:** B2-1 - **Mode:** LOOP (per-run scoping
  seam + loud-fail + test); **OWNER** (hardware timeout / GPU / routing-width tuning)
- **Evidence (VERIFIED):** `ABLATION_P2-2.md` -- the breaker is a process-wide shared singleton
  (deliberate, so a short-lived client accumulates failures), so variant A's trip poisoned B/D/F in
  the SAME process (they degenerated to C's floor while still inside the 60s cooldown). Report rec
  #3: "a fresh circuit breaker per run ... so a starvation cascade in one repeat cannot silently
  poison the numbers." Existing mitigation (`concurrency.max_parallel_agents: 1`,
  `ollama.timeout_seconds: 240`) is insufficient on this box (`ollama ps` 41%/59% CPU/GPU -- model
  not fully GPU-resident).
- **Problem:** (a) cross-run contamination -- a shared breaker lets one run's trip silently starve
  the next; (b) the cascade burns ~720s and then degrades silently.
- **Recommendation:** (LOOP) add a per-run circuit-breaker scoping/reset seam (mirroring the fresh
  state/cache DB the ablation driver already uses) so an eval/engagement run gets an isolated
  breaker, plus a runner-level breaker-state assertion so a starved run FAILS LOUD (raises/flags)
  instead of emitting silent zeros; ship OFF/opt-in so committed behavior is unchanged. (OWNER)
  raise `ollama.timeout_seconds`, add a GPU-headroom preflight, or bound per-exchange routing width
  -- hardware-specific, not a committed default.
- **Acceptance:** test -- two sequential runs where the first trips the breaker do NOT silently
  share it (the second still dispatches agents, or the starvation is flagged, not silent); a
  simulated stuck call surfaces the failure within a bounded number of stalls; negative control --
  normal timing -> no isolation/flag side-effects. Owner tunes the real timeout on their hardware.
- **Impact:** High (the P2-2 re-run blocker + a production reliability hazard).

### [x] B2-3 -- Issue-level `controls_clean` + per-URL FP attribution in the scorecard
- **Result (VERIFIED):** `e05c821` -- `build_scorecard` (testing/blind-target-2/
  run_blind_eval.py) gains a FAIRER issue-level view ALONGSIDE the preserved raw
  `controls_clean`/`dirty_controls`: `controls_clean_issue_level`/
  `dirty_controls_issue_level` computed by grouping surfaced control findings via
  `harness.issues.group_findings_into_issues` (pure, consumed read-only) so N
  duplicate dependency/banner findings collapse to 1 issue; `ambiguous_control_urls`
  = `control_urls & vuln_urls` excluded from the clean denominator (findings carry
  only a url, not an exchange id -> exclude the shared URL rather than guess), bounded
  to the intersection and surfaced as `n_controls_excluded_ambiguous` (auditable);
  `per_control_drivers` names the class/agent per dirty issue. Testing-side only;
  `harness/issues.py` + `config.yaml` untouched. +4 tests
  (`IssueLevelControlsCleanTests`): dedup, URL-reuse fairness, shape, and a
  genuinely-dirty NEGATIVE CONTROL that the issue-level metric still flags (mirrors
  `test_dirty_control_is_detected_not_quarantined`) -- all on synthetic
  `eval-fixture.invalid` fixtures + the canned-model stub, no answer-key/app.py/real
  corpus read. Module 18 OK; smoke exit 0; full **2490 OK / 2 skip** (testing tier
  27->31), exit 0. Opus-reviewed APPROVE (raw metric preserved, exclusion bounded +
  auditable, non-tautological negative control confirmed at source). **OWNER re-run:**
  the real-model blind scorecard now reports the fair issue-level number. **Follow-on
  (noted):** if findings gain exchange-id provenance, revisit the ambiguous-URL
  exclusion to attribute rather than exclude.
- **Domain:** Evaluation - **Effort:** S - **Depends on:** none - **Mode:** LOOP builds; OWNER re-runs
- **Evidence (VERIFIED):** `reviews/2026-09-22/BLIND_SCORECARD_P0-3.md` -- `build_scorecard`
  computes `dirty_controls` PER URL (not per exchange), so a URL shared between a `confirmed_vuln`
  and a `confirmed_secure` exchange (`GET /api/tickets/1`, exchanges 5 & 7) marks the secure control
  dirty from the real IDOR finding, overstating "0/5". It also counts RAW findings, not post-RB-3
  issues.
- **Problem:** the controls-clean denominator overstates the FP problem (URL-reuse false-dirty +
  raw findings vs issues), so it is not the fair number for the RB-2b decision.
- **Recommendation:** add to `build_scorecard` an issue-level controls-clean metric (via
  `issues.group_findings_into_issues`, not raw findings) + a per-control breakdown naming the
  class/agent driving each dirty control; exclude/flag a control URL that also hosts a labeled vuln
  exchange from the clean denominator. Keep the raw metric alongside for comparability.
- **Acceptance:** stubbed test -- N duplicate banner findings on one control -> 1 issue; a control URL
  that also hosts a labeled vuln exchange is not counted dirty solely from that vuln's finding; the
  scorecard emits raw + issue-level controls-clean + the per-control driver list.
- **Impact:** Medium-High (the fair denominator P0-3/RB-2b needs).

### [x] B2-3b -- Attribute control findings by (method, url), not url alone (corrects B2-3)
- **Result (VERIFIED):** `e560f6e` -- `build_scorecard` now keys `control_pairs`/`vuln_pairs`
  on `(method.upper(), url)` at construction, so the ambiguity intersection, the
  `n_controls_issue_level` denominator, and the finding-attribution `_pair(f)` share one
  uppercased case-space; a control is excluded only when a labeled vuln has the SAME method
  AND url. Vuln labels restricted to explicit `_VULN_LABELS={'confirmed_vuln'}` (inconclusive
  no longer removes a control). Host-wide banner/dependency findings
  (`harness.issues._is_dependency_class`, read-only) split into new
  `host_level_issues_on_controls` and excluded from the per-control decision (architect
  ruling: host-scoped, not endpoint-scoped). `per_control_drivers` one entry per dirty
  `(method,url)`; duplicate `dirty_controls_issue_level` key removed; added
  `n_controls_clean_issue_level`/`n_controls_issue_level` counts, issue-level metric added to
  `_VARIANCE_METRICS`/`aggregate_variance` and the `_live_main` summary; raw fields untouched.
  Testing-side only (`harness/issues.py`+`config.yaml` untouched). +tests (23 total in
  `test_blind_eval_harness.py`): rewritten URL-reuse (GET vuln vs DELETE control clean),
  hidden-FP guard (DELETE control with own finding -> `controls_clean_issue_level` False, RED
  against url-only logic), mixed-case same-method guard (`delete` vs `DELETE`, RED against
  raw-case construction), host-wide-exclusion, inconclusive-not-excluding, genuinely-dirty
  negative control. smoke 92 OK; full **2490 OK / 2 skip** (testing tier 36), exit 0.
  Opus-reviewed APPROVE after one REVISE (method-case was normalized only downstream; fixed at
  source + a mixed-case regression test added). **OWNER re-run:** the real-model blind scorecard
  now reports the fair (method,url)-attributed issue-level number.
- **Domain:** Evaluation - **Effort:** S - **Depends on:** B2-3 - **Mode:** LOOP builds; OWNER re-runs
- **Evidence (VERIFIED, 2026-09-22, stubbed repro):** `e05c821`'s `build_scorecard` keys control and
  vuln exchanges by url only and excludes any shared url from the issue-level denominator, on the
  premise that findings "carry no exchange id, only a url". Stored findings also carry `method`
  (`store.py` `findings.method`, returned by `all_host_findings`, part of `finding_fingerprint`), and
  the corpus's shared url splits by method: exchange 5 `GET /api/tickets/1` (`confirmed_vuln`) vs
  exchange 7 `DELETE /api/tickets/1` (`confirmed_secure`). Repro (GET vuln + DELETE control on one
  url, each with a surfaced finding): raw `controls_clean=False` (2 dirty) but
  `controls_clean_issue_level=True`, `dirty_controls_issue_level=[]`,
  `n_controls_excluded_ambiguous=1` -- the DELETE control's own FP is hidden. The URL-reuse test
  passes only because `_exchange()` hardcodes `method: "GET"` for both exchanges.
- **Problem:** the "fair" metric can read clean while a control is dirty -- the opposite of B2-3's
  intent -- and it is the number RB-2b is gated on. Secondary: any non-control label (including the
  corpus's 2 `inconclusive`) counts as a vuln for exclusion; the issue-level metric is missing from
  `_VARIANCE_METRICS` and the `_live_main` summary; `per_control_drivers` is per issue (a multi-control
  banner issue reports only `affected_instances[0]`) and duplicates `dirty_controls_issue_level`.
- **Recommendation:** key the issue-level control/vuln sets on `(method.upper(), url)`; exclude only
  when a labeled vuln exchange has the same method AND url. Use an explicit vuln-label set instead of
  "any non-control label". Add the issue-level metric plus a clean/total count to
  `_VARIANCE_METRICS` and the console summary. Make the driver list per control `(method, url)`; drop
  or differentiate the alias key. Leave the raw fields untouched for comparability.
- **Acceptance:** stubbed tests -- GET vuln + DELETE control on one url: the control is in the
  denominator and clean when only the vuln has a finding; the same pair with a surfaced finding on
  the DELETE control -> `controls_clean_issue_level=False` (NEGATIVE control, the repro above); a
  same-method-and-url pair is still excluded; an `inconclusive` exchange sharing a control's
  method+url does not exclude it; `aggregate_variance` reports the issue-level metric. `full` green.
- **Impact:** High (otherwise the owner re-run reports a wrong fair number). **Pick before B2-4.**

### [x] B2-4 (LOOP half) -- Make `cross_identity_reject` stubbed-testable + recorded in the manifest
- **Result (VERIFIED):** `d1f6390` -- (a) the cross-identity REJECT/downgrade path is now proven
  OFFLINE with NO production change: the deterministic non-LLM block in
  `orchestrator_confirm._validate_findings` (:550-566, cap `_CROSS_IDENTITY_REJECT_CAP=0.15`)
  already downgrades a finding to confidence 0.15 / severity low / `review_verdict="downgraded"`
  (stamping `original_confidence`) when a `cross_identity` validator returns `not_confirmed`. New
  `harness/test_cross_identity_reject.py` (+4) drives the REAL `_validate_findings` via a stub
  validator (temp store, stub ollama never contacted): POSITIVE (cross_identity not_confirmed ->
  downgraded); NEGATIVE controls (unrelated validator / none present -> untouched 0.6/high/None);
  edge (already <=cap not re-stamped). REJECT on/off modeled by validator PRESENCE/ABSENCE, NOT a
  new config gate. (b) `build_scorecard` gains a `cross_identity_reject` param + returned-dict key;
  `run_once` computes it = `active_enabled AND cross_identity.enabled`; `_live_main` prints it. +5
  scorecard tests. The armed `run_once` test sets the flags on an in-memory config copy ONLY and
  fails CLOSED on scope (`eval-fixture.invalid` outside committed `allowed_hosts:[]`) -> no live
  traffic, no committed config mutation. B2-3/B2-3b metric code untouched. smoke 92 OK; full
  **2494 OK / 2 skip** (testing tier 41), exit 0. Opus-reviewed APPROVE (real caller-level exercise,
  non-trivial negative controls, no config/production change, fail-closed confirmed at source).
  **OWNER/LIVE half stays open (`[ ]` in spirit):** the real REJECT-on precision number still needs
  `validators.active_enabled` + `validators.cross_identity.enabled` + the blind-target-2 Flask app on
  `127.0.0.1:5002`.
- **Domain:** Evaluation / Precision - **Effort:** M - **Depends on:** none - **Mode:** LOOP builds
  (stubbed); **OWNER/LIVE** runs it (needs `validators.active_enabled` + the blind-target-2 Flask app
  on `127.0.0.1:5002`)
- **Evidence (VERIFIED):** `BLIND_SCORECARD_P0-3.md` -- the run used `HARNESS_CROSS_IDENTITY_REJECT=0`;
  it "is the one documented lever ... that should directly cut the IDOR-shaped FPs on secure endpoints,
  but it turns on `validators.active_enabled` and sends live ... requests," so the precision lever most
  likely to clean the controls was never exercised or measured.
- **Problem:** the scorecard cannot show precision with the intended fixes engaged (REJECT needs live
  traffic and was off), and the manifest does not make the REJECT state a first-class recorded axis.
- **Recommendation:** (LOOP) make the cross-identity REJECT/downgrade path provable OFFLINE with a
  stubbed model + a synthetic cross-identity control FP (REJECT on -> suppressed/downgraded; off ->
  surfaced), and record `cross_identity_reject` on/off in the blind manifest + scorecard so a
  REJECT-on run is self-describing. (OWNER/LIVE) the live REJECT run produces the real precision
  number. Do NOT enable `active_enabled` in committed config.
- **Acceptance:** stubbed test -- a synthetic cross-identity control FP is REJECTED/downgraded with
  REJECT on and surfaced with it off; the manifest/scorecard records the REJECT state.
- **Impact:** High (unblocks a fair precision measurement + a real precision lever).

### [x] B2-5 -- Gate the generic low-confidence agent guesses (the dominant FP driver)
- **Result (VERIFIED):** `53d6d66` -- evidence-gated suppression shipped OFF. New SIBLING
  predicate `is_low_confidence_generic_guess` in `confirmation_gate.py`
  (`should_quarantine_as_lead` untouched): True only when NOT confirmed, NOT oracle_verified,
  confidence is a real number `< floor`, and the canonicalized class is in a narrow 3-element
  `DEFAULT_GENERIC_CLASSES` (misconfig / broken-access-control-workflow-bypass / sqli; exact-key,
  no substring). RECALL GUARD (hard invariant, reviewer-confirmed airtight): confirmed /
  oracle_verified / at-or-above-floor findings are NEVER gated (strict `<`). `generate_markdown_report`
  gains `gate_low_confidence_generic` (default False) + `generic_confidence_floor` (0.5); matches route
  into the existing leads bucket. Both flags False => byte-for-byte the pre-B2-5 output (proven by an
  `assertEqual` on the full report string). `config.yaml`: `reporting.gate_low_confidence_generic: false`
  + `generic_confidence_floor: 0.5` ADDED, both OFF; NO existing default flipped (SafeDefaultGuardTests +
  `test_committed_config_defaults_stay_safe` green). `run_blind_eval.py` threads both flags from config so
  the measurement driver can enable them; B2-3/B2-3b metric code untouched. +16 tests
  (`test_gate_generic_guesses.py`): positive routed-to-leads, recall negative control (confirmed +
  high-confidence same class stay surfaced), flag-off byte-for-byte no-op, FP-drop-no-TP-loss, predicate
  units. smoke 92 OK; full **2510 OK / 2 skip**, exit 0. Opus-reviewed APPROVE (config-safe, recall guard,
  no-op equivalence all verified at source). **OWNER-reported:** the real FP-drop on the blind corpus is
  measured by a real-model run with the flag on (the lever is now available + measured offline).
- **Domain:** Precision - **Effort:** M - **Depends on:** none (uses B2-3's attribution) - **Mode:** LOOP
- **Evidence (VERIFIED):** `BLIND_SCORECARD_P0-3.md` -- "the dominant FP driver ... generic
  low-confidence agent guesses (`Security misconfiguration`, `Broken Access Control (Workflow
  Bypass)`, `SQL injection` at confidence 0.3-0.5) fire on nearly every exchange regardless of actual
  target behavior" (9 spurious findings on a bare `POST /register` alone). These are SURFACED
  findings, which is why quarantine (2/60, leads-only) did not catch them.
- **Problem:** unconfirmed, low-confidence generic-class findings are surfaced on nearly every
  exchange, driving the controls-clean failure.
- **Recommendation:** an evidence-gated suppression / down-rank for UNCONFIRMED, low-confidence
  (< floor), generic-class findings with no confirming leg -- e.g. extend `should_quarantine_as_lead`
  to route this surfaced-but-unconfirmed class to leads, or down-rank it out of the surfaced set.
  Must NEVER suppress a confirmed finding or a high-confidence one (recall guard). Config-gated +
  measured, not a blanket threshold flip.
- **Acceptance:** caller-level test -- a synthetic UNCONFIRMED generic finding at confidence 0.4 on a
  clean exchange is NOT surfaced (-> leads/down-ranked); a CONFIRMED finding and a high-confidence
  finding on the same exchange ARE surfaced (recall negative control); on a small fixture the
  surfaced-FP count drops with no TP lost.
- **Impact:** High (directly targets the measured 0/5 controls-clean).

> **OWNER/LIVE follow-ups this batch unblocks (not loop-consumable):** the P2-2 ablation re-run once
> B2-1/B2-2 land (prioritise A-vs-B -- B ran clean); the cross-identity REJECT-on live precision run
> (B2-4, needs the Flask app + active-validator opt-in); the >=5-run variance pass; and the RB-2b
> `curated` flip decision, now gated on a REJECT-on, issue-level, variance-backed number -- not the
> single REJECT-off raw-count sample.

---

## External-review borrow batch -- 2026-09-22 (ER-1..ER-5)

Filed from a user-requested objective evaluation (this session) of external LLM-pentest projects
against this codebase: **burpai** (Java/Montoya + Ollama; timing-based blind detection, AgentLoop,
TargetMemoryStore/AttackGraph), **hackingBuddyGPT** (run-governance: `max_rounds`/`max_tokens`/
`max_cost`/`max_duration` + OpenTelemetry JSONL traces + ground-truth `check_success`), and **Strix**
(no finding without a reproducible PoC). Most of those ideas were found ALREADY PRESENT here in a
more mature form (leg-tiered `confirmation_gate`, controlled-negative refutation, `EvidenceLedger`,
`EffortBudget` SOFT/HARD token modes) -- so only the genuinely-additive remainder is filed below.

**De-dup (do NOT re-implement):** surfacing a breaker-OPEN run as `degraded` is already **B2-1**;
per-run breaker isolation + loud-fail on a starvation cascade is already **B2-2**. ER items must
REUSE those, not build a parallel mechanism.

**Freeze compliance (updated 2026-09-23):** P2-2 landed = **COLLAPSE**
([reviews/2026-09-23/ABLATION_P2-2_RERUN.md](reviews/2026-09-23/ABLATION_P2-2_RERUN.md)).
The freeze that gated ER-3/ER-5 has therefore *resolved against adding surface*: both widen the
detection surface the collapse just trimmed, so they stay **DEPRIORITIZED**, not auto-unblocked
into pickable work. Do NOT pick ER-3/ER-5 on the strength of "P2-2 is now `[x]`"; reopen them only
if the collapse is later shown to hurt recall on a broader corpus. **Loop pick order (only the
unblocked ones):** ER-1 -> ER-2 -> ER-4. `Mode: LOOP` = offline,
stubbed-model-testable. The non-negotiables at the top of this file apply (safe config defaults, a
caller-test + negative control per item, never read `*ANSWER_KEY*`/a blind `app.py`,
`python -m harness.suite full` before closing).

### [x] ER-1 -- Add a wall-clock/duration dimension to `EffortBudget`
- **Result (VERIFIED):** `ad6e829` -- `EffortBudget` gains `max_duration_s: int|None=None`
  (mirrors `total_tokens=None`: track-but-never-block) + an injectable per-instance
  `clock: Callable=time.monotonic` seam (deterministically testable, no real sleeps). A
  monotonic `_deadline` is set on the FIRST `record()` (not construction), so an idle
  never-dispatched budget never trips; `_deadline_passed()` is False when unset/None. `allow()`
  folds the deadline into the EXISTING SOFT/HARD branching -- no new `BudgetMode`, one reused
  `_overspend_confirmed` flag: HARD deadline stop is not talk-past-able; SOFT returns
  awaiting-confirmation and `confirm_overspend()` unblocks either the token OR duration limit;
  token-exhaustion reason takes precedence if both trip; `exhausted()` stays token-only. Ships
  UNSET => byte-for-byte no-op; `config.yaml`/`orchestrator.py` untouched (constructor-arg-only,
  all existing call sites pass only mode+total_tokens and still work). +5 tests
  (`EffortBudgetDurationTests`, `_FakeClock` counter): HARD block+ignore-confirm, SOFT
  block-until-confirm-then-allow, None no-op negative control (advances clock 10Ms -> still
  `(True,"")`), before-deadline negative control, deadline-on-first-spend-not-construction. smoke
  92 OK; full **2515 OK / 2 skip**, exit 0. Opus-reviewed APPROVE (strict None no-op, no HARD
  bypass, deterministic clock, additive-only allow() all confirmed at source).
- **Domain:** Reliability / Governance - **Effort:** S - **Depends on:** none - **Mode:** LOOP
- **Evidence (VERIFIED by source inspection):** `harness/effort.py:98-150` -- `EffortBudget` gates
  only on `total_tokens` (SOFT/HARD) and `spent`; there is no time dimension. `allow()` never
  consults a deadline. The P2-2 stall (`reviews/2026-09-22/ABLATION_P2-2.md`) burned ~720s of
  wall-clock with no run-level deadline to stop it; B2-2 isolates/loud-fails the *breaker*, but no
  budget object bounds *elapsed time* independent of the breaker. (Borrowed from hackingBuddyGPT's
  `max_duration` run limit.)
- **Problem:** a run can consume unbounded wall-clock (a slow/degraded backend, a long redirect
  chain, a stuck leg) while still under token budget, with no clean, caller-visible abort.
- **Recommendation:** add optional `max_duration_s: int | None` (default `None` = track-but-never-
  block, mirroring `total_tokens=None`) and a monotonic `deadline` set on first spend; extend
  `allow()` to also return `(False, reason)` when the deadline is passed, with the same SOFT (warn/
  confirm) vs HARD (stop) semantics already implemented. Ships unset -> byte-for-byte no-op.
- **Acceptance:** caller-level test -- a budget with a short `max_duration_s` returns `allow()==False`
  with a duration reason once the deadline passes, HARD stops / SOFT warns-then-confirms; negative
  control -- `max_duration_s=None` and an under-deadline budget both keep `allow()==True` and are
  behaviourally identical to today. `full` suite green.
- **Impact:** Medium-High (a clean elapsed-time stop, complementary to B2-2's breaker isolation).

### [x] ER-2 -- Emit one canonical per-run trace summary onto the EvidenceLedger
- **Result (VERIFIED):** `0ad91e6` -- new additive `EventType.RUN_SUMMARY`; `analyze()` captures
  `_run_start` (monotonic) + `owns_run = run_context is None` at method top (before it self-creates
  a RunContext), and just before return, when `owns_run`, emits ONE `RUN_SUMMARY` via the EXISTING
  `evidence_ledger.emit` onto the default ledger (single-ledger reuse, no second ledger) with
  `Provenance.capture`. Payload: `tokens_total` (== `EffortLedger.total_tokens`), `tokens_breakdown`,
  `elapsed_s`, `degraded` (== the B2-1 `agents_circuit_open` flag), `validator_count`/`leg_count`;
  `finding_ref`/`case_ref` = `run_context.run_id` (non-empty so the event lands). Wrapped best-effort
  (try/except log-and-continue) -> can NEVER raise into `analyze()` or alter the response; no
  verdict/severity/scope/config change. `owns_run` gating => exactly one summary per standalone run,
  ZERO when `analyze()` is nested in an engagement (shared run_context) -> no per-exchange
  multiplication; cache-hit early return emits nothing. +4 tests (`test_run_summary_ledger.py`, stub
  model, breaker+default-ledger reset in setUp/tearDown): exactly-one positive, healthy negative
  control (degraded False + non-zero elapsed), degraded positive (breaker forced open), multiplication
  guard (nested analyze -> 0 summaries). smoke 92 OK; full **2519 OK / 2 skip**, exit 0. Opus-reviewed
  APPROVE (single-ledger reuse, best-effort isolation, owns_run captured pre-self-create, non-empty
  finding_ref all confirmed at source).
- **Domain:** Observability / Evaluation - **Effort:** S - **Depends on:** B2-1 - **Mode:** LOOP
- **Evidence (VERIFIED by source inspection):** `harness/ablation_harness.py:231-278` recomputes
  tokens / wall-clock / tp-fp-fn ad hoc per arm; `EffortLedger.breakdown()` (`effort.py:90-94`) and
  the `EvidenceLedger` already hold the raw material, but no single run-summary event ties
  tokens + duration + degraded-state + tool/leg counts together. (Borrowed from hackingBuddyGPT's
  JSONL run traces + `log-analyze` aggregate.)
- **Problem:** run-level metrics the ablation/variance work (P2-2, RB-2b's >=5-run basis) needs are
  reconstructed by hand each time and are not attached to the auditable ledger stream.
- **Recommendation:** at orchestrator/engagement teardown emit ONE `EvidenceLedger` run-summary
  event carrying `EffortLedger.breakdown()`, elapsed wall-clock, the B2-1 `degraded`/
  `agents_circuit_open` flag, and validator/leg dispatch counts. Reuse the existing ledger +
  `Provenance.capture`; add NO new logging stack and change no verdict/severity/scope.
- **Acceptance:** caller-level test -- one driven run emits exactly one run-summary event whose
  token total equals `EffortLedger.total_tokens` and whose `degraded` matches the B2-1 flag; negative
  control -- a healthy run reports `degraded=False` and non-zero elapsed. `full` suite green.
- **Impact:** Medium (cheaper, auditable variance/ablation measurement).

### [x] ER-4 -- Optional reproduction-replay determinism gate for active confirmation legs
- **Result (VERIFIED):** `bf8cea3` -- config-gated `confirm_replay` (DEFAULT OFF). `orchestrator.py`
  reads `self.confirm_replay = validators.confirm_replay`; `orchestrator_confirm._maybe_replay`
  wraps `validator.validate()` at the dispatch loop (one job per finding/validator preserved, `zip`
  untouched). When ON AND `validator.name in {ssrf,ssti,command_injection}` AND the first result
  confirmed, it re-runs `validate()` ONCE through the SAME scope/throttle/budget/mutating gating
  (never a hand-rolled re-send): both agree -> stays CONFIRMED; disagree -> returns a
  `confirmed=False`/`status="not_confirmed"` result so the EXISTING `confirmation_gate` routes the
  finding to its provisional/unproven tier (no new downgrade mechanism, only existing
  `ValidationResult` fields). When OFF / out-of-scope marker / first-not-confirmed -> returns the
  ORIGINAL result object, exactly one `validate()` call, byte-for-byte unchanged. `config.yaml`:
  `validators.confirm_replay: false` (OFF; `active_enabled`/`allow_mutating_replay` untouched;
  SafeDefaultGuardTests green with the key present-and-false). +4 tests (`test_confirm_replay.py`,
  scripted stub validator through the REAL `_validate_findings`): positive-agree (confirmed, validate
  called TWICE), downgrade-disagree (unconfirmed, status not_confirmed), OFF byte-for-byte negative
  control (validate called ONCE, confirmed True), out-of-scope marker not replayed (one call). smoke
  92 OK; full **2523 OK / 2 skip**, exit 0. Opus-reviewed APPROVE (OFF identity-return + single call,
  replay-via-validate()-only, scope+first.confirmed short-circuit, downgrade-reuse, zip in-sync all
  confirmed at source). **OWNER (owner-reported efficacy):** measure precision with `confirm_replay`
  on vs off on the blind corpus; doubles active traffic only when explicitly enabled.
- **Domain:** Precision / Trust - **Effort:** M - **Depends on:** none - **Mode:** LOOP
- **Evidence (VERIFIED by source inspection):** active legs stamp `confirmed=True` from a single
  successful observation (e.g. one OOB callback / one differential); `confirmation_gate` then trusts
  it. The P0-3 scorecard caveat (`reviews/2026-09-22/BLIND_SCORECARD_P0-3.md`) and P0-6 both flag
  single-shot confirmations as a precision risk. (Borrowed from Strix's "no finding without a
  reproducible PoC".)
- **Problem:** a flaky single observation (transient timing, a shared-state artifact) can produce a
  `confirmed=True` that would not reproduce, inflating precision.
- **Recommendation:** add a config-gated `confirm_replay` (DEFAULT OFF, safe-defaults preserved):
  when on, an active leg that confirms re-runs its confirming request once and only keeps
  `confirmed=True` if BOTH agree; on disagreement it downgrades to the provisional/unproven path the
  gate already implements. Start with `ssrf` / `ssti` / `command_injection`. Doubles active traffic
  only when explicitly enabled; stays within scope/throttle/budget/`allow_mutating_replay`.
- **Acceptance:** caller-level test -- with `confirm_replay` on, a leg that confirms twice stays
  CONFIRMED; a leg that confirms once then fails the replay is NOT confirmed (routed to
  provisional); negative control -- with `confirm_replay` off (shipped default) behaviour and traffic
  are byte-for-byte unchanged. `full` suite green.
- **Impact:** Medium (a precision guard for the single-shot-confirmation risk P0-3/P0-6 name).

### [ ] ER-3 -- Time-based blind-injection fallback confirmation leg (provisional tier)  [DEPRIORITIZED — P2-2 decided COLLAPSE]
- **Domain:** Efficacy / Coverage - **Effort:** L - **Depends on:** P2-2 [ ] (new-validator freeze) - **Mode:** LOOP-BUILD (gated)
- **Evidence (VERIFIED by source inspection):** no timing/latency confirmation exists -- `grep`
  `elapsed|latency|timing|perf_counter|response_time` across `harness/validators/` returns nothing;
  blind SSRF/XXE/command-injection confirmation is OOB-collaborator-only
  (`harness/validators/registry.py:181-197`). (Borrowed from burpai's `fuzz_parameter`
  timing-anomaly: response `> N s` absolute OR `> K x` baseline.)
- **Problem:** the OOB legs cannot confirm on egress-filtered targets where the collaborator callback
  can't return -- a real blind spot with no fallback today.
- **Recommendation (DEPRIORITIZED — P2-2 decided COLLAPSE; do not start unless the collapse is shown to hurt recall):** add a `timing_validator` that samples a
  per-endpoint baseline and flags a payload whose latency exceeds an absolute floor AND a
  baseline-multiple, requiring multiple confirming samples to control jitter FPs. Register it
  `active=True` (gated by `active_enabled` + `allow_mutating_replay`); add its markers to
  `PROVISIONAL_MARKERS` in `confirmation_gate.py` ONLY -- never `LIVE_VERIFIED_MARKERS` (so the gate
  caps it at medium, matching its higher FP rate).
- **Acceptance:** caller-level test on a stable-latency fixture -- an injected artificial delay
  confirms (provisional), a normal endpoint does not; negative control -- a slow-but-benign endpoint
  under natural jitter is NOT confirmed. `full` suite green. Ships OFF/active-gated.
- **Impact:** Medium-High if P2-2 keeps the validator layer; **held** so it doesn't widen detection
  surface before the ablation decides keep/collapse.

### [ ] ER-5 -- Per-class methodology priming for specialist agents  [DEPRIORITIZED — P2-2 decided COLLAPSE]
- **Domain:** AI / Efficacy - **Effort:** M - **Depends on:** P2-2 [ ] (new-surface freeze) - **Mode:** LOOP-BUILD (gated)
- **Evidence (SUPPORTED):** external `SnailSploit/Claude-Red` (MIT) carries ~20 concrete web/API/auth
  attack-methodology skills (SQLi/IDOR/SSRF/etc.) usable as detect-side priming; VulnBot shows the
  RAG-over-methodology pattern. This codebase primes agents from `agents/base_agent._COMMON_RULES`
  + a specialty prompt, with no per-class methodology corpus keyed off `categories.py`.
- **Problem:** detection priming is generic; concrete per-class methodology could lift recall on the
  detect side -- but this expands the detection surface the P2-2 ablation is meant to justify first.
- **Recommendation (DEPRIORITIZED — P2-2 decided COLLAPSE; do not start unless the collapse is shown to hurt recall):** curate the MIT web/API/auth methodology
  into per-class prompt snippets keyed on `categories.canonicalize`, injected into the matching
  specialist agent's prompt only. Prompt-only (no new agent module, no new send authority); attribute
  the MIT source. Keep behind a default-off flag and measure recall ON vs OFF on P0-3's corpus.
- **Acceptance:** caller-level test -- the SQLi/IDOR specialist prompt includes its class snippet when
  the flag is on and is byte-for-byte unchanged when off (negative control); `_prompt_version` bumps
  only when on. Efficacy (owner-reported) -- recall ON vs OFF on the P0-3 corpus, kept only if it
  helps without hurting precision. `full` suite green.
- **Impact:** Medium (cheap recall lever) -- **held** behind P2-2 to avoid growing surface pre-ablation.

---

## Architecture rebalance batch -- 2026-09-22 (AR-1..AR-3)

Filed from a user-requested architecture review (this session: `docs/ARCHITECTURE.md`, a
module/config survey, and the P0-3/P2-2 live-run reports). Verdict: the core shape is sound (the
model proposes, deterministic legs confirm, `confirmation_gate` routes unconfirmed findings to
leads, evidence ledger, layered scope/safety) -- do NOT rewrite. The items below move weight off the
parts the live runs show failing. A fourth concern, the overlapping evaluation layers, is already
**P1-3**; new evidence was added there instead of filing a duplicate.

**Freeze compliance:** AR-1 builds a consolidation *candidate* for P2-2 to measure. It adds no
detection class or validator and ships OFF, matching P2-2's own recommendation (collapse to agent
families if recall holds) and the "prefer changes that reduce components" rationale above.
**De-dup:** AR-2 generalizes B2-2's opt-in breaker seam and subsumes the "live-driver wiring" part
of B2-2's OWNER half; it must reuse `scoped_ollama_breaker`/`raise_if_ollama_starved` semantics, not
build a second breaker. **Pick order within the batch:** AR-2 -> AR-3 -> AR-1. Placement relative to
Batch 2 / ER is the owner's call; recommended before the P2-2 re-run (AR-2 is a reliability
prerequisite; AR-1 supplies the collapse candidate). The non-negotiables at the top of this file
apply (safe config defaults, a caller-test + negative control per item, never read
`*ANSWER_KEY*`/a blind `app.py`, `python -m harness.suite full` before closing).

### [x] AR-1 (LOOP half) -- Opt-in agent-family routing mode as the P2-2 collapse candidate (ablation variant G)
- **Result (VERIFIED):** `994e5a0` -- owner decided the P2-2 ablation = COLLAPSE with a required
  revert path; this lands the reversible opt-in mechanism. New `harness/agent_families.py` (routing/
  composition module OUTSIDE `harness/agents/`; NO new agent modules, NO new detection class):
  `DEFAULT_FAMILIES` (6 disjoint families covering all 36 registered agents, membership verified
  against the live plugin registry at runtime), `group_dispatched_agents`, `compose_family_prompt`,
  `FamilyRunner` (one composed model call per routed family from members' existing
  `specialty_prompt`/`tactical_guide`, preserves each finding's `vulnerability_class` verbatim, labels
  `AgentReport.agent="family:<name>"` for observability). `agent_manager.run_multiple_agents` branches
  on `coordinator.routing_mode`: default `"agents"` = `_run_multiple_agents_default` (original body
  VERBATIM) -> **OFF is the byte-for-byte revert state**; `"families"` = one call per routed family
  (solo fallback for agents in no family, never dropped). `_choose_agents`/dispatch untouched;
  confirmation/validator routing keys on `vulnerability_class` (not `AgentReport.agent`) so it is
  invariant (parity tested). `config_schema` adds `routing_mode` + `_VALID_ROUTING_MODES` (NOT a
  SafeDefaultGuard SAFE_CHECK -- reduces model calls, no traffic/scope); `config.yaml` adds
  `coordinator.routing_mode: "agents"` (safe default, no existing default flipped). `ablation_harness`
  gains `Variant("G")` (reuses RB-7's mechanism). +16 tests incl. the 3 owner-mandated REVERT tests
  (OFF==baseline byte-for-byte; ON deterministic; ON->OFF==original with NO residual state), call-count
  (families<agents), confirmation parity, stub reachability. Updated 8 `test_ablation_harness`
  assertions A-F->A-G (acceptance requires VARIANTS to list G; no defect-injection/arm assertion
  weakened -- reviewer-verified). smoke 92 OK; full **2539 OK / 2 skip**, exit 0. Opus-reviewed APPROVE
  (revert guarantee + no residual state, confirmation parity, legitimate ablation edits, config safety
  all confirmed at source). **OWNER measures** in the P2-2 re-run via variant G: recall/precision/model-
  cost of `routing_mode: families` vs the full agents set; keep the collapse only if recall holds, and
  revert by flipping the flag back to `"agents"` (default) if it doesn't.
- **Domain:** AI / Architecture / Performance - **Effort:** M - **Depends on:** none (feeds P2-2) - **Mode:** LOOP builds; OWNER measures in the P2-2 re-run
- **Evidence (VERIFIED by source inspection, 2026-09-22):** 36 specialist agent modules in
  `harness/agents/`, most 33-55 lines of prompt wrapper over `base_agent.py` (411 lines). Routing
  averages ~5.8 agents/exchange via `fast_path` (`config.yaml:98` comment), each a separate serial
  model call (`concurrency.max_parallel_agents: 1`, `ollama.timeout_seconds: 240`), and falls back
  to every agent when routing returns nothing (`coordinator.fail_open_mode: "all"`,
  `config.yaml:89`). Live (owner-reported): the P2-2 stall/breaker cascade
  (`reviews/2026-09-22/ABLATION_P2-2.md`); B (one forced agent) recall 0.364 vs A (full routing,
  degraded) 0.182; P0-3's dominant FP driver is generic low-confidence guesses across many
  exchanges. `ablation_harness.VARIANTS` (A-F) has no variant for the consolidation P2-2 names, so
  even a clean re-run can only answer through proxies (B, F).
- **Problem:** per-exchange model calls scale with routed-agent count on hardware that serializes
  inference, and P2-2 cannot measure the actual collapse candidate.
- **Recommendation:** add `coordinator.routing_mode` (`"agents"` default = today, byte-for-byte;
  `"families"` opt-in) that groups the existing agents into a small number of families (~5-7; the
  grouping is proposed and justified in the item's review) and issues one model call per routed
  family, composed from the member agents' existing prompts -- no new detection logic. Findings keep
  their per-class `vulnerability_class`, so confirmation/validator routing is unchanged. Register it
  as variant G in `harness/ablation_harness.py`. Do not touch `fail_open_mode` (that is RB-2b).
- **Acceptance:** caller-level stubbed test -- `"families"` issues at most one model call per routed
  family per exchange (counted at the model stub) where `"agents"` issues one per routed agent; a
  canned finding from a family call reaches the same confirmation/validator dispatch as the same
  finding from its member agent; NEGATIVE control -- `"agents"` mode dispatch and call counts are
  identical to before; `config.yaml` default unchanged; `VARIANTS` lists G. `full` suite green.
- **Impact:** High (gives P2-2 the real collapse candidate; if recall holds, it cuts serial model
  calls per exchange several-fold on the hardware that currently starves).

### [x] AR-2 (LOOP half) -- Run-scoped model-backend state by default (breaker + fail-open counters on `RunContext`)
- **Result (VERIFIED):** `077b772` -- generalizes B2-2's opt-in seam: a RunContext now owns its own
  `OllamaCircuitBreaker` (built with the SAME config as `OllamaClient.__init__`) + fail-open counters,
  resolved via an ambient ContextVar mirroring `safety_gate._gate_ctx` (the concurrency requirement
  B2-2's snapshot/restore singleton could not meet). `circuit_breaker.py`: `_ollama_breaker_ctx` +
  push/pop (plain get/set, cross-Task safe) + `current_ollama_breaker(name)` (ambient if pushed, ELSE
  `get_ollama_circuit_breaker(name)` unchanged); `raise_if_ollama_starved` generalized; B2-2 primitives
  untouched (no second breaker/registry). `run_context.py`: per-run breaker + counter dict built and
  pushed in `__aenter__` alongside `push_gate`, popped in `aclose()` -- lazy/opt-in (nothing built
  unless `async with`). `coordinator.py`: `fail_open_stats`/`_record_fail_open` resolve the ambient
  run's counters else module-global `_FAIL_OPEN`. `ollama_client._chat` resolves at CALL TIME (keeps
  `self.circuit_breaker` fallback); `orchestrator_detect` `.is_open` sites use `current_ollama_breaker()`.
  **Ships OFF byte-for-byte:** with no ambient RunContext every resolver returns the IDENTICAL pre-existing
  singleton/module-global object (assertIs-tested); NO config.yaml key; no safety flag/default touched.
  +5 tests (`test_run_scoped_backend_state.py`, singleton reset in setUp/tearDown): sequential no-poison,
  concurrent isolation (two asyncio tasks), within-run OPEN still short-circuits (isolation != disabling),
  no-run identical-singleton, never-entered allocates nothing. smoke 92 OK; full **2544 OK / 2 skip**,
  exit 0. Opus-reviewed APPROVE (byte-for-byte OFF via object-identity fallback, ContextVar task-locality,
  within-run breaker intact, reuse-not-fork + hot-path safety all confirmed). **OWNER half stays open:**
  wire `run_blind_eval.run_once` / `run_ablation_live.py` to create one RunContext per run and call
  `raise_if_ollama_starved` / record `degraded` at run end (needs live Ollama/Docker).
- **Domain:** Reliability / Architecture - **Effort:** M - **Depends on:** B2-2 (LOOP half, done) - **Mode:** LOOP
- **Evidence (VERIFIED by source inspection, 2026-09-22):** the "ollama" breaker is a process-wide
  registry singleton (`circuit_breaker.py:345-359`, `get_ollama_circuit_breaker` at :397), bound
  once per client (`ollama_client.py:121`) and read directly at `orchestrator_detect.py:909` and
  `orchestrator_chain.py:1056`; coordinator fail-open telemetry is a module global
  (`coordinator.py:27`). B2-2's `scoped_ollama_breaker` (:500) snapshots and restores that single
  instance -- correct for sequential runs, but two concurrent runs (server mode) still share one
  breaker, and one scoped block's exit restores over the other's state. No committed run path uses
  the seam (grep: only `circuit_breaker.py` and `test_circuit_isolation.py`), so the live drivers
  `run_blind_eval.py` and `run_ablation_live.py` stay exposed to P2-2's cross-run poisoning.
  `RunContext` (`run_context.py:524`) already solved the same problem for the safety gate ("A FRESH
  gate per run ... the #3 isolation fix", ambient push/restore).
- **Problem:** model-backend health and routing telemetry leak across runs, and isolation depends on
  each driver remembering to opt in.
- **Recommendation:** `RunContext` owns a per-run breaker and fail-open counters, installed as
  ambient on create and restored on `aclose()` (mirror `push_gate`). `OllamaClient`, the
  orchestrator's `is_open` reads and the coordinator counters resolve through the ambient run
  context, falling back to today's process-wide objects when none is active (server/default path
  unchanged). Wire `run_blind_eval.run_once` and the ablation runner to create one run context per
  run and call `raise_if_ollama_starved` (or record `degraded`) at run end. No trip/reset threshold
  changes.
- **Acceptance:** caller-level test -- two sequential runs in one process: run 1 trips its breaker
  OPEN; run 2's agent calls are dispatched (not zeroed) and its fail-open count starts at 0; two
  concurrent runs: tripping one leaves the other CLOSED. NEGATIVE controls -- within one run an OPEN
  breaker still short-circuits later calls; with no run context, behavior is byte-for-byte today's.
  `full` suite green.
- **Impact:** High (removes a class of silently degraded live runs; prerequisite for trusting the
  P2-2 re-run).

### [x] AR-3 -- Record which captured exchange produced each finding (exchange provenance)
- **Result (VERIFIED):** `07d650b` -- additive `HttpExchange.capture_id` (trusted transport field);
  `store.py` findings gains additive `exchange_id`/`run_id` (via `_SCHEMA` + the PRAGMA table_info
  migration guard, identities dup-column idiom) + a new `finding_observations(fingerprint, run_id,
  exchange_id, created_at)` link table (`CREATE TABLE IF NOT EXISTS`, `UNIQUE(fingerprint,run_id,
  exchange_id)`). `persist_findings` derives `exchange_id = capture_id or compute_exchange_hash[:16]`,
  `run_id = telemetry.current_run_id()`, and writes one `INSERT OR IGNORE` observation per (finding,
  exchange) -- so a DEDUPED finding still records every distinct exchange that produced it. Neither
  column enters `finding_fingerprint`/`idx_findings_fingerprint_case` -> dedup counts/fingerprints
  byte-for-byte unchanged. `all_host_findings` surfaces the ids; new `finding_observations()` reader.
  `build_scorecard` disambiguates shared method+url control pairs off `finding_observations` (a control
  scored on ITS OWN exchange's observations, never the vuln's finding), falling back to the exact
  B2-3b `(method.upper(),url)` logic when no observation data exists (legacy DB); new
  `n_controls_exchange_disambiguated`. This CLOSES the B2-3b follow-on (attribute rather than exclude).
  Additive/back-compat: no destructive migration, pre-AR-3 DBs migrate cleanly (legacy rows default
  ''); no config change; no safety flag/default. +tests (test_store `TestExchangeProvenanceAR3`:
  round-trip, content-hash fallback, second-observation-row, pre-AR3-DB migration; test_blind_eval
  `ExchangeProvenanceAttributionAR3Tests`: same-url control now SCORED, no-dup corpus byte-for-byte
  unchanged); pre-existing mixed-case B2-3b test updated to the more-precise disambiguated-clean
  outcome (case-normalization regression still caught via the disambiguation counter). smoke 92 OK;
  full **2548 OK / 2 skip**, exit 0. Opus-reviewed APPROVE (dedup unchanged, back-compat migration,
  attribution-off-observations + legacy fallback, legitimate B2-3b test update all confirmed at source).
- **Domain:** Evaluation / Data model - **Effort:** M - **Depends on:** none (B2-3b is the method+url stopgap) - **Mode:** LOOP
- **Evidence (VERIFIED by source inspection, 2026-09-22):** the `findings` table (`store.py:58-84`)
  has host/url/method/agent/fingerprint/case/proof ids but no exchange or run identifier, and
  `persist_findings` dedups via `INSERT OR IGNORE` on a fingerprint of host+method+url+class
  (+param/principal), so two exchanges producing the same fingerprint (e.g. the corpus's two
  `POST /api/register` exchanges) can collapse to one row. B2-3's Result line names this gap as a
  follow-on; scoring must infer attribution from url (B2-3) or method+url (B2-3b).
- **Problem:** evaluation cannot attribute a finding to the exchange that produced it, so pairs that
  share method+url (or duplicate exchanges) can only be excluded, not scored.
- **Recommendation:** additive migration: nullable `run_id` + `exchange_id` on first-seen rows, plus
  a `finding_observations(fingerprint, run_id, exchange_id, created_at)` link table so a deduped
  re-observation still records its exchange (fingerprint and dedup semantics unchanged).
  `exchange_id` = the caller-supplied index/id when present, else a stable hash of the captured
  request. Surface both via `all_host_findings`; `build_scorecard` attributes control findings by
  exchange when present and falls back to B2-3b's (method, url) otherwise.
- **Acceptance:** caller-level test -- two exchanges with identical method+url (one vuln-labeled, one
  control), each with a finding: the scorecard attributes each to its own exchange and scores the
  control (not excluded); a deduped re-observation records a second observation row. NEGATIVE
  controls -- finding counts, fingerprints and report output are unchanged for a corpus without
  duplicates; an existing DB migrates without error. `full` suite green.
- **Impact:** Medium-High (fair per-exchange scoring; retires the exclusion heuristics).

## Principal review batch — 2026-09-24 (PR-*)

**Dispatch (2026-09-24, user-requested):** Filed from the
[principal review](reviews/2026-09-24/principal-review/REVIEW.md) (findings
R01–R16, independently re-verified for R01/R04/R05/R06/R07/R14). Full sequenced
spec, do-not-duplicate map and acceptance detail:
[docs/PRINCIPAL_REVIEW_IMPLEMENTATION_PATH.md](docs/PRINCIPAL_REVIEW_IMPLEMENTATION_PATH.md).
Loop order: **PR-1 → PR-2 → PR-3 → PR-4 → PR-5 → PR-6 → PR-7 → PR-9 →
PR-10(offline) → PR-11(offline)**. `Mode: OWNER/LIVE` items (PR-A..PR-E) are NOT
loop-consumable — leave `[ ]`, skip, and note why in the report. R03 -> P1-10,
R10 -> P0-6, R04 -> RB-1b, R07 -> P2-2/RB-7, R11/R12 -> P1-3 already exist; do not
re-file. Honour the non-negotiables above: safe defaults only, caller test +
negative control per item, never read `*ANSWER_KEY*`/blind `app.py`, `full` suite
green before close.

### [x] PR-1 — Portable, injectable audit sink; construction never blocks on unwritable audit storage
- **Result (VERIFIED):** `c26d769` — default audit path moved off `/var/log` to a per-user
  platform dir (LOCALAPPDATA/APPDATA/home on Windows; XDG/`~/.local/state` on POSIX); the
  `RotatingFileHandler` OPEN is now guarded (not just `makedirs`) via `_disable_file_logging` —
  default degrades to `enable_file=False`+warning, new `require_file=True` raises
  `AuditStorageUnavailable`. `log_file` arg + `set_default_audit_logger` still override.
  Caller-level tests + writable-path negative control added; smoke 92 OK, focused 28 OK,
  full 2558 OK / 2 skip. Opus-reviewed APPROVE (isolated 2-file diff; setter/override intact).
- **Domain:** Reliability / DX - **Effort:** S - **Depends on:** none - **Mode:** LOOP
- **Evidence (VERIFIED, R05):** `audit_logger.py` catches `os.makedirs` failure (~line 204) but
  NOT the `RotatingFileHandler` file-open (~line 227); default `log_file=/var/log/{name}/audit.log`
  becomes `C:\var\log\agentic_burp\audit.log`. Fresh `smoke` = 30 errors, `full` = 183 errors, all
  `PermissionError` opening that file (`reviews/2026-09-24/principal-review/{smoke,full}.log`).
- **Problem:** an unprivileged/sandboxed tester cannot initialise the pipeline even for offline
  fixtures; earlier green-suite claims cannot be carried forward.
- **Recommendation:** platform-appropriate per-user data dir default (keep the setter injectable);
  guard the handler open, degrade to `enable_file=False` with ONE diagnostic on `OSError`/
  `PermissionError`; add a deliberate policy hook for "required audit storage unavailable"
  (default degrade-with-warning). Do not disable audit checks or require admin.
- **Acceptance:** caller-level tests construct the logger AND a pipeline entry point with (a) an
  unwritable directory and (b) an unwritable EXISTING file — both degrade, no exception. NEGATIVE
  control: a writable path still attaches the handler and writes a record. `smoke`+`full` reach a
  green tier in a restricted (non-admin, no `C:\var`) workspace.
- **Impact:** High (unblocks the entire suite; prerequisite for trustworthy re-runs).

### [x] PR-2 — Seed exact-class label manifest (BP-0)
- **Result (VERIFIED):** `b8fd09b` — `testing/labels/manifest.py` (typed `LabelRecord`/`Manifest`,
  `load_manifest`, closed exact-class vocabulary, closed-key label-leak guard, sha256 record-hash
  integrity) + `testing/labels/pixelmart.labels.json` (22 records: 11 positive/6 negative/4 setup/
  1 inconclusive). Labels from permitted public sources only (score.py `_LABEL_CATEGORY`, bench.py
  `KEYWORDS`, corpus public label strings); TP8 left `inconclusive`; provenance per record. 15
  caller-level tests incl. malformed/label-leaking/tampered-hash negative controls. smoke 92 OK,
  testing 58 OK, full green. Opus-reviewed APPROVE (new files only; no tracked/config change).
  Coder surfaced a corpus-contamination hazard → filed as **PR-13** below.
- **Domain:** Evaluation - **Effort:** S/M - **Depends on:** none - **Mode:** LOOP
- **Evidence (VERIFIED, R06):** `testing/score.py` has only coarse OWASP-category labels; no
  per-exchange exact-class ground truth exists for most corpora.
- **Problem:** every strict metric needs per-exchange expected exact classes + tested-negatives;
  this is the load-bearing input and does not yet exist.
- **Recommendation:** hand-seed a provenance-tracked manifest (stable IDs, >=1 expected exact class,
  tested-negative classes, label scope, `positive|negative|inconclusive|setup`) from PERMITTED
  captured evidence only. Unknown/unresolved stay visible and unscored.
- **Acceptance:** loader tests prove multiple expected classes, per-class negatives, surfaced
  unresolved labels, and setup rows never scored as positive/FP. NEGATIVE control: a label-leaking
  or malformed manifest is rejected. Never read answer-key/blind `app.py`.
- **Impact:** Transformational (spine of strict scoring).

### [x] PR-3 — Strict exact-class scorer + indiscriminate baselines (BP-1a)
- **Result (VERIFIED):** `809dd9c` — `testing/strict_score.py`: `classify_exact()` fixes R06
  (longest-keyword match; `csrf`≠`ssrf`, sqli≠xss; import-time drift assert vs `EXACT_CLASSES`).
  Three metric families side by side (any-alert coverage / exact-class P·R / `evidence_supported`
  = `unavailable` sentinel + hook for PR-4). Baselines as negative controls on a balanced fixture:
  all-classes prec 0.038 & always-alert prec 0.125 FAIL the precision gate at coverage 1.0; silent
  FAILS recall. 20 caller-level tests (wrong-class≠TP, csrf≠ssrf, dedup, absent=miss, setup/
  inconclusive excluded). `score.py` unchanged. smoke 92, testing 78 (58+20), full 2558 OK/2 skip.
  Opus-reviewed APPROVE (purely additive; R06 fix + baselines independently re-verified).
- **Domain:** Evaluation / trust - **Effort:** M - **Depends on:** PR-2 - **Mode:** LOOP
- **Evidence (VERIFIED, R06):** "cross-site request forgery" -> SSRF via `request forgery` substring
  (`score.py:41`); literal `csrf` unmapped; SQLi and XSS share A03; blind corpora count any finding.
- **Problem:** wrong-class alerts count as TP; an indiscriminate detector looks high-recall.
- **Recommendation:** new versioned scorer (keep `score.py` as explicit coarse/historical), exact
  aliases separating SQLi/XSS/SSTI/cmdi/SSRF/CSRF; emit any-alert vs exact-class vs
  evidence-supported metrics; explicit dedup/matching units.
- **Acceptance:** fixtures prove wrong-class != TP, SQLi != XSS, CSRF != SSRF, dedup holds, absent
  predictions are misses. Mandatory baselines as NEGATIVE controls: always-alert and
  all-classes-on-every-exchange MUST fail the exact-class precision gate at perfect coverage; the
  silent baseline MUST fail recall.
- **Impact:** Transformational.

### [x] PR-4 — Evidence-supported grading tier (BP-1b)
- **Result (VERIFIED):** `112a884` — `testing/evidence_grade.py` grades findings via
  `evaluation_integrity.audit_findings` (single call site) into differential_reproduced / captured /
  insufficient / unsupported, fed through PR-3's `evidence_grade_hook` (zero diff to strict_score.py).
  Evidence-supported TP requires BOTH exact-class-correct AND captured/differential. `unavailable`
  (hook=None) only when proofs+cases+artifacts all empty — distinct from a computed genuine 0. 17
  caller-level tests incl. bare-confirmed/wrong-case≠TP, adequate-proof→captured-TP, class-wrong-
  but-proven≠TP, unavailable-vs-zero negative control. smoke 92, testing 95 (78+17), full 2558 OK/2
  skip. Opus-reviewed APPROVE (purely additive; single evidence reader; re-verified focused 17 OK).
- **Domain:** Evaluation / trust - **Effort:** M - **Depends on:** PR-3 - **Mode:** LOOP
- **Evidence (VERIFIED, R06):** `ablation_harness.run_variant_async` leaves `confirmed_tp/
  confirmed_fp` at default 0; `evaluation_integrity/evidence_audit.py` already grades proof claims.
- **Problem:** unavailable evidence scoring reads as a genuine zero.
- **Recommendation:** grade captured / differential-reproduced / unsupported / insufficient tiers,
  reusing `evidence_audit.py`; emit `unavailable` when instrumentation is absent (never fabricate 0).
- **Acceptance:** fixtures grade bare-`true`-no-proof as unsupported, mismatched-case proof as
  unsupported, adequate proof as supported. NEGATIVE control: a no-instrumentation run reports
  `unavailable`, distinct from a real zero.
- **Impact:** High.

### [x] PR-5 — One maintained runner + read-only historical rescoring (BP-2)
- **Result (VERIFIED):** `81558ab` — `testing/eval_adapter.py`: `build_eval_artifact()` (raw/surfaced/
  lead stages, AR-3 exchange attribution w/ ambiguous→unresolved, reused `ScoreProvenance`, strict +
  evidence-supported metrics) and `rescore_saved_run()` (recomputes from a saved artifact with no
  model/store/network). Visibility reuses `should_quarantine_as_lead`+`is_low_confidence_generic_guess`
  in report order; the report's declared lead count is diffed and a mismatch RAISES. Missing
  instrumentation → `unavailable`, never a fabricated 0. 15 caller-level tests via a controlled-model
  stub (only stubbed boundary) through the real analyze→store→report path, incl. all four negative
  controls (label leakage / dropped findings / wrong-exchange joins / scorer-report disagreement, last
  proven non-vacuous). Drivers NOT migrated (documented follow-on). smoke 92, testing 110 (95+15),
  full 2558 OK/2 skip. Opus-reviewed APPROVE (purely additive; focused 15 OK re-run; reuse verified).
- **Domain:** Evaluation / architecture - **Effort:** M/L - **Depends on:** PR-3 - **Mode:** LOOP
- **Evidence (VERIFIED, R14):** `scratchpad/bench_blindstyle.py` (the repro driver) is absent;
  saved runs cannot be reconstructed. Two drivers (`run_blind_eval.py`, `run_ablation_live.py`)
  diverge.
- **Problem:** benchmarks are not reproducible; scorer and rendered report can disagree.
- **Recommendation:** shared adapter/schema; attribute by exchange observations (AR-3); export
  finding IDs at raw/surfaced/lead stages from the real report decision; record full provenance
  (hashes, effective config+overrides, model identity, calls/tokens -> `unavailable` if missing);
  strip scoring annotations before `analyze()`; read-only rescoring with no model/target traffic.
- **Acceptance:** caller-level tests drive real driver->orchestrator->store->report with synthetic
  exchanges + controlled model output. NEGATIVE controls detect label leakage, dropped findings,
  wrong-exchange joins, scorer/report disagreement. Synthetic CLI run needs no Docker/Ollama/network.
- **Impact:** High.

### [x] PR-6 — Rescore + correct historical benchmark; config-drift manifest (BP-3)
- **Result (VERIFIED):** `605863b` — `testing/reconcile_benchmark.py` recomputes saved-run aggregates
  and flags the contradictions (wall 1330 = repeat-3 not the 1138.631 mean; tokens=0 vs ~447k =
  `unavailable`; "no starved" vs breaker `[2,0,2]`). `CONFIG_DRIFT_MANIFEST` (4 blind corpora ran
  curated/quarantine-on ≠ shipped all/quarantine-off; PixelMart no fingerprint) +
  `CORRECTED_ASSESSMENT_2026-09-24.md` (marks "recall solved"/"quarantine buys nothing"/parity
  superseded). Strict recall refused (`unavailable`) for all 5, never inferred from broad category.
  Originals preserved; BENCHMARK_REPORT.md pointer-only. 25 tests incl. synthetic corrupted-total /
  fabricated-recall negative controls; real-artifact tests skip-guarded (logs git-ignored). smoke 92,
  testing 135 (110+25), full 2558 OK/2 skip. Opus-reviewed APPROVE + added artifact skip-guards
  during review (fresh-checkout safe); config/score.py byte-unchanged; no forbidden read.
- **Domain:** Reproducibility / documentation - **Effort:** S/M - **Depends on:** PR-5 - **Mode:** LOOP
- **Evidence (VERIFIED, R14):** saved runs `fail_open_mode: curated` + `quarantine_leads: true`;
  shipped `config.yaml` `fail_open_mode: all` (l.89) + `quarantine_unverified_leads: false` (l.596)
  + `routing_mode: agents` (l.133). PixelMart table `tokens=0` vs log `model_tokens=447k`;
  footer "no run starved" vs `breaker_failures=2`.
- **Problem:** contributors could tune/market the wrong runtime profile from mismatched artifacts.
- **Recommendation:** versioned corrected assessment under `reviews/2026-09-23/benchmark/` +
  config-diff manifest; recompute only what artifacts support (mark historical); preserve originals
  with a dated correction pointer; remove/annotate "recall solved"/"quarantine buys nothing"/parity.
- **Acceptance:** a reconciliation script asserts generated totals match each input file (including
  the token and breaker contradictions above) and documents control units (exchange vs method/URL
  vs issue). NEGATIVE control: the script fails if a total is inferred from broad categories alone.
- **Impact:** High.

### [x] PR-7 — Typed stage health; a degraded run is never reported clean (R08)
- **Result (VERIFIED):** `a33a1ab` — typed `StageOutcome` (completed/failed/skipped/disabled +
  counts + affected_finding_ids) on `models.py`; `_critique` returns it (all four paths distinct;
  affected-id ref does NOT mutate finding_id so healthy runs stay side-effect-free);
  `run_full_analysis` 4-tuple, all callers updated; `orchestrator_detect` sets additive
  `stage_outcomes[]` + `degraded = circuit_open OR any-stage-failed`; findings never dropped.
  Caller-level tests over the real analyze() path for all 3 modes + mandatory negative control
  (healthy run not degraded, keeps its exact finding). 2 existing tests updated for 4-tuple arity
  (legitimate). smoke 92, harness 2563 OK/2 skip, testing 135, full green. **Salvaged** from a
  rate-limit-interrupted coder; Opus finished one stale-rename assertion + reviewed the full diff +
  ran the full suite. Opus-reviewed APPROVE (existing-test edits legitimate; no config/safety change).
- **Domain:** Reliability / observability - **Effort:** M - **Depends on:** none (coord. P0-6) - **Mode:** LOOP
- **Evidence (VERIFIED, R08):** `analysis_pipeline.py:247` returns `(0,0)` on error; PixelMart log
  shows an HTTP 500 critique failure under a "breaker-healthy" footer.
- **Problem:** no-candidates, disabled-critique and FAILED-critique produce identical counters; a
  breaker not opening is an insufficient health predicate.
- **Recommendation:** typed stage outcomes (attempted/completed/failed/skipped + affected finding
  ids); `degraded` response/report status; preserve labelled partial results.
- **Acceptance:** caller-level tests show the three failure modes produce DISTINCT inspectable
  outcomes. NEGATIVE control: a healthy full run reports no degradation and identical findings (no
  false-degraded). Report/response never reads clean when a stage failed.
- **Impact:** High.

### [x] PR-9 — Schema-aware recursive redaction across sinks (R09)
- **Result (VERIFIED):** `07d1e13` — `audit_logger._sanitize_data` now recurses into nested dicts/lists
  (top-level byte-identical); `security.py` adds `SECRET_FIELD_NAMES` + `redact_secrets_in_url`/
  `redact_secrets_in_body` (EXACT normalized name match, values-only, no query re-encode, input
  returned unchanged when nothing secret); `base_agent._user_prompt` routes url/request_body/
  response_body through them (header path untouched). 18 additive tests incl. canary absence across
  header/URL/JSON/nested + audit event, mandatory detection-preservation control (SQLi/XSS payloads
  survive verbatim beside a scrubbed secret), structure-preservation control. smoke 92, harness 2581
  OK/2 skip, testing 135, full green. Opus-reviewed APPROVE (no existing assertion changed —
  verified; header semantics intact; re-ran focused 63 OK).
- **Domain:** Security / privacy - **Effort:** L - **Depends on:** none - **Mode:** LOOP
- **Evidence (VERIFIED synthetic, R09):** header bearer is redacted, but a JSON password, a query
  token and a nested password dict survive into agent prompts / audit events
  (`security.redact_headers`, `base_agent._user_prompt`, `audit_logger._sanitize_data`).
- **Problem:** opt-in remote reasoning or persisted events can leak secrets in body/URL/nested state.
- **Recommendation:** classify sinks; recursive schema-aware redaction of nested/body/URL/query
  secrets; keep prompt logs storing hashes/lengths; explicit egress preview/policy. No claim that
  all sensitive data is auto-removable.
- **Acceptance:** synthetic canaries in header/URL/query/body/nested state are ABSENT from every
  prohibited sink across each provider/export boundary. NEGATIVE control: a task-relevant non-secret
  field is preserved. No real credentials.
- **Impact:** High.

### [~] PR-10 — Policy-bound browser adapter (offline half done; live half OWNER) (R01)
- **Result (VERIFIED, offline half):** `4913488` — pure `evaluate_browser_request` +
  `BrowserRequestDecision` (playwright-free, reuses `ScopePolicy`, fail-closed): blocks
  non-http(s) schemes, service_worker/websocket/download + unknown resource types, out-of-scope
  origins, non-GET off-origin; `attach_credentials` only when request origin == run_origin.
  `visit()` drops blanket `extra_http_headers`, installs `context.route("**/*")` that aborts
  disallowed requests + attaches creds per-decision; cancel checked at 3 points; same-origin default
  preserves the XSS validators. 30 offline tests (playwright absent) incl. off-origin block,
  cross-origin credential refusal, redirect re-eval, cancel seam, same-origin negative control.
  smoke 92, harness 2611 OK/2 skip, testing 135, full green. Opus-reviewed APPROVE.
- **OWNER/LIVE half still `[ ]`:** two-origin real-browser proof that an owned off-scope listener
  receives zero requests/credentials (needs a playwright install + browser run). Leave for owner.
- **Domain:** Security / execution - **Effort:** L - **Depends on:** transport/capability contract - **Mode:** LOOP (offline half done); OWNER/LIVE (two-origin verification)
- **Evidence (VERIFIED, R01):** `browser_driver.py:56,156` projects captured `Authorization` to
  context `extra_http_headers`; no `route`/interception; only the initial URL is scope-checked.
- **Problem:** redirects/subresources/fetches are separate network actions that bypass Python
  request-budget/method/credential policy.
- **Recommendation:** run-bound adapter intercepting EVERY request (scheme/origin/method/address +
  credentials only to approved origins; block service-worker/download/uncontrolled WS; honor cancel).
- **Acceptance (OFFLINE, loop-consumable):** unit tests over the interception-decision function —
  off-origin subresource BLOCKED, credential only on approved origin, new-origin redirect
  re-checked, cancel stops dispatch. NEGATIVE control: in-scope same-origin GET allowed with
  expected headers. OWNER/LIVE (leave `[ ]`): two-origin real-browser proof of zero off-scope traffic.
- **Impact:** High.

### [~] PR-11 — External-tool egress boundary (offline half done; live half OWNER) (R02)
- **Result (VERIFIED, offline half):** `d82aab9` — `tool_runner.EgressPolicy` (network/proxy/
  allowed_hosts → docker flags before the image) + `EgressPolicyRequired`/`ToolRunCancelled` +
  `_is_cancelled`; `docker_cmd` additive `egress` param; `run()` gains egress/enforce_egress/cancel/
  receipt — **fails closed** without a policy when enforced, aborts on cancel, records a receipt, and
  force-removes the container in `finally` on any non-clean exit. sqlmap's container branch now routes
  through `tool_runner.run` with an enforced per-run policy (host path + except handlers unchanged);
  ffuf caller unaffected. 14 tests (docker mocked): argv seam, fail-closed negative control, receipt,
  cleanup-in-finally on timeout/exception, no-cleanup on clean exit, cancel-before-launch, sqlmap
  routing integration. smoke 92, harness 2625 OK/2 skip, testing 135, full green. Implemented by Opus
  (Sonnet weekly-limited) + self-reviewed; additive to existing callers.
- **OWNER/LIVE half still `[ ]`:** real container run proving redirected/off-scope egress is blocked
  and killed on cancel (needs Docker + a proxy/network sandbox config). Leave for owner.
- **Domain:** Security / reliability - **Effort:** L - **Depends on:** transport/capability contract - **Mode:** LOOP (offline half done); OWNER/LIVE (container egress verification)
- **Evidence (VERIFIED, R02):** `sqlmap.py` launches argv after an initial check without routing
  requests through `TargetTransport`; the direct path uses `docker_cmd` not the cleanup wrapper.
- **Problem:** tool-generated redirects/probes can exceed request/credential/destination assumptions;
  a subprocess timeout is not a bound on container activity.
- **Recommendation:** per-run egress-proxy/network-sandbox seam; scoped container identity;
  cancellation/cleanup in `finally`; tool/version/digest + request receipts; route direct sqlmap
  through the cleanup wrapper. Keep structured argv.
- **Acceptance (OFFLINE):** tests assert the invocation is built WITH the proxy/sandbox params and
  that cancel triggers `finally` cleanup + a receipt. NEGATIVE control: with no proxy seam
  configured the run refuses to launch (fails closed). OWNER/LIVE (leave `[ ]`): container proof
  that off-scope egress is blocked and killed on cancel.
- **Impact:** High.

### [~] PR-13 — Corpus ground-truth contamination audit + sanitized benchmark corpora (offline half done `2d66c5e`; OWNER re-measure) (new, from PR-2)
- **Status (2026-09-24):** offline audit + sanitizer DONE — `2d66c5e` (Opus-authored; Sonnet coder weekly-limited until 2026-09-28).
  `testing/corpus_sanitize.py` (`marker_hits`/`audit_exchanges`/`audit_corpus_file` read-only detection; `sanitize_text`/`sanitize_exchanges`
  strip ONLY annotations, keep the disclosed source byte-for-byte, clean body returns the original object). 13 tests
  (`testing/test_corpus_sanitize.py`), incl. byte-identical negative control + CRLF preservation + skip-guarded real-corpus audit.
  Audit report `reviews/2026-09-24/CORPUS_CONTAMINATION_AUDIT.md`: **PixelMart TP10 = 19 markers (contaminated); DVWA/WebGoat = 0 (clean)**.
  Suite: harness 2625 OK (skip 2) / testing 148 OK / evaluation_integrity 42 OK. **OWNER/LIVE half remains `[ ]`:** re-measure detection on
  sanitized vs contaminated PixelMart with a real model to quantify the recall inflation (needs GPU/Ollama).
- **Domain:** Evaluation integrity - **Effort:** M - **Depends on:** none - **Mode:** LOOP (audit + sanitize offline); OWNER re-run to re-measure
- **Evidence (VERIFIED by the PR-2 coder, 2026-09-24):** the permitted PixelMart corpus
  `C:/tmp/pixelmart_exchanges.json` includes a TP10 path-traversal exchange whose captured
  `response_body` contains the ENTIRE source of `testing/test-target/app.py` verbatim — including
  inline `BUG:` ground-truth comments for every endpoint and a reference to `ANSWER_KEY.md`.
- **Problem:** when the harness analyses this corpus during a benchmark, the detector model reads
  TP10's response and thereby sees ground-truth bug annotations for the WHOLE app. That is direct
  train-on-the-test contamination that can inflate detection/recall on the other exchanges — a
  concrete instance of the review's R06/R15 contamination concern, distinct from the source
  disclosure a real attacker would legitimately see.
- **Recommendation:** (1) offline audit of every benchmark corpus (`C:/tmp/pixelmart_exchanges.json`,
  `reviews/2026-09-23/benchmark/{dvwa,webgoat}_exchanges.json`, and any others the runner reads) for
  embedded ground-truth annotations (`BUG:`, `ANSWER_KEY`, source comments) in response bodies;
  (2) produce SANITIZED corpus variants where a legitimately-disclosed source response has its
  ground-truth ANNOTATIONS stripped (keep the realistic disclosure, remove the answer key) and record
  the transform + a hash; (3) the runner/scorer (PR-5/PR-6) must consume the sanitized corpus and flag
  any corpus that still carries annotations. Do NOT read `*ANSWER_KEY*`/blind `app.py` directly —
  work only from the permitted corpus files, and treat the embedded annotations as data to remove.
- **Acceptance:** an audit report enumerating which corpora/exchanges carry annotations; a sanitizer
  with a caller-level test proving `BUG:`/`ANSWER_KEY` annotations are removed from a synthetic
  contaminated response while the exploit-relevant content is preserved. NEGATIVE control: a clean
  response is passed through unchanged (byte-identical). OWNER/LIVE follow-up (leave that half `[ ]`):
  re-measure detection on sanitized vs contaminated corpora to quantify the inflation.
- **Impact:** High (any benchmark run on the contaminated corpus overstates recall; blocks trustworthy
  efficacy numbers until quantified).

### [ ] PR-A — Secure local Burp<->API token pairing (R04 / RB-1b)  — **Mode: OWNER/LIVE (skip)**
- Needs JDK/Burp build. Server writes an ephemeral token to `.harness_token.lock`; `HarnessClient.java:63`
  reads only `HARNESS_BEARER_TOKEN` env (no lockfile reader / setter caller). Finish pairing/refresh,
  token-file perms, actionable 401 UI. Do not weaken API auth. Leave `[ ]` for the owner.

### [ ] PR-B — True A–G ablations (R07 / P2-2)  — **Mode: OWNER/LIVE (skip)**
- Needs real model/GPU. Real generalist (not `force_agents=['sqli']`), a no-model provider that
  RAISES on any inference, a genuinely stronger model for F, an interaction corpus for E,
  stage-level invocation assertions, predeclared noninferiority margins. Leave `[ ]`.

### [ ] PR-C — Reproducible Java build + release gate (R13)  — **Mode: OWNER/LIVE (skip)**
- Gradle wrapper/toolchain, PR Java build/tests, wheel/JAR install smoke, SBOM, checksummed release
  manifest, digest-pinned tool images. Verification needs a JDK. Leave `[ ]`.

### [ ] PR-D — Independent labeled corpus expansion (R15 / BP-5C)  — **Mode: OWNER/LIVE (skip)**
- Independent case authoring, clustered splits, frozen sampling/decision design, untouched curated
  holdout. Not automatable; mandatory before confirmatory live validation. Leave `[ ]`.

### [ ] PR-E — Evidence-workflow design-partner pilot (R16)  — **Mode: OWNER (skip)**
- Five practitioners, paired tasks, measure analyst minutes saved per accepted reproducible issue.
  Non-code. Leave `[ ]`.

## Re-review cycle-2 batch — 2026-09-24 (NC-*)

**Dispatch (2026-09-24, cycle 2):** filed from the delta re-review
[reviews/2026-09-24/principal-review-r2/REVIEW.md](reviews/2026-09-24/principal-review-r2/REVIEW.md)
(new findings N01–N05). Full spec + do-not-duplicate map:
[reviews/2026-09-24/principal-review-r2/IMPLEMENTATION_PATH.md](reviews/2026-09-24/principal-review-r2/IMPLEMENTATION_PATH.md).
Loop order **NC-1 → NC-2 → NC-3 → NC-4**; NC-O1..NC-O5 are OWNER/LIVE (skip).
Coding constraint: Sonnet coder weekly-limited until 2026-09-28 → loop items are
Opus-authored or deferred. Honour cycle-1 non-negotiables (safe defaults, caller
test + negative control, never read `*ANSWER_KEY*`/blind `app.py`, `full` green).

### [x] NC-1 — Apply the strict scorer in an offline runner (N01 / R06)
- **Result (VERIFIED):** `ed555dd` — `testing/rescore_run.py` applies `eval_adapter.rescore_saved_run`
  to a saved run (read-only) AND runs the three indiscriminate baselines through `strict_score`'s
  precision/recall gates as a built-in negative control; refuses (raises `StrictScorecardError`) when
  any baseline passes a gate it must fail. Coarse metrics only under an explicit `historical_coarse`
  label; `run_from_files`/`main` CLI (exit 0 certified / 2 refused). 8 tests incl. the "baselines fail
  the gate THROUGH the runner" control and the low-gate refusal negative control. Opus-authored (Sonnet
  weekly-limited). Suite: harness 2625 OK (skip 2) / testing 156 OK / evaluation_integrity 42 OK.
- **Domain:** Evaluation - **Effort:** M - **Depends on:** PR-3/PR-5 (done) - **Mode:** LOOP
- **Evidence (VERIFIED):** grep of `harness/` finds no importer of `strict_score`/`eval_adapter`/
  `classify_exact`; only `testing/evidence_grade.py:103` (a sibling instrument) imports it. A
  live/benchmark run still scores through coarse `testing/score.py`.
- **Problem:** the strict scorer (PR-3), evidence grade (PR-4) and adapter (PR-5) are a correct,
  tested toolkit that no run consumes — "implemented ≠ working" one level up. R06 is an available
  instrument, not an applied contract.
- **Recommendation:** an offline entry point that takes a saved run artifact and emits the strict
  scorecard via `eval_adapter.rescore_saved_run`/`strict_score.score`; coarse metrics only under an
  explicit `historical` label; `ScoreProvenance` stamped on the output. Do not rewrite PR-3/PR-5.
- **Acceptance:** caller-level test — a saved-run fixture scored end-to-end yields exact-class
  precision/recall; the always-alert / all-class / silent baselines each FAIL the strict precision
  gate THROUGH the runner (negative controls); a clean run is unchanged. `full` green.
- **Impact:** High (makes R06 load-bearing rather than a tested island).

### [x] NC-2 — Verify + gate browser-validator interception (N04 / R01,R11)
- **Result (VERIFIED):** `d505bd6` — audit correction: the browser plane is already single-source, so
  N04 does NOT materialize today. `harness/test_browser_interception_gate.py` (13 pure/offline tests)
  locks it in: (a) `default_driver()` returns the intercepting `PlaywrightDriver` or `None` (fail-closed);
  (b) a **source scan asserts NO browser context is created outside `browser_driver.py`** (the
  `.new_context`/`async_playwright`/`connect_over_cdp`/`chromium.launch` anti-bypass guard) and each of
  the 3 browser validators uses `default_driver()`; (c) PR-10's policy re-asserted under the exact
  same-host fallback the validators rely on (cross-host blocked, same-host different-port allowed but
  credentials withheld, non-GET nav blocked, ws/download/non-http blocked); (d) the `is_cancelled` seam.
  Note the `:157` "legacy visit" in the original evidence was the `BrowserDriver` **Protocol** signature,
  not a competing concrete driver. **Residual (follow-up):** the validators rely on the safe same-host
  fallback rather than threading the run's full `ScopePolicy`/cancel token into `visit()` — fold into the
  R11 capability-catalogue work. Suite: harness 2638 OK (skip 2) / testing 156 OK / evaluation_integrity 42 OK.
- **Domain:** Security / architecture - **Effort:** M/L - **Depends on:** PR-10 - **Mode:** LOOP
- **Evidence (VERIFIED):** `browser_driver.py` has two `visit` paths (`:157` legacy, `:239`
  intercepting); only the intercepting one carries PR-10's per-request `evaluate_browser_request`
  policy + `context.route`.
- **Problem:** PR-10 hardened one driver; a browser-using validator on the other path gets none of
  its guarantees (R11 duplication intact).
- **Recommendation:** confirm every browser-using validator routes through the intercepting `visit`;
  make a non-intercepted context refuse to send. Begin the typed capability catalogue with the
  browser family (no big-bang).
- **Acceptance:** test that a browser request without the interceptor installed is rejected/raises;
  enumeration test that each browser validator uses the intercepting path. NEGATIVE control: an
  in-scope request through the intercepting path still succeeds. `full` green.
- **Impact:** High.

### [x] NC-3 — Regenerable config/profile drift manifest (R14 residual)
- **Result (VERIFIED):** `b8c573d` — `testing/config_manifest.py` extracts 12 safety/profile toggles
  from `config.yaml` into a normalized manifest + sha256; committed snapshot
  `testing/config_safety_manifest.snapshot.json`; `main --check` exits 2 on drift, `--write` regenerates
  deliberately. `REQUIRED_SAFE_VALUES` asserts the safe shipped values (active_enabled/allow_mutating_replay/
  cloud_primary/cloud_reasoning/quarantine = false) **independently of the snapshot**, so a flip can't be
  laundered by regenerating it. 7 tests incl. the flip-detection negative control. Suite: harness 2638 OK
  (skip 2) / testing 163 OK / evaluation_integrity 42 OK.
- **Domain:** Reproducibility - **Effort:** S - **Depends on:** PR-6 - **Mode:** LOOP
- **Problem:** PR-6's reconciliation is a one-off artifact; drift can silently recur.
- **Recommendation:** a generator that emits the config/profile/egress manifest from `config.yaml`
  on demand + a test that the committed manifest matches regeneration (fails on drift).
- **Acceptance:** mutating a tracked default fails the drift check; unchanged config passes. `full` green.
- **Impact:** Medium.

### [x] NC-4 — Per-sink secret-canary tests (R09 residual)
- **Result (VERIFIED):** `0f0f107` — canaries across every sink (`harness/test_secret_canary_sinks.py`,
  7 tests): headers, URL secret param, body + NESTED body field, audit recursive `_sanitize_data`,
  and report export (individual + chain finding); each asserts the secret CANARY is gone and a
  non-secret-field injection payload (`q=`/`<script>`) survives verbatim. **Found + fixed a real leak:**
  `report_generator`'s attack-chains render loop emitted a chain's `evidence`/`suggested_test`
  UNREDACTED (the R03 render-boundary fix never reached the chains twin) — both now route through the
  existing `issues.redact`. Suite: harness 2645 OK (skip 2) / testing 163 OK / evaluation_integrity 42 OK.
- **Domain:** Security / privacy - **Effort:** M - **Depends on:** PR-9 - **Mode:** LOOP
- **Problem:** PR-9 redaction is wired but only prompt-path coverage is proven; export/provider/
  nested-audit sinks need canary proof.
- **Recommendation:** synthetic secret canaries in header/URL/body/nested-state asserted absent at
  every export/provider boundary. Do not re-implement redaction.
- **Acceptance:** canary test per sink; NEGATIVE control — a `q`/`search` SQLi/XSS payload survives
  verbatim (redaction is name-scoped). `full` green.
- **Impact:** High for remote-reasoning opt-in.

### [ ] NC-O1 — Prove tool egress containment (N02 / R02)  — **Mode: OWNER/LIVE (skip)**
- Seam only today: sqlmap caller passes `proxy_url=None`, `network="bridge"` → container keeps full
  egress, `allowed_hosts` inert. Stand up per-run proxy (or `--network none` + host alias); prove an
  off-scope listener receives zero packets. Needs Docker. Leave `[ ]`.

### [ ] NC-O2 — Connect-time address pinning (N03 / R03)  — **Mode: OWNER/LIVE (skip)**
- `run_context.py:64-75` states the scope "deliberately does not build" address pinning; PR-10's
  per-request browser checks inherit the same address-blind `ScopePolicy`. Build shared HTTP+browser
  address pinning, or a gated lab-mode; prove with a two-origin/DNS-rebinding test. Leave `[ ]`.

### [ ] NC-O3 — Two-origin browser credential-forwarding proof (R01 live)  — **Mode: OWNER/LIVE (skip)**
- Live proof that PR-10's adapter attaches credentials only to approved origins and forwards none to
  a second owned origin. Needs a browser engine + two owned origins. Leave `[ ]`.

### [ ] NC-O4 — Recall re-measure + independent corpus (PR-13 live / R15)  — **Mode: OWNER/LIVE (skip)**
- Quantify sanitized-vs-contaminated PixelMart recall inflation with a real model; BP-4/BP-5C
  independent labeled-case collection + holdout. Needs GPU/Ollama. Leave `[ ]`.

### [ ] NC-O5 — Java/API pairing + reproducible build gate (R04 / R13)  — **Mode: OWNER/LIVE (skip)**
- Supersedes PR-A/PR-C: secure local token pairing/refresh + Gradle wrapper/toolchain + PR Java
  build/test + checksummed release. Needs JDK/Gradle. Leave `[ ]`.

## Benchmark-driven batch — 2026-09-25 (BM-*)

Filed from the live full performance benchmark
([reviews/2026-09-25/benchmark/BENCHMARK_REPORT.md](reviews/2026-09-25/benchmark/BENCHMARK_REPORT.md);
pooled exact-class P=0.23, R=0.81 across 4 corpora on `qwen3:8b`). The evaluation is
now trustworthy (strict exact-class scorer + sanitized corpus + baseline gate); these
items act on what it measured. Honour the standing non-negotiables (safe defaults,
caller test + negative control, `full` green before close).

### [ ] BM-1 — Tame the two catch-all false-positive classes (precision)  — **SUPERSEDED by FR-4 (2026-09-25)**
- **Superseded:** FR-4 carries this forward with the measured correction — a confidence floor barely
  moves precision here (the catch-all FPs are high-confidence), and the gate's class set does not even
  match the model's dominant labels. Do this via FR-4, not the confidence-floor recommendation below.
- **Domain:** Detection precision - **Effort:** M - **Mode:** LOOP
- **Evidence (VERIFIED, 2026-09-25 run):** `security_misconfiguration` and `info_disclosure` are the
  dominant FP source on every corpus — DVWA security_misconfiguration 11 FP with ZERO support (pure
  noise); PixelMart 16 FP; Juice Shop 14 FP; info_disclosure 8–11 FP each. They drag pooled precision to
  0.23 while concrete classes (sqli/csrf/path_traversal) sit at 0.5–1.0.
- **Recommendation:** require stronger evidence for these two broad classes before surfacing (a higher
  confidence floor and/or a corroborating signal), analogous to `gate_low_confidence_generic`. Do NOT
  suppress the concrete classes. Ship any threshold OFF/safe or as a shipped default only with a
  before/after re-measure.
- **Acceptance:** offline test — a synthetic finding set with N security_misconfiguration/info_disclosure
  guesses on clean exchanges is gated out while a well-evidenced one survives; NEGATIVE control — sqli/xss/
  path_traversal findings are unchanged. Re-run `strict_benchmark` on ≥2 corpora shows precision up,
  recall not materially down. `full` green.
- **Impact:** High (directly lifts the measured pooled precision).

### [ ] BM-2 — Same-class secure-vs-vulnerable discriminator (stop firing on clean controls)
- **Domain:** Detection precision - **Effort:** L - **Mode:** LOOP (harder; may be partly research)
- **Evidence (VERIFIED):** across corpora, `fp_on_tested_negative_control ≥ 1` for sqli/xss/idor/
  command_injection/path_traversal — the model flags a SECURE endpoint of a class as vulnerable.
- **Recommendation:** add a control-aware check (e.g. compare against a benign baseline response for the
  same endpoint, or require a differential signal) so a secure exchange of a known class is not reported.
- **Acceptance:** caller test — a tested-secure exchange paired with its vulnerable twin: the secure one
  produces no confirmed finding, the vulnerable one still does. `full` green.
- **Impact:** High.

### [ ] BM-3 — Reasoning-heavy class recall (auth_bypass / business_logic / ssrf)  — **Mode: OWNER/LIVE (skip)**
- **Evidence (VERIFIED):** these three classes are missed (R=0) on BOTH PixelMart and Juice Shop — the
  classes needing multi-step inference about intent/state. Unlikely to close with an 8B local model alone.
- **Direction:** a stronger model routed to these classes, or class-specific active probes. Needs a real
  model/GPU to measure. Leave `[ ]`.

## Founder-review batch — 2026-09-25 (FR-*)

Derived from the founder decision review
([reviews/2026-09-25/founder-review/REVIEW.md](reviews/2026-09-25/founder-review/REVIEW.md)) and an
offline re-score of the 2026-09-25 captured benchmark findings. The review's verdict: a promising
local-first Burp copilot whose main weakness is the *distance between its safety/evidence vocabulary
and what its boundaries actually guarantee* — a declaration used as evidence of enforcement, sparse
metadata labelled reproducible, a failed run stamped complete, a class-level non-confirmation read as
a refutation. The FR items below are the **offline, loop-consumable** half of that finding set: each
tightens an honesty/precision contract with a caller test and a negative control, ships any new gate
OFF/safe, and leaves `config.yaml` untouched. The enforcement/live/build/adjudication half is already
filed as OWNER/LIVE and is listed as skip-only `FR-O*` at the end of this batch so the loop does not
re-file it. Recommended order: **FR-4 → FR-3 → FR-1 → FR-2 → FR-5 → FR-6 → FR-7 → FR-8**.

### [x] FR-4 — Fix the generic-guess gate + scope the catch-all gate to evidence, not self-confidence (F06; supersedes BM-1)
- **Domain:** Detection precision - **Effort:** M - **Mode:** LOOP
- **Evidence (VERIFIED, 2026-09-25 offline re-score):** two independent defects. **(a) Normalization
  gap:** `harness/confirmation_gate.is_low_confidence_generic_guess` keys on
  `DEFAULT_GENERIC_CLASSES = {misconfig, sqli, broken access control (workflow bypass)}` via
  `_generic_class_key` (`categories.canonicalize` → raw-lowercase fallback). The model's dominant FP
  label — snake_case `security_misconfiguration` (35× in the captured runs) — canonicalizes to `None`
  and falls to `"security_misconfiguration"`, which is NOT in the set; only the space-spelled
  `Security misconfiguration` matches. Every `info_disclosure` variant (`information_disclosure`,
  `verbose_error_disclosure`, `excessive_data_exposure`, `exposure_of_internal_data`, …) misses too.
  So flipping `gate_low_confidence_generic` ON today catches ~16 of 51 misconfig labels and ZERO
  info-disclosure. **(b) Confidence is the wrong lever:** the two classes are 69 of 101 pooled FPs but
  only 8 of 30 TPs; yet 86/96 misconfig and 65/76 info-disclosure findings sit at confidence ≥ 0.5
  (61 pinned at exactly 0.50 — an uncalibrated default). An offline re-score (replaying the captured
  `surfaced` findings + real `attribution.by_exchange` through `testing/strict_score`, faithful — it
  reproduces the report's first-run pool at P=0.232/R=0.784): a <0.5 floor moves precision +0.01;
  requiring a **confirming leg for ONLY the two catch-all classes** lifts pooled P 0.232→0.407 and
  F1 0.358→0.500 (R 0.784→0.649, and the demoted findings survive as quarantined leads, not deleted).
  A **global** leg requirement collapses recall to 0.05 — do not apply it outside the two classes.
- **Recommendation:** (1) make the gate's class key robust to the model's spelling variants — reuse
  the strict scorer's `classify_exact` folding (or an equivalent narrow, reviewable normalizer) and add
  `info_disclosure` to the generic set. (2) For `security_misconfiguration` + `info_disclosure` only,
  require a corroborating signal (a confirming/oracle leg, or class-specific evidence) before the
  finding is *surfaced*, rather than trusting the model's self-reported confidence. Leave the concrete
  classes (sqli/xss/idor/path_traversal/jwt/csrf) untouched. Ship OFF/safe; re-measure before any
  default flip.
- **Acceptance:** caller test — catch-all guesses (across ALL spelling variants) on clean exchanges are
  gated while a leg-backed catch-all finding survives; NEGATIVE control — sqli/xss/path_traversal
  findings are unchanged and a global leg requirement is explicitly NOT introduced (a same-class
  concrete finding without a leg still surfaces). Offline re-score on ≥2 corpora shows precision up and
  recall noninferior within a declared bound. `full` green.
- **Impact:** High (the measured pooled-precision lever; directly addresses the FP burden in F06).
- **Result (`96c17ff`, VERIFIED):** normalization fixed in `categories._SYNONYMS` (snake_case + compound
  info-disclosure/misconfig variants fold; `canonicalize("Broken Access Control")` still `None`);
  `info_disclosure` added to `DEFAULT_GENERIC_CLASSES`; new `is_uncorroborated_catchall_guess` +
  `reporting.gate_uncorroborated_catchall` (ships **false**) require a confirming leg for ONLY
  `misconfig`/`info_disclosure`, ignoring confidence; mirrored identically in `report_generator` +
  `eval_adapter`, wired into `strict_benchmark` config read, tracked in the config-drift manifest
  (snapshot regenerated, `--check` clean). Caller test + negative controls (concrete classes never
  gated; flag-off byte-for-byte no-op) added. Offline re-score (captured findings, all 12 repeats):
  pooled P 0.236→0.283, F1 0.367→0.403, recall 0.820→0.703 (demoted → leads, not deleted). `full`
  green (harness 2684 OK/2 skip, pytest-native 38, testing 168, evaluation_integrity 42). Live
  re-measure through `strict_benchmark` with the flag ON remains OWNER/LIVE.

### [x] FR-3 — Report benchmark headlines from artifacts, all-repeat pooling (F15)
- **Domain:** Evaluation honesty - **Effort:** S - **Mode:** LOOP
- **Evidence (VERIFIED):** the published headline `30 TP / 101 FP / 7 FN` is exactly the **first run**
  of each corpus; pooling all 12 scored runs gives **91 / 294 / 20** (P=0.236, R=0.820). The review's
  #1 recommendation. `over-alert ×` is findings/exchanges (workload volume), not an FP rate against
  ground truth; "3 repeats" are not 3 independent applications.
- **Recommendation:** generate the report's headline counts/ratios from the `*_strict_3x.json`
  artifacts (all repeats, denominators named, uncertainty clustered by application/case), and stop
  hand-transcribing. Rename or footnote `over-alert ×` so it is not read as a false-positive rate.
- **Acceptance:** a script recomputes the report's pooled numbers from the artifacts; a unit test
  asserts the published pooled counts equal the sum over all runs (a hand-edited/first-run-only number
  fails loudly). `full` green.
- **Impact:** High (cheap; removes a live source of manual score drift and over-claim).
- **Result (`7050d89`, VERIFIED):** new pure/offline `testing/pool_strict_runs.py` recomputes both
  denominators from the `*_strict_3x.json` artifacts — one-repeat/per-app 30/101/7 (P=0.229/R=0.811)
  and all-12-runs 91/294/20 (P=0.236/R=0.820), reproduced independently. `BENCHMARK_REPORT.md` now
  presents BOTH with named denominators + the founder-review §9 "3 repeats ≠ 3 independent apps" caveat,
  and footnotes `over-alert ×` as workload-not-FP-rate; all prior caveats kept. Tests
  (`testing/test_pool_strict_runs.py`, synthetic-only so CI needs no local artifacts): correctness sums
  hand-computed; NEGATIVE control asserts a first-run-only pool differs from `all_runs_pooled` (a silent
  revert fails loudly) + mean-vs-pooled denominators cannot be conflated. `full` green (harness 2684
  OK/2 skip, pytest-native 38, testing 177, evaluation_integrity 42).

### [x] FR-1 — Health-certify the strict benchmark runner; a failed run is never "complete" (F04)
- **Domain:** Evaluation / Reliability - **Effort:** M - **Mode:** LOOP
- **Evidence (VERIFIED source + synthetic failure):** `testing/strict_benchmark._one_run()` runs the
  orchestrator but discards per-exchange analyze failures, and `run_corpus_strict()` passes a hardcoded
  `complete=True` (strict_benchmark.py:117). An all-failing synthetic orchestrator still returns
  normally and emits a "complete" artifact from an empty/partial store. `inputs_hash` is only the label
  manifest hash — not a corpus/config/model identity.
- **Recommendation:** return typed run outcomes (expected/completed/failed exchanges + stage
  degradation); certify only eligible runs; hash corpus bytes + config + prompt versions + model digest
  + dirty diff into a real inputs identity; pass real usage; unique run IDs; fail certification on any
  missing requirement; keep partial scores as explicitly-ineligible diagnostics; restore cache globals
  and close owned orchestrators on exit.
- **Acceptance:** run-health falsifier — fail all exchanges / one exchange / critique / store writes /
  model startup: no affected run receives a healthy certification, partial metrics stay visible;
  NEGATIVE control — a genuinely healthy run still certifies. `full` green.
- **Impact:** High (a completion stamp currently can hide an inoperative detector).
- **Result (`cf0f953`, VERIFIED):** `_one_run` now returns the `ExchangeOutcome` list (+ guarded
  orchestrator cleanup); new pure `assess_run_health` marks a run ineligible on any exchange error,
  missing exchanges, zero completed, or empty store despite exchanges (partial metrics stay visible);
  `run_corpus_strict` sets `complete=health.eligible`, attaches `run_health`, returns
  `certified`/`all_runs_eligible`, and restores the leaked `harness.cache` global. New `_inputs_identity`
  hashes corpus+config+manifest+git(+dirty); `model_digest` recorded `"unavailable"`, never fabricated.
  Tests (`testing/test_strict_benchmark_health.py`, offline): pure layer + healthy negative control;
  run-health falsifier monkeypatches `_one_run` (all-fail → ineligible/`complete=False`, metrics still
  visible; healthy stub persists a real finding → `complete=True`) + asserts store/cache globals
  restored. `full` green (harness 2684 OK/2 skip, pytest-native 38, testing 185, evaluation_integrity 42).
  Live health-gated re-run remains OWNER/LIVE. (Untracked `founder-review/probes.py`, a stale F04
  reproducer, now errors on the fixed return type — left as-is; not repo/suite code.)

### [x] FR-2 — Make evidence resolvability a storage-backed invariant (F03)
- **Domain:** Trust / Reliability - **Effort:** M - **Mode:** LOOP
- **Evidence (VERIFIED):** `run_context.TargetTransport._artifact()` records `request_ref=url` and
  `response_ref="HTTP {status}"` (run_context.py:361-364); the P0-6 reproducibility check
  (`evidence_ledger.py`) sets `resolvable` from *nonempty* strings, so a status-only artifact reads as
  resolvable with `missing=[]` — a tester cannot actually reproduce a body mutation or audit an oracle
  from it.
- **Recommendation:** store content-addressed request/response blobs (method/body/headers/session refs
  + payload transformations); the resolver verifies presence AND hashes; a missing blob forces
  incomplete reproduction; a durable-logging failure marks evidence health degraded. Keep per-event
  provenance so `reconstruct()` reports every contributing stage/model, not just the first event's.
- **Acceptance:** caller test — a blob-backed artifact resolves reproducible; a status-only / mixed
  artifact does NOT; the "resolvable" negative control **removes the blob** and the record flips to not
  resolvable with a populated `missing[]`. `full` green.
- **Impact:** High (turns "resolvable" into a real, replayable claim).
- **Result (`aa0d42b`, VERIFIED):** new content-addressed blob store in `store.py`
  (`evidence_blobs`, per-run isolated; `put_evidence_blob`/`get_evidence_blob`/`evidence_blob_resolves`
  = present AND hash-verified). `run_context._artifact` stores REDACTED request/response blobs
  (`security.redact_secrets_in_url`/`redact_headers`/`redact_secrets_in_body`) only at the successful-send
  site, double-guarded so a blob failure marks `evidence_blob_degraded` and never breaks a send;
  non-executed paths store nothing. `_assess_completeness` now requires both blobs present+hash-verified;
  string-only/mixed/missing/degraded each get a specific `missing[]`. Tests (offline): blob round-trip +
  corruption, resolver positive/status-only/mixed, the NEGATIVE control (delete blob → resolvable flips),
  producer wiring (send→resolvable; patched failure→ok+degraded), and an **NC-4 secret-canary** proving a
  canary in url/header/body is absent from both stored blobs. Three P0-6 tests asserting string-only
  resolvability flipped to the honest contract (not weakened). `full` green (harness 2696 OK/2 skip,
  pytest-native 38, testing 185, evaluation_integrity 42). NOTE: generated reports now honestly render
  historical status-only findings as "NOT independently reproducible" — intended F03 behavior.

### [x] FR-5 — Bind negative evidence to the case, not the class (F09)
- **Domain:** Trust / Correctness - **Effort:** M - **Mode:** LOOP
- **Evidence (VERIFIED):** `confirmation_gate._controlled_negative_classes()` collects a controlled
  negative keyed by `canonicalize(finding_class)`, and `apply_confirmation_suppression()` matches by
  class — so one parameter's controlled negative can demote all same-class findings. The R08 work
  already splits REFUTED / UNVERIFIED / UNPROVEN; the residual is case-binding.
- **Recommendation:** bind a controlled negative to `(class, url, method, parameter, oracle-condition)`;
  only a same-case finding is eligible for REFUTED; a different parameter/case of the same class stays
  `inconclusive`, never "likely false positive". Preserve severity assessment separately from
  verification status.
- **Acceptance:** caller test — a controlled negative on parameter A refutes the parameter-A finding
  but leaves a same-class parameter-B finding `inconclusive`; NEGATIVE control — a genuine same-case
  controlled negative still refutes. `full` green.
- **Impact:** Medium-High (stops class-wide overconfident "secure" verdicts; complements BM-2).
- **Result (`c4dd349`, VERIFIED):** `ValidationReport` gained optional `url`/`method`/`parameter`
  (default ""), populated at all 5 `orchestrator_confirm.py` producer sites from the finding/exchange.
  New `_controlled_negatives` (`{class: {parameters}}`) + `_has_controlled_negative`: a finding is REFUTED
  only by a class-level (empty-parameter, backward-compat/endpoint-level) OR same-parameter negative; a
  same-class negative on a DIFFERENT parameter falls through to the existing UNVERIFIED tier. The call is
  per-exchange so url/method are invariant (key = class+parameter); caps/tiers/ledger/recall-guards
  unchanged. Tests: caller (param-A negative refutes A `[Hypothesis]`, leaves same-class param-B
  `[Unverified]`) + negative controls (same-case still refutes; parameter-less still refutes same-class).
  No existing test changed. `full` green (harness 2699 OK/2 skip, pytest-native 38, testing 185,
  evaluation_integrity 42).

### [x] FR-6 — Credential-grant verification needs a differential (F10)
- **Domain:** Graph / Correctness - **Effort:** M - **Mode:** LOOP
- **Evidence (VERIFIED):** `orchestrator_chain._credential_grants_access()` returns
  `out.ok and out.status < 400` (orchestrator_chain.py:252) with no anonymous / invalid-token control —
  a public 200 or a login redirect "grants" access, inflating chain plausibility and wasting crawl
  budget.
- **Recommendation:** compare the credentialed response against anonymous and invalid-token controls on
  the same protected resource; require an identity/access-change signal before asserting a grant; mark
  uncertain tokens as candidates with limited downstream use.
- **Acceptance:** caller test — a resource whose anonymous and credentialed responses are equivalent
  does NOT count as a grant, and an invalid-token control matching anonymous yields no grant; NEGATIVE
  control — a resource that genuinely differs for the credentialed principal still counts. `full` green.
- **Impact:** Medium (removes false capabilities from the engagement graph).
- **Result (`a2aba42`, VERIFIED):** `_credential_grants_access` now runs three scope-gated + throttled
  probes (credentialed / anonymous / invalid-token via `_invalidated_headers`) through the one throwaway
  transport; fast-exits False on a credentialed error (controls not spent); grants only when the
  credentialed response is not equivalent (status AND body, `_responses_equivalent`) to BOTH controls;
  fail-closed on control exception/incomplete. Signature + both callers unchanged. Tests (offline, 17):
  public-resource/no-diff → no grant, early-exit, fail-closed, and genuine-grant negative controls
  (status-diff and body-only-diff → grant) + helper units. Updated `test_engagement_escalation.py`'s
  shared mock to distinguish a genuine credential from anon/invalid (it previously returned one response
  regardless — the assumption FR-6 removes; public assertions unchanged). `full` green (harness 2716
  OK/2 skip, pytest-native 38, testing 185, evaluation_integrity 42).

### [x] FR-7 — Separate pure-inference caching from run-bound proof (F11)
- **Result (VERIFIED, offline; default-OFF):** `c2cb427` — added a run-INDEPENDENT hypothesis cache
  (`cache.HypothesisCacheEntry` + sibling `hypothesis_cache_entries` table +
  `get_hypothesis`/`put_hypothesis`/`hypothesis_stats`) keyed by exchange-hash (run namespace
  EXCLUDED) + coordinator model + prompt versions + `config_schema.config_fingerprint(config)`. It
  stores ONLY the pre-proof half of an analysis (the model-inference `reports` + `dispatch`/`reason`/
  `stage_outcomes`/review counts) — never an `AnalysisResponse`, never `proof_records`/`proof_id`/
  `case_id`/`oracle_*`. Wired into `Orchestrator.analyze()` behind `runs.hypothesis_cache.enabled`
  (ships **false**): on a hit it reconstitutes `reports` and FALLS THROUGH to the always-run tail
  (`_validate_findings`), so proof/case/oracle are freshly minted in the CURRENT run and never cached
  or shared; on a miss it caches the pre-proof snapshot. The stale-cross-run-proof hazard is handled
  structurally (capture is strictly BEFORE `_validate_findings`, so cached findings have empty
  proof/case/oracle by construction) AND defensively (`put_hypothesis` refuses+logs if any finding
  already carries a proof/case/oracle value). Flag-OFF is byte-for-byte identical (the original
  dispatch/inference block is unchanged except re-indented into an `else:`; the only always-on changes
  are a hoisted idempotent `activity_feed` import and an idempotent `CREATE TABLE IF NOT EXISTS`). +7
  caller-level tests (`test_cache_hypothesis_reuse.py`, stub coordinator): cross-run reuse (2nd fresh
  run does not re-invoke the model; hit-rate>0), proof rebound per run (both runs get non-empty DISTINCT
  case_id/proof_id), raw-SQLite-row inspection (payload has no proof/case/oracle keys), 3 negative
  controls (config-fingerprint / coordinator-model / prompt-version change → miss+re-dispatch), 2
  default-off byte-identical controls. **DEFERRED:** live/API hit-rate measurement and any default-ON
  (retention is owner-gated on measured hit-rate); dispatch-wiring beyond the new stats counters. New
  `runs.hypothesis_cache.enabled` flag is perf/cost-only (no egress/scope/mutation/verification-state
  effect), so correctly not added to SafeDefaultGuard's SAFE_CHECKS; guard stays green.
  `test_pipeline_gate.py` untouched. Full suite green (harness 2812 OK / 2 skip, pytest 38, evaluation
  221, evaluation-integrity 42; 2 consecutive green full runs — one earlier full run had a single
  unattributed transient failure that did not reproduce and is unrelated to this default-OFF change).
- **Domain:** Performance - **Effort:** M - **Mode:** LOOP (partly research)
- **Evidence (VERIFIED control flow):** `orchestrator_detect.py` creates a fresh run before the cache
  lookup and `RunContext.create()` embeds a new run UUID in the cache namespace, so two independent
  `/analyze` calls on identical traffic re-pay all model cost; naively widening cache scope would reuse
  stale proof references. `CacheEntry.is_stale()` keys on coordinator model + prompt version, not the
  full behavioral config.
- **Recommendation:** add a content/config/model/prompt-addressed *hypothesis* cache that is reusable
  across runs, while observations are rebound to each run and active proof is revalidated per run.
  Instrument and measure hit-rate at the API boundary before optimizing.
- **Acceptance:** caller test — identical traffic across two fresh runs reuses hypotheses (measured
  hit-rate > 0) while proof/evidence is re-bound per run and never shared; NEGATIVE control — a
  config/model/prompt change invalidates the hypothesis cache. `full` green.
- **Impact:** Medium (latency/cost on repeated captures; strictly gated on measured hit-rate).

### [x] FR-8 — Authenticate sensitive reads on the local API (F12, offline half)
- **Domain:** Security / Privacy - **Effort:** M - **Mode:** LOOP
- **Evidence (VERIFIED):** `server._require_auth()` bypasses the token check for loopback "safe" routes,
  so another local process/user reaching the API can read findings/evidence without the mutation token;
  the token requirement today guards only mutations.
- **Recommendation:** require the operator token for routes that expose findings/evidence/reports while
  keeping an unauthenticated health/liveness route for pairing; ship the read-auth requirement in a way
  that does not break the extension's health handshake. (Per-user file ACLs, at-rest encryption and
  retention/deletion are the OWNER half — see FR-O* / F12; do NOT attempt them here.)
- **Acceptance:** caller test — a sensitive read without a valid token is rejected while the health
  route still answers; NEGATIVE control — a valid-token read succeeds and mutation-path behavior is
  unchanged. `full` green.
- **Impact:** Medium-High (client traffic + discovered secrets are the product's most sensitive assets).
- **Result (`cdb238d`, VERIFIED):** new `server.require_read_auth` flag (**ships false**) + `_require_read_auth`
  (separate from the untouched `_require_auth`; no-op when off, requires the effective `_mutation_token()`
  when on) wired into `/report`, `/telemetry`, `/test-plans/{id}`, GET `/settings`; `/health` stays open.
  Tracked in the config-drift manifest (snapshot regenerated; `--check` clean). Tests (offline, TestClient):
  enabled → token-less sensitive read 401, valid-token 200, `/health` 200; NEGATIVE control disabled
  (default) → reads 200; mutation gating unaffected by the flag. Ships OFF so the default deploy is
  byte-identical and the extension's reads aren't broken until the Java side sends the token on GETs
  (OWNER half of F12). `full` green (harness 2724 OK/2 skip, pytest-native 38, testing 185,
  evaluation_integrity 42).

### Skip-only cross-references (already filed OWNER/LIVE — do NOT re-file)
- **FR-O1 (F01)** browser execution-policy enforcement + two-origin credential-forwarding proof →
  `PR-10` (offline half done) / `NC-O3`. **Mode: OWNER/LIVE (skip).**
- **FR-O2 (F02)** enforced tool egress via an attested proxy worker (not `--network bridge`) →
  `PR-11` (offline half done) / `NC-O1`. **Mode: OWNER/LIVE (skip).**
- **FR-O3 (F08)** per-engagement origin/address policy + TLS-verify-on + validated re-resolution →
  `NC-O2` / `P1-10` live half. **Mode: OWNER/LIVE (skip).**
- **FR-O4 (F05/F14)** secure Java↔API pairing + reproducible Java build/release gate →
  `PR-A` / `PR-C` / `NC-O5`. **Mode: OWNER/LIVE (skip).**
- **FR-O5 (F07)** faithful A–G ablations (rename variants to their real mechanism; instrument model
  calls; assert treatment) → `PR-B` (harness = `RB-7`). **Mode: OWNER/LIVE (skip).**
- **FR-O6 (F06)** independent, exhaustively-adjudicated precision + analyst-time study on held-out
  cases → `PR-D` / `NC-O4` / `PR-E`. **Mode: OWNER/LIVE (skip).** FR-4 is the offline precision lever;
  this is the live measurement of net operator value.

---

## Re-analysis batch — 2026-09-26 (RA-*)

Filed by an Opus re-analysis pass after the prior offline pool was exhausted (P1-3
offline-complete, P3-1 `[x]`). Each item is grounded in a `file:line` observation
verified against the checkout at this session's HEAD. Dispatch order: RA-1 → RA-2 →
RA-3 → RA-4 (all offline/loop-consumable). Standing non-negotiables apply.

### [x] RA-1 — Make `reproduction_recipe` surface the resolvable evidence blobs
- **Result (VERIFIED offline):** `9d3e579` — each EXECUTION step now carries `method`, the
  request/response blob hashes (only when they storage-resolve, via a per-step `_blob_resolves`
  mirroring `_resolved_blob_hash`), a `replayable` flag, and a "reference-only, not replayable"
  note otherwise; a top-level `resolvable` reuses `_resolved_blob_hash` over the same executions
  list so the recipe's resolvability is guaranteed to agree with `completeness.resolvable`. Legacy
  `request`/`expected` keys preserved (additive; `reproduction_recipe_persisted` fixed transitively).
  +5 caller-level tests (positive agreement, status-only negative, corrupted-blob negative, persisted
  variant, back-compat). Full suite green (harness 2743 OK/2 skip, exit 0).
- **Domain:** Evidence / Trust · **Effort:** S-M · **Depends on:** none (P0-1/P0-6/FR-2 `[x]`) · **Mode:** LOOP (offline)
- **Evidence (VERIFIED):** `reproduction_recipe` builds each step as
  `{"request": e.data.get("request",""), "expected": e.data.get("expected","")}`
  ([evidence_ledger.py:326-329](harness/evidence_ledger.py)). But the EXECUTION producer sets
  `data = {"request": artifact.request_ref, "response": artifact.response_ref, ...}` and the REAL
  replayable, hash-verified evidence in `data["request_blob"]`/`data["response_blob"]`
  ([run_context.py:385-423](harness/run_context.py)); `data["expected"]` is NEVER set in production.
  `_assess_completeness` sets `completeness.resolvable=True` only when those blobs resolve
  ([evidence_ledger.py:195](harness/evidence_ledger.py)). So `GET /findings/{ref}/evidence`
  ([server.py:1508](harness/server.py)) can return `resolvable=True` beside a recipe whose steps carry
  only a redacted-URL ref and an empty `expected`, referencing none of the blobs — producer/consumer
  out of contract.
- **Problem:** The one artifact a triager uses to replay a finding omits the replayable request/response
  the harness actually stored, while the sibling field asserts reproducibility — undercutting the
  "evidence-grade, reproducible confirmation" claim.
- **Recommendation:** In `reproduction_recipe`/`reproduction_recipe_persisted`, emit steps from the
  EXECUTION events' `request_blob`/`response_blob` (+ method/status), and mark a step
  "reference-only, not replayable" when no resolvable blob exists (mirroring `_assess_completeness`).
  Read-only; no new store schema.
- **Acceptance criteria:** Caller test — one EXECUTION with stored blobs → recipe step references the
  resolving blob hashes (+ method) and agrees with `completeness.resolvable`. **Negative control:** a
  status-only EXECUTION (no blob) → recipe honestly shows a non-replayable step and `resolvable=False`
  (proving the recipe no longer over-claims). `full` green.
- **Impact:** High (evidence-trust core).

### [x] RA-2 — Extend FR-8 read-auth to the finding/evidence/identity/session reads it missed
- **Result (VERIFIED offline):** `e4008b1` — added `_require_read_auth` (after `_require_auth`) to the
  7 sensitive GET reads FR-8 missed (`/findings/{finding_ref}/evidence`, `/engagement/{host}`,
  `/engagement/{host}/investigate/{job_id}`, `/identities`, `/hosts/{host}/sessions`,
  `/findings/suppressions`, `/issues/{host}/merges`); `/health` stays open. Behind the existing
  `server.require_read_auth` flag (ships false) → default deploy byte-identical; no new config key /
  no drift-manifest change. Docstring updated to list every covered route. +7 tests (flag ON+no token
  → 401; flag ON+valid token → not 401; flag OFF default → not 401 negative control). Full suite green
  (harness 2751 OK/2 skip, `config_manifest --check` clean, exit 0).
- **Domain:** Security / Privacy · **Effort:** S · **Depends on:** FR-8 `[x]` · **Mode:** LOOP (offline)
- **Evidence (VERIFIED):** `_require_read_auth` is wired into only `/telemetry`, `/report`,
  `/test-plans/{id}`, GET `/settings`. These sensitive reads still call only `_require_auth` (which
  returns immediately on the default loopback+no-token deploy): `GET /findings/{finding_ref}/evidence`
  ([server.py:1508](harness/server.py) — reconstructed request/response + reproduction recipe, the most
  sensitive read), `/engagement/{host}` (:1045), `/identities` (:1451), `/hosts/{host}/sessions` (:1471),
  `/findings/suppressions` (:1502), `/issues/{host}/merges` (:1561), and the investigate-job read.
  Founder-review F12 is thus only half-closed.
- **Problem:** With `require_read_auth` on, an operator reasonably believes findings/evidence reads are
  token-gated; they are not for the endpoints that actually expose discovered vulns, reconstructed
  traffic, identities and session refs.
- **Recommendation:** Add `_require_read_auth(authorization)` to those GET handlers; keep `/health`
  open. Ships behind the existing `server.require_read_auth` flag (already OFF by default) → default
  deploy byte-identical. No new toggle, so no drift-manifest change.
- **Acceptance criteria:** TestClient with `require_read_auth` on: token-less GET of each endpoint → 401;
  valid token → 200; `/health` → 200. **Negative control:** flag off (default) → all reads 200 and
  mutation gating unchanged. `full` green.
- **Impact:** Medium-High (privacy/safety; completes FR-8's stated intent).

### [x] RA-3 — Offline SARIF export endpoint (surface the built-but-unused adapter)
- **Result (VERIFIED offline):** `fbf43d1` — new read-only `GET /report/sarif` renders a host's stored
  findings as SARIF 2.1.0 (`all_host_findings` → `group_findings_into_issues` → `export_issue` →
  `export_issues_to_sarif`, stamped with the Provenance `code_version`), giving the tested-but-uncalled
  `sarif_adapter.py` a production caller. Separate route (so `/report` markdown is untouched); gated by
  `_require_auth` + `_require_read_auth` (reachable by default like `/report`; token-gated when
  `require_read_auth` armed). +5 tests (positive validates `[]`, empty-host zero-result not 500, read-auth
  on→401/off→reachable, `/report` unchanged). Full suite green (harness 2756 OK/2 skip, exit 0). This is
  the offline slice of P2-3; the Burp-tab surfacing stays under P1-5.
- **Domain:** UX / Portability · **Effort:** S-M · **Depends on:** P0-1 `[x]` · cross-refs P2-3 · **Mode:** LOOP (offline)
- **Evidence (VERIFIED):** `harness/sarif_adapter.py` (`export_issues_to_sarif`/`import_sarif_to_findings`,
  fully tested in `test_sarif_adapter.py`) has ZERO production callers (grep of `harness/*.py` excluding
  tests/its own module); there is no `/export` or `sarif` route in `server.py`. P2-3 bundles SARIF with
  the Burp tab and gates the whole item on P1-5 (OWNER/LIVE), so the offline-shippable half never lands.
- **Problem:** Findings are not portable into SARIF-consuming triage/CI pipelines despite the tested code
  existing; unreachable tested code is a maintenance liability.
- **Recommendation:** Add a read-only `GET /report?format=sarif` (or `GET /export/sarif`) that runs the
  host's stored issues through `export_issues_to_sarif`, gated by `_require_read_auth` (per RA-2). Record
  as the offline slice of P2-3; leave the Burp-tab surfacing under P1-5.
- **Acceptance criteria:** TestClient — seed a finding, GET the SARIF endpoint → `validate_sarif_shape()`
  returns `[]` and the issue round-trips. **Negative control:** empty host → a schema-valid SARIF doc with
  zero results (not a 500). `full` green.
- **Impact:** Medium (portability; removes dead code).

### [x] RA-4 — Batch report-time ledger/blob reads (avoid O(N·E) fresh connections)
- **Result (VERIFIED offline):** `1321626` — added `store.ledger_events_for_many` (one grouped query,
  same order/shape as `ledger_events_for`), an optional shared `conn=` on `get_evidence_blob`/
  `evidence_blob_resolves` (default = prior behavior), an optional `resolver=` threaded through
  `evidence_ledger.reconstruct`/`_assess_completeness`/`_resolved_blob_hash`, a shared `_ledger_from_rows`,
  and `reconstruct_persisted_many(refs)` (one batched fetch + per-hash memo over ONE shared connection).
  `generate_markdown_report` builds the reconstruction map once up front; `_render_finding` looks it up and
  falls back to the single-ref call when absent → rendered output byte-identical (`reconstruct_persisted`
  single-ref untouched). +6 tests: batched == single-ref field-for-field, `ledger_events_for_many` slices ==
  `ledger_events_for`, and a counting shim proving connections are CONSTANT in K (K=3 == K=6) while the old
  per-finding path opens strictly more. Full suite green (harness 2762 OK/2 skip, exit 0).
- **Domain:** Efficiency · **Effort:** M · **Depends on:** none · **Mode:** LOOP (offline)
- **Evidence (VERIFIED):** `report_generator.py:618` calls `evidence_ledger.reconstruct_persisted(...)`
  per finding; each → `ledger_from_store` → `store.ledger_events_for` opens a fresh `_connect()`
  ([store.py:1530](harness/store.py)), then `_assess_completeness` → `evidence_blob_resolves` opens
  ANOTHER fresh connection per blob via `get_evidence_blob` ([store.py:1582,1598](harness/store.py)). A
  report over N findings × E execution events does ~N×(1+2E) serial connect+query cycles at render time;
  no batch reader exists.
- **Problem:** `GET /report` on a host with hundreds of findings pays hundreds–thousands of serial
  connection setups; scales poorly and is invisible to callers.
- **Recommendation:** Add a batched `store.ledger_events_for_many(refs)` (one grouped query) and reuse a
  single connection / memoize `evidence_blob_resolves` within one report render. No change to rendered text.
- **Acceptance criteria:** Test — render a report over K findings and assert the ledger/blob query (or
  `_connect`) count is bounded (O(1)–O(few), not O(N·E)) via a counting shim. **Negative control:** the
  rendered report bytes are byte-identical before/after (pure perf refactor). `full` green.
- **Impact:** Medium (latency cliff on large engagements).

### [x] RA-5 — Honor the `reporting.*` surfacing gates on the live `/report` route
- **Result (VERIFIED offline):** `8e80524` — filed by re-analysis pass #2. `generate_markdown_report`
  already consumed `gate_uncorroborated_catchall`/`gate_low_confidence_generic`/`generic_confidence_floor`/
  `quarantine_leads`, but `generate_report_for_host` (what `GET /report` calls) never forwarded them and no
  production code read `reporting.gate_*` — so an operator's `config.local.yaml` knob silently did nothing on
  the live report (founder-review vocabulary-vs-enforcement theme). `generate_report_for_host` now takes an
  optional `config` and forwards the four gates; `GET /report` passes the server's effective config. Gates
  ship OFF and only re-bucket to "leads" (never drop), so default `/report` is byte-identical and opt-in never
  loses recall. +3 tests (gate ON demotes a catch-all `security_misconfiguration` to leads while a concrete
  sqli is never demoted; default byte-identical across no/empty/default config; gate ON changes the report).
  Full suite green (harness 2765 OK/2 skip, exit 0).
- **Domain:** Trust / UX · **Effort:** S · **Depends on:** none (FR-4/RA-3 `[x]`) · **Mode:** LOOP (offline)
- **Impact:** Medium (a documented precision knob now reaches the live analyst-facing report).

### [x] RA-6 — Apply the `reporting.*` gates to `/report/sarif` for consistency
- **Result (VERIFIED offline):** SUBSUMED by R07 (`41bec3c`). `/report/sarif` now routes through
  `export_issues_for_host(url, config=config)`, which omits gate-demoted findings (OFF by default,
  byte-identical); a concrete/confirmed finding is never omitted. Covered by R07's tests.
- **Domain:** Trust / UX · **Effort:** S · **Depends on:** RA-5 `[x]`, RA-3 `[x]` · **Mode:** LOOP (offline)
- **Evidence (VERIFIED):** RA-5 wired the surfacing gates into `GET /report` (markdown) but `GET /report/sarif`
  ([server.py](harness/server.py)) still runs `all_host_findings → group_findings_into_issues →
  export_issues_to_sarif` with no gating, so with a gate armed the two routes disagree on what is surfaced.
- **Problem:** Minor inconsistency: an operator who opts into catch-all gating sees it on the markdown report
  but not the SARIF export.
- **Recommendation:** Filter the findings through the same demote-to-leads predicates
  (`is_uncorroborated_catchall_guess` / `is_low_confidence_generic_guess` / `should_quarantine_as_lead`)
  before `group_findings_into_issues`, gated by the same OFF-by-default flags. Requires a small SARIF-semantics
  decision (omit demoted findings from results, vs. tag them at a lower `level`) — pick omit-to-match the
  markdown "leads are not reported vulnerabilities" framing, documented.
- **Acceptance criteria:** caller test — gate ON → the catch-all finding is absent from `runs[0].results`
  while a concrete finding remains; negative control — gate OFF (default) → SARIF byte-identical to today
  (finding present). `full` green.
- **Impact:** Low-Medium (consistency; small surface).

### [x] R06 — Complete opt-in read-auth over knowledge/activity/investigate-list reads
- **Result (VERIFIED offline):** `12b4340` — from the 2026-09-26 founder-refresh (R06). `/knowledge`,
  `/activity`, and `/engagement/{host}/investigate` (job list) called only `_require_auth` (loopback-bypassed
  by default); each now also calls `_require_read_auth`, completing FR-8/RA-2 coverage. Behind the existing
  `server.require_read_auth` flag (ships false) → default deploy byte-identical; no new config key. +2 tests
  (flag ON → 401 / valid token → 200 for all three; flag OFF default → not 401 negative control). Full suite
  green (harness 2767 OK/2 skip, exit 0).
- **Domain:** Security / Privacy · **Effort:** S · **Depends on:** RA-2 `[x]` · **Mode:** LOOP (offline)
- **Source:** [founder-refresh REVIEW.md](reviews/2026-09-26/founder-refresh/REVIEW.md) R06.

### [x] R07 — Route `/report/sarif` through the canonical enriched + gated export
- **Result (VERIFIED offline):** `41bec3c` — from the 2026-09-26 founder-refresh (R07). RA-3's SARIF endpoint
  built issues via the raw `group_findings_into_issues`+`export_issue` chain, dropping persisted proof-attempt
  history and operator merge overrides (which `report_generator.export_issues_for_host` — used by `/report` and
  the MCP issues resource — applies) and ignoring the reporting.* gates. `report_sarif` now builds from
  `export_issues_for_host(url, config=config)`: SARIF reflects proofs+merges identically to the canonical
  export, and (subsuming RA-6) omits gate-demoted findings when the operator opts in — OFF by default →
  byte-identical; concrete/confirmed findings never omitted (recall guard). +2 tests (merge + 2-attempt proof
  history match the canonical export; gate ON omits catch-all / gate OFF byte-identical). Full suite green
  (harness 2769 OK/2 skip, exit 0).
- **Domain:** Evidence / Export / UX · **Effort:** S-M · **Depends on:** RA-3 `[x]`, RA-5 `[x]` · **Mode:** LOOP (offline)
- **Source:** [founder-refresh REVIEW.md](reviews/2026-09-26/founder-refresh/REVIEW.md) R07.

### [x] R01 — Stop reproduction_recipe/completeness overstating reproducibility
- **Result (VERIFIED offline):** `455cfe3` — from the 2026-09-26 founder-refresh (R01). New
  `_resolvable_execution()` requires a SINGLE execution's OWN request+response blob pair to both
  storage-resolve; `_assess_completeness.resolvable` and the RA-1 recipe top-level `resolvable` now use it
  (still agreeing) instead of pooling request/response blobs independently across executions (which falsely
  called a request-only A + response-only B "resolvable"). The producer (`run_context._artifact`) now sets
  `data["method"]` so the recipe method survives round-trip (was None). Resolvable completeness/recipe/steps
  declare `rehydration_required` (redacted blobs need session/credential/input rehydration for authenticated
  replay). +4 tests (split-pair fails on both; single-pair passes+agrees; missing-response not resolvable;
  method round-trip via the REAL producer). No existing test weakened. Full suite green (harness 2773 OK/2 skip,
  exit 0). Honesty-tightening only — no verdict/confirm logic changed.
- **Domain:** Evidence / Trust · **Effort:** M · **Depends on:** RA-1 `[x]`, FR-2 `[x]` · **Mode:** LOOP (offline)
- **Source:** [founder-refresh REVIEW.md](reviews/2026-09-26/founder-refresh/REVIEW.md) R01.

## Swarm-comparison batch — 2026-09-27 (SC-*)

Source: [reviews/2026-09-27/swarm-comparison/REVIEW.md](reviews/2026-09-27/swarm-comparison/REVIEW.md)
+ [VERIFICATION.md](reviews/2026-09-27/swarm-comparison/VERIFICATION.md). A source-inspected
comparison against `Armur-Ai/Pentest-Swarm-AI` (upstream HEAD `661c2182`) reviewed at local HEAD
`678dcce`. Two groups: **SC-1..SC-9** are local verification/shipping defects (the review's A1–A9),
each re-verified against current source this session; **SC-10..SC-15** are the six borrowable
patterns ("technology worth adapting"), each an enhancement whose *retention* is gated on a
matched-budget measurement. The upstream repo is **AGPL-3.0**: reimplement patterns, never copy
code, and document provenance.

Delivery order (the review's own): (1) SC-1..SC-3 + proof/control identity → (2) SC-4, SC-6, SC-5
report parity → (3) SC-7..SC-9 execution policy + budgets → (4) SC-10 tool contract + one adapter
→ (5) SC-11 workflow packs + SC-12 durable queue → (6) SC-13..SC-15 release UX, provider routing,
report polish.

### [x] SC-1 — A failed/inconclusive negative control must not produce VERIFIED (A1)
- **Result (VERIFIED):** `0fea458a` — `Oracle.run_negative_control` now routes control
  cleanliness through the shared `_clean_negative` helper (clean requires the probe
  EXECUTED to `not_confirmed`; a `skipped`/`error`/`blocked`/cancelled control is
  inconclusive, never clean), and `Oracle.run`'s `available and not clean` branch splits
  into control-CONFIRMED (keeps the "negative control ALSO confirmed" reason) vs
  control-INCONCLUSIVE (new reason, `verified` stays False either way). "Ran and stayed
  clean" and "never ran" no longer collapse into one boolean. +7 tests: 3 at `Oracle.run`
  (skipped/error/blocked → not-clean/not-verified/INCONCLUSIVE) and 4 caller-level through
  the real `_validate_findings`→`_oracle_gate`→`OracleRegistry` wiring (executed-clean
  `not_confirmed` → verified [positive control]; skipped/error/blocked → `oracle_verified`
  False + state `candidate`); the two existing framework controls
  (`test_verified_requires_clean_negative_control`,
  `test_not_verified_when_negative_control_also_confirms`) stay green unchanged, and the
  new tests fail against the old code. Reuses `_clean_negative` (no second definition); no
  signature/verdict/severity/scope/replay/`confirmation_gate` change. `config.yaml`
  unchanged (`oracle.enabled` ships false); `test_pipeline_gate.py` preserved. Full suite
  2780 OK / 2 skip, pytest 38, evaluation 221, evaluation-integrity 42, exit 0.
- **Domain:** Verification / Trust · **Effort:** M · **Depends on:** none · **Mode:** LOOP (offline)
- **Evidence (VERIFIED, re-read this session):** `OracleValidator.run_negative_control`
  ([harness/oracle_framework.py:180](harness/oracle_framework.py)) returns
  `(available, not _is_confirmed(res), res)` — so a control that is `skipped` / `blocked` / `error`
  is counted `clean=True`. After N-of-N successful reproductions, `ConfirmMixin._oracle_gate`
  ([harness/orchestrator_confirm.py:58](harness/orchestrator_confirm.py)) stamps the case
  `verified`. The review reproduced this end-to-end through the real `_oracle_gate` + registry with a
  stub validator (`probe_agenticvibe.py`); a confirmed control correctly leaves it `candidate`, but a
  non-executed control verifies.
- **Problem:** "Ran and stayed clean" and "never actually ran" are collapsed into one boolean, so an
  inconclusive control can manufacture a VERIFIED verdict — the single most trust-critical defect.
- **Recommendation:** Introduce a distinct `executed_clean` outcome requiring transport success AND a
  real class-specific control observation. `error` / cancellation / missing resource / skipped /
  unavailable control stay **inconclusive** (never clean). Preserve why reproduction succeeded and why
  the control did or did not execute. Redesign the `negative_controls.py` builders around an immutable
  test case + explicit attack/control requests (change only the vulnerable variable; preserve auth,
  unrelated params, workflow state). Audit each `SELF_CONTROLLING` exception individually.
- **Acceptance criteria:** Caller-level regressions at BOTH `_oracle_gate` and `_validate_findings`: an
  executed-and-clean control verifies; a `skipped`/`blocked`/`error`/unavailable control leaves the case
  `candidate`/inconclusive (negative control per terminal status). Preserve `test_pipeline_gate.py`
  defect-injection controls.
- **Impact:** Transformational (this is the evidence boundary A2/A3 and every later item sit on).
- **Source:** REVIEW.md A1.

### [x] SC-2 — Credential "grant" needs an authorization discriminator, not a noise differential (A2)
- **Result (VERIFIED):** `2764a60` — `_credential_grants_access`'s grant decision no longer
  keys on a byte-exact differential (which any per-request nonce/CSRF/timestamp/ad/rate-limit/
  login-page noise trivially satisfied → false grant → wasted role-recrawl). New module-level
  `_responses_materially_same(a, b)` (sibling to `_responses_equivalent`, identical None/errored
  normalization) requires `same status AND identity_compare.similarity(bodies) >= MATCH_THRESHOLD
  (0.70)`; the grant line now uses it in the suppression position, so a credential is granted only
  when its response is materially distinguishable from BOTH the anonymous and invalid-token
  controls. Strict tightening: byte-equal bodies score 1.0, so every FR-6 grant-rejection is
  preserved (superset proof) and only previously-granted noisy-public cases now correctly reject;
  the more-conservative direction (never a false grant). Reuses `identity_compare` (no second
  similarity metric/normalizer); fast-path, fail-closed control branches, scope/no-headers guard,
  `_responses_equivalent`, `_invalidated_headers` untouched. +4 tests: 2 differential
  (noisy-nonce triple → no grant [similarity 0.9077, empirically flips old byte-exact grant→True];
  distinct privileged body vs denied controls → grant) and 2 caller-level around the real
  `_auto_escalate`→`_credential_grants_access` path (noisy-public bogus credential → no crawl/no
  escalation; genuine credential → protected owner-bound object → 1 crawl). FR-6 tests green
  unchanged (incl. `test_genuine_grant_same_status_different_body_still_counts`, bodies score
  0.0263 < 0.70). No `config.yaml` change (strict tightening ships on unconditionally, no new
  gate); `test_pipeline_gate.py` preserved. Full suite 2784 OK / 2 skip, pytest 38, evaluation 221,
  evaluation-integrity 42, exit 0.
- **Domain:** Verification / Trust · **Effort:** M · **Depends on:** SC-1 (nice) · **Mode:** LOOP (offline)
- **Evidence (VERIFIED, re-read this session):** `_credential_grants_access`
  ([harness/orchestrator_chain.py:276](harness/orchestrator_chain.py)) already carries the **FR-6**
  differential (credentialed vs anonymous vs invalid-token, fail-closed on control failure). The review
  reproduced that a credential is still "granted" when the three public responses merely *differ*
  (nonce/timestamp/CSRF/ads/login-redirect noise) — a differential exists but proves nothing. Static
  public responses correctly reject; dynamic public responses falsely accept. `_auto_escalate` consumes
  the result to accept learned credentials.
- **Problem:** FR-6 established "the response changed"; A2 is the remaining gap — a *changed* public
  response is not authorized access, so noisy public endpoints still escalate on a bogus credential.
- **Recommendation:** Require an **authorization discriminator**: authenticated identity, access to a
  known protected owner-bound object, or a stable privileged capability denied to both controls.
  Normalize noisy bodies (nonces, timestamps, CSRF, ads, rate-limit pages, login redirects) to supporting
  evidence only — never as the grant signal. Persist the three requests + principal bindings. Reuse
  `identity_compare.py` / `cross_identity_validator.py` rather than raw body diffing.
- **Acceptance criteria:** Owned-loopback caller tests around `_auto_escalate`: a bogus credential against
  a noisy public endpoint does NOT grant/escalate; a real credential reaching a protected owner-bound
  object does (positive control). Extends, does not weaken, FR-6's tests.
- **Impact:** High. **Follow-on to FR-6 `[x]` (scoped to the remaining gap).**
- **Source:** REVIEW.md A2.

### [x] SC-3 — Control identity: retire the empty-parameter wildcard; bind controls to the case (A3)
- **Result (VERIFIED):** `debb3e7` — `_has_controlled_negative` no longer treats an empty
  parameter key as a wildcard (`if "" in params: return True` deleted). A controlled negative now
  matches a finding iff `neg_param == parameter_name` (exact) AND the principals are not a
  resolved-vs-resolved mismatch. `_controlled_negatives` stores `(parameter, principal)` tuples;
  a new `ValidationReport.principal_id` (default "") is populated at the not_confirmed record site
  from `finding.principal_id` (Finding already carried it — no cross-module plumbing). Effect:
  an empty-parameter negative refutes ONLY an empty-parameter (genuinely endpoint-level) finding —
  preserved — and no longer demotes a specific-parameter finding it never tested (falls through to
  UNVERIFIED); a negative from a different *resolved* principal no longer suppresses. Principal
  binding is fail-safe: an empty principal on either side never removes a refutation that fired
  before (so no real refutation is lost), and the precision-floor cap runs BEFORE the
  REFUTED/UNVERIFIED branch split, so a demoted finding still ships capped — only the honesty label
  changes. run_id/method/location/workflow binding deferred (not on Finding; run-scoping already
  enforced per-run/per-exchange). +3 net tests: `test_negative_control_2` rewritten (it previously
  *pinned the defect* — empty-neg refuting a specific-param finding; now asserts the preserved
  empty-neg→empty-finding case) plus a hazard-closed test (empty-neg does NOT refute a specific-param
  finding → UNVERIFIED) and a cross-principal pair (admin-neg does NOT refute a user-finding →
  UNVERIFIED; same-principal user-neg DOES refute → positive control). FR-5 preservation tests
  (`test_negative_on_parameter_A_does_not_refute_parameter_B`, `test_negative_control_1...`) byte-for-byte
  unchanged; `_controlled_negative_classes` untouched; `test_pipeline_gate.py` defect-injection controls
  unaffected (same-case matching). No `config.yaml` change (strict correctness tightening, no gate).
  Full suite exit 0 (harness unittest + pytest 38 + evaluation 221 + evaluation-integrity 42 all green;
  targeted `test_confirmation_gate` 28 OK).
- **Domain:** Verification / Trust · **Effort:** M · **Depends on:** none · **Mode:** LOOP (offline)
- **Evidence (VERIFIED, re-read this session):** `_has_controlled_negative`
  ([harness/confirmation_gate.py:610](harness/confirmation_gate.py)) — **FR-5** already stops a negative
  recorded under a *different named* parameter from refuting a finding, but the current code still has
  `if "" in params: return True`, so a negative with an **empty/unknown parameter key** refutes any
  finding of that class. `_controlled_negatives` keys only on `(class, parameter)` — it does not bind run
  / principal / session / method / parameter-location / workflow state, so a control from a different run
  or principal can suppress.
- **Problem:** An unresolved-identity control is treated as universal refutation, and cross-run /
  cross-principal controls can suppress a legitimate finding — evidence-correctness defect.
- **Recommendation:** Match controls on `(run, request template, principal/session, method, parameter
  location+name, class, workflow state)`. Distinguish a *genuinely non-parameter-scoped* check (e.g. a
  missing-header class — may legitimately refute at class level) from an *unknown/unresolved* parameter
  (→ unresolved evidence, the existing UNVERIFIED tier, never refutation).
- **Acceptance criteria:** Production suppression test with two parameters (one vulnerable, one clean)
  proving only the matching-parameter control refutes; a control from a different run/principal does NOT
  suppress; a genuinely class-scoped check still refutes at class level (kept behaviour).
- **Impact:** High. **Follow-on to FR-5 `[x]` (empty-key wildcard + match-tuple binding remain).**
- **Source:** REVIEW.md A3.

### [x] SC-4 — Unknown workflow assertions must fail closed (load-time + runtime) (A4)
- **Result (VERIFIED):** `895dda3` — RUNTIME: `_assertions_hold` now returns
  `(False, "unknown assertion kind: X")` as the first check in its loop for any kind outside the
  closed `_ASSERTION_KINDS = {status, body_contains, json_pointer}` set, so an unrecognized/misspelled
  assertion maps to `StepStatus.FAILED` (executed-but-unverifiable, distinct from BLOCKED) via the
  existing `execute_workflow` mapping — it can no longer fall through to `(True,"")`/PASSED. LOAD-TIME:
  a new `_load_assertion` helper (called by `workflow_from_dict`, the loader `engagement_builder.
  execute_declared_workflows` uses) raises `ValueError` for an unknown kind, a status/body_contains
  missing `expected`, or a json_pointer missing `expression` — the error propagates (not swallowed), so
  a malformed workflow is rejected before execution. Uses `expected is None` (not falsy), so a
  legitimate `expected: 0/""/false` and an expression-only json_pointer are still accepted (no
  over-tightening; no in-repo declaration is newly rejected). `Assertion.kind` stays a plain str (no
  Enum churn). +6 tests: load-time unknown-kind rejected by the real loader AND end-to-end via
  `execute_declared_workflows`; status-missing-expected and json_pointer-missing-expression rejected;
  runtime unknown-kind → FAILED + "unknown assertion kind" in reason + explicitly NOT PASSED (the exact
  misspelled_status/403-vs-200 repro, fails against old code); well-formed workflow still PASSES
  (negative control). The trailing crash/restart-tests clause (extractor state / cleanup registration /
  principal switches) is DEFERRED — separable reliability extra, remains open. No `config.yaml` change
  (unconditional correctness); `test_pipeline_gate.py` untouched. Full suite exit 0 (harness unittest +
  pytest 38 + evaluation 221 + evaluation-integrity 42; targeted `test_workflow_engine` 28 OK).
- **Domain:** Verification / Reliability · **Effort:** S · **Depends on:** none · **Mode:** LOOP (offline)
- **Evidence (VERIFIED, re-read this session):** `_assertions_hold`
  ([harness/workflow_engine.py:198](harness/workflow_engine.py)) handles `status` / `body_contains` /
  `json_pointer` and returns `(True, "")` for any unrecognized `kind`. A workflow with
  `Assertion(kind="misspelled_status", expected=403)` "passes" against a `200`. Reproduced through the
  real `execute_workflow`.
- **Problem:** A typo'd or unsupported assertion silently satisfies a business-invariant check, so a
  workflow can report success it never verified.
- **Recommendation:** Closed enum / discriminated schema for assertion kinds; validate operands at
  workflow load (the same loader API/engagement callers use); fail closed at runtime for any unknown
  assertion. Keep "request executed" vs "assertion satisfied" vs "invariant violated" distinct.
- **Acceptance criteria:** A malformed workflow is rejected by the loader used by the API/engagement
  callers; at runtime an unknown assertion yields inconclusive/failed, never pass; a well-formed workflow
  still executes (negative control). Extend crash/restart tests to extractor state, cleanup registration
  and principal switches.
- **Impact:** Medium-High.
- **Source:** REVIEW.md A4.

### [x] SC-5 — One required ReportPolicy across every exporter/adapter (MCP parity) (A9)
- **Result (VERIFIED):** `6a581d5` — `ReadOnlyMcpAdapter` gained a kw-only `config: dict | None =
  None` (stored as `self._config`) and its `issues` export call now passes `config=self._config`
  to `report_generator.export_issues_for_host`, so the MCP path honors the same `reporting.*`
  surfacing gates that RA-5/RA-6/R07 added to `/report` + `/report/sarif` (the adapter previously
  called it with no config → gates bypassed). Chose to thread the effective config (the same
  `server.config`/`load_config()` object the HTTP routes use) rather than introduce a new
  `ReportPolicy` type — avoids rippling across the Markdown/JSON/SARIF/issue exporters. The `issues`
  branch was the ONLY config-omitting export call (coverage/provenance branches don't route through
  `export_issues_for_host`). Presentation-only: the gate is a pure list-filter (`_demoted_by_reporting_
  gates`, which refuses confirmed/oracle-verified findings) — no store write, no verification-state
  change. Default `config=None` = gates OFF = byte-for-byte unchanged. +2 tests: parity
  (`read_resource(...)["data"] == export_issues_for_host(host, config=<gate cfg>)` with the demotable
  catch-all omitted on BOTH + `total` reduced + the concrete confirmed `sqli` present on both as a
  recall guard; fails against old code) and default-no-config-still-surfaces (proves the gate, not the
  wiring, does the omitting); the existing gates-OFF parity test stays green unchanged (negative
  control). Scope boundary: the adapter is constructed only in tests (no live MCP server route), so
  the constructor seam + direct config injection is the bounded fix; a future live route must pass
  `server.config` (documented inline). No `config.yaml` change (gates already ship OFF);
  `report_generator.py`/`server.py`/`test_pipeline_gate.py` untouched. Full suite exit 0 (evaluation
  221 + evaluation-integrity 42 OK; targeted `test_mcp_adapter`+`test_report_gates_wired`+
  `test_sarif_endpoint` 26 OK).
- **Domain:** Reporting / Trust · **Effort:** S-M · **Depends on:** none · **Mode:** LOOP (offline)
- **Evidence (VERIFIED, re-read this session):** `ReadOnlyMcpAdapter.read_resource`
  ([harness/mcp_adapter.py:130](harness/mcp_adapter.py)) calls
  `report_generator.export_issues_for_host(host)` with **no `config`**, so the `reporting.*` surfacing
  gates that **RA-6 / R07 / RA-5** added to `export_issues_for_host(url, config=...)`
  ([harness/report_generator.py:773](harness/report_generator.py)) are bypassed on the MCP path — the
  adapter cannot reproduce a configured report policy.
- **Problem:** The same confirmed/candidate/quarantined/merged fixtures render differently depending on
  the export path; a finding the operator's config would demote is surfaced in full through MCP.
- **Recommendation:** Inject one immutable `ReportPolicy` (or thread the effective `config`) into every
  exporter/adapter — Markdown, JSON, SARIF, issue export, MCP. Presentation must never change technical
  verification state.
- **Acceptance criteria:** Cross-format parity test: all export paths (incl. MCP `read_resource`) agree on
  reportable issues for the same fixture set under a given `reporting.*` config; default (gates OFF) is
  byte-for-byte unchanged.
- **Impact:** Medium. **Follow-on to RA-5/RA-6/R07 `[x]` (the MCP adapter path they missed).**
- **Source:** REVIEW.md A9.

### [ ] SC-6 — The built wheel must import outside the checkout (package resources + entry points) (A5)
- **Loop deferral note (2026-09-27):** SKIPPED by the offline loop and left `[ ]` for the owner —
  the acceptance is offline-infeasible here. (1) Its verification explicitly requires a FRESH-VENV
  install from an unrelated directory (import `harness.server` + `/health` + stub-analyze + persist +
  restart, "a wheel-building job alone does not satisfy this"), which needs `pip install` of
  fastapi/uvicorn/httpx/pydantic/pyyaml (+ transitive deps) — off-host PyPI egress or an unassumable
  local wheelhouse, outside offline loop scope. (2) The config/writable-state paths are all
  checkout-relative via `Path(__file__).parent` (`server.py` CONFIG_PATH/TOKEN_LOCKFILE, `store._DB_PATH`,
  `cache.py`, `pattern_memory.py`, `mcp_adapter`/`run_manifest` run-output), and ~a dozen tests rely on
  or override those exact paths (`test_pipeline_gate.py` reasons about `harness/harness_state.db`), so
  the importlib.resources + writable-state-separation refactor is not behavior-preserving-in-checkout
  in one bounded iteration. Owner task (needs a real environment + package build/install).
- **Evidence (SUPPORTED — review built + reproduced; not rebuilt this session):** `pip wheel . --no-deps`
  succeeds but the wheel omits `harness/config.yaml`; importing `harness.server` from an extracted wheel
  outside the repo raises `FileNotFoundError`. The wheel bundles 392 Python files incl. 193 test modules;
  `pyproject.toml` discovers packages without declaring the config resource (VERIFICATION.md wheel-import
  row; artifact SHA `01d02982…`).
- **Problem:** The distributable artifact cannot boot outside a repo checkout, and it ships the test tree —
  a shipping blocker for wheel/JAR distribution.
- **Recommendation:** Package safe-default config as a resource read via `importlib.resources`; resolve
  writable config/state separately from the installed package dir; exclude test modules/fixtures from the
  runtime distribution; provide `agenticvibe init` / `doctor` / `serve` entry points. (Do not flip any
  committed safe default — the packaged default is the same safe config.)
- **Acceptance criteria:** A fresh-venv install from an unrelated working directory can `import
  harness.server`, hit `/health`, analyze a captured-exchange fixture with a stub model, persist state and
  restart — all without a checkout. A wheel-*building* job alone does not satisfy this.
- **Impact:** High (blocks distribution). Overlaps the product-UX half of SC-14 / P1-5.
- **Source:** REVIEW.md A5.

### [x] SC-7 — Route every browser request through the RunContext capability/budget policy (A7)
- **Result (VERIFIED, offline half):** `77a0838` — `evaluate_browser_request` gained opt-in kw-only
  `gate`/`budget` params, applied AFTER the existing scheme/resource_type/scope/method checks and
  immediately before the allow-return, in `TargetTransport.execute`'s scope→gate→budget order: a
  same-origin non-GET (mutating) subrequest is routed through `SafetyGate.authorize(validator_name=
  "browser", ...)` (GET skips the gate — ScopePolicy stays the scope authority), then `budget.reserve(1)`
  is the LAST step for an otherwise-allowed request, so a request blocked by any prior check NEVER
  reserves budget. Threaded (default None) through `PlaywrightDriver.visit`/`_handle_route`. Opt-in and
  behavior-preserving: when `gate`/`budget` are both None (every shipped caller — validators pass
  neither) the function is byte-for-byte identical, so runtime behavior is unchanged this iteration; the
  seam can only BLOCK/ACCOUNT more, never allow more. +6 caller-level tests (new
  `test_browser_budget_gate.py`, real ScopePolicy/SafetyGate/SafetyGateConfig/RequestBudget): mutation
  gated-by-default (allow False, budget unspent — flips old same-origin-POST-allowed behavior); mutation
  allowed+accounted when active; out-of-scope redirect blocked before reserve (budget unspent, negative
  control); in-scope GET allowed+accounted; budget exhaustion (2nd GET blocked); gate=None/budget=None
  behavior-preserving guard. The 13 `test_browser_interception_gate` tests stay green unchanged. **LIVE
  half DEFERRED (OWNER):** wiring a real RunContext gate/budget into the live `visit` call sites +
  browser health/doctor + WebSocket/service-worker constraints — needs a working Playwright browser,
  out of offline scope. No `config.yaml` change; no new capability ON by default; single-context-site
  invariant preserved; `test_pipeline_gate.py` untouched. Full suite exit 0 (evaluation 221 +
  evaluation-integrity 42 OK; targeted 19 OK).
- **Domain:** Security / Safety · **Effort:** M · **Depends on:** none · **Mode:** LOOP (offline policy adapter; live browser health = OWNER)
- **Evidence (SUPPORTED — review source-verified; not re-read this session):** `browser_driver.py` checks
  origin/scope for routed requests but does not pass every browser request through the RunContext
  mutation/request-budget rules; same-origin non-GET traffic needs a policy decision too.
  `playwright_available` only imports the package (does not prove a working browser).
- **Problem:** Browser-originated traffic can mutate or spend outside the single execution policy that
  governs the transport — an enforcement gap under one immutable policy.
- **Recommendation:** A browser policy adapter that accounts for every request against the same
  budget/mutation rules; block service workers where they bypass interception; constrain WebSocket /
  navigation; reject unexpected mutations. Doctor should launch/attach to the configured browser and run an
  owned health op.
- **Acceptance criteria:** A page fixture attempting a same-origin mutation is gated/accounted; an
  out-of-scope redirect is blocked; a benign in-scope GET still succeeds (negative control).
- **Impact:** Medium-High.
- **Source:** REVIEW.md A7.

### [x] SC-8 — LLM budgets need atomic reservations and a run-start deadline (A8)
- **Result (VERIFIED, offline primitive):** `0522472` — `EffortBudget` gained an ADDITIVE
  lock-serialized reservation primitive: `reserve(est) -> (bool, reason)` checks committed `spent`
  PLUS in-flight `_reserved` against `total_tokens` and `_deadline_passed()` under a `threading.Lock`
  (so N concurrent reservers can't jointly overshoot the cap — the atomic check+increment is
  serialized), reusing `allow()`'s exact HARD/SOFT/`_overspend_confirmed` branches + reason strings;
  `commit(kind, model, pt, ct, reserved=)` releases the estimate and records ACTUAL usage (calls
  `self.ledger.record` DIRECTLY — not `self.record` — to avoid re-locking the non-reentrant lock);
  `release(reserved)` refunds a failed/aborted call. The wall-clock deadline is now armed in
  `__post_init__` (construction) instead of on the first `record()`, so an idle/slow-first-call run
  can expire from time alone. Harder-not-looser; no gate loosened. Behavior-preserving for sequential
  callers: `allow()` is untouched, `record()` only takes the lock (same ledger append), and a
  `reserve→commit` pair leaves `spent` identical to a bare `record()` of the actuals (proven by a twin-
  budget test). +5 tests (new `EffortBudgetReservationTests` + `EffortBudgetDurationTests`): deterministic
  barrier-based concurrency (10 threads reserve(1) vs total_tokens=3 → exactly 3 succeed, `_reserved==3`;
  re-run 5× non-flaky), reserve-blocked-past-construction-deadline, reserve/commit == bare-record-of-actuals,
  reserve/release-leaves-no-trace, and a REPLACED deadline test (`test_deadline_set_at_construction_not_
  first_spend`) — the old one pinned the pre-SC-8 "idle budget never expires" contract that SC-8 inverts
  (contract inversion, harder, not a weakening). **DEFERRED (not this iteration):** wiring the primitive
  into the concurrent dispatch seam (agent_manager/retry/critique/coordinator/specialist), streaming/failed-
  call accounting beyond release, and money/pricing — the primitive is additive and wired by nobody yet
  (the shipped `EffortBudget` at orchestrator.py sets no `max_duration_s`, so runtime behavior is
  unchanged this iteration). Note: the `RequestBudget.reserve` used by the SC-7 browser seam is a
  SEPARATE class, unaffected. No `config.yaml` change; `test_pipeline_gate.py` untouched. Full suite
  exit 0 (evaluation 221 + evaluation-integrity 42 OK; targeted 47 OK).
- **Domain:** Safety / Cost · **Effort:** M · **Depends on:** none · **Mode:** LOOP (offline)
- **Evidence (SUPPORTED — review source-verified; not re-read this session):** `EffortBudget.allow` checks
  already-recorded usage with no in-flight reservation, so concurrent calls can all pass before any result
  records; the duration deadline is initialized by the first `record`
  ([harness/effort.py:184](harness/effort.py)) — after that first call finishes.
- **Problem:** A hard budget is not actually hard under concurrency, and a run with a slow/blocking first
  call has no deadline until it returns.
- **Recommendation:** Create the deadline at run creation. Reserve an upper-bound token/cost allowance
  atomically before dispatch, reconcile actual usage afterward, refund unused reservations. Route retry /
  critique / planning / coordinator / specialist calls through the same meter; account for streaming and
  failed calls. Keep token budgets for local models; expose money only where a reliable price schedule
  applies.
- **Acceptance criteria:** A test with concurrent dispatch against a small budget cannot exceed it; a first
  call that exceeds the deadline is stopped; every model path is charged to one run.
- **Impact:** Medium-High. Related to (not duplicated by) FR-7.
- **Source:** REVIEW.md A8.

### [ ] SC-9 — Per-tool bounded execution broker (reinforces PR-11 / NC-O1) (A6)
- **Domain:** Security / Safety · **Effort:** M · **Depends on:** PR-11 · **Mode:** LOOP (offline broker/args); container-confinement proof = OWNER/LIVE (see NC-O1)
- **Evidence (SUPPORTED — review source-verified; not re-read this session):** `tool_runner.EgressPolicy`
  defaults to Docker's bridge network and places `allowed_hosts` in `NO_PROXY` (not a firewall allowlist);
  requiring a policy object does not confine the tool; `run` checks cancellation before execution but a
  blocking subprocess can continue to timeout.
- **Problem:** Egress metadata is not network confinement, and cancellation does not necessarily kill a
  running process/container — the same boundary PR-11/NC-O1 already track, plus a lifecycle gap.
- **Recommendation:** Give each tool a bounded execution broker: explicit image digest, timeout, output
  cap, process/container identity, network policy, and cancellation cleanup that actually terminates the
  owned process/container. Enforce destinations in the real network path (the live-confinement proof stays
  under NC-O1). **This is the broker/lifecycle slice of PR-11 — extend PR-11, do not open a parallel item.**
- **Acceptance criteria (offline slice):** cancellation removes the owned process/container; malformed
  output is inconclusive; unsupported capability is rejected before launch. (Allowed/forbidden endpoint,
  redirect escape, socket/proxy bypass = the OWNER/LIVE NC-O1 proof.)
- **Impact:** Medium-High. **Folds into PR-11 `[~]` / NC-O1 (OWNER).**
- **Source:** REVIEW.md A6.

### [ ] SC-10 — Governed ToolAdapter contract + one high-value adapter (borrow #1)
- **Domain:** Extensibility / Discovery · **Effort:** L · **Depends on:** SC-1..SC-3, SC-9 · **Mode:** build LOOP; retention OWNER/LIVE (measured)
- **Evidence (INFERRED — design proposal):** upstream `internal/tools` is a uniform adapter/registry
  (Name/Run/IsAvailable, standardized result, allowlist derived from names) genuinely used in production;
  AgenticVibe has agent plugins + validators but no governed *tool* contract beneath them.
- **Recommendation:** Add a `ToolAdapter` contract BENEATH validators/worklists (do not conflate an LLM
  agent with a scanner). Each adapter declares version, image digest, input schema, passive/active
  capabilities, request+mutation costs, auth support, scope behaviour, output schema, redaction, readiness;
  output keeps bounded raw artifacts + normalized observations + provenance. First adapter addresses a
  *measured* web gap (e.g. Nuclei with an allowed capability set); keep sqlmap container-only; do not add
  AD/cloud tooling just to match their catalog.
- **Acceptance criteria:** production worklist dispatch invokes a pinned adapter; unsupported capability
  rejected before launch; forbidden destination unreachable; malformed output inconclusive; cancellation
  removes the owned process/container; replayed output cannot confirm a different case. **Retention gated:**
  demonstrable extra *verified* coverage under equal budgets with no new false positives / scope violations.
- **Impact:** High (only if the ablation shows a benefit).
- **Source:** REVIEW.md "Technology worth adapting" #1.

### [ ] SC-11 — Versioned workflow/chain data packs with strict schema + fixtures (borrow #2)
- **Domain:** Business logic / Maintainability · **Effort:** M-L · **Depends on:** SC-4 · **Mode:** LOOP (offline)
- **Evidence (INFERRED — design proposal):** upstream `internal/plugins` (playbooks) + `internal/chains`
  (curated CVE/KEV chains: fingerprint → safe non-weaponized verify → remediation) are clean *data*
  organization; AgenticVibe already has a richer executable workflow engine (prereq graph, typed
  extractors, principals, assertions, cleanup, variants).
- **Recommendation:** Package AgenticVibe's own workflow definitions as versioned data with a strict schema
  — schema version, supported engine range, vuln taxonomy, required capabilities, impact constraints, proof
  contract, negative fixture, cleanup contract. Borrow their *packaging*, not their model-generated
  commands. A fingerprint mismatch must stop execution **programmatically** (an enforced state transition),
  not merely instruct the model (upstream's gap — see B7/chains, where "safe verify" is prose guidance).
- **Acceptance criteria:** deterministic compile/validate command; unknown fields/assertions rejected
  (SC-4); cyclic prerequisites rejected; a vulnerable and a patched fixture reach *opposite* final evidence
  states through the real engagement caller.
- **Impact:** Medium-High.
- **Source:** REVIEW.md "Technology worth adapting" #2.

### [ ] SC-12 — Durable WorkItem queue behind the existing graph (borrow #3)
- **Domain:** Architecture / Orchestration · **Effort:** L · **Depends on:** SC-1 · **Mode:** LOOP (offline; SQLite)
- **Evidence (INFERRED — design proposal):** upstream's event board is lossy (B1: 100 findings → 32
  delivered; cursor commits after errors). The borrowable idea is typed work-dispatch, NOT their board.
- **Recommendation:** Introduce durable `WorkItem` records in the current SQLite DB: case, dependencies,
  required capability, principal, priority, attempt, lease, budget reservation, result reference. Detection
  creates candidates → planning proposes bounded work → execution produces observations → independent
  verification changes evidence state → reporting reads state. Keep the API and Burp UI as adapters. One
  process + SQLite transactions first; PostgreSQL only on measured multi-user contention (no Redis/Go
  service for "swarm" terminology).
- **Acceptance criteria:** crash + replay produce no duplicate external mutations and no lost work; two
  concurrent engagements cannot share credentials/policy/budget/conclusions; a failed task is retryable
  without changing its proof identity.
- **Impact:** High (enables resumable/team work later — P3-3 seed).
- **Source:** REVIEW.md "Technology worth adapting" #3.

### [ ] SC-13 — Provider composition + unified cost/latency trace through llm_provider (borrow #4)
- **Domain:** LLM routing / Observability · **Effort:** M · **Depends on:** SC-8 · **Mode:** build LOOP; routing measurement OWNER/LIVE
- **Evidence (INFERRED — design proposal):** upstream has a real provider interface + per-role routing + a
  metering wrapper (useful composition), but its meter/token caps are not a real reservation system (do not
  copy its cost arithmetic as a hard limit). AgenticVibe's `llm_provider.py` already supports
  local/OpenAI/Anthropic coordinator + critique.
- **Recommendation:** Extend the existing `Provider` protocol (no parallel abstraction). Put
  provider/model/prompt-version, input/output usage, retries, latency and case/run identity in one shared
  trace consumed by the run ledger. Optional role routing (cheap classify vs deeper reasoning) only where
  evaluation justifies it. Remote use stays explicit + redacted; captured credentials/confidential payloads
  need a data policy before dispatch.
- **Acceptance criteria:** every model path appears in the run ledger; concurrent reservations cannot exceed
  the SC-8 hard budget; failures/streaming accounted; role routing measured on fixed cases at the same total
  budget (retain only if it wins).
- **Impact:** Medium.
- **Source:** REVIEW.md "Technology worth adapting" #4.

### [ ] SC-14 — Install / doctor / serve + aligned release (borrow #5)
- **Domain:** Product / DX · **Effort:** M · **Depends on:** SC-6 · **Mode:** offline build LOOP; Burp load + fresh-machine matrix OWNER/LIVE (see P1-5)
- **Evidence (INFERRED — design proposal + SUPPORTED build facts):** upstream's install/doctor/progress/
  lab-launch UX is genuinely useful; their Java build passed here under JDK 17 (explicit UTF-8 clean). Not
  every check is substantive (a constant disk-check / TCP port check ≠ readiness); their npm downloader
  lacks checksum/failure handling.
- **Recommendation:** Ship an aligned wheel + JAR + machine-readable manifest with resource versions,
  checksums, build provenance; pinned Gradle wrapper + explicit UTF-8 compile. `doctor` distinguishes
  executable-found vs dependency-installed vs service-reachable vs auth-accepted vs model-loaded vs
  browser-usable vs tool-allowed-for-this-engagement. Preserve Burp as the primary authenticated-context
  source; add a coherent install/start/diagnose flow around it. Overlaps SC-6 (packaging) and P1-5 (Burp UX
  walkthrough).
- **Acceptance criteria:** a clean Windows + Linux machine can install, init, serve `/health`, run an
  offline captured-exchange fixture, restart and export a report without a repo checkout; the JAR builds in
  PR CI and is separately tested in a supported Burp version (the live half is OWNER/LIVE).
- **Impact:** Medium-High.
- **Source:** REVIEW.md "Technology worth adapting" #5.

### [ ] SC-15 — Evidence-first report polish + retest classification (borrow #6)
- **Domain:** Reporting / UX · **Effort:** M · **Depends on:** SC-5 · **Mode:** LOOP (offline)
- **Evidence (INFERRED — design proposal):** upstream's shareable single-file HTML layout + remediation/
  reproduction sections are worth adapting; AgenticVibe already has canonical issues, proof linkage,
  reversible merges, candidate/verified tiers, leads.
- **Recommendation:** Adapt the presentation (shareable layout, remediation/reproduction narrative) through
  the SAME canonical report policy (SC-5) — never promote LLM prose to evidence. Show exact observed impact,
  authorized scope, limitations, failed/inconclusive controls, replay instructions, redacted evidence.
  Retests reference the original case and classify fixed / still-vulnerable / inconclusive / not-run.
  Consider `.http`-style evidence export (Burp Repeater import) and a self-contained offline HTML, both
  gated by the report policy.
- **Acceptance criteria:** all formats agree on reportable issues (SC-5 parity); unproved prose never
  changes verification state; secret-canary fixtures stay redacted; stable issue IDs survive export and a
  patched-fixture retest.
- **Impact:** Medium.
- **Source:** REVIEW.md "Technology worth adapting" #6.

## Re-analysis batch 2 — 2026-09-27 (RA-7, RA-8)

**Dispatch (offline; reopens loop work after the SC batch + FR-7 exhausted the pool):** A fresh
Opus re-analysis pass over the confirmation/verification, transport/policy, engagement, and
store/report/api clusters (after SC-1..SC-8, FR-7, RA-1..RA-6, RB-*, FR-* all closed) surfaced two
new evidence-based offline-loop-consumable items, each grounded in a `file:line` observation verified
against the current checkout. Select in this order: **RA-7 → RA-8**. RA-7 is the higher-value
correctness/recall/honesty fix on an always-on gate; RA-8 is a small completion of SC-4's fail-closed
invariant at the operand level. Honour the non-negotiables: safe `config.yaml` defaults (both are strict
tightenings, no new flag), a caller-level test + negative control per item, `full` green before close.
The pass found NO other offline item above the bar; the remaining backlog is owner/live/too-large.

### [x] RA-7 — Cross-identity REJECT downgrade must fire only on a genuine control-held reject, not on inconclusive observations
- **Result (VERIFIED):** `981c5ff` — added a trailing `control_outcome: str = ""` to `ValidationResult`
  and set `"control_held"` on EXACTLY the two genuine "every configured identity + the anonymous
  baseline were denied" rejects (`cross_identity_validator` BFLA and BOLA `rejects == considered`
  branches); the two `not_confirmed` OBSERVATION branches (BFLA reached-but-unproven conf 0.4, BOLA
  ownership-authorized conf 0.3) are left unset. The deterministic reject-downgrade in
  `_validate_findings` now requires `getattr(result, "control_outcome", "") == "control_held"` in
  addition to the prior conditions, so an inconclusive observation (e.g. a non-admin that actually
  REACHED an admin function) is no longer capped to 0.15 / demoted to LEAD / stamped the false "access
  correctly restricted (every identity denied)" note — it falls through unmodified. This is the SC-1
  anti-pattern (an inconclusive control must not produce a verdict) fixed on the reject side; strict
  tightening toward honest evidence + recall, never loosening a genuine reject. Grep confirmed only 4
  `not_confirmed` return sites (+ skip/error, unmatched by the guard), so no legitimate downgrade is
  silently dropped. +2 negative-control tests (BFLA reached-unproven / BOLA ownership-authorized → NOT
  downgraded, note absent; both fail against the old bare-status guard) driving the real
  `_validate_findings`; the existing positive test's stub now sets `control_outcome="control_held"`
  (faithful — it models the genuine reject) and still asserts low/0.15/"downgraded". No `config.yaml`
  change (no new flag); `ValidationResult` field is trailing/defaulted (no consumer breaks — no
  asdict/astuple/equality use); `test_pipeline_gate.py` untouched. Full suite exit 0 (harness 2814 OK /
  2 skip, pytest 38, evaluation 221, evaluation-integrity 42; targeted 29 OK).
- **Domain:** Confirmation-correctness / recall+honesty · **Effort:** M · **Depends on:** none · **Mode:** LOOP (offline)
- **Evidence (VERIFIED, re-read this session):** the deterministic cross-identity reject-downgrade block
  ([harness/orchestrator_confirm.py:622-638](harness/orchestrator_confirm.py)) fires on ANY
  `result.validator == "cross_identity" and result.status == "not_confirmed" and not finding.confirmed and
  finding.confidence > _CROSS_IDENTITY_REJECT_CAP` (`_CROSS_IDENTITY_REJECT_CAP = 0.15`,
  [orchestrator_helpers.py:60](harness/orchestrator_helpers.py) — fires on essentially every real
  finding), stamping severity=low, confidence=0.15, `review_verdict="downgraded"` (∈ `_LEAD_VERDICTS`,
  [confirmation_gate.py:296-317](harness/confirmation_gate.py) → LEAD) and a note "access correctly
  restricted (every configured other identity and the anonymous baseline were denied)". But
  `cross_identity_validator` returns `not_confirmed` for THREE different outcomes: a GENUINE reject
  (rejects==considered, conf 0.8, [cross_identity_validator.py:461-467] and BFLA :350-356) where the
  downgrade is correct; an ownership-AUTHORIZED observation (:452-460, conf 0.3 — a principal REACHED
  it); and a BFLA reached-but-UNPROVEN observation (`_confirm_bfla` :340-349, conf 0.4 — a non-admin
  REACHED an admin function, "a lead, not proof"). `ValidationResult` ([validators/base.py:9-19]) carries
  only `status`, so the block cannot tell a control-held reject from an observation. Only the genuine
  reject is tested ([harness/test_cross_identity_reject.py]).
- **Problem:** An inconclusive/authorized cross-identity OBSERVATION is treated as a refutation — most
  sharply a "non-admin reached an admin function (privileged data unproven)" lead is capped to 0.15 and
  buried as a LEAD while being stamped "access correctly restricted (every identity denied)", which is
  both false and a recall loss. This is the SC-1 anti-pattern (a non-executed/inconclusive control must
  not produce a verdict) inverted onto the reject side.
- **Recommendation:** Add one structured discriminator to `ValidationResult` (e.g.
  `control_outcome: str = ""`, trailing/defaulted — safe for existing construction). Set it to
  `"control_held"` ONLY on the two genuine control-held rejects (BOLA rejects==considered :461-467, BFLA
  rejects==considered :350-356); leave it unset on the ownership-authorized (:452-460) and BFLA
  reached-unproven (:340-349) observations. Gate the `_validate_findings` reject-downgrade (:622-638) on
  `result.control_outcome == "control_held"` instead of bare `status == "not_confirmed"`. Observation
  not_confirmeds then fall through untouched (no false "restricted" note, no LEAD burial of a real reach).
- **Acceptance criteria:** caller tests via `_validate_findings` (same harness as
  test_cross_identity_reject.py): POSITIVE — a control-held reject still downgrades to low/0.15/"downgraded"
  (existing test stays green, its stub setting `control_outcome="control_held"`); NEGATIVE CONTROL — a BFLA
  reached-unproven `not_confirmed` (conf 0.4, no `control_outcome`) is NOT capped/demoted and NOT stamped
  "access correctly restricted"; NEGATIVE CONTROL — an ownership-authorized `not_confirmed` (0.3) likewise
  untouched. `full` green.
- **Impact:** High. **Follow-on to SC-1 (same anti-pattern, reject side; a different gate/object).**
- **Source:** 2026-09-27 re-analysis batch 2.

### [x] RA-8 — Workflow "status" assertion must validate its operand is an integer (complete SC-4's fail-closed invariant)
- **Result (VERIFIED):** `c4a534b` — `_load_assertion` now rejects a non-int-coercible `expected` on a
  `status` assertion at load time (ValueError, same shape as the unknown-kind / missing-operand raises,
  placed after the existing `expected is not None` guard), so `{"kind":"status","expected":"abc"}` no
  longer loads; int and digit-string operands (`200`, `"200"`) still load fine. Belt-and-suspenders:
  `_assertions_hold` wraps the runtime `int(assertion.expected)` in try/except so a slipped-through operand
  (e.g. a directly-constructed `Assertion` bypassing the loader) fails the step CLOSED
  (`return False, "malformed status assertion operand: ..."`) instead of raising an unhandled
  ValueError/TypeError out of `execute_workflow` (which previously crashed the run — only `finally`
  cleanups ran). Valid operands are byte-identical (same `expected HTTP X, got Y` reason on mismatch, pass
  on match). Completes SC-4 on the operand-TYPE half (SC-4 closed the unknown-KIND half at load+runtime).
  +3 tests in `test_workflow_engine.py::UnknownAssertionKindFailsClosedTests`: NEGATIVE load control
  (`workflow_from_dict` rejects `expected="abc"` → ValueError; fails against pre-change code, which loaded
  it fine), POSITIVE load control (`expected=200` loads to a valid status Assertion), RUNTIME fail-closed
  (a directly-constructed malformed `Assertion` → `StepStatus.FAILED`, reason "malformed status assertion
  operand", `execute_workflow` returns rather than raising; fails against pre-change code, which raised out
  of the run). No `config.yaml` change (no new flag; strict tightening). `test_pipeline_gate.py` untouched.
  Full suite green: harness unittest 2817 OK / 2 skip (+3 RA-8 tests), pytest-native 38 passed, evaluation
  221 OK, evaluation-integrity 42 OK (targeted `test_workflow_engine` 31 OK; smoke 92 OK).
- **Domain:** Workflow robustness / fail-closed · **Effort:** S · **Depends on:** none · **Mode:** LOOP (offline)
- **Evidence (VERIFIED, re-read this session):** `_assertions_hold` does
  `if assertion.kind == "status" and status != int(assertion.expected):`
  ([harness/workflow_engine.py:206](harness/workflow_engine.py)) with `int(assertion.expected)` UNGUARDED;
  `_load_assertion` (:377-386) requires `expected is not None` for status/body_contains but does NOT check
  int-coercibility, and `workflow_from_dict` (:396) passes `a.get("expected")` raw — so
  `{"kind":"status","expected":"twohundred"}` loads fine. `_assertions_hold` is called from `run_step`
  (:287) with no try/except, so a raised `ValueError`/`TypeError` from `int()` propagates out of
  `execute_workflow` (only `finally` cleanups run), crashing the workflow run. SC-4 closed unknown-KIND
  fail-closed (load + runtime) but left operand TYPE unvalidated; test_workflow_engine.py covers only the
  misspelled-kind case.
- **Problem:** A loadable-but-malformed operator workflow (a `status` assertion whose `expected` isn't
  int-coercible) crashes `execute_workflow` with an unhandled exception instead of the clean load-time
  rejection / runtime fail-closed SC-4 established for the rest of the assertion surface.
- **Recommendation:** In `_load_assertion`, for `kind == "status"` coerce/validate `expected` to `int` and
  raise `ValueError` on failure (same shape as the unknown-kind raise). Belt-and-suspenders: guard the
  `int()` in `_assertions_hold` so a slipped-through value fails the step closed
  (`return False, "malformed status assertion operand: ..."`) rather than raising.
- **Acceptance criteria:** NEGATIVE CONTROL (load) — `_load_assertion({"kind":"status","expected":"abc"})`
  raises `ValueError`; `{"kind":"status","expected":200}` still returns a valid `Assertion` (positive
  control, existing valid workflows unaffected). If the runtime guard is added: `execute_workflow` on a
  step carrying a slipped-through malformed status assertion fails the step closed (BLOCKED/FAILED), never
  raises out of the run. `full` green.
- **Impact:** Medium-Low (operator-config-crash class; completes SC-4). **Follow-on to SC-4 (operand-type
  half).**
- **Source:** 2026-09-27 re-analysis batch 2.

## Swarm-refresh batch — 2026-09-28 (R-*)

Source: [`reviews/2026-09-28/swarm-refresh/REVIEW.md`](reviews/2026-09-28/swarm-refresh/REVIEW.md) +
[`VERIFICATION.md`](reviews/2026-09-28/swarm-refresh/VERIFICATION.md) (delta refresh of the SC-*/FR-7/RA-7/
RA-8 batches against `ce387cf3`). At review time no production file was modified. By the time this batch
was filed (same day), R1/R3/R4/R5/R6 already had **uncommitted** production fixes on disk; this session
re-verified each by re-running the review's `probes.py` against the current working tree (it needed one
local, scratch-only patch — a third `pipeline` side effect — because the R6 fix itself changes the call
count the script assumes; the review's own `probes.json` is left untouched as the pre-fix historical
record) plus one isolated follow-up probe for R2. Commands and before/after values are in
CURRENT_STATE.md. **Same day, still within this session, R7 also landed a fix** (browser/DOM/stored-XSS
callers now thread `run_context` through), and R1/R4/R7 picked up dedicated caller-level tests (R7's are
new files; R1/R4's corrected two pre-existing tests that had asserted the pre-fix buggy behavior — see
each item's own Result for which). **R2/R3/R5/R6 still have no dedicated regression test.** Every item
below stays `[~]` (or `[ ]` for a truly untouched one) until it has both a test and a commit, per this
file's own completion bar — R1/R4/R7 are now one commit away; R2/R3/R5/R6 need a test first.

### [x] R1 — `_credential_grants_access` treats response dissimilarity alone as authorization
- **Result (VERIFIED):** `c2fe5c75` — `harness/orchestrator_chain.py`'s `_credential_grants_access`
  now requires an explicit denial (401/403, or a 3xx redirect away) from **both** the anonymous and
  invalid-credential controls before accepting the credentialed response as authorized
  (`_denied(anon) and _denied(invalid)`, replacing bare `_responses_materially_same`-based dissimilarity).
  Re-verified this session via `probes.py`'s `credential_*` scenarios: both false-grant repros the review
  reported (`public_rotating` — a per-response nonce; `public_status_variation` — 200/202/203 on an
  identical public body) now return `False`; `public_stable`/`public_short_noise` stay `False`; the
  positive control (`protected`: 200 vs two 401s) stays `True`. **Update (same day, still uncommitted):** a
  caller-level test now exists — `test_credential_grant_differential.py` was corrected (the old
  `test_genuine_grant_same_status_different_body_still_counts` asserted the pre-fix buggy behavior; it's
  renamed to `test_same_status_different_body_without_denial_signal_returns_no_grant` and now asserts
  `False`, with a new `test_genuine_grant_redirect_denial_controls` preserving the original scenario's
  intent using real 302-redirect denials) plus a new `test_dissimilar_status_without_denial_returns_no_grant`
  for the status-jitter case. **Closed (VERIFIED):** committed `c2fe5c75` with two added hardening
  negative controls — `test_only_one_control_denied_returns_no_grant` pins the "BOTH controls must be
  denied" `and` (an `or` mutant survived before), and `test_server_error_controls_are_not_a_denial_returns_no_grant`
  pins `_denied`'s status set so a 5xx is not read as a denial (a `status>=300` mutant survived before);
  `ExecutionOutcome.ok == (outcome=="ok")` was confirmed so both denied/5xx controls actually reach `_denied`.
  `full` green: 2831 unittest OK (2 skipped), 38 pytest, 229 evaluation OK, 42 integrity OK, exit 0.
- **Domain:** Detection precision / credential-learning trust boundary · **Effort:** S · **Depends on:**
  none · **Mode:** LOOP (offline)
- **Evidence:** `orchestrator_chain.py:349` (pre-fix) returned `True` whenever neither control was
  materially similar to the credentialed response — dissimilarity, not a positive access fact.
- **Problem:** A public endpoint with per-response nonces or jittering status codes was accepted as proof
  bogus credentials grant access, feeding `_auto_escalate`'s learned-credential re-crawl.
- **Recommendation:** (implemented, per Result) — add the caller test + negative controls above, then close.
- **Acceptance criteria:** the five `credential_*` scenarios in `probes.py`, promoted to a real
  `test_orchestrator_chain.py` (or equivalent) case; `full` green.
- **Impact:** High. **Source:** 2026-09-28 swarm-refresh, residual A2/SC-2.

### [~] R2 — RA-7's `control_outcome` discriminator still collapses at the final suppression site
- **Result (in progress, uncommitted):** `models.py` now declares `ValidationReport.control_outcome`
  (default `""`), `orchestrator_confirm.py` carries it from `ValidationResult` when building the report,
  and `confirmation_gate._controlled_negatives`/`_has_controlled_negative` only count `outcome in ("",
  "control_held")` as a controlled negative — so an explicit `control_outcome="inconclusive"` correctly
  produces `inconclusive_unverified` instead of a refutation (re-verified in isolation this session: same
  finding/report, `control_outcome` swept over `""`/`"control_held"`/`"inconclusive"` — only the third
  yields the honest "neither confirmed nor refuted" verdict). `cross_identity_validator.py`'s two genuine
  reached-but-unproven branches now set `control_outcome="inconclusive"` explicitly. **What's still
  missing (this is the actual residual, not a re-file of the original RA-7 finding):** (a) no test drives
  this through the full `Orchestrator.analyze()` path — the existing `test_cross_identity_reject.py`
  fixtures stop at `_validate_findings`, and this session's attempt to exercise the full path with the
  *existing* `_CrossIdentityBflaReachedUnprovenValidator` stub reproduced the old symptom, because that
  stub's own docstring convention (predating this fix) is to leave `control_outcome` **unset** for
  "inconclusive" — which the gate's backward-compat default (`""` = legacy validator = presumed negative)
  still treats as a controlled negative. The stub needs updating to set `control_outcome="inconclusive"`
  explicitly (matching the real validator now), and a new caller test should drive `analyze()` itself, not
  just `_validate_findings`. (b) Any *other* validator that returns `not_confirmed` for a genuinely
  inconclusive reason without setting `control_outcome` is still silently treated as a legacy negative —
  worth a registry-wide audit before relying on this for a class besides cross-identity.
- **Domain:** Confirmation-gate correctness · **Effort:** S (stub + test) · **Depends on:** none ·
  **Mode:** LOOP (offline)
- **Evidence:** `reviews/2026-09-28/swarm-refresh/REVIEW.md` §R2; this session's
  `reviews/2026-09-28/swarm-refresh/probes.py` rerun (see CURRENT_STATE.md) and a standalone
  `apply_confirmation_suppression` sweep over the three `control_outcome` values.
- **Problem:** the plumbing is right; the one fixture/test that was supposed to prove the full pipeline
  respects it doesn't, because it wasn't updated to the new convention it's meant to be testing.
- **Recommendation:** update `_CrossIdentityBflaReachedUnprovenValidator` to set
  `control_outcome="inconclusive"`; add an `analyze()`-level caller test (control-held stays a refutation,
  inconclusive does not); audit other `not_confirmed`-returning validators for the same gap.
- **Acceptance criteria:** `analyze()` on the inconclusive fixture yields `inconclusive_unverified`, not
  "likely false positive"; the control-held fixture still yields the refutation; `full` green.
- **Impact:** High (this is RA-7's whole point — don't bury a genuine reach as "access correctly
  restricted"). **Source:** 2026-09-28 swarm-refresh, residual RA-7.

### [~] R3 — Unknown/anonymous principal no longer wildcards a resolved principal
- **Result (in progress, uncommitted):** `confirmation_gate._has_controlled_negative` now requires
  `neg_principal == principal_id` exactly (was: skip the principal check entirely unless *both* sides were
  non-empty and differed). Re-verified this session via `probes.py`'s `suppression_*` cases: an
  unknown-principal negative against an `alice` finding on the same parameter now yields
  `inconclusive_unverified` (was: `unconfirmed_hypothesis`, i.e. wrongly refuted); a different named
  principal (`bob`) and an empty parameter still correctly yield `inconclusive_unverified`; a matching
  principal (`alice`==`alice`) still correctly yields `unconfirmed_hypothesis` (a real controlled
  negative). **Missing:** a caller-level test encoding these four cases, and a commit.
- **Domain:** Confirmation-gate correctness / evidence binding · **Effort:** S · **Depends on:** none ·
  **Mode:** LOOP (offline)
- **Evidence:** `confirmation_gate.py:645` (pre-fix) rejected a principal mismatch only when both strings
  were non-empty, so an unresolved/anonymous negative wildcarded onto any named principal's finding.
- **Problem:** a negative recorded under no known principal could refute a finding scoped to a specific,
  different principal — the "unknown-identity wildcard" half of the original A3 finding.
- **Recommendation:** (implemented, per Result) — add the caller test above, then close. Full case/URL/
  method binding beyond parameter+principal remains out of scope for this item.
- **Acceptance criteria:** the four `suppression_*` cases above as a real test; `full` green.
- **Impact:** Medium-High (evidence-correctness, not a live-exploit path by itself). **Source:** 2026-09-28
  swarm-refresh, residual A3/SC-3.

### [~] R4 — `EffortBudget.reserve` admission arithmetic omitted the requested amount (narrow scope: SC-8 covers the rest)
- **Result (in progress, uncommitted):** `effort.py`'s `reserve` now also rejects when
  `spent + reserved + requested > total_tokens`, not just when already at/over the ceiling before adding
  the request. Re-verified this session: against a 100-token `HARD` budget, `reserve(60)` then `reserve(60)`
  now admits the first and **rejects** the second (`reserved` stays `60`) — was: both admitted,
  `reserved == 120`, i.e. 20% over a hard ceiling. **Scope note:** this item is deliberately narrow — it is
  only the admission-arithmetic bug. SC-8's broader finding (no production caller uses the reservation API;
  `allow`/`record` remain in dispatch paths; `Orchestrator` doesn't pass `max_duration_s` at construction)
  is **not** touched by this diff and stays open under SC-8, not re-filed here. **Update (same day, still
  uncommitted):** `test_effort.py` now has `test_reserve_rejects_estimate_larger_than_total_capacity` (a
  single `reserve(1600)` against a 1000 HARD budget is refused outright) and
  `test_reserve_rejects_second_reservation_that_would_overshoot` (two sequential `reserve(600)` calls: first
  admitted, second refused, `_reserved` stays `600`). The pre-existing `reserve(1600)` in
  `test_reserve_then_commit_matches_record` — an incidental setup value for an unrelated reserve-then-
  commit-ledger assertion, not a test of admission itself — was changed to `reserve(600)` so it keeps
  testing what it always meant to, without being confounded by the new (correct) rejection. **Missing:**
  only the commit; concurrent-dispatch coverage stays SC-8's scope once production callers exist.
- **Domain:** Resource governance · **Effort:** S (this item) · **Depends on:** none for this item; SC-8 for
  production wiring · **Mode:** LOOP (offline)
- **Evidence:** `effort.py:216` (pre-fix) computed `token_full` from `spent + reserved` only, then added the
  new request's estimate regardless of whether it would cross the ceiling.
- **Problem:** a hard budget's reservation primitive could itself be walked past its own ceiling.
- **Recommendation:** (implemented, per Result) — add the caller test above, then close this item; leave
  SC-8's dispatch-wiring gap to SC-8.
- **Acceptance criteria:** the 100/60/60 case above plus an unequal-size case and a single request larger
  than total capacity, as a real test; `full` green.
- **Impact:** Medium (a real primitive bug, but unreachable from production until SC-8's wiring lands).
  **Source:** 2026-09-28 swarm-refresh, residual A8/SC-8 (arithmetic slice only).

### [~] R5 — Cache `clear()`/`size()` missed the hypothesis-cache table (FR-7 lifecycle)
- **Result (in progress, uncommitted):** `cache.py`'s `clear()` now also deletes
  `hypothesis_cache_entries` (counted into the eviction total), and `size()` is now
  `exchange_size() + hypothesis_size()` with both new accessors exposed separately. Re-verified this
  session: write a hypothesis, confirm it's retrievable, `clear()`, and it is now correctly gone
  (`hypothesis_after_clear: False`, was `True`); reported size after clear is `0` in both the old and new
  runs (that half was never broken). **Missing:** a caller-level test (write hypothesis + exchange entry,
  clear, assert both miss and both size accessors read 0), and a commit.
- **Domain:** Cache lifecycle (FR-7, ships default-OFF) · **Effort:** S · **Depends on:** none · **Mode:**
  LOOP (offline)
- **Evidence:** `cache.py:737` (pre-fix) `clear()` only issued `DELETE FROM cache_entries`; `size()` only
  counted that same table.
- **Problem:** with hypothesis reuse enabled, an operator's `/cache/clear` did not force fresh inference —
  a cached finding could survive the exact operation meant to remove it.
- **Recommendation:** (implemented, per Result) — add the caller test above, then close.
- **Acceptance criteria:** post-`clear()`, both `get_hypothesis` and the equivalent exchange-cache read miss,
  and `size()`/`exchange_size()`/`hypothesis_size()` all read 0; `full` green.
- **Impact:** Medium (FR-7 ships off; this is a correctness gate before it can be turned on). **Source:**
  2026-09-28 swarm-refresh, new FR-7 lifecycle defect.

### [~] R6 — A failed inference stage was cached and replayed as a reusable hypothesis (FR-7 lifecycle)
- **Result (in progress, uncommitted):** `orchestrator_detect.py` now skips `put_hypothesis` whenever any
  `stage_outcomes` entry has `status == "failed"` — a failed stage is treated as an outage, never a
  reusable result. Re-verified this session (and this is *why* `probes.py` needed a scratch-only patch to
  add a third pipeline response: the fix changes the call count the script assumed): first `analyze()` on
  a stubbed failing stage is degraded (as before); the **second**, fresh-run `analyze()` on identical
  traffic now makes a **new** inference call and comes back healthy on its own
  (`second_degraded: False`, `calls_after_second: 2` — was: cache-hit, stayed degraded,
  `calls_after_second: 1`, needing an explicit bypass to recover). This is a better outcome than the
  review's minimum ask (which only required *not reusing* the failure) — recovery is now automatic on the
  very next call. **Missing:** a caller-level test (fail then succeed across two fresh `RunContext`s,
  assert the second call re-invokes inference and recovers), and a commit.
- **Domain:** Cache lifecycle (FR-7, ships default-OFF) · **Effort:** S · **Depends on:** none · **Mode:**
  LOOP (offline)
- **Evidence:** `orchestrator_detect.py` (pre-fix) called `put_hypothesis` whenever `_hyp_enabled`, with no
  check on `stage_outcomes` status, so a transient failure was cached and replayed until TTL/bypass.
- **Problem:** an opt-in reuse cache could indefinitely prolong an outage instead of just avoiding
  redundant work.
- **Recommendation:** (implemented, per Result) — add the caller test above, then close. A deliberate
  short-lived negative/circuit-breaker cache, if wanted later, should be a separate, explicit policy.
- **Acceptance criteria:** the fail-then-recover sequence above as a real test; `full` green.
- **Impact:** Medium (FR-7 ships off; same enabling condition as R5). **Source:** 2026-09-28 swarm-refresh,
  new FR-7 lifecycle defect.

### [~] R7 — Browser/DOM/stored-XSS validator callers omitted the gate/budget objects SC-7 added
- **Result (in progress, uncommitted; done same day, after this item was first filed above):** all three
  validators now take an optional `run_context=None` constructor param (bound per-dispatch by the existing
  `ValidatorRegistry.bind_run_context` seam, the same one every other active validator already uses — no
  new wiring mechanism introduced). `browser_xss_validator.py` and `dom_xss_validator.py` forward
  `scope`/`gate`/`budget`/`cancel` into `driver.visit(...)` only when a `run_context` is actually bound
  (`visit_kw = {}` otherwise, so a no-context caller — including every fake driver in the existing test
  suite — sees byte-identical behavior). `stored_xss_validator.py` additionally uses
  `run_context.gate` instead of always `get_default_gate()` for its plant/render mutating-write gate check,
  and forwards the same four kwargs into its own optional browser-confirm `visit()`. Caller tests landed
  alongside: `test_browser_xss_validator.py` (+51 lines), `test_dom_xss_validator.py` (+47 lines), and a new
  `test_stored_xss_validator.py`. **Missing:** only the commit; live interception coverage (real Chromium,
  service-worker/WebSocket behavior, engine readiness) stays a separate OWNER/LIVE follow-up, not something
  a mocked-driver caller test can establish.
- **Domain:** Safety enforcement (browser execution) · **Effort:** M · **Depends on:** none · **Mode:** LOOP
  (offline for the wiring + mocked-driver caller tests; live interception coverage is a separate,
  OWNER/LIVE efficacy question)
- **Evidence:** `validators/browser_xss_validator.py:123`, `validators/dom_xss_validator.py:107`, and
  `validators/stored_xss_validator.py:167` (pre-fix) called their browser `visit()` without the gate/budget
  parameters SC-7 added to that seam.
- **Problem:** the safety primitive SC-7 built had no production caller, so browser-driven validation was
  still ungoverned by the same policy every other active leg respects.
- **Recommendation:** (implemented, per Result) — commit; confirm the new caller tests actually assert a
  denial/exhaustion is honored (not just that the kwargs are passed through) before treating this as closed.
- **Acceptance criteria:** all three validators pass gate/budget through; a mocked-driver test per
  validator proves a denial/exhaustion is actually honored; `full` green.
- **Impact:** High (production safety-enforcement gap, not just a missing feature). **Source:** 2026-09-28
  swarm-refresh, continuation of A7/SC-7.
