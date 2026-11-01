# Evaluation reassessment — 2026-09-20

Review base: `c1133d5`, branch `reconciliation-backlog`, including pre-existing
uncommitted backlog/investigation instructions. This is a documentation correction,
not a fresh efficacy evaluation. Source inspected; no tests, model runs, target
traffic, Java builds, or external competitive research performed in this pass.
Existing test outcomes and benchmark numbers below are historical/reported.

## Verdict on the earlier evaluation

**5/10 overall: useful prioritization, insufficient evidence discipline.**
Strategic usefulness: 7/10; factual completeness: 4/10; fulfillment of the original
review brief: 4/10. These are reviewer judgments, not measured product scores.

Agree with prioritizing trustworthy evidence, precision, operator effort, safe
execution and ablation before more specialists. Agree that incremental improvement
is preferable to a rewrite. Disagree with the absence-of-benchmarks claim, the
near-perfect safety score, confident competitor comparisons without research,
and prescribing six-to-eight agents before measuring the alternatives.

The original review missed `testing/SCORECARD.md`, confused unknown current efficacy
with demonstrated poor efficacy, and inferred too much from file counts, comments
and limited source excerpts. A test-function count is not a test-quality measure;
commit frequency does not establish AI authorship or code maturity. The review
also omitted most per-score explanations, a fully specified ablation protocol,
and current competitive sources required by the brief. Claims of superiority to
commercial tools and commercial defensibility should be withdrawn pending evidence.

## Reconcile the changelog with source

Changelog sources: `CURRENT_STATE.md`, `IMPROVEMENT_BACKLOG.md` Result entries,
and git history. Historical statements remain revision-bound.

| Earlier conclusion | Current evidence | Corrected assessment |
|---|---|---|
| No real-model benchmark exists | `testing/SCORECARD.md`, dated 2026-09-20 section | Incorrect even as an inventory claim. Historical real-model measurements exist; current-change effectiveness remains unmeasured. |
| EvidenceLedger has no production callers | `25a737a`; emissions in `agents/base_agent.py`, `run_context.py`, `orchestrator_confirm.py`; persistence/API | Superseded. Instrumentation exists. Complete, replayable evidence is still not established: `EvidenceLedger.reconstruct` accepts a validation/revision event alone as complete. Track P0-6, not a second ledger implementation. |
| Trust tiers are static only | `533928c`; `ConfirmMixin._run_live_markers`, `leg_self_test.py` | Partially addressed. Self-tests are opt-in, cached on the orchestrator, and cover a subset; static defaults remain. Do not describe all legs as freshly qualified per engagement. |
| Unsafe committed scope | `0e993da`; empty allowed-host default and safe-default guard | Addressed in source. Preserve guard; do not redo P0-4. |
| No prompt isolation found | `33392c9`; existing nonce fencing plus breakout neutralization | Original search was incomplete. Fencing is defense in depth, not semantic prompt-injection immunity. Prior-context coverage and actual model behavior still need evaluation. |
| DNS rebinding protection proven by new tests | `e54cfb6`; `test_rebinding_hostname_not_itself_scoped_is_refused` | Overstatement: unlisted hostname rejection is tested, not an allowed name changing address. Existing P1-9 covers the real boundary question. |
| Operating profiles are missing | `1e084e1`; `resolve_operating_profile` | Superseded. Profiles exist, but value-equals-default cannot identify explicit overrides; passive-only can preserve active true values. P0-5 is the necessary follow-up. |

### Additional self-test caveat

VERIFIED-by-inspection: `leg_self_test._case_passes` rejects a negative control
only if its status or boolean says confirmed. A skipped/error/inconclusive result
with `confirmed=False` can therefore satisfy the negative half. This is not a
controlled negative. `run_self_test` also calls `global_throttle.configure(0)`
and later restores it, affecting process-wide resource policy during the test.
Neither observation establishes a live exploit; both need caller-level controls
before self-tests are treated as authoritative qualification.

## What the available measurements actually say

Source: `../testing/SCORECARD.md`, 2026-09-20 section. VERIFIED that the document
contains these results; execution and artifact validity were not independently
reproduced here. Do not combine the corpora or treat them as current-HEAD results.

| Historical run | Reported outcome | Decision supported |
|---|---|---|
| PixelMart, `249b799` plus documented five-file diff | TP 11, FP 15, FN 0; precision .423, recall 1.000 | Detection occurs on this small corpus, but noise is substantial. Live agent generation plus cached scoring is not full live validator coverage. |
| blind-target-2, same revision/diff | Positives 2/2; clean secure controls 1/6; 51 findings | Secure-control precision needs work; two positives cannot establish broad recall. |
| VulnCorp, separate `eb70210` worktree | 9/13 raw confirmed, 6/13 proof-linked; zero chains; 8.3h; 1,914 fused findings | Investigate proof durability, chain funnel, noise and time attribution. Raw volume is not precision; zero chains alone does not identify a regression. |

These runs precede curated-routing/quarantine changes and the improvement-loop
commits. They neither prove nor disprove those later changes. The correct next
step is the existing INV-1 controlled comparison, not creating a first benchmark.
Retain INV-2 proof-link investigation, INV-3 chain funnel and INV-4 cost/noise
attribution; do not replace them with new feature work.

## Revised score interpretation

These limited provisional judgments replace the most misleading earlier scores.
Other numerical scores should be regarded as provisional, not silently endorsed.

| Category | Earlier | Revised | Why not higher / why not lower / improvement gate |
|---|---:|---:|---|
| Safety controls | 9 | 6 | Profile composition and address-bound scope remain unresolved; layered fail-closed transport deserves credit; +2 requires caller-level safety guarantees across profiles/tools/redirects. |
| Evidence quality | 4 | 5 | Emissions/persistence exist, but completeness is too weak; +2 requires resolvable per-run request/response and proof identity across storage/reload/export. |
| Evaluation maturity | 3 | 5 | Revision-pinned real runs and negative controls exist; small samples and no current controlled ablations limit confidence; +2 requires repeatable comparisons with stable definitions and variance. |
| Real-world efficacy | 2 | Not established | Small-fixture efficacy exists with substantial noise. Broad field efficacy cannot be assigned a defensible point score; require diverse blinded corpora and practitioner time measurements. |
| Trustworthiness | 6 | 5 | Proof-linked/raw divergence and permissive completeness limit reliance; explicit lifecycle/negative-control concepts deserve credit; +2 requires durable evidence and controlled-negative qualification. |
| Business viability | 4 | Not established | A privacy-sensitive Burp practitioner wedge is a hypothesis; require interviews, observed repeat usage, comparative time savings and willingness to pay. |

## Business reasoning and next decisions

Keep P2-1, but make it a bounded application-context/planning component, not an
unconditional extra specialist call per exchange. First inventory existing
business-logic agents, workflow state and capability/chaining consumers. Zero
chains is insufficient evidence that missing semantic understanding caused the
failure. INV-3 should establish whether the current loop consumes candidates at all.

Use roles, objects, workflows and transitions with source references and explicit
unknowns. Outputs are hypotheses, never authorization or confirmation. Evaluate
ON/OFF using the same model/corpus/budgets, counting distinct proof-linked chains,
false chains, requests, model cost and operator time. Ship only if it improves
useful outcomes over the existing planner. No new permission to run live tests is
implied by this review.

Practical order: preserve the paused task and INV-1..4 dispatch; then address
P0-5/P0-6, negative-control qualification, and P1-9; perform controlled owner-run
measurements; only then expand application reasoning or simplify agent families
according to ablation evidence. Retention/redaction must precede expanded sensitive
evidence storage. Six more months is a conditional investment, with a 30-day
evidence/precision checkpoint rather than a promise to build all listed features.
