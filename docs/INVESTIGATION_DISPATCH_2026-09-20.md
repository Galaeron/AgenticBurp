# Investigation dispatch for the Opus reviewer / Sonnet implementation loop

## Mission and execution boundary

The user requested investigations based on committed live results. The task source
is IMPROVEMENT_BACKLOG.md, not an archived changelog. Complete the paused item first,
then process INV-1 through INV-4 sequentially, one item per iteration. Opus reviews
and decides; Sonnet performs the bounded investigation. Do not start another loop
or change its schedule. Do not silently substitute models or start live workloads.

These items are eligible OFFLINE: their product is an evidence-backed diagnosis
and precise follow-up tickets. Live efficacy measurement is a separate owner-run
step, not a prerequisite for documenting what the current code does. Missing
historical artifacts limit conclusions; they do not justify invented causes.

## Mandatory reviewer/coder procedure

1. Read AGENTS.md, CURRENT_STATE.md, the selected backlog item, and this guide.
   Record HEAD, branch, and tracked/untracked status without reading prohibited
   files. Inspect only task-relevant source and artifact metadata/content.
2. Preserve all pre-existing edits and worktrees. There is pending transport and
   evidence work elsewhere. Inspect overlaps read-only before proposing a fix.
   Never use `git checkout -- .`, `git reset --hard`, or blanket cleanup on rejection;
   discard only this iteration's own changes after checking their exact diff.
3. Opus selects one item and gives Sonnet its exact output path and acceptance
   criteria. Sonnet first traces the actual production caller, then proposes causes.
   Do not treat a helper's existence or a mocked unit test as pipeline integration.
4. Write the selected investigation document. Production fixes are separate,
   narrowly scoped follow-up tickets, not incidental changes in the investigation.
   Do not refactor, change thresholds, turn on flags, or add agents in these items.
5. Every conclusion has a source path/symbol or command/artifact reference and
   tested revision. Use VERIFIED-by-inspection, VERIFIED-in-run, SUPPORTED,
   INFERRED, or UNKNOWN explicitly. Committed numbers are historical/reported.
6. Opus returns APPROVE only when the item-specific checklist below is satisfied.
   REVISE if the document substitutes guesses for evidence, omits a caller, or
   claims unavailable measurements. Missing artifacts can be an approved explicit
   limitation when source analysis and a reproducible retrieval/audit recipe exist;
   never call the historical cause resolved in that case.
7. Documentation-only validation: `git diff --check`, verify local references and
   the factual basis of commands. If executable helpers/tests are added, run from
   repository root with `.venv-rationalisation/Scripts/python.exe`:
   `-m harness.suite smoke`, `-m harness.suite full`, and
   `-m unittest harness.test_orchestrator_precondition`. Record actual outcomes.
   Do not rerun historical benchmark scripts merely to discover their CLI.
8. Close only the selected INV item after review, record the commit/evidence tag,
   and update CURRENT_STATE.md within its 100-line limit. A focused commit needs
   the required Co-Authored-By trailer; no push. Preserve historical evidence.

Never read `*ANSWER_KEY*` (case variants included) or any blind target's app.py.
Do not inspect other blind implementation files to infer planted weaknesses.
Do not execute/import scorers or drivers that load prohibited material. Inspect
their imports and input paths first. Use allowed aggregate reports, sanitized
outputs and harness-generated records; otherwise record the limitation. Do not
expose credentials in documents or copy raw request secrets into audit outputs.
Read original databases only read-only; never migrate, repair, or write to them.

## Established baseline: do not rediscover or erase it

Read the dated 2026-09-20 section of `testing/SCORECARD.md`. Commits `95b124a`
and `02de8bf` record import-path repairs and exact revision provenance.

| Run | Historical/reported result | Interpretation boundary |
|---|---|---|
| PixelMart agents fixture + scorer | TP 11, FP 15, FN 0; precision .423, recall 1.000 | Fresh agent generation followed by cached scoring; not proof of full live validation |
| blind-target-2 full pipeline | positives 2/2; clean controls 1/6; 51 findings | Small sample; five secure controls still noisy |
| VulnCorp maxrun | 9/13 raw confirmed, 6/13 proof-linked; 0 chains; 8.3h; 1,914 fused findings | Different revision/worktree; raw volume is not precision |

PixelMart/blind-target-2 ran on `249b799` plus the five-file working diff whose
hash is recorded in the scorecard. VulnCorp ran on `eb70210`. Neither establishes
current-HEAD behavior. Curated routing/quarantine changes came later. Do not claim
the later changes failed based on an earlier run, or succeeded from offline tests.

## INV-1: baseline reconciliation and comparison preparation

Entry points: `testing/SCORECARD.md`, `testing/score.py`,
`testing/test-target/detection_fixture.py`,
`testing/blind-target-2/run_blind_eval.py`, `harness/config_schema.py`,
`harness/test_fail_open_curated.py`, `harness/test_quarantine_leads.py`.
Inspect driver text safely before importing or running anything.

Steps:
1. Build a revision table for the three historical runs: tested commit/diff,
   corpus, model identifier, fresh-generation/cache-scoring behavior, operating
   threshold, scope of pipeline exercised, artifact location and availability.
2. Map each later change (curated routing, passive oracle, quarantine) to its
   production consumer. Verify which real and vendored config each driver loads;
   an overlay in the wrong config is not a valid comparison.
3. Prepare a same-revision 2x2 comparison: routing all/curated crossed with
   quarantine off/on. Hold model, corpus, oracle mode, scope, budgets and all
   other settings fixed. Record effective config fingerprints and fresh cache
   namespaces. Where quarantine is strictly postprocessing, explain how identical
   raw findings can isolate its effect from stochastic model generation.
4. Report both raw detection recall and surfaced-finding recall, raw/surfaced FP
   counts, clean controls, leads, proof-linked confirmation, elapsed time and
   model calls/tokens when available. Hiding everything as leads is not a win.
   Use unchanged labels and scoring definitions; never tune ground truth to output.
5. Write exact commands only after inspecting supported arguments/environment
   variables. Include prerequisite checks, artifact outputs and repeat policy
   (at least three independent runs per model-generating condition when feasible;
   otherwise label single-pass variance explicitly). No live execution this item.
6. Identify P0-3's remaining acceptance gaps rather than marking it wholly absent
   or done. File a separate owner-run measurement step with this prepared recipe.

Review gate: a second operator can distinguish historical evidence, current-code
inspection and proposed execution, and reproduce the comparison without guessing
which config or cache is used. No claim that precision/recall improved yet.

## INV-2: raw confirmation versus durable proof

Entry points: `harness/orchestrator_confirm.py`, `harness/confirmation_gate.py`,
`harness/evidence.py`, `harness/store.py`, `harness/evidence_ledger.py`, and
the proof registration/lookup callers found by targeted search.

Steps:
1. Trace validator result -> proof creation -> persistence -> finding reference
   -> suppression/fusion -> report/audit lookup. Record actual keys and types.
   Distinguish proof records from the newer ledger events; they are not synonyms.
2. If allowed historical artifacts exist, audit each raw-confirmed record using
   the actual run/case/validator identity. Count missing references, dangling
   references, identity mismatches, rejected proofs and valid links separately.
   Never join by URL/title alone or borrow a proof from another run/principal.
3. If artifacts are missing, provide a read-only audit recipe against the actual
   schema and state that the three-case historical difference remains unexplained.
   Do not fabricate a per-bug breakdown from the aggregate 9/13 and 6/13 counts.
4. For each source-supported failure mode, propose the smallest caller-level
   regression scenario: valid matching proof positive control; missing proof,
   wrong case/validator/run, and storage/reload negative controls as applicable.
5. File bounded implementation tickets with exact symbols and acceptance tests.
   Link P0-6 when appropriate instead of implementing a second evidence ledger.

Review gate: separate a reproduced defect from a plausible cause, and specify
what a complete proof link means. Do not solve the gap by trusting `confirmed`
or weakening the audit until the counts agree.

## INV-3: chain candidate-to-report funnel

Entry points: `harness/server.py` investigation endpoint,
`harness/orchestrator_chain.py`, `harness/engagement_builder.py`,
`harness/worklist_investigator.py`, `harness/chain_linker.py`,
`harness/chaining.py`, and their actual callers.

Steps:
1. Map invocation and required flags from API/driver to final report, including
   evidence trust requirements, capability extraction, linking, budget/scope gates,
   execution, confirmation and persistence. Identify which chain path the reported
   run actually invoked; similarly named helpers need not share a pipeline.
2. Make a stage table: input findings -> eligible capabilities -> candidate edges
   -> proposed chains -> authorized attempts -> confirmed chains -> reported chains.
   Fill counts only from available artifacts; write UNKNOWN for absent telemetry.
3. Locate the first demonstrated loss, or specify minimal instrumentation needed
   to locate it. Distinguish disabled/not invoked, no compatible evidence, rejected
   proposal, exhausted budget, failed confirmation and dropped reporting.
4. Design one synthetic owned-fixture caller test with two compatible steps and
   deterministic evidence. Negative control removes a required capability or uses
   a different principal/scope; no confirmed chain may result. Active-disabled
   control must send zero requests. Proposals must not masquerade as confirmations.
5. Propose one fix or instrumentation ticket for the earliest supported failure.
   Do not build BusinessContextAgent or enable defaults to force a nonzero count.

Review gate: zero chains alone is not a regression diagnosis. The old one-chain
claim is not a comparable control without matching revision/config/evidence.

## INV-4: duplicate noise and cost attribution

Entry points: `harness/host_dep_dedup.py`, finding fusion/store/report callers,
`harness/telemetry.py`, `harness/ollama_client.py` and existing agent scheduling.

Steps:
1. Map existing dedup keys and placement before proposing new logic. Separate
   raw observations, fused findings, surfaced findings, leads and distinct cases.
2. On available allowed artifacts, group by normalized endpoint, vulnerability
   class, validator, principal/object and proof identity where recorded. Explain
   missing fields. A repeated class on one endpoint is not automatically one bug.
3. Trace repeated 641/107 disclosure counts from the scorecard to evidence if
   available. If not, retain them as reported counts, not a verified dedup defect.
4. Attribute runtime from existing telemetry to model calls, queue wait, validator
   work, retries and discovery where measurable. Do not assume all 8.3h was LLM
   time. Specify missing instrumentation before recommending concurrency changes.
5. Produce at most three tickets. Each names a source-supported bottleneck, target
   metric, smallest change, and positive/negative regression controls. Dedup tests
   must retain distinct object/principal vulnerabilities and all supporting proof
   links while consolidating genuine repeated evidence.

Review gate: no raw-volume precision claims, severity-only noise concealment,
unmeasured speedup promises, or specialist removal without the existing ablation.
