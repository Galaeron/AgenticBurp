# Passive inference ownership

The bounded R27 cleanup is the accounting boundary introduced by R07/R08.
No additional orchestrator decomposition is needed to establish that contract.

`passive_inference.metered_passive_call` receives a client, an explicit run-owned
EffortBudget, a call kind, model, and prompts. It sanitizes the prompt copy,
reserves admission before dispatch, returns the metered result, and settles one
attempt on success, error or cancellation. The reservation is an admission
estimate, not a promised upper bound on provider consumption. Unknown usage
remains unknown; known consumption is a lower bound.

Two production caller families use this boundary: BaseAgent through
`passive_chat_json` (including family dispatch), and Coordinator routing.
AnalysisPipeline critique also uses it. AgentManager forwards the supplied budget
through dispatch; it does not hold a mutable current-run budget. Overlapping
runs can share the manager without replacing each other's accounting context.
The pipeline's budget is assigned to a task-local shallow pipeline view during
`Orchestrator.analyze`. The context binding is restored on completion or failure.
Two calls that explicitly share the same RunContext share its inference view.
Outside analysis, UI effort settings and admission still use the cumulative
operator budget: this change does not reset or increase its cap. Each receipt
appears once in that aggregate and once in its own run ledger. Remaining admission
capacity is aggregate; run consumption and run summaries are local.

The local helper calls the Ollama client's metered interface. Provider adapters
use `provider_trace.traced_call`, which retains their provider identity and retry
attempts while sharing `settle_call`. Do not wrap the same attempt through both
entry points: that would double-count. Client counters are diagnostics; the
explicit run ledger is authoritative for that run. Process-global caches or
shared manager state must not become the owner of a run budget.

Legacy standalone calls with no budget remain possible and emit an unmetered
warning. They do not manufacture a run receipt. Reports/status expose usage
completeness separately from the legacy known-token scalar. Neither confidence
nor completion of a provider call proves response quality.

Caller evidence: `test_remediation_inference_budget` exercises actual dispatch,
family/solo fallback, concurrent admission and shared-manager/separate-run
behavior. Its dropped-budget injection defeats the accounting assertion.
`test_remediation_inference_usage` checks routing/critique, parse failure,
missing/partial counts, retries, cancellation, and real passive analysis exports;
removing a receipt defeats the measured-consumption control. The root's fresh
2026-10-08 selection passed these 20 tests together with 12 TLS controls; exact
command, timing and source hashes are in
`reviews/2026-10-05-reconciled-remediation/root-review-20261008.json`.

That first selection did not establish isolation of actual calls sharing one
Orchestrator. Root review found the constructor's pipeline/budget were still
shared; a real overlapping caller returned [42,42] for independent receipts of
11 and 31 tokens. The corrected ownership controls require [11,31], retain
aggregate42, recreate the defect by removing the context binding, preserve the
hard aggregate cap, and check shared-context ownership and cancellation. All 29
inspected checks passed in
`reviews/2026-10-05-reconciled-remediation/r07-actual-run-ownership-2026-10-08/`.
The earlier manager-only evidence must not be substituted for this caller proof.

This boundary does not establish isolation of persistent engagement data,
cache correctness, active-path accounting, model effectiveness or a green full
suite. Those retain their own tickets and gates. Broad mixin rewrites and action
planning changes are outside this ownership cleanup.
