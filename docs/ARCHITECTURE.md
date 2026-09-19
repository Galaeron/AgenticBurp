# Architecture and source ownership

All paths below are relative to `harness/` unless noted. `orchestrator.py` assembles
mixins; searching only that file misses the implementation.

| Behavior | Production owner | First useful test |
|---|---|---|
| Captured exchange to findings | `orchestrator_detect.py`, `analysis_pipeline.py`, `agent_manager.py` | `test_smoke_detection.py` |
| Discovered routes to confirmed findings | `orchestrator_chain.py`, `engagement_builder.py`, `worklist_investigator.py` | `test_pipeline_gate.py` |
| Validator dispatch/proof binding | `orchestrator_confirm.py`, `validators/registry.py`, `evidence_ledger.py` | `test_evidence_ledger.py`, `test_oracle_wiring.py` |
| Endpoint shape warrants a confirmation attempt | `orchestrator_helpers.py`, `orchestrator_chain.py` | `test_smoke_shape_precondition.py`, `test_orchestrator_precondition.py` |
| Discovery and request templates | `api_surface_discovery.py`, `role_crawl.py`, `openapi_ingest.py` | `test_api_surface_discovery.py`, `test_role_crawl.py` |
| Invocation isolation, scope and credentials | `run_context.py`, `target_transport.py`, `safety_gate.py`, `scope_lock.py` | `test_run_context.py`, `test_offscope_host_lock.py` |
| Stateful workflows | `workflow_engine.py`, `feature_workflow.py` | `test_workflow_engine.py` |
| Coverage applicability/proof state | `coverage_model.py`, `coverage_tracker.py`, `evidence.py` | `test_coverage_tracker.py`, `test_coverage_cases.py` |
| Escalation and second-order pairs | `chain_linker.py`, `chaining.py`, `second_order.py` | `test_chain_linker.py`, `test_second_order.py` |
| Persistence, issue aggregation and export | `store.py`, `issues.py`, `report_generator.py` | `test_issues.py`, `test_verification_state_consistency.py` |
| Model/provider selection | `ollama_client.py`, `llm_provider.py`, `coordinator.py` | `test_llm_provider.py`, `test_fail_open_telemetry.py` |

Captured analysis selects agents, parses/synthesizes their output and dispatches
validators. Engagement discovery builds role-specific request templates, ranks
work, investigates nodes, then links findings and capabilities. Shape/coverage
rules can request deterministic legs independently of an LLM label. Eligibility
is not execution: policy, budget, transport, prerequisites and evidence still
matter. Do not describe every applicable cell as executed by construction.

Confirmation has multiple meanings. `confirmed` and the oracle framework's
`verification_state` are distinct; neither an agent assertion nor a validator
name alone establishes an executed proof. Inspect `confirmation_gate.py`,
`oracle_framework.py`, and the exact caller. Registry availability does not mean
all validators are routed identically in both analysis paths. Retired verdicts
and requalification requirements live in [ORACLE_RETIREMENTS.md](../ORACLE_RETIREMENTS.md).

Evaluation code has overlapping layers: `testing/score.py` and
`testing/nightly_precision.py`, standalone `evaluation_integrity/`, and newer
`harness/{score_provenance,evidence_audit,coverage_summary,eval_health}.py` helpers.
The [implementation review](../reviews/2026-09-19/implementation-review/REVIEW.md)
identified missing consumers at `8f63511`. Subsequent commits through `57bcc02`
added consumers in `testing/score.py` (provenance), `issues.py` (proof audit),
`coverage_tracker.py` (execution summary) and the evaluation driver (health).
Use caller tests alongside helper tests; source wiring and an offline pass do not
establish live evaluation integrity or close every review requirement.

Configuration is loaded by `server.load_config()` from defaults plus local
overrides. Optional behavior may be implemented but disabled. Read the current
config and call sites before describing it as shipped/active. API/provider,
Java UI, and real-model behavior require their own boundary verification.

