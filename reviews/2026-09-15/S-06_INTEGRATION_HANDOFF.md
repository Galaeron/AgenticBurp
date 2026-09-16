# S-06 integration handoff

Reverified against integrated revision
`0dc6a523d56cd7268f6f50b46399d5dc4c998a46`. This is a production-owner
checklist, not a claim that the offline diagnostics close production contracts.

**Update:** the four items below were implemented directly on
`reconciliation-backlog` (commits `e2b7ee7`, `54ebc49`, `79535ed`, `4c1cb63`,
following the `codex/supplemental-evidence` merge at `e4f02df`), each re-verified
against the current integrated revision first (W-9/W-24/W-23/W-8/W-13/W-14 had
all landed since this handoff's original base, and were re-checked before
touching anything). Full harness suite green after every commit (1902 -> 1912
tests). Kept here, retitled, as the audit trail this handoff exists to leave.

## Resolved

- **W-7/W-24 — enforce evidence at every confirmation consumer.** Root cause:
  two of three sites building `Finding` objects from raw, untrusted LLM JSON
  (`harness/agents/base_agent.py`, `harness/orchestrator_detect.py`'s
  `_attempt_rediscovery`, whose own prompt says "ALREADY CONFIRMED") passed the
  parsed dict straight to `Finding(**f)` with no override, unlike
  `iterative_agent.py` which already forced `confirmed=False`. A model echoing a
  `"confirmed": true` key would mint a persisted, proof-less confirmation that
  never touched `orchestrator_confirm.py`'s validator/proof pipeline. Fixed by
  stripping `confirmed` at both ingestion sites; only `orchestrator_confirm.py`
  may now set it True, always alongside a linked `proof_id`/`case_id`. Tests:
  `harness/test_base_agent.py::SelfReportedConfirmationTests`,
  `harness/test_rediscovery_confirmation.py`.

- **W-9 — preserve case-sensitive input identity.** `finding_fingerprint()`
  lower-cased `parameter_name` alongside `parameter_location`, so
  `userId`/`userid` collided (suppressing one silently swallowed the other).
  Fixed: `parameter_location` still folds (fixed enum), `parameter_name` no
  longer does; `_FINGERPRINT_ALGO_VERSION` bumped per the documented
  bump-on-formula-change contract (the migration's own recompute is
  coordinate-free, so it does not retroactively fix old rows' parameter case --
  this closes the bug for all findings persisted from here forward). Tests:
  `harness/test_finding_fingerprint.py::test_parameter_name_is_case_sensitive`,
  `::test_case_distinct_findings_persist_as_two_rows`,
  `::test_suppression_does_not_leak_across_case_variants`.

- **W-11 — bind saved diagnostics to an invocation.** Telemetry counters are
  now bucketed by run_id via a `contextvars.ContextVar` (`bind_current_run`),
  which asyncio isolates per-Task without a matching unbind on every exit path.
  `Orchestrator.analyze()` binds `run_context.run_id` at entry.
  `snapshot()`/`events()`/`swallowed_exceptions()`/`reset()` all take an
  optional `run_id`; omitted, they keep the old process-wide aggregate but now
  say so explicitly (`"scope": "process"`, a `runs_observed` count) instead of
  silently presenting a process-wide number as one run's explanation.
  `/telemetry` gained a `run_id` query param. Test proving the real caller:
  `harness/test_telemetry.py::TelemetryInvocationBindingTests::test_two_overlapping_analyze_calls_bind_distinct_run_ids`
  (two concurrent `Orchestrator.analyze()` calls, distinct run_ids observed,
  each run's events isolated).

- **W-8/W-23 — separate detection scoring from verified-issue evaluation and
  bind freshness.** `testing/score.py` only ever matched a label against
  `vulnerability_class` strings -- it has no path to a `proof_id`/`case_id`, so
  it cannot produce a verified-issue metric at all. Report/table/CI-gate
  messages now explicitly say `"metric_scope": "raw_detection"` / "NOT
  verified-issue" so the two can't be conflated. Neither wired mode
  (`--from-cache`, `--refresh`) carries an invocation/revision/artifact-hash
  manifest, so `provenance.freshness` is stamped `historical_cache_rescore` or
  `live_refresh_no_manifest_binding` -- deliberately never `fresh_end_to_end`.
  Tests: `testing/test_score.py::MetricScopeTest`.

## Verified and removed from the open checklist

- **W-14 implementation/default contract is present.** Cloud-primary and cloud
  reasoning are default-off (`harness/config.yaml:67-76`), and tests cover the
  local default plus opt-in behavior (`harness/test_coordinator.py:113-127`,
  `harness/test_cloud_reasoning_seam.py:20-60`). Source language describes the
  privacy trade-off rather than claiming measured cost reduction
  (`harness/coordinator.py:62-78`). No production change is requested. Any future
  comparative operational-cost or efficacy claim still requires an evaluation;
  unchanged defaults alone are not that evidence.

- **W-13 resource-bound contract is now verified.** The semaphore and method
  documentation state that the limit is scoped to one shared `AgentManager`, not
  all managers or the Ollama process (`harness/agent_manager.py:47-65`,
  `harness/agent_manager.py:437-446`), and the configuration comment uses the same
  scope (`harness/config.yaml:20-29`). The caller-level regression overlaps two
  top-level `Orchestrator.analyze()` calls, four inert jobs total, and asserts an
  exact combined peak of two (`harness/test_agent_concurrency.py:113-185`). The
  direct manager controls remain (`harness/test_agent_concurrency.py:52-111`).
