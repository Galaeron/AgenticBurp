# S-06 integration handoff

Reverified against integrated revision
`0dc6a523d56cd7268f6f50b46399d5dc4c998a46`. This is a production-owner
checklist, not a claim that the offline diagnostics close production contracts.

## Remaining owner checks

- **W-7/W-24 — enforce evidence at every confirmation consumer.** Structured
  proofs exist and the validator path persists exact case/proof links
  (`harness/store.py:552-630`, `harness/test_evidence.py:288-316`), but persisted
  findings still have an independent boolean (`harness/store.py:69-75`) and the
  report converts that boolean directly (`harness/report_generator.py:142`). The
  detection scorer consumes class strings only (`testing/score.py:92-137`), so it
  cannot score proof-backed issues. Smallest expectation: a finding with
  `confirmed=true` and no exact matching confirmed proof must remain an
  unverifiable claim in persistence/API/export and must not enter a metric named
  verified-issue precision or recall; an inconclusive proof must remain distinct
  from a controlled negative.

- **W-9 — preserve case-sensitive input identity through migration and
  suppression.** The current fingerprint lowercases `parameter_name`
  (`harness/store.py:30-50`), so `userId` and `userid` collide. Migration
  re-fingerprints rows (`harness/store.py:276-289`) while suppressions are keyed
  only by fingerprint (`harness/store.py:303-313`, `harness/store.py:762-807`).
  Append-only proof history itself is already covered and is not reopened
  (`harness/store.py:158-185`, `harness/test_issues.py:217-227`). Smallest
  expectation: two otherwise identical findings whose input names differ only by
  case retain distinct identities after migration; a pre-migration suppression
  still applies to its intended finding and to no collision sibling.

- **W-11 — bind saved diagnostics to an invocation.** Telemetry explicitly uses
  process-global counters (`harness/telemetry.py:1-25`) and returns an unscoped
  snapshot (`harness/telemetry.py:68-92`); `/telemetry` exposes it without an
  invocation identifier (`harness/server.py:110-126`). Existing tests reset global
  state between cases (`harness/test_telemetry.py:22-62`) but do not prove
  concurrent isolation. Smallest expectation: two overlapping inert run contexts
  record distinct diagnostic events and each saved explanation contains only its
  own run ID/events; uninstrumented sites are explicitly reported as partial.

- **W-8/W-23 — separate detection scoring from verified-issue evaluation and bind
  freshness.** `testing/score.py:2-16` defines exchange-level raw detection, and
  its only wired mode is cached fixture scoring (`testing/score.py:203-227`). It
  has no invocation/revision/artifact-hash contract and no proof resolution.
  Smallest expectation: output names raw detection precision/recall separately;
  verified-issue metrics require labels plus matching evidence; historical cache
  rescoring declares itself historical and cannot satisfy a fresh end-to-end gate.

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
