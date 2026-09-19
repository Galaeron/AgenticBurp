# AgenticVibe — agent onboarding

Read this file and [CURRENT_STATE.md](CURRENT_STATE.md). Read other documents only
when the task needs them. Do not ingest archive/, reviews/, or runtime artifacts
as general onboarding.

## Product and code entry points

Burp Suite copilot: captured HTTP analysis plus a bounded engagement graph, with
Ollama-backed reasoning and deterministic validators. Safe defaults are passive.

- API/config: `harness/server.py`; packaged imports use `harness.*`.
- Orchestrator assembly: `orchestrator.py`; analysis: `orchestrator_detect.py`;
  confirmation: `orchestrator_confirm.py`; engagement: `orchestrator_chain.py`.
- Discovery/worklist: `engagement_builder.py`, `api_surface_discovery.py`,
  `role_crawl.py`, `worklist_investigator.py`.
- Transport/policy: `run_context.py` (the `TargetTransport` class), `safety_gate.py`.
- Evidence: `evidence.py`, `evidence_ledger.py`, `store.py`; validator registration:
  `validators/registry.py`; confirmation tiers: `confirmation_gate.py`.
- Burp UI: `burp-extension/` (Java). See [architecture](docs/ARCHITECTURE.md)
  for a task-directed map, not a second mandatory onboarding document.

## Non-negotiable safeguards

1. Never read `*ANSWER_KEY*` (including case variants) or a blind target's `app.py`.
   `testing/vulncorp-helpdesk/README.md` is safe; its implementation and keys are not.
2. Keep `harness/config.yaml` at safe defaults. Live toggles belong in ignored
   `harness/config.local.yaml`; never commit that file or stage flipped defaults.
3. Do not install sqlmap on the Windows host; use its Docker image. Containers
   reach host services via `host.docker.internal`.
4. Python servers use `reload=False`: restart the owned server and use a fresh
   cache for a live re-run after Python changes. Do not disrupt unrelated runs.
5. VulnCorp rebuilds its DB on startup. Use one owned instance; do not diagnose a
   stale/multiple-instance database as a product finding.
6. A Java source review is not a build. Report `gradle shadowJar` as unverified
   unless actually run with a JDK. Check service/tool availability when needed;
   old notes saying Docker/Ollama are running are not current evidence.
7. Preserve pre-existing edits and runtime artifacts. Keep commits focused and
   end commit messages with a `Co-Authored-By` trailer.

## Verification discipline

Green mocked tests have hidden a dead pipeline here. Tie claims to commands and
artifacts from this checkout; label inherited results **historical/reported**.
Helper tests do not establish production integration. A skipped test is not proof.
New pipeline behavior needs a caller-level test and a negative control; preserve
`test_pipeline_gate.py` and its defect-injection controls when consolidating tests.
Do not delete regression coverage merely because it is old or mocks a boundary.

Run from the **repository root**, with the project's test dependencies installed:

```sh
python -m harness.suite smoke
python -m harness.suite full
python -m unittest harness.test_orchestrator_precondition
```

Run full after changes before claiming a green suite. `full` includes unittest,
pytest-native and evaluation tests in separate processes; smoke is a subset.
See [testing](docs/TESTING.md) for scope, limitations, dependencies and CI tiers.
No offline tier establishes current model accuracy or blind-target recall.

## Keep onboarding bounded

Overwrite CURRENT_STATE.md with the current branch/base, verification, open work
and pointers; do not append session histories. Keep it under 100 lines and this
file under 100 lines. Put durable task-specific detail in docs/ or its existing
reference. Preserve historical evidence in archive/ or reviews/ without promoting
old completion claims. CLAUDE.md is a pointer to this file, not a duplicate.
