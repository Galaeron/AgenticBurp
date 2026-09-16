# Bottom-up S-06 integration log

Order requested: W-14 → W-13 → W-8/W-23 → W-11 → W-9 → W-7/W-24.

## Coordination

The T05/T06/T08 owner was notified before shared-file work began. They confirmed
that they will continue only the remaining T08 transport inventory and avoid the
S-06 production contracts. W-13 work is isolated on
`codex/supplemental-evidence`; it does not touch their `orchestrator.py` work.

## W-14

No code change. Reinspection confirmed the opt-ins and defaults are implemented
and already tested. No measured operational-cost claim is made.

## W-13

Implemented a production-caller regression that overlaps two
`Orchestrator.analyze()` invocations with two inert agents each. The combined
peak is asserted as exactly two under `max_parallel_agents: 2`; all four jobs
must complete. This distinguishes the actual guarantee from a per-exchange
limit. Documentation now states the narrow guarantee: one shared
`AgentManager` instance, including overlapping calls through it. Separate
managers and the Ollama server are outside the guarantee.

Verification:

- Python 3.12.10 plus the existing `typing_extensions` shim and `.review-deps`:
  `python.exe -m unittest test_agent_concurrency` → **5 tests OK**.
- An initial full-suite attempt under bundled Python 3.14 without the documented
  shim ran 1,819 tests and failed with 210 errors/7 failures/2 skipped. The errors
  were dominated by `cannot import name 'sentinel' from typing_extensions`; this
  is an environment failure, not accepted as a W-13 product result.
- A full-suite rerun in the correct documented environment is required after
  integrating the latest committed revision.
