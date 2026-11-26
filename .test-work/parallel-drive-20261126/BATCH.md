# Batch: parallel coverage drive (2026-11-26)

## Problem
`CoverageTracker.drive_coverage_legs` (`harness/coverage_tracker.py:755`) and
`drive_coverage_cases` (`:865`) send one cell at a time: each loop body is a single
`await run_leg(...)` / `await run_case(...)` and there is no gather, task group or semaphore in
`:755-1110`. r10 ended with 912 cells `budget_exhausted` (CURRENT_STATE open work 7). The
deterministic legs do not use the model, so `concurrency.max_parallel_agents: 1` (a GPU limit)
need not bound them.

## Idea (from ARTEX, not its code)
A fixed pool of workers; each claims the next open unit atomically (open -> running), runs it,
and records a terminal state. A unit is never run twice; cancellation stops every worker.

## Requirements
1. New config key for the drive's worker count (name it to match existing conventions; document
   it in `harness/config.yaml`). Default 1, and with 1 the order and results are exactly today's.
2. With N > 1: cells are claimed exactly once; the time-fair order from `_drive_order` (`:349`,
   commit `dcedade9`) decides claim order; the deadline and cancellation stop all workers; the
   run's `RequestBudget` is never overspent (it is locked; prove it under concurrency).
3. Exclusive lane. Legs whose oracle depends on timing, concurrency or target state must never
   overlap with another send: race, TOCTOU, rate limit, time-based (sleep) injection oracles,
   write/mutating legs, file upload, sqlmap. Classify from the validators; when unsure, exclusive.
4. Per-identity session state (cookie jars, CSRF refresh, `session_freshness` re-login) must not
   race. If `SessionManager`/`RoleSession` is not safe for concurrent use, serialise per identity.
5. Find what actually bounds throughput (the global request throttle may). Measure offline with
   a 127.0.0.1 fixture that adds latency: cells per second at 1 vs N workers, default throttle.
6. If the knob makes the drive send traffic faster, consider whether passive-only mode must force
   it to 1 (`config_schema._PASSIVE_FORCE_OFF_KNOBS`).

## Tests (caller-level, each with a negative control)
- N workers overlap (a barrier proves concurrency); with 1 they do not.
- Exclusive-lane legs never overlap anything (instrumented run_leg).
- Each cell runs once; budget not overspent; deadline stops all workers; final cell states equal
  the sequential run's for the same inputs.
- Keep `harness/test_pipeline_gate.py` and its defect-injection controls passing.
