# Parallel coverage drive: handoff (2026-11-26)

Brief: `.test-work/parallel-drive-20261126/BATCH.md` (on main, not copied here).
Branch `worktree-agent-a42a414930e03452f` (base `0fb8cd5`). Not pushed.
ARTEX (`server/engine.go` workerLoop/claimNext, `db/exploration.go` ClaimIntent) was
read for the idea only; no code or text copied, nothing run from it.

## Change
- New key `engagement.coverage_drive_workers` (config.yaml, documented in place;
  default `1`). Strict parse in `engagement_policy._workers`: an int >= 1, no bool,
  float or quoted number. `Orchestrator.coverage_drive_workers` carries it;
  `orchestrator_chain` passes `workers=` to `build_coverage_driven` /
  `build_coverage_cases_driven` only when it is not 1, so the default call is the
  former one byte for byte (several tests patch these with the old signatures).
- `coverage_tracker._run_drive_pool(order, workers, claim, dispatch, cell_of, stats)`:
  - `workers == 1` is the plain loop: claim, then await the dispatch, as before.
  - `workers > 1`: N asyncio workers share one lazily read `_drive_order` iterator
    (the time-fair order of `dcedade9` still decides claim order; its `seconds`
    are read at each pick). `claim()` runs with no await between decision and
    claim, so a cell is claimed once and its budget reserved atomically. A worker
    takes the first startable cell of the next `workers` cells.
  - Exclusive lane (`_drive_lane`): runs alone, and nothing behind it is claimed
    first. Exclusive = `_EXCLUSIVE_LEG_CONFIRMATIONS` (race_condition, toctou,
    rate_limit, http_request_smuggling, sqlmap, write_integrity, verb_tamper,
    file_upload, csrf, client_trust, stored_xss, sequence, reset_token,
    auth_sequence, deserialization_oob, xxe, browser_xss, dom_xss, oauth, websocket),
    ANY cell on a method other than GET/HEAD/OPTIONS, and any leg in neither list
    (a new leg is exclusive until classified). Shared (may overlap, reads only):
    `_SHARED_LEG_CONFIRMATIONS` (cross_identity, jwt_forge, ssrf, ssti,
    command_injection, path_traversal, open_redirect, csp, cors, nosql,
    header_injection, the five exposure GET legs). Passive legs send nothing.
  - Per identity: at most one shared cell in flight per coverage identity.
  - Stop: leg budget or deadline at claim -> no worker claims again; started cells
    finish (as the sequential drive lets a started leg finish). Cancelling the drive
    cancels every worker; a worker that raises cancels the others and re-raises.
- `drive_coverage_legs` / `drive_coverage_cases` split into claim (budget, deadline,
  checkpoint, `attempted`) and dispatch (`_drive_leg_cell`, the former loop body).
  Case drive: a per-parameter cell holds `min(budget left, min(inputs, field_cap)+1)`
  units while it runs and hands back what it did not use; a claim that finds the
  budget held by cells in flight waits instead of stopping. One worker computes the
  same `remaining` as before (shown equal in the brief's terms: the leg never uses
  more than that bound).
- Report: `drive_pool` {workers, max_in_flight, exclusive_dispatches} only when
  workers > 1; one worker's report keys are unchanged.
- `run_context.TargetTransport` (requirement 4): sessions were mostly safe under
  asyncio (sync cookie/health updates, `health_lock` around probes). Two races fixed:
  (1) concurrent sends that each saw the same stale window queued on `health_lock`
  and each refreshed in turn (spending `max_session_refreshes`, then marking a
  freshly refreshed session stale); now a waiter that wakes after another acted
  (generation or refresh count changed) stops. (2) A send in flight across a
  refresh fed its old-credential 401/403 into the new login's health and freshness
  window; feedback now only counts when the session's generation is the one the send
  carried. Sequentially neither can change behaviour (the generation cannot change
  between a send and its own feedback).

## Deviations from the brief / what the code said
- Brief said `drive_coverage_legs` at `:755` and `drive_coverage_cases` at `:865`;
  correct. The global throttle is NOT applied by `TargetTransport`: each validator
  calls `global_throttle.acquire()` itself before its sends (the throughput fixture
  does the same). Default `throttle.max_requests_per_second: 0` = off.
- Passive-only: not added to `_PASSIVE_FORCE_OFF_KNOBS`. That profile already forces
  `engagement.coverage_drive_legs` off, so no drive runs; and the force-off writes
  `False`, which this strict key would refuse. Documented in config.yaml.
- `GlobalRequestThrottle` holds one process-wide `asyncio.Lock`; it binds to the first
  event loop that contends for it, and a later `asyncio.run` loop then errors on
  acquire. Pre-existing; one loop per server process, so not a production issue I
  could show. The throughput fixture builds a fresh throttle per drive.
- Per-identity serialisation is keyed on the CELL's identity. cross_identity also
  sends as other identities, so two identities' sessions can be in use at once by
  different cells; with the two transport fixes above I found no shared mutable
  session state that breaks, but cookie-jar ordering for one session under
  overlapping sends is not established (legs that read a cookie/CSRF token and then
  write are exclusive).
- The orchestrator's per-(endpoint, check) time share (`_endpoint_check_spent`) is a
  check-then-run bound: with workers > 1, replays of one share key that start
  together can each pass it. It stays a soft bound (it only ever held new replays).

## What bounds throughput
Default throttle off: per-send latency times sequential sends. In the pool: the number
of identities (one shared cell each) and the exclusive lane (sqlmap's cells run alone,
so a sqlmap-heavy drive gains little). With a throttle set, the throttle: the pool
does not raise the request rate above it.

Measured (`python -m harness.test_coverage_drive_pool`, this container, 4 CPUs,
Python 3.13.18; 127.0.0.1 ThreadingHTTPServer; CORS+CSP legs on 8 GET routes x 4
identities, 2 GETs per cell through the real TargetTransport; 0 error cells, all
sends answered):

| fixture | workers 1 | 2 | 4 | 8 |
|---|---|---|---|---|
| 50 ms latency, throttle off (96 cells, 192 sends) | 9.16 cells/s | 14.88 | 23.85 | 27.80 (max 4 in flight) |
| 10 ms latency, throttle 20 req/s (24 cells, 48 sends) | 16.88 | 16.89 | 16.84 | 16.83 |

## Tests
New `harness/test_coverage_drive_pool.py` (32 tests; drive tests through
`build_coverage_driven`/`build_coverage_cases_driven`, the orchestrator's entry, and
`CallerTests` through `investigate_engagement`). Each claim has a negative control:
- overlap: an `asyncio.Barrier(3)` passes with 3 workers; control 1 worker never;
  1 worker dispatches exactly in `_drive_order` order (with and without deadline);
- exclusive lane never overlaps (legs and cases); control: all-shared lanes overlap;
- one shared cell per identity; control: without the identity key they overlap;
- each cell once, statuses and case statuses equal the sequential run (legs and
  cases); control: an order offering a cell twice is seen;
- leg budget exact at 1/4/16 workers; case budget never exceeded at 1/3/8 workers x
  budgets 1/4/9/13 and spent as fully as one worker; control: a leg ignoring its
  units overspends;
- run RequestBudget through the real transport: used == server-received == 9 at
  1/4/8 workers; control: a budget that records use after the answer is fine with 1
  worker and overspends with 8;
- deadline: no leg starts after it, every worker done; control without deadline;
  cancel: all 4 in-flight legs cancelled, none started after; a raising worker stops
  the drive;
- session: concurrent stale denials refresh once; control: the former feedback
  refreshes more than once; a send racing a refresh does not count (control counts);
- caller: `coverage_drive_workers: 3` reaches the drive, legs overlap, `drive_pool`
  reported, cell states equal to the default; control default: 1 worker, no overlap;
- throughput: 4 workers > 2x cells/s at the default throttle; control: a 20 req/s
  throttle keeps 4 workers under 1.5x.
`harness/test_engagement_policy.py`: field list, parity reads and strict-parse tests.

Commands (worktree root, `/home/user/.venv-agb/bin/python`, Python 3.13.18,
`PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers`):
- `python -m unittest <49 modules>`: the modules that import coverage_tracker or
  drive coverage (38), plus test_engagement_policy, test_coverage_drive_pool,
  test_stage_reservations, test_pipeline_gate, test_run_context, test_transport_health,
  test_check_session_identities, test_ephemeral_session_identities, test_crawl_loop,
  test_config_schema, test_operating_profiles, test_experiment_final_pass,
  test_iterative_experiments, test_param_dispatch_caller, test_idle_review,
  test_retry_rounds, test_review_overlap, test_run_journal, test_result_payload_size
  (full list in the final report): **Ran 985, OK** (2026-11-27, final code).
- `python -m harness.suite smoke`: **Ran 182, OK**, exit 0.
- `python -m unittest harness.test_orchestrator_precondition`: **Ran 74, OK**.
- Earlier, separately: 14 session/transport/profile modules, Ran 263, OK.
- `git diff --check` clean. `full` not run (per instructions).
- Fixed along the way: test_stage_reservations' defect control patches
  `drive_coverage_legs` with the old signature, so `workers` is only passed when != 1.

## Unverified
- No live run (no Juice Shop/Ollama/Docker here). The gain on a real target, and
  whether Juice Shop or the validators misbehave under overlapping reads, is not
  established. Browser legs are exclusive because one driver per validator was not
  shown safe to overlap.
- `python -m harness.suite full` not run (orchestrator runs it after the merge).
- Java untouched.

## Next steps
1. Live run on the owned Juice Shop :3002 with `coverage_drive_workers: 4` in
   config.local.yaml vs 1, same budget and deadline: compare cells reached,
   `drive_pool`, 5xx/route-circuit events and session_refresh events.
2. If sqlmap dominates the drive time again, the exclusive lane is the bound; a
   separate sqlmap concurrency rule would need its own evidence.
3. Consider making `GlobalRequestThrottle` loop-safe (lazy lock per loop, like
   `ManagedSession.health_lock`).
