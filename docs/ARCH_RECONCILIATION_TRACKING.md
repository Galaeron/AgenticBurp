# ARCH reconciliation tracking — 2026-10-16

Status of the architecture defects raised in the 2026-10-15/16 reconciliation
review (previously untracked under ARCH-* identifiers in `IMPROVEMENT_BACKLOG.md`).
Fold into the backlog at a convenient point; kept here to avoid an isolated edit
to the large, concurrently-modified `IMPROVEMENT_BACKLOG.md`.

Verification: `.venv-rationalisation/Scripts/python.exe` (3.12.14), from repo root.

## [x] ARCH-1 — iterative probe escaped the owning run's accounting
- **Fixed:** commit `ef00ca4`. `investigate_engagement` forwards its `run_context`
  to `run_active_probe`; the probe routes every send through the owning run's one
  `TargetTransport` (budget / cancel / scope / TLS / evidence). A standalone probe
  (e.g. the `/active-probe` endpoint) builds ONE ceilinged context for the whole
  probe and closes it, replacing the per-send `transport_for(None, ...)` client.
- **Tests:** `harness/test_iterative_probe_run_context.py` (exhausted budget → zero
  sends; allowed send increments the shared count; one budget exhausts across sends
  — negative control; run scope governs destination; cancelled run sends nothing;
  `run_active_probe` forwarding + owned-ceiling).

## [x] ARCH-2 — second-order write bypassed the central transport
- **Fixed:** commit `d82c49d`. New `second_order.send_through_run` is the single
  send path for both the plant and the read; `_plant` no longer uses a separate
  `GatedAsyncClient(..., verify=False)`. The write now takes the run's transport
  (scope + gate + budget + evidence, under the run's TLS trust); the plant and the
  trigger-read of a pair share one stable `case_ref`.
- **Tests:** `harness/test_second_order_transport.py` (permitted write sends +
  moves budget + emits evidence; exhausted budget / out-of-scope / cancelled /
  gate-denied each prevent it; a 500 is surfaced not reported as success; the
  write moves `rc.budget` — bypass regression; `case_ref` forwarded).

## ARCH-3 — standalone-analysis gate policy + lifecycle (SPLIT)
- **[x] Policy half (resolved earlier):** gate-flag inheritance + identity seeding —
  commit `f7b968f6` (`per_run_gate_config` + `_seed_identities_from_store` at the
  standalone `analyze` path). Do not carry forward as an unfixed defect.
- **[x] Lifecycle half (resolved here):** commit `df3456a`. A thin public `analyze`
  wrapper owns the standalone run context: it sets an explicit `max_requests`
  ceiling (default 1000, overridable via `config analyze.max_requests`) and closes
  the owned context on every exit (success / early return / error) via try/finally;
  a borrowed engagement context is never created or closed there. Body unchanged in
  `_analyze_inner`.
- **Tests:** `harness/test_standalone_analysis_lifecycle.py`.

## [x] False-confirmation safeguard — caller-level regression
- See `harness/test_confirmation_class_binding_caller.py` (commit on this branch).
  Verifies evidence for claim A cannot confirm claim B through the real
  registry/fallback/confirm/persist path, with a positive control and a
  safeguard-removal mutation.
