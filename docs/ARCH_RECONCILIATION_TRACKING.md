# ARCH reconciliation tracking — 2026-10-16

Status of the architecture defects raised in the 2026-10-15/16 reconciliation
review (previously untracked under ARCH-* identifiers in `IMPROVEMENT_BACKLOG.md`).
Fold into the backlog at a convenient point; kept here to avoid an isolated edit
to the large, concurrently-modified `IMPROVEMENT_BACKLOG.md`.

Verification: `.venv-rationalisation/Scripts/python.exe` (3.12.14), from repo root.

**Reconciled 2026-10-17 (I01).** `[x]` below means the source fix is implemented
and its helper/caller tests pass. It does not mean caller-verified, live-validated
or released. The remaining acceptance for each item has one owner in
`docs/REMAINING_IMPLEMENTATION_PLAN_2026-10-17.md`, as noted per item.

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
- **Test boundary (2026-10-17):** every test calls `run_active_probe` directly with
  a borrowed or owned context. None drives `investigate_engagement` into the probe
  or removes its forwarding. **Open → I03** (engagement-caller negative control).

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
- **Test boundary (2026-10-17):** the tests call `send_through_run` through a
  test-local `_plant` helper. They do not drive the production plant/read closures
  in `orchestrator_chain`, so they cannot alone prove the wiring. **Open → I03**
  (engagement caller, including cancellation between plant and read).

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
- **[x] Ceiling/cleanup hardening:** commit `64e09ed6` (pushed; head of PR #1).
  Explicit zero ceilings are preserved for standalone analysis and iterative
  probes. Boolean, non-integer and negative ceilings are rejected before a context
  is created. The owned context closes even when identity seeding raises. Four
  caller-level tests were added in the two test files named above.
- **Not in `64e09ed6`:** the `"owned-context-v2"` cache-namespace hunk in
  `orchestrator_detect.py` and its `test_cache_hypothesis_reuse.py` counterpart.
  They are uncommitted cache-trust work, owned by I02 (see
  `docs/I01_CANDIDATE_MANIFEST_2026-10-17.md`).
- **Open → I13 / I15:** release identity and live operational verification.

## [x] False-confirmation safeguard — caller-level regression
- See `harness/test_confirmation_class_binding_caller.py` (commit `1644dc58`).
  Verifies evidence for claim A cannot confirm claim B through the real
  registry/fallback/confirm path, with a positive control and a
  safeguard-removal mutation.
- **Test boundary (2026-10-17):** the test patches `_persist_confirmation_proof`,
  `_oracle_gate` and `store.persist_validation_submission`. It is therefore not
  storage, API or export evidence, and it does not close the global
  false-confirmation problem. **Open → I02** (real persistence and API/Markdown/SARIF
  output); the fresh adjudicated measurement belongs to I13.
