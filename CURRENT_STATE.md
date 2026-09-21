# Current state — 2026-09-20

## Checkout

Branch `reconciliation-backlog`, ahead of `main`, 0 behind. The agents-subsystem
refactor and the precision & blind-control sprint (Items 1–3) are committed
(base `02de8bf`, HEAD of that batch `bc5f599`). On top, improvement-loop items
**P0-1, P0-2, P0-4, P1-1, P1-2, P1-4** landed. Re-verified green (full suite 2365
OK / 2 skip). Full per-item detail with Result lines is in IMPROVEMENT_BACKLOG.md.

## Astra T02–T08 workstream — merged, not open (verified 2026-09-21)

The Astra roadmap (`reviews/review-Astra-Medium-10-09-06-30/`) T02–T08 is complete
and reconciled **below** sprint base `02de8bf`, so it is already in this branch:
W-13/W-14 (`1553178`), W-15 orchestrator split (`99c5712`), W-16 single
`TargetTransport` (`cfb4504`, `routing_gaps()` empty), on the per-oracle T08
migration + T08u websocket (`fa20bf7`); T04/T06 milestones wired
(`test_smoke_authorization_workflow.py`, `issues.py`). Full suite re-verified green
here 2026-09-21 (2365 OK / 2 skip). The `.worktrees/astra-*`, `supplemental-evidence`,
`t08-final` and `../AgenticVibe-impl` checkouts hold only **superseded drafts** —
do not resume them; the one un-merged commit, `t08-final 5aa4a1a` (T08v), was redone
as W-16.

## Improvement loop (IMPROVEMENT_BACKLOG.md)

- **P0-1 (`25a737a`):** EvidenceLedger wired into the live pipeline (append-only
  `ledger_events` table; `GET /findings/{ref}/evidence`). Instrumentation-only.
- **P0-2 (`533928c`):** run-derived leg trust tiers via the `live_verified_markers`
  override; demotion-only, OFF by default (`leg_self_test.enabled`), fail-safe.
- **P0-4 (`0e993da`):** reverted committed `server.allowed_hosts` to `[]` (live
  scope → git-ignored `config.local.yaml`); `SafeDefaultGuardTests` blocks drift.
- **P1-1 (`33392c9`):** fence-breakout neutralization for untrusted target text;
  defensive-only, caps/high-signal-slice preserved.
- **P1-2 (`e54cfb6`):** scope-escape adversarial regression coverage (IP-literal,
  DNS-rebinding, file://+gopher://, mid-hop redirect) — all already blocked; no
  production change.
- **P1-4 (`1e084e1`):** 5 named operating profiles via one opt-in `operating_profile`
  selector (ships "none" → no-op); passive-only asserted all-flags-off; safe
  defaults + SafeDefaultGuardTests intact.
- Follow-on nits filed: P3-4 (ledger singleton), P3-5 (fence prior-context).
- **Now on the INV dispatch** (IMPROVEMENT_BACKLOG.md + docs/INVESTIGATION_DISPATCH_2026-09-20.md):
  offline read-only investigations, one per iteration. (The Astra T02–T08
  workstream once tracked here as "paused" is in fact merged — see the section
  above; the codex/astra worktrees hold only superseded drafts.)
- **INV-1 done (`e0ba0aa`):** baseline reconciled; `run_blind_eval.py` sets
  `quarantine_unverified_leads` but never calls the report generator → quarantine
  knob is a no-op on that driver (blocking sub-ticket filed).
- **INV-2 done (`40104a9`):** two confirmation paths diverge —
  `orchestrator_confirm._validate_findings` persists a ProofRecord; the PASS2 graph
  loop `orchestrator_chain._apply` stamps `confirmed_by_leg` only and persists no
  proof (honesty backstop's OR-logic misses it). Historical 9/13→6/13 gap =
  {GT04,GT05,GT06} idor/cross_identity (audited read-only). 3 sequenced tickets filed.
- Backlog also gained review follow-ups P0-5/P0-6/P0-7 (safety/trust gaps in the
  loop's own P1-4/P0-1/P0-2), to address after INV-1..4. Next: INV-3 (chain funnel).

## Committed this session (agents refactor + sprint Items 1–3)

Five focused commits `02de8bf..bc5f599`: `4dfa89c` agents refactor
(`get_all_agent_classes()`), `50fe65a` ollama hardening, and sprint Items 1–3
(`a549d0b`, `ee54d02`, `bc5f599`). The two new `config.yaml` knobs ship safe:
`oracle.safe_passive_default: true` (zero live traffic) and
`reporting.quarantine_unverified_leads: false`; `oracle.enabled` stays `false`. The
vendored `testing/blind-test-kit/harness/config.yaml` is updated separately (bare
`yaml.safe_load`, no overlay inheritance).


Owner action required (these numbers are NOT verified here):
- Re-run PixelMart + blind helpdesk under `fail_open_mode=curated` and
  `quarantine_unverified_leads=true`; record precision AND recall deltas in this
  file as owner-reported.

## Verified here (2026-09-20, clean committed tree at HEAD `bc5f599`)

From the repository root, using `.venv-rationalisation/Scripts/python.exe`
(Python 3.12.14, isolated deps):

- `-m harness.suite smoke`: **90 tests OK**, exit 0.
- `-m harness.suite full`: **green, exit 0.** Unittest **2,321 tests OK, 2 skips**
  (261s); pytest-native **13 OK**; evaluation **42 OK**.

These are offline/stubbed-model, owned-loopback results only. No real-model
benchmark, blind-target run, hosted CI or Java build was performed here.

## Open work and pointers

- Owner: run both corpora under curated + quarantine; record precision/recall
  deltas in this file as owner-reported (sprint exit criterion).
- Items 4–6 are scoped in [PRECISION_BLIND_CONTROLS_PLAN.md](reviews/2026-09-19/PRECISION_BLIND_CONTROLS_PLAN.md)
  (negative-control builders, per-endpoint baseline, coordinator model split).
  Do not start until Items 1–3 are measured.
- Concurrent branch history and implementation review remain revision-bound; do not
  restart unrelated processes based on old notes.
