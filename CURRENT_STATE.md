# Current state — 2026-09-20

## Checkout

Branch `reconciliation-backlog`, ahead of `main`, 0 behind. The agents-subsystem
refactor and the precision & blind-control sprint (Items 1–3) are committed
(base `02de8bf`, HEAD of that batch `bc5f599`). On top, the improvement-loop items
below landed; re-verified green (full suite 2414 OK / 2 skip).

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

Full per-item Result lines (evidence tags, tests, commits) live in the backlog.
Shipped code items this session:
- **P0-1** `25a737a` EvidenceLedger wiring · **P0-2** `533928c` run-derived leg trust
  tiers · **P0-4** `0e993da` safe-default guard (`allowed_hosts→[]`) · **P1-1** `33392c9`
  injection fence neutralization · **P1-2** `e54cfb6` scope-escape · **P1-4** `1e084e1`
  operating profiles.
- **P0-5** `c7e0ce4` — `passive-only` now safety-authoritative (force-off all 10
  active knobs unconditionally) + `explicit_keys` provenance seam; fixes a P1-4 gap.
- **P0-7** `ec03060` — leg qualification requires an EXECUTED negative control;
  throttle isolated to a scoped contextvar; fixes a P0-2 gap.
- **INV-1..4 dispatch COMPLETE** (`e0ba0aa`, `40104a9`, `cc8e817`, `a6e125f`):
  evidence-tagged read-only diagnoses with filed tickets — INV-1 quarantine knob no-op
  on `run_blind_eval.py`; INV-2 PASS2 confirm path persists no ProofRecord (9/13→6/13);
  INV-3 graph `chains` computed on a pre-confirmation snapshot; INV-4 1914/641/107 is a
  driver-side un-deduped union + no timing instrumentation. Production fixes are
  separate tickets.
- **P0-6 SKIPPED (still `[ ]`):** can't land as one offline unit — needs new per-hop
  transport evidence emission + request/response storage that P0-6 gates behind P3-1
  (unstarted). Left for the owner.
- **P1-6 done (`4054135`):** `EngagementPolicy` dataclass extracts the 13 active/
  engagement toggles from `Orchestrator.__init__` — behavior-preserving (parity +
  safe-defaults tests). Single source for "what active traffic is on".
- **P1-7 done (`912df45`):** `/investigate` enforces pre-authorized scope + route/
  `base_url` host consistency before job allocation; removed the implicit `base_url`
  self-grant (was silently widening scope). +3 tests.
- **P1-8 done (`6a42cc6`):** bounded `/investigate` admission (`_MAX_RUNNING_JOBS=4`
  → 503) + terminal-job retention/eviction (900s / max 50, running never evicted,
  expired id → 404). Module constants only. +6 tests.
- **P1-9 done (`bd96d9b`):** documented the scope contract honestly (hostname-string,
  not address-pinning); corrected a P1-2 overclaim; +characterization test. Filed P1-10.
- **P3-5 (`349a51a`) + P3-4 (`6d1950c`) done:** fence defang extended to prior-context/knowledge blocks; `EvidenceLedger` bounded (5000 FIFO) + reset seam. +7 tests. (P1-10 DNS pin → owner/live below.)
- **LOOP RUNNING (2026-09-21 consensus batch):** LOOP_DONE hold lifted; the four-way
  reconciliation (`reviews/2026-09-21/`) filed the INV-1..4 production fixes as the
  **Consensus batch** in `IMPROVEMENT_BACKLOG.md`. Order (deps-corrected): RB-1 → RB-4 →
  RB-3 → RB-8 → RB-5 → RB-2 → RB-7 → RB-6 (RB-8 `Depends on RB-3`, so RB-3 precedes it).
  - **RB-1 (`f24ff8e`):** local-API CSRF/token — ephemeral token→0600 lockfile + cross-site Origin/Sec-Fetch-Site middleware; token required on mutating routes even on loopback.
  - **RB-4 (`301d848`):** engagement confirm path persists ProofRecord + VALIDATION_DECISION via shared `_persist_confirmation_proof` (INV-2; confirmed-only). +2 tests.
  - **RB-3 (`3028cf7`):** identical dependency/banner findings collapse to one issue via `issue_key` (INV-4 surfacing gap; non-dependency keys byte-identical). +6 tests.
  - **RB-8 (`dd104f9`):** blind-eval harness importable + quarantine path actually invoked; scorecard w/ controls-clean+variance+timing; +14 offline tests (INV-1). Live RUN owner-only.
  - **Next: RB-5** (INV-3 chain re-link after 2nd-order+coverage phases; deps RB-4 [x]).
  Owner/live, skip in loop: RB-1b (Java token reader), P0-3 (blind scorecard RUN, via RB-8),
  P2-2 (ablation RUN, via RB-7), P1-10 (DNS pin), RB-2b (`curated` flip, gated on RB-8's
  delta), P0-6/P3-1, P1-5, P3-2/3-3.

## Committed this session (agents refactor + sprint Items 1–3)

Five focused commits `02de8bf..bc5f599`: `4dfa89c` agents refactor
(`get_all_agent_classes()`), `50fe65a` ollama hardening, and sprint Items 1–3
(`a549d0b`, `ee54d02`, `bc5f599`). The two new `config.yaml` knobs ship safe:
`oracle.safe_passive_default: true` (zero live traffic) and
`reporting.quarantine_unverified_leads: false`; `oracle.enabled` stays `false`. The
vendored `testing/blind-test-kit/harness/config.yaml` is updated separately (bare
`yaml.safe_load`, no overlay inheritance).

Owner action required (NOT verified here): re-run PixelMart + blind helpdesk under
`fail_open_mode=curated` and `quarantine_unverified_leads=true`; record precision AND
recall deltas in this file as owner-reported.

## Verified here (2026-09-21, current HEAD)

From repo root, `.venv-rationalisation/Scripts/python.exe` (Python 3.12.14, isolated):
`-m harness.suite smoke` = **90 OK**, exit 0; `-m harness.suite full` = **green, exit 0**
(unittest **2418 OK, 2 skip** ~260s; pytest-native 13 OK; evaluation 42 OK). These are
offline/stubbed-model, owned-loopback results only — no real-model benchmark,
blind-target run, hosted CI or Java build was performed here.

## Open work and pointers

- Owner: run both corpora under curated + quarantine; record precision/recall deltas here (sprint exit criterion).
- Items 4–6 are scoped in [PRECISION_BLIND_CONTROLS_PLAN.md](reviews/2026-09-19/PRECISION_BLIND_CONTROLS_PLAN.md)
  (negative-control builders, per-endpoint baseline, coordinator model split).
  Do not start until Items 1–3 are measured.
- Concurrent branch history and implementation review remain revision-bound; do not
  restart unrelated processes based on old notes.
