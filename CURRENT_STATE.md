# Current state — 2026-09-26

## Checkout

Branch `reconciliation-backlog`; base HEAD before this session's work was
`c4435fc`. This session ran one role-split improvement-loop iteration and landed
the **offline first slice of P1-3** (evaluation-layer metric consolidation). The
prior founder-review batch (FR-4/FR-3/FR-1/FR-2/FR-5/FR-6/FR-8) remains landed;
**FR-7 stays `[ ]` for the owner** (live cache hit-rate measurement). Pre-existing
README edits and untracked runtime/evaluation/worktree artifacts remain —
preserve them. Remote-main parity is not established. No push.

## This session's loop iteration (VERIFIED offline)

- **Selected:** P1-3 — Unify the evaluation layers into one driver (first eligible
  ordinary-queue item: FR-* loop batch exhausted, RB-1..8 + INV-1..4 + P0 tier all
  `[x]`; P1-3's only dep P0-3 is `[x]`).
- **Landed `31aed88`:** new `testing/eval_metrics.py` — shared `precision`/`recall`/
  `f1` + one-pass `summarize` (mean/pstdev/pvariance/n). Routed both live-ish eval
  drivers through it: `harness/ablation_harness.py` (`_precision`/`_recall`/`_agg`)
  and `testing/blind-target-2/run_blind_eval.py` (`aggregate_variance`). Removed 3
  private metric copies + collapsed the pstdev-vs-pvariance drift. Byte-identical
  outputs; `strict_score.py` (canonical) left untouched, equivalence documented.
- **Tests:** +21 caller-level/negative-control tests (`testing/test_eval_metrics.py`)
  driving the real driver aggregation functions against hand-computed values.
- **P1-3 stays `[ ]` (partial):** older eval layers, the `strict_score` reroute, and
  the single-command scorecard (needs a live run) remain. Map:
  [reviews/2026-09-26/P1-3_METRICS_CONSOLIDATION.md](reviews/2026-09-26/P1-3_METRICS_CONSOLIDATION.md).

## Verification (this session)

Fresh execution with `.venv-rationalisation/Scripts/python.exe` (Python 3.12.14),
from repo root, independently rerun by the orchestrator after the change:
- `python -m harness.suite smoke` → 92 OK.
- `python -m unittest testing.test_eval_metrics -v` → 21 OK.
- `python -m harness.suite full` → harness 2724 OK (2 skip); pytest-native 38
  passed; testing 206 OK (185 baseline + 21 new); evaluation_integrity 42 OK.
  Exit 0. Every `ERROR:` line in the log is a deliberate fault-injection/
  negative-control assertion; no `FAILED` line present.
- No live model/Docker/JDK/blind-target run performed. No `config.yaml` change.
  No `*ANSWER_KEY*` / blind-target `app.py` read.

## Improvement loop — dispatch status

FR-* loop batch is exhausted for offline work (FR-7 owner-only). The ordinary
priority queue is now active. Next eligible offline candidate after P1-3's
remaining slices: revisit P1-3 follow-on (older layers / strict_score reroute) or
the next open loop-consumable P-tier item; P1-5 (Burp build), P2-1/P2-2 efficacy,
P3-3 remain OWNER/LIVE. Selection is re-derived fresh each iteration.

## Benchmark honesty caveat

Saved 2026-09-25 benchmark results remain historical/reported; they measure
captured-exchange class detection, not live exploitability. No blind keys or
blind-target implementations were read. Model/call/token instrumentation for a
fresh efficacy number is still unavailable offline.

## Durable pointers and prior work

- [IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md): durable implementation record.
- [founder decision review](reviews/2026-09-25/founder-review/REVIEW.md);
  [verification](reviews/2026-09-25/founder-review/VERIFICATION.md).
- [Precision path](docs/BENCHMARK_PRECISION_IMPLEMENTATION_PATH.md);
  [Testing](docs/TESTING.md): suite boundaries and dependency caveats.

Prior loop batches are historical completed implementation work, not proof of live
safety or efficacy. Tool egress, browser two-origin, real HTTPS/DNS, Java
pairing/build and independent model/target evaluation still need live evidence.
Do not revive superseded worktrees/drafts. Keep this file under 100 lines.
