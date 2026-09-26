# Current state — 2026-09-26

## Checkout

Branch `reconciliation-backlog`; base HEAD before this session's work was
`c4435fc`. This session is running the improvement loop continuously: it landed
**three offline slices of P1-3** (evaluation-layer metric consolidation — now
offline-complete; only a live single-command scorecard remains, OWNER/LIVE) and
then a **P3-1 retention/expiry slice** (evidence-blob store, OFF by default). The
prior founder-review batch (FR-4/FR-3/FR-1/FR-2/FR-5/FR-6/FR-8) remains landed;
**FR-7 stays `[ ]` for the owner** (live cache hit-rate measurement). Pre-existing
README edits and untracked runtime/evaluation/worktree artifacts remain —
preserve them. Remote-main parity is not established. No push.

## This session's loop iterations (VERIFIED offline)

Selected P1-3 — Unify the evaluation layers into one driver (first eligible
ordinary-queue item: FR-* loop batch exhausted, RB-1..8 + INV-1..4 + P0 tier all
`[x]`; P1-3's only dep P0-3 is `[x]`).

- **Iter 1 `31aed88`:** new `testing/eval_metrics.py` — shared `precision`/`recall`/
  `f1` + one-pass `summarize` (mean/pstdev/pvariance/n). Routed both live-ish eval
  drivers through it: `harness/ablation_harness.py` (`_precision`/`_recall`/`_agg`)
  and `testing/blind-target-2/run_blind_eval.py` (`aggregate_variance`). Removed 3
  private metric copies + collapsed the pstdev-vs-pvariance drift. +21 caller-level/
  negative-control tests (`testing/test_eval_metrics.py`).
- **Iter 2 `491b982`:** rerouted the canonical `testing/strict_score.py` (both
  scorers' per-class + micro precision/recall/F1) onto the shared primitives.
  Byte-identical (golden captured from the pre-reroute scorer via git-stash diff);
  +9 tests (`testing/test_strict_score_eval_metrics_reroute.py`).
- **Iter 3 `80b9050`:** rerouted `testing/score.py` (OWASP-bucket scorer) scalar
  precision/recall/F1; `nightly_precision.py` covered transitively. Byte-identical;
  +6 tests. Grep-verified the remaining older layers (`eval_health`, `score_provenance`,
  `evidence_audit`, `coverage_summary`, `evaluation_integrity/`) carry no metric
  arithmetic — different questions, correctly not rerouted.
- **P1-3 stays `[ ]`:** offline metric consolidation is COMPLETE; only the live
  single-command scorecard (owner) remains. Map:
  [reviews/2026-09-26/P1-3_METRICS_CONSOLIDATION.md](reviews/2026-09-26/P1-3_METRICS_CONSOLIDATION.md).
- **Iter 4 `f45f979` (P3-1 partial):** config-gated retention/expiry for the SQLite
  `evidence_blobs` store — `store.purge_evidence_blobs_older_than` /
  `apply_retention_policy` / `apply_retention_from_config`, `config.yaml`
  `store.evidence_retention_days: 0` (OFF/keep-forever default). +4 caller-level tests.
  P3-1 stays `[ ]`: header redaction already done (FR-2/PR-9); wipe-engagement action
  + auto-wiring remain. (P3-1 is priority-elevated to P1 per the backlog note, so it
  is not blocked by the P3 efficacy gate.)

## Verification (this session)

Fresh execution with `.venv-rationalisation/Scripts/python.exe` (Python 3.12.14),
from repo root, independently rerun by the orchestrator after EACH change:
- `python -m harness.suite full` (after iter 4) → harness 2728 OK (2 skip);
  pytest-native 38 passed; testing 221 OK; evaluation_integrity 42 OK. Exit 0. Every
  `ERROR:`/`WARNING:` line in the log is a deliberate fault-injection/negative-control
  assertion; no `FAILED` line present. `config_manifest.py --check` clean.
- Iters 1-3 independent `full` runs were likewise green (harness 2724, testing 206→215→221).
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
