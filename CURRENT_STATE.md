# Current state — 2026-09-26

## Checkout

Branch `reconciliation-backlog`; base HEAD before this session was `c4435fc`. This
session ran the improvement loop continuously (Opus reviews/decides, Sonnet codes,
orchestrator independently reruns `full` and commits). It landed **P1-3 (offline
metric consolidation, 3 slices) and P3-1 (now `[x]` DONE, 4 slices + endpoint)**.
Pre-existing README edits and untracked runtime/review/worktree artifacts remain —
preserve them. No push; remote-main parity not established.

## This session's loop (all VERIFIED offline, `full` green after each)

**P1-3 — unify the evaluation layers (offline metric consolidation COMPLETE; only a
live single-command scorecard remains → OWNER/LIVE, so P1-3 stays `[ ]`):**
- `31aed88` — new `testing/eval_metrics.py` (shared precision/recall/f1 + one-pass
  mean/pstdev/pvariance `summarize`); rerouted `ablation_harness` + `run_blind_eval`.
- `491b982` — rerouted canonical `strict_score.py` (byte-identical golden test).
- `80b9050` — rerouted `score.py`; `nightly_precision` transitive. Grep-verified the
  other older layers carry no metric arithmetic (different questions).
- Map: [reviews/2026-09-26/P1-3_METRICS_CONSOLIDATION.md](reviews/2026-09-26/P1-3_METRICS_CONSOLIDATION.md).

**P3-1 — captured-data retention & redaction (`[x]` DONE):** all three recommended
capabilities delivered + tested.
- redaction already done by FR-2/PR-9; retention/expiry `f45f979` (config-gated OFF);
  `wipe_engagement` callable `81050fd`; `validation_runs` orphan cascade `4b3fab0`;
  opt-in auth-gated `DELETE /engagement/{host}/evidence` `3b83f0e`
  (`server.enable_wipe_endpoint` ships false, tracked in the NC-3 drift manifest).
- Optional non-blocking follow-on (not in the recommendation): a retention scheduler /
  retention-apply endpoint; retention is operator-callable today.

## Verification (this session)

Fresh execution with `.venv-rationalisation/Scripts/python.exe` (Python 3.12.14),
from repo root, independently rerun by the orchestrator after EACH change:
- Latest `python -m harness.suite full` → harness 2738 OK (2 skip); pytest-native 38
  passed; testing 221 OK; evaluation_integrity 42 OK. Exit 0. `config_manifest.py
  --check` clean; SafeDefaultGuardTests green. Every `ERROR:`/`WARNING:` line in the
  log is a deliberate fault-injection/negative-control assertion; no `FAILED` present.
- No live model/Docker/JDK/blind-target run; no `config.yaml` default weakened
  (new `store`/`server` keys ship at safe/OFF values); no `*ANSWER_KEY*`/blind
  `app.py` read.

## Improvement loop — dispatch status / what's next

FR-* loop batch exhausted (FR-7 owner-only). Ordinary queue: P0 all `[x]`; P1-3
offline-complete (live scorecard OWNER/LIVE); P1-5 OWNER/LIVE; P1-10 `[~]` (live
half); P2-1 (L, efficacy-gated), P2-3 (dep P1-5) not eligible; P3-1 now `[x]`; P3-2
largely non-offline; P3-3/BM-3/PR-*/NC-O*/FR-O* OWNER/LIVE; BM-2 is L/"partly
research"; ER-3/ER-5 deprioritized. The offline-eligible pool is now essentially
exhausted — the next iteration is expected to reach LOOP_DONE and trigger a
re-analysis pass to file NEW evidence-based improvements (per the standing
instruction to keep improving after the list empties).

## Benchmark honesty caveat

Saved 2026-09-25 benchmark results remain historical/reported; they measure
captured-exchange class detection, not live exploitability. No blind keys or
blind-target implementations were read. A fresh live efficacy number is unavailable
offline.

## Durable pointers

- [IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md): durable implementation record.
- [founder review](reviews/2026-09-25/founder-review/REVIEW.md);
  [testing](docs/TESTING.md): suite boundaries + dependency caveats.

Prior loop batches are historical completed implementation work, not proof of live
safety/efficacy. Tool egress, browser two-origin, real HTTPS/DNS, Java pairing/build
and independent model/target evaluation still need live evidence. Keep this file
under 100 lines.
