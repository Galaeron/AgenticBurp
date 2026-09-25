# Current state — 2026-09-25

## Checkout

Branch `reconciliation-backlog`; base HEAD before this session's work was
`59ef1f536e3fffec23aff43656c26d4185124dbe`. This session filed a founder-review
improvement batch and landed **FR-4** (`96c17ff`) and **FR-3** (`7050d89`) plus doc updates.
Pre-existing README edits and untracked runtime/evaluation/worktree artifacts
remain — preserve them. Remote-main parity is not established.

## Current review and evidence

Current: [founder decision review](reviews/2026-09-25/founder-review/REVIEW.md).
Commands, limits and external sources:
[verification](reviews/2026-09-25/founder-review/VERIFICATION.md).
The review has 23 sections, 15 findings (F01–F15), target architecture, a P0–P3
roadmap, scorecard, ablation protocol and 30/60/90-day gates.

Fresh execution with `.venv-rationalisation/Scripts/python.exe` (Python 3.12.14):
- `full` green after FR-4+FR-3: harness 2684 OK (2 skips); pytest-native 38 passed;
  testing 177 OK; evaluation_integrity 42 OK. `config_manifest --check` clean.
- Founder-review synthetic probes reproduce browser same-origin POST permission,
  bridge-only tool-egress flags, false ledger resolvability, and discarded runner
  failures (F01/F02/F03/F04).
- Ollama version endpoint responded 0.34.3; no fresh model efficacy run.
  Docker access denied; JDK/Gradle/Burp execution unverified.

## Improvement loop — active (founder-review + FP batch)

The founder review + an offline re-score of the 2026-09-25 captured benchmark
findings produced the **FR-\*** batch in
[IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md). Loop order:
**FR-4 → FR-3 → FR-1 → FR-2 → FR-5 → FR-6 → FR-7 → FR-8**.

- **FR-4 `[x]` `96c17ff` (VERIFIED, supersedes BM-1):** fixed the generic-gate
  class-normalization gap (the model's snake_case `security_misconfiguration` and
  all `info_disclosure` variants now fold) and added an evidence-scoped catch-all
  gate — `reporting.gate_uncorroborated_catchall` (ships **false**) requires a
  confirming leg for ONLY `misconfig`/`info_disclosure`, ignoring self-reported
  confidence; a global leg requirement is deliberately NOT introduced. Mirrored in
  `report_generator` + `eval_adapter`, wired into `strict_benchmark`, tracked in
  the config-drift manifest. Offline re-score (captured findings, all 12 repeats):
  pooled P 0.236→0.283, F1 0.367→0.403, recall 0.820→0.703 (demoted → leads).
  Default-off path byte-for-byte unchanged; `config.yaml` safe defaults intact.
- **FR-3 `[x]` `7050d89` (VERIFIED):** new pure/offline `testing/pool_strict_runs.py`
  recomputes benchmark headlines from the `*_strict_3x.json` artifacts; `BENCHMARK_REPORT`
  now shows BOTH the one-repeat/per-app pool (30/101/7, P=0.229/R=0.811) and the all-12-runs
  sum (91/294/20, P=0.236/R=0.820) with the "3 repeats ≠ 3 independent apps" caveat, and
  footnotes `over-alert ×` as workload not FP-rate. Synthetic-only tests with a first-run-only
  negative control.
- **Still open (loop-consumable, offline), in order:** FR-1 (runner health-certification
  / F04), FR-2 (resolvable evidence blobs / F03), FR-5 (case-bound negative evidence /
  F09), FR-6 (credential differential / F10), FR-7 (pure-inference cache / F11), FR-8
  (authenticated reads / F12).
- **Skip-only (OWNER/LIVE), cross-referenced as FR-O\*:** F01/F02/F08 enforcement
  + two-origin/egress proof (`PR-10`/`PR-11`/`NC-O1..3`, `P1-10`), F05/F14 pairing
  + build (`PR-A`/`PR-C`/`NC-O5`), F07 ablations (`PR-B`), F06 independent
  adjudication + analyst-value (`PR-D`/`NC-O4`/`PR-E`), FR-3's live re-measure.

## Benchmark honesty caveat

Saved 2026-09-25 benchmark results remain historical/reported. Fresh arithmetic
over the 4 scored corpora × 3 repeats gives TP=91/FP=294/FN=20, P=0.236/R=0.820;
the published P=.229/R=.811 headline uses first repeats only (FR-3 fixes this).
Artifact revision `ebe461e`; model/call/token instrumentation unavailable. These
measure captured-exchange class detection, not live exploitability. No blind keys
or blind-target implementations were read.

## Durable pointers and prior work

- [IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md): durable implementation record.
- [Cycle-1 path](docs/PRINCIPAL_REVIEW_IMPLEMENTATION_PATH.md);
  [Cycle-2 review](reviews/2026-09-24/principal-review-r2/REVIEW.md).
- [Benchmark report](reviews/2026-09-25/benchmark/BENCHMARK_REPORT.md): historical,
  with aggregation/provenance/causality qualifications noted in the current review.
- [Precision path](docs/BENCHMARK_PRECISION_IMPLEMENTATION_PATH.md);
  [Testing](docs/TESTING.md): suite boundaries and dependency caveats.

Prior loop batches are historical completed implementation work, not proof of live
safety or efficacy. Tool egress, browser two-origin, real HTTPS/DNS, Java
pairing/build and independent model/target evaluation still need live evidence.
Do not revive superseded worktrees/drafts. Keep this file under 100 lines.
