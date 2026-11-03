# P1-3 slice 4 — eval_repeat routed through eval_metrics (2026-11-02)

Base: `origin/main` @ `f817f4c`. Branch `claude/p1-3-eval-driver-3a5814`. Not pushed.

## What landed
- `4db35bc` refactor: `harness/eval_repeat.py` `EvalReport._agg` (W-23 `run_repeated`
  driver) now calls `testing.eval_metrics.summarize` (lazy import, like
  `ablation_harness`). The driver keeps its own 4dp rounding, min/max, empty-run
  dict, `len>1` stdev guard and high-variance flag on the ROUNDED stdev. The unused
  `import statistics` is removed.
- New `harness/test_eval_repeat_eval_metrics_reroute.py` (5 tests, all through
  `run_repeated` -> `summary`/`passes_floor`/`compare`):
  - a golden captured from the PRE-reroute driver (varied / high-variance /
    irrational / single-run / empty);
  - a spy proving the driver calls the shared `summarize` (2 calls);
  - agreement with a direct `eval_metrics` call;
  - an unchanged `compare()` delta;
  - a negative control: variance-as-stdev breaks the golden and silently turns off the
    high-variance gate.
- Docs commit: a backlog P1-3 progress note and slice 4 plus the still-unrouted list in
  `reviews/2026-09-26/P1-3_METRICS_CONSOLIDATION.md`.

## Byte-identity evidence
`capture.py` (this folder) dumps sorted-key JSON of `summary()` + `passes_floor()`
for 7 fixtures. `golden_pre.json` (pre-edit) == `golden_post.json` (post-edit), compared
with `cmp`, on both venv 3.12 and system 3.14.

## Gates (PYTHONPATH=worktree; see gates.txt; logs are local, not committed)
| gate | 3.12 | 3.14 |
|---|---|---|
| unittest precondition + eval_repeat + reroute + test_eval_metrics (111) | OK | OK |
| `harness.suite smoke` | exit 0 | exit 0 |
| `harness.suite full` (harness 5173 OK, pytest 38, testing 451 OK/17 skip, eval_integrity 59 OK) | exit 0 | exit 0 |
| `git diff --check` | clean | clean |

## Correction to the earlier backlog claim
Slice 3 said the offline metric consolidation was "complete (grep-verified)". It was not.
Code that still does its own arithmetic is listed below; these are the next offline slices:
- `testing/pool_strict_runs.py::_prf`: P/R with zero->0.0, F1 that matches
  `eval_metrics.f1` with `on_zero=0.0`. Has `testing/test_pool_strict_runs.py`.
- `testing/reconcile_benchmark.py`: `_recompute` (fmean/pstdev with a `len>1` guard),
  inline P/R at ~L345, `pvariance` at ~L490. Has `testing/test_reconcile_benchmark.py`.
The single-command scorecard is still OWNER/LIVE.

## Hazards hit
- A bare `python -` heredoc in Git Bash hung on the WindowsApps alias. It was killed by
  its exact PID tree (`taskkill /PID 32620 /T /F`). Use the explicit venv path.

## Not touched
`ar10_scorer.py`, `tool_runner.py`, `coverage_tracker.py`, `validators/sqlmap.py`,
`injection_targets.py`, config defaults, live-v10 sources, answer keys / blind targets.
