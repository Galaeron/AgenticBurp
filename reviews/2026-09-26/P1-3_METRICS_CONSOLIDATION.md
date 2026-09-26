# P1-3 -- unify the evaluation layers into one driver (offline first slice)

Scope note: this is the OFFLINE FIRST SLICE only. It creates one shared
scalar-metric module and routes the two live-ish eval **drivers**
(`harness/ablation_harness.py`, `testing/blind-target-2/run_blind_eval.py`)
through it. It does not touch the older layers (`testing/score.py`,
`testing/nightly_precision.py`, `harness/eval_health.py`,
`harness/score_provenance.py`, `harness/evidence_audit.py`,
`harness/coverage_summary.py`, `evaluation_integrity/`) and does not produce
a single-command scorecard -- see **Remaining slice** below.

## What is now unified

New module: `testing/eval_metrics.py`. Pure, deterministic, no I/O/model/
network. Exposes:

- `precision(tp, fp, *, on_zero=None)` -- `tp/(tp+fp)`, or `on_zero` on a
  zero denominator.
- `recall(tp, fn, *, on_zero=None)` -- `tp/(tp+fn)`, or `on_zero` on a zero
  denominator.
- `f1(p, r)` -- harmonic mean; `None` if either input is `None`; `0.0` if
  either is `0.0` (avoids a division by zero and matches
  `strict_score.score_exact_class`'s exact edge-case behavior).
- `summarize(values)` -- one-pass mean (`fmean`) / population stdev
  (`pstdev`) / population variance (`pvariance`) / `n`, filtering `None`
  first. Returns raw, unrounded floats (or all-`None` when `n == 0`) --
  every caller keeps its own rounding and its own "no values" fallback at
  the call site, which is what keeps output byte-identical.

Rewired callers (both now import `eval_metrics` lazily, matching this
codebase's existing convention of deferring `testing.*` imports inside
functions rather than at module load time -- see
`ablation_harness.run_variant_async`'s pre-existing
`from testing.score import score`):

- `harness/ablation_harness.py`: `_precision`/`_recall` now call
  `eval_metrics.precision(r.tp, r.fp, on_zero=None)` /
  `eval_metrics.recall(r.tp, r.fn, on_zero=None)` instead of their own
  inline `tp/(tp+fp)`/`tp/(tp+fn)` arithmetic. `_agg` now calls
  `eval_metrics.summarize(values)` and applies its OWN rounding
  (`round(..., 3)`) and its OWN empty-input convention
  (`{"mean": None, "stdev": None, "n": 0}`) on top of the raw result --
  unchanged from before. The now-unused `import statistics` was removed.
- `testing/blind-target-2/run_blind_eval.py`: `aggregate_variance` now
  calls `eval_metrics.summarize(values)` per metric and applies its OWN
  empty-input convention (`0.0`/`0.0`, not `None`) and its OWN
  no-rounding policy on top -- unchanged from before. The now-unused
  `import statistics` was removed (a stale comment referencing
  `statistics.pvariance` was updated to reference the shared module
  instead).

**The pstdev-vs-pvariance divergence, resolved:** before this change,
`ablation_harness._agg` computed `statistics.pstdev` and
`run_blind_eval.aggregate_variance` computed `statistics.pvariance` --
two names for dispersion across repeated runs, each hand-rolled
separately. `eval_metrics.summarize()` now computes both (`pstdev` and
`pvariance`) from the SAME one-pass call over the SAME filtered value
list, so the two drivers read off the one they each already reported
instead of maintaining two independent implementations that could drift
further apart (e.g. one gaining a bug fix, like a `None`-filtering
change, that the other never receives).

`testing/strict_score.py` (the canonical exact-class scorer) was
deliberately **left untouched**. Its per-class/micro precision, recall and
F1 lines were verified by hand to be mathematically identical to
`eval_metrics.precision`/`recall`/`f1` (per-class uses `on_zero=None`,
micro uses `on_zero=0.0`, and its F1's `(prec and rec)`-gated branch and
its micro F1's `(p+r)`-gated branch both collapse to the same
`f1(p, r)` logic above) -- but `strict_score.py`'s own test suite
(`testing/test_strict_score.py`, 79 tests incl. this driver) is the
canonical regression gate for the harness's headline metric, and routing
it through a new shared module was assessed as more risk than the
consolidation needed to buy for this slice. `eval_metrics.py`'s docstring
documents the equivalence and cites `strict_score` as the formula source
of truth, so a future pass CAN route `strict_score` through it with a
byte-identical-output test as the acceptance bar, without re-deriving the
mapping from scratch.

## Verification

- New module tests: `testing/test_eval_metrics.py` (21 tests) -- pinned
  primitive values, negative controls (swapped fp/fn changes the result;
  a varied run set has `pstdev > 0`/`pvariance > 0` while an
  identical-value run set gives exactly `0.0`), and caller-level
  agreement tests that build a synthetic `ablation_harness.VariantResult`
  / list of synthetic `run_blind_eval` scorecards, run them through each
  driver's real `aggregate()` / `aggregate_variance()`, and assert the
  result matches both hand-computed numbers and a direct
  `eval_metrics` call.
- Existing regression suites unchanged and green: `harness.suite smoke`
  (92 tests), `harness.test_ablation_harness` +
  `testing.test_blind_eval_harness` + `testing.test_strict_score` (79
  tests together), and `harness.suite full`. See the coding session's
  verbatim command output for exact counts/timestamps.

## Remaining slice (why P1-3 stays open)

This offline slice unifies exactly the two live-ish DRIVERS' scalar
metric arithmetic. Still open, deliberately out of scope here:

1. **Older layers not touched**: `testing/score.py` (coarse OWASP-bucket
   scorer), `testing/nightly_precision.py`, `harness/eval_health.py`,
   `harness/score_provenance.py`, `harness/evidence_audit.py`,
   `harness/coverage_summary.py`, `evaluation_integrity/` all still carry
   their own metric-shaped code paths (some overlapping, some genuinely
   answering a different question, e.g. coarse-bucket coverage vs.
   exact-class precision/recall) that were never in this slice's
   dependency list.
2. **`strict_score.py` still has its own (verified-equivalent, not
   shared) arithmetic** -- see above. A future pass can route it through
   `eval_metrics` behind a byte-identical-output regression test.
3. **No single-command scorecard**: P1-3's full ambition ("one command
   produces the scorecard") needs a real driver invocation over a real
   corpus/model, which this offline slice explicitly does not attempt
   (synthetic tp/fp/fn and existing artifacts only, no live Ollama/Docker
   run, per this task's non-goals).
