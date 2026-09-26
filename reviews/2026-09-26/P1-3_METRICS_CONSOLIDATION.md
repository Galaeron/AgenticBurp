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

`testing/strict_score.py` (the canonical exact-class scorer) was left
untouched in slice 1 and **rerouted in slice 2 (`491b982`)**. Its
per-class/micro precision, recall and F1 lines in both `score_exact_class`
and `score_evidence_supported` now call `eval_metrics.precision`/`recall`/
`f1` (per-class `on_zero=None`, micro `on_zero=0.0`; per-class recall passes
`fn[c]` directly because `support[c] == tp[c] + fn[c]` holds by construction
in both counting loops). Output is byte-identical: the golden dicts pinned in
`testing/test_strict_score_eval_metrics_reroute.py` (9 tests) were captured
from the PRE-reroute scorer via a `git stash` diff and compared field-for-
field across both scorers x no-hook/always-supported/never-supported hooks +
an empty corpus, and a load-bearing non-vacuous negative control shows a
wrong `on_zero=0.0` per-class (or swapped tp/fp) would have failed the golden
comparison. The full suite stayed green (harness 2724 OK/2 skip, pytest 38,
testing 215 OK, evaluation_integrity 42 OK, exit 0).

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

## Consolidation status (across slices 1-3)

Every code path in the repo that computed precision/recall/F1 (or cross-run
mean/variance) with its own inline arithmetic now routes through
`testing/eval_metrics.py`:

1. **Slice 1 (`31aed88`)**: `harness/ablation_harness.py` + `testing/blind-target-2/
   run_blind_eval.py` drivers. DONE.
2. **Slice 2 (`491b982`)**: `testing/strict_score.py` (canonical exact-class scorer),
   behind a byte-identical golden test. DONE.
3. **Slice 3 (`80b9050`)**: `testing/score.py` (OWASP-bucket scorer) scalar
   precision/recall/F1, behind a byte-identical golden test; `testing/nightly_precision.py`
   is covered transitively (delegates to `score.score`/`score.format_table`). DONE.

**Verified NOT to contain duplicated metric arithmetic** (grep-confirmed; they answer
different questions and are correctly left alone): `harness/eval_health.py` (stage
health), `harness/score_provenance.py` (provenance stamping), `harness/evidence_audit.py`
(evidence resolvability), `harness/coverage_summary.py` (coverage buckets),
`evaluation_integrity/` (occurrence/issue-identity diagnostics, coverage, health, audit).

## Remaining (why P1-3 stays open)

The only remaining piece of P1-3's full ambition ("one command produces the scorecard +
provenance + health + coverage summary") is a **single-command entry point that emits all
four in one run**. That needs a real driver invocation over a real corpus/model — a live
Ollama run — so it is OWNER/LIVE and out of the offline loop's scope. The offline metric-
arithmetic consolidation this item hinged on is complete.
