# Corrected assessment of the 2026-09-23 five-app benchmark

**Dated correction, 2026-09-24.** This document supersedes specific claims in
`BENCHMARK_REPORT.md` (2026-09-23/24) without rewriting or deleting it -- the
original is preserved unchanged except for a one-line pointer added at its
top. Everything below is **historical rescoring/reconciliation** of the
already-saved artifacts, never a fresh model run: no model, target, or
network was touched to produce this document.

Generated evidence this assessment cites:
- `testing/reconcile_benchmark.py` (PR-6/BP-3) -- the reconciliation script,
  reviewed alongside this document.
- `CONFIG_DRIFT_MANIFEST.json` / `CONFIG_DRIFT_MANIFEST.md` -- machine-
  generated from the saved artifacts + `harness/config.yaml`.
- `RECONCILIATION_REPORT.json` -- machine-generated recomputed aggregates +
  every flagged contradiction, per corpus.
- Original inputs, unmodified: `{pixelmart,blindtarget2,juiceshop,dvwa,
  webgoat}_default_3x.json` (+ `.log` siblings), `pixelmart_default_3x_table
  .md`, `BENCHMARK_REPORT.md`.

Reproduce this document's numbers:
```
.venv-rationalisation/Scripts/python.exe testing/reconcile_benchmark.py
.venv-rationalisation/Scripts/python.exe -m unittest testing.test_reconcile_benchmark
```

## 1. Config-drift: this benchmark did NOT run at shipped defaults for 4 of 5 apps

`BENCHMARK_REPORT.md`'s "What this measures" section describes the whole
benchmark as running "at its **shipped default config**" while ALSO stating,
in the same paragraph, `fail_open_mode: curated` and "quarantine-leads on" --
**that is internally contradictory**: `harness/config.yaml` ships
`coordinator.fail_open_mode: "all"` (line 89) and
`reporting.quarantine_unverified_leads: false` (line 596). The saved runs'
own fingerprints settle which value each corpus actually used:

| corpus | fail_open_mode | quarantine_unverified_leads | routing_mode | num_ctx |
|---|---|---|---|---|
| PixelMart | *not recorded in the artifact* (see note below) | *not recorded* | *not recorded* | 8192 (override) |
| blind-target-2 | **DRIFT**: `curated` (shipped: `all`) | **DRIFT**: `true` (shipped: `false`) | *not recorded* | 8192 (override) |
| DVWA | **DRIFT**: `curated` (shipped: `all`) | **DRIFT**: `true` (shipped: `false`) | *not recorded* | 8192 (override) |
| WebGoat | **DRIFT**: `curated` (shipped: `all`) | **DRIFT**: `true` (shipped: `false`) | *not recorded* | 8192 (override) |
| Juice Shop | **DRIFT**: `curated` (shipped: `all`) | **DRIFT**: `true` (shipped: `false`) | *not recorded* | 8192 (override) |

(Full manifest, including `gate_low_confidence_generic` and `model`:
`CONFIG_DRIFT_MANIFEST.json`/`.md`.)

**PixelMart is the interesting exception.** Its driver,
`testing/test-target/run_ablation_live.py`, loads `harness/config.yaml`
directly (`load_base_config()`) and variant A ("current") applies **zero**
config overrides besides an in-memory `ollama.num_ctx` pin (`ablation_harness
.py`: "Only A/E are pure passthrough"). The saved PixelMart artifact records
no fail_open_mode/quarantine fingerprint at all (a genuine instrumentation
gap, now flagged), but `git blame` shows `coordinator.fail_open_mode` and
`reporting.quarantine_unverified_leads` were both last touched before this
run's 2026-09-23 22:06 timestamp -- so PixelMart's numbers most likely **did**
reflect shipped defaults, unlike the other four corpora, which explicitly
recorded the curated/quarantine-on profile. This is a documented inference
from source, not a verified artifact field -- see `CONFIG_DRIFT_MANIFEST.md`'s
`source_note`.

**Bottom line:** whatever this benchmark measured, it was not one consistent
"shipped default" configuration across all five apps. Four of the five apps
were run under a more conservative, non-default policy
(`fail_open_mode=curated`, quarantine-on) that trades recall for reduced
blast radius; only PixelMart plausibly ran at the true shipped default. Any
future comparison, marketing claim, or tuning decision must cite the actual
per-corpus fingerprint above, not "shipped default" as a blanket label.

The `num_ctx=8192` pin is **not** hidden drift -- `BENCHMARK_REPORT.md`
explicitly documents it as an intentional in-memory override for GPU
residency on the 8GB test rig, and `config.yaml` itself never pins
`num_ctx` (there is no shipped default to drift from).

## 2. Reconciled numbers and the three known contradictions

Recomputing PixelMart's `results[0]` summary directly from its own
`run_health` per-repeat rows (`testing.reconcile_benchmark.reconcile_
pixelmart`) reproduces the saved summary exactly (wall mean **1138.631s**,
precision **0.209**, recall **0.909** -- all recomputed independently and
matched to 3 decimals), so the JSON artifact is internally self-consistent.
The problems are in what the prose report says ABOUT that data:

1. **Wall-clock: the report cites one repeat's time, not the mean.**
   `run_health.wall_time_s` = `[1132.1994, 953.3544, 1330.3394]` across the 3
   repeats; the true mean is **1138.631s** (population stdev 153.971s -- also
   what `results[0].wall_time_s.mean` itself already says).
   `BENCHMARK_REPORT.md`'s results table instead cites **"~1330s"** for
   PixelMart's wall/run column, which is repeat 3's individual wall-clock
   time, not the 3-run mean. **Corrected: PixelMart's mean wall time per run
   is 1138.6s, ~14% lower than reported.**

2. **Tokens: the table's `0.0±0.0` is a broken counter, not a true zero.**
   `results[0].cost_tokens.mean = 0.0` (and the companion
   `pixelmart_default_3x_table.md` renders the same 0.0±0.0), while the SAME
   artifact's `run_health`/`model_cost_by_variant` blocks record real,
   nonzero token counts every repeat (mean **447,693** tokens, ~158 model
   calls/run). `RunMetrics.cost_tokens` is simply not wired to the real
   OllamaClient counters (`run_ablation_live.py`'s own `_run_one` docstring
   says as much). **Corrected: report PixelMart token cost as ~448k
   tokens/run (from `run_health`), and treat any `cost_tokens`-sourced "0
   tokens" reading anywhere in this benchmark as an instrumentation gap, not
   a measurement.** (The same `total_tokens_spent: 0` also appears,
   uniformly, in all four blind-eval-style corpora -- but unlike PixelMart,
   those artifacts record no alternate real number anywhere, so for them the
   honest label is `unavailable`, not "contradicted 0".)

3. **"Breaker-healthy" overstates what happened.** PixelMart's
   `run_health.breaker_failures` = `[2, 0, 2]` -- 2 of the 3 repeats hit
   circuit-breaker failures mid-run. The log's own footer ("no run was
   starved -- every row above is a clean, breaker-healthy measurement.") and
   `BENCHMARK_REPORT.md`'s top-line status ("all runs breaker-healthy (no
   starvation)") are not literally false -- `starved`/`breaker_ended_open`
   are indeed `False` for every repeat, so no run's findings degraded to the
   zero-agent floor -- but "breaker-healthy" reads as "no failures occurred,"
   which is false for 2 of 3 repeats. **Corrected: "not starved" (true) is a
   narrower and more defensible claim than "breaker-healthy" (overstated);
   two of three PixelMart repeats recorded transient circuit-breaker
   failures that recovered within the run.**

Full machine detail for all three: `RECONCILIATION_REPORT.json` →
`per_corpus.pixelmart.flags`.

A fourth, narrower check: `pixelmart_default_3x_table.md` (the standalone
rendered table) agrees byte-for-byte with `pixelmart_default_3x.json`'s
`results[0]` on precision/recall/wall -- no independent drift between those
two companion files.

## 3. Control units and recall semantics, per corpus (never conflated)

| Corpus | Control unit | Recall semantics |
|---|---|---|
| PixelMart | **Exchange** -- `testing.score.py`'s `_LABEL_CATEGORY` coarse-OWASP-category TP/TN scheme, via `run_ablation_live.py`. | any-finding / coarse-category coverage (`tp/(tp+fn)` over the 11 TP-labeled exchanges). **Not** exact-class recall, even though `testing/labels/pixelmart.labels.json` (PR-2's exact-class manifest) exists -- this 2026-09-23 run predates that wiring and never consulted it. |
| blind-target-2, DVWA, WebGoat, Juice Shop | **Two units, both reported**: `controls_clean` is per-**exchange** (any finding at all on a `confirmed_secure` exchange makes it dirty); `controls_clean_issue_level`/`dirty_controls` is per **(method+URL, vulnerability_class) issue pair** on that same exchange. | `recall_any_finding` = any finding present on a `confirmed_vuln` exchange; `recall_surfaced_only` = at least one of those findings was surfaced (not quarantined as a lead). Ground truth is the coarse `confirmed_vuln`/`confirmed_secure`/`inconclusive` scheme, not an exact-class manifest -- **no exact-class manifest exists for any of these four corpora**. |

Recomputing `recall_any_finding`/`recall_surfaced_only` directly from each
corpus's lowest-level per-exchange `results` (ground truth + findings +
surfaced-id set) reproduces `_bench_meta`'s stored numbers exactly for all
four corpora (e.g. blind-target-2: recall(any)=1.00, recall(surfaced)=0.833;
Juice Shop: 1.00/1.00; DVWA: 1.00/0.917; WebGoat: 1.00/0.667) -- these numbers
were not wrong, only mislabeled by omission of what "recall" means here.

**Strict exact-class recall is `unavailable` for all five corpora in this
benchmark**, and `testing/reconcile_benchmark.py`'s
`strict_exact_class_recall()` refuses to report a number for any of them:
- blind-target-2 / DVWA / WebGoat / Juice Shop: no exact-class manifest
  exists for any of these corpora under `testing/labels/` at all.
- PixelMart: an exact-class manifest DOES exist
  (`testing/labels/pixelmart.labels.json`, from PR-2), but this saved
  artifact carries only aggregate `tp`/`fp`/`fn` counts, not the per-finding
  `stages`/`attribution` shape `eval_adapter.rescore_saved_run` needs --
  none of the five 2026-09-23 artifacts predate PR-5's shared adapter, so
  none can be rescored that way without a fresh run. (`eval_adapter.py`'s own
  docstring already flags migrating `run_ablation_live.py`/`run_blind_eval
  .py` onto `build_eval_artifact` as a follow-on; that migration would make
  a future PixelMart run rescorable here.)

## 4. Claims removed or annotated as superseded

The following lines from `BENCHMARK_REPORT.md` are **superseded by this
assessment** (the original text is left in place; treat it as historical,
not current):

- *"Detection recall is excellent and stable: 0.91-1.00 across all five
  apps... The pipeline reliably finds the vuln."* -- **Superseded.**
  0.91-1.00 is real (reconciled above) but is coarse-category/any-finding
  recall on a non-uniform config (curated fail-open + quarantine-on for 4 of
  5 apps). It is not evidence about exact-class recall (no manifest exists
  to check that for 4 of 5 corpora), and it is not evidence about the
  shipped-default configuration for those same 4 corpora.
- *"Recall is solved; the product gap is precision/triage."* -- **Superseded
  as written.** No corpus in this benchmark measured exact-class recall,
  and 4 of 5 corpora were not run at the shipped default. "Solved" overstates
  what was measured; the precision finding (every control flagged, 4-9
  findings/exchange) stands on its own and is not weakened by this
  correction.
- *"Lead-quarantine trades recall for nothing measurable here... it isn't
  buying precision on these corpora, it's only hiding true positives."* --
  **Superseded.** This claim is drawn from runs where `quarantine_leads` was
  forced `true` (non-default) on 4 of 5 corpora -- it is evidence about the
  curated/quarantine-on profile specifically, not a general verdict on
  whether quarantine "buys nothing." A comparison against the SAME corpora
  run with quarantine off (shipped default) does not exist in this
  benchmark.
- *"Where we lose to the field, decisively: false positives... our
  precision is not in the same league"* (commercial/frontier parity claim)
  -- **Annotate, do not remove.** The precision/FP finding itself is real and
  reconciled (every control exchange flagged across all 5 apps, 0 clean, in
  both the per-exchange and per-issue control-unit views). The comparison
  TO commercial tools (Aikido/XBOW/Cascade/Claude) remains an
  apples-to-oranges cross-study comparison on the report's own admission
  ("Heavy caveat") and is not itself something this reconciliation can
  verify or refute -- treat the specific FP-rate numbers cited for other
  tools as reported by their own studies, not independently confirmed here.

Nothing about the **precision** finding (0/17 controls clean across all five
apps and both control-unit views; 4-9 findings/exchange) is weakened by this
correction -- it reconciles cleanly and is, if anything, the most robust
result in the original report.

## 5. What would need to change to re-measure honestly

1. Re-run all five corpora at ONE deliberately chosen, explicitly labeled
   config profile (either true shipped defaults, or curated/quarantine-on --
   not a mix reported as if it were one thing).
2. Seed exact-class manifests for blind-target-2/DVWA/WebGoat/Juice Shop
   (BP-0/PR-2's approach, extended past PixelMart) before claiming any
   "recall" number more specific than any-finding/coarse-category coverage.
3. Migrate `run_ablation_live.py`/`run_blind_eval.py`-style drivers onto
   `eval_adapter.build_eval_artifact` (already flagged as a follow-on in
   `eval_adapter.py`) so future saved runs carry per-finding `stages`/
   `attribution` and are rescorable by `rescore_saved_run` without a fresh
   model run.
4. Wire `RunMetrics.cost_tokens`/the blind-eval driver's token counter to
   the real `OllamaClient` counters PixelMart's `run_health` already proves
   exist, so token cost stops reading as a false zero.

---
*Historical rescoring/reconciliation only. No model, target, or network was
invoked to produce this document; every number above is either read directly
from, or recomputed offline from, the saved 2026-09-23 artifacts.*
