"""pool_strict_runs.py -- pure, offline aggregation over strict exact-class
benchmark runs (FR-3 / F15, reviews/2026-09-25/founder-review/REVIEW.md).

The problem this fixes: `reviews/2026-09-25/benchmark/BENCHMARK_REPORT.md`'s
headline `tp=30, fp=101, fn=7` is a HAND-TRANSCRIBED number that happens to
equal exactly the FIRST run of each of the 4 scored corpora (webgoat, dvwa,
pixelmart, juiceshop; blind-target-2 is never scored -- no exact-class
manifest, answer key off-limits). Summing all 12 scored runs (4 corpora x 3
repeats) instead gives 91/294/20. Neither number is "the" answer on its own:

  - The FIRST-RUN (or, more generally, a MEAN-OF-RUNS) figure is the
    per-application estimate: one measurement per app, so 4 apps is 4 data
    points.
  - The ALL-RUNS-POOLED sum (91/294/20) is NOT independent evidence on top
    of that -- three repeats of the SAME corpus/config/model are not three
    independent applications (founder review Sec. 9). Summing all 12 runs'
    raw counts inflates the denominator (4 apps' worth of TP/FP/FN becomes
    12 "apps'" worth) without adding 3x the independent samples. Uncertainty
    should be clustered by application, not by run.

This module computes BOTH, plus the per-run detail, and never picks a
winner -- callers (the report, a future dashboard) must always label
whichever number they surface with its denominator ("one repeat" /
"mean of N repeats" / "sum over N runs").

Pure and offline: the core function takes already-loaded artifact dicts and
never touches the filesystem, the model, or the live orchestrator, so it is
unit-testable against small synthetic fixtures without the (untracked,
local-only) real `*_strict_3x.json` evidence. `load_artifact`/`main` are a
thin IO wrapper for ad-hoc/CLI use only.

Never reads `*ANSWER_KEY*` files or a blind target's `app.py`; never imports
the live orchestrator (`orchestrator.py`, `testing/strict_benchmark.py`,
`testing/blind-target-2/run_blind_eval.py`) and never runs a model.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

NOT_INDEPENDENT_NOTE = (
    "Repeats of the same corpus/config/model are not independent "
    "applications. The all-runs-pooled sum inflates the denominator rather "
    "than adding independent evidence; cluster uncertainty by application, "
    "not by run."
)


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    """Precision/recall/F1 DERIVED from counts -- never averaged in from
    elsewhere. Zero-safe (an empty/degenerate pool reads as 0.0, not a
    ZeroDivisionError)."""
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def _run_counts(run: dict) -> tuple[int, int, int]:
    """(tp, fp, fn) from one strict-run artifact's `metrics.exact_class.overall`
    block (the shape `testing/eval_adapter.build_eval_artifact` produces and
    `testing/strict_benchmark.run_corpus_strict` writes to each `runs[i]`)."""
    overall = run["metrics"]["exact_class"]["overall"]
    return int(overall["tp"]), int(overall["fp"]), int(overall["fn"])


def _iter_runs(artifacts: Iterable[dict]) -> Iterable[tuple[str, int, dict]]:
    """Yield (corpus, run_index, run_dict) for every run in every artifact.
    Accepts either a full `*_strict_3x.json`-shaped dict (`{"corpus": ...,
    "runs": [...]}`) or a bare `runs` list (no `corpus` key) -- the latter is
    labelled `"unknown"` so callers scoring a single corpus's raw `runs[]`
    array do not need to fabricate a wrapper."""
    for artifact in artifacts:
        corpus = artifact.get("corpus", "unknown")
        for i, run in enumerate(artifact.get("runs", [])):
            yield corpus, i, run


def pool_strict_runs(artifacts: Iterable[dict]) -> dict[str, Any]:
    """Pool strict exact-class runs from one or more `*_strict_3x.json`-shaped
    artifacts. Returns three clearly-named, differently-denominated views:

    - `per_run`: one row per individual run, in artifact/run order --
      {corpus, run_index, tp, fp, fn, precision, recall, f1}.
    - `all_runs_pooled`: {tp, fp, fn, precision, recall, f1, n_runs, note} --
      the SUM of tp/fp/fn across every run in every artifact, with P/R/F1
      DERIVED FROM THOSE SUMMED COUNTS (never averaged in). This is the
      "sum over N runs" denominator (91/294/20 over the real 2026-09-25
      artifacts). Always report it next to `mean_of_runs`, never alone --
      see `NOT_INDEPENDENT_NOTE`.
    - `mean_of_runs`: {precision, recall, f1, n_runs, note} -- the unweighted
      mean of each individual run's OWN precision/recall/f1 (not recomputed
      from summed counts). The per-application figure: repeated runs of the
      same app average out sampling noise instead of being stacked as if
      they were independent apps.

    Raises ValueError if no runs are found (an empty/malformed input must
    fail loudly, not silently report zeros as if they were real).
    """
    per_run: list[dict] = []
    for corpus, i, run in _iter_runs(artifacts):
        tp, fp, fn = _run_counts(run)
        precision, recall, f1 = _prf(tp, fp, fn)
        per_run.append({
            "corpus": corpus,
            "run_index": i,
            "tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1,
        })

    if not per_run:
        raise ValueError("pool_strict_runs: no runs found in the given artifacts")

    n = len(per_run)
    total_tp = sum(r["tp"] for r in per_run)
    total_fp = sum(r["fp"] for r in per_run)
    total_fn = sum(r["fn"] for r in per_run)
    pooled_p, pooled_r, pooled_f1 = _prf(total_tp, total_fp, total_fn)

    mean_p = sum(r["precision"] for r in per_run) / n
    mean_r = sum(r["recall"] for r in per_run) / n
    mean_f1 = sum(r["f1"] for r in per_run) / n

    return {
        "per_run": per_run,
        "all_runs_pooled": {
            "tp": total_tp, "fp": total_fp, "fn": total_fn,
            "precision": round(pooled_p, 3),
            "recall": round(pooled_r, 3),
            "f1": round(pooled_f1, 3),
            "n_runs": n,
            "note": NOT_INDEPENDENT_NOTE,
        },
        "mean_of_runs": {
            "precision": round(mean_p, 3),
            "recall": round(mean_r, 3),
            "f1": round(mean_f1, 3),
            "n_runs": n,
            "note": "Unweighted mean of each run's own P/R/F1 -- the per-application figure.",
        },
    }


def first_run_pool(artifacts: Iterable[dict]) -> dict[str, Any]:
    """Sum of tp/fp/fn using ONLY each artifact's first run (`runs[0]`).

    This reproduces the (drift-prone, hand-transcribed) headline FR-3 fixes
    -- one repeat per corpus, so the denominator is genuinely "4 apps, one
    measurement each". Exposed here as an explicit, named comparison point
    only; it is never returned as part of `pool_strict_runs`'s output so a
    caller cannot mistake it for `all_runs_pooled` by accident.
    """
    total_tp = total_fp = total_fn = 0
    for artifact in artifacts:
        runs = artifact.get("runs") or []
        if not runs:
            continue
        tp, fp, fn = _run_counts(runs[0])
        total_tp += tp
        total_fp += fp
        total_fn += fn
    precision, recall, f1 = _prf(total_tp, total_fp, total_fn)
    return {
        "tp": total_tp, "fp": total_fp, "fn": total_fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


# ---------------------------------------------------------------------------
# Thin IO wrapper -- the only place this module touches the filesystem.
# ---------------------------------------------------------------------------

def load_artifact(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Pool strict exact-class benchmark runs from *_strict_3x.json "
                     "artifacts (FR-3): both the all-runs sum and the per-application "
                     "mean, clearly labelled and never conflated.")
    ap.add_argument("artifacts", nargs="+", help="Paths to *_strict_3x.json files.")
    args = ap.parse_args(argv)
    loaded = [load_artifact(p) for p in args.artifacts]
    pooled = pool_strict_runs(loaded)
    first = first_run_pool(loaded)

    ar = pooled["all_runs_pooled"]
    mr = pooled["mean_of_runs"]
    print(f"[pool_strict_runs] {len(loaded)} artifact(s), {ar['n_runs']} runs total")
    print(f"  all_runs_pooled (sum over {ar['n_runs']} runs): "
          f"tp={ar['tp']} fp={ar['fp']} fn={ar['fn']}  "
          f"P={ar['precision']} R={ar['recall']} F1={ar['f1']}")
    print(f"  mean_of_runs (per-application): P={mr['precision']} R={mr['recall']} F1={mr['f1']}")
    print(f"  first_run_pool (one repeat, per-application counts): "
          f"tp={first['tp']} fp={first['fp']} fn={first['fn']}  "
          f"P={first['precision']} R={first['recall']} F1={first['f1']}")
    print(f"  NOTE: {NOT_INDEPENDENT_NOTE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
