"""A-F architecture ablation harness (W-22).

The 36-agent design is currently an unproven assumption -- no specialist-vs-
single-model evidence exists, and "lane discipline" once made precision WORSE.
This harness runs the same held-out corpus, budgets, and credentials across
architecture variants, repeats each run, and produces one comparison table
(TP/FP/FN, confirmed TP/FP, class recall, discovery coverage, time-to-first-
finding, cost) -- enough to decide which specialists survive.

Design: the per-run work is an INJECTABLE callable (`variant_runner`), so the
harness logic (variant definitions, repeated runs, metric aggregation with
variance, table rendering) is reproducible and testable WITHOUT a live model.
A real run plugs an orchestrator-backed runner in that scores findings against
the corpus ground truth (reuse testing/score.py's scoring), reading each
variant's config via `_ablation_variant`.

Variants that are pure config (D minus-critique) are expressed as config
transforms; those that need a different code path (B one general model, C
deterministic-only, E no graph loop, F stronger single model) set the variant
marker and are flagged needs_implementation, so the table never pretends an
unbuilt variant was measured.
"""
from __future__ import annotations

import copy
import statistics
from dataclasses import dataclass, field
from typing import Callable

MARKER = "_ablation_variant"


def _tag(cfg: dict, key: str) -> dict:
    c = copy.deepcopy(cfg or {})
    c[MARKER] = key
    return c


def _identity(cfg):
    return _tag(cfg, "A")


def _general_model(cfg):
    return _tag(cfg, "B")


def _deterministic_only(cfg):
    return _tag(cfg, "C")


def _minus_critique(cfg):
    c = _tag(cfg, "D")
    c.setdefault("critique", {})["enabled"] = False  # pure-config ablation
    return c


def _minus_graph_loop(cfg):
    return _tag(cfg, "E")


def _strong_single(cfg):
    return _tag(cfg, "F")


@dataclass(frozen=True)
class Variant:
    key: str
    name: str
    description: str
    config_transform: Callable[[dict], dict]
    # Honest: a variant that is not pure config needs a runner code path; the
    # table flags it so an unbuilt variant is never reported as measured.
    needs_implementation: bool = False


VARIANTS: tuple[Variant, ...] = (
    Variant("A", "current", "36 specialists + graph loop + critique (baseline)", _identity),
    Variant("B", "general-model", "one general model + tools, no specialists", _general_model, True),
    Variant("C", "deterministic-only", "deterministic detectors/validators, no LLM agents", _deterministic_only, True),
    Variant("D", "minus-critique", "baseline minus the adversarial critique pass", _minus_critique),
    Variant("E", "minus-graph-loop", "captured-exchange analyze() only, no investigate_engagement", _minus_graph_loop, True),
    Variant("F", "strong-single", "one stronger model + simplified orchestration", _strong_single, True),
)


@dataclass
class RunMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    confirmed_tp: int = 0
    confirmed_fp: int = 0
    class_recall: dict = field(default_factory=dict)   # canonical class -> recall
    discovery_coverage: float = 0.0                    # fraction of the surface reached
    time_to_first_finding_s: float | None = None
    cost_tokens: int = 0
    wall_time_s: float = 0.0


@dataclass
class VariantResult:
    variant: Variant
    runs: list[RunMetrics]


def _agg(values) -> dict:
    vals = [v for v in values if v is not None]
    if not vals:
        return {"mean": None, "stdev": None, "n": 0}
    return {
        "mean": round(statistics.fmean(vals), 3),
        "stdev": round(statistics.pstdev(vals), 3) if len(vals) > 1 else 0.0,
        "n": len(vals),
    }


def aggregate(result: VariantResult) -> dict:
    runs = result.runs
    return {
        "variant": result.variant.key,
        "name": result.variant.name,
        "repeats": len(runs),
        "tp": _agg([r.tp for r in runs]),
        "fp": _agg([r.fp for r in runs]),
        "fn": _agg([r.fn for r in runs]),
        "confirmed_tp": _agg([r.confirmed_tp for r in runs]),
        "confirmed_fp": _agg([r.confirmed_fp for r in runs]),
        "discovery_coverage": _agg([r.discovery_coverage for r in runs]),
        "time_to_first_finding_s": _agg([r.time_to_first_finding_s for r in runs]),
        "cost_tokens": _agg([r.cost_tokens for r in runs]),
        "wall_time_s": _agg([r.wall_time_s for r in runs]),
        "needs_implementation": result.variant.needs_implementation,
    }


def run_ablation(corpus, variant_runner: Callable[[Variant, dict, object], RunMetrics], *,
                 variants=VARIANTS, base_config: dict | None = None,
                 repeats: int = 5) -> list[VariantResult]:
    """Run each variant `repeats` times over `corpus`.

    `variant_runner(variant, config, corpus) -> RunMetrics` does the per-run work;
    injecting it keeps the harness reproducible and testable without a live model.
    Repeating each variant is required (a single run's recall swings 8/13 -> 7/13
    on variance alone), so the table reports mean +/- stdev.
    """
    base_config = base_config or {}
    results: list[VariantResult] = []
    for v in variants:
        cfg = v.config_transform(base_config)
        runs = [variant_runner(v, cfg, corpus) for _ in range(repeats)]
        results.append(VariantResult(variant=v, runs=runs))
    return results


def render_table(results: list[VariantResult]) -> str:
    rows = [aggregate(r) for r in results]

    def cell(a):
        if a["mean"] is None:
            return "-"
        return f"{a['mean']}±{a['stdev']}" if a["n"] > 1 else f"{a['mean']}"

    lines = [
        "| variant | TP | FP | FN | conf TP | conf FP | disc cov | ttff(s) | cost | notes |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        note = "needs runner impl" if r["needs_implementation"] else ""
        lines.append(
            f"| {r['variant']} {r['name']} | {cell(r['tp'])} | {cell(r['fp'])} | {cell(r['fn'])} "
            f"| {cell(r['confirmed_tp'])} | {cell(r['confirmed_fp'])} | {cell(r['discovery_coverage'])} "
            f"| {cell(r['time_to_first_finding_s'])} | {cell(r['cost_tokens'])} | {note} |")
    return "\n".join(lines)
