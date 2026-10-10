"""
eval_metrics.py -- shared scalar metric primitives and cross-run dispersion
helper (P1-3).

Before this module, three independent codebases each computed precision/
recall/F1 (and, for the two multi-run drivers, cross-run dispersion) with
their own private arithmetic:

  * ``testing/strict_score.py``'s ``score_exact_class`` /
    ``score_evidence_supported`` -- the CANONICAL scorer. Per-class
    precision/recall return ``None`` on a zero denominator; micro
    (corpus-wide) precision/recall return ``0.0`` on a zero denominator.
    F1 is the harmonic mean, with ``None`` propagated and a zero-vs-zero
    (or zero-vs-nonzero) case collapsing to ``0.0`` rather than raising.
  * ``harness/ablation_harness.py``'s ``_precision``/``_recall`` (same
    tp/(tp+fp), tp/(tp+fn) formulas, ``None`` on a zero denominator) and
    ``_agg`` (mean via ``statistics.fmean``, dispersion via
    ``statistics.pstdev``, both rounded to 3dp, filtering ``None`` values).
  * ``testing/blind-target-2/run_blind_eval.py``'s ``aggregate_variance``
    (mean via ``statistics.fmean``, dispersion via ``statistics.pvariance``,
    UNROUNDED, defaulting to ``0.0``/``0.0`` on an empty run list rather
    than ``None``).

The real drift this module targets: ablation reports population STDEV and
blind_eval reports population VARIANCE for the same "spread across
repeated runs" concept -- two names, two functions, one underlying
computation (``statistics.pvariance`` is a call away from ``pstdev``, and
both are one pass over the same filtered values). ``summarize()`` below
computes mean/pstdev/pvariance/n from ONE pass so neither caller needs its
own copy of that arithmetic; each keeps its own rounding and its own
empty-input default AT THE CALL SITE, so output stays byte-identical.

This module is pure: no I/O, no model, no network, deterministic. It does
not depend on ``testing.strict_score`` or vice versa -- ``strict_score.py``
is left untouched (see ``reviews/2026-09-26/P1-3_METRICS_CONSOLIDATION.md``
for why), but ``precision``/``recall``/``f1`` below are written to match its
existing formulas exactly, so a future caller (or a routed-through
``strict_score``) gets identical numbers.
"""
from __future__ import annotations

import statistics
from typing import Sequence

Number = float | int


def precision(tp: Number, fp: Number, *, on_zero: float | None = None) -> float | None:
    """``tp / (tp + fp)``, or ``on_zero`` when ``tp + fp == 0``.

    Callers pass ``on_zero=None`` to match ``strict_score.score_exact_class``'s
    per-class convention (undefined precision is reported as ``None``, never
    a fabricated ``0.0``) or ``on_zero=0.0`` to match its micro/overall
    convention (corpus-wide precision is always a number). Also matches
    ``ablation_harness._precision`` (``on_zero=None``).
    """
    denom = tp + fp
    return tp / denom if denom else on_zero


def recall(tp: Number, fn: Number, *, on_zero: float | None = None) -> float | None:
    """``tp / (tp + fn)``, or ``on_zero`` when ``tp + fn == 0``.

    Same zero policy as ``precision`` above -- see its docstring. Matches
    ``strict_score.score_exact_class``'s per-class recall (``tp / support``,
    where ``support == tp + fn`` by construction) and micro recall, and
    ``ablation_harness._recall``.
    """
    denom = tp + fn
    return tp / denom if denom else on_zero


def f1(p: float | None, r: float | None) -> float | None:
    """Harmonic mean of precision ``p`` and recall ``r``, matching
    ``strict_score``'s exact existing edge-case behavior:

      * either input ``None`` -> ``None`` (undefined precision or recall
        makes F1 undefined too, never a fabricated number).
      * either input ``0.0`` (but neither ``None``) -> ``0.0`` (avoids a
        division by zero when ``p + r == 0`` while staying correct for the
        ``p==0 xor r==0`` case too, since the harmonic-mean numerator is
        already zero there).
      * otherwise -> ``2 * p * r / (p + r)``.

    This single branch reproduces both ``score_exact_class``'s per-class
    formula (``(prec and rec) else (0.0 if both not None else None)``) and
    its micro formula (``2*p*r/(p+r) if (p+r) else 0.0``, where p/r are
    never ``None``) bit-for-bit -- the two only *look* different because
    the per-class one also has to handle ``None`` inputs.
    """
    if p is None or r is None:
        return None
    if not p or not r:
        return 0.0
    return 2 * p * r / (p + r)


def summarize(values: Sequence[float | None]) -> dict:
    """Mean, population stdev and population variance of `values` in one
    pass, filtering out ``None`` entries first (exactly as
    ``ablation_harness._agg`` does today).

    Returns raw, UNROUNDED floats -- callers round (or not) at the call
    site to preserve their own byte-identical output:
      * ``ablation_harness._agg`` rounds ``mean``/``pstdev`` to 3dp and
        returns ``{"mean": None, "stdev": None, "n": 0}`` when there are no
        values.
      * ``run_blind_eval.aggregate_variance`` never rounds, and falls back
        to ``0.0``/``0.0`` (not ``None``) when there are no values -- that
        empty-input default is the caller's choice, not this function's;
        when ``n == 0`` here every field is ``None`` so either caller can
        apply its own convention on top.

    ``n == 1`` -> ``pstdev == pvariance == 0.0`` falls out of the plain
    population formulas (a single point has zero deviation from its own
    mean); no special-casing is needed here for that.
    """
    vals = [v for v in values if v is not None]
    n = len(vals)
    if n == 0:
        return {"mean": None, "pstdev": None, "pvariance": None, "n": 0}
    return {
        "mean": statistics.fmean(vals),
        "pstdev": statistics.pstdev(vals),
        "pvariance": statistics.pvariance(vals),
        "n": n,
    }
