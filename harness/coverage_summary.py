"""Auditable coverage summary (P0.6, evaluation integrity).

`CoverageMatrix.summary()` already gives honest per-status counts (I2/R02:
skipped/pending/not_applicable never inflate "tested"). What it does NOT do
is separate an EXECUTED verdict (a deterministic leg actually ran --
`CellResult.validator` is set) from an INFERRED one (a conclusive status
set from an agent's finding with no leg behind it -- the exact ambiguity
CURRENT_STATE.md flagged: "336 include statuses inferred from findings, not
independently audited requests"), or say a percentage's denominator out
loud. This module adds that: every reported percentage NAMES its numerator
and denominator and is None rather than a fabricated number when the
denominator is zero (a 0/0 "100% covered" is exactly the kind of number that
made an untested surface look tested before).

Pure and hermetic: reads an existing CoverageMatrix, no I/O.
"""
from __future__ import annotations

from harness.coverage_model import CellStatus, CoverageMatrix

KIND_EXECUTED = "executed"
KIND_INFERRED = "inferred"
KIND_UNKNOWN = "unknown"

# Statuses that represent a real, conclusive verdict either way (executed or
# inferred) -- mirrors coverage_model._CONCLUSIVE_STATUSES.
_CONCLUSIVE = frozenset({
    CellStatus.CONFIRMED, CellStatus.DETECTED, CellStatus.NOT_DETECTED,
    CellStatus.CONTROLLED_NEGATIVE,
})

# Statuses that are executed but produced no usable verdict, or were denied --
# NEVER a "clean negative" (Q03/Q11's rule, mirrored here at the summary level):
# a target that errored, was skipped, or was blocked by the safety gate must
# never be read as "the check ran and found nothing".
_NOT_A_CLEAN_NEGATIVE = frozenset({
    CellStatus.SKIPPED, CellStatus.ERROR, CellStatus.INCONCLUSIVE, CellStatus.BLOCKED,
})


def _metric(numerator: int, denominator: int, kind: str) -> dict:
    pct = None if (denominator <= 0 or kind == KIND_UNKNOWN) else round(100.0 * numerator / denominator, 2)
    return {"numerator": numerator, "denominator": denominator, "kind": kind, "pct": pct}


def summarize_coverage(matrix: CoverageMatrix) -> dict:
    """Auditable coverage summary over every cell in `matrix`.

    Returns:
      {
        "total_cells": int, "not_applicable": int, "applicable": int,
        "executed": {numerator, denominator, kind, pct},   # leg actually ran
        "inferred": {numerator, denominator, kind, pct},   # agent-asserted, no leg
        "not_a_clean_negative": {"skipped": n, "error": n, "inconclusive": n,
                                  "blocked": n, "total": n},
      }

    `executed`/`inferred` are both denominated over `applicable` (total minus
    not_applicable). When `applicable` is 0 -- nothing in the matrix is even
    applicable -- both metrics report kind="unknown" and pct=None rather than
    a division-by-zero "0%" or a fabricated "100%".
    """
    not_applicable = 0
    executed_n = 0
    inferred_n = 0
    not_a_clean_negative = {"skipped": 0, "error": 0, "inconclusive": 0, "blocked": 0}

    for result in matrix.cells().values():
        status = result.status
        if status == CellStatus.NOT_APPLICABLE:
            not_applicable += 1
            continue
        if status in _CONCLUSIVE:
            if result.validator:
                executed_n += 1
            else:
                inferred_n += 1
        elif status in _NOT_A_CLEAN_NEGATIVE:
            not_a_clean_negative[status.value] += 1
        # PENDING/RUNNING: neither executed, inferred, nor a clean-negative
        # candidate -- simply not yet resolved. Counted in total/applicable only.

    total = len(matrix.cells())
    applicable = total - not_applicable
    kind = KIND_UNKNOWN if applicable <= 0 else None

    not_a_clean_negative["total"] = sum(not_a_clean_negative.values())

    return {
        "total_cells": total,
        "not_applicable": not_applicable,
        "applicable": applicable,
        "executed": _metric(executed_n, applicable, kind or KIND_EXECUTED),
        "inferred": _metric(inferred_n, applicable, kind or KIND_INFERRED),
        "not_a_clean_negative": not_a_clean_negative,
    }
