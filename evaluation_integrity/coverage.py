"""Honest, layer-separated coverage summaries for saved artifacts."""
from __future__ import annotations

from typing import Any


_STATUS_ALIASES = {
    "attempted": ("attempted",),
    "skipped": ("skipped",),
    "not_applicable": ("not_applicable",),
    "blocked": ("blocked",),
    "failed": ("failed", "error"),
    "unknown": ("unknown", "pending", "running"),
    "positive_evidence": ("positive_evidence", "confirmed"),
    "controlled_negatives": ("controlled_negatives", "controlled_negative"),
    "inconclusive": ("inconclusive",),
}


def _value(source: dict[str, Any], aliases: tuple[str, ...]) -> int | None:
    for key in aliases:
        value = source.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _layer(source: dict[str, Any], total_keys: tuple[str, ...]) -> dict[str, Any]:
    total = _value(source, total_keys)
    values = {name: _value(source, aliases) for name, aliases in _STATUS_ALIASES.items()}
    warnings: list[str] = []
    for name, value in values.items():
        if value is not None and value < 0:
            warnings.append(f"{name} is negative")
    attempted = values["attempted"]
    decisive = None
    if values["positive_evidence"] is not None and values["controlled_negatives"] is not None:
        decisive = values["positive_evidence"] + values["controlled_negatives"]
        if attempted is not None and decisive > attempted:
            warnings.append("decisive evidence exceeds attempted checks")
    if total is not None:
        partition = [values[key] for key in ("attempted", "skipped", "not_applicable", "blocked", "failed")]
        if all(value is not None for value in partition) and sum(partition) > total:
            warnings.append("reported coverage categories exceed the reported total")
        if attempted is not None and attempted > total:
            warnings.append("attempted checks exceed the reported total")
    percentages: dict[str, dict[str, Any]] = {}
    for name, value in values.items():
        if value is None or total is None or total == 0:
            percent = None
        else:
            percent = round(100 * value / total, 2)
        percentages[name] = {"numerator": value, "denominator": total, "percent": percent}
    return {"reported_total": total, **values, "decisive_evidence": decisive,
            "percentages": percentages, "warnings": warnings}


def summarize_coverage(coverage: Any) -> dict[str, Any]:
    if coverage is None:
        return {"available": False, "request_level": None, "case_level": None,
                "applicability": {"declared": None, "independently_established": None},
                "warnings": ["coverage fields are absent; counts are unknown, not zero"]}
    if not isinstance(coverage, dict):
        return {"available": False, "request_level": None, "case_level": None,
                "applicability": {"declared": None, "independently_established": None},
                "warnings": ["coverage is malformed; expected an object"]}
    request = _layer(coverage, ("total_cells", "total"))
    cases = coverage.get("cases")
    case = _layer(cases, ("total_cases", "total")) if isinstance(cases, dict) else None
    warnings = list(request["warnings"])
    if case:
        warnings.extend(f"case layer: {item}" for item in case["warnings"])
    if coverage.get("process_complete") is True:
        warnings.append("finished process does not establish complete coverage")
    if request["attempted"] is not None and request["decisive_evidence"] is not None:
        if request["attempted"] > request["decisive_evidence"]:
            warnings.append("some attempted request-level checks lack decisive evidence")
    return {
        "available": True,
        "request_level": request,
        "case_level": case,
        "layers_combined": False,
        "applicability": {
            "declared": coverage.get("declared_applicable"),
            "independently_established": coverage.get("independently_established_applicable"),
        },
        "original_counts_preserved": True,
        "warnings": warnings,
    }
