"""Offline study accounting; never starts inference or reads a target/corpus.

Inputs contain opaque case IDs and independently adjudicated class labels only.
The plan fixes denominators before results. Missing runs remain inconclusive.
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path


def unique_ids(rows, key):
    values = [row[key] for row in rows]
    if not values or any(not isinstance(x, str) or not x for x in values) or len(values) != len(set(values)):
        raise ValueError(f"invalid or duplicate {key}")
    return set(values)


def labels(value):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value) or len(value) != len(set(value)):
        raise ValueError("labels must be unique nonempty strings")
    return set(value)


def nonnegative(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("invalid nonnegative measurement")
    return value


def summarize(plan, results):
    cases = plan["cases"]
    profiles = plan["profiles"]
    case_ids = unique_ids(cases, "case_id")
    profile_ids = unique_ids(profiles, "profile_id")
    repeats = plan["repeats"]
    if type(repeats) is not int or repeats < 3:
        raise ValueError("at least three planned fresh-cache repeats required")
    for profile in profiles:
        if any(not isinstance(profile.get(k), str) or not profile[k] for k in ("model", "config_hash", "hardware")):
            raise ValueError("model/config/hardware identity required")
    for case in cases:
        labels(case["expected"])
        if not isinstance(case.get("stratum"), str) or not case["stratum"]:
            raise ValueError("stratum required")
        if type(case.get("annotation_disagreement", False)) is not bool:
            raise ValueError("annotation disagreement must be boolean")
    by_key = {}
    caches = set()
    for row in results:
        key = (row["profile_id"], row["case_id"], row["repeat"])
        if key[0] not in profile_ids or key[1] not in case_ids or type(key[2]) is not int or not 0 <= key[2] < repeats or key in by_key:
            raise ValueError("unknown or duplicate result cell")
        if row["status"] not in {"complete", "failed", "inconclusive", "unsupported"}:
            raise ValueError("invalid result status")
        cache_id = row.get("fresh_cache_id")
        if not isinstance(cache_id, str) or not cache_id or cache_id in caches:
            raise ValueError("each attempt requires a distinct declared fresh cache")
        caches.add(cache_id)
        labels(row.get("predicted", []))
        if type(row.get("evidence_complete")) is not bool:
            raise ValueError("evidence completeness must be boolean")
        for field in ("latency_ms", "prompt_tokens", "completion_tokens", "peak_memory_bytes"):
            if row.get(field) is not None:
                nonnegative(row[field])
        by_key[key] = row
    output = {}
    for profile_id in sorted(profile_ids):
        counts = Counter(planned=len(cases) * repeats)
        strata = {}
        measurements = {field: [] for field in ("latency_ms", "prompt_tokens", "completion_tokens", "peak_memory_bytes")}
        for case in cases:
            stratum = strata.setdefault(case["stratum"], Counter())
            for repeat in range(repeats):
                stratum["planned"] += 1
                row = by_key.get((profile_id, case["case_id"], repeat))
                status = "missing" if row is None else row["status"]
                counts[status] += 1
                stratum[status] += 1
                if row is not None:
                    counts["evidence_complete"] += int(row["evidence_complete"])
                    stratum["evidence_complete"] += int(row["evidence_complete"])
                    for field in measurements:
                        if row.get(field) is not None:
                            measurements[field].append(row[field])
                expected = labels(case["expected"])
                if case.get("annotation_disagreement", False):
                    counts["annotation_disagreement"] += 1
                    counts["disputed_positive_labels"] += len(expected)
                    counts["unscored"] += 1
                    stratum["annotation_disagreement"] += 1
                    stratum["disputed_positive_labels"] += len(expected)
                    stratum["unscored"] += 1
                elif status != "complete":
                    counts["unscored"] += 1
                    counts["positive_labels_unresolved"] += len(expected)
                    stratum["unscored"] += 1
                    stratum["positive_labels_unresolved"] += len(expected)
                else:
                    predicted = labels(row.get("predicted", []))
                    for name, amount in {"tp": len(predicted & expected), "fp": len(predicted - expected),
                                         "fn": len(expected - predicted), "negative_cases": int(not expected),
                                         "tn_cases": int(not expected and not predicted)}.items():
                        counts[name] += amount
                        stratum[name] += amount
        for counter in [counts, *strata.values()]:
            for name in ("tp", "fp", "fn", "unscored", "missing", "failed", "unsupported", "inconclusive", "evidence_complete", "annotation_disagreement", "positive_labels_unresolved", "disputed_positive_labels", "negative_cases", "tn_cases"):
                counter[name] += 0
        metrics = {}
        for field, values in measurements.items():
            values.sort()
            metrics[field] = {"observed": len(values), "unknown": counts["planned"] - len(values),
                              "p50": values[math.ceil(len(values) * .5) - 1] if values else None,
                              "p95": values[math.ceil(len(values) * .95) - 1] if values else None}
        output[profile_id] = {"counts": dict(counts), "strata": strata, "measurements": metrics,
                              "quality_eligible": counts["unscored"] == 0 and counts["evidence_complete"] == counts["planned"]}
    return {"schema": "passive-study-summary/v1", "profiles": output,
            "limitation": "Declared metadata only; does not verify blinding, fresh caches, annotations, real inference, or analyst benefit."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    try:
        report = summarize(json.loads(args.plan.read_text(encoding="utf-8")), json.loads(args.results.read_text(encoding="utf-8")))
    except (ValueError, KeyError, TypeError, OSError):
        parser.exit(2, "Invalid study input; details withheld.\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
