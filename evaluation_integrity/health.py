"""Offline evaluation-validity assessment from recorded benign controls."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any


def _time(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def assess_health(controls: Any, logs: Any = None, evaluation_interval: Any = None) -> dict[str, Any]:
    warnings: list[str] = []
    controls = controls if isinstance(controls, list) else []
    ordinary = [item for item in controls if isinstance(item, dict)
                and item.get("kind") == "ordinary_application"
                and item.get("service", "target") == "target"]
    security = [item for item in controls if isinstance(item, dict)
                and item.get("kind") == "security_test"]
    failed_intervals: list[dict[str, Any]] = []
    passing_intervals: list[dict[str, Any]] = []
    malformed = 0
    for item in ordinary:
        outcome = item.get("outcome")
        interval = item.get("affected_interval")
        control_id = str(item.get("control_id") or "unnamed-control")
        if outcome not in {"pass", "fail", "expected_error"}:
            malformed += 1
            continue
        record = {"control_id": control_id, "affected_interval": interval}
        if outcome == "fail":
            failed_intervals.append(record)
        else:
            passing_intervals.append(record)
    if not ordinary:
        validity = "unknown"
        warnings.append("no independently recorded benign target-health controls were supplied")
    elif malformed:
        validity = "unknown"
        warnings.append("one or more ordinary health controls have an unsupported outcome")
    elif failed_intervals:
        validity = "invalid_for_affected_intervals"
        warnings.append("failed controls qualify only their recorded affected intervals")
    else:
        validity = "valid_for_controlled_intervals"
        warnings.append("passing controls establish health only for their recorded affected intervals")
    if security:
        warnings.append("security-test responses are excluded from ordinary application-health controls")

    log_summary: dict[str, Any] | None = None
    if isinstance(logs, list):
        services: Counter[str] = Counter()
        unparseable = 0
        timestamps: list[float] = []
        http_500 = 0
        for record in logs:
            if not isinstance(record, dict) or record.get("parseable") is False:
                unparseable += 1
                continue
            services[str(record.get("service") or "unknown")] += 1
            timestamp = _time(record.get("timestamp"))
            if timestamp is not None:
                timestamps.append(timestamp)
            if record.get("status") == 500:
                http_500 += 1
        log_summary = {
            "records_by_service": dict(sorted(services.items())),
            "unparseable_records": unparseable,
            "http_500_records_observed": http_500,
            "http_500_invalidates_evaluation": False,
            "observed_time_window": ([min(timestamps), max(timestamps)] if timestamps else None),
        }
        if unparseable:
            warnings.append("unparseable log records are disclosed and excluded from service counts")
        if logs and not timestamps:
            warnings.append("log records have no parseable timestamps; time-window attribution is unavailable")
    return {
        "evaluation_validity": validity,
        "ordinary_control_count": len(ordinary),
        "security_test_control_count": len(security),
        "failed_intervals": failed_intervals,
        "passing_intervals": passing_intervals,
        "evaluation_interval": evaluation_interval,
        "log_summary": log_summary,
        "warnings": warnings,
    }
