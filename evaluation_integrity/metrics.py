"""Occurrence, issue-identity, and benchmark-scope robustness diagnostics."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


def diagnose_metrics(findings: list[dict[str, Any]], evidence_audit: dict[str, Any],
                     issues: Any = None, metrics: Any = None,
                     benchmark_scope: Any = None) -> dict[str, Any]:
    warnings: list[str] = []
    occurrences = len(findings)
    issue_ids = [item.get("issue_id") for item in findings]
    if findings and all(isinstance(value, str) and value for value in issue_ids):
        unique_issues: int | None = len(set(issue_ids))
        identity_basis = "production_issue_id"
    elif isinstance(issues, list) and all(isinstance(item, dict) and item.get("issue_id") for item in issues):
        unique_issues = len({str(item["issue_id"]) for item in issues})
        identity_basis = "production_issue_records"
    else:
        unique_issues = None
        identity_basis = "unavailable"
        if findings:
            warnings.append("unique issue count is unknown because trustworthy production issue identity is incomplete")

    supported_ids = {item["finding_id"] for item in evidence_audit.get("diagnostics", [])
                     if item.get("support") == "supported"}
    proof_ids_by_finding = {item["finding_id"]: item.get("proof_id")
                            for item in evidence_audit.get("diagnostics", [])}
    distinct_supporting_proofs = {proof_ids_by_finding[item] for item in supported_ids
                                  if proof_ids_by_finding.get(item)}
    if len(supported_ids) > len(distinct_supporting_proofs):
        warnings.append("a repeated proof reference supports multiple occurrences and is counted once as proof evidence")

    exact_inputs = {(item.get("parameter_location"), item.get("parameter_name"))
                    for item in findings if item.get("parameter_name")}
    folded: dict[tuple[str, str], set[str]] = defaultdict(set)
    for location, name in exact_inputs:
        folded[(str(location), str(name).casefold())].add(str(name))
    case_collisions = [
        {"parameter_location": location, "casefolded_name": folded_name,
         "distinct_names": sorted(names)}
        for (location, folded_name), names in folded.items() if len(names) > 1
    ]

    reported = metrics if isinstance(metrics, dict) else {}
    reported_occurrences = reported.get("reported_all_finding_occurrences")
    if isinstance(reported_occurrences, int) and reported_occurrences != occurrences:
        warnings.append(
            "source-reported occurrence count differs from normalized auditable records; "
            "both are preserved and neither is silently substituted"
        )
    metric_names: list[str] = []
    if reported:
        if benchmark_scope == "endpoint_known_items":
            metric_names.append("endpoint_known_detection_recall")
            warnings.append("endpoint-known benchmark results are not whole-target recall")
        else:
            metric_names.append("reported_detection_metrics")
    metric_names.append("proof_supported_confirmation_occurrences")
    if unique_issues is not None:
        metric_names.append("production_unique_issues")

    labelled = reported.get("labelled_items")
    labels_present = isinstance(labelled, list) and bool(labelled) and all(
        isinstance(item, dict) and item.get("status") is not None for item in labelled)
    confusion_available = labels_present and reported.get("confusion_inputs_complete") is True
    if reported and not confusion_available:
        warnings.append("missing labels or complete prediction/evidence inputs prevent independently deriving TP/FP/FN conclusions")
    return {
        "finding_occurrences": occurrences,
        "normalized_auditable_finding_records": occurrences,
        "source_reported_finding_occurrences": reported_occurrences,
        "unique_issues": unique_issues,
        "unique_issue_identity_basis": identity_basis,
        "proof_supported_confirmation_occurrences": len(supported_ids),
        "distinct_supporting_proofs": len(distinct_supporting_proofs),
        "case_sensitive_input_identity": True,
        "casefold_collisions_preserved_as_distinct": case_collisions,
        "benchmark_scope": benchmark_scope,
        "metric_names": metric_names,
        "confusion_matrix_independently_derivable": confusion_available,
        "reported_metrics": reported or None,
        "warnings": warnings,
    }
