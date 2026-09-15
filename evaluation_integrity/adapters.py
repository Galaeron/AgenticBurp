"""Read-only adapters for explicitly supplied JSON artifacts.

The normalized records contain identifiers and verdict coordinates only.  Raw
request/response bodies, credentials, and evidence excerpts are never copied to
diagnostic output.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class ArtifactError(ValueError):
    """An input is malformed or uses an unsupported schema."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    source = Path(path)
    before = source.read_bytes()
    try:
        value = json.loads(before)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"invalid JSON in {source.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactError(f"invalid root in {source.name}: expected an object")
    after = source.read_bytes()
    if before != after:
        raise ArtifactError(f"source changed while being audited: {source.name}")
    return value, {
        "path": str(source.resolve()),
        "sha256": _sha256(before),
        "bytes": len(before),
        "source_unchanged_during_read": True,
    }


def _finding(record: dict[str, Any], source: str, pointer: str) -> dict[str, Any]:
    finding_id = record.get("finding_id") or record.get("id") or f"{source}:{pointer}"
    return {
        "finding_id": str(finding_id),
        "confirmed": record.get("confirmed"),
        "validator": str(record.get("validator") or record.get("confirmation_leg") or ""),
        "proof_id": str(record.get("proof_id") or ""),
        "case_id": str(record.get("case_id") or ""),
        "issue_id": str(record.get("issue_id") or ""),
        "parameter_location": str(record.get("parameter_location") or ""),
        "parameter_name": str(record.get("parameter_name") or ""),
        "source": source,
        "pointer": pointer,
    }


def _generic(document: dict[str, Any], source: str) -> dict[str, Any]:
    allowed = {"evaluation-integrity-input/v1", "agenticvibe-evaluation-bundle/v1"}
    schema = document.get("schema_version")
    if schema not in allowed:
        raise ArtifactError(f"unsupported schema version {schema!r} in {source}")
    findings = document.get("findings", [])
    proofs = document.get("proofs", [])
    cases = document.get("cases", [])
    artifacts = document.get("artifacts", [])
    for name, records in (("findings", findings), ("proofs", proofs),
                          ("cases", cases), ("artifacts", artifacts)):
        if not isinstance(records, list) or not all(isinstance(x, dict) for x in records):
            raise ArtifactError(f"{source}: {name} must be a list of objects")
    normalized_cases = list(cases)
    known_case_ids = {str(item.get("case_id")) for item in normalized_cases if item.get("case_id")}
    for proof in proofs:
        nested = proof.get("case")
        if isinstance(nested, dict) and nested.get("case_id") and str(nested["case_id"]) not in known_case_ids:
            normalized_cases.append(nested)
            known_case_ids.add(str(nested["case_id"]))
    return {
        "adapter": "generic-evaluation-bundle/v1",
        "findings": [_finding(item, source, f"/findings/{i}") for i, item in enumerate(findings)],
        "proofs": proofs,
        "cases": normalized_cases,
        "artifacts": artifacts,
        "coverage": document.get("coverage"),
        "process": document.get("process"),
        "health_controls": document.get("health_controls"),
        "logs": document.get("logs"),
        "issues": document.get("issues"),
        "metrics": document.get("metrics"),
        "benchmark_scope": document.get("benchmark_scope"),
        "evaluation_interval": document.get("evaluation_interval"),
        "invocation_id": document.get("invocation_id"),
    }


def _maxcov(document: dict[str, Any], source: str) -> dict[str, Any]:
    analyze = document.get("analyze")
    investigate = document.get("investigate")
    if not isinstance(analyze, list) or not isinstance(investigate, dict):
        raise ArtifactError(f"{source}: malformed max-coverage result")
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add_many(records: Any, pointer: str) -> None:
        if not isinstance(records, list):
            return
        for index, item in enumerate(records):
            if not isinstance(item, dict):
                continue
            normalized = _finding(item, source, f"{pointer}/{index}")
            # A stable production finding id may recur in several report layers.
            key = (normalized["finding_id"], normalized["case_id"])
            if key not in seen:
                findings.append(normalized)
                seen.add(key)

    for index, result in enumerate(analyze):
        if isinstance(result, dict):
            add_many(result.get("findings"), f"/analyze/{index}/findings")
    outcomes = investigate.get("outcomes", [])
    if isinstance(outcomes, list):
        for index, outcome in enumerate(outcomes):
            if isinstance(outcome, dict):
                add_many(outcome.get("findings_detail"),
                         f"/investigate/outcomes/{index}/findings_detail")
                add_many(outcome.get("precondition_findings"),
                         f"/investigate/outcomes/{index}/precondition_findings")
    return {
        "adapter": "agenticvibe-maxcov-results/v1",
        "findings": findings,
        # This legacy artifact does not bundle the proof/case/artifact ledger.
        "proofs": [], "cases": [], "artifacts": [],
        "coverage": investigate.get("coverage"),
        "process": {
            "finished": True,
            "degraded": investigate.get("degraded"),
            "errors": investigate.get("errors"),
            "elapsed_seconds": document.get("elapsed_s"),
        },
        "health_controls": None,
        "logs": None,
        "issues": None,
        "metrics": None,
        "benchmark_scope": None,
        "evaluation_interval": None,
        "invocation_id": None,
    }


def _recall(document: dict[str, Any], source: str) -> dict[str, Any]:
    score = document.get("recall_score")
    if not isinstance(score, dict) or not isinstance(score.get("items"), list):
        raise ArtifactError(f"{source}: malformed recall report")
    totals = document.get("totals") if isinstance(document.get("totals"), dict) else {}
    metrics = {
        "reported_all_finding_occurrences": totals.get("all_findings"),
        "reported_confirmed_finding_occurrences": totals.get("confirmed"),
        "reported_endpoint_known_total": score.get("total"),
        "reported_endpoint_known_confirmed": score.get("confirmed"),
        "reported_endpoint_known_detected_unconfirmed": score.get("detected_unconfirmed"),
        "reported_endpoint_known_missed": score.get("missed"),
        "reported_unknown_provenance_confirmations": score.get("unknown_provenance_confirms"),
        "labelled_items": [
            {"item_id": str(item.get("id") or f"item-{i}"),
             "status": item.get("status"), "provenance": item.get("provenance")}
            for i, item in enumerate(score["items"]) if isinstance(item, dict)
        ],
        # The saved status rollup can be reproduced, but it does not include all
        # prediction/evidence inputs needed for an independent TP/FP/FN derivation.
        "confusion_inputs_complete": False,
    }
    return {
        "adapter": "agenticvibe-endpoint-known-recall/v1",
        "findings": [], "proofs": [], "cases": [], "artifacts": [],
        "coverage": None, "process": None, "health_controls": None, "logs": None,
        "issues": None, "metrics": metrics,
        "benchmark_scope": "endpoint_known_items",
        "evaluation_interval": None, "invocation_id": None,
    }


def adapt(document: dict[str, Any], source: str) -> dict[str, Any]:
    """Normalize one document through an explicit, versioned adapter."""
    if "schema_version" in document:
        return _generic(document, source)
    if isinstance(document.get("analyze"), list) and isinstance(document.get("investigate"), dict):
        return _maxcov(document, source)
    if isinstance(document.get("recall_score"), dict):
        return _recall(document, source)
    raise ArtifactError(f"unsupported artifact schema in {source}")
