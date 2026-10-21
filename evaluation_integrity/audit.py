"""CLI for offline, read-only evaluation artifact diagnostics."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters import ArtifactError, adapt, load_json
from .coverage import summarize_coverage
from .evidence_audit import audit_findings
from .health import assess_health
from .metrics import diagnose_metrics
from .provenance import check_manifest


def _first(records: list[dict[str, Any]], key: str) -> Any:
    for record in records:
        if record.get(key) is not None:
            return record[key]
    return None


def _merged(records: list[dict[str, Any]], key: str, malformed: dict[str, Any]) -> list[Any] | None:
    """Every input's list for ``key`` concatenated, so that no input's health
    evidence is discarded because another input precedes it.  An input whose value
    is present but not a list contributes ``malformed`` (a record the health
    assessment cannot accept) instead of silently vanishing."""
    merged: list[Any] | None = None
    for record in records:
        value = record.get(key)
        if value is None:
            continue
        merged = [] if merged is None else merged
        merged.extend(value if isinstance(value, list) else [malformed])
    return merged


def _unreadable_provenance(reason: str) -> dict[str, Any]:
    return {"valid": False, "provenance": "unknown_or_mismatched", "errors": [reason],
            "warnings": [], "checked_artifacts": []}


def _manifest_provenance(manifest: str | Path, bundle_root: str | Path | None,
                         sources: list[dict[str, Any]],
                         normalized: list[dict[str, Any]]) -> dict[str, Any]:
    """Check the manifest, then bind every audited input to it.

    A manifest that is internally consistent only vouches for the artifacts it
    hashes.  An input outside that hashed set, or one that names a different
    invocation, must not borrow the manifest's provenance label."""
    path = Path(manifest)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _unreadable_provenance(f"cannot read manifest: {exc}")
    if not isinstance(document, dict):
        return _unreadable_provenance("manifest root must be an object")
    provenance = check_manifest(document, bundle_root or path.parent)

    listed = document.get("artifacts")
    declared = {item.get("sha256") for item in (listed if isinstance(listed, list) else [])
                if isinstance(item, dict) and isinstance(item.get("sha256"), str)}
    invocation = document.get("invocation_id")
    bound: list[dict[str, Any]] = []
    binding_errors: list[str] = []
    for source, record in zip(sources, normalized):
        name = Path(source["path"]).name
        covered = source["sha256"] in declared
        content_invocation = record.get("invocation_id")
        invocation_matches = None if content_invocation is None else content_invocation == invocation
        bound.append({"name": name, "sha256": source["sha256"], "covered_by_manifest": covered,
                      "invocation_id_matches": invocation_matches})
        if not covered:
            binding_errors.append(
                f"audited input {name} (sha256 {source['sha256'][:12]}) is not in the manifest's hashed artifact set")
        if invocation_matches is False:
            binding_errors.append(
                f"audited input {name} names invocation_id {content_invocation!r}, "
                f"but the manifest is for {invocation!r}")
    provenance = {**provenance, "bound_inputs": bound}
    if binding_errors:
        provenance.update(valid=False, provenance="unknown_or_mismatched",
                          errors=[*provenance["errors"], *binding_errors])
    return provenance


def build_audit(paths: list[str | Path], manifest: str | Path | None = None,
                bundle_root: str | Path | None = None) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    normalized: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in paths:
        try:
            document, source = load_json(path)
            record = adapt(document, Path(path).name)
            source["adapter"] = record["adapter"]
            sources.append(source)
            normalized.append(record)
        except (OSError, ArtifactError) as exc:
            errors.append(str(exc))
    if not normalized:
        return {
            "schema_version": "evaluation-integrity-audit/v1",
            "audit_valid": False, "errors": errors or ["no inputs supplied"],
            "sources": sources,
        }

    findings = [item for record in normalized for item in record["findings"]]
    proofs = [item for record in normalized for item in record["proofs"]]
    cases = [item for record in normalized for item in record["cases"]]
    artifacts = [item for record in normalized for item in record["artifacts"]]
    evidence = audit_findings(findings, proofs, cases, artifacts)
    coverage = summarize_coverage(_first(normalized, "coverage"))
    # Health is judged over every input: a failed control on a later input must
    # not be hidden by a passing one that happens to come first.
    health = assess_health(
        _merged(normalized, "health_controls",
                {"kind": "ordinary_application", "outcome": "malformed",
                 "control_id": "health_controls was not a list"}),
        _merged(normalized, "logs", {"parseable": False}),
        _first(normalized, "evaluation_interval"),
    )
    process = _first(normalized, "process")
    metrics_input = _first(normalized, "metrics")
    scope = _first(normalized, "benchmark_scope")
    metrics = diagnose_metrics(findings, evidence, _first(normalized, "issues"), metrics_input, scope)
    provenance = (_manifest_provenance(manifest, bundle_root, sources, normalized) if manifest else {
        "valid": False,
        "provenance": "unknown_or_mismatched",
        "errors": ["no evaluation manifest supplied"],
        "warnings": ["artifact hashes establish consistency, not independent authenticity"],
        "checked_artifacts": [],
    })
    warnings = []
    if errors:
        warnings.append("one or more supplied inputs could not be audited")
    if process and process.get("finished") is True:
        warnings.append("process completion is reported separately and does not imply complete coverage or valid evaluation")
    return {
        "schema_version": "evaluation-integrity-audit/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audit_valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "sources": sources,
        "process_outcome": process,
        "evaluation_validity": health["evaluation_validity"],
        "provenance": provenance,
        "evidence": evidence,
        "coverage": coverage,
        "health": health,
        "metrics": metrics,
    }


def markdown(report: dict[str, Any]) -> str:
    lines = ["# Evaluation-integrity audit", "",
             f"Audit input valid: **{str(report.get('audit_valid', False)).lower()}**."]
    if report.get("errors"):
        lines += ["", "## Input errors", ""] + [f"- {item}" for item in report["errors"]]
        return "\n".join(lines) + "\n"
    lines += [
        "",
        "This is an offline consistency and support audit. It is not a fresh pipeline run,",
        "does not authenticate the artifact producer, and makes no live-efficacy claim.",
        "",
        "## Provenance and health",
        "",
        f"- Provenance: `{report['provenance']['provenance']}`",
        f"- Evaluation validity: `{report['evaluation_validity']}`",
        f"- Process finished: `{(report.get('process_outcome') or {}).get('finished', 'unknown')}`",
    ]
    for item in report["provenance"].get("errors", []):
        lines.append(f"- Provenance limitation: {item}")
    for item in report["health"].get("warnings", []):
        lines.append(f"- Health limitation: {item}")
    ev = report["evidence"]
    lines += ["", "## Confirmation evidence", "",
              f"- Confirmation claims: **{ev['confirmation_claims']}**",
              f"- Named validator references: **{ev['named_validator_references']}**",
              f"- Proof references: **{ev['proof_references']}**",
              f"- Matching proof-supported confirmations: **{ev['supported_confirmations']}**"]
    reason_counts: dict[str, int] = {}
    for item in ev["diagnostics"]:
        if item["support"] == "supported" or not item["confirmation_claimed"]:
            continue
        for reason in item["reasons"]:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    if reason_counts:
        lines += ["", "Unverifiable confirmation reasons (IDs remain in the JSON diagnostic):", ""]
        lines += [f"- {count} × {reason}" for reason, count in sorted(reason_counts.items())]
    cov = report["coverage"]
    lines += ["", "## Coverage (layers are not summed)", ""]
    if not cov["available"]:
        lines.append("- Coverage: unknown (fields absent)")
    else:
        for label, layer in (("Request/cell", cov["request_level"]), ("Parameter/case", cov["case_level"])):
            if layer is None:
                lines.append(f"- {label}: unknown (layer absent)")
                continue
            lines.append(f"- {label} total: {layer['reported_total'] if layer['reported_total'] is not None else 'unknown'}")
            for name in ("attempted", "skipped", "not_applicable", "blocked", "failed", "unknown",
                         "positive_evidence", "controlled_negatives", "inconclusive"):
                p = layer["percentages"][name]
                pct = "unknown" if p["percent"] is None else f"{p['percent']}%"
                lines.append(f"  - {name}: {p['numerator'] if p['numerator'] is not None else 'unknown'} / "
                             f"{p['denominator'] if p['denominator'] is not None else 'unknown'} ({pct})")
        for item in cov.get("warnings", []):
            lines.append(f"- Coverage warning: {item}")
    met = report["metrics"]
    lines += ["", "## Counts and metric scope", "",
              f"- Normalized auditable finding records: **{met['normalized_auditable_finding_records']}**",
              f"- Unique issues: **{met['unique_issues'] if met['unique_issues'] is not None else 'unknown'}** "
              f"(`{met['unique_issue_identity_basis']}`)",
              f"- Proof-supported confirmation occurrences: **{met['proof_supported_confirmation_occurrences']}**",
              f"- Benchmark scope: `{met['benchmark_scope'] or 'unknown'}`"]
    reported = met.get("reported_metrics") or {}
    if reported:
        lines.append(f"- Original reported finding occurrences: **{reported.get('reported_all_finding_occurrences', 'unknown')}**")
        lines.append(f"- Original reported confirmed occurrences: **{reported.get('reported_confirmed_finding_occurrences', 'unknown')}**")
        lines.append(f"- Original reported endpoint-known result: **{reported.get('reported_endpoint_known_confirmed', 'unknown')} / "
                     f"{reported.get('reported_endpoint_known_total', 'unknown')}**")
    for item in met["warnings"]:
        lines.append(f"- Metric limitation: {item}")
    lines += ["", "## Source consistency", ""]
    for source in report["sources"]:
        lines.append(f"- `{Path(source['path']).name}`: `{source['adapter']}`, SHA-256 `{source['sha256']}`, "
                     f"unchanged during read: `{str(source['source_unchanged_during_read']).lower()}`")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit saved AgenticVibe evaluation artifacts offline")
    parser.add_argument("--input", action="append", required=True, help="explicit JSON artifact (repeatable)")
    parser.add_argument("--manifest", help="optional evaluation manifest")
    parser.add_argument("--bundle-root", help="root for manifest artifact paths")
    parser.add_argument("--json", dest="json_output", help="write machine-readable diagnostics")
    parser.add_argument("--markdown", dest="markdown_output", help="write Markdown diagnostics")
    args = parser.parse_args(argv)
    report = build_audit(args.input, args.manifest, args.bundle_root)
    rendered = markdown(report)
    if args.json_output:
        Path(args.json_output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_output:
        Path(args.markdown_output).write_text(rendered, encoding="utf-8")
    if not args.json_output and not args.markdown_output:
        sys.stdout.write(rendered)
    return 0 if report.get("audit_valid") else 2


if __name__ == "__main__":
    raise SystemExit(main())
