"""Versioned SARIF (2.1.0) export/import adapter (P2.4).

Export renders this harness's issue exports (issues.export_issue) as a
standard SARIF document another tool (a dashboard, a ticketing pipeline, a
different scanner's aggregator) can consume. Import reads a SARIF document
-- OUR OWN previously-exported one, or an external static/LLM tool's --
back into harness-shaped finding dicts.

The round trip preserves issue id, tool/rule name+version, source revision,
the ORIGINAL observation type, and evidence references -- nothing is
discarded. But an imported finding is ALWAYS advisory: `confirmed`,
`verification_state`, and `oracle_verified` are unconditionally reset to
the unconfirmed/candidate defaults on import, regardless of what the
source SARIF claimed (even a result whose own properties say
"observation_type: confirmed_exploit"). A SARIF document is an external,
unauthenticated claim about this harness's own security posture the moment
it crosses a process boundary; only THIS harness's own oracle/validator
pipeline can promote a finding past candidate (see oracle_framework.py).
The original claim survives as inert metadata
(`imported_observation_type`), never as operative confirmation state.
"""
from __future__ import annotations

from harness import __version__ as _HARNESS_VERSION

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "AgenticBurp"

_LEVEL_BY_SEVERITY = {
    "critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note",
}
_SEVERITY_BY_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _observation_type(issue_export: dict) -> str:
    return "confirmed_exploit" if issue_export.get("confirmed") else "candidate"


def _uri_for(issue_export: dict) -> str:
    return f"{issue_export.get('host', '')}{issue_export.get('endpoint_family', '') or '/'}"


def export_issues_to_sarif(issue_exports: list[dict], *, source_revision: str = "") -> dict:
    """Render a list of issues.export_issue()-shaped dicts as a SARIF 2.1.0
    document. `source_revision` (e.g. a git sha) is stamped on every result
    so an importer can tell which code state produced it."""
    rules_by_id: dict[str, dict] = {}
    results = []
    for exp in issue_exports:
        rule_id = exp.get("vulnerability_class", "unknown")
        rules_by_id.setdefault(rule_id, {
            "id": rule_id, "name": rule_id,
            "properties": {"toolVersion": _HARNESS_VERSION},
        })
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL_BY_SEVERITY.get((exp.get("severity") or "info").lower(), "note"),
            "message": {"text": exp.get("title", "") or exp.get("evidence", "")},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": _uri_for(exp)}},
            }],
            "properties": {
                "issue_id": exp.get("issue_id", ""),
                "observation_type": _observation_type(exp),
                "evidence_refs": exp.get("proof_references", []),
                "sourceRevision": source_revision,
            },
        })
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": _HARNESS_VERSION,
                                "rules": list(rules_by_id.values())}},
            "properties": {"sourceRevision": source_revision},
            "results": results,
        }],
    }


def import_sarif_to_findings(sarif_doc: dict) -> list[dict]:
    """Read a SARIF 2.1.0 document (ours or an external tool's) back into
    harness-shaped finding dicts. ALWAYS advisory (candidate) -- see module
    docstring for why confirmation state is never trusted from an import."""
    findings: list[dict] = []
    for run in (sarif_doc.get("runs") or []):
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool_name = driver.get("name", "")
        tool_version = driver.get("version", "")
        run_revision = (run.get("properties") or {}).get("sourceRevision", "")
        for result in (run.get("results") or []):
            props = result.get("properties") or {}
            locations = result.get("locations") or []
            uri = ""
            if locations:
                uri = ((locations[0].get("physicalLocation") or {})
                       .get("artifactLocation") or {}).get("uri", "")
            findings.append({
                "vulnerability_class": result.get("ruleId", ""),
                "summary": (result.get("message") or {}).get("text", ""),
                "severity": _SEVERITY_BY_LEVEL.get(result.get("level", "warning"), "medium"),
                "url": uri,
                "basis": "imported",
                "evidence": "", "suggested_test": "", "confidence": 0.0,
                # P2.4: unconditionally advisory -- never promoted by an import,
                # regardless of what the source SARIF's own properties claim.
                "confirmed": False,
                "verification_state": "candidate",
                "oracle_verified": False,
                # Round-trip-preserved provenance metadata (inert -- read-only
                # context for a human/report, never fed back into confirmation).
                "issue_id": props.get("issue_id", ""),
                "imported_observation_type": props.get("observation_type", ""),
                "imported_evidence_refs": props.get("evidence_refs", []),
                "source_tool": tool_name,
                "source_tool_version": tool_version,
                "source_revision": props.get("sourceRevision", "") or run_revision,
            })
    return findings
