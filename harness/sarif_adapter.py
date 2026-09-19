"""Versioned SARIF (2.1.0) export/import adapter (P2.4/R09).

Export renders this harness's issue exports (issues.export_issue) as a
standard SARIF document another tool (a dashboard, a ticketing pipeline, a
different scanner's aggregator) can consume. Import reads a SARIF document
-- OUR OWN previously-exported one, or an external static/LLM tool's --
back into harness-shaped finding dicts.

The round trip preserves issue id, tool/rule name+version, source revision,
the request METHOD, the AFFECTED INPUT, the ORIGINAL severity (not just its
lossy SARIF `level` bucket), the ORIGINAL observation type, and evidence
references -- nothing supported by this adapter's own properties schema is
discarded. SARIF's `level` enum (error/warning/note/none) is coarser than
this harness's 5-value severity scale (critical/high/medium/low/info) --
`level` folds critical+high into "error" and low+info into "note" -- so a
naive re-import THROUGH `level` alone cannot recover the original value.
R09 fix: the original severity is additionally stamped into
`properties.originalSeverity` on export, and import prefers that exact value
over the lossy level-derived guess whenever it is present (an external
SARIF doc with no such property still gets the best-effort level mapping).

An imported finding is ALWAYS advisory: `confirmed`, `verification_state`,
and `oracle_verified` are unconditionally reset to the unconfirmed/candidate
defaults on import, regardless of what the source SARIF claimed (even a
result whose own properties say "observation_type: confirmed_exploit"). A
SARIF document is an external, unauthenticated claim about this harness's
own security posture the moment it crosses a process boundary; only THIS
harness's own oracle/validator pipeline can promote a finding past candidate
(see oracle_framework.py). The original claim survives as inert metadata
(`imported_observation_type`), never as operative confirmation state.
`observation_type` itself is now driven by the OWN issue export's oracle
verification state (`oracle_verified`/`verification_state`), not just the
legacy `confirmed` flag, so it distinguishes "oracle-verified",
"leg-confirmed-only", and "candidate" instead of collapsing the first two.
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

# The properties/fields this adapter's export schema actually understands and
# round-trips. `validate_sarif_shape` uses this to describe an unsupported
# document honestly instead of silently pretending a partial parse is complete.
_REQUIRED_TOP_LEVEL_KEYS = ("version", "runs")
_REQUIRED_RUN_KEYS = ("tool", "results")


def _observation_type(issue_export: dict) -> str:
    """R09: driven by the OWN issue export's oracle-verification state, not
    just the legacy `confirmed` flag -- so an oracle-verified finding and a
    merely leg-confirmed one are no longer indistinguishable on export."""
    if issue_export.get("oracle_verified") or issue_export.get("verification_state") == "verified":
        return "oracle_verified"
    if issue_export.get("confirmed"):
        return "confirmed_exploit"
    return "candidate"


def _uri_for(issue_export: dict) -> str:
    return f"{issue_export.get('host', '')}{issue_export.get('endpoint_family', '') or '/'}"


def validate_sarif_shape(sarif_doc: dict) -> list[str]:
    """Describe, honestly, which parts of `sarif_doc` this adapter's schema
    does NOT recognize/support, rather than silently ignoring them (R09: "the
    existing 'valid minimal SARIF' test checks a few keys, not the SARIF
    schema"). Returns a list of human-readable problems; an empty list means
    the document has the shape this adapter's import path expects. This is
    NOT a full SARIF 2.1.0 JSON-schema validator -- it checks the structural
    keys this adapter itself reads."""
    problems: list[str] = []
    for key in _REQUIRED_TOP_LEVEL_KEYS:
        if key not in sarif_doc:
            problems.append(f"missing required top-level key {key!r}")
    for i, run in enumerate(sarif_doc.get("runs") or []):
        for key in _REQUIRED_RUN_KEYS:
            if key not in run:
                problems.append(f"runs[{i}] missing required key {key!r}")
    return problems


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
                # R09: fields SARIF's own result schema has no first-class slot
                # for, preserved as versioned properties instead of silently
                # dropped -- method, affected input, and the ORIGINAL severity
                # (lossy through `level`'s 4-bucket enum otherwise).
                "requestMethod": exp.get("method", ""),
                "affectedInput": exp.get("affected_input", ""),
                "originalSeverity": exp.get("severity", ""),
                "propertiesSchemaVersion": "1",
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
            level = result.get("level", "warning")
            # R09: prefer the exact originalSeverity this adapter itself
            # stamped on export -- SARIF's level enum is strictly coarser
            # (5 severities -> 4 levels) and cannot losslessly recover it.
            # An external SARIF with no such property still gets the
            # best-effort level-derived mapping.
            severity = props.get("originalSeverity") or _SEVERITY_BY_LEVEL.get(level, "medium")
            findings.append({
                "vulnerability_class": result.get("ruleId", ""),
                "summary": (result.get("message") or {}).get("text", ""),
                "severity": severity,
                "url": uri,
                "method": props.get("requestMethod", ""),
                "affected_input": props.get("affectedInput", ""),
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
                "imported_level": level,
                "source_tool": tool_name,
                "source_tool_version": tool_version,
                "source_revision": props.get("sourceRevision", "") or run_revision,
            })
    return findings
