"""Hermetic tests for the SARIF export/import adapter (P2.4). No network, no
live tool -- exercises the round trip against issues.export_issue()'s real
shape (not a hand-rolled stand-in)."""
from __future__ import annotations

import unittest

from harness import issues, sarif_adapter
from harness import __version__ as _HARNESS_VERSION


def _finding(url, vc, *, confirmed=False, case_id="", proof_id="", pname="id"):
    return {"url": url, "vulnerability_class": vc, "method": "GET",
            "parameter_location": "query", "parameter_name": pname, "confirmed": confirmed,
            "severity": "high", "confidence": 0.8, "case_id": case_id, "proof_id": proof_id,
            "principal_id": "", "evidence": "db error surfaced", "summary": "SQLi in id"}


class TestSarifRoundTrip(unittest.TestCase):
    def _export_one_issue(self, confirmed: bool, pname: str = "id") -> dict:
        grouped = issues.group_findings_into_issues(
            [_finding("https://x.test/api/items", "sqli", confirmed=confirmed,
                     case_id="case-1", proof_id="proof-1", pname=pname)])
        self.assertEqual(len(grouped), 1)
        return issues.export_issue(grouped[0])

    def test_round_trip_preserves_issue_id_tool_version_and_revision(self):
        exp = self._export_one_issue(confirmed=True)
        sarif_doc = sarif_adapter.export_issues_to_sarif([exp], source_revision="abc123def")
        imported = sarif_adapter.import_sarif_to_findings(sarif_doc)
        self.assertEqual(len(imported), 1)
        f = imported[0]
        self.assertEqual(f["issue_id"], exp["issue_id"])
        self.assertEqual(f["source_tool"], sarif_adapter.TOOL_NAME)
        self.assertEqual(f["source_tool_version"], _HARNESS_VERSION)
        self.assertEqual(f["source_revision"], "abc123def")

    def test_round_trip_preserves_observation_type_as_metadata(self):
        confirmed_exp = self._export_one_issue(confirmed=True, pname="id")
        candidate_exp = self._export_one_issue(confirmed=False, pname="other_id")
        sarif_doc = sarif_adapter.export_issues_to_sarif([confirmed_exp, candidate_exp])
        imported = sarif_adapter.import_sarif_to_findings(sarif_doc)
        types = {f["issue_id"]: f["imported_observation_type"] for f in imported}
        self.assertEqual(types[confirmed_exp["issue_id"]], "confirmed_exploit")
        self.assertEqual(types[candidate_exp["issue_id"]], "candidate")

    def test_round_trip_preserves_evidence_refs(self):
        exp = self._export_one_issue(confirmed=True)
        self.assertTrue(exp["proof_references"])  # sanity: the fixture actually has refs
        sarif_doc = sarif_adapter.export_issues_to_sarif([exp])
        imported = sarif_adapter.import_sarif_to_findings(sarif_doc)
        self.assertEqual(imported[0]["imported_evidence_refs"], exp["proof_references"])

    def test_round_trip_is_a_valid_minimal_sarif_document(self):
        exp = self._export_one_issue(confirmed=True)
        sarif_doc = sarif_adapter.export_issues_to_sarif([exp])
        self.assertEqual(sarif_doc["version"], "2.1.0")
        self.assertEqual(sarif_doc["$schema"], sarif_adapter.SARIF_SCHEMA_URI)
        run = sarif_doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], sarif_adapter.TOOL_NAME)
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(sarif_adapter.validate_sarif_shape(sarif_doc), [])

    def test_reviewer_repro_critical_severity_round_trips_exactly(self):
        """R09 reproduction: a critical-severity issue must round-trip as
        "critical", not collapse to "high" through SARIF's coarser 4-level
        `level` enum (critical and high both map to "error")."""
        grouped = issues.group_findings_into_issues(
            [dict(_finding("https://x.test/api/items", "sqli", confirmed=True,
                          case_id="case-1", proof_id="proof-1"), severity="critical")])
        exp = issues.export_issue(grouped[0])
        self.assertEqual(exp["severity"], "critical")
        sarif_doc = sarif_adapter.export_issues_to_sarif([exp])
        imported = sarif_adapter.import_sarif_to_findings(sarif_doc)
        self.assertEqual(imported[0]["severity"], "critical")

    def test_round_trip_preserves_method_and_affected_input(self):
        """R09 reproduction: method and affected-input context, both already
        present on issues.export_issue()'s output, were previously dropped
        entirely by the SARIF adapter."""
        grouped = issues.group_findings_into_issues(
            [_finding("https://x.test/api/items", "sqli", confirmed=True,
                     case_id="case-1", proof_id="proof-1", pname="id")])
        exp = issues.export_issue(grouped[0])
        self.assertEqual(exp["method"], "GET")
        sarif_doc = sarif_adapter.export_issues_to_sarif([exp])
        imported = sarif_adapter.import_sarif_to_findings(sarif_doc)
        self.assertEqual(imported[0]["method"], "GET")
        self.assertEqual(imported[0]["affected_input"], exp["affected_input"])

    def test_external_sarif_with_no_original_severity_uses_level_mapping(self):
        """An external SARIF document has no originalSeverity property to
        prefer -- import must still fall back to the level-derived guess
        rather than erroring or leaving severity empty."""
        external_doc = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "SomeOtherScanner", "version": "1.0"}},
                "results": [{
                    "ruleId": "xss", "level": "error",
                    "message": {"text": "x"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://ext.test/x"}}}],
                    "properties": {},
                }],
            }],
        }
        imported = sarif_adapter.import_sarif_to_findings(external_doc)
        self.assertEqual(imported[0]["severity"], "high")

    def test_oracle_verified_observation_type_distinct_from_confirmed_only(self):
        """R09/R06: an oracle-verified issue must not be indistinguishable
        from a merely leg-confirmed one in the exported observation_type."""
        oracle_exp = self._export_one_issue(confirmed=True)
        oracle_exp["oracle_verified"] = True
        oracle_exp["verification_state"] = "verified"
        confirmed_only_exp = self._export_one_issue(confirmed=True, pname="other")
        sarif_doc = sarif_adapter.export_issues_to_sarif([oracle_exp, confirmed_only_exp])
        types = {r["properties"]["issue_id"]: r["properties"]["observation_type"]
                for r in sarif_doc["runs"][0]["results"]}
        self.assertEqual(types[oracle_exp["issue_id"]], "oracle_verified")
        self.assertEqual(types[confirmed_only_exp["issue_id"]], "confirmed_exploit")

    def test_validate_sarif_shape_flags_missing_required_keys(self):
        problems = sarif_adapter.validate_sarif_shape({"version": "2.1.0"})
        self.assertTrue(any("runs" in p for p in problems))


class TestImportedFindingsStayAdvisory(unittest.TestCase):
    """Negative control: an imported finding must NEVER carry confirmation
    authority, even when the source SARIF explicitly claims a confirmed
    exploit -- only this harness's own oracle/validator pipeline can promote
    a finding past candidate."""

    def _confirmed_sarif_doc(self) -> dict:
        grouped = issues.group_findings_into_issues(
            [_finding("https://x.test/api/items", "sqli", confirmed=True,
                     case_id="case-1", proof_id="proof-1")])
        exp = issues.export_issue(grouped[0])
        self.assertTrue(exp["confirmed"])  # sanity: the source claim IS confirmed
        return sarif_adapter.export_issues_to_sarif([exp])

    def test_imported_finding_is_never_confirmed(self):
        sarif_doc = self._confirmed_sarif_doc()
        imported = sarif_adapter.import_sarif_to_findings(sarif_doc)
        self.assertFalse(imported[0]["confirmed"])

    def test_imported_finding_verification_state_is_candidate(self):
        sarif_doc = self._confirmed_sarif_doc()
        imported = sarif_adapter.import_sarif_to_findings(sarif_doc)
        self.assertEqual(imported[0]["verification_state"], "candidate")
        self.assertFalse(imported[0]["oracle_verified"])

    def test_external_sarif_claiming_confirmed_is_still_downgraded(self):
        """Same guarantee for a document THIS harness never produced -- an
        arbitrary external static/LLM tool's SARIF claiming a confirmed
        result must be downgraded exactly the same way."""
        external_doc = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "SomeOtherScanner", "version": "9.9.9"}},
                "properties": {"sourceRevision": "external-rev"},
                "results": [{
                    "ruleId": "xss",
                    "level": "error",
                    "message": {"text": "Reflected XSS, definitely exploitable"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://ext.test/x"}}}],
                    "properties": {"issue_id": "ext-1", "observation_type": "confirmed_exploit",
                                  "evidence_refs": ["irrelevant"]},
                }],
            }],
        }
        imported = sarif_adapter.import_sarif_to_findings(external_doc)
        self.assertEqual(len(imported), 1)
        f = imported[0]
        self.assertFalse(f["confirmed"])
        self.assertEqual(f["verification_state"], "candidate")
        self.assertEqual(f["source_tool"], "SomeOtherScanner")
        # The original claim is preserved as inert metadata, not discarded --
        # just never trusted as operative confirmation state.
        self.assertEqual(f["imported_observation_type"], "confirmed_exploit")


if __name__ == "__main__":
    unittest.main()
