"""R24 core export callers over synthetic records; no validation or target I/O."""
import unittest
from contextlib import closing
from unittest.mock import patch

from harness import confirmation_gate as gate, issues, report_generator, store
from harness import test_pairing_contract as pairing
from harness.models import AgentReport, Finding, HttpExchange


class CoreExportParityCallerTests(unittest.TestCase):
    def setUp(self):
        pairing.PairingCallerTests.setUp(self)
        for target in ["harness.run_context.TargetTransport.execute",
                       "httpx.HTTPTransport.handle_request", "httpx.AsyncHTTPTransport.handle_async_request"]:
            guard = patch(target, side_effect=AssertionError("R24 external I/O forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        self.url = "https://captured.example/ordinary"
        self.partition = "r24-synthetic"

    def persist(self, finding):
        store.persist_findings(HttpExchange(url=self.url, method="POST", capture_id="r24-capture",
                                           request_headers={"Cookie": "session=synthetic-private"}),
                               "synthetic", [finding], engagement_id=self.partition)

    def surfaces(self):
        params = {"url": self.url, "engagement_id": self.partition}
        markdown = self.client.get("/report", headers=self.auth, params=params)
        sarif = self.client.get("/report/sarif", headers=self.auth, params=params)
        self.assertEqual(markdown.status_code, 200)
        self.assertEqual(sarif.status_code, 200)
        structured = report_generator.export_issues_for_host(self.url, engagement_id=self.partition)
        return markdown.text, sarif.json()["runs"][0]["results"], structured

    def test_gate_capped_impact_survives_store_and_every_core_export(self):
        finding = Finding(vulnerability_class="sqli", confidence=.9, severity="critical",
            summary="Ordinary synthetic review", evidence="Cookie: session=synthetic-private",
            suggested_test="Review supplied capture", basis="derived", parameter_location="body", parameter_name="label")
        gate.apply_confirmation_suppression([AgentReport(agent="synthetic", model="inert", findings=[finding])])
        self.assertEqual(finding.original_severity, "critical")
        self.assertNotEqual(finding.severity, "critical")
        self.persist(finding)
        stored = store.all_host_findings(self.url, engagement_id=self.partition)[0]
        self.assertEqual(stored["original_severity"], "critical")
        markdown, sarif, structured = self.surfaces()
        self.assertEqual(len(sarif), 1)
        self.assertEqual(len(structured), 1)
        self.assertEqual(sarif[0]["properties"]["issue_id"], structured[0]["issue_id"])
        for export in [structured[0], sarif[0]["properties"], finding.model_dump()]:
            self.assertEqual(export["impact_severity"], "critical")
            self.assertEqual(export["evidence_maturity"], finding.evidence_maturity)
            self.assertEqual(export["triage_priority"], finding.triage_priority)
        self.assertIn("**Impact severity:** critical", markdown)
        self.assertNotIn("synthetic-private", markdown + str(sarif) + str(structured))
        self.assertFalse(structured[0]["confirmed"])
        # Removing the stored original axis must fail the same parity claim.
        original = store.all_host_findings
        def lose_original(*args, **kwargs):
            return [{k: v for k, v in row.items() if k != "original_severity"}
                    for row in original(*args, **kwargs)]
        with patch.object(store, "all_host_findings", side_effect=lose_original):
            damaged = report_generator.export_issues_for_host(self.url, engagement_id=self.partition)
        with self.assertRaises(AssertionError):
            self.assertEqual(damaged[0]["impact_severity"], "critical")

    def test_unavailable_proof_pointer_is_preserved_without_replayability(self):
        finding = Finding(vulnerability_class="unknown-workflow-risk", confidence=.5, severity="high",
            summary="Ordinary missing proof observation", evidence="ordinary metadata", suggested_test="Review capture",
            basis="derived", finding_id="r24-missing-finding", case_id="r24-missing-case", proof_id="r24-missing-proof")
        self.persist(finding)
        markdown, sarif, structured = self.surfaces()
        self.assertFalse(structured[0]["artifacts"]["replayable"])
        ref = structured[0]["proof_references"][0]
        self.assertEqual(ref["proof_id"], "r24-missing-proof")
        self.assertEqual(ref["availability"], "unavailable")
        self.assertEqual(sarif[0]["properties"]["evidence_refs"], structured[0]["proof_references"])
        self.assertEqual(sarif[0]["properties"]["artifacts"], structured[0]["artifacts"])
        self.assertIn("unavailable", markdown.lower())
        read = self.client.get("/findings/r24-missing-finding/evidence", headers=self.auth,
                               params={"engagement_id": self.partition})
        self.assertEqual(read.status_code, 404)
        # Reproduce the former unresolved-pointer representation: omitting
        # availability made a dangling ID look like a reachable proof.
        with patch.object(issues, "_proof_references", return_value=[{
                "case_id": finding.case_id, "proof_id": finding.proof_id, "verdict": None}]):
            defective = report_generator.export_issues_for_host(self.url, engagement_id=self.partition)
        with self.assertRaises(AssertionError):
            self.assertFalse(defective[0]["artifacts"]["replayable"])

    def test_old_schema_preserves_unknown_original_severity_without_invention(self):
        finding = Finding(vulnerability_class="unknown-workflow-risk", confidence=.5, severity="medium",
            summary="Ordinary legacy observation", evidence="ordinary metadata", suggested_test="Review capture",
            basis="derived")
        self.persist(finding)
        with closing(store._connect()) as conn, conn:
            conn.execute("ALTER TABLE findings DROP COLUMN original_severity")
        row = store.all_host_findings(self.url, engagement_id=self.partition)[0]
        self.assertIsNone(row["original_severity"])
        markdown, sarif, structured = self.surfaces()
        self.assertEqual(structured[0]["impact_severity"], "medium")
        self.assertEqual(sarif[0]["properties"]["impact_severity"], "medium")
        self.assertIn("**Impact severity:** medium", markdown)


if __name__ == "__main__":
    unittest.main()
