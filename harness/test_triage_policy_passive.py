"""Canned captured findings only; no confirmation execution or target requests."""
import asyncio
import json
from unittest.mock import patch
from harness import confirmation_gate as gate, issues, report_generator, sarif_adapter, store
from harness.models import Finding, AgentReport, HttpExchange, ValidationReport
from harness.test_pairing_contract import PairingCallerTests
from harness.test_privacy_contract import PassiveAgent, RecordingProvider


def candidate(vulnerability_class="unknown-workflow-risk", **kwargs):
    return Finding(vulnerability_class=vulnerability_class, confidence=.99, severity="critical",
                   summary="Ordinary captured workflow observation", evidence="ordinary metadata",
                   suggested_test="Human review of captured metadata", basis="derived", **kwargs)


class TriageCallerTests(PairingCallerTests):
    def test_high_impact_no_leg_agrees_across_wire_canonical_markdown_sarif(self):
        finding = candidate()
        gate.apply_confirmation_suppression([AgentReport(agent="synthetic", model="fake", findings=[finding])])
        wire = finding.model_dump()
        self.assertEqual(wire["evidence_maturity"], "unverified_no_leg")
        self.assertEqual(wire["triage_priority"], "manual_verification")
        self.assertEqual((finding.severity, finding.confidence), ("critical", .99))
        exchange = HttpExchange(url="https://captured.example/ordinary", method="GET")
        store.persist_findings(exchange, "synthetic", [finding])
        canonical = report_generator.export_issues_for_host(exchange.url)[0]
        for key in ("evidence_maturity", "triage_priority", "impact_severity"):
            self.assertEqual(canonical[key], wire[key])
        self.assertFalse(canonical["confirmed"])
        markdown = self.client.get("/report", params={"url": exchange.url}, headers=self.auth)
        self.assertEqual(markdown.status_code, 200)
        self.assertIn("**Evidence maturity:** unverified_no_leg", markdown.text)
        self.assertIn("**Triage priority:** manual_verification", markdown.text)
        self.assertIn("**Impact severity:** critical", markdown.text)
        self.assertIn("no deterministic confirmation leg", markdown.text)
        result = self.client.get("/report/sarif", params={"url": exchange.url}, headers=self.auth).json()["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["observation_type"], "candidate")
        for key in ("evidence_maturity", "triage_priority", "impact_severity"):
            self.assertEqual(result["properties"][key], wire[key])

    def test_actual_model_ingestion_cannot_set_evidence_or_proof_authority(self):
        raw = candidate().model_dump()
        raw.update(confirmed=True, oracle_verified=True, verification_state="verified", proof_id="fake-proof",
                   evidence_maturity="confirmed", triage_priority="review_confirmed", impact_severity="info")
        provider = RecordingProvider({"findings": [raw]})
        result = asyncio.run(PassiveAgent(provider, "fake").run(
            HttpExchange(url="https://captured.example/ordinary", method="GET"), 6000))
        self.assertEqual(len(result.findings), 1)
        clean = result.findings[0].model_dump()
        self.assertFalse(clean["confirmed"])
        self.assertFalse(clean["oracle_verified"])
        self.assertEqual(clean["proof_id"], "")
        self.assertEqual(clean["evidence_maturity"], "unverified_no_leg")
        self.assertEqual(clean["triage_priority"], "manual_verification")
        self.assertEqual(clean["impact_severity"], "critical")

    def test_controlled_negative_distinct_from_skipped_errored_and_passive_observation(self):
        values = []
        for status in ("not_confirmed", "skipped", "error"):
            finding = candidate("sqli")
            report = ValidationReport(validator="synthetic-control", status=status, finding_class="sqli", confirmed=False)
            gate.apply_confirmation_suppression([AgentReport(agent="synthetic", model="fake", findings=[finding])],
                                                validation_reports=[report])
            values.append(gate.finding_triage(finding))
        self.assertEqual(values[0]["evidence_maturity"], "controlled_negative")
        self.assertEqual(values[0]["triage_priority"], "review_negative")
        for skipped in values[1:]:
            self.assertEqual(skipped["evidence_maturity"], "unverified")
            self.assertEqual(skipped["triage_priority"], "manual_verification")
        observation = candidate("cors", confirmed=True)
        self.assertEqual(observation.evidence_maturity, "confirmed_observation")
        self.assertEqual(observation.severity, "critical")

    def test_defect_control_export_without_policy_loses_unverified_marker(self):
        raw = {**candidate().model_dump(), "url": "https://captured.example/ordinary", "method": "GET"}
        issue = issues.group_findings_into_issues([raw])[0]
        with patch("harness.confirmation_gate.finding_triage", return_value={}):
            self.assertNotIn("evidence_maturity", issues.export_issue(issue))
