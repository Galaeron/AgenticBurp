import json
import unittest
from pathlib import Path

from harness.models import HttpExchange, AgentReport, Finding
from harness.confirmation_gate import apply_confirmation_suppression


class TestBlindNegativesRegression(unittest.TestCase):
    """
    Regression test suite for blind negative precision.
    
    Verifies that the 6 'confirmed_secure' endpoints from blind-target-2
    (the helpdesk application eval) remain 100% clean of medium/high/critical
    findings, permanently resolving the '0/6 controls clean' failure mode.
    """

    @classmethod
    def setUpClass(cls):
        fixture_path = (
            Path(__file__).resolve().parent.parent
            / "testing"
            / "blind-target-2"
            / "blind_eval_exchanges.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            all_exchanges = json.load(f)
        cls.secure_exchanges = [
            e for e in all_exchanges if e.get("ground_truth") == "confirmed_secure"
        ]

    def test_fixture_contains_six_secure_controls(self):
        """Ensure the ground-truth benchmark contains the expected 6 secure controls."""
        self.assertEqual(len(self.secure_exchanges), 6)
        labels = [e["label"] for e in self.secure_exchanges]
        self.assertIn("register u_45277ca1", labels)
        self.assertIn("register u_fa610b15", labels)
        self.assertIn("alice login (baseline auth)", labels)
        self.assertIn("alice reads OWN ticket (normal/TN)", labels)
        self.assertIn("bob comments on foreign ticket (authz enforced)", labels)
        self.assertIn("bob DELETE foreign ticket (blocked)", labels)

    def test_unconfirmed_speculative_findings_demoted_on_all_secure_controls(self):
        """
        Simulate the exact agent hypotheses that previously caused the 0/6 collapse
        (unconfirmed IDOR, SQLi, and Auth hypotheses on normal endpoints).
        Verify that confirmation suppression demotes them so 0 medium+ findings ship.
        """
        for entry in self.secure_exchanges:
            ex = HttpExchange(
                url=entry["url"],
                method=entry["method"],
                request_headers=entry.get("request_headers", {}),
                request_body=entry.get("request_body", ""),
                response_status=entry.get("response_status", 200),
                response_headers=entry.get("response_headers", {}),
                response_body=entry.get("response_body", ""),
            )

            # Construct speculative findings that an LLM agent would produce from URL shape
            speculative_findings = [
                Finding(
                    vulnerability_class="idor",
                    confidence=0.85,
                    severity="high",
                    summary=f"Speculative IDOR on {ex.url}",
                    evidence="Object ID in path/body",
                    suggested_test="Swap token",
                    basis="derived",
                    confirmed=False,
                ),
                Finding(
                    vulnerability_class="sql_injection",
                    confidence=0.75,
                    severity="critical",
                    summary=f"Speculative SQLi on {ex.url}",
                    evidence="Parameter presence",
                    suggested_test="Inject single quote",
                    basis="derived",
                    confirmed=False,
                ),
            ]

            reports = [
                AgentReport(
                    agent="idor",
                    model="test",
                    findings=[speculative_findings[0]],
                ),
                AgentReport(
                    agent="sqli",
                    model="test",
                    findings=[speculative_findings[1]],
                ),
            ]

            # Run confirmation-suppression gate
            apply_confirmation_suppression(reports)

            # Collect actionable findings (severity >= medium)
            actionable_findings = [
                f
                for r in reports
                for f in r.findings
                if f.severity in ("medium", "high", "critical")
            ]

            # Critical assertion: ZERO actionable findings on secure controls
            self.assertEqual(
                len(actionable_findings),
                0,
                f"Secure control '{entry['label']}' emitted actionable findings: {actionable_findings}",
            )

            # All findings must be capped to low with confidence <= 0.35 (the
            # precision floor). With no leg execution simulated here, the honest
            # verdict is UNVERIFIED (inconclusive), not "refuted" (R08) -- but the
            # floor (zero medium+) is identical either way.
            for r in reports:
                for f in r.findings:
                    self.assertEqual(f.severity, "low")
                    self.assertLessEqual(f.confidence, 0.35)
                    self.assertEqual(f.review_verdict, "inconclusive_unverified")
                    self.assertTrue(f.summary.startswith("[Unverified]"))

    # NOTE: passive-banner dependency capping (formerly asserted inline here with
    # test-local logic) moved to Phase 1.2 -- the cap now lives in harness code
    # (host_dep_dedup) and is exercised by test_host_dep_dedup, so this precision
    # floor tests the confirmation-suppression gate only.


if __name__ == "__main__":
    unittest.main()
