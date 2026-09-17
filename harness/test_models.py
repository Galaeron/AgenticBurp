"""R02: no field this harness's own pipeline owns (confirmation, proof
linkage, critique verdicts, attribution relabeling) may be set by an agent's
raw, untrusted JSON output. sanitize_agent_finding is the one place that
list lives, so every ingestion site (base_agent, iterative_agent,
orchestrator_detect's rediscovery) strips the same fields the same way.
"""
import unittest

from harness.models import AGENT_AUTHORITY_FIELDS, Finding, sanitize_agent_finding


class SanitizeAgentFindingTests(unittest.TestCase):
    def _raw(self, **overrides) -> dict:
        base = {
            "vulnerability_class": "sqli",
            "confidence": 0.8,
            "summary": "s",
            "evidence": "e",
            "suggested_test": "t",
            "basis": "derived",
        }
        base.update(overrides)
        return base

    def test_strips_every_authority_field(self):
        raw = self._raw(confirmed=True, proof_id="model-supplied-id", case_id="model-case",
                        review_verdict="validator-confirmed", review_note="looks solid",
                        original_confidence=0.99, original_severity="critical",
                        original_vulnerability_class="idor", shape_inconsistent=True,
                        confirmed_by_leg="cross_identity")
        cleaned = sanitize_agent_finding(raw)
        for field in AGENT_AUTHORITY_FIELDS:
            self.assertNotIn(field, cleaned)

    def test_legitimate_hypothesis_fields_survive(self):
        raw = self._raw(severity="high", parameter_name="userId", parameter_location="query")
        cleaned = sanitize_agent_finding(raw)
        self.assertEqual(cleaned["severity"], "high")
        self.assertEqual(cleaned["parameter_name"], "userId")
        self.assertEqual(cleaned["parameter_location"], "query")

    def test_finding_built_from_sanitized_dict_has_safe_defaults(self):
        raw = self._raw(confirmed=True, proof_id="forged", case_id="forged-case",
                        review_verdict="validator-confirmed")
        finding = Finding(**sanitize_agent_finding(raw))
        self.assertFalse(finding.confirmed)
        self.assertEqual(finding.proof_id, "")
        self.assertEqual(finding.case_id, "")
        self.assertIsNone(finding.review_verdict)


if __name__ == "__main__":
    unittest.main()
