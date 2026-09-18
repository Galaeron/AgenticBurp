"""P0.2-API: the same finding must report the SAME verification_state in
store.all_host_findings() (the findings-API/report/Burp-panel data source --
see test_smoke_detection.py's own comment naming it as such),
report_generator._from_store_dict(), and an agent must never be able to
assert the field itself.

Regression coverage: store.all_host_findings() previously never selected
the oracle_verified/verification_state/oracle_capsule_id columns from the
findings table, so report_generator's derive_verification_state(d) always
saw an absent key and silently reported every finding as "candidate" no
matter what was persisted.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness import store
from harness.models import HttpExchange, Finding, sanitize_agent_finding
from harness import report_generator


class TestVerificationStateConsistency(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _persist_verified_finding(self) -> HttpExchange:
        exchange = HttpExchange(
            url="https://example.com/api/proxy?url=http://x", method="GET",
            request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
        )
        finding = Finding(
            vulnerability_class="ssrf",
            confidence=0.9,
            summary="Blind SSRF via url param",
            evidence="collaborator callback observed",
            suggested_test="replay with collaborator URL",
            basis="derived",
            severity="high",
            confirmed=True,
            oracle_verified=True,
            verification_state="verified",
            oracle_capsule_id="abc123deadbeef",
        )
        store.persist_findings(exchange, "ssrf_agent", [finding])
        return exchange

    def test_store_dict_carries_verified_state(self):
        exchange = self._persist_verified_finding()
        results = store.all_host_findings(exchange.url)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertTrue(r["oracle_verified"])
        self.assertEqual(r["verification_state"], "verified")
        self.assertEqual(r["oracle_capsule_id"], "abc123deadbeef")

    def test_report_generator_reads_same_state_from_store_dict(self):
        exchange = self._persist_verified_finding()
        rows = store.all_host_findings(exchange.url)
        rf = report_generator._from_store_dict(rows[0])
        self.assertEqual(rf.verification_state, "verified")

    def test_candidate_finding_stays_candidate_end_to_end(self):
        """Negative control: a finding that was NEVER oracle-verified must
        read back as "candidate" through both the store dict and the report
        view -- not silently promoted."""
        exchange = HttpExchange(
            url="https://example.com/api/other", method="GET",
            request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
        )
        finding = Finding(
            vulnerability_class="idor", confidence=0.7, summary="s", evidence="e",
            suggested_test="t", basis="derived", confirmed=True,
        )
        store.persist_findings(exchange, "idor_agent", [finding])
        rows = store.all_host_findings(exchange.url)
        self.assertFalse(rows[0]["oracle_verified"])
        self.assertEqual(rows[0]["verification_state"], "candidate")
        rf = report_generator._from_store_dict(rows[0])
        self.assertEqual(rf.verification_state, "candidate")

    def test_agent_cannot_assert_verification_state(self):
        """Negative control: an agent-authored raw finding dict claiming
        verification_state="verified" must have that field stripped before
        it ever reaches Finding(**...)."""
        raw = {
            "vulnerability_class": "sqli",
            "confidence": 0.99,
            "summary": "s", "evidence": "e", "suggested_test": "t", "basis": "derived",
            "verification_state": "verified",
            "oracle_verified": True,
            "oracle_capsule_id": "forged",
            "oracle_reason": "trust me",
        }
        cleaned = sanitize_agent_finding(raw)
        self.assertNotIn("verification_state", cleaned)
        self.assertNotIn("oracle_verified", cleaned)
        self.assertNotIn("oracle_capsule_id", cleaned)
        self.assertNotIn("oracle_reason", cleaned)
        finding = Finding(**cleaned)
        self.assertFalse(finding.oracle_verified)
        self.assertEqual(finding.verification_state, "candidate")


if __name__ == "__main__":
    unittest.main()
