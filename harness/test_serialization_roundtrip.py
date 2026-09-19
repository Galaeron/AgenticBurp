"""Cross-layer serialization round-trip (P1.9). The PYTHON side of this is
fully runnable and hermetic; the Java (Burp extension) side cannot be
compiled or tested in this environment (no JDK -- see CLAUDE.md hazard #6)
and stays self-review only (burp-extension/src/main/java/com/harness/llm/
model/AnalysisModels.java's Finding POJO gained the matching fields, marked
UNBUILT/UNVERIFIED in its own comment).

This proves the Python half of the wire format -- Finding -> the exact JSON
shape the API/report/Burp panel actually exchange -- loses none of the
candidate/verified/evidence fields across a real json.dumps/json.loads
boundary (not just a pydantic-internal round trip), and that an agent still
cannot forge authority fields even after that boundary.
"""
from __future__ import annotations

import json
import unittest

from harness.models import AGENT_AUTHORITY_FIELDS, Finding, sanitize_agent_finding


def _oracle_verified_finding() -> Finding:
    return Finding(
        vulnerability_class="ssrf", confidence=0.9, summary="s", evidence="e",
        suggested_test="t", basis="derived",
        confirmed=True, case_id="case-1", proof_id="proof-1",
        confirmed_by_leg="ssrf", oracle_verified=True,
        verification_state="verified", oracle_capsule_id="cap-1",
        oracle_reason="reproduced N-of-N; self-controlling OOB leg",
    )


class TestFindingJsonRoundTrip(unittest.TestCase):
    def test_all_authority_and_case_proof_fields_survive_json_boundary(self):
        original = _oracle_verified_finding()
        wire = json.loads(json.dumps(original.model_dump()))
        restored = Finding(**wire)
        for field in ("confirmed", "case_id", "proof_id", "confirmed_by_leg",
                      "oracle_verified", "verification_state", "oracle_capsule_id",
                      "oracle_reason"):
            self.assertEqual(
                getattr(restored, field), getattr(original, field),
                f"{field} did not survive the JSON round trip")

    def test_candidate_finding_round_trips_as_candidate_not_upgraded(self):
        """Negative control: a finding that was NEVER oracle-verified must not
        somehow read as verified after a serialize/deserialize round trip --
        the round trip must be lossless in BOTH directions, not just
        preserve a True flag."""
        original = Finding(vulnerability_class="idor", confidence=0.6, summary="s",
                           evidence="e", suggested_test="t", basis="derived")
        wire = json.loads(json.dumps(original.model_dump()))
        restored = Finding(**wire)
        self.assertFalse(restored.oracle_verified)
        self.assertEqual(restored.verification_state, "candidate")
        self.assertFalse(restored.confirmed)

    def test_agent_cannot_forge_authority_fields_across_the_boundary(self):
        """An agent's raw JSON output (as it would arrive over the wire from
        the model, then get parsed) must have every AGENT_AUTHORITY_FIELDS
        key stripped BEFORE Finding(**...), even after going through a real
        json round trip (not just a Python dict literal)."""
        raw_model_output = {
            "vulnerability_class": "sqli", "confidence": 0.99, "summary": "s",
            "evidence": "e", "suggested_test": "t", "basis": "derived",
            "confirmed": True, "case_id": "forged-case", "proof_id": "forged-proof",
            "confirmed_by_leg": "sqlmap", "oracle_verified": True,
            "verification_state": "verified", "oracle_capsule_id": "forged-capsule",
            "oracle_reason": "trust me",
        }
        wire = json.loads(json.dumps(raw_model_output))
        cleaned = sanitize_agent_finding(wire)
        for field in AGENT_AUTHORITY_FIELDS:
            self.assertNotIn(field, cleaned)
        finding = Finding(**cleaned)
        self.assertFalse(finding.confirmed)
        self.assertFalse(finding.oracle_verified)
        self.assertEqual(finding.verification_state, "candidate")
        self.assertEqual(finding.case_id, "")
        self.assertEqual(finding.proof_id, "")


if __name__ == "__main__":
    unittest.main()
