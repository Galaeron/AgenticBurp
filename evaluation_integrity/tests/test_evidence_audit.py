import unittest

from evaluation_integrity.evidence_audit import audit_findings


def finding(fid="f1", **changes):
    value = {"finding_id": fid, "confirmed": True, "validator": "cross_identity",
             "proof_id": "p1", "case_id": "c1", "issue_id": "i1",
             "parameter_location": "query", "parameter_name": "userId"}
    value.update(changes)
    return value


def proof(**changes):
    value = {"proof_id": "p1", "case_id": "c1", "validator": "cross_identity",
             "verdict": "confirmed", "executed": True, "legacy": False,
             "attack_artifact_id": "a1", "expected_invariant": "access denied",
             "observed_result": "cross-principal access succeeded"}
    value.update(changes)
    return value


class EvidenceAuditTests(unittest.TestCase):
    def audit(self, f=None, p=None, c=None, a=None):
        return audit_findings(f or [finding()], p or [],
                              c or [{"case_id": "c1", "finding_ref": "f1"}],
                              a or [{"artifact_id": "a1", "transport_outcome": "ok"}])

    def test_bare_true_boolean_is_unsupported(self):
        result = self.audit([finding(proof_id="", case_id="")])
        self.assertEqual(result["supported_confirmations"], 0)
        self.assertIn("bare true boolean", result["diagnostics"][0]["reasons"][0])

    def test_missing_proof_and_orphan_reference_are_unverifiable(self):
        missing = self.audit([finding(proof_id="")])
        orphan = self.audit([finding(proof_id="orphan")])
        self.assertEqual(missing["diagnostics"][0]["support"], "unverifiable")
        self.assertIn("absent", orphan["diagnostics"][0]["reasons"][0])

    def test_wrong_case_reference_is_unverifiable(self):
        result = self.audit(p=[proof(case_id="c2")])
        self.assertIn("different case", " ".join(result["diagnostics"][0]["reasons"]))

    def test_inconclusive_evidence_does_not_support_confirmation(self):
        result = self.audit(p=[proof(verdict="inconclusive")])
        self.assertEqual(result["supported_confirmations"], 0)
        self.assertIn("inconclusive", " ".join(result["diagnostics"][0]["reasons"]))

    def test_valid_matching_record_is_supported(self):
        result = self.audit(p=[proof()])
        self.assertEqual(result["supported_confirmations"], 1)
        self.assertEqual(result["diagnostics"][0]["support"], "supported")

    def test_named_validator_is_not_sufficient(self):
        result = self.audit([finding(proof_id="", validator="sqlmap")])
        self.assertEqual(result["named_validator_references"], 1)
        self.assertEqual(result["supported_confirmations"], 0)

    def test_legacy_proof_is_unverifiable(self):
        result = self.audit(p=[proof(legacy=True)])
        self.assertIn("legacy/unstructured", " ".join(result["diagnostics"][0]["reasons"]))

    def test_unsuccessful_transport_cannot_support_verdict(self):
        result = self.audit(p=[proof()], a=[{"artifact_id": "a1", "transport_outcome": "timeout"}])
        self.assertEqual(result["supported_confirmations"], 0)
        self.assertIn("transport outcome", " ".join(result["diagnostics"][0]["reasons"]))


if __name__ == "__main__":
    unittest.main()
