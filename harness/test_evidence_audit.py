"""Hermetic tests for evidence_audit.py (P0.5). Pure function, no I/O -- proof
records are built directly or as store.best_proof_for_case()-shaped dicts."""
from __future__ import annotations

import unittest

from harness.evidence import ProofRecord, TestCaseRef, Verdict
from harness.evidence_audit import (
    audit_proof, AUDIT_VERIFIED, AUDIT_REJECTED, AUDIT_UNVERIFIABLE,
)
from harness.models import Finding


def _case(run_id="run-1", check_id="sqli", finding_ref="f1"):
    return TestCaseRef.make(run_id=run_id, request_template_id="GET /x",
                             check_id=check_id, finding_ref=finding_ref)


def _confirmed_proof(case=None):
    return ProofRecord(
        proof_id="", case=case or _case(), validator="sqlmap",
        verdict=Verdict.CONFIRMED, executed=True, observed_result="boolean diff")


def _finding_for(case: TestCaseRef, confirmed=True):
    return Finding(vulnerability_class="sqli", confidence=0.9, summary="s", evidence="e",
                   suggested_test="t", basis="derived", confirmed=confirmed,
                   case_id=case.case_id)


class TestAuditProof(unittest.TestCase):
    def test_synthetic_pass_same_case_same_run_confirmed(self):
        case = _case()
        finding = _finding_for(case)
        proof = _confirmed_proof(case)
        self.assertEqual(audit_proof(finding, proof, "run-1"), AUDIT_VERIFIED)

    def test_missing_proof_is_unverifiable(self):
        case = _case()
        finding = _finding_for(case)
        self.assertEqual(audit_proof(finding, None, "run-1"), AUDIT_UNVERIFIABLE)

    def test_wrong_case_is_rejected(self):
        case = _case()
        other_case = _case(check_id="idor")  # different check -> different case_id
        finding = _finding_for(case)
        proof = _confirmed_proof(other_case)
        self.assertEqual(audit_proof(finding, proof, "run-1"), AUDIT_REJECTED)

    def test_wrong_run_is_rejected(self):
        case = _case(run_id="run-1")
        finding = _finding_for(case)
        proof = _confirmed_proof(case)
        self.assertEqual(audit_proof(finding, proof, "run-2"), AUDIT_REJECTED)

    def test_forged_label_no_proof_is_unverifiable_not_rejected(self):
        """Negative control: a finding that CLAIMS confirmed/verified with no
        backing proof must read as unverifiable -- absence of evidence, not
        proof of falsehood, and specifically NOT "rejected" (which would
        imply a mismatch was actually found)."""
        case = _case()
        finding = _finding_for(case, confirmed=True)
        finding.verification_state = "verified"
        finding.oracle_verified = True
        self.assertEqual(audit_proof(finding, None, "run-1"), AUDIT_UNVERIFIABLE)

    def test_non_confirming_verdict_is_rejected(self):
        case = _case()
        finding = _finding_for(case)
        proof = ProofRecord(
            proof_id="", case=case, validator="sqlmap",
            verdict=Verdict.CONTROLLED_NEGATIVE, executed=True,
            control_artifact_ids=("a1",), observed_result="no diff")
        self.assertEqual(audit_proof(finding, proof, "run-1"), AUDIT_REJECTED)

    def test_accepts_store_shaped_dict(self):
        """audit_proof must also accept the plain dict shape
        store.best_proof_for_case() actually returns (nested "case" dict),
        not just a live ProofRecord object."""
        case = _case()
        finding = _finding_for(case)
        proof_dict = {
            "proof_id": "p1",
            "case": {"run_id": "run-1", "case_id": case.case_id},
            "verdict": "confirmed",
        }
        self.assertEqual(audit_proof(finding, proof_dict, "run-1"), AUDIT_VERIFIED)


if __name__ == "__main__":
    unittest.main()
