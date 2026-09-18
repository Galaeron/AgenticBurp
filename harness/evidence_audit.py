"""Proof-audit shared contract (P0.5, evaluation integrity).

One function, one rule: a "verified" claim needs a REAL, PERSISTED proof, for
the SAME case, from the SAME run, with a CONFIRMING verdict. Anything else is
either "rejected" (a proof exists but doesn't back this claim) or
"unverifiable" (no proof exists at all) -- unverifiable is deliberately NOT
the same as rejected: a missing proof is an absence of evidence, not evidence
of absence, and must never be silently read as either "verified" or "false".

`evaluation_integrity/evidence_audit.py`, referenced by an earlier source
list, does not exist in this repo -- this is that module, under the real
package. Reuses `harness.evidence` (Verdict/TestCaseRef/ProofRecord) and
`store.py`'s proof helpers (`best_proof_for_case` returns exactly the dict
shape this module's `proof` parameter accepts).

Pure and hermetic: no I/O here -- the caller supplies the proof record (or
None) it already looked up.
"""
from __future__ import annotations

from harness.evidence import ProofRecord, Verdict

AUDIT_VERIFIED = "verified"
AUDIT_REJECTED = "rejected"
AUDIT_UNVERIFIABLE = "unverifiable"


def _case_id_of(proof) -> str:
    if isinstance(proof, ProofRecord):
        return proof.case.case_id
    return str((proof.get("case") or {}).get("case_id", ""))


def _run_id_of(proof) -> str:
    if isinstance(proof, ProofRecord):
        return proof.case.run_id
    return str((proof.get("case") or {}).get("run_id", ""))


def _verdict_of(proof) -> Verdict:
    if isinstance(proof, ProofRecord):
        return proof.verdict
    return Verdict(proof.get("verdict"))


def audit_proof(finding, proof, run_id: str) -> str:
    """Audit whether `proof` actually backs a "verified"/"confirmed" claim on
    `finding`, within `run_id`.

    `finding` may be a Finding model or a dict; only `case_id` is read.
    `proof` may be a `ProofRecord`, a dict shaped like
    `store.best_proof_for_case()`'s return value, or None.

    Returns one of AUDIT_VERIFIED / AUDIT_REJECTED / AUDIT_UNVERIFIABLE:
    - AUDIT_UNVERIFIABLE: proof is None -- no evidence exists to audit at all.
      Never conflated with AUDIT_REJECTED (which asserts a mismatch was found).
    - AUDIT_REJECTED: a proof exists but is for a different case, a different
      run, or its verdict does not confirm the finding.
    - AUDIT_VERIFIED: the proof is for the SAME case, the SAME run, AND its
      verdict is CONFIRMED.
    """
    if proof is None:
        return AUDIT_UNVERIFIABLE

    finding_case_id = finding.get("case_id", "") if isinstance(finding, dict) \
        else getattr(finding, "case_id", "")

    if finding_case_id and _case_id_of(proof) != finding_case_id:
        return AUDIT_REJECTED
    if run_id and _run_id_of(proof) != run_id:
        return AUDIT_REJECTED
    if _verdict_of(proof) != Verdict.CONFIRMED:
        return AUDIT_REJECTED
    return AUDIT_VERIFIED
