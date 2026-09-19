"""Proof-audit shared contract (P0.5, evaluation integrity).

One function, one rule: a "verified" claim needs a REAL, PERSISTED proof, for
the SAME case, from the SAME run, that actually EXECUTED, with a CONFIRMING
verdict -- and if the finding itself already declares which proof backs it,
the supplied proof must be THAT proof. Anything else is either "rejected" (a
proof exists but doesn't back this claim) or "unverifiable" (no proof, or not
enough identity to bind against, exists at all) -- unverifiable is
deliberately NOT the same as rejected: a missing proof, or a missing case/run
identifier to check it against, is an absence of evidence, not evidence of
absence, and must never be silently read as either "verified" or "false".

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


def _proof_id_of(proof) -> str:
    if isinstance(proof, ProofRecord):
        return proof.proof_id
    return str(proof.get("proof_id", "") or "")


def _case_id_of(proof) -> str:
    if isinstance(proof, ProofRecord):
        return proof.case.case_id
    return str((proof.get("case") or {}).get("case_id", ""))


def _run_id_of(proof) -> str:
    if isinstance(proof, ProofRecord):
        return proof.case.run_id
    return str((proof.get("case") or {}).get("run_id", ""))


def _executed_of(proof) -> bool:
    if isinstance(proof, ProofRecord):
        return bool(proof.executed)
    return bool(proof.get("executed", False))


def _verdict_of(proof) -> Verdict:
    if isinstance(proof, ProofRecord):
        return proof.verdict
    return Verdict(proof.get("verdict"))


def audit_proof(finding, proof, run_id: str) -> str:
    """Audit whether `proof` actually backs a "verified"/"confirmed" claim on
    `finding`, within `run_id`.

    `finding` may be a Finding model or a dict; `case_id` and `proof_id` are
    read. `proof` may be a `ProofRecord`, a dict shaped like
    `store.best_proof_for_case()`'s return value, or None.

    Returns one of AUDIT_VERIFIED / AUDIT_REJECTED / AUDIT_UNVERIFIABLE:
    - AUDIT_UNVERIFIABLE: proof is None, or the finding/caller does not supply
      enough identity (case_id, run_id) to bind the proof against at all --
      never conflated with AUDIT_REJECTED (which asserts a demonstrated
      mismatch), and never weakened into a pass by treating a missing
      identifier as "nothing to check".
    - AUDIT_REJECTED: a proof exists, identity is present on both sides, but
      it is for a different case, a different run, a different declared
      proof_id, did not actually execute, or its verdict does not confirm
      the finding.
    - AUDIT_VERIFIED: the proof is for the SAME case, the SAME run, the SAME
      declared proof_id (when the finding declares one), it ACTUALLY
      EXECUTED, AND its verdict is CONFIRMED.
    """
    if proof is None:
        return AUDIT_UNVERIFIABLE

    finding_case_id = finding.get("case_id", "") if isinstance(finding, dict) \
        else getattr(finding, "case_id", "")
    finding_proof_id = finding.get("proof_id", "") if isinstance(finding, dict) \
        else getattr(finding, "proof_id", "")

    proof_case_id = _case_id_of(proof)
    proof_run_id = _run_id_of(proof)

    # Missing identity on either side means there is nothing concrete to bind
    # against: an absence of evidence, not a demonstrated mismatch. A caller
    # passing an empty run_id, or a finding with no case_id, must never fall
    # through to a weakened check that only fires when both sides happen to
    # be nonempty.
    if not finding_case_id or not run_id or not proof_case_id or not proof_run_id:
        return AUDIT_UNVERIFIABLE

    if proof_case_id != finding_case_id:
        return AUDIT_REJECTED
    if proof_run_id != run_id:
        return AUDIT_REJECTED
    if finding_proof_id and _proof_id_of(proof) != finding_proof_id:
        return AUDIT_REJECTED
    if not _executed_of(proof):
        return AUDIT_REJECTED
    if _verdict_of(proof) != Verdict.CONFIRMED:
        return AUDIT_REJECTED
    return AUDIT_VERIFIED
