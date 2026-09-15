"""Resolve confirmation claims against case-bound, structured proof evidence."""
from __future__ import annotations

from collections import Counter
from typing import Any


def _index(records: list[dict[str, Any]], key: str) -> tuple[dict[str, dict[str, Any]], set[str]]:
    result: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for item in records:
        value = item.get(key)
        if not value:
            continue
        value = str(value)
        if value in result:
            duplicates.add(value)
        else:
            result[value] = item
    return result, duplicates


def audit_findings(findings: list[dict[str, Any]], proofs: list[dict[str, Any]],
                   cases: list[dict[str, Any]], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    proof_by_id, duplicate_proofs = _index(proofs, "proof_id")
    case_by_id, duplicate_cases = _index(cases, "case_id")
    artifact_by_id, duplicate_artifacts = _index(artifacts, "artifact_id")
    diagnostics: list[dict[str, Any]] = []

    for finding in findings:
        finding_id = finding["finding_id"]
        claimed = finding.get("confirmed") is True
        proof_id = finding.get("proof_id") or ""
        case_id = finding.get("case_id") or ""
        validator = finding.get("validator") or ""
        reasons: list[str] = []
        support = "not_claimed"

        if claimed:
            support = "unverifiable"
            if not proof_id:
                reasons.append("confirmation is a bare true boolean with no proof reference")
            elif proof_id in duplicate_proofs:
                reasons.append("proof reference is ambiguous because the proof id is duplicated")
            else:
                proof = proof_by_id.get(proof_id)
                if proof is None:
                    reasons.append("proof reference is absent from the supplied artifact set")
                else:
                    proof_case = proof.get("case_id")
                    if isinstance(proof.get("case"), dict):
                        proof_case = proof["case"].get("case_id") or proof_case
                    if not case_id:
                        reasons.append("finding has no case reference")
                    elif proof_case != case_id:
                        reasons.append("proof resolves to a different case")
                    elif case_id in duplicate_cases:
                        reasons.append("case reference is ambiguous because the case id is duplicated")
                    elif case_id not in case_by_id:
                        reasons.append("case reference is absent from the supplied artifact set")
                    else:
                        case = case_by_id[case_id]
                        case_finding = case.get("finding_ref") or case.get("finding_id")
                        if case_finding and str(case_finding) != finding_id:
                            reasons.append("case resolves to a different finding")
                        verdict = str(proof.get("verdict") or "").lower()
                        if verdict != "confirmed":
                            reasons.append(f"proof verdict is {verdict or 'missing'}, not confirmed")
                        if proof.get("executed") is not True:
                            reasons.append("proof does not record an executed comparison")
                        if proof.get("legacy") is True:
                            reasons.append("legacy/unstructured proof cannot independently support confirmation")
                        if not proof.get("expected_invariant") or not proof.get("observed_result"):
                            reasons.append("proof lacks an expected invariant or observed result")
                        proof_validator = str(proof.get("validator") or "")
                        if validator and proof_validator and validator != proof_validator:
                            reasons.append("finding and proof name different validators")
                        evidence_ids: list[str] = []
                        for key in ("baseline_artifact_id", "attack_artifact_id"):
                            if proof.get(key):
                                evidence_ids.append(str(proof[key]))
                        evidence_ids.extend(str(x) for x in (proof.get("control_artifact_ids") or []))
                        if not evidence_ids:
                            reasons.append("proof has no resolvable exchange-artifact references")
                        else:
                            missing = [item for item in evidence_ids if item not in artifact_by_id]
                            ambiguous = [item for item in evidence_ids if item in duplicate_artifacts]
                            if missing:
                                reasons.append("proof references exchange artifacts absent from the supplied set")
                            if ambiguous:
                                reasons.append("proof references ambiguous duplicate exchange-artifact ids")
                            bad_outcomes = [
                                item for item in evidence_ids
                                if item in artifact_by_id
                                and str(artifact_by_id[item].get("transport_outcome") or "").lower()
                                not in {"ok", "success"}
                            ]
                            if bad_outcomes:
                                reasons.append("proof references an exchange artifact without a successful transport outcome")
                        if not reasons:
                            support = "supported"
                            reasons.append("matching case-bound executed proof and exchange artifacts support the verdict")
        elif finding.get("confirmed") not in (True, False):
            support = "unknown_claim"
            reasons.append("confirmation field is missing or is not a boolean")
        else:
            reasons.append("finding does not claim confirmation")

        diagnostics.append({
            "finding_id": finding_id,
            "confirmation_claimed": claimed,
            "named_validator_present": bool(validator),
            "proof_reference_present": bool(proof_id),
            "case_id": case_id or None,
            "proof_id": proof_id or None,
            "support": support,
            "reasons": reasons,
        })

    counts = Counter(item["support"] for item in diagnostics)
    return {
        "counts": dict(sorted(counts.items())),
        "confirmation_claims": sum(item["confirmation_claimed"] for item in diagnostics),
        "named_validator_references": sum(item["named_validator_present"] for item in diagnostics),
        "proof_references": sum(item["proof_reference_present"] for item in diagnostics),
        "supported_confirmations": sum(item["support"] == "supported" for item in diagnostics),
        "diagnostics": diagnostics,
    }
