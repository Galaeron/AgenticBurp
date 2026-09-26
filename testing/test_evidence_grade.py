"""
Caller-level tests for testing/evidence_grade.py (PR-4, BP-1b).

Discovered both via `python -m unittest discover -s testing -p test_*.py`
(harness.suite's smoke/full tiers) and directly via
`python -m unittest testing.test_evidence_grade`. Deterministic and fully
offline -- no model/GPU/network. Never opens an *ANSWER_KEY* file or a
blind target's app.py; every finding/proof/case/artifact below is a
synthetic in-memory fixture.

Fixture shapes mirror evaluation_integrity/tests/test_evidence_audit.py's
finding/proof/case/artifact builders and testing/test_strict_score.py's
manifest fixture-builder pattern, so this file does not re-derive its own
notion of what a valid proof/case/artifact looks like.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_TESTING_DIR = Path(__file__).resolve().parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

from labels.manifest import LabelRecord, Manifest, compute_hash  # noqa: E402
from evidence_grade import (  # noqa: E402
    build_evidence_grade_hook,
    grade_findings,
    predictions_from_findings,
    score_with_evidence,
)


# --- fixture builders --------------------------------------------------------

def _record(exchange_id: str, expected=(), tested_negative=(), status="positive") -> LabelRecord:
    return LabelRecord(exchange_id=exchange_id, expected_classes=tuple(expected),
                       tested_negative_classes=tuple(tested_negative),
                       label_scope="synthetic fixture", status=status,
                       provenance="unit test fixture")


def _manifest(records: list[LabelRecord], corpus: str = "unittest-evidence-corpus") -> Manifest:
    return Manifest(corpus=corpus, version="0.0.1", hash=compute_hash(records),
                    records=tuple(records))


def _finding(finding_id: str, exchange_id: str, vulnerability_class: str, **changes) -> dict:
    value = {
        "finding_id": finding_id, "exchange_id": exchange_id,
        "vulnerability_class": vulnerability_class, "confirmed": True,
        "validator": "cross_identity", "proof_id": "p1", "case_id": "c1",
    }
    value.update(changes)
    return value


def _proof(**changes) -> dict:
    value = {"proof_id": "p1", "case_id": "c1", "validator": "cross_identity",
             "verdict": "confirmed", "executed": True, "legacy": False,
             "attack_artifact_id": "a1", "expected_invariant": "baseline rejects",
             "observed_result": "attack request succeeded where baseline was rejected"}
    value.update(changes)
    return value


def _case(case_id: str = "c1", finding_ref: str = "f1") -> dict:
    return {"case_id": case_id, "finding_ref": finding_ref}


def _artifact(artifact_id: str = "a1", transport_outcome: str = "ok") -> dict:
    return {"artifact_id": artifact_id, "transport_outcome": transport_outcome}


# --- grade_findings: tier-mapping unit tests ---------------------------------

class GradeFindingsTests(unittest.TestCase):
    """Directly exercises the audit-support -> PR-4-tier mapping, isolated
    from strict_score's precision/recall arithmetic."""

    def test_bare_true_no_proof_is_graded_unsupported(self):
        findings = [_finding("f1", "EX1", "sql injection", proof_id="", case_id="")]
        graded = grade_findings(findings, [], [], [])
        self.assertEqual(graded["f1"]["support"], "unverifiable")
        self.assertEqual(graded["f1"]["tier"], "unsupported")

    def test_orphan_proof_reference_is_graded_unsupported(self):
        findings = [_finding("f1", "EX1", "sql injection", proof_id="orphan")]
        graded = grade_findings(findings, [], [_case()], [_artifact()])
        self.assertEqual(graded["f1"]["support"], "unverifiable")
        self.assertEqual(graded["f1"]["tier"], "unsupported")

    def test_wrong_case_proof_is_graded_unsupported(self):
        findings = [_finding("f1", "EX1", "sql injection")]
        proofs = [_proof(case_id="c2")]
        cases = [_case(case_id="c1", finding_ref="f1"), _case(case_id="c2", finding_ref="other")]
        artifacts = [_artifact()]
        graded = grade_findings(findings, proofs, cases, artifacts)
        self.assertEqual(graded["f1"]["support"], "unverifiable")
        self.assertEqual(graded["f1"]["tier"], "unsupported")
        self.assertIn("different case", " ".join(graded["f1"]["reasons"]))

    def test_non_confirmed_verdict_is_graded_unsupported(self):
        findings = [_finding("f1", "EX1", "sql injection")]
        proofs = [_proof(verdict="inconclusive")]
        graded = grade_findings(findings, proofs, [_case()], [_artifact()])
        self.assertEqual(graded["f1"]["tier"], "unsupported")

    def test_adequate_single_sided_proof_is_graded_captured(self):
        findings = [_finding("f1", "EX1", "sql injection")]
        proofs = [_proof()]  # only attack_artifact_id -- no baseline
        cases = [_case()]
        artifacts = [_artifact()]
        graded = grade_findings(findings, proofs, cases, artifacts)
        self.assertEqual(graded["f1"]["support"], "supported")
        self.assertEqual(graded["f1"]["tier"], "captured")

    def test_baseline_and_attack_proof_is_graded_differential_reproduced(self):
        findings = [_finding("f1", "EX1", "sql injection")]
        proofs = [_proof(baseline_artifact_id="b1", attack_artifact_id="a1")]
        cases = [_case()]
        artifacts = [_artifact("a1"), _artifact("b1")]
        graded = grade_findings(findings, proofs, cases, artifacts)
        self.assertEqual(graded["f1"]["support"], "supported")
        self.assertEqual(graded["f1"]["tier"], "differential_reproduced")

    def test_proof_referencing_missing_artifact_is_graded_insufficient(self):
        findings = [_finding("f1", "EX1", "sql injection")]
        proofs = [_proof(attack_artifact_id="missing-artifact")]
        cases = [_case()]
        graded = grade_findings(findings, proofs, cases, [])  # artifact never supplied
        self.assertEqual(graded["f1"]["support"], "unverifiable")
        self.assertEqual(graded["f1"]["tier"], "insufficient")

    def test_no_confirmation_claim_at_all_is_graded_unsupported(self):
        findings = [_finding("f1", "EX1", "sql injection", confirmed=False,
                             proof_id="", case_id="")]
        graded = grade_findings(findings, [], [], [])
        self.assertEqual(graded["f1"]["support"], "not_claimed")
        self.assertEqual(graded["f1"]["tier"], "unsupported")


# --- predictions_from_findings -----------------------------------------------

class PredictionsFromFindingsTests(unittest.TestCase):
    def test_groups_raw_classes_by_exchange(self):
        findings = [
            _finding("f1", "EX1", "sql injection"),
            _finding("f2", "EX1", "cross-site scripting"),
            _finding("f3", "EX2", "sql injection"),
        ]
        predictions = predictions_from_findings(findings)
        self.assertEqual(sorted(predictions["EX1"]), ["cross-site scripting", "sql injection"])
        self.assertEqual(predictions["EX2"], ["sql injection"])


# --- score_with_evidence: caller-level integration through strict_score -----

class ScoreWithEvidenceTests(unittest.TestCase):
    """Caller-level: drives real strict_score.score() with a real hook built
    from synthetic evidence artifacts -- proves the full PR-3 -> PR-4 wiring,
    not just the tier classifier in isolation."""

    def test_class_correct_and_captured_finding_is_evidence_supported_tp(self):
        manifest = _manifest([_record("EX1", expected=["sqli"])])
        findings = [_finding("f1", "EX1", "sql injection")]
        report = score_with_evidence(manifest, findings, [_proof()], [_case()], [_artifact()])
        ev = report["evidence_supported"]
        self.assertEqual(ev["status"], "computed")
        self.assertEqual(ev["overall"]["tp"], 1)
        self.assertEqual(ev["overall"]["fn"], 0)
        self.assertEqual(ev["overall"]["precision"], 1.0)
        self.assertEqual(ev["overall"]["recall"], 1.0)
        self.assertEqual(ev["tiers"]["tier_counts"].get("captured"), 1)

    def test_bare_true_no_proof_is_not_evidence_supported_tp_even_if_class_matches(self):
        # Instrumentation IS present for this RUN (non-empty cases/artifacts
        # from other activity) but THIS finding's claim has no proof at all.
        manifest = _manifest([_record("EX1", expected=["sqli"])])
        findings = [_finding("f1", "EX1", "sql injection", proof_id="", case_id="")]
        cases = [_case(case_id="unrelated", finding_ref="other")]
        artifacts = [_artifact(artifact_id="unrelated_a")]
        report = score_with_evidence(manifest, findings, [], cases, artifacts)
        ev = report["evidence_supported"]
        self.assertEqual(ev["status"], "computed")
        self.assertEqual(ev["overall"]["tp"], 0)
        self.assertEqual(ev["overall"]["fn"], 1)
        self.assertEqual(ev["tiers"]["per_finding"]["f1"]["tier"], "unsupported")

    def test_proof_resolving_to_different_case_is_not_evidence_supported_tp(self):
        manifest = _manifest([_record("EX1", expected=["sqli"])])
        findings = [_finding("f1", "EX1", "sql injection")]
        proofs = [_proof(case_id="c2")]
        cases = [_case(case_id="c1", finding_ref="f1"), _case(case_id="c2", finding_ref="other")]
        artifacts = [_artifact()]
        report = score_with_evidence(manifest, findings, proofs, cases, artifacts)
        ev = report["evidence_supported"]
        self.assertEqual(ev["overall"]["tp"], 0)
        self.assertEqual(ev["overall"]["fn"], 1)

    def test_exact_class_wrong_but_well_proven_is_not_evidence_supported_tp(self):
        # Manifest expects sqli for EX1; the well-proven finding predicts a
        # DIFFERENT exact class (xss). Must be BOTH class-correct AND
        # supported to count as a TP -- a well-proven wrong-class prediction
        # is an evidence-supported FP (over-prediction), never a TP, and the
        # expected sqli class is still an uncontested miss.
        manifest = _manifest([_record("EX1", expected=["sqli"])])
        findings = [_finding("f1", "EX1", "cross-site scripting")]  # classifies to xss
        report = score_with_evidence(manifest, findings, [_proof()], [_case()], [_artifact()])
        ev = report["evidence_supported"]
        self.assertEqual(ev["overall"]["tp"], 0)
        self.assertEqual(ev["overall"]["fn"], 1)
        self.assertEqual(ev["overall"]["fp"], 1)

    def test_differential_reproduced_also_counts_as_evidence_supported_tp(self):
        manifest = _manifest([_record("EX1", expected=["sqli"])])
        findings = [_finding("f1", "EX1", "sql injection")]
        proofs = [_proof(baseline_artifact_id="b1", attack_artifact_id="a1")]
        artifacts = [_artifact("a1"), _artifact("b1")]
        report = score_with_evidence(manifest, findings, proofs, [_case()], artifacts)
        ev = report["evidence_supported"]
        self.assertEqual(ev["overall"]["tp"], 1)
        self.assertEqual(ev["tiers"]["tier_counts"].get("differential_reproduced"), 1)


# --- REQUIRED negative control: unavailable vs genuine zero -----------------

class NegativeControlTests(unittest.TestCase):
    def test_no_evidence_instrumentation_reports_unavailable_not_zero(self):
        manifest = _manifest([_record("EX1", expected=["sqli"])])
        findings = [_finding("f1", "EX1", "sql injection")]
        # Nothing supplied at all: no proofs, no cases, no artifacts.
        report = score_with_evidence(manifest, findings, [], [], [])
        ev = report["evidence_supported"]
        self.assertEqual(ev["status"], "unavailable")
        self.assertIsNone(ev["overall"]["precision"])
        self.assertIsNone(ev["overall"]["recall"])
        self.assertIsNone(ev["overall"]["tp"])
        self.assertEqual(ev["tiers"]["status"], "unavailable")

    def test_instrumented_run_with_nothing_supported_is_a_distinct_genuine_zero(self):
        # Instrumentation IS present this run (non-trivial cases/artifacts)
        # but every claim fails the audit -- a REAL zero, never "unavailable".
        manifest = _manifest([_record("EX1", expected=["sqli"])])
        findings = [_finding("f1", "EX1", "sql injection", proof_id="", case_id="")]
        cases = [_case(case_id="unrelated", finding_ref="other")]
        artifacts = [_artifact(artifact_id="unrelated_a")]
        report = score_with_evidence(manifest, findings, [], cases, artifacts)
        ev = report["evidence_supported"]
        self.assertEqual(ev["status"], "computed")
        self.assertEqual(ev["overall"]["precision"], 0.0)
        self.assertEqual(ev["overall"]["recall"], 0.0)
        self.assertIsNotNone(ev["overall"]["tp"])

    def test_no_hook_sentinel_still_reaches_strict_score_unchanged(self):
        # build_evidence_grade_hook's None branch must compose transparently
        # with strict_score's own pre-existing (PR-3) no-hook behaviour.
        manifest = _manifest([_record("EX1", expected=["sqli"])])
        hook, tier_report = build_evidence_grade_hook([], [], [], [])
        self.assertIsNone(hook)
        self.assertEqual(tier_report["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
