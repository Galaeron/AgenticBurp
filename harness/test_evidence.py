"""Tests for Astra T01 -- case-bound structured proof (evidence.py + store).

Covers the handoff's required checks: two same-class findings receive only their
own proof; serialization/store round-trip; unknown case rejected; an error cannot
become a controlled_negative; a later inconclusive attempt preserves the earlier
proof; legacy data remains readable after the additive migration.
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence
import store
from evidence import ExchangeArtifact, ProofLedger, ProofRecord, TestCaseRef, Verdict


def _case(**over) -> TestCaseRef:
    base = dict(run_id="run1", request_template_id="tmpl1", check_id="sqli", principal_id="alice")
    base.update(over)
    return TestCaseRef.make(**base)


class VerdictTests(unittest.TestCase):
    def test_status_mapping(self):
        self.assertEqual(Verdict.from_validation("confirmed", True), Verdict.CONFIRMED)
        self.assertEqual(Verdict.from_validation("not_confirmed", False), Verdict.INCONCLUSIVE)
        self.assertEqual(
            Verdict.from_validation("not_confirmed", False, controlled=True, executed=True),
            Verdict.CONTROLLED_NEGATIVE,
        )
        self.assertEqual(Verdict.from_validation("error", False), Verdict.ERROR)
        self.assertEqual(Verdict.from_validation("skipped", False), Verdict.INCONCLUSIVE)
        self.assertEqual(Verdict.from_validation("confirmed", True, blocked=True), Verdict.BLOCKED)

    def test_error_never_controlled_negative(self):
        # A failed leg is not evidence the boundary held.
        self.assertEqual(Verdict.from_validation("error", False), Verdict.ERROR)
        # And you cannot construct one directly from a non-executed leg.
        with self.assertRaises(ValueError):
            ProofRecord(proof_id="", case=_case(), validator="v",
                        verdict=Verdict.CONTROLLED_NEGATIVE, executed=False)

    def test_controlled_negative_requires_control_artifact(self):
        with self.assertRaises(ValueError):
            ProofRecord(proof_id="", case=_case(), validator="v",
                        verdict=Verdict.CONTROLLED_NEGATIVE, executed=True)

    def test_confirmed_requires_execution(self):
        with self.assertRaises(ValueError):
            ProofRecord(proof_id="", case=_case(), validator="v",
                        verdict=Verdict.CONFIRMED, executed=False)
        # executed=True is accepted.
        p = ProofRecord(proof_id="", case=_case(), validator="v",
                        verdict=Verdict.CONFIRMED, executed=True)
        self.assertTrue(p.confirmed)

    def test_rank_orders_strength(self):
        self.assertGreater(Verdict.CONFIRMED.rank(), Verdict.CONTROLLED_NEGATIVE.rank())
        self.assertGreater(Verdict.CONTROLLED_NEGATIVE.rank(), Verdict.INCONCLUSIVE.rank())
        self.assertGreater(Verdict.INCONCLUSIVE.rank(), Verdict.ERROR.rank())


class CaseIdentityTests(unittest.TestCase):
    def test_distinct_parameter_distinct_case(self):
        a = _case(parameter_location="query", parameter_name="q")
        b = _case(parameter_location="query", parameter_name="sort")
        self.assertNotEqual(a.case_id, b.case_id)

    def test_same_scenario_same_case(self):
        self.assertEqual(_case().case_id, _case().case_id)  # deterministic, re-test = same case

    def test_distinct_principal_distinct_case(self):
        self.assertNotEqual(_case(principal_id="alice").case_id, _case(principal_id="bob").case_id)

    def test_consistency_detects_forged_case(self):
        good = _case()
        self.assertTrue(good.consistent)
        forged = TestCaseRef(run_id="run1", request_template_id="tmpl1", check_id="sqli",
                             principal_id="alice", case_id="deadbeefdeadbeef")  # wrong id
        self.assertFalse(forged.consistent)


class RoundTripTests(unittest.TestCase):
    def test_case_roundtrip(self):
        c = _case(parameter_location="body_json", parameter_name="/user/role")
        self.assertEqual(TestCaseRef.from_dict(c.to_dict()), c)

    def test_artifact_roundtrip(self):
        a = ExchangeArtifact.make(request_ref="r1", response_ref="s1",
                                  actual_destination="https://t.local", transport_outcome="ok")
        self.assertEqual(ExchangeArtifact.from_dict(a.to_dict()), a)

    def test_proof_roundtrip(self):
        p = ProofRecord.from_validation_result(
            case=_case(), validator="sqlmap", status="confirmed", confirmed=True,
            observed_result="boolean differential", expected_invariant="SQL evaluated")
        back = ProofRecord.from_dict(p.to_dict())
        self.assertEqual(back.proof_id, p.proof_id)
        self.assertEqual(back.verdict, Verdict.CONFIRMED)
        self.assertEqual(back.case, p.case)
        self.assertTrue(back.executed)
        self.assertTrue(back.legacy)
        self.assertIn("legacy/unstructured", back.limitation)

    def test_structured_controlled_negative_requires_explicit_execution_and_control(self):
        kwargs = dict(case=_case(), validator="cross_identity", status="not_confirmed",
                      confirmed=False, controlled=True, control_artifact_ids=("control-1",))
        implicit = ProofRecord.from_validation_result(**kwargs)
        self.assertEqual(implicit.verdict, Verdict.INCONCLUSIVE)
        explicit = ProofRecord.from_validation_result(**kwargs, executed=True)
        self.assertEqual(explicit.verdict, Verdict.CONTROLLED_NEGATIVE)
        self.assertFalse(explicit.legacy)

    def test_legacy_confirmed_is_flagged_not_fabricated(self):
        p = ProofRecord.legacy_confirmed(case=_case(), validator="cross_identity")
        self.assertTrue(p.legacy)
        self.assertEqual(p.verdict, Verdict.CONFIRMED)
        # No fabricated attack/baseline/control evidence.
        self.assertEqual(p.attack_artifact_id, "")
        self.assertEqual(p.baseline_artifact_id, "")
        self.assertEqual(p.control_artifact_ids, ())
        self.assertIn("legacy", p.limitation.lower())


class LedgerTests(unittest.TestCase):
    def test_two_same_class_findings_get_own_proof(self):
        # Same class + endpoint, different parameter -> two distinct cases.
        ca = _case(parameter_location="query", parameter_name="id")
        cb = _case(parameter_location="query", parameter_name="ref")
        ledger = ProofLedger()
        ledger.record(ProofRecord.from_validation_result(
            case=ca, validator="sqlmap", status="confirmed", confirmed=True))
        ledger.record(ProofRecord.from_validation_result(
            case=cb, validator="sqlmap", status="not_confirmed", confirmed=False))
        self.assertEqual(len(ledger.proofs_for(ca.case_id)), 1)
        self.assertEqual(len(ledger.proofs_for(cb.case_id)), 1)
        self.assertEqual(ledger.best_proof(ca.case_id).verdict, Verdict.CONFIRMED)
        self.assertEqual(ledger.best_proof(cb.case_id).verdict, Verdict.INCONCLUSIVE)

    def test_later_inconclusive_preserves_earlier_confirmed(self):
        c = _case()
        ledger = ProofLedger()
        ledger.record(ProofRecord.from_validation_result(
            case=c, validator="sqlmap", status="confirmed", confirmed=True))
        ledger.record(ProofRecord.from_validation_result(
            case=c, validator="sqlmap", status="skipped", confirmed=False))  # later, weaker
        self.assertEqual(len(ledger.proofs_for(c.case_id)), 2)          # history kept
        self.assertEqual(ledger.best_proof(c.case_id).verdict, Verdict.CONFIRMED)  # not downgraded

    def test_rejects_unknown_case(self):
        forged = TestCaseRef(run_id="run1", request_template_id="tmpl1", check_id="sqli",
                             case_id="0000000000000000")
        p = ProofRecord(proof_id="", case=forged, validator="v",
                        verdict=Verdict.INCONCLUSIVE, executed=False)
        with self.assertRaises(ValueError):
            ProofLedger().record(p)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "t.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_persist_and_roundtrip(self):
        p = ProofRecord.from_validation_result(
            case=_case(), validator="sqlmap", status="confirmed", confirmed=True,
            observed_result="diff", expected_invariant="SQL evaluated")
        ok, reason = store.persist_proof_record(p)
        self.assertTrue(ok, reason)
        rows = store.proofs_for_case(p.case.case_id)
        self.assertEqual(len(rows), 1)
        back = ProofRecord.from_dict(rows[0])
        self.assertEqual(back.proof_id, p.proof_id)
        self.assertEqual(back.verdict, Verdict.CONFIRMED)
        self.assertEqual(back.case.case_id, p.case.case_id)

    def test_unknown_case_rejected(self):
        forged = TestCaseRef(run_id="run1", request_template_id="tmpl1", check_id="sqli",
                             case_id="ffffffffffffffff")
        p = ProofRecord(proof_id="", case=forged, validator="v",
                        verdict=Verdict.ERROR, executed=True)
        ok, reason = store.persist_proof_record(p)
        self.assertFalse(ok)
        self.assertEqual(reason, "unknown_or_forged_case")

    def test_best_proof_selects_strongest_regardless_of_order(self):
        c = _case()
        store.persist_proof_record(ProofRecord.from_validation_result(
            case=c, validator="sqlmap", status="confirmed", confirmed=True))
        store.persist_proof_record(ProofRecord.from_validation_result(
            case=c, validator="sqlmap", status="skipped", confirmed=False))  # later, weaker
        best = store.best_proof_for_case(c.case_id)
        self.assertEqual(best["verdict"], Verdict.CONFIRMED.value)
        self.assertEqual(len(store.proofs_for_case(c.case_id)), 2)

    def test_additive_migration_preserves_legacy_data(self):
        # Old-world data written before the proof table exists...
        self.assertTrue(store.save_knowledge_note(["legacy"], "pre-T01 note"))
        # ...simulate a database from before T01 by dropping the new table...
        conn = store._connect()
        conn.execute("DROP TABLE proof_records")
        conn.commit()
        conn.close()
        # ...a T01 write heals the schema (CREATE TABLE IF NOT EXISTS) and succeeds,
        # and the legacy note is still readable.
        ok, reason = store.persist_proof_record(ProofRecord.from_validation_result(
            case=_case(), validator="sqlmap", status="confirmed", confirmed=True))
        self.assertTrue(ok, reason)
        notes = store.list_knowledge_notes()
        self.assertTrue(any("pre-T01 note" in (n.get("note", "")) for n in notes))


class _FakeValidator:
    """Minimal validator: returns a fixed ValidationResult (or raises)."""
    def __init__(self, name, status, confirmed, raise_exc=False):
        self.name = name
        self._status, self._confirmed, self._raise = status, confirmed, raise_exc

    def plan(self, finding, exchange):
        return None  # no test-plan -> skip the validation_runs submission path

    async def validate(self, finding, exchange):
        if self._raise:
            raise RuntimeError("boom")
        from validators.base import ValidationResult
        return ValidationResult(validator=self.name, status=self._status,
                                finding_class=finding.vulnerability_class,
                                confidence=0.9 if self._confirmed else 0.2,
                                confirmed=self._confirmed, summary="s", evidence="e")


class _FakeRegistry:
    def __init__(self, mapping):
        self._mapping = mapping

    def for_finding(self, finding, exchange):
        v = self._mapping.get(finding.vulnerability_class)
        return [v] if v else []


class ValidateFindingsWiringTests(unittest.TestCase):
    """The T01 'Done' bar: the PRODUCTION confirmation path (_validate_findings)
    persists structured proofs and returns them through the response data -- not
    just a dataclass held in memory."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "t.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _exchange(self):
        from models import HttpExchange
        return HttpExchange(url="http://t.local/api/item?id=1", method="GET")

    def _reports(self, *classes):
        from models import AgentReport, Finding
        findings = [Finding(vulnerability_class=c, confidence=0.7, summary="s", evidence="e",
                            suggested_test="t", basis="derived") for c in classes]
        return [AgentReport(agent="a", model="m", findings=findings)]

    def _run(self, reports, exchange, registry):
        import orchestrator
        orch = orchestrator.Orchestrator.__new__(orchestrator.Orchestrator)
        orch.validator_registry = registry
        return asyncio.run(orch._validate_findings(exchange, reports))

    def test_confirmed_result_persists_and_returns_proof(self):
        reg = _FakeRegistry({"sqli": _FakeValidator("sqlmap", "confirmed", True)})
        vreports, proofs = self._run(self._reports("sqli"), self._exchange(), reg)
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0]["verdict"], "confirmed")
        case_id = proofs[0]["case"]["case_id"]
        # Persisted (returned through report/API data AND written to the store).
        self.assertEqual(len(store.proofs_for_case(case_id)), 1)
        self.assertEqual(store.best_proof_for_case(case_id)["verdict"], "confirmed")

    def test_legacy_not_confirmed_is_inconclusive(self):
        reg = _FakeRegistry({"idor": _FakeValidator("cross_identity", "not_confirmed", False)})
        _, proofs = self._run(self._reports("idor"), self._exchange(), reg)
        self.assertEqual(proofs[0]["verdict"], "inconclusive")
        self.assertTrue(proofs[0]["legacy"])
        self.assertIn("legacy/unstructured", proofs[0]["limitation"])

    def test_retired_observation_is_not_a_secure_boundary(self):
        reg = _FakeRegistry({"csrf": _FakeValidator("csrf", "not_confirmed", False)})
        _, proofs = self._run(self._reports("csrf"), self._exchange(), reg)
        self.assertEqual(proofs[0]["verdict"], "inconclusive")
        self.assertFalse(proofs[0]["confirmed"] if "confirmed" in proofs[0] else False)

    def test_errored_validator_is_error_not_controlled_negative(self):
        reg = _FakeRegistry({"xxe": _FakeValidator("xxe", "confirmed", True, raise_exc=True)})
        vreports, proofs = self._run(self._reports("xxe"), self._exchange(), reg)
        self.assertEqual(len(vreports), 0)                 # crashed leg -> no validation report
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0]["verdict"], "error")    # honestly recorded, never controlled_negative

    def test_persistence_rejection_is_surfaced_and_not_returned_as_durable(self):
        reg = _FakeRegistry({"sqli": _FakeValidator("sqlmap", "confirmed", True)})
        with patch("store.persist_proof_record", return_value=(False, "disk_unavailable")):
            vreports, proofs = self._run(self._reports("sqli"), self._exchange(), reg)
        self.assertEqual(proofs, [])
        self.assertEqual(vreports[0].status, "error")
        self.assertFalse(vreports[0].confirmed)
        self.assertIn("disk_unavailable", vreports[0].summary)

    def test_distinct_classes_get_distinct_cases(self):
        reg = _FakeRegistry({"sqli": _FakeValidator("sqlmap", "confirmed", True),
                             "xss": _FakeValidator("browser_xss", "not_confirmed", False)})
        _, proofs = self._run(self._reports("sqli", "xss"), self._exchange(), reg)
        self.assertEqual(len({p["case"]["case_id"] for p in proofs}), 2)

    def test_no_validators_returns_empty_pair(self):
        vreports, proofs = self._run(self._reports("sqli"), self._exchange(), _FakeRegistry({}))
        self.assertEqual((vreports, proofs), ([], []))


if __name__ == "__main__":
    unittest.main()
