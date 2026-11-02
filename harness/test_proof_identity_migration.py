"""AR-08a: the versioned, additive proof_identity migration.

The "old" database is the frozen pre-I02-C schema (testing_fixtures/
state_schema_pre_i02c.sql) plus a legacy structured jwt_forge proof row with no
fingerprint. The new store opens it. Positive: the side table and its marker
appear, proof_records and every legacy row are unchanged, nothing is backfilled,
and the legacy proof reads back with policy "" (unknown). Control: two legacy
proofs of one mechanism on two routes stay two issues, never merged on a guess.
Rollback: dropping the table and its marker restores the legacy schema exactly,
the previous build's proof read still works, and a re-migrated store reads the
rolled-back proof as unknown rather than failing. The caller-level grouping proof
(real confirm path, real store reads) is in test_proof_identity.
"""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from harness import store
from harness.assessment_health import confirmed_issue_accounting
from harness.evidence import ProofRecord, TestCaseRef
from harness.models import Finding, HttpExchange
from harness.test_observation_migration import _LEGACY_SQL, _legacy_identity, _schema

_HOST = "https://legacy.example"
_RUN = "run-legacy"
_POLICY = "jwt-policy-fp"


def _case(path: str) -> TestCaseRef:
    return TestCaseRef.make(run_id=_RUN, request_template_id=f"GET {path}", check_id="jwt",
                            principal_id="captured")


def _legacy_proof_row(proof_id: str, case: TestCaseRef) -> tuple:
    # The previous build's INSERT: a structured, executed jwt_forge proof.
    return (proof_id, case.run_id, case.case_id, case.principal_id, case.request_template_id,
            case.check_id, "", "", "", "", "jwt_forge", "1", "confirmed", 1, 0,
            f"{proof_id}-b", f"{proof_id}-a", f'["{proof_id}-c"]', "", "", "", 1.0)


def _finding(path: str, case: TestCaseRef, proof_id: str) -> dict:
    # A finding as store.all_host_findings returns it: no header_fingerprint key.
    return {"url": _HOST + path, "vulnerability_class": "jwt", "confirmed": True, "agent": "jwt_forge",
            "case_id": case.case_id, "proof_id": proof_id, "finding_id": f"f-{proof_id}"}


class ProofIdentityMigrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ar08a_migration_")
        self._orig = store._DB_PATH
        self.db = Path(self._tmp) / "legacy.db"
        self.cases = {"/api/me": _case("/api/me"), "/api/orders": _case("/api/orders")}
        conn = sqlite3.connect(self.db)
        try:
            conn.executescript(_LEGACY_SQL.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO state_metadata VALUES ('principal-hmac-v1', ?)", ("11" * 32,))
            for n, case in enumerate(self.cases.values()):
                conn.execute(f"INSERT INTO proof_records ({store._PROOF_COLUMNS}) VALUES "
                             f"({','.join('?' * 22)})", _legacy_proof_row(f"legacy-{n}", case))
            conn.commit()
            self.before = _legacy_identity(conn)
        finally:
            conn.close()
        store._DB_PATH = self.db

    def tearDown(self):
        store._DB_PATH = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _open(self) -> sqlite3.Connection:
        store._connect().close()
        return sqlite3.connect(self.db)

    def _new_proof(self, policy: str = _POLICY) -> ProofRecord:
        proof = ProofRecord.from_validation_result(
            case=_case("/api/new"), validator="jwt_forge", status="confirmed", confirmed=True,
            validator_version="1", executed=True, baseline_artifact_id="b", attack_artifact_id="a",
            control_artifact_ids=("c",), policy_fingerprint=policy)
        ok, why = store.persist_proof_record(proof)
        self.assertTrue(ok, why)
        return proof

    def test_migration_is_additive_versioned_and_backfills_nothing(self):
        conn = self._open()
        try:
            self.assertIn("proof_identity", _schema(conn))
            self.assertEqual(conn.execute("SELECT value FROM state_metadata WHERE name = "
                                          "'proof-identity-schema'").fetchone(), ("1",))
            after = _legacy_identity(conn)
            self.assertEqual(after["schema"]["proof_records"], self.before["schema"]["proof_records"])
            self.assertEqual(after["user_version"], 3)
            self.assertEqual(after["rows"]["proof_records"], self.before["rows"]["proof_records"])
            self.assertEqual(conn.execute("SELECT count(*) FROM proof_identity").fetchone()[0], 0)
        finally:
            conn.close()

    def test_legacy_proof_reads_back_with_unknown_policy(self):
        self._open().close()
        for case in self.cases.values():
            (proof,) = store.proofs_for_case(case.case_id)
            self.assertEqual(proof["policy_fingerprint"], "")
            self.assertEqual(ProofRecord.from_dict(proof).policy_fingerprint, "")
        self.assertEqual({p["policy_fingerprint"] for p in store.proofs_for_run(_RUN)}, {""})

    def test_legacy_proofs_without_fingerprint_are_never_merged(self):
        self._open().close()
        findings = [_finding(path, case, f"legacy-{n}") for n, (path, case) in enumerate(self.cases.items())]
        acc = confirmed_issue_accounting(findings, _RUN, store.proofs_for_case,
                                         run_proofs=store.proofs_for_run(_RUN),
                                         artifact_resolver=lambda proof: True)
        self.assertEqual(acc["counts"]["vulnerabilities"], 2, acc["groups"])
        self.assertEqual({g["identity"]["policy_fingerprint"] for g in acc["groups"]}, {""})

    def test_new_proof_round_trips_its_fingerprint_and_reopen_is_idempotent(self):
        proof = self._new_proof()
        (stored,) = store.proofs_for_case(proof.case.case_id)
        self.assertEqual(stored["policy_fingerprint"], _POLICY)
        self.assertEqual(ProofRecord.from_dict(stored), proof)
        first = self._open()
        try:
            schema = _schema(first)
        finally:
            first.close()
        store._INITIALISED.clear()   # force the full setup to run again
        second = self._open()
        try:
            self.assertEqual(_schema(second), schema)
            self.assertEqual(second.execute("SELECT count(*) FROM state_metadata WHERE name = "
                                            "'proof-identity-schema'").fetchone()[0], 1)
            self.assertEqual(second.execute("SELECT count(*) FROM proof_identity").fetchone()[0], 1)
        finally:
            second.close()

    def test_proof_without_policy_writes_no_identity_row(self):
        proof = self._new_proof(policy="")
        (stored,) = store.proofs_for_case(proof.case.case_id)
        self.assertEqual(stored["policy_fingerprint"], "")
        conn = sqlite3.connect(self.db)
        try:
            self.assertEqual(conn.execute("SELECT count(*) FROM proof_identity").fetchone()[0], 0)
        finally:
            conn.close()

    def test_unknown_identity_version_reads_as_unknown(self):
        proof = self._new_proof()
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("UPDATE proof_identity SET identity_version = ?", (store._PROOF_IDENTITY_VERSION + 1,))
            conn.commit()
        finally:
            conn.close()
        (stored,) = store.proofs_for_case(proof.case.case_id)
        self.assertEqual(stored["policy_fingerprint"], "")

    def test_rollback_restores_the_legacy_store_and_degrades_safely(self):
        proof = self._new_proof()
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("DROP TABLE proof_identity")
            conn.execute("DELETE FROM state_metadata WHERE name = 'proof-identity-schema'")
            conn.execute("DROP TABLE engagement_declarations")
            conn.execute("DELETE FROM state_metadata WHERE name = 'engagement-declarations-schema'")
            conn.execute("DROP TABLE exchange_observations")
            conn.execute("DROP TABLE observation_attributions")
            conn.execute("DELETE FROM state_metadata WHERE name = 'observation-schema'")
            conn.commit()
            after = _legacy_identity(conn)
            # The previous build's proof read (no join) still works on the rolled-back file.
            self.assertEqual(conn.execute(f"SELECT {store._PROOF_COLUMNS} FROM proof_records "
                                          "WHERE proof_id = ?", (proof.proof_id,)).fetchone()[0],
                             proof.proof_id)
        finally:
            conn.close()
        self.assertEqual(after["schema"], self.before["schema"])
        self.assertEqual(after["user_version"], self.before["user_version"])
        # Only the proof written while migrated remains, as an ordinary proof row.
        rows = dict(after["rows"])
        self.assertEqual(len(rows.pop("proof_records")), len(self.before["rows"]["proof_records"]) + 1)
        before_rows = dict(self.before["rows"])
        before_rows.pop("proof_records")
        self.assertEqual(rows, before_rows)
        # Re-migrating recreates the table; the rolled-back fingerprint is lost, so
        # the proof reads as unknown (never merged), not as an error.
        (stored,) = store.proofs_for_case(proof.case.case_id)
        self.assertEqual(stored["policy_fingerprint"], "")

    def test_wipe_engagement_removes_the_proof_fingerprint(self):
        proof = self._new_proof()
        exchange = HttpExchange(url=_HOST + "/api/new", method="GET", response_status=200)
        store.persist_findings(exchange, "jwt_forge", [Finding(
            vulnerability_class="jwt", confidence=0.9, summary="s", evidence="e", suggested_test="t",
            basis="derived", case_id=proof.case.case_id, proof_id=proof.proof_id)])
        counts = store.wipe_engagement("legacy.example")
        self.assertEqual(counts["proof_identity"], 1)
        conn = sqlite3.connect(self.db)
        try:
            self.assertEqual(conn.execute("SELECT count(*) FROM proof_identity").fetchone()[0], 0)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
