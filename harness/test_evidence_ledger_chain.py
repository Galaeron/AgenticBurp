"""ARC-13: the durable evidence ledger is hash-chained and verifiable, and
`put_evidence_blob` asserts that what it is given was redacted.

Every test writes through the REAL path (`evidence_ledger.emit` ->
`store.persist_ledger_event`, or a real `TargetTransport.execute` send against a
mocked HTTP transport) into a throwaway store, then tampers with the file the way
an operator with sqlite3 would and runs the verifier. Negative controls:
  - `test_negative_control_content_blind_hash_misses_the_edit`: with the row hash
    made content-blind (the chain check bypassed) the same edit verifies.
  - `test_negative_control_unchained_rows_hide_the_edit`: the same edit on a row
    with no hash is invisible, so detection comes from the chain.
  - `test_negative_control_bypassed_assertion_stores_the_secret`: with the
    redaction check bypassed, a refuse-policy store keeps the unredacted blob.
"""
from __future__ import annotations

import io
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import httpx

from harness import evidence_ledger, evidence_redaction, security, store
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext, TypedRequest

ROOT = Path(__file__).resolve().parent.parent
EL = evidence_ledger


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_db = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "chain_t.db"
        self.db = store._DB_PATH

    def tearDown(self):
        store._DB_PATH = self._orig_db
        shutil.rmtree(self._tmp, ignore_errors=True)

    def emit_many(self, ref: str, count: int, *, start: int = 0) -> None:
        for i in range(start, start + count):
            EL.emit(EL.EventType.OBSERVATION, ref, f"event {i}", data={"i": i, "note": "é✓"})

    def sql(self, statement: str, params=()):
        conn = sqlite3.connect(self.db)
        try:
            rows = conn.execute(statement, params).fetchall()
            conn.commit()
            return rows
        finally:
            conn.close()

    def verify(self, **kw) -> dict:
        return EL.verify_ledger(self.db, **kw)

    def event_ids(self, ref: str) -> list:
        return [r[0] for r in self.sql(
            "SELECT event_id FROM ledger_events WHERE finding_ref = ? ORDER BY seq", (ref,))]


class ChainWriteTests(_StoreCase):
    def test_rows_are_chained_per_finding_through_the_real_emit_path(self):
        self.emit_many("f1", 3)
        self.emit_many("f2", 2)
        self.emit_many("f1", 1, start=3)
        rows = self.sql("SELECT finding_ref, seq, prev_hash, row_hash FROM ledger_events ORDER BY seq")
        self.assertEqual([r[1] for r in rows], [1, 2, 3, 4, 5, 6])
        by_ref = {}
        for ref, _seq, prev, row_hash in rows:
            self.assertEqual(len(row_hash), 64)
            self.assertEqual(prev, by_ref.get(ref, ""), "prev_hash must be the finding's previous row_hash")
            by_ref[ref] = row_hash
        report = self.verify()
        self.assertTrue(report["ok"], report)
        self.assertEqual((report["rows"], report["chained"], report["legacy_unchained"], report["findings"]),
                         (6, 6, 0, 2))
        self.assertIsNone(report["first_bad"])

    def test_re_persisting_an_event_is_a_no_op_and_does_not_fork_the_chain(self):
        event = EL.emit(EL.EventType.OBSERVATION, "f1", "once")
        before = self.sql("SELECT seq, row_hash FROM ledger_events")
        store.persist_ledger_event(event.to_dict())
        store.persist_ledger_event(event.to_dict())
        self.assertEqual(self.sql("SELECT seq, row_hash FROM ledger_events"), before)
        self.emit_many("f1", 1, start=1)
        self.assertTrue(self.verify()["ok"])

    def test_read_path_row_shape_is_unchanged(self):
        self.emit_many("f1", 1)
        self.assertEqual(
            set(store.ledger_events_for("f1")[0]),
            {"event_id", "event_type", "finding_ref", "case_ref", "summary", "data", "provenance",
             "created_at"})
        self.assertEqual(len(EL.ledger_from_store("f1").events_for("f1")), 1)

    def test_concurrent_writers_cannot_fork_the_chain(self):
        errors = []

        def writer(ref: str, n: int):
            try:
                for i in range(n):
                    EL.emit(EL.EventType.OBSERVATION, ref, f"{ref} {i}")
            except Exception as exc:       # pragma: no cover - surfaced by the assert below
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=("shared", 12)) for _ in range(6)]
        threads += [threading.Thread(target=writer, args=(f"own-{k}", 8)) for k in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        report = self.verify()
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["chained"], 6 * 12 + 3 * 8)
        seqs = [r[0] for r in self.sql("SELECT seq FROM ledger_events ORDER BY seq")]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)), "seq must be unique and gap free")
        prevs = [r[0] for r in self.sql("SELECT prev_hash FROM ledger_events WHERE finding_ref = 'shared'")]
        self.assertEqual(len(prevs), len(set(prevs)), "two rows share a prev_hash: the chain forked")

    def test_wiping_one_finding_leaves_every_other_chain_valid(self):
        for host, case in (("a.example.com", "case-A"), ("b.example.com", "case-B")):
            exchange = HttpExchange(url=f"https://{host}/x", method="GET", request_headers={},
                                    request_body="", response_status=200, response_headers={},
                                    response_body="")
            store.persist_findings(exchange, "agent", [Finding(
                vulnerability_class="sqli", confidence=0.9, summary="s", evidence="e",
                suggested_test="t", basis="derived", case_id=case, finding_id=f"fid-{case}",
                proof_id=f"proof-{case}")])
            self.emit_many(case, 3)
        self.assertTrue(self.verify()["ok"])
        counts = store.wipe_engagement("a.example.com")
        self.assertEqual(counts["ledger_events"], 3)
        report = self.verify()
        self.assertTrue(report["ok"], report)
        self.assertEqual((report["chained"], report["findings"]), (3, 1))


class TamperDetectionTests(_StoreCase):
    def setUp(self):
        super().setUp()
        self.emit_many("f1", 5)
        self.emit_many("f2", 2)
        self.ids = self.event_ids("f1")
        self.assertTrue(self.verify()["ok"])

    def assertBadAt(self, report, event_id, reason):
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["first_bad"]["event_id"], event_id, report)
        self.assertIn(reason, report["first_bad"]["reasons"], report)

    def test_edited_summary_is_named(self):
        self.sql("UPDATE ledger_events SET summary = 'forged' WHERE event_id = ?", (self.ids[2],))
        report = self.verify()
        self.assertBadAt(report, self.ids[2], "hash-mismatch")
        self.assertEqual(report["problem_count"], 1, "one edit must be one problem, not a cascade")

    def test_every_hashed_column_is_covered(self):
        for column, value in (("data_json", '{"i": 99}'), ("provenance_json", '{"model": "x"}'),
                              ("event_type", "execution"), ("case_ref", "other"),
                              ("engagement_id", "eng-X"), ("captured_principal_id", "p-9"),
                              ("created_at", 1.5), ("finding_ref", "f2")):
            with self.subTest(column=column):
                original = self.sql(f"SELECT {column} FROM ledger_events WHERE event_id = ?",
                                    (self.ids[1],))[0][0]
                self.sql(f"UPDATE ledger_events SET {column} = ? WHERE event_id = ?", (value, self.ids[1]))
                report = self.verify()
                self.assertFalse(report["ok"], f"editing {column} went undetected")
                self.assertEqual(report["first_bad"]["event_id"], self.ids[1])
                self.sql(f"UPDATE ledger_events SET {column} = ? WHERE event_id = ?", (original, self.ids[1]))
                self.assertTrue(self.verify()["ok"], f"restoring {column} should verify again")

    def test_deleted_middle_row_is_named_at_the_row_after_the_gap(self):
        self.sql("DELETE FROM ledger_events WHERE event_id = ?", (self.ids[2],))
        self.assertBadAt(self.verify(), self.ids[3], "prev-mismatch")

    def test_deleted_first_row_is_a_missing_predecessor(self):
        self.sql("DELETE FROM ledger_events WHERE event_id = ?", (self.ids[0],))
        self.assertBadAt(self.verify(), self.ids[1], "missing-predecessor")

    def test_inserted_row_with_a_valid_own_hash_still_breaks_the_chain(self):
        rows = self.sql("SELECT row_hash, seq FROM ledger_events WHERE event_id = ?", (self.ids[1],))
        anchor_hash, anchor_seq = rows[0]
        forged_hash = EL.ledger_row_hash(
            prev_hash=anchor_hash, seq=anchor_seq, event_id="forged-event", event_type="observation",
            finding_ref="f1", case_ref="", summary="inserted", data_json="{}", provenance_json="{}",
            engagement_id="", captured_principal_id="", created_at=7.0)
        # Same seq as the row it follows is the only slot a forger can pick without renumbering.
        self.sql("INSERT INTO ledger_events (event_id, event_type, finding_ref, case_ref, summary, "
                 "data_json, provenance_json, engagement_id, captured_principal_id, created_at, "
                 "seq, prev_hash, row_hash) VALUES ('forged-event', 'observation', 'f1', '', "
                 "'inserted', '{}', '{}', '', '', 7.0, ?, ?, ?)", (anchor_seq, anchor_hash, forged_hash))
        report = self.verify()
        self.assertFalse(report["ok"], report)
        reasons = {r for p in report["problems"] for r in p["reasons"]}
        self.assertTrue({"seq-not-increasing", "prev-mismatch"} & reasons, report)

    def test_reordered_rows_are_detected(self):
        a, b = self.ids[1], self.ids[2]
        seq_a, seq_b = (self.sql("SELECT seq FROM ledger_events WHERE event_id = ?", (e,))[0][0] for e in (a, b))
        self.sql("UPDATE ledger_events SET seq = ? WHERE event_id = ?", (seq_b, a))
        self.sql("UPDATE ledger_events SET seq = ? WHERE event_id = ?", (seq_a, b))
        report = self.verify()
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["first_bad"]["event_id"], b, "b now sorts first and fails its prev link")

    def test_first_bad_is_the_lowest_seq_when_several_rows_are_edited(self):
        self.sql("UPDATE ledger_events SET summary = 'x' WHERE event_id IN (?, ?)", (self.ids[3], self.ids[1]))
        report = self.verify()
        self.assertEqual(report["problem_count"], 2)
        self.assertEqual(report["first_bad"]["event_id"], self.ids[1])

    def test_a_row_turned_unchained_after_the_chain_started_is_flagged(self):
        self.sql("UPDATE ledger_events SET row_hash = '', prev_hash = '', seq = 0, "
                 "created_at = created_at + 1000 WHERE event_id = ?", (self.ids[2],))
        report = self.verify()
        self.assertFalse(report["ok"], report)
        reasons = {r for p in report["problems"] for r in p["reasons"]}
        self.assertIn("unchained-after-chain", reasons)
        self.assertEqual(report["first_bad"]["event_id"], self.ids[2])

    def test_malformed_values_are_reported_not_raised(self):
        self.sql("UPDATE ledger_events SET seq = 'abc' WHERE event_id = ?", (self.ids[1],))
        report = self.verify()
        self.assertFalse(report["ok"], report)
        reasons = {r for p in report["problems"] for r in p["reasons"]}
        self.assertIn("malformed-row", reasons)

    def test_digest_anchor_catches_removal_of_the_newest_row(self):
        digest = self.verify()["digest"]
        self.sql("DELETE FROM ledger_events WHERE event_id = ?", (self.ids[-1],))
        chain_only = self.verify()
        self.assertTrue(chain_only["ok"], "the chain alone cannot see a removed newest row")
        anchored = self.verify(expect_digest=digest)
        self.assertFalse(anchored["ok"])
        self.assertFalse(anchored["digest_matches"])
        self.assertTrue(self.verify(expect_digest=chain_only["digest"])["ok"])

    def test_negative_control_content_blind_hash_misses_the_edit(self):
        """With the chain check bypassed (a hash that ignores content), the same
        edit that test_edited_summary_is_named catches verifies cleanly."""
        shutil.rmtree(self._tmp)
        self._tmp = tempfile.mkdtemp()
        store._DB_PATH = self.db = Path(self._tmp) / "blind.db"
        with patch.object(EL, "ledger_row_hash", return_value="0" * 64):
            self.emit_many("f1", 5)
            self.assertTrue(self.verify()["ok"])
            ids = self.event_ids("f1")
            self.sql("UPDATE ledger_events SET summary = 'forged' WHERE event_id = ?", (ids[2],))
            report = self.verify()
        self.assertTrue(report["ok"], "bypassing the hash check must let the edit through: " + str(report))

    def test_negative_control_unchained_rows_hide_the_edit(self):
        self.sql("UPDATE ledger_events SET row_hash = '', prev_hash = '', seq = 0")
        self.sql("UPDATE ledger_events SET summary = 'forged' WHERE event_id = ?", (self.ids[2],))
        report = self.verify()
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["legacy_unchained"], 7)
        self.assertFalse(self.verify(strict=True)["ok"], "strict mode must not accept unchained rows")


class LegacyLedgerTests(_StoreCase):
    LEGACY_SCHEMA = """
        CREATE TABLE ledger_events (
            event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, finding_ref TEXT NOT NULL,
            case_ref TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '',
            data_json TEXT NOT NULL DEFAULT '{}', provenance_json TEXT NOT NULL DEFAULT '{}',
            engagement_id TEXT NOT NULL DEFAULT '', captured_principal_id TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL);
        CREATE INDEX idx_ledger_finding_ref ON ledger_events(finding_ref);
    """

    def make_legacy(self, count: int = 3) -> None:
        conn = sqlite3.connect(self.db)
        conn.executescript(self.LEGACY_SCHEMA)
        for i in range(count):
            conn.execute("INSERT INTO ledger_events (event_id, event_type, finding_ref, summary, "
                         "data_json, created_at) VALUES (?, 'observation', 'old', ?, '{}', ?)",
                         (f"old-{i}", f"legacy {i}", 100.0 + i))
        conn.commit()
        conn.close()

    def test_verifier_reads_a_store_that_predates_the_chain_without_touching_it(self):
        self.make_legacy()
        size = self.db.stat().st_size
        report = self.verify()
        self.assertTrue(report["ok"], report)
        self.assertEqual((report["rows"], report["chained"], report["legacy_unchained"]), (3, 0, 3))
        self.assertEqual(self.db.stat().st_size, size)
        cols = {r[1] for r in self.sql("PRAGMA table_info(ledger_events)")}
        self.assertNotIn("row_hash", cols, "the verifier must not migrate the file it inspects")
        self.assertFalse(self.verify(strict=True)["ok"])

    def test_legacy_rows_still_load_and_new_rows_chain_after_them(self):
        self.make_legacy()
        loaded = EL.ledger_from_store("old")
        self.assertEqual([e.summary for e in loaded.events_for("old")], ["legacy 0", "legacy 1", "legacy 2"])
        EL.emit(EL.EventType.OBSERVATION, "old", "new after legacy")
        EL.emit(EL.EventType.OBSERVATION, "old", "newer")
        report = self.verify()
        self.assertTrue(report["ok"], report)
        self.assertEqual((report["chained"], report["legacy_unchained"]), (2, 3))
        first = self.sql("SELECT prev_hash FROM ledger_events WHERE summary = 'new after legacy'")[0][0]
        self.assertEqual(first, "", "the first chained row of a finding with legacy history starts the chain")
        self.assertEqual(len(store.ledger_events_for("old")), 5)

    def test_a_legacy_row_appearing_after_chained_rows_is_flagged(self):
        self.make_legacy(1)
        EL.emit(EL.EventType.OBSERVATION, "old", "chained")
        self.sql("INSERT INTO ledger_events (event_id, event_type, finding_ref, summary, data_json, "
                 "created_at) VALUES ('smuggled', 'observation', 'old', 'late', '{}', ?)",
                 (time.time() + 60,))
        report = self.verify()
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["first_bad"]["event_id"], "smuggled")
        self.assertEqual(report["first_bad"]["reasons"], ["unchained-after-chain"])

    def test_known_limit_a_back_dated_unchained_row_reads_as_legacy(self):
        """Pins the documented limit: an unchained row cannot be told from real legacy
        data when its timestamp predates the chain. It is counted, and strict fails it."""
        self.make_legacy(1)
        EL.emit(EL.EventType.OBSERVATION, "old", "chained")
        self.sql("INSERT INTO ledger_events (event_id, event_type, finding_ref, summary, data_json, "
                 "created_at) VALUES ('backdated', 'observation', 'old', 'forged', '{}', 5.0)")
        report = self.verify()
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["legacy_unchained"], 2)
        self.assertFalse(self.verify(strict=True)["ok"])


class RedactionAssertionTests(_StoreCase):
    SECRET_BLOB = json.dumps({"method": "POST", "url": "https://a.test/login?token=abc123",
                              "headers": {"Authorization": "Bearer abc.def.ghi"},
                              "body": '{"password": "hunter2"}'}).encode()

    def test_a_correctly_redacted_blob_is_stored_without_a_flag(self):
        record = {"method": "POST",
                  "url": security.redact_secrets_in_url("https://a.test/login?token=abc123"),
                  "headers": security.redact_headers({"Authorization": "Bearer abc.def.ghi",
                                                      "Cookie": "sid=1", "Accept": "*/*"}),
                  "body": security.redact_secrets_in_body('{"password": "hunter2", "user": "bob"}')}
        self.assertEqual(evidence_redaction.redaction_findings(json.dumps(record).encode()), [])
        before = store.evidence_blob_redaction_status()["unredacted_flags"]
        digest = store.put_evidence_blob(json.dumps(record, sort_keys=True).encode())
        self.assertTrue(store.evidence_blob_resolves(digest))
        self.assertEqual(store.evidence_blob_redaction_status()["unredacted_flags"], before)

    def test_findings_name_kinds_and_paths_never_values(self):
        findings = evidence_redaction.redaction_findings(self.SECRET_BLOB)
        kinds = {kind for kind, _ in findings}
        self.assertEqual(kinds, {evidence_redaction.SECRET_FIELD, evidence_redaction.SECRET_URL,
                                 evidence_redaction.SECRET_BODY})
        flat = json.dumps(findings)
        for secret in ("abc123", "hunter2", "abc.def.ghi"):
            self.assertNotIn(secret, flat)

    def test_default_policy_flags_stores_and_logs_without_the_value(self):
        self.assertEqual(store.EVIDENCE_BLOB_UNREDACTED_POLICY, "flag")
        before = store.evidence_blob_redaction_status()["unredacted_flags"]
        with self.assertLogs("harness.store", level="WARNING") as logs:
            digest = store.put_evidence_blob(self.SECRET_BLOB)
        self.assertTrue(store.evidence_blob_resolves(digest), "flag mode must keep storing the blob")
        self.assertEqual(store.evidence_blob_redaction_status()["unredacted_flags"], before + 1)
        self.assertNotIn("hunter2", "\n".join(logs.output))

    def test_refuse_policy_raises_and_stores_nothing(self):
        import hashlib
        digest = hashlib.sha256(self.SECRET_BLOB).hexdigest()
        with self.assertRaises(store.UnredactedEvidenceError) as caught:
            store.put_evidence_blob(self.SECRET_BLOB, unredacted="refuse")
        self.assertNotIn("hunter2", str(caught.exception))
        self.assertIsNone(store.get_evidence_blob(digest))
        with patch.object(store, "EVIDENCE_BLOB_UNREDACTED_POLICY", "refuse"):
            with self.assertRaises(store.UnredactedEvidenceError):
                store.put_evidence_blob(self.SECRET_BLOB)
            self.assertTrue(store.evidence_blob_resolves(store.put_evidence_blob(b'{"ok": true}')),
                            "refuse mode must still store clean blobs")

    def test_a_failing_check_does_not_stop_the_blob_being_stored_unless_refusing(self):
        with patch("harness.evidence_redaction.redaction_findings", side_effect=RecursionError):
            with self.assertLogs("harness.store", level="WARNING"):
                digest = store.put_evidence_blob(b'{"deep": true}')
            self.assertTrue(store.evidence_blob_resolves(digest))
            with self.assertRaises(store.UnredactedEvidenceError):
                store.put_evidence_blob(b'{"deep": false}', unredacted="refuse")

    def test_bad_policy_and_non_bytes_are_rejected(self):
        with self.assertRaises(ValueError):
            store.put_evidence_blob(b"x", unredacted="ignore")
        with self.assertRaises(TypeError):
            store.put_evidence_blob("not bytes")

    def test_known_limit_the_check_is_the_callers_field_name_contract(self):
        """The callers redact by secret NAME (security.redact_secrets_in_body), so a
        secret carried in a URL or `key=value` fragment INSIDE a body string is neither
        redacted by them nor reported here. security.sanitize_text would catch it;
        switching the callers to it is a separate change (see HANDOFF)."""
        blob = json.dumps({"body": '{"next": "https://a.test/p?api_key=query-secret-888"}'}).encode()
        self.assertEqual(evidence_redaction.redaction_findings(blob), [])

    def test_non_json_body_is_checked_as_a_body(self):
        self.assertTrue(evidence_redaction.redaction_findings(b"password=hunter2"))
        self.assertEqual(evidence_redaction.redaction_findings(b"password=[REDACTED-SECRET]"), [])
        self.assertEqual(evidence_redaction.redaction_findings(b"\xff\xfe plain bytes"), [])

    def test_negative_control_bypassed_assertion_stores_the_secret(self):
        with patch("harness.evidence_redaction.redaction_findings", return_value=[]):
            digest = store.put_evidence_blob(self.SECRET_BLOB, unredacted="refuse")
        self.assertEqual(store.get_evidence_blob(digest), self.SECRET_BLOB,
                         "with the assertion bypassed the unredacted blob is persisted")
        report = self.verify(check_blobs=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["blobs"]["unredacted_count"], 1)
        self.assertEqual(report["blobs"]["unredacted"][0]["sha256"], digest)

    def test_blob_scan_reports_a_corrupted_blob(self):
        digest = store.put_evidence_blob(b'{"status": 200}')
        self.sql("UPDATE evidence_blobs SET data = ? WHERE sha256 = ?", (b'{"status": 500}', digest))
        report = self.verify(check_blobs=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["blobs"]["corrupt"], [digest])


class RealCallerTests(unittest.IsolatedAsyncioTestCase):
    """The production sink: a real TargetTransport send writes a ledger EXECUTION
    event and two blobs. They must verify, and the blobs must pass the assertion
    that the caller's own redaction satisfied."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_db = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "caller_t.db"

    def tearDown(self):
        store._DB_PATH = self._orig_db
        shutil.rmtree(self._tmp, ignore_errors=True)

    async def test_transport_send_produces_a_verifiable_chain_and_clean_blobs(self):
        body = json.dumps({"token": "response-secret-777", "name": "ok",
                           "next": "https://a.test/p?api_key=query-secret-888"}).encode()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body, headers={"Set-Cookie": "sid=cookie-secret-999"})

        run_context = RunContext.create(
            allowed_hosts=["a.test"],
            gate_config={"active_enabled": True, "allow_mutating_replay": True})
        run_context._default_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        flags_before = store.evidence_blob_redaction_status()["unredacted_flags"]
        try:
            with patch.object(store, "EVIDENCE_BLOB_UNREDACTED_POLICY", "refuse"):
                outcome = await run_context.target_transport().execute(
                    TypedRequest(method="POST", url="https://a.test/login?password=url-secret-111",
                                 headers={"X-Trace": "t-1"},
                                 body='{"password": "body-secret-333", "user": "bob"}'),
                    capability="probe", case_ref="caller-finding-1")
        finally:
            await run_context.aclose()
        self.assertTrue(outcome.ok, (outcome.outcome, outcome.error))
        self.assertEqual(store.evidence_blob_redaction_status()["unredacted_flags"], flags_before)
        executions = [e for e in store.ledger_events_for("caller-finding-1") if e["event_type"] == "execution"]
        self.assertTrue(executions)
        self.assertNotIn("evidence_blob_degraded", executions[0]["data"],
                         "the caller's blobs must pass a REFUSE-policy store")
        report = EL.verify_ledger(store._DB_PATH, check_blobs=True)
        self.assertTrue(report["ok"], report)
        self.assertGreaterEqual(report["chained"], 2)
        self.assertEqual(report["blobs"]["checked"], 2)
        for secret in ("body-secret-333", "url-secret-111",
                       "response-secret-777", "cookie-secret-999"):
            for _digest, data in store.iter_evidence_blobs(store._DB_PATH):
                self.assertNotIn(secret.encode(), data)

    async def test_editing_the_recorded_execution_event_breaks_verification(self):
        run_context = RunContext.create(allowed_hosts=["a.test"], config={})
        run_context._default_client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"fine")))
        try:
            await run_context.target_transport().execute(
                TypedRequest(method="GET", url="https://a.test/x"), capability="probe",
                case_ref="caller-finding-2")
        finally:
            await run_context.aclose()
        self.assertTrue(EL.verify_ledger(store._DB_PATH)["ok"])
        conn = sqlite3.connect(store._DB_PATH)
        conn.execute("UPDATE ledger_events SET data_json = replace(data_json, '\"ok\"', '\"error:forged\"') "
                     "WHERE event_type = 'execution'")
        conn.commit()
        conn.close()
        report = EL.verify_ledger(store._DB_PATH)
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["first_bad"]["finding_ref"], "caller-finding-2")


class CommandLineTests(_StoreCase):
    def run_cli(self, *argv):
        from tools import verify_evidence_ledger as cli
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes_and_output(self):
        self.emit_many("f1", 3)
        code, out, _ = self.run_cli("--db", str(self.db))
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT: OK", out)
        digest = json.loads(self.run_cli("--db", str(self.db), "--json")[1])["digest"]
        self.assertEqual(self.run_cli("--db", str(self.db), "--expect-digest", digest)[0], 0)
        self.assertEqual(self.run_cli("--db", str(self.db), "--expect-digest", "0" * 64)[0], 1)
        bad = self.event_ids("f1")[1]
        self.sql("UPDATE ledger_events SET summary = 'forged' WHERE event_id = ?", (bad,))
        code, out, _ = self.run_cli("--db", str(self.db))
        self.assertEqual(code, 1)
        self.assertIn("BAD ROW", out)
        self.assertIn(bad, out)
        self.assertIn("RESULT: FAILED", out)
        self.assertEqual(json.loads(self.run_cli("--db", str(self.db), "--json")[1])["first_bad"]["event_id"], bad)

    def test_unreadable_store_exits_2(self):
        code, _, err = self.run_cli("--db", str(Path(self._tmp) / "missing.db"))
        self.assertEqual(code, 2)
        self.assertIn("cannot read the store", err)
        garbage = Path(self._tmp) / "garbage.db"
        garbage.write_bytes(b"this is not a sqlite file" * 40)
        self.assertEqual(self.run_cli("--db", str(garbage))[0], 2)

    def test_script_runs_standalone(self):
        self.emit_many("f1", 2)
        done = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_evidence_ledger.py"),
                               "--db", str(self.db)], capture_output=True, text=True,
                              cwd=self._tmp, timeout=60)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("RESULT: OK", done.stdout)


if __name__ == "__main__":
    unittest.main()
