"""Tests for the ledger reproducibility assessment (P0-6 / R10; FR-2 / F03).

`complete` (a verdict was reached) is deliberately separate from whether a tester
can independently reproduce a finding. FR-2 tightened `resolvable` further: it now
requires a REAL, content-addressed, hash-verified blob for BOTH the request and the
response (harness.store.evidence_blob_resolves) -- a nonempty `request`/`response`
STRING like a bare URL or "HTTP 200" is a human-readable reference, not reproducible
evidence, and is no longer sufficient by itself (that was the old, honestly-wrong
P0-6 behavior this file used to assert). These tests exercise the `completeness`
block reconstruct() returns: a blob-backed EXECUTION is resolvable; a status-only /
string-only EXECUTION, a mixed one (one blob present, one absent), a verdict with no
execution, and an execution with an empty response capture are all honestly reported
as NOT resolvable with the specific missing piece. The negative control proves this
is storage-backed, not a nonempty-string illusion: a fully blob-backed record that IS
resolvable flips to NOT resolvable the moment its stored blob is deleted. The
persistence-failure negative control proves a durable record whose EXECUTION event
never persisted reconstructs as complete-verdict-but-not-resolvable, never a silent
"reproducible" durable record.

Offline, deterministic. In-memory ledger for the unit cases, backed by an isolated
store DB whenever a real blob hash needs to resolve; an isolated store DB for the
persisted cases too.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness import store, evidence_ledger
from harness.evidence_ledger import EvidenceLedger, EventType, LedgerEvent

_REF = "finding-p06"


def _ledger_with(*events) -> EvidenceLedger:
    led = EvidenceLedger()
    for et, summary, data in events:
        led.record(et, _REF, summary, data=dict(data))
    return led


class ResolvableTests(unittest.TestCase):
    """Blob hashes referenced here must actually resolve against a real store, so
    these tests get their own isolated DB (same pattern as PersistedCompletenessTests
    below), even though the ledger itself stays in-memory."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "resolvable.db"

    def tearDown(self):
        store._DB_PATH = self._orig

    def test_execution_with_verified_blobs_is_resolvable(self):
        # FR-2 positive case: both request and response were actually stored,
        # content-addressed, and hash-verify -- this is what "resolvable" now means.
        req_hash = store.put_evidence_blob(b'{"method":"GET","url":"http://a.test/x"}')
        resp_hash = store.put_evidence_blob(b'{"status":200,"body":"other-user data"}')
        led = _ledger_with(
            (EventType.HYPOTHESIS, "suspected idor", {}),
            (EventType.EXECUTION, "ok: GET /x", {"request": "GET http://a.test/x",
                                                 "response": "HTTP 200 other-user data",
                                                 "request_blob": req_hash,
                                                 "response_blob": resp_hash}),
            (EventType.VALIDATION_DECISION, "confirmed", {}),
        )
        c = led.reconstruct(_REF)["completeness"]
        self.assertTrue(c["resolvable"])
        self.assertTrue(c["has_conclusion"] and c["has_request"] and c["has_response"])
        self.assertTrue(c["has_request_blob"] and c["has_response_blob"])
        self.assertEqual(c["missing"], [])

    def test_status_only_string_reference_is_not_resolvable(self):
        # FR-2 (F03) -- the defect this backlog item fixes: "GET /x" and
        # "HTTP 200 other-user data" are just strings, no blob was ever hashed or
        # stored, so this must NOT read as resolvable (the old, wrong behavior).
        led = _ledger_with(
            (EventType.HYPOTHESIS, "suspected idor", {}),
            (EventType.EXECUTION, "ok: GET /x", {"request": "GET http://a.test/x",
                                                 "response": "HTTP 200 other-user data"}),
            (EventType.VALIDATION_DECISION, "confirmed", {}),
        )
        c = led.reconstruct(_REF)["completeness"]
        self.assertFalse(c["resolvable"])
        self.assertTrue(c["has_conclusion"] and c["has_request"] and c["has_response"])
        self.assertFalse(c["has_request_blob"] and c["has_response_blob"])
        self.assertIn(
            "request/response recorded only as a reference (e.g. 'HTTP 200'), "
            "not a stored hash-verified artifact",
            c["missing"])

    def test_mixed_request_blob_present_response_blob_absent_is_not_resolvable(self):
        # MIXED case from the FR-2 acceptance criteria: one side is real,
        # hash-verified evidence, the other is only ever a reference -- still not
        # resolvable, because reproduction needs BOTH halves of the exchange.
        req_hash = store.put_evidence_blob(b'{"method":"GET","url":"http://a.test/x"}')
        led = _ledger_with(
            (EventType.EXECUTION, "ok: GET /x", {"request": "GET http://a.test/x",
                                                 "response": "HTTP 200",
                                                 "request_blob": req_hash}),
            (EventType.VALIDATION_DECISION, "confirmed", {}),
        )
        c = led.reconstruct(_REF)["completeness"]
        self.assertFalse(c["resolvable"])
        self.assertTrue(c["has_request_blob"])
        self.assertFalse(c["has_response_blob"])
        self.assertIn("no response blob recorded -- reference only", c["missing"])

    def test_negative_control_deleting_the_stored_blob_flips_resolvable_to_false(self):
        # THE negative control FR-2 requires: prove resolvability is storage-backed,
        # not a nonempty-string illusion, by taking an otherwise-resolvable record
        # and deleting its stored blob out from under it.
        req_hash = store.put_evidence_blob(b'{"method":"GET","url":"http://a.test/x"}')
        resp_hash = store.put_evidence_blob(b'{"status":200,"body":"other-user data"}')
        led = _ledger_with(
            (EventType.EXECUTION, "ok: GET /x", {"request": "GET http://a.test/x",
                                                 "response": "HTTP 200 other-user data",
                                                 "request_blob": req_hash,
                                                 "response_blob": resp_hash}),
            (EventType.VALIDATION_DECISION, "confirmed", {}),
        )
        before = led.reconstruct(_REF)["completeness"]
        self.assertTrue(before["resolvable"], before)
        self.assertEqual(before["missing"], [])

        conn = store._connect()
        try:
            conn.execute("DELETE FROM evidence_blobs WHERE sha256 = ?", (resp_hash,))
            conn.commit()
        finally:
            conn.close()
        self.assertFalse(store.evidence_blob_resolves(resp_hash), "precondition: blob must really be gone")

        after = led.reconstruct(_REF)["completeness"]
        self.assertFalse(after["resolvable"], after)
        self.assertTrue(after["missing"], "missing[] must be populated once the blob disappears")
        self.assertIn("referenced response blob is missing or failed hash verification", after["missing"])

    def test_verdict_only_no_execution_is_not_resolvable(self):
        # NEGATIVE control: "only a revision event cannot claim reproducibility".
        led = _ledger_with((EventType.FINDING_REVISION, "severity raised", {}))
        recon = led.reconstruct(_REF)
        self.assertTrue(recon["complete"])                 # a verdict axis exists
        self.assertFalse(recon["completeness"]["resolvable"])   # but not reproducible
        self.assertIn("no execution and no captured observation to reproduce from",
                      recon["completeness"]["missing"])

    def test_execution_with_empty_response_is_not_resolvable(self):
        led = _ledger_with(
            (EventType.EXECUTION, "blocked: GET /x", {"request": "GET http://a.test/x",
                                                      "response": ""}),
            (EventType.VALIDATION_DECISION, "inconclusive", {}),
        )
        c = led.reconstruct(_REF)["completeness"]
        self.assertFalse(c["resolvable"])
        self.assertTrue(c["has_request"])
        self.assertFalse(c["has_response"])
        self.assertIn("execution recorded but the response capture is empty", c["missing"])

    def test_no_conclusion_is_reported_missing(self):
        # FLIPPED under FR-2: this used to assert `resolvable` True purely because
        # the legacy request/response STRINGS were nonempty -- exactly the illusion
        # F03 identified. No blob was ever stored here, so it now honestly reads
        # NOT resolvable; the missing-verdict reason is still reported independently.
        led = _ledger_with(
            (EventType.EXECUTION, "ok", {"request": "GET http://a.test/x", "response": "HTTP 200"}),
        )
        c = led.reconstruct(_REF)["completeness"]
        self.assertFalse(c["has_conclusion"])
        self.assertIn("no verdict (validation decision / finding revision) recorded", c["missing"])
        self.assertFalse(c["resolvable"])


class PersistedCompletenessTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "p06.db"

    def tearDown(self):
        store._DB_PATH = self._orig

    def test_persistence_failure_yields_verdict_but_not_resolvable(self):
        # Simulate the EXECUTION event failing to persist (only the verdict made it
        # durable). The durable reconstruction must NOT claim reproducibility.
        verdict = LedgerEvent(event_type=EventType.VALIDATION_DECISION,
                              finding_ref=_REF, summary="confirmed")
        store.persist_ledger_event(verdict.to_dict())   # execution deliberately NOT persisted

        recon = evidence_ledger.reconstruct_persisted(_REF)
        self.assertTrue(recon["complete"])                     # verdict persisted
        self.assertFalse(recon["completeness"]["resolvable"])  # but no re-runnable evidence
        self.assertFalse(recon["completeness"]["has_execution"])

    def test_full_chain_persists_and_is_resolvable(self):
        # FLIPPED under FR-2: previously "resolvable" here came from the legacy
        # request/response STRINGS alone. Now the positive persisted case must
        # actually store and hash-verify blobs to demonstrate real resolvability.
        req_hash = store.put_evidence_blob(b'{"method":"GET","url":"http://a.test/x"}')
        resp_hash = store.put_evidence_blob(b'{"status":200,"body":"leaked"}')
        for ev in (
            LedgerEvent(event_type=EventType.EXECUTION, finding_ref=_REF, summary="ok",
                        data={"request": "GET http://a.test/x", "response": "HTTP 200 leaked",
                              "request_blob": req_hash, "response_blob": resp_hash}),
            LedgerEvent(event_type=EventType.VALIDATION_DECISION, finding_ref=_REF, summary="confirmed"),
        ):
            store.persist_ledger_event(ev.to_dict())
        recon = evidence_ledger.reconstruct_persisted(_REF)
        self.assertTrue(recon["complete"])
        self.assertTrue(recon["completeness"]["resolvable"])
        self.assertEqual(recon["completeness"]["missing"], [])

    def test_full_chain_with_string_only_refs_is_no_longer_resolvable(self):
        # New coverage: the exact durable shape run_context._artifact wrote before
        # FR-2 (request/response strings, no blob hashes) must reconstruct as NOT
        # resolvable from the persisted store, not just from the in-memory ledger.
        for ev in (
            LedgerEvent(event_type=EventType.EXECUTION, finding_ref=_REF, summary="ok",
                        data={"request": "GET http://a.test/x", "response": "HTTP 200 leaked"}),
            LedgerEvent(event_type=EventType.VALIDATION_DECISION, finding_ref=_REF, summary="confirmed"),
        ):
            store.persist_ledger_event(ev.to_dict())
        recon = evidence_ledger.reconstruct_persisted(_REF)
        self.assertTrue(recon["complete"])
        self.assertFalse(recon["completeness"]["resolvable"])
        self.assertTrue(recon["completeness"]["missing"])


if __name__ == "__main__":
    unittest.main()
