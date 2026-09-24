"""Tests for the ledger reproducibility assessment (P0-6 / R10).

`complete` (a verdict was reached) is deliberately separate from whether a tester
can independently reproduce a finding. These tests exercise the `completeness`
block reconstruct() now returns: an EXECUTION with a real request AND response is
resolvable; a verdict with no execution, or an execution with an empty response
capture, is honestly reported as NOT resolvable with the specific missing piece.
The persistence-failure negative control proves a durable record whose EXECUTION
event never persisted reconstructs as complete-verdict-but-not-resolvable, never a
silent "reproducible" durable record.

Offline, deterministic. In-memory ledger for the unit cases; an isolated store DB
for the persisted case.
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
    def test_execution_with_request_and_response_is_resolvable(self):
        led = _ledger_with(
            (EventType.HYPOTHESIS, "suspected idor", {}),
            (EventType.EXECUTION, "ok: GET /x", {"request": "GET http://a.test/x",
                                                 "response": "HTTP 200 other-user data"}),
            (EventType.VALIDATION_DECISION, "confirmed", {}),
        )
        c = led.reconstruct(_REF)["completeness"]
        self.assertTrue(c["resolvable"])
        self.assertTrue(c["has_conclusion"] and c["has_request"] and c["has_response"])
        self.assertEqual(c["missing"], [])

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
        led = _ledger_with(
            (EventType.EXECUTION, "ok", {"request": "GET http://a.test/x", "response": "HTTP 200"}),
        )
        c = led.reconstruct(_REF)["completeness"]
        self.assertFalse(c["has_conclusion"])
        self.assertIn("no verdict (validation decision / finding revision) recorded", c["missing"])
        # execution evidence present, so it is still independently re-runnable...
        self.assertTrue(c["resolvable"])


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
        for ev in (
            LedgerEvent(event_type=EventType.EXECUTION, finding_ref=_REF, summary="ok",
                        data={"request": "GET http://a.test/x", "response": "HTTP 200 leaked"}),
            LedgerEvent(event_type=EventType.VALIDATION_DECISION, finding_ref=_REF, summary="confirmed"),
        ):
            store.persist_ledger_event(ev.to_dict())
        recon = evidence_ledger.reconstruct_persisted(_REF)
        self.assertTrue(recon["complete"])
        self.assertTrue(recon["completeness"]["resolvable"])


if __name__ == "__main__":
    unittest.main()
