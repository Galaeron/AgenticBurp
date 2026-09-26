"""W-24: the append-only evidence ledger reconstructs a finding's causal chain."""
import shutil
import tempfile
import unittest
from pathlib import Path

import harness.evidence_ledger as el
from harness.evidence_ledger import EventType, EvidenceLedger, LedgerEvent, Provenance
from harness import store


class ProvenanceTests(unittest.TestCase):
    def test_capture_pulls_code_and_config_fingerprint(self):
        prov = Provenance.capture(config={"validators": {"active_enabled": False}},
                                  model="qwen3:8b", prompt_version="abc123")
        self.assertTrue(prov.config_fingerprint)  # W-20 fingerprint present
        self.assertEqual(prov.model, "qwen3:8b")
        self.assertEqual(prov.prompt_version, "abc123")
        self.assertEqual(prov.evidence_schema_version, el.EVIDENCE_SCHEMA_VERSION)
        # code_version is either the git short sha or the honest "unknown"
        self.assertTrue(prov.code_version)


class AppendOnlyTests(unittest.TestCase):
    def test_append_only_rejects_duplicate_event(self):
        ledger = EvidenceLedger()
        e = ledger.record(EventType.OBSERVATION, "F1", "saw a numeric id param")
        with self.assertRaises(el.AppendOnlyViolation):
            ledger.append(e)  # re-appending the same event is forbidden

    def test_correction_is_a_new_revision_not_a_mutation(self):
        ledger = EvidenceLedger()
        ledger.record(EventType.FINDING_REVISION, "F1", "severity high")
        ledger.record(EventType.FINDING_REVISION, "F1", "demoted to low (leg refuted)")
        revs = [e for e in ledger.events_for("F1")
                if e.event_type == EventType.FINDING_REVISION]
        # both revisions retained -- the history is preserved, nothing overwritten
        self.assertEqual(len(revs), 2)


class BoundedLedgerTests(unittest.TestCase):
    def test_below_cap_all_events_retained(self):
        ledger = EvidenceLedger(max_events=10)
        for i in range(5):
            ledger.record(EventType.OBSERVATION, f"F{i}", f"event {i}")
        self.assertEqual(len(ledger), 5)

    def test_append_past_cap_evicts_oldest_and_stays_bounded(self):
        cap = 50
        ledger = EvidenceLedger(max_events=cap)
        for i in range(cap * 4):
            ledger.record(EventType.OBSERVATION, f"F{i}", f"event {i}")
        self.assertLessEqual(len(ledger), cap)
        self.assertEqual(len(ledger), cap)
        # the oldest events were evicted; the newest ones survive
        remaining_refs = {d["finding_ref"] for d in ledger.to_dicts()}
        self.assertNotIn("F0", remaining_refs)
        self.assertIn(f"F{cap * 4 - 1}", remaining_refs)
        # _ids stays consistent with _events (no leaked ids from evicted events)
        self.assertEqual(len(ledger._ids), len(ledger._events))

    def test_reset_default_ledger_empties_it_and_respects_new_cap(self):
        default = el.get_default_ledger()
        default.record(EventType.OBSERVATION, "F-before-reset", "should be cleared")
        self.assertGreater(len(default), 0)
        fresh = el.reset_default_ledger(max_events=7)
        try:
            self.assertEqual(len(fresh), 0)
            self.assertIs(el.get_default_ledger(), fresh)
            for i in range(20):
                fresh.record(EventType.OBSERVATION, f"G{i}", f"event {i}")
            self.assertEqual(len(el.get_default_ledger()), 7)
        finally:
            el.reset_default_ledger()  # restore module default cap for other tests


class ReconstructionTests(unittest.TestCase):
    def _full_chain(self):
        ledger = EvidenceLedger()
        prov = Provenance.capture(config={"validators": {"active_enabled": True}},
                                  model="qwen3:8b", prompt_version="p1")
        ref = "F-idor-orders-1"
        ledger.record(EventType.OBSERVATION, ref, "GET /api/orders/1 returned order data",
                      provenance=prov)
        ledger.record(EventType.HYPOTHESIS, ref, "possible IDOR: object-scoped id, no visible auth",
                      provenance=prov)
        ledger.record(EventType.PLANNED_ACTION, ref, "cross-identity replay as bob + anon",
                      data={"request": "GET /api/orders/1 as bob"}, provenance=prov)
        ledger.record(EventType.AUTHORIZATION_DECISION, ref, "allowed: in scope, GET, identities present",
                      provenance=prov)
        ledger.record(EventType.EXECUTION, ref, "replayed as bob",
                      data={"request": "GET /api/orders/1 (bob cookie)",
                            "response": "200, alice's order", "expected": "403/404"}, provenance=prov)
        ledger.record(EventType.VALIDATION_DECISION, ref,
                      "CONFIRMED: bob read alice's order; anon denied",
                      data={"not_tested": "PATCH/DELETE on the same object (read-only leg)"},
                      provenance=prov)
        ledger.record(EventType.FINDING_REVISION, ref, "lifecycle -> CONFIRMED, severity high",
                      provenance=prov)
        return ledger, ref

    def test_reconstruct_answers_the_five_questions(self):
        ledger, ref = self._full_chain()
        r = ledger.reconstruct(ref)
        self.assertTrue(r["why_tested"])          # observation + hypothesis
        self.assertTrue(r["what_sent"])           # planned action + execution request
        self.assertTrue(r["what_came_back"])      # execution response
        self.assertTrue(r["why_concluded"])       # validation decision + revision
        self.assertTrue(r["authorization"])       # gate decision
        self.assertTrue(r["what_was_never_tested"])  # the read-only-leg gap
        self.assertTrue(r["complete"])
        self.assertEqual(r["event_count"], 7)
        self.assertTrue(r["provenance"]["config_fingerprint"])

    def test_reproduction_recipe_is_provenance_stamped(self):
        ledger, ref = self._full_chain()
        recipe = ledger.reproduction_recipe(ref)
        self.assertTrue(recipe["config_fingerprint"])
        self.assertTrue(recipe["code_version"])
        self.assertEqual(recipe["evidence_schema_version"], el.EVIDENCE_SCHEMA_VERSION)
        self.assertEqual(len(recipe["steps"]), 1)  # the one EXECUTION
        self.assertIn("bob cookie", recipe["steps"][0]["request"])

    def test_events_isolated_per_finding(self):
        ledger, ref = self._full_chain()
        ledger.record(EventType.OBSERVATION, "OTHER", "unrelated")
        self.assertEqual(ledger.reconstruct(ref)["event_count"], 7)
        self.assertEqual(ledger.reconstruct("OTHER")["event_count"], 1)

    def test_serialization_round_trips_event_types(self):
        ledger, ref = self._full_chain()
        dicts = ledger.to_dicts()
        self.assertEqual(len(dicts), 7)
        self.assertTrue(all(isinstance(d["event_type"], str) for d in dicts))
        self.assertIn("provenance", dicts[0])


class ReproductionRecipeBlobTests(unittest.TestCase):
    """RA-1: reproduction_recipe must surface the actual replayable evidence
    blobs it claims exist -- method plus resolving request/response blob
    hashes and a per-step `replayable` flag -- rather than only the old
    reference-only `request`/`expected` strings, and its own top-level
    `resolvable` must AGREE with reconstruct(...)['completeness']['resolvable']
    for the same finding (evidence_ledger.py's producer/consumer contract).
    Uses a temp store._DB_PATH so evidence_blob_resolves() has a real,
    isolated blob store to check against (mirrors test_evidence_ledger_wiring.
    py's setUp/tearDown pattern)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_db = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "recipe_blob_t.db"

    def tearDown(self):
        store._DB_PATH = self._orig_db
        shutil.rmtree(self._tmp, ignore_errors=True)

    @staticmethod
    def _ledger_with_execution(ref: str, data: dict) -> EvidenceLedger:
        ledger = EvidenceLedger()
        prov = Provenance.capture(config={}, model="m", prompt_version="p1")
        ledger.record(EventType.OBSERVATION, ref, "saw something", provenance=prov)
        ledger.record(EventType.EXECUTION, ref, "sent it", data=data, provenance=prov)
        ledger.record(EventType.VALIDATION_DECISION, ref, "CONFIRMED", provenance=prov)
        return ledger

    def test_resolving_send_step_is_replayable_and_agrees_with_completeness(self):
        req_hash = store.put_evidence_blob(b'{"method": "GET", "url": "https://a.test/x"}')
        resp_hash = store.put_evidence_blob(b'{"status": 200, "body": "ok"}')
        ref = "F-recipe-positive"
        data = {"request": "GET https://a.test/x", "response": "HTTP 200",
                "method": "GET", "request_blob": req_hash, "response_blob": resp_hash}
        ledger = self._ledger_with_execution(ref, data)

        recipe = ledger.reproduction_recipe(ref)
        step = recipe["steps"][0]
        self.assertEqual(step["method"], "GET")
        self.assertEqual(step["request_blob"], req_hash)
        self.assertEqual(step["response_blob"], resp_hash)
        self.assertTrue(step["replayable"], step)
        self.assertNotIn("note", step)
        self.assertTrue(recipe["resolvable"], recipe)

        recon = ledger.reconstruct(ref)
        self.assertTrue(recon["completeness"]["resolvable"], recon["completeness"])
        # The recipe's own resolvability must AGREE with completeness.resolvable.
        self.assertEqual(recipe["resolvable"], recon["completeness"]["resolvable"])

    def test_status_only_execution_is_not_replayable_and_completeness_agrees(self):
        """Negative control: the historical shape (no blob refs at all, just
        a human-readable request/response string) -- the step must be
        honestly reference-only, and completeness.resolvable must be False
        right alongside it, proving the recipe no longer over-claims."""
        ref = "F-recipe-status-only"
        data = {"request": "GET https://a.test/y", "response": "HTTP 200"}
        ledger = self._ledger_with_execution(ref, data)

        recipe = ledger.reproduction_recipe(ref)
        step = recipe["steps"][0]
        self.assertFalse(step["replayable"])
        self.assertIsNone(step["request_blob"])
        self.assertIsNone(step["response_blob"])
        self.assertIn("note", step)
        self.assertFalse(recipe["resolvable"], recipe)

        recon = ledger.reconstruct(ref)
        self.assertFalse(recon["completeness"]["resolvable"], recon["completeness"])
        self.assertEqual(recipe["resolvable"], recon["completeness"]["resolvable"])

    def test_referenced_blob_that_does_not_resolve_is_not_replayable(self):
        """A blob hash was recorded but the bytes were never stored (or were
        later corrupted/deleted) -- must resolve to not-replayable exactly
        like no hash at all, mirroring _resolved_blob_hash's own contract."""
        ref = "F-recipe-corrupted"
        data = {"request": "GET https://a.test/z", "response": "HTTP 200",
                "method": "GET",
                "request_blob": "deadbeef" * 8, "response_blob": "cafebabe" * 8}
        ledger = self._ledger_with_execution(ref, data)

        recipe = ledger.reproduction_recipe(ref)
        step = recipe["steps"][0]
        self.assertFalse(step["replayable"])
        self.assertIsNone(step["request_blob"])
        self.assertIsNone(step["response_blob"])
        self.assertIn("note", step)
        self.assertFalse(recipe["resolvable"])

        recon = ledger.reconstruct(ref)
        self.assertFalse(recon["completeness"]["resolvable"])
        self.assertEqual(recipe["resolvable"], recon["completeness"]["resolvable"])

    def test_existing_keys_preserved_for_back_compat(self):
        ref = "F-recipe-backcompat"
        data = {"request": "GET https://a.test/w", "expected": "403", "response": "HTTP 200"}
        ledger = self._ledger_with_execution(ref, data)
        recipe = ledger.reproduction_recipe(ref)
        self.assertEqual(recipe["steps"][0]["request"], "GET https://a.test/w")
        self.assertEqual(recipe["steps"][0]["expected"], "403")
        for key in ("finding_ref", "code_version", "config_fingerprint",
                   "evidence_schema_version", "steps"):
            self.assertIn(key, recipe)

    def test_persisted_recipe_variant_agrees_with_persisted_completeness(self):
        """reproduction_recipe_persisted (the durable-store-backed variant
        that server.py's GET /findings/{ref}/evidence actually reads, beside
        reconstruct_persisted) must show the same replayable/resolvable
        agreement as the in-memory ledger."""
        req_hash = store.put_evidence_blob(b'{"method": "POST", "url": "https://a.test/p"}')
        resp_hash = store.put_evidence_blob(b'{"status": 201}')
        ref = "F-recipe-persisted"
        prov = Provenance.capture(config={}, model="m", prompt_version="p1")
        events = [
            LedgerEvent(event_type=EventType.OBSERVATION, finding_ref=ref,
                       summary="saw something", provenance=prov),
            LedgerEvent(event_type=EventType.EXECUTION, finding_ref=ref,
                       summary="sent it", provenance=prov,
                       data={"request": "POST https://a.test/p", "response": "HTTP 201",
                             "method": "POST", "request_blob": req_hash,
                             "response_blob": resp_hash}),
            LedgerEvent(event_type=EventType.VALIDATION_DECISION, finding_ref=ref,
                       summary="CONFIRMED", provenance=prov),
        ]
        for ev in events:
            store.persist_ledger_event(ev.to_dict())

        recipe = el.reproduction_recipe_persisted(ref)
        self.assertTrue(recipe["steps"])
        step = recipe["steps"][0]
        self.assertTrue(step["replayable"], step)
        self.assertEqual(step["request_blob"], req_hash)
        self.assertEqual(step["response_blob"], resp_hash)
        self.assertTrue(recipe["resolvable"], recipe)

        recon = el.reconstruct_persisted(ref)
        self.assertTrue(recon["completeness"]["resolvable"], recon["completeness"])
        self.assertEqual(recipe["resolvable"], recon["completeness"]["resolvable"])


if __name__ == "__main__":
    unittest.main()
