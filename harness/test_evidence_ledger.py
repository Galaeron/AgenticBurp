"""W-24: the append-only evidence ledger reconstructs a finding's causal chain."""
import unittest

import evidence_ledger as el
from evidence_ledger import EventType, EvidenceLedger, LedgerEvent, Provenance


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


if __name__ == "__main__":
    unittest.main()
