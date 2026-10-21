"""I02 batch C (C1): storage contract for supplied observations.

These are store-level tests of record_observation / select_observations and the
analyst actions, with real temporary SQLite. They do not establish caller
integration: the analyze() and API callers are covered in
test_observation_memory_caller.py. Each rule has a positive case, a negative
control and a fault injection that the positive assertion must notice.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from harness import data_maintenance, store
from harness.models import HttpExchange

_URL = "https://shop.example/api/orders/1001"
_TOKEN_A = "Bearer synthetic-token-alpha"
_TOKEN_B = "Bearer synthetic-token-bravo"


def _exchange(body: str = '{"id": 1001, "state": "shipped"}', *, url: str = _URL,
              token: str | None = _TOKEN_A, **capture) -> HttpExchange:
    headers = {"Authorization": token} if token else {}
    return HttpExchange(url=url, method="GET", request_headers=headers, response_status=200,
                        response_headers={"Content-Type": "application/json"},
                        response_body=body, **capture)


class _TempStore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i02c_store_")
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "state.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _rows(self, sql: str, params=()) -> list:
        conn = store._connect()
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def _count(self) -> int:
        return self._rows("SELECT count(*) FROM exchange_observations")[0][0]

    def _select(self, exchange: HttpExchange, *, engagement_id: str = "", attribution=None) -> dict:
        return store.select_observations(
            exchange.url, engagement_id=engagement_id,
            captured_principal=store.captured_principal_id(exchange), attribution=attribution,
            exclude_exchange_id=store.exchange_identity(exchange)[0])


class DuplicateRuleTests(_TempStore):
    """Design section 3 (acceptance C07): the key is (host, engagement_id, exchange_id)."""

    def test_replaying_the_same_capture_is_idempotent(self):
        first = store.record_observation(_exchange(capture_id="cap-1"))
        again = store.record_observation(_exchange(capture_id="cap-1"))
        self.assertEqual((first["status"], again["status"]), ("stored", "duplicate"))
        self.assertEqual(first["observation_id"], again["observation_id"])
        self.assertEqual(self._count(), 1)

    def test_content_derived_key_ignores_volatile_headers_only(self):
        a = _exchange(token=None)
        b = a.model_copy(update={"response_headers": {**a.response_headers, "Date": "Mon"}})
        self.assertEqual(store.record_observation(a)["status"], "stored")
        self.assertEqual(store.record_observation(b)["status"], "duplicate")
        changed = a.model_copy(update={"response_body": '{"id": 1001, "state": "placed"}'})
        self.assertEqual(store.record_observation(changed)["status"], "stored")
        self.assertEqual(self._count(), 2, "same URL with different content is a distinct observation")

    def test_same_capture_id_with_changed_content_is_rejected(self):
        store.record_observation(_exchange(capture_id="cap-1"))
        before = self._rows("SELECT * FROM exchange_observations")
        result = store.record_observation(_exchange('{"id": 1001, "state": "placed"}', capture_id="cap-1"))
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(self._rows("SELECT * FROM exchange_observations"), before)

    def test_same_capture_id_from_other_credentials_is_rejected(self):
        """I07's same-ID/different-tenant case: other credentials change the digest."""
        store.record_observation(_exchange(capture_id="cap-1"))
        self.assertEqual(store.record_observation(_exchange(capture_id="cap-1", token=_TOKEN_B))["status"],
                         "conflict")

    def test_same_body_captured_at_two_times_is_two_observations(self):
        store.record_observation(_exchange(token=None, captured_at=100.0))
        self.assertEqual(store.record_observation(_exchange(token=None, captured_at=200.0))["status"], "stored")
        self.assertEqual(self._count(), 2)

    def test_the_same_capture_id_in_other_scopes_is_distinct(self):
        store.record_observation(_exchange(capture_id="cap-1"))
        self.assertEqual(store.record_observation(_exchange(capture_id="cap-1"),
                                                  engagement_id="review-1")["status"], "stored")
        other_host = _exchange(capture_id="cap-1", url="https://other.example/api/orders/1001")
        self.assertEqual(store.record_observation(other_host)["status"], "stored")
        self.assertEqual(self._count(), 3)

    def test_unique_index_backstops_the_key(self):
        store.record_observation(_exchange(capture_id="cap-1"))
        conn = sqlite3.connect(store._DB_PATH)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO exchange_observations (observation_id, host, engagement_id, "
                             "exchange_id, id_source, content_digest, captured_principal_id, method, "
                             "normalized_endpoint, ingested_at) SELECT 'x', host, engagement_id, "
                             "exchange_id, id_source, content_digest, captured_principal_id, method, "
                             "normalized_endpoint, ingested_at FROM exchange_observations")
        finally:
            conn.close()

    def test_fault_without_a_stable_key_replays_duplicate(self):
        """Fault injection: a per-call identity breaks idempotency, and the replay
        count assertion notices."""
        with patch.object(store, "exchange_identity", lambda e: (uuid.uuid4().hex[:16], "content")):
            store.record_observation(_exchange(capture_id="cap-1"))
            store.record_observation(_exchange(capture_id="cap-1"))
        self.assertNotEqual(self._count(), 1)

    def test_a_deleted_capture_is_not_resurrected(self):
        first = store.record_observation(_exchange(capture_id="cap-1"))
        store.delete_observation(first["observation_id"])
        self.assertEqual(store.record_observation(_exchange(capture_id="cap-1"))["status"], "deleted")
        self.assertEqual(store.resolve_observation_refs([first["observation_id"]]),
                         {first["observation_id"]: "deleted"})

    def test_finding_provenance_keeps_the_legacy_exchange_id(self):
        from harness import cache
        legacy = _exchange()
        self.assertEqual(store.exchange_identity(legacy),
                         (cache.ExchangeCache.compute_exchange_hash(legacy)[:16], "content"))
        self.assertEqual(store.exchange_identity(_exchange(capture_id="cap-9")), ("cap-9", "client"))


class RetrievalScopeTests(_TempStore):
    """Design section 5 (acceptance C04 and C03 at the store boundary)."""

    def test_same_endpoint_same_context_is_selected(self):
        stored = store.record_observation(_exchange())
        later = _exchange('{"id": 1001, "state": "placed"}')
        selection = self._select(later)
        self.assertEqual([o["observation_id"] for o in selection["selected"]], [stored["observation_id"]])
        self.assertEqual(selection["selected"][0]["reason"], "same-captured-context")
        self.assertEqual(selection["selected"][0]["evidence_status"], "resolved")

    def test_current_capture_and_other_endpoints_are_not_selected(self):
        current = _exchange()
        store.record_observation(current)
        store.record_observation(_exchange(url="https://shop.example/api/orders/1002"))
        self.assertEqual(self._select(current)["selected"], [])

    def test_other_pile_and_other_host_never_join(self):
        store.record_observation(_exchange(), engagement_id="review-1")
        store.record_observation(_exchange(url="https://other.example/api/orders/1001"))
        later = _exchange('{"id": 1001, "state": "placed"}')
        self.assertEqual(self._select(later)["selected"], [])
        self.assertEqual(self._select(later, engagement_id="review-2")["selected"], [])
        self.assertEqual(len(self._select(later, engagement_id="review-1")["selected"]), 1)

    def test_declared_tenants_that_differ_do_not_join_and_ids_stay_hidden(self):
        stored = store.record_observation(_exchange(), attribution={"tenant": "tenant-one"})
        selection = self._select(_exchange('{"id": 1001}', token=_TOKEN_B),
                                 attribution={"tenant": "tenant-two"})
        self.assertEqual(selection["selected"], [])
        self.assertEqual(selection["excluded_counts"], {"tenant-mismatch": 1})
        self.assertNotIn(stored["observation_id"], json.dumps(selection))

    def test_same_credentials_with_conflicting_declared_tenants_do_not_join(self):
        store.record_observation(_exchange(), attribution={"tenant": "tenant-one"})
        selection = self._select(_exchange('{"id": 1001}'), attribution={"tenant": "tenant-two"})
        self.assertEqual(selection["excluded_counts"], {"tenant-mismatch": 1})

    def test_within_tenant_declared_relation_is_retrieved(self):
        store.record_observation(_exchange(), attribution={"tenant": "tenant-one"})
        selection = self._select(_exchange('{"id": 1001}', token=_TOKEN_B),
                                 attribution={"tenant": "tenant-one"})
        self.assertEqual([o["reason"] for o in selection["selected"]], ["declared-same-tenant"])

    def test_unknown_identities_never_collapse_into_one_owner(self):
        store.record_observation(_exchange(token=None))
        anonymous = self._select(_exchange('{"id": 1001}', token=None))
        self.assertEqual(anonymous["selected"], [], "two captures without credentials are not one owner")
        store.record_observation(_exchange(token=_TOKEN_A))
        other = self._select(_exchange('{"id": 1001}', token=_TOKEN_B))
        self.assertEqual(other["selected"], [], "unknown tenants never match each other")
        self.assertEqual(other["excluded_counts"], {"unattributed-context": 2})

    def test_fault_without_the_tenant_predicate_is_detected(self):
        """Fault injection: removing the attribution predicate joins the other
        tenant, and the isolation assertion notices."""
        store.record_observation(_exchange(), attribution={"tenant": "tenant-one"})
        with patch.object(store, "_attribution_join", lambda *a: (True, "fault")):
            leaked = self._select(_exchange('{"id": 1001}', token=_TOKEN_B),
                                  attribution={"tenant": "tenant-two"})
        self.assertNotEqual(leaked["selected"], [])

    def test_fault_collapsing_piles_is_detected(self):
        """Fault injection: dropping the pile from the key merges named piles."""
        with patch.object(store, "_engagement_partition", lambda e: ""):
            store.record_observation(_exchange(), engagement_id="review-1")
            leaked = self._select(_exchange('{"id": 1001}'), engagement_id="review-2")
        self.assertNotEqual(leaked["selected"], [])

    def test_stored_attribution_of_the_current_capture_wins(self):
        store.record_observation(_exchange(), attribution={"tenant": "tenant-one"})
        current = _exchange('{"id": 1001}', token=_TOKEN_B)
        store.record_observation(current, attribution={"tenant": "tenant-one"})
        selection = self._select(current, attribution={"tenant": "tenant-two"})
        self.assertEqual([o["reason"] for o in selection["selected"]], ["declared-same-tenant"])

    def test_capture_time_orders_a_late_arrival(self):
        store.record_observation(_exchange('{"state": "placed"}', captured_at=200.0))
        store.record_observation(_exchange('{"state": "new"}', captured_at=100.0))   # arrives late
        selection = self._select(_exchange('{"state": "shipped"}', captured_at=300.0))
        self.assertEqual([o["captured_at"] for o in selection["selected"]], [100.0, 200.0])
        self.assertEqual(selection["order_basis"], "capture")

    def test_unknown_capture_time_is_labelled_as_ingest_order(self):
        store.record_observation(_exchange('{"state": "placed"}'))
        store.record_observation(_exchange('{"state": "new"}', captured_at=100.0))
        selection = self._select(_exchange('{"state": "shipped"}'))
        self.assertEqual(selection["order_basis"], "mixed")
        self.assertEqual([o["order_basis"] for o in selection["selected"]], ["capture", "ingest"])
        self.assertIn("capture time unknown", store.observation_context_block(selection))

    def test_fault_replacing_capture_time_with_arrival_order_is_detected(self):
        with patch.object(store, "_supplied_capture_fields", lambda e: {}):
            store.record_observation(_exchange('{"state": "placed"}', captured_at=200.0))
            store.record_observation(_exchange('{"state": "new"}', captured_at=100.0))
        selection = self._select(_exchange('{"state": "shipped"}', captured_at=300.0))
        self.assertNotEqual([o["captured_at"] for o in selection["selected"]], [100.0, 200.0])

    def test_selection_is_bounded(self):
        for n in range(12):
            store.record_observation(_exchange(json.dumps({"n": n})))
        selection = self._select(_exchange('{"n": 99}'))
        self.assertEqual(len(selection["selected"]), 8)
        self.assertEqual(selection["excluded_counts"], {"over-limit": 4})
        scanned = store.select_observations(_URL, captured_principal=store.captured_principal_id(_exchange()),
                                            scan_limit=5)
        self.assertEqual(len(scanned["selected"]), 5)


class CorrectionAndDeletionTests(_TempStore):
    """Acceptance C09 at the store boundary; the caller/cache half is in C2."""

    def test_correction_versions_attribution_and_changes_the_selection(self):
        a = store.record_observation(_exchange(), attribution={"tenant": "tenant-one"})
        current = _exchange('{"id": 1001}', token=_TOKEN_B)
        before = self._select(current, attribution={"tenant": "tenant-one"})
        self.assertEqual(len(before["selected"]), 1)
        result = store.correct_observation_attribution(
            a["observation_id"], expected_revision=1, attribution={"tenant": "tenant-two"},
            reason="mislabelled")
        self.assertEqual(result["revision"], 2)
        after = self._select(current, attribution={"tenant": "tenant-one"})
        self.assertEqual(after["selected"], [])
        self.assertNotEqual(before["digest"], after["digest"])
        history = store.get_observation(a["observation_id"])["attribution_history"]
        self.assertEqual([h["tenant"] for h in history], ["tenant-one", "tenant-two"])

    def test_stale_revision_and_other_pile_are_rejected(self):
        a = store.record_observation(_exchange())
        with self.assertRaises(store.ObservationRevisionConflict):
            store.correct_observation_attribution(a["observation_id"], expected_revision=0,
                                                  attribution={"tenant": "t"})
        with self.assertRaises(LookupError):
            store.correct_observation_attribution(a["observation_id"], engagement_id="review-1",
                                                  expected_revision=1, attribution={"tenant": "t"})

    def test_delete_leaves_a_visible_tombstone_and_removes_evidence(self):
        a = store.record_observation(_exchange())
        unrelated = store.record_observation(_exchange(url="https://shop.example/api/orders/2002"))
        blob = self._rows("SELECT evidence_sha256 FROM exchange_observations WHERE observation_id = ?",
                          (a["observation_id"],))[0][0]
        before = self._select(_exchange('{"id": 1001}'))
        result = store.delete_observation(a["observation_id"])
        self.assertTrue(result["evidence_deleted"])
        self.assertFalse(store.evidence_blob_resolves(blob))
        after = self._select(_exchange('{"id": 1001}'))
        self.assertEqual(after["selected"], [])
        self.assertEqual(after["unavailable"], [{"observation_id": a["observation_id"], "reason": "deleted"}])
        self.assertNotEqual(before["digest"], after["digest"])
        self.assertIn("deleted by the analyst", store.observation_context_block(after))
        self.assertEqual(store.resolve_observation_refs([a["observation_id"], unrelated["observation_id"]]),
                         {a["observation_id"]: "deleted", unrelated["observation_id"]: "resolved"})
        tombstone = self._rows("SELECT facts_json, url_redacted, evidence_sha256, state_version "
                               "FROM exchange_observations WHERE observation_id = ?", (a["observation_id"],))
        self.assertEqual(tombstone, [("{}", "", "", None)])

    def test_delete_keeps_a_blob_another_observation_still_uses(self):
        shared = store.record_observation(_exchange(capture_id="cap-1"), engagement_id="review-1")
        store.record_observation(_exchange(capture_id="cap-1"))
        blob = self._rows("SELECT evidence_sha256 FROM exchange_observations WHERE observation_id = ?",
                          (shared["observation_id"],))[0][0]
        self.assertFalse(store.delete_observation(shared["observation_id"], engagement_id="review-1")
                         ["evidence_deleted"])
        self.assertTrue(store.evidence_blob_resolves(blob))

    def test_fault_keeping_the_blob_on_delete_is_detected(self):
        a = store.record_observation(_exchange())
        blob = self._rows("SELECT evidence_sha256 FROM exchange_observations")[0][0]
        with patch.object(store, "_blob_still_referenced", lambda conn, digest: True):
            store.delete_observation(a["observation_id"])
        self.assertTrue(store.evidence_blob_resolves(blob), "fault left the deleted capture's bytes behind")

    def test_expired_evidence_is_reported_not_served(self):
        a = store.record_observation(_exchange())
        before = self._select(_exchange('{"id": 1001}'))
        store.purge_evidence_blobs_older_than(1, now=10 ** 12)
        after = self._select(_exchange('{"id": 1001}'))
        self.assertEqual(after["selected"][0]["evidence_status"], "unavailable")
        self.assertNotEqual(before["digest"], after["digest"])
        self.assertEqual(store.resolve_observation_refs([a["observation_id"]]),
                         {a["observation_id"]: "evidence_unavailable"})
        conn = sqlite3.connect(store._DB_PATH)
        try:
            self.assertEqual(data_maintenance.inspect_database(conn)["unavailable_reference_count"], 1)
        finally:
            conn.close()


class CredentialHandlingTests(_TempStore):
    _SECRETS = ("synthetic-token-alpha", "SYNTH-COOKIE-77", "SYNTH-QUERY-55", "SYNTH-PASS-99")

    def _all_stored_text(self) -> str:
        parts = [repr(r) for r in self._rows("SELECT * FROM exchange_observations")]
        parts += [repr(r) for r in self._rows("SELECT * FROM observation_attributions")]
        parts += [bytes(r[0]).decode("utf-8", "replace") for r in self._rows("SELECT data FROM evidence_blobs")]
        return "\n".join(parts)

    def test_no_credential_value_is_stored_or_rendered(self):
        exchange = HttpExchange(
            url="https://user:SYNTH-PASS-99@shop.example/api/orders/1001?token=SYNTH-QUERY-55",
            method="POST",
            request_headers={"Authorization": _TOKEN_A, "Cookie": "session=SYNTH-COOKIE-77"},
            request_body='{"password": "SYNTH-PASS-99"}', response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"id": 1, "token": "SYNTH-QUERY-55"}')
        store.record_observation(exchange)
        stored = self._all_stored_text()
        for secret in self._SECRETS:
            self.assertNotIn(secret, stored)
        later = exchange.model_copy(update={"response_body": "{}"})
        block = store.observation_context_block(store.select_observations(
            later.url, captured_principal=store.captured_principal_id(later)))
        self.assertTrue(block)
        for secret in self._SECRETS:
            self.assertNotIn(secret, block)

    def test_credential_shaped_attribution_is_rejected(self):
        for value in ("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
                      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "aB3" * 12,
                      "password=hunter2", "a`b", "x" * 65):
            with self.assertRaises(ValueError, msg=value):
                store.record_observation(_exchange(), attribution={"tenant": value})
        with self.assertRaises(ValueError):
            store.record_observation(_exchange(), attribution={"owner": "x"})
        self.assertEqual(self._count(), 0)

    def test_ordinary_labels_are_accepted(self):
        labels = {"tenant": "Acme Corp EU", "role": "billing-admin",
                  "principal_ref": "customer-12345678901234567890-ab", "session_ref": "alice@shop:2"}
        stored = store.record_observation(_exchange(), attribution=labels)
        current = store.get_observation(stored["observation_id"])["attribution"]
        self.assertEqual({k: current[k] for k in labels}, labels)
        self.assertEqual(current["source"], "analyst")

    def test_bounds_and_explicit_truncation(self):
        many_keys = json.dumps({f"field_{n:03d}_" + "k" * 40: n for n in range(100)})
        store.record_observation(_exchange(many_keys))
        facts_json = self._rows("SELECT facts_json FROM exchange_observations")[0][0]
        self.assertLessEqual(len(facts_json), 2048)
        self.assertTrue(json.loads(facts_json)["json_keys_truncated"])
        store.record_observation(_exchange("x" * 300_000, url="https://shop.example/big"))
        truncated, blob = self._rows(
            "SELECT o.evidence_truncated, b.data FROM exchange_observations o "
            "JOIN evidence_blobs b ON b.sha256 = o.evidence_sha256 WHERE o.host = 'shop.example' "
            "AND o.normalized_endpoint LIKE '%/big'")[0]
        self.assertEqual(truncated, 1)
        self.assertLessEqual(len(blob), 64 * 1024)
        self.assertTrue(json.loads(bytes(blob))["evidence_truncated"])


class WipeTests(_TempStore):
    def test_host_wipe_removes_observations_and_guards_shared_blobs(self):
        a = store.record_observation(_exchange())
        store.record_observation(_exchange(), engagement_id="review-1")
        b = store.record_observation(_exchange(url="https://other.example/api/orders/1001"))
        a_blob = self._rows("SELECT evidence_sha256 FROM exchange_observations WHERE observation_id = ?",
                            (a["observation_id"],))[0][0]
        b_blob = self._rows("SELECT evidence_sha256 FROM exchange_observations WHERE observation_id = ?",
                            (b["observation_id"],))[0][0]
        # Another host's registered ledger evidence names a's blob: it must survive.
        from harness.models import Finding
        other = HttpExchange(url="https://third.example/x", method="GET")
        store.persist_findings(other, "agent", [Finding(
            vulnerability_class="idor", confidence=0.4, summary="s", evidence="e", suggested_test="t",
            basis="assumed", case_id="case-third")])
        store.persist_ledger_event({"event_id": "ev-1", "event_type": "execution", "finding_ref": "case-third",
                                    "data": {"request_blob": a_blob}})
        counts = store.wipe_engagement("shop.example")
        self.assertEqual(counts["exchange_observations"], 2)
        self.assertEqual(counts["observation_attributions"], 2)
        self.assertEqual(self._rows("SELECT host FROM exchange_observations"), [("other.example",)])
        self.assertTrue(store.evidence_blob_resolves(a_blob), "a blob another host references survives")
        self.assertTrue(store.evidence_blob_resolves(b_blob))

    def test_host_wipe_deletes_target_only_blobs(self):
        store.record_observation(_exchange())
        blob = self._rows("SELECT evidence_sha256 FROM exchange_observations")[0][0]
        store.wipe_engagement("shop.example")
        self.assertFalse(store.evidence_blob_resolves(blob))

    def test_named_pile_wipe_leaves_the_site_pile(self):
        store.record_observation(_exchange(capture_id="cap-1"), engagement_id="review-1")
        site = store.record_observation(_exchange(capture_id="cap-1"))
        only_named = store.record_observation(_exchange(capture_id="cap-2", url="https://shop.example/n"),
                                              engagement_id="review-1")
        named_blob = self._rows("SELECT evidence_sha256 FROM exchange_observations WHERE observation_id = ?",
                                (only_named["observation_id"],))[0][0]
        shared_blob = self._rows("SELECT evidence_sha256 FROM exchange_observations WHERE observation_id = ?",
                                 (site["observation_id"],))[0][0]
        receipt = data_maintenance.wipe_context(store._DB_PATH, "review-1")
        self.assertEqual(receipt["deleted"]["exchange_observations"], 2)
        self.assertEqual(receipt["deleted"]["observation_attributions"], 2)
        self.assertEqual(self._rows("SELECT observation_id FROM exchange_observations"),
                         [(site["observation_id"],)])
        self.assertTrue(store.evidence_blob_resolves(shared_blob), "the site pile still uses this blob")
        self.assertFalse(store.evidence_blob_resolves(named_blob))


if __name__ == "__main__":
    unittest.main()
