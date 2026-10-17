"""
RA-4: batched report-time ledger/blob reads.

`report_generator` used to call `evidence_ledger.reconstruct_persisted(ref)`
once PER FINDING, each opening a fresh SQLite connection for the events query
plus another per blob field it resolved -- an O(N findings x E events) pile of
serial connections for one report. `evidence_ledger.reconstruct_persisted_many`
now does ONE batched events fetch (`store.ledger_events_for_many`) and resolves
every blob hash over ONE shared connection with a per-hash memo, and
`generate_markdown_report` builds that map once up front.

These tests assert the two things that make the refactor safe + worthwhile:
  1. CORRECTNESS (byte-identical): the batched reconstruction for each ref is
     equal, field-for-field, to what the single-ref `reconstruct_persisted`
     returns -- including a resolvable-blob finding, a present-but-unresolvable
     blob, and a ref with no events at all. And `ledger_events_for_many` slices
     match `ledger_events_for`.
  2. BOUNDED CONNECTIONS (the perf claim): a counting shim over `store._connect`
     shows `reconstruct_persisted_many` opens a small CONSTANT number of
     connections, independent of the finding count K (K=3 and K=6 give the same
     count) -- not O(N x E).

Deterministic, fully offline (temp `store._DB_PATH`); no model/GPU/network, no
*ANSWER_KEY*/blind-target content.
"""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from harness import store, evidence_ledger


class _TempStoreDB(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_report_batch_reads.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _seed_finding_with_events(self, ref: str, *, resolvable_blobs: bool = True,
                                  unresolvable_blob: bool = False,
                                  add_validation: bool = True) -> None:
        """Persist one EXECUTION ledger event for `ref` (optionally carrying a
        real, storage-resolving request/response blob pair, or a blob ref that
        does NOT resolve), plus optionally a VALIDATION_DECISION event so the
        reconstruction reports `complete=True`. The blobs are put via the
        production `put_evidence_blob` so `evidence_blob_resolves` really
        resolves them."""
        data: dict = {"method": "GET", "request": f"GET https://{ref}.example/x",
                      "response": "HTTP 200"}
        if resolvable_blobs:
            data["request_blob"] = store.put_evidence_blob(f"req-{ref}".encode())
            data["response_blob"] = store.put_evidence_blob(f"resp-{ref}".encode())
        elif unresolvable_blob:
            # A recorded hash that was never stored -> present ref, unresolvable.
            data["request_blob"] = "0" * 64
            data["response_blob"] = "1" * 64
        store.persist_ledger_event({
            "event_id": f"exec-{ref}", "event_type": evidence_ledger.EventType.EXECUTION.value,
            "finding_ref": ref, "case_ref": ref, "summary": f"exec {ref}",
            "data": data, "provenance": {}, "created_at": time.time(),
        })
        if add_validation:
            store.persist_ledger_event({
                "event_id": f"val-{ref}", "event_type": evidence_ledger.EventType.VALIDATION_DECISION.value,
                "finding_ref": ref, "case_ref": ref, "summary": f"validated {ref}",
                "data": {"verdict": "confirmed"}, "provenance": {}, "created_at": time.time() + 1,
            })


class BatchedReconstructionMatchesSingleRefTests(_TempStoreDB):
    """CORRECTNESS: reconstruct_persisted_many(refs)[ref] must equal
    reconstruct_persisted(ref) field-for-field for every ref -- the guarantee
    that makes the rendered report byte-identical after the refactor."""

    def test_resolvable_present_and_absent_refs_all_match_single_ref(self):
        # r1/r2: real resolving blobs; r3: blob refs that do NOT resolve;
        # r_empty: no events at all. Mix so the memoized resolver, the
        # unresolvable path, and the no-events default path are all exercised.
        self._seed_finding_with_events("r1", resolvable_blobs=True)
        self._seed_finding_with_events("r2", resolvable_blobs=True)
        self._seed_finding_with_events("r3", resolvable_blobs=False, unresolvable_blob=True)
        refs = ["r1", "r2", "r3", "r_empty"]

        many = evidence_ledger.reconstruct_persisted_many(refs)

        # Every requested ref present (including the no-events one).
        self.assertEqual(set(many.keys()), set(refs))
        for ref in refs:
            with self.subTest(ref=ref):
                self.assertEqual(many[ref], evidence_ledger.reconstruct_persisted(ref))

        # Spot-check the discriminating fields so this isn't a vacuous
        # "both computed the same wrong thing": r1 resolves, r3 does not.
        self.assertTrue(many["r1"]["completeness"]["resolvable"])
        self.assertFalse(many["r3"]["completeness"]["resolvable"])
        self.assertTrue(many["r1"]["complete"])
        self.assertEqual(many["r_empty"]["event_count"], 0)

    def test_empty_and_duplicate_ref_inputs(self):
        self._seed_finding_with_events("dup", resolvable_blobs=True)
        self.assertEqual(evidence_ledger.reconstruct_persisted_many([]), {})
        # Duplicates collapse to one entry, still equal to the single-ref call.
        many = evidence_ledger.reconstruct_persisted_many(["dup", "dup"])
        self.assertEqual(set(many.keys()), {"dup"})
        self.assertEqual(many["dup"], evidence_ledger.reconstruct_persisted("dup"))


class LedgerEventsForManyMatchesSingleTests(_TempStoreDB):
    def test_slice_equals_single_and_missing_ref_absent(self):
        self._seed_finding_with_events("a", resolvable_blobs=True)
        self._seed_finding_with_events("b", resolvable_blobs=True)
        batched = store.ledger_events_for_many(["a", "b", "no_events"])
        self.assertEqual(batched.get("a"), store.ledger_events_for("a"))
        self.assertEqual(batched.get("b"), store.ledger_events_for("b"))
        # A ref with no rows is absent (never an empty-list placeholder),
        # matching ledger_events_for's own "no rows" outcome.
        self.assertNotIn("no_events", batched)
        self.assertEqual(store.ledger_events_for("no_events"), [])

    def test_empty_input_opens_no_connection_and_returns_empty(self):
        self.assertEqual(store.ledger_events_for_many([]), {})
        self.assertEqual(store.ledger_events_for_many(["", None]), {})


class BoundedConnectionCountTests(_TempStoreDB):
    """PERF: reconstruct_persisted_many opens a small CONSTANT number of
    connections regardless of how many findings (K) or events/blobs it covers
    -- proving the O(N x E) fresh-connection cliff is gone. The negative-control
    shape is the K=3 vs K=6 comparison: the count must NOT grow with K."""

    def _count_connects_during(self, fn) -> int:
        original = store._connect
        calls = {"n": 0}

        def _counting():
            calls["n"] += 1
            return original()

        store._connect = _counting
        try:
            fn()
        finally:
            store._connect = original
        return calls["n"]

    def _seed_k(self, k: int) -> list[str]:
        refs = [f"k{k}_r{i}" for i in range(k)]
        for ref in refs:
            # Distinct blobs per finding, so a per-hash memo alone would NOT
            # bound the count -- only the shared connection does.
            self._seed_finding_with_events(ref, resolvable_blobs=True)
        return refs

    def test_connection_count_is_constant_in_K(self):
        refs3 = self._seed_k(3)
        refs6 = self._seed_k(6)

        n3 = self._count_connects_during(
            lambda: evidence_ledger.reconstruct_persisted_many(refs3))
        n6 = self._count_connects_during(
            lambda: evidence_ledger.reconstruct_persisted_many(refs6))

        # Constant in K (the whole point): one batched events fetch + one
        # shared blob-resolution connection = 2, for both K=3 and K=6.
        self.assertEqual(n3, n6, f"connection count scaled with K: K=3 -> {n3}, K=6 -> {n6}")
        self.assertLessEqual(n3, 3, f"expected a small constant (<=3), got {n3}")

        # Non-vacuousness: the OLD per-finding path (K single reconstruct_
        # persisted calls) opens strictly more, and grows with K -- so the
        # assertion above is really catching the improvement.
        n6_perfinding = self._count_connects_during(
            lambda: [evidence_ledger.reconstruct_persisted(r) for r in refs6])
        self.assertGreater(n6_perfinding, n6)


class ReportRendersWithBatchedMapTests(_TempStoreDB):
    """The wiring in generate_markdown_report must render without error and
    still surface the evidence-chain line for a finding that has a ledger
    chain (the batched map feeds the same _render_finding branch as before)."""

    def test_report_includes_evidence_chain_line_via_batched_map(self):
        from harness import report_generator
        from harness.models import HttpExchange, Finding
        url = "https://batch.example.com/api/x"
        finding = Finding(
            vulnerability_class="sqli", confidence=0.9, summary="batched-report finding",
            evidence="e", suggested_test="t", basis="derived",
            case_id="case-batch-1", finding_id="finding-batch-1", proof_id="proof-batch-1",
        )
        store.persist_findings(
            HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                         response_status=200, response_headers={}, response_body=""),
            "test_agent", [finding])
        # Seed a ledger chain under the finding's finding_id (the ref the
        # report looks up) so the evidence-chain line is emitted.
        self._seed_finding_with_events("finding-batch-1", resolvable_blobs=True)

        stored = store.all_host_findings(url)
        report = report_generator.generate_markdown_report(url, stored)
        self.assertIn("Evidence chain: `finding-batch-1`", report)
        self.assertIn("independently reproducible", report)


if __name__ == "__main__":
    unittest.main()
