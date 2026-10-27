"""Ticket E11: the job result carries the coverage cell matrix once, not three times.

`CoverageTracker.report()` used to serialise every cell as a phase_ledger row, as a
not_tested row and again in checkpoint.matrix. Now the ledger lists only cells that
are shape-applicable or have a non-default state, the not-applicable rows are
counted per check, and checkpoint.matrix (what resume reads) stays complete. The
worklist in the job result carries each capture variant's response body as a digest;
the engagement state keeps the full body.

Caller-level: the coverage tests run the real build_coverage_driven (budget-limited,
so some cells are attempted and some stay queued) and resume from its checkpoint;
the worklist test runs Orchestrator.investigate_engagement. The uncompacted baseline
is the tracker's own `compact=False` rendering of the same run, i.e. the old payload.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import yaml

from harness import coverage_tracker, engagement_builder, role_crawl, worklist_investigator
from harness.coverage_model import CellStatus, CoverageMatrix
from harness.coverage_tracker import CoverageTracker, build_coverage_driven
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession

_ENDPOINTS = 40


def _state() -> EngagementState:
    """40 endpoints: mostly plain GET pages (most checks do not apply), a few
    object-scoped ones the cross-identity leg does apply to."""
    state = EngagementState("shop.test")
    for n in range(_ENDPOINTS):
        path = f"/api/orders/{n}" if n < 4 else f"/pages/static-{n}"
        url = "http://shop.test" + path
        state.record_template(url, "GET", HttpExchange(url=url, method="GET", response_status=200))
    for ep in state.endpoints.values():
        ep.reachable_roles = ["user"]
        ep.object_scoped = ep.path.startswith("/api/orders/")
    return state


def _roles():
    return [RoleSession("user", {}, name="alice"), RoleSession("user", {}, name="bob")]


async def _run_leg(identity, method, path, check):
    return SimpleNamespace(status="not_confirmed", sent_count=2, summary="controls held")


def _drive(budget=3, **kwargs):
    """build_coverage_driven through the real caller, returning (report, tracker)."""
    created = []

    class Recording(CoverageTracker):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            created.append(self)

    with patch.object(coverage_tracker, "CoverageTracker", Recording):
        report = asyncio.run(build_coverage_driven(
            _state(), _roles(), _run_leg, driveable={"cross_identity"}, budget=budget,
            context_key="same-source", **kwargs))
    return report, created[-1]


def _size(report) -> int:
    return len(json.dumps(report, default=str))


class CoveragePayloadTests(unittest.TestCase):
    def setUp(self):
        self.report, self.tracker = _drive()
        self.full = self.tracker.report(compact=False)   # the old payload for this very run

    def _assert_at_least_40_percent_smaller(self, compact, full):
        before, after = _size(full), _size(compact)
        self.assertLessEqual(after, before * 0.6,
                             f"report is not 40% smaller: {before} -> {after} bytes")

    def test_report_is_at_least_40_percent_smaller_and_sizes_are_printed(self):
        before, after = _size(self.full), _size(self.report)
        cells = len(self.tracker.matrix.cells())
        print(f"\n[E11] coverage report for {_ENDPOINTS} endpoints / {cells} cells: "
              f"{before} -> {after} bytes ({100 * (before - after) / before:.1f}% smaller); "
              f"phase_ledger {_size(self.full['phase_ledger'])} -> {_size(self.report['phase_ledger'])}, "
              f"not_tested {_size(self.full['not_tested'])} -> {_size(self.report['not_tested'])}")
        self._assert_at_least_40_percent_smaller(self.report, self.full)

    def test_size_control_fails_on_the_uncompacted_rendering(self):
        with self.assertRaises(AssertionError):
            self._assert_at_least_40_percent_smaller(self.full, self.full)

    def test_counts_are_identical_to_the_full_computation(self):
        compact, full = self.report["phase_ledger"], self.full["phase_ledger"]
        self.assertEqual(compact["counts"], full["counts"])
        self.assertEqual(compact["counts"]["discovered"], len(self.tracker.matrix.cells()))
        self.assertGreater(compact["counts"]["attempted"], 0)
        self.assertGreater(compact["counts"]["queued"], compact["counts"]["attempted"])

    def test_not_applicable_total_plus_emitted_rows_is_the_cell_count(self):
        ledger = self.report["phase_ledger"]
        cell_count = len(self.tracker.matrix.cells())
        self.assertEqual(ledger["not_applicable"]["total"] + len(ledger["cells"]), cell_count)
        self.assertEqual(sum(ledger["not_applicable"]["by_check"].values()),
                         ledger["not_applicable"]["total"])
        self.assertGreater(ledger["not_applicable"]["total"], len(ledger["cells"]),
                           "the fixture must be mostly not applicable")
        self.assertIn("checkpoint.matrix", ledger["cells_omitted_note"])
        # Only not-applicable, untouched cells were left out.
        listed = {(r["identity"], r["endpoint"], r["check"]) for r in ledger["cells"]}
        for key, cell in self.tracker.matrix.cells().items():
            if key not in listed:
                self.assertEqual(cell.status, CellStatus.NOT_APPLICABLE, key)
                self.assertNotIn(key, self.tracker.queued | self.tracker.attempted | self.tracker.reused)

    def test_every_applicable_not_tested_cell_is_still_listed_with_its_reason(self):
        expected = {(r["identity"], r["endpoint"], r["check"]): r
                    for r in self.tracker.matrix.not_tested()
                    if r["status"] != CellStatus.NOT_APPLICABLE.value}
        listed = {(r["identity"], r["endpoint"], r["check"]): r for r in self.report["not_tested"]}
        self.assertTrue(expected)
        self.assertEqual(listed, expected)
        self.assertTrue(all(r["reason"] for r in listed.values()))
        self.assertNotIn(CellStatus.NOT_APPLICABLE.value, {r["status"] for r in listed.values()})

    def test_not_applicable_cells_are_aggregated_by_check_and_reason(self):
        na_rows = [r for r in self.tracker.matrix.not_tested()
                   if r["status"] == CellStatus.NOT_APPLICABLE.value]
        expected: dict = {}
        for r in na_rows:
            expected.setdefault(r["check"], Counter())[r["reason"]] += 1
        self.assertTrue(expected)
        self.assertEqual(self.report["not_tested_not_applicable"],
                         {check: dict(reasons) for check, reasons in expected.items()})

    def test_matrix_method_is_unchanged_for_other_callers(self):
        self.assertTrue(any(r["status"] == CellStatus.NOT_APPLICABLE.value
                            for r in self.tracker.matrix.not_tested()))

    def test_checkpoint_matrix_is_complete_and_round_trips_through_resume(self):
        matrix = CoverageMatrix.from_dict(self.report["checkpoint"]["matrix"])
        self.assertEqual(set(matrix.cells()), set(self.tracker.matrix.cells()))
        # Resume from the compact report's checkpoint: the finished cells are reused,
        # not re-run, and the denominator is unchanged.
        done = set(self.tracker.attempted)
        calls = []

        async def run_leg(identity, method, path, check):
            calls.append((identity, f"{method} {path}", check.id))
            return await _run_leg(identity, method, path, check)

        created = []

        class Recording(CoverageTracker):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                created.append(self)
        with patch.object(coverage_tracker, "CoverageTracker", Recording):
            second = asyncio.run(build_coverage_driven(
                _state(), _roles(), run_leg, driveable={"cross_identity"}, budget=100,
                checkpoint=self.report["checkpoint"], context_key="same-source"))
        self.assertEqual(second["phase_ledger"]["counts"]["resumed"], len(done))
        self.assertFalse(done & set(calls), "a completed cell was run again")
        self.assertEqual(second["phase_ledger"]["counts"]["discovered"],
                         self.report["phase_ledger"]["counts"]["discovered"])
        self.assertEqual(created[-1].reused, done)

    def test_resume_depends_on_the_complete_checkpoint_matrix(self):
        # Control for the round trip: a checkpoint holding only the compact ledger's
        # cells (the cut that would be wrong) resumes nothing.
        gutted = dict(self.report["checkpoint"], matrix={"cells": {}})
        again = asyncio.run(build_coverage_driven(
            _state(), _roles(), _run_leg, driveable={"cross_identity"}, budget=100,
            checkpoint=gutted, context_key="same-source"))
        self.assertEqual(again["phase_ledger"]["counts"]["resumed"], 0)

    # -- a not-applicable cell that was nevertheless worked is never hidden -------
    def _tracker_with_worked_not_applicable_cells(self):
        tracker = self.tracker
        na_keys = [k for k, c in tracker.matrix.cells().items()
                   if c.status == CellStatus.NOT_APPLICABLE
                   and k not in tracker.queued and k not in tracker.attempted]
        queued_key, attempted_key = na_keys[0], na_keys[1]
        tracker.queued.add(queued_key)
        tracker.attempted.add(attempted_key)
        return tracker, queued_key, attempted_key

    def _assert_worked_cells_are_rows(self, report, queued_key, attempted_key):
        rows = {(r["identity"], r["endpoint"], r["check"]): r for r in report["phase_ledger"]["cells"]}
        self.assertIn(queued_key, rows)
        self.assertIn(attempted_key, rows)
        self.assertFalse(rows[queued_key]["shape_applicable"])
        self.assertTrue(rows[queued_key]["queued"])
        self.assertTrue(rows[attempted_key]["attempted"])

    def test_not_applicable_but_queued_or_attempted_cell_is_still_a_row(self):
        tracker, queued_key, attempted_key = self._tracker_with_worked_not_applicable_cells()
        self._assert_worked_cells_are_rows(tracker.report(), queued_key, attempted_key)

    def test_worked_cell_control_fails_when_only_shape_decides_the_rows(self):
        tracker, queued_key, attempted_key = self._tracker_with_worked_not_applicable_cells()
        with patch.object(coverage_tracker, "_listed_in_compact_ledger",
                          lambda row: row["shape_applicable"]):
            report = tracker.report()
        with self.assertRaises(AssertionError):
            self._assert_worked_cells_are_rows(report, queued_key, attempted_key)


_BASE = "http://shop.test/"
_BIG_BODY = "<html>" + "inventory-row;" * 400 + "</html>"


def _config() -> dict:
    cfg = yaml.safe_load((Path(__file__).resolve().parent / "config.yaml").read_text(encoding="utf-8")) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = False
    eng = cfg.setdefault("engagement", {})
    eng["auto_escalate"] = False
    eng["feature_crawl"] = False
    eng["coverage_drive_legs"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["shop.test"]
    return cfg


class WorklistResultTests(unittest.TestCase):
    def _investigate(self, **kwargs):
        built = {}

        async def build(base_url, roles, **kw):
            state = EngagementState(host="shop.test")
            capture = HttpExchange(method="GET", url=f"{_BASE}inventory", request_headers={},
                                   response_status=200, response_headers={"Content-Type": "text/html"},
                                   response_body=_BIG_BODY)
            state.record_template(capture.url, "GET", capture)
            built["state"] = state
            rc = role_crawl.RoleCrawlResult(base_url=base_url)
            rc.captured.append(capture)
            return state, rc

        async def investigate(*args, **kw):
            return [{"path": "/inventory", "method": "GET", "findings_detail": [], "confirmed": False}]

        orch = Orchestrator(_config())
        orch.allowed_hosts = ["shop.test"]
        with patch.object(engagement_builder, "build_engagement", new=build), \
             patch.object(worklist_investigator, "investigate_worklist", new=investigate), \
             patch("harness.orchestrator_chain.review_captured_exchanges", new=AsyncMock(return_value=0)), \
             patch("harness.orchestrator_chain.universal_header_audit", new=AsyncMock(return_value=0)):
            result = asyncio.run(orch.investigate_engagement(
                _BASE, [RoleSession("anonymous", {})], max_nodes=1, max_chain_rounds=0,
                discovery_max_probes=1, **kwargs))
        return result, built["state"]

    def _assert_digest_in_result_and_full_body_in_state(self, result, state):
        variant = result["worklist"][0]["capture_variants"][0]
        self.assertNotIn("response_body", variant)
        self.assertEqual(variant["response_body_len"], len(_BIG_BODY))
        self.assertEqual(variant["response_body_sha256"],
                         __import__("hashlib").sha256(_BIG_BODY.encode()).hexdigest())
        self.assertEqual(variant["response_body_head"], _BIG_BODY[:200])
        self.assertEqual(len(variant["response_body_head"]), 200)
        # The engagement state, and the snapshot taken from it, keep the full body.
        self.assertEqual(state.endpoints["GET /inventory"].capture_variants[0]["response_body"], _BIG_BODY)
        self.assertEqual(state.to_dict()["endpoints"]["GET /inventory"]["capture_variants"][0]["response_body"],
                         _BIG_BODY)
        self.assertEqual(state.worklist(5)[0]["capture_variants"][0]["response_body"], _BIG_BODY)

    def test_job_result_worklist_carries_a_digest_and_the_state_keeps_the_body(self):
        result, state = self._investigate()
        self._assert_digest_in_result_and_full_body_in_state(result, state)

    def test_objective_result_worklist_is_compacted_too(self):
        result, state = self._investigate(stop_on_confirm=True, objective_class="sqli")
        self._assert_digest_in_result_and_full_body_in_state(result, state)

    def test_digest_control_fails_when_the_result_carries_the_raw_worklist(self):
        with patch.object(EngagementState, "result_worklist",
                          lambda self, limit=25: self.worklist(limit)):
            result, state = self._investigate()
        with self.assertRaises(AssertionError):
            self._assert_digest_in_result_and_full_body_in_state(result, state)

    def test_job_result_is_smaller_than_the_raw_worklist(self):
        result, state = self._investigate()
        before, after = _size(state.worklist(50)), _size(result["worklist"])
        print(f"\n[E11] worklist in the job result: {before} -> {after} bytes")
        self.assertLess(after, before * 0.5)


if __name__ == "__main__":
    unittest.main()
