"""Coverage defects from the r7 live run, through the real cell-building and drive
path (coverage_tracker.build_coverage_cases_driven / build_coverage_driven).

- A GET endpoint whose captures carry a query parameter -- blank (`?term=`) or
  not -- gets parameter-level injection cells. The endpoint key's path is stored
  without its query, so the applicability predicate used to read every such
  endpoint as taking no input.
- Under a leg budget the drive shares the budget across check classes, so many
  per-route endpoint checks cannot starve a write route's function-level authz
  cell or an injection cell on a captured parameter.

Synthetic loopback endpoints only; no request is sent (the leg seam is a stub).
"""
import asyncio
import unittest
from types import SimpleNamespace

from harness.coverage_model import CellStatus
from harness.coverage_tracker import build_coverage_cases_driven, build_coverage_driven
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.role_crawl import RoleSession

BASE = "http://127.0.0.1:9/"
ROLES = [RoleSession("anonymous", {})]
SQLI = "WSTG-INJT-05"


def _state(captures, endpoints):
    """`endpoints`: (method, path) reached anonymously; `captures`: URLs recorded
    as request templates (GET)."""
    state = EngagementState(host="127.0.0.1")
    state.ingest_role_crawl({"endpoints": [
        {"method": m, "path": p, "by_role": {"anonymous": 200},
         "reachable_roles": ["anonymous"], "object_scoped": False} for m, p in endpoints]})
    for url in captures:
        state.record_template(url, "GET", HttpExchange(
            url=url, method="GET", response_status=200, response_body="[]"))
    return state


def _drive(state, driveable=frozenset({"sqlmap"}), budget=50):
    calls = []

    async def run_case(ident, method, path, check, case):
        calls.append((f"{method} {path}", check.id, case.label()))
        return SimpleNamespace(status="not_confirmed", summary="stub leg", confidence=None,
                               validator=check.confirmation, evidence="",
                               tested_parameter=(case.parameter_location, case.parameter_name))
    out = []
    report = asyncio.run(build_coverage_cases_driven(
        state, ROLES, run_case, driveable=set(driveable), budget=budget, tracker_out=out))
    return report, out[0], calls


class BlankQueryParameterCellsTests(unittest.TestCase):
    def test_a_blank_query_parameter_gets_a_parameter_level_injection_cell(self):
        state = _state([BASE + "api/items/search?term=", BASE + "api/items/search?term="],
                       [("GET", "/api/items/search")])
        report, tracker, calls = _drive(state)
        cell = tracker.matrix.get("anonymous", "GET /api/items/search", SQLI)
        self.assertNotEqual(cell.status, CellStatus.NOT_APPLICABLE, cell.reason)
        labels = {c.label() for c, _ in tracker.matrix.cases_for_cell(
            "anonymous", "GET /api/items/search", SQLI)}
        self.assertIn("query:term", labels)
        self.assertTrue(any(ep == "GET /api/items/search" and cid == SQLI for ep, cid, _ in calls),
                        calls)

    def test_control_a_parameter_no_capture_carried_gets_no_cell(self):
        state = _state([BASE + "api/items/search?term="],
                       [("GET", "/api/items/search"), ("GET", "/api/items/catalog")])
        _, tracker, calls = _drive(state)
        labels = {c.label() for c, _ in tracker.matrix.cases_for_cell(
            "anonymous", "GET /api/items/search", SQLI)}
        self.assertNotIn("query:page", labels)
        self.assertEqual(labels - {"<no-parameter>", "query:term"}, set())
        # an endpoint no capture gave a parameter stays out of the injection leg
        cell = tracker.matrix.get("anonymous", "GET /api/items/catalog", SQLI)
        self.assertEqual(cell.status, CellStatus.NOT_APPLICABLE)
        self.assertFalse(any(ep == "GET /api/items/catalog" for ep, _, _ in calls))


class BudgetSharedAcrossCheckClassesTests(unittest.TestCase):
    ROLES = [RoleSession("anonymous", {}), RoleSession("user", {"Authorization": "Bearer u"})]
    DRIVEABLE = {"cors", "cross_identity", "sqlmap"}
    WRITE = "PUT /api/things/{id}"
    SEARCH = "GET /api/items/search"

    def state(self):
        reads = [("GET", f"/api/page{chr(97 + i)}{chr(97 + j)}") for i in range(5) for j in range(6)]
        state = EngagementState(host="127.0.0.1")
        state.ingest_role_crawl({"endpoints": [
            {"method": m, "path": p, "by_role": {"anonymous": 200, "user": 200},
             "reachable_roles": ["anonymous", "user"], "object_scoped": False}
            for m, p in reads + [("GET", "/api/items/search")]] + [
            {"method": "PUT", "path": "/api/things/{id}", "by_role": {"anonymous": 401, "user": 200},
             "reachable_roles": ["user"], "object_scoped": True}]})
        state.record_template(BASE + "api/items/search?term=", "GET", HttpExchange(
            url=BASE + "api/items/search?term=", method="GET", response_status=200))
        return state

    def drive(self, budget):
        calls = []

        async def run(identity, method, path, check):
            calls.append((identity, f"{method} {path}", check.id))
            return SimpleNamespace(status="not_confirmed", sent_count=1, summary="stub leg")
        report = asyncio.run(build_coverage_driven(self.state(), self.ROLES, run,
                                                   driveable=set(self.DRIVEABLE), budget=budget))
        return report, calls

    def test_a_small_budget_reaches_the_write_authz_and_injection_cells(self):
        report, calls = self.drive(budget=6)
        self.assertEqual(len(calls), 6)
        self.assertGreater(report["queued_not_attempted"], 50)   # most cells stay queued
        driven = {(ep, cid) for _, ep, cid in calls}
        self.assertIn((self.WRITE, "WSTG-ATHZ-02"), driven, calls)
        self.assertIn((self.SEARCH, SQLI), driven, calls)

    def test_negative_control_the_previous_order_starves_them(self):
        from unittest.mock import patch
        from harness import coverage_tracker
        with patch.object(coverage_tracker, "_fair_cells", coverage_tracker._spread_cells):
            _, calls = self.drive(budget=6)
        driven = {(ep, cid) for _, ep, cid in calls}
        self.assertNotIn((self.WRITE, "WSTG-ATHZ-02"), driven, calls)
        self.assertNotIn((self.SEARCH, SQLI), driven, calls)

    def test_control_an_unlimited_budget_still_drives_every_queued_leg(self):
        report, calls = self.drive(budget=10_000)
        self.assertEqual(report["queued_not_attempted"], 0)
        self.assertEqual(len(calls), len(set(calls)), "a cell was driven twice")
        self.assertEqual(report["legs_driven"], len(calls))
        # every route x check the matrix queued was driven, reads included
        self.assertEqual(len({ep for _, ep, _ in calls}), 32)


if __name__ == "__main__":
    unittest.main()
