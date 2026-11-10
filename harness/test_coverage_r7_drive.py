"""Coverage defects from the r7 live run, through the real cell-building and drive
path (coverage_tracker.build_coverage_cases_driven / build_coverage_driven).

- A GET endpoint whose captures carry a query parameter -- blank (`?term=`) or
  not -- gets parameter-level injection cells. The endpoint key's path is stored
  without its query, so the applicability predicate used to read every such
  endpoint as taking no input.

Synthetic loopback endpoints only; no request is sent (the leg seam is a stub).
"""
import asyncio
import unittest
from types import SimpleNamespace

from harness.coverage_model import CellStatus
from harness.coverage_tracker import build_coverage_cases_driven
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.role_crawl import RoleSession

BASE = "http://127.0.0.1:9/"
ROLES = [RoleSession("anonymous", {})]
SQLI = "WSTG-INPV-05"


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


if __name__ == "__main__":
    unittest.main()
