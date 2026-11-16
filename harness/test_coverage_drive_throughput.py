"""Coverage drive throughput (CURRENT_STATE open item 7), from the r10 ledger.

- Time-bound drive order. One cell per check per pass shares a count: in r10 the
  5 h deadline came after about 172 cells of every check, sqlmap's took most of the
  time, and 912 cells of quick checks stayed queued. Under a deadline the next cell
  now comes from the check that has used the least drive time. Controls: the
  count-fair order starves the quick check; legs that take no time keep the
  count-fair order.
- A capture no request could be built from (no observed object id, no parameter
  for the leg, not the input a case names) no longer hides the verdict of a capture
  of the same cell that ran. Control: a run that answered without a verdict still
  keeps the cell open.
- A leg that declined every input it was dispatched on, sending nothing, reads
  as `leg_precondition_unmet`, as a request-level refusal already did, not as an
  unfinished attempt. Control: one input with a verdict keeps it incomplete.

Synthetic loopback endpoints; the drive tests stub the legs, and nothing is sent to
a live target.
"""
from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from harness import coverage_tracker
from harness import test_coverage_replay_dedupe as dedupe
from harness.coverage_model import CHECKS_BY_ID, CellStatus
from harness.coverage_tracker import build_coverage_cases_driven, build_coverage_driven
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.role_crawl import RoleSession
from harness.test_engagement_transport_callers import _EngagementCallerBase
from harness.validators.base import ValidationResult

BASE = "http://127.0.0.1:9/"
ROLES = [RoleSession("anonymous", {})]
SQLI = "WSTG-INJT-05"
NOSQL = "WSTG-INJT-05.6"
CMDI = "WSTG-INJT-12"


class _Clock:
    """A fake `time` module for coverage_tracker: legs advance it by hand."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


def _search_state(searches, reads):
    """`searches` GET routes with a captured query parameter (sqlmap applies) and
    `reads` plain GET routes; CORS applies to every one."""
    state = EngagementState(host="127.0.0.1")
    paths = [f"/api/search{i}" for i in range(searches)] + [f"/api/page{i}" for i in range(reads)]
    state.ingest_role_crawl({"endpoints": [
        {"method": "GET", "path": p, "by_role": {"anonymous": 200},
         "reachable_roles": ["anonymous"], "object_scoped": False} for p in paths]})
    for i in range(searches):
        url = f"{BASE}api/search{i}?term=x"
        state.record_template(url, "GET", HttpExchange(url=url, method="GET", response_status=200))
    return state


class TimeFairDriveTests(unittest.TestCase):
    SLOW, QUICK = 100.0, 1.0   # fake seconds per sqlmap / per CORS dispatch
    DEADLINE = 300.0

    def drive(self, case_drive, *, deadline=DEADLINE, leg_seconds=None):
        clock = _Clock()
        calls = []

        def spend(check):
            calls.append(check.confirmation)
            if leg_seconds is None:
                clock.now += self.SLOW if check.confirmation == "sqlmap" else self.QUICK

        async def run_leg(identity, method, path, check):
            spend(check)
            return SimpleNamespace(status="not_confirmed", sent_count=1, summary="stub leg")

        async def run_case(identity, method, path, check, case, **kwargs):
            spend(check)
            return SimpleNamespace(status="not_confirmed", sent_count=1, summary="stub leg",
                                   tested_parameters=((case.parameter_location, case.parameter_name),))
        out = []
        with patch.object(coverage_tracker, "time", clock):
            limit = None if deadline is None else clock.now + deadline
            if case_drive:
                report = asyncio.run(build_coverage_cases_driven(
                    _search_state(10, 40), ROLES, run_case, driveable={"sqlmap", "cors"},
                    budget=10_000, deadline=limit, tracker_out=out))
            else:
                report = asyncio.run(build_coverage_driven(
                    _search_state(10, 40), ROLES, run_leg, driveable={"sqlmap", "cors"},
                    budget=10_000, deadline=limit, tracker_out=out))
        tracker = out[0]
        left = [CHECKS_BY_ID[cid].confirmation for _i, _e, cid in tracker.queued - tracker.attempted]
        return report, calls, left

    def test_quick_cells_are_not_starved_by_a_slow_check_under_a_deadline(self):
        for case_drive in (False, True):
            with self.subTest(case_drive=case_drive):
                report, calls, left = self.drive(case_drive)
                self.assertEqual(report["drive_stopped_by"], "time budget")
                self.assertEqual(calls.count("cors"), 50, calls)
                self.assertNotIn("cors", left)
                self.assertGreaterEqual(calls.count("sqlmap"), 2, calls)   # the slow check still gets turns
                self.assertIn("sqlmap", left)

    def test_negative_control_the_count_fair_order_starves_the_quick_check(self):
        def count_fair(items, unauthenticated=frozenset(), spent=None):
            return coverage_tracker._fair_cells(items, unauthenticated)
        for case_drive in (False, True):
            with self.subTest(case_drive=case_drive), \
                    patch.object(coverage_tracker, "_time_fair_cells", count_fair):
                report, calls, left = self.drive(case_drive)
                self.assertEqual(report["drive_stopped_by"], "time budget")
                self.assertLessEqual(calls.count("cors"), 4, calls)
                self.assertGreater(left.count("cors"), 40)

    def test_control_legs_that_take_no_time_keep_the_count_fair_order(self):
        for case_drive in (False, True):
            with self.subTest(case_drive=case_drive):
                _, timed, _ = self.drive(case_drive, leg_seconds=0.0)
                _, untimed, left = self.drive(case_drive, deadline=None, leg_seconds=0.0)
                self.assertEqual(timed, untimed)
                self.assertEqual(left, [])
                self.assertEqual(untimed[:4], ["sqlmap", "cors", "sqlmap", "cors"])


class DeclinedInputsTests(unittest.TestCase):
    KEY = ("anonymous", "GET /api/items/search", SQLI)

    def drive(self, answer):
        state = EngagementState(host="127.0.0.1")
        state.ingest_role_crawl({"endpoints": [
            {"method": "GET", "path": "/api/items/search", "by_role": {"anonymous": 200},
             "reachable_roles": ["anonymous"], "object_scoped": False}]})
        url = BASE + "api/items/search?term=x&sort=y"
        state.record_template(url, "GET", HttpExchange(url=url, method="GET", response_status=200))

        async def run_case(identity, method, path, check, case, **kwargs):
            return answer(case)
        out = []
        asyncio.run(build_coverage_cases_driven(state, ROLES, run_case, driveable={"sqlmap"},
                                                budget=50, tracker_out=out))
        tracker = out[0]
        row = next(r for r in tracker.phase_ledger()["cells"]
                   if (r["identity"], r["endpoint"], r["check"]) == self.KEY)
        rep = next(r for c, r in tracker.matrix.cases_for_cell(*self.KEY) if c.is_no_parameter)
        return row, rep

    @staticmethod
    def declined(case):
        return SimpleNamespace(status="skipped", sent_count=0,
                               summary=f"no parameter named {case.parameter_name} to inject into")

    def test_a_leg_that_declined_every_input_is_a_precondition_not_an_incomplete_attempt(self):
        row, rep = self.drive(self.declined)
        self.assertEqual(rep.status, CellStatus.SKIPPED)
        self.assertIn("declined every input", rep.reason)
        self.assertTrue(row["attempted"])
        self.assertEqual(row["terminal_reason"], "leg_precondition_unmet", row)
        self.assertFalse(row["sent"] or row["conclusive"], row)

    def test_control_one_input_with_a_verdict_stays_an_incomplete_attempt(self):
        def answer(case):
            if case.parameter_name == "term":
                return SimpleNamespace(status="not_confirmed", sent_count=3, summary="stub negative",
                                       tested_parameters=(("query", "term"),))
            return self.declined(case)
        row, rep = self.drive(answer)
        self.assertEqual(rep.status, CellStatus.INCONCLUSIVE)
        self.assertEqual(row["terminal_reason"], "incomplete_attempt", row)
        self.assertFalse(row["conclusive"], row)


class UnbuiltCaptureTests(_EngagementCallerBase, unittest.TestCase):
    """investigate_engagement with the coverage drive on, as the server enters it;
    the drive's legs are recorded, not sent. GET /api/items/list is captured twice
    as alice, without a query and with `?q=lamp`."""

    CAPTURES = [("/api/items/list", {}), ("/api/items/list?q=lamp", {})]

    def investigate(self, name, answer, *, case_drive=False):
        calls = []

        async def validate(self_, finding, exchange, *args, **kwargs):
            path = exchange.url.split("/api/", 1)[-1]
            calls.append((path, getattr(finding, "parameter_name", "") or ""))
            return answer(finding, path)
        target = {"nosql": "harness.validators.nosql_validator.NosqlValidator.validate",
                  "command_injection": "harness.validators.command_injection_validator."
                                       "CommandInjectionValidator.validate"}[name]
        result, _ = dedupe.DriveCallerTests._investigate(
            self, self.CAPTURES, engagement_cfg={"coverage_drive_cases": case_drive},
            extra=[patch(target, new=validate)])
        return result, calls

    @staticmethod
    def cell(result, check_id):
        return dedupe.DriveCallerTests.cell(result, dedupe.ALICE_ID, "GET /api/items/list", check_id)

    def test_a_capture_without_a_parameter_does_not_hide_the_one_that_ran(self):
        # r10: 53 NoSQL cells read "missing_parameter", with no sends.
        result, calls = self.investigate("nosql", lambda f, path: ValidationResult(
            "nosql", "not_confirmed", "nosql_injection", summary="operator values behaved like strings"))
        self.assertEqual([path for path, _ in calls], ["items/list?q=lamp"], calls)
        row = self.cell(result, NOSQL)
        self.assertEqual(row["terminal_reason"], "conclusive", row)
        self.assertNotIn("missing_parameter", row["detail"])

    def test_control_a_run_without_a_verdict_leaves_the_cell_open_under_its_own_reason(self):
        result, _ = self.investigate("nosql", lambda f, path: ValidationResult(
            "nosql", "inconclusive", "nosql_injection", summary="no complete differential"))
        row = self.cell(result, NOSQL)
        self.assertEqual(row["terminal_reason"], "incomplete_attempt", row)
        self.assertIn("no complete differential", row["detail"])

    def test_a_parameter_case_replays_only_the_captures_that_carry_it(self):
        def answer(finding, path):
            if not getattr(finding, "parameter_only", False):
                return ValidationResult("command_injection", "not_confirmed", "command_injection",
                                        summary="no shell payload took effect")
            if f"{finding.parameter_name}=" not in path:
                # what the leg says of a request without that input
                return ValidationResult("command_injection", "skipped", "command_injection",
                                        summary="no parameter to inject a shell payload into")
            return ValidationResult("command_injection", "not_confirmed", "command_injection",
                                    summary="no shell payload took effect",
                                    tested_parameters=(("query", finding.parameter_name),))
        result, calls = self.investigate("command_injection", answer, case_drive=True)
        self.assertNotIn(("items/list", "q"), calls)
        self.assertIn(("items/list?q=lamp", "q"), calls)
        row = self.cell(result, CMDI)
        self.assertEqual(row["terminal_reason"], "conclusive", row)


if __name__ == "__main__":
    unittest.main()
