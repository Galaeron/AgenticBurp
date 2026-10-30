"""Stage reservations: the coverage drive keeps a share of the run's request ceiling,
and the investigation and coverage stages end on their own time bounds.

Units cover the budget hold, the worklist deadline and both coverage drivers; the
caller tests drive ``investigate_engagement`` with a real RunContext. Each fix has a
defect-injection control that reinstates the old behaviour and shows the symptom.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from harness import (cache, coverage_tracker, engagement_builder, evidence_ledger, role_crawl,
                     safety_gate, store, worklist_investigator)
from harness import worklist_investigator as wi
from harness.coverage_tracker import CoverageTracker, build_coverage_driven
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.run_context import RequestBudget, RunContext
from harness.test_coverage_tracker import _state_with as _coverage_state
from harness.test_deterministic_first import BASE, _config
from harness.test_worklist_investigator import ADMIN, OBJ, ROLES, _nothing
from harness.test_worklist_investigator import _state_with as _worklist_state


class _Clock:
    """A monotonic clock the code under test reads through its `time` module."""

    def __init__(self, now=100.0):
        self.now = now

    def monotonic(self):
        return self.now


# ------------------------------------------------------------------ RequestBudget
class RequestBudgetHoldTests(unittest.TestCase):
    def test_hold_withholds_from_every_reservation_until_released(self):
        budget = RequestBudget(10)
        self.assertEqual(budget.hold(4), 4)
        self.assertEqual(budget.remaining, 6)
        self.assertEqual(sum(budget.reserve() for _ in range(10)), 6)
        self.assertEqual(budget.used, 6)
        self.assertEqual(budget.release_hold(), 4)
        self.assertEqual(budget.remaining, 4)
        self.assertEqual(sum(budget.reserve() for _ in range(10)), 4)
        self.assertEqual(budget.used, 10)

    def test_hold_is_capped_at_the_unspent_ceiling(self):
        budget = RequestBudget(10)
        for _ in range(7):
            budget.reserve()
        self.assertEqual(budget.hold(50), 3)
        self.assertFalse(budget.reserve())
        self.assertEqual(budget.remaining, 0)

    def test_unbounded_or_empty_hold_reserves_nothing(self):
        self.assertEqual(RequestBudget(None).hold(5), 0)
        budget = RequestBudget(10)
        self.assertEqual(budget.hold(0), 0)
        self.assertEqual(budget.remaining, 10)
        self.assertEqual(budget.release_hold(), 0)


# ------------------------------------------------------------------ worklist deadline
class WorklistDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def _sweep(self, deadline, *, clock=None, advance=0.0):
        st = _worklist_state([OBJ, ADMIN])
        calls = []

        async def probe(exchange, hypothesis, specialty, step_budget):
            calls.append(specialty)
            if clock is not None:
                clock.now += advance
            return _nothing()

        summary = {}
        with patch.object(wi, "time", clock or time):
            await wi.investigate_worklist(probe, st, "http://t", ROLES, max_nodes=8,
                                          summary_out=summary, deadline=deadline)
        return calls, summary

    async def test_unexpired_deadline_investigates_as_without_one(self):
        unbounded, base = await self._sweep(None)
        bounded, summary = await self._sweep(time.monotonic() + 3600)
        self.assertEqual(sorted(bounded), sorted(unbounded))
        self.assertGreaterEqual(len(unbounded), 2)
        self.assertNotIn(wi.SKIP_TIME_BUDGET, summary["skipped_by_reason"])
        self.assertEqual(summary["eligible"], base["eligible"])

    async def test_expired_deadline_probes_nothing_and_names_every_due_node(self):
        calls, summary = await self._sweep(time.monotonic() - 1)
        self.assertEqual(calls, [])
        timed_out = [s for s in summary["skipped"] if s["reason"] == wi.SKIP_TIME_BUDGET]
        self.assertEqual({s["path"] for s in timed_out}, {OBJ["path"], ADMIN["path"]})
        self.assertEqual(summary["skipped_by_reason"][wi.SKIP_TIME_BUDGET], 2)
        # Nodes left by the deadline still count as eligible work.
        self.assertEqual(summary["eligible"], 2)
        self.assertEqual(summary["investigated"], 0)
        self.assertTrue(all(s["next_action"] == "Resume with additional time" for s in timed_out))

    async def test_deadline_reached_mid_sweep_stops_before_the_next_node(self):
        clock = _Clock()
        calls, summary = await self._sweep(130.0, clock=clock, advance=45.0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(summary["investigated"], 1)
        self.assertEqual(summary["skipped_by_reason"].get(wi.SKIP_TIME_BUDGET), 1)

    async def test_node_with_nothing_to_run_keeps_its_own_reason(self):
        benign = {"method": "GET", "path": "/api/health", "by_role": {"anonymous": 200},
                  "reachable_roles": ["anonymous"], "object_scoped": False}
        st = _worklist_state([benign])
        summary = {}
        await wi.investigate_worklist(AsyncMock(), st, "http://t", ROLES,
                                      summary_out=summary, deadline=time.monotonic() - 1)
        self.assertNotIn(wi.SKIP_TIME_BUDGET, summary["skipped_by_reason"])


# ------------------------------------------------------------------ coverage deadlines
def _coverage_endpoints():
    st = _coverage_state([
        ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),
        ("POST", "/api/search", {"reachable_roles": ["user"]}),
    ])
    st.endpoints["POST /api/search"].template = {
        "method": "POST", "query": "search=x&sort=y", "body": "",
        "content_type": "", "object_id": None}
    return st


class _Negative:
    status = "not_confirmed"
    summary = "no signal"
    confidence = None
    evidence = ""
    validator = "fixture"


class CoverageDeadlineTests(unittest.TestCase):
    def _legs(self, deadline, *, clock=None, advance=0.0, budget=100):
        sent = []

        async def run_leg(identity, method, path, check):
            sent.append((identity, method, path, check.id))
            if clock is not None:
                clock.now += advance
            return _Negative()

        with patch.object(coverage_tracker, "time", clock or time):
            report = asyncio.run(build_coverage_driven(
                _coverage_endpoints(), ["user"], run_leg, budget=budget, deadline=deadline))
        return sent, report

    def _cases(self, deadline, *, clock=None, advance=0.0):
        sent = []

        async def run_case(identity, method, path, check, case_key):
            sent.append((identity, method, path, check.id))
            if clock is not None:
                clock.now += advance
            return _Negative()

        with patch.object(coverage_tracker, "time", clock or time):
            report = asyncio.run(coverage_tracker.build_coverage_cases_driven(
                _coverage_endpoints(), [SimpleNamespace(role="user")], run_case, budget=100,
                deadline=deadline))
        return sent, report

    def test_unexpired_deadline_drives_every_leg(self):
        unbounded, base = self._legs(None)
        bounded, report = self._legs(time.monotonic() + 3600)
        self.assertGreaterEqual(len(unbounded), 2)
        self.assertEqual(sorted(bounded), sorted(unbounded))
        self.assertIsNone(report["drive_stopped_by"])
        self.assertEqual(report["queued_not_attempted"], 0)
        self.assertEqual(base["queued_not_attempted"], 0)

    def test_expired_deadline_drives_no_leg_and_reports_the_queue(self):
        unbounded, _ = self._legs(None)
        sent, report = self._legs(time.monotonic() - 1)
        self.assertEqual(sent, [])
        self.assertEqual(report["legs_driven"], 0)
        self.assertEqual(report["drive_stopped_by"], "time budget")
        self.assertEqual(report["queued_not_attempted"], len(unbounded))

    def test_deadline_reached_mid_drive_stops_before_the_next_leg(self):
        unbounded, _ = self._legs(None)
        sent, report = self._legs(130.0, clock=_Clock(), advance=45.0)
        self.assertEqual(len(sent), 1)
        self.assertEqual(report["drive_stopped_by"], "time budget")
        self.assertEqual(report["queued_not_attempted"], len(unbounded) - 1)

    def test_leg_budget_stop_is_named_apart_from_time(self):
        sent, report = self._legs(None, budget=1)
        self.assertEqual(len(sent), 1)
        self.assertEqual(report["drive_stopped_by"], "leg budget")

    def test_case_drive_honours_the_deadline(self):
        unbounded, base = self._cases(None)
        self.assertGreaterEqual(len(unbounded), 2)
        self.assertIsNone(base["drive_stopped_by"])
        sent, report = self._cases(130.0, clock=_Clock(), advance=45.0)
        self.assertEqual(len(sent), 1)
        self.assertEqual(report["cases_driven"], 1)
        self.assertEqual(report["drive_stopped_by"], "time budget")
        self.assertEqual(report["queued_not_attempted"], len(unbounded) - 1)

    def test_control_a_drive_ignoring_its_deadline_sends_after_it(self):
        """Defect injection: the former driver had no deadline; the test above sees it."""
        original = CoverageTracker.drive_coverage_legs

        async def no_deadline(self, run_leg, *, driveable=None, budget=80, deadline=None, readiness=None):
            return await original(self, run_leg, driveable=driveable, budget=budget, readiness=readiness)

        with patch.object(CoverageTracker, "drive_coverage_legs", no_deadline):
            sent, report = self._legs(time.monotonic() - 1)
        self.assertGreaterEqual(len(sent), 2)
        self.assertIsNone(report["drive_stopped_by"])


# ------------------------------------------------------------------ caller wiring
async def _build(base_url, roles, **kwargs):
    state = EngagementState(host="shop.test")
    state._ep("GET", "/filter")
    rc = role_crawl.RoleCrawlResult(base_url=base_url)
    rc.captured.append(HttpExchange(method="GET", url=f"{BASE}filter?q=1",
                                    response_status=200, response_body="ok"))
    return state, rc


class StageReservationCaller(unittest.TestCase):
    """investigate_engagement holds the coverage reserve and passes the stage bounds."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="stage_reservations_")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()

    def tearDown(self):
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _investigate(self, *, reserve=0, investigation=0.0, coverage_seconds=0.0,
                     review_seconds=0.0, max_requests=100, worklist_skips=None,
                     drive_report=None, chain_rounds=0, cases=False, extra_patches=()):
        cfg = _config()
        cfg["engagement"].update(coverage_drive_legs=True, coverage_drive_cases=cases,
                                 capture_review_seconds=review_seconds,
                                 coverage_request_reserve=reserve,
                                 investigation_seconds=investigation,
                                 coverage_drive_seconds=coverage_seconds)
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["shop.test"]
        rc = RunContext.create(allowed_hosts=["shop.test"], max_requests=max_requests, config=cfg)
        seen = {}

        async def spend_worklist(*args, **kwargs):
            # An earlier stage spends every request the run will let it have.
            seen["worklist_deadline"] = kwargs.get("deadline")
            while rc.budget.reserve():
                pass
            seen["used_by_worklist"] = rc.budget.used
            if worklist_skips:
                kwargs["summary_out"].update(skipped_by_reason=dict(worklist_skips))
            return []

        async def review(*args, **kwargs):
            seen["review_deadline"] = kwargs.get("deadline")
            return 0

        async def drive(state, roles, run_leg, **kwargs):
            seen["drive"] = "cases" if "per_cell_case_budget" in kwargs else "legs"
            seen["drive_deadline"] = kwargs.get("deadline")
            seen["remaining_at_drive"] = rc.budget.remaining
            return dict(drive_report or {"drive_stopped_by": None, "queued_not_attempted": 0})

        patches = [patch.object(engagement_builder, "build_engagement", new=_build),
                   patch.object(worklist_investigator, "investigate_worklist", new=spend_worklist),
                   patch.object(coverage_tracker, "build_coverage_driven", new=drive),
                   patch.object(coverage_tracker, "build_coverage_cases_driven", new=drive),
                   patch("harness.orchestrator_chain.review_captured_exchanges", new=review),
                   patch("harness.orchestrator_chain.universal_header_audit",
                         new=AsyncMock(return_value=0)),
                   patch("harness.browser_driver.default_driver", return_value=None),
                   *extra_patches]

        async def go():
            try:
                async with rc:
                    return await orch.investigate_engagement(
                        BASE, [RoleSession("anonymous", {})], max_nodes=1,
                        max_chain_rounds=chain_rounds, discovery_max_probes=1,
                        run_context=rc)
            finally:
                await rc.aclose()

        for p in patches:
            p.start()
        try:
            started = time.monotonic()
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        seen["started"], seen["ended"] = started, time.monotonic()
        return result, seen

    def test_reserve_is_withheld_from_earlier_stages_and_released_for_coverage(self):
        result, seen = self._investigate(reserve=30, max_requests=100)
        self.assertEqual(seen["used_by_worklist"], 70)
        self.assertEqual(seen["remaining_at_drive"], 30)
        self.assertEqual(result["stage_budgets"]["coverage_request_reserve"], 30)
        self.assertEqual(result["stage_budgets"]["requests_before_coverage"], 70)

    def test_default_configuration_reserves_nothing_and_bounds_no_stage(self):
        result, seen = self._investigate()
        self.assertEqual(seen["used_by_worklist"], 100)
        self.assertEqual(seen["remaining_at_drive"], 0)
        self.assertIsNone(seen["worklist_deadline"])
        self.assertIsNone(seen["review_deadline"])
        self.assertIsNone(seen["drive_deadline"])
        self.assertEqual(result["stage_budgets"]["coverage_request_reserve"], 0)
        self.assertFalse([e for e in result["errors"] if "time budget" in str(e.get("error"))])

    def test_investigation_bound_reaches_the_worklist_and_caps_review(self):
        _, seen = self._investigate(investigation=900)
        self.assertGreaterEqual(seen["worklist_deadline"], seen["started"] + 900)
        self.assertLessEqual(seen["worklist_deadline"], seen["ended"] + 900)
        # No review bound of its own: the review ends with the investigation.
        self.assertEqual(seen["review_deadline"], seen["worklist_deadline"])
        self.assertIsNone(seen["drive_deadline"])

    def test_shorter_review_bound_is_kept_under_the_investigation_bound(self):
        _, seen = self._investigate(investigation=900, review_seconds=5)
        self.assertLess(seen["review_deadline"], seen["worklist_deadline"])
        self.assertLessEqual(seen["review_deadline"], seen["ended"] + 5)

    def test_coverage_bound_reaches_the_drive_and_starts_at_the_drive(self):
        _, seen = self._investigate(coverage_seconds=600)
        self.assertGreaterEqual(seen["drive_deadline"], seen["started"] + 600)
        self.assertLessEqual(seen["drive_deadline"], seen["ended"] + 600)
        self.assertIsNone(seen["worklist_deadline"])

    def test_coverage_bound_reaches_the_case_drive(self):
        _, seen = self._investigate(coverage_seconds=600, cases=True)
        self.assertEqual(seen["drive"], "cases")
        self.assertGreaterEqual(seen["drive_deadline"], seen["started"] + 600)
        self.assertLessEqual(seen["drive_deadline"], seen["ended"] + 600)

    def test_truncation_by_either_bound_is_reported_and_the_run_is_incomplete(self):
        result, _ = self._investigate(
            investigation=900, coverage_seconds=600,
            worklist_skips={wi.SKIP_TIME_BUDGET: 3},
            drive_report={"drive_stopped_by": "time budget", "queued_not_attempted": 4})
        self.assertIn({"phase": "worklist", "error": "investigation time budget reached: "
                       "3 worklist node(s) not investigated"}, result["errors"])
        self.assertIn({"phase": "coverage_drive", "error": "coverage drive time budget "
                       "reached: 4 queued leg(s) not attempted"}, result["errors"])
        self.assertTrue(result["degraded"])
        self.assertEqual(result["assessment"]["status"], "incomplete")

    def _chain(self, investigation):
        """One run whose first link offers a credential, so a chain round is due.
        Linking moves the chain module's clock past any investigation bound."""
        skew = {"seconds": 0.0}
        clock = SimpleNamespace(monotonic=lambda: time.monotonic() + skew["seconds"],
                                time=time.time, perf_counter=time.perf_counter)

        def link(*args, **kwargs):
            skew["seconds"] = 10_000.0
            return {"chain_findings": [], "credential_caps": [
                {"kind": "bearer", "source_url": f"{BASE}login", "headers": {}}]}

        return self._investigate(investigation=investigation, chain_rounds=2, extra_patches=(
            patch("harness.chain_linker.link_findings", new=link),
            patch("harness.orchestrator_chain.time", clock),
            patch.object(Orchestrator, "_credential_grants_access",
                         new=AsyncMock(return_value=False))))

    def test_expired_investigation_bound_starts_no_chain_round(self):
        result, _ = self._chain(investigation=900)
        self.assertEqual(result["chain_rounds"], 0)
        self.assertIn({"phase": "chain_rounds", "error": "investigation time budget reached: "
                       "chain round 1 of up to 2 not started"}, result["errors"])
        self.assertEqual(result["assessment"]["status"], "incomplete")

    def test_control_without_a_bound_the_due_chain_round_starts(self):
        result, _ = self._chain(investigation=0)
        self.assertEqual(result["chain_rounds"], 1)
        self.assertFalse([e for e in result["errors"] if e.get("phase") == "chain_rounds"])

    def test_control_without_the_hold_earlier_stages_starve_coverage(self):
        """Defect injection: the former budget had no hold; the reserve test sees it."""
        _, seen = self._investigate(
            reserve=30, extra_patches=(patch.object(RequestBudget, "hold", return_value=0),))
        self.assertEqual(seen["used_by_worklist"], 100)
        self.assertEqual(seen["remaining_at_drive"], 0)

    def test_control_a_hold_never_released_leaves_coverage_nothing(self):
        """Defect injection: a reserve that is not released before the drive is lost."""
        _, seen = self._investigate(
            reserve=30, extra_patches=(patch.object(RequestBudget, "release_hold",
                                                    return_value=0),))
        self.assertEqual(seen["used_by_worklist"], 70)
        self.assertEqual(seen["remaining_at_drive"], 0)


if __name__ == "__main__":
    unittest.main()
