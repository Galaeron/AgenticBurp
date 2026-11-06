"""The r3 bounds (2026-11-04 yield analysis of the 10 h Juice Shop run).

- The shape-driven legs: a fixed 24 per sweep skipped 262 warranted nodes as
  budget_exhausted. A time-boxed run now leaves them to its deadline.
- Discovery: max_endpoints=150 cut 64 of 214 operations from the sorted list. An
  engagement now probes every discovered operation unless a cap is configured.
- Coverage: a validator's "safe" verdict (CORS) left its case inconclusive in the
  case driver, so 208 executed CORS cases kept their cells pending.

Each change has a control: the old bound still applies where it is asked for.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from harness import test_retry_rounds, test_role_crawl, worklist_investigator
from harness.coverage_model import CellStatus
from harness.coverage_tracker import build_coverage_cases_driven
from harness.role_crawl import RoleSession
from harness.test_attempt_facts import ITEMS, _cell, _Run, _state, _Target
from harness.test_stage_reservations import _build
from harness.test_worklist_investigator import BENIGN, ROLES, _nothing, _state_with


class ResolvePreconditionLegsTests(unittest.TestCase):
    def test_auto_leaves_a_time_boxed_run_to_its_deadline(self):
        resolve = worklist_investigator.resolve_precondition_legs
        self.assertIsNone(resolve(None, time_boxed=True))
        self.assertIsNone(resolve("auto", time_boxed=True))
        self.assertIsNone(resolve("unlimited", time_boxed=False))

    def test_control_without_a_deadline_or_with_a_number_the_count_bounds(self):
        resolve = worklist_investigator.resolve_precondition_legs
        self.assertEqual(resolve(None, time_boxed=False), 24)
        self.assertEqual(resolve("auto", time_boxed=False), 24)
        self.assertEqual(resolve(40, time_boxed=True), 40)
        self.assertEqual(resolve(0, time_boxed=True), 0)       # the legs turned off
        self.assertEqual(resolve(-3, time_boxed=True), 0)


class UnboundedLegsTests(unittest.IsolatedAsyncioTestCase):
    async def _sweep(self, max_legs):
        st = _state_with([BENIGN, dict(BENIGN, path="/api/status"), dict(BENIGN, path="/api/info")])
        legs, summary = [], {}

        async def precondition(node, exchange):
            legs.append(node["path"])
            return []

        async def probe(exchange, hypothesis, specialty, step_budget):
            return _nothing()

        await worklist_investigator.investigate_worklist(
            probe, st, "http://t", ROLES, precondition_fn=precondition,
            max_precondition_legs=max_legs, summary_out=summary)
        return legs, summary.get("skipped_by_reason") or {}

    async def test_no_count_bound_attempts_every_warranted_node(self):
        legs, skipped = await self._sweep(None)
        self.assertEqual(len(legs), 3)
        self.assertNotIn("budget_exhausted", skipped)

    async def test_control_a_count_bound_skips_the_rest_as_budget_exhausted(self):
        legs, skipped = await self._sweep(1)
        self.assertEqual(len(legs), 1)
        self.assertEqual(skipped.get("budget_exhausted"), 2)


def _only_new(cls):
    """Run only the tests a subclass adds, not the ones it inherits."""
    own = {name for name in vars(cls) if name.startswith("test_")}
    for name in dir(cls):
        if name.startswith("test_") and name not in own:
            setattr(cls, name, None)
    return cls


@_only_new
class _BoundsCaller(test_retry_rounds.RetryRoundsCallerTests):
    """investigate_engagement passes the resolved bounds to its phases."""

    def _run(self, engagement=None, **investigate):
        builds = []

        async def build(base_url, roles, **kwargs):
            builds.append(kwargs)
            return await _build(base_url, roles, **kwargs)

        with patch("harness.test_retry_rounds._build", new=build):
            result, sweeps, _ = self._investigate(engagement, **investigate)
        return builds, sweeps


@_only_new
class EngagementBoundsCallerTests(_BoundsCaller):
    def test_a_time_boxed_engagement_bounds_its_legs_by_the_deadline(self):
        _, sweeps = self._run({"investigation_seconds": 900})
        self.assertIsNone(sweeps[0]["max_precondition_legs"])

    def test_control_without_a_deadline_or_with_a_configured_count_the_count_holds(self):
        _, sweeps = self._run()
        self.assertEqual(sweeps[0]["max_precondition_legs"], 24)
        _, sweeps = self._run({"investigation_seconds": 900, "max_precondition_legs": 40})
        self.assertEqual(sweeps[0]["max_precondition_legs"], 40)

    def test_discovery_probes_every_operation_by_default(self):
        builds, _ = self._run()
        self.assertEqual(builds[0]["max_endpoints"], 0)

    def test_control_a_configured_or_requested_cap_is_passed_on(self):
        builds, _ = self._run({"discovery_max_endpoints": 150})
        self.assertEqual(builds[0]["max_endpoints"], 150)
        builds, _ = self._run({"discovery_max_endpoints": 150}, discovery_max_endpoints=7)
        self.assertEqual(builds[0]["max_endpoints"], 7)


@_only_new
class UncappedDiscoveryTests(test_role_crawl.RoleCrawlTests):
    """role_crawl with max_endpoints=0 probes every operation."""

    def test_zero_probes_every_operation(self):
        roles = [RoleSession("user", {"Authorization": "Bearer u"})]
        endpoints = [f"/api/e{i}" for i in range(20)]
        matrix = {f"/api/e{i}": (lambda auth: (200, "d")) for i in range(20)}
        r = self._run(endpoints, matrix, roles, max_endpoints=0)
        self.assertEqual(len(r.endpoints), 20)
        self.assertFalse(any("truncated" in e for e in r.errors))


class DiscoveryCapRequestTests(unittest.TestCase):
    """The investigate route forwards a requested discovery cap, clamped."""

    def setUp(self):
        from harness.test_i16_wiring import InvestigateRouteForwardsDeclarationsTests
        self.fx = InvestigateRouteForwardsDeclarationsTests("test_declared_lists_are_forwarded")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def _forwarded(self, **extra):
        self.fx.calls.clear()
        return self.fx._run(**extra)

    def test_a_requested_cap_is_forwarded_and_clamped(self):
        for requested, forwarded in ((150, 150), (0, 0), (-5, 0), (10**9, 100000)):
            with self.subTest(requested=requested):
                kwargs = self._forwarded(discovery_max_endpoints=requested)
                self.assertEqual(kwargs["discovery_max_endpoints"], forwarded)

    def test_control_no_requested_cap_leaves_the_engagement_config(self):
        self.assertNotIn("discovery_max_endpoints", self._forwarded())


class SafeVerdictCaseTests(unittest.TestCase):
    """The case driver maps a validator's "safe" to its executed negative."""

    def setUp(self):
        self.target = _Target()
        self.addCleanup(self.target.close)

    def _cases(self, status):
        run = _Run(self.target, status=status, bind_cases=True)
        report = run.drive(build_coverage_cases_driven, _state(self.target.base, "/items/1?q=1"))
        matrix, _parent = _cell(report)
        return {ck.parameter_name: r for ck, r in matrix.cases_for_cell("anonymous", ITEMS, "WSTG-INPV-05")}

    def test_safe_is_a_tested_negative(self):
        cases = self._cases("safe")
        self.assertGreater(self.target.requests, 0)
        for name in ("q", ""):
            self.assertEqual(cases[name].status, CellStatus.NOT_DETECTED, name)
            self.assertTrue(cases[name].executed, name)

    def test_control_an_unknown_status_stays_inconclusive(self):
        cases = self._cases("no_such_status")
        for name in ("q", ""):
            self.assertEqual(cases[name].status, CellStatus.INCONCLUSIVE, name)


if __name__ == "__main__":
    unittest.main()
