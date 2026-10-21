"""Code review 02, batch RV-F (I10), finding R11: a leg that was blocked, skipped or
gave no verdict is untested coverage; only an executed negative satisfies it.

Drives the production coverage driver (``build_coverage_driven``, and
``investigate_engagement`` which calls it) with the reviewer's blocked-sqlmap shape; the
executed negative is the control, and one fault injection reinstates the old projection.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from harness import cache, store
from harness.models import Finding
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _config, _exchange

ORIGIN = "http://shop.invalid"


def _finding(cls: str) -> Finding:
    return Finding(vulnerability_class=cls, confidence=0.5, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived")


def _brief(report):
    """The coverage counts that matter, so a failure message stays short."""
    return {k: report.get(k) for k in ("tested", "not_detected", "blocked", "inconclusive",
                                       "skipped", "confirmed", "error", "legs_driven")}


# ------------------------------------------------------------------ R11
class CoverageBlockedLegTests(unittest.TestCase):
    """R11: only an executed negative satisfies tested coverage."""

    def _state(self):
        return SimpleNamespace(endpoints={"POST /search": SimpleNamespace(
            path="/search", method="POST", access={}, reachable_roles=[],
            object_scoped=False, findings=[], template=None)})

    def _drive(self, make_result, *, sqlmap=False):
        from harness.coverage_tracker import build_coverage_driven
        results = []

        async def run_leg(*args):
            result = await make_result()
            results.append(result)
            return result
        with patch.object(httpx.AsyncClient, "request",
                          AsyncMock(side_effect=AssertionError("unexpected network"))):
            report = asyncio.run(build_coverage_driven(
                self._state(), ["anonymous"], run_leg, driveable={"sqlmap"}, budget=1))
        return report, results

    def _sqlmap_blocked(self):
        # The reviewer's shape: the production validator refuses the POST (the gate
        # allows no mutating replay) and reports "blocked".
        from harness.validators.sqlmap import SqlmapValidator
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["shop.invalid"]
        cfg["validators"].update(active_enabled=True, allow_mutating_replay=False)
        Orchestrator(cfg)
        ex = _exchange(ORIGIN + "/search", {"Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "q=test"

        async def make():
            return await SqlmapValidator(allowed_hosts=["shop.invalid"]).validate(
                _finding("sqli"), ex)
        return make

    def test_coverage_does_not_count_blocked_sqlmap_as_tested(self):
        report, results = self._drive(self._sqlmap_blocked())
        self.assertEqual([r.status for r in results], ["blocked"])
        self.assertEqual(report["tested"], 0, _brief(report))
        self.assertEqual(report["not_detected"], 0, _brief(report))
        self.assertEqual(report["blocked"], 1, _brief(report))

    def test_executed_negative_coverage_control(self):
        from harness.validators.base import ValidationResult

        async def make():
            return ValidationResult("sqlmap", "not_confirmed", "sqli")
        report, results = self._drive(make)
        self.assertEqual([r.status for r in results], ["not_confirmed"])
        self.assertEqual(report["tested"], 1, _brief(report))
        self.assertEqual(report["not_detected"], 1, _brief(report))

    def test_a_confirmed_leg_still_counts(self):
        from harness.validators.base import ValidationResult

        async def make():
            return ValidationResult("sqlmap", "confirmed", "sqli", confirmed=True)
        report, _ = self._drive(make)
        self.assertEqual((report["tested"], report["confirmed"]), (1, 1), _brief(report))

    def test_unrun_leg_results_are_never_tested(self):
        from harness.validators.base import ValidationResult
        for status, key in (("inconclusive", "inconclusive"), ("skipped", None),
                            ("a-status-nobody-defined", "inconclusive")):
            with self.subTest(status=status):
                async def make(status=status):
                    return ValidationResult("sqlmap", status, "sqli")
                report, _ = self._drive(make)
                self.assertEqual(report["tested"], 0, _brief(report))
                self.assertEqual(report["not_detected"], 0, _brief(report))
                if key:
                    self.assertEqual(report[key], 1, _brief(report))

    def test_unrun_cells_are_not_marked_executed(self):
        from harness.coverage_tracker import CoverageTracker, endpoint_view
        from harness.validators.base import ValidationResult
        for status, executed in (("blocked", False), ("skipped", False), ("inconclusive", False),
                                 ("not_confirmed", True)):
            with self.subTest(status=status):
                tracker = CoverageTracker()
                tracker.build(endpoint_view(self._state()), ["anonymous"], {})

                async def run_leg(*args, status=status):
                    return ValidationResult("sqlmap", status, "sqli")
                asyncio.run(tracker.drive_coverage_legs(run_leg, driveable={"sqlmap"}, budget=1))
                cells = [c for c in tracker.matrix.cells().values() if c.validator == "sqlmap"]
                self.assertEqual([c.executed for c in cells], [executed])

    def test_fault_injection_projecting_blocked_as_negative_is_detected(self):
        """Fault injection: the old projection (anything unmapped is a negative)."""
        from harness import coverage_tracker
        from harness.coverage_model import CellStatus
        legacy = {"confirmed": CellStatus.CONFIRMED, "not_confirmed": CellStatus.NOT_DETECTED,
                  "skipped": CellStatus.SKIPPED, "error": CellStatus.ERROR}
        with patch.object(coverage_tracker, "_LEG_STATUS", legacy), \
                patch.object(coverage_tracker, "_LEG_STATUS_UNKNOWN", CellStatus.NOT_DETECTED):
            report, results = self._drive(self._sqlmap_blocked())
        self.assertEqual([r.status for r in results], ["blocked"])
        self.assertEqual(report["tested"], 1,
                         "reinstating the old projection no longer counts the blocked leg as "
                         "tested -- the guard test is vacuous: " + str(_brief(report)))


class CoverageBlockedEngagementTests(unittest.TestCase):
    """R11 through the production caller: investigate_engagement drives the legs."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="rvf_engagement_")
        cls._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH, cache._cache = cls._orig
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _run(self, leg_status):
        from harness import test_smoke_investigate as smoke
        from harness.validators.base import ValidationResult
        from harness.validators.jwt_forge_validator import JwtForgeValidator

        async def leg(self_, finding, exchange):
            return ValidationResult("jwt_forge", leg_status, finding.vulnerability_class)
        orch = Orchestrator(smoke._test_config())
        orch.engagement_coverage_drive = True
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        with patch("harness.engagement_builder.build_engagement",
                   side_effect=smoke._canned_engagement), \
                patch("httpx.AsyncClient.get", new_callable=AsyncMock,
                      side_effect=smoke._responder(False)), \
                patch.object(JwtForgeValidator, "validate", leg):
            result = asyncio.run(orch.investigate_engagement(
                smoke.BASE_URL, smoke.ROLES, max_nodes=0, step_budget=4, max_chain_rounds=0))
        return (result.get("coverage") or {}).get("by_check", {}).get("WSTG-CRYP-04", {})

    def test_blocked_jwt_leg_is_not_tested_coverage(self):
        cell = self._run("blocked")
        self.assertEqual(cell.get("blocked", 0), 1, cell)
        self.assertEqual(cell.get("not_detected", 0), 0, cell)

    def test_executed_negative_jwt_leg_control(self):
        cell = self._run("not_confirmed")
        self.assertEqual(cell.get("not_detected", 0), 1, cell)
        self.assertEqual(cell.get("blocked", 0), 0, cell)


if __name__ == "__main__":
    unittest.main()
