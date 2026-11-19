"""Unused phase time goes to the work the budgets set aside (R11-4).

The pieces (harness/final_pass.py, PhaseSchedule.rollover, the phase recorder's
budget fields, the coverage tracker's drive_remaining) are driven with a fake clock;
investigate_engagement is driven with its phases stubbed, as in test_retry_rounds,
and with orchestrator_chain's clock replaced by a fake one. Every behaviour has a
negative control: the feature off, no deadline, or no time left before the deadline.
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

from harness import (cache, run_handoff, config_schema, coverage_tracker, engagement_builder,
                     evidence_ledger, instrumentation, retry_rounds, safety_gate,
                     sqlmap_targeting, store, worklist_investigator)
from harness.final_pass import STEPS, FinalPassConfig, run_final_pass
from harness.orchestrator import Orchestrator
from harness.orchestrator_chain import ChainMixin
from harness.phase_schedule import PhaseSchedule
from harness.role_crawl import RoleSession
from harness.run_context import RunContext
from harness.run_manifest import RunManifest
from harness.test_deterministic_first import BASE, _config
from harness.test_stage_reservations import _build


class _Clock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now


def _outcome(stop, *, path="/n", findings=0):
    return {"path": path, "specialty": "idor", "stop_reason": stop, "confirmed": False,
            "findings_detail": [{"vulnerability_class": "idor", "confirmed": False}
                                for _ in range(findings)]}


# ------------------------------------------------------------------ config
class ConfigTests(unittest.TestCase):
    def test_shipped_config_keeps_the_pass_and_the_rollover_off(self):
        cfg = _config()
        self.assertFalse(FinalPassConfig.from_config(cfg).enabled)
        self.assertFalse((cfg.get("engagement") or {}).get("coverage_drive_rollover", False))
        self.assertIn("engagement.final_pass.enabled", config_schema._PASSIVE_FORCE_OFF_KNOBS)

    def test_bad_values_fall_back_to_the_defaults(self):
        self.assertEqual(FinalPassConfig.from_config({"engagement": {"final_pass": "yes"}}),
                         FinalPassConfig())
        cfg = FinalPassConfig.from_config(
            {"engagement": {"final_pass": {"enabled": True, "reserve_seconds": "x"}}})
        self.assertEqual((cfg.enabled, cfg.reserve_seconds), (True, 60.0))
        cfg = FinalPassConfig.from_config(
            {"engagement": {"final_pass": {"enabled": True, "reserve_seconds": -5}}})
        self.assertEqual(cfg.reserve_seconds, 0.0)


# ------------------------------------------------------------------ run_final_pass
class RunFinalPassTests(unittest.TestCase):
    def _run(self, *, deadline, clock, steps=None, cancelled=lambda: False, reserve=60.0):
        calls = []

        def step(name, spend=0.0, result=None, raises=False):
            async def fn(stop_at):
                calls.append((name, stop_at))
                clock.now += spend
                if raises:
                    raise RuntimeError("boom")
                return result
            return fn

        steps = steps if steps is not None else {
            name: step(name, result={"ran": name}) for name in STEPS}
        if callable(steps):
            steps = steps(step)
        report = asyncio.run(run_final_pass(
            FinalPassConfig(enabled=True, reserve_seconds=reserve), deadline=deadline,
            steps=steps, cancelled=cancelled, clock=clock))
        return report, calls

    def test_steps_run_in_priority_order_each_given_the_deadline_less_the_reserve(self):
        clock = _Clock(100.0)
        report, calls = self._run(deadline=1000.0, clock=clock)
        self.assertEqual(calls, [(name, 940.0) for name in STEPS])
        self.assertEqual(report["stopped_by"], "done")
        self.assertEqual(report["skipped"], [])
        self.assertEqual([s["step"] for s in report["steps"]], list(STEPS))
        self.assertEqual(report["stop_at_s"], 840.0)

    def test_a_failing_step_is_recorded_and_the_next_one_runs(self):
        clock = _Clock(0.0)
        report, calls = self._run(deadline=1000.0, clock=clock, steps=lambda step: {
            "worklist_nodes": step("worklist_nodes", raises=True),
            "drive_legs": step("drive_legs", result={"ok": 1})})
        self.assertEqual([c[0] for c in calls], ["worklist_nodes", "drive_legs"])
        self.assertEqual(report["steps"][0]["error"], "RuntimeError: boom")
        self.assertEqual(report["steps"][1]["result"], {"ok": 1})

    def test_control_no_step_starts_after_the_deadline_less_the_reserve(self):
        clock = _Clock(941.0)
        report, calls = self._run(deadline=1000.0, clock=clock)
        self.assertEqual(calls, [])
        self.assertEqual(report["stopped_by"], "deadline")
        self.assertEqual(report["skipped"], list(STEPS))

    def test_control_a_step_that_runs_to_the_deadline_stops_the_ones_after_it(self):
        clock = _Clock(0.0)
        report, calls = self._run(deadline=1000.0, clock=clock, steps=lambda step: {
            name: step(name, spend=(950.0 if name == "worklist_nodes" else 0.0)) for name in STEPS})
        self.assertEqual([c[0] for c in calls], ["worklist_nodes"])
        self.assertEqual(report["stopped_by"], "deadline")
        self.assertEqual(report["skipped"], ["drive_legs", "held_replays"])

    def test_control_cancellation_and_no_deadline_start_nothing(self):
        report, calls = self._run(deadline=1000.0, clock=_Clock(0.0), cancelled=lambda: True)
        self.assertEqual((calls, report["stopped_by"]), ([], "cancelled"))
        report, calls = self._run(deadline=None, clock=_Clock(0.0))
        self.assertEqual((calls, report["stopped_by"]), ([], "no_deadline"))


# ------------------------------------------------------------------ PhaseSchedule
class RolloverTests(unittest.TestCase):
    def test_phase_a_ending_at_half_its_slice_gives_phase_b_the_rest(self):
        clock = _Clock(0.0)
        sched = PhaseSchedule(100.0, {"worklist": 1, "recrawl": 1}, clock=clock)
        self.assertEqual(sched.deadline_for("worklist"), 50.0)
        clock.now = 25.0                        # A used half of its 50 s
        self.assertEqual(sched.deadline_for("recrawl"), 100.0)
        self.assertEqual(sched.granted, {"worklist": 50.0, "recrawl": 75.0})

    def test_rollover_is_what_the_last_sliced_phase_left(self):
        clock = _Clock(0.0)
        sched = PhaseSchedule(100.0, {"chain_rounds": 1, "final_passes": 1}, clock=clock)
        self.assertEqual(sched.rollover(), 0.0)             # nothing granted yet
        sched.deadline_for("chain_rounds")                  # granted up to 50
        clock.now = 10.0
        self.assertEqual(sched.rollover(), 40.0)
        clock.now = 60.0
        self.assertEqual(sched.rollover(), 0.0)             # it ran past its slice

    def test_control_inactive_schedule_has_no_rollover(self):
        clock = _Clock(0.0)
        self.assertEqual(PhaseSchedule(None, {"chain_rounds": 1}, clock=clock).rollover(), 0.0)
        sched = PhaseSchedule(100.0, {}, clock=clock)
        sched.deadline_for("chain_rounds", 80.0)
        self.assertEqual(sched.rollover(), 0.0)


# ------------------------------------------------------------------ PhaseRecorder
class PhaseRecordTests(unittest.TestCase):
    def test_records_carry_end_budget_and_unused_time(self):
        clock = _Clock(0.0)
        rec = instrumentation.PhaseRecorder(announce=False, clock=clock)
        rec.begin("worklist")
        rec.set_budget("worklist", 100.0)
        clock.now = 40.0
        rec.begin("recrawl", budget_s=10.0)
        rec.set_budget("worklist", 5.0)       # not the open phase: ignored
        clock.now = 55.0
        rec.begin("finalise")
        clock.now = 56.0
        rec.finish()
        wl, rc, fin = rec.timings()
        self.assertEqual((wl["started_s"], wl["ended_s"], wl["budget_s"], wl["unused_s"]),
                         (0.0, 40.0, 100.0, 60.0))
        self.assertEqual((rc["elapsed_s"], rc["budget_s"], rc["unused_s"]), (15.0, 10.0, 0.0))
        self.assertEqual((fin["budget_s"], fin["unused_s"], fin["ended_s"]), (None, None, 56.0))

    def test_control_without_a_budget_the_fields_are_none(self):
        rec = instrumentation.PhaseRecorder(announce=False, clock=_Clock(0.0))
        with rec.phase("x"):
            pass
        rec.set_budget("x", 10.0)             # nothing open
        (record,) = rec.timings()
        self.assertIsNone(record["budget_s"])
        self.assertIsNone(record["unused_s"])


    def test_a_skipped_phase_records_why_and_an_aborted_one_is_interrupted(self):
        # R11-4b: skip() for experiments_final past its deadline; abort() for the
        # phase a cancel cut (the server's cancelled-job result).
        clock = _Clock(0.0)
        events = []
        rec = instrumentation.PhaseRecorder(announce=False, clock=clock,
                                            on_event=lambda *a: events.append(a))
        rec.begin("final_pass", budget_s=50.0)
        clock.now = 20.0
        rec.skip("experiments_final", "deadline passed")
        rec.begin("finalise")
        clock.now = 25.0
        rec.abort()
        rec.abort()                                       # nothing open: no-op
        fp, ef, fin = rec.timings()
        self.assertEqual((fp["elapsed_s"], fp["unused_s"]), (20.0, 30.0))
        self.assertNotIn("interrupted", fp)
        self.assertEqual((ef["skipped"], ef["elapsed_s"], ef["started_s"]), ("deadline passed", 0.0, 20.0))
        self.assertTrue(fin["interrupted"])
        self.assertEqual(fin["elapsed_s"], 5.0)
        self.assertEqual(events, [("begin", "final_pass"), ("end", "final_pass"),
                                  ("skip", "experiments_final", "deadline passed"),
                                  ("begin", "finalise"), ("abort", "finalise")])

    def test_control_a_handoff_without_a_skip_lists_no_skipped_phase(self):
        handoff = run_handoff.RunHandoff("r11-4b", host="shop.test")
        handoff.phase_event("begin", "worklist")
        handoff.phase_event("skip", "experiments_final", "deadline passed")
        phases = handoff.snapshot()["phases"]
        self.assertEqual(phases["skipped"], [{"phase": "experiments_final", "reason": "deadline passed"}])
        self.assertEqual([p["phase"] for p in phases["not_run"]], ["finalise"])
        self.assertNotIn("experiments_final", phases["not_applicable"])
        plain = run_handoff.RunHandoff("r11-4b-off", host="shop.test")
        plain.phase_event("begin", "worklist")
        phases = plain.snapshot()["phases"]
        self.assertEqual(phases["skipped"], [])
        self.assertIn({"phase": "experiments_final", "conditional": True}, phases["not_run"])


class ManifestTests(unittest.TestCase):
    def test_manifest_keeps_phase_timings_and_the_sqlmap_report_beside_them(self):
        report = {"endpoint_family_seconds": 600.0, "seconds_by_family": {},
                  "held": [], "transport_endpoints": [{"endpoint": "https://shop.test/socket.io/",
                                                       "framing": "engine.io", "targets_skipped": 2}]}
        timings = [{"phase": "worklist", "elapsed_s": 1.0, "budget_s": 5.0, "unused_s": 4.0}]
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent.parent / ".test-work") as td:
            run = RunManifest.start(run_id="r11-4", target_identifier="fixture", config={},
                                    output_dir=td)
            self.assertIsNone(run.data["sqlmap_targeting"])
            run.finish("completed", result={"instrumentation": {
                "phase_timings": timings, "sqlmap_targeting": report}})
        self.assertEqual(run.data["phase_timings"], timings)
        self.assertEqual(run.data["sqlmap_targeting"]["transport_endpoints"][0]["targets_skipped"], 2)


# ------------------------------------------------------------------ coverage tracker
class DriveRemainingTests(unittest.TestCase):
    class _Res:
        status = "not_confirmed"; summary = ""; confidence = None; evidence = ""; validator = "v"
        confirmed = False

    def _tracker(self):
        from harness.coverage_tracker import CoverageTracker, endpoint_view
        from harness.test_coverage_tracker import _state_with
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),
            ("POST", "/api/search", {"reachable_roles": ["user"]}),
        ])
        t = CoverageTracker()
        t.build(endpoint_view(st), ["user"])
        return t

    def test_the_cells_the_drive_left_are_driven_and_its_own_stop_reason_kept(self):
        from harness.coverage_model import CellStatus
        t = self._tracker()
        sent = []

        async def run_leg(identity, method, path, check):
            sent.append((identity, f"{method} {path}", check.id))
            return self._Res()

        asyncio.run(t.drive_coverage_legs(run_leg, budget=1))
        left = t.queued - t.attempted
        self.assertTrue(left)
        first_stop = t.stopped_by
        t.finalize_pending_reasons(investigated_keys=set())
        self.assertTrue(all(t.matrix.cells()[k].status == CellStatus.SKIPPED for k in left
                            if not t.matrix.has_cases(*k)))
        before = list(sent)
        out = asyncio.run(t.drive_remaining(run_leg, case_mode=False, budget=100, deadline=None))
        self.assertEqual(out["queued_not_attempted"], 0)
        self.assertGreater(out["dispatches"], 0)
        self.assertGreater(out["reopened"], 0)
        self.assertEqual(t.stopped_by, first_stop)
        # Nothing the first drive sent is sent again.
        self.assertFalse(set(before) & set(sent[len(before):]))
        report = coverage_tracker.report_after_final_pass(t, {"legs_driven": 1},
                                                          final_pass={"drive_legs": out})
        self.assertEqual(report["queued_not_attempted"], 0)
        self.assertEqual(report["final_pass"]["drive_legs"], out)

    def test_control_a_past_deadline_drives_nothing_more(self):
        t = self._tracker()

        async def run_leg(identity, method, path, check):
            return self._Res()

        asyncio.run(t.drive_coverage_legs(run_leg, budget=1))
        left = len(t.queued - t.attempted)
        out = asyncio.run(t.drive_remaining(run_leg, case_mode=False, budget=100, deadline=0.0))
        self.assertEqual(out["dispatches"], 0)
        self.assertEqual(out["queued_not_attempted"], left)


# ------------------------------------------------------------------ investigate_engagement
class FinalPassCallerTests(unittest.TestCase):
    """investigate_engagement hands the time left to the final pass, on a fake clock."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="final_pass_", dir=Path(__file__).parent.parent
                                     / ".test-work")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()

    def tearDown(self):
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _investigate(self, engagement=None, *, first_sweep_seconds=10.0, start=1000.0,
                     later_sweep_seconds=0.0, experiments_final=None, handoff=False):
        cfg = _config()
        cfg["engagement"].update(engagement or {})
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["shop.test"]
        rc = RunContext.create(allowed_hosts=["shop.test"], max_requests=100, config=cfg)
        self.rc = rc
        if handoff:
            run_handoff.attach(rc, host="shop.test", base_url=BASE, output_dir=self._tmp)
        clock = _Clock(start)
        sweeps = []

        async def worklist(probe, st, base, roles, **kwargs):
            sweeps.append(dict(kwargs, now=clock.now))
            on_outcome = kwargs.get("on_outcome")
            if len(sweeps) == 1:
                # The first sweep: /a ran, one node was over its budget, and sqlmap
                # skipped a transport endpoint (recorded on the run's targeting).
                clock.now += first_sweep_seconds
                out = _outcome("found", path="/a")
                if on_outcome is not None:
                    on_outcome("GET|/a", out)
                targeting = sqlmap_targeting.targeting_for(rc)
                targeting.finish(targeting.start("GET", "https://shop.test/rest/search?q=1"))
                kwargs["summary_out"].update({"skipped_by_reason": {"budget_exhausted": 1}})
                return [out]
            clock.now += later_sweep_seconds
            completed = kwargs.get("completed") or {}
            outs = [dict(completed[k], resumed=True) for k in completed]
            out = _outcome("found", path="/b", findings=1)
            if on_outcome is not None:
                on_outcome("GET|/b", out)
            return outs + [out]

        patches = [patch.object(engagement_builder, "build_engagement", new=_build),
                   patch.object(worklist_investigator, "investigate_worklist", new=worklist),
                   patch.object(coverage_tracker, "build_coverage_driven",
                                new=AsyncMock(return_value={})),
                   patch("harness.orchestrator_chain.review_captured_exchanges",
                         new=AsyncMock(return_value=0)),
                   patch("harness.orchestrator_chain.universal_header_audit",
                         new=AsyncMock(return_value=0)),
                   patch("harness.orchestrator_chain.time", new=SimpleNamespace(monotonic=clock, time=time.time)),
                   patch("harness.browser_driver.default_driver", return_value=None),
                   patch.object(retry_rounds, "_breaker_retry_after", return_value=0.0)]
        if experiments_final is not None:
            async def spy(_self, *args, deadline=None, **kwargs):
                experiments_final.append({"deadline": deadline, "now": clock.now})
                return {"runs": 0, "stopped_by": "no ready experiment"}
            patches.append(patch.object(ChainMixin, "_final_experiment_pass", spy))

        async def go():
            try:
                async with rc:
                    return await orch.investigate_engagement(
                        BASE, [RoleSession("anonymous", {})], max_nodes=1, step_budget=16,
                        max_chain_rounds=0, discovery_max_probes=1, run_context=rc)
            finally:
                await rc.aclose()

        for p in patches:
            p.start()
        try:
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        return result, sweeps, start

    @staticmethod
    def _timing(result, phase):
        return next(r for r in result["instrumentation"]["phase_timings"] if r["phase"] == phase)

    def test_budget_skipped_nodes_run_before_the_job_ends_when_time_remains(self):
        result, sweeps, start = self._investigate({
            "investigation_seconds": 900, "final_pass": {"enabled": True, "reserve_seconds": 60}})
        self.assertEqual(len(sweeps), 2)
        first, final = sweeps
        self.assertEqual(final["deadline"], start + 900 - 60)
        self.assertIn("GET|/a", final["completed"])            # settled: resumed, not resent
        self.assertIs(final["legs_done"], first["legs_done"])  # attempted legs not resent
        report = result["crawl_loop"]["final_pass"]
        self.assertEqual(report["stopped_by"], "done")
        wl = next(s for s in report["steps"] if s["step"] == "worklist_nodes")
        self.assertEqual((wl["result"]["skipped_before"], wl["result"]["ran"]), (1, 1))
        fresh = [o for o in result["outcomes"] if o.get("final_pass")]
        self.assertEqual([o["path"] for o in fresh], ["/b"])
        self.assertEqual(self._timing(result, "final_pass")["budget_s"], 900 - 10 - 60)

    def test_phase_timings_carry_budgets_and_the_sqlmap_report_is_in_the_summary(self):
        result, _, _ = self._investigate({"investigation_seconds": 900})
        instr = result["instrumentation"]
        phases = [r["phase"] for r in instr["phase_timings"]]
        self.assertIn("worklist", phases)
        self.assertIn("finalise", phases)
        for record in instr["phase_timings"]:
            self.assertIn("ended_s", record)
            self.assertIn("budget_s", record)
        self.assertEqual(self._timing(result, "worklist")["budget_s"], 900.0)
        self.assertEqual(list(instr["sqlmap_targeting"]["seconds_by_family"]),
                         [sqlmap_targeting.endpoint_family("GET", "https://shop.test/rest/search?q=1")])

    def test_the_engagement_leaves_its_instrumentation_on_the_run(self):
        # R11-4b: the server's cancelled-job result reads it from there.
        result, _, _ = self._investigate({"investigation_seconds": 900})
        instr = self.rc.instrumentation
        self.assertIsInstance(instr, instrumentation.RunInstrumentation)
        self.assertEqual([r["phase"] for r in instr.phases.timings()],
                         [r["phase"] for r in result["instrumentation"]["phase_timings"]])

    def test_a_phase_ending_at_half_its_slice_gives_the_next_one_the_rest(self):
        result, _, _ = self._investigate({
            "investigation_seconds": 1000, "phase_slices": {"worklist": 1, "chain_rounds": 1}},
            first_sweep_seconds=250.0)
        self.assertEqual(self._timing(result, "worklist")["budget_s"], 500.0)
        self.assertEqual(self._timing(result, "chain_rounds")["budget_s"], 750.0)
        self.assertEqual(result["crawl_loop"]["phase_schedule"]["granted_seconds"],
                         {"worklist": 500.0, "chain_rounds": 750.0})

    def test_the_drive_takes_over_the_slack_of_the_last_sliced_phase(self):
        on = {"investigation_seconds": 1000, "coverage_drive_seconds": 100,
              "phase_slices": {"chain_rounds": 1, "final_passes": 1}}
        result, _, _ = self._investigate(dict(on, coverage_drive_rollover=True))
        # The chain rounds were granted half of the 990 s left and used none of it.
        self.assertEqual(result["stage_budgets"]["coverage_drive_rollover_seconds"], 495.0)
        self.assertEqual(self._timing(result, "coverage_drive")["budget_s"], 595.0)
        # Control: without the rollover the drive keeps its own seconds.
        result, _, _ = self._investigate(on)
        self.assertEqual(result["stage_budgets"]["coverage_drive_rollover_seconds"], 0.0)
        self.assertEqual(self._timing(result, "coverage_drive")["budget_s"], 100.0)

    def test_control_no_extra_pass_starts_after_the_deadline_less_the_reserve(self):
        result, sweeps, _ = self._investigate({
            "investigation_seconds": 900, "final_pass": {"enabled": True, "reserve_seconds": 60}},
            first_sweep_seconds=850.0)
        self.assertEqual(len(sweeps), 1)
        report = result["crawl_loop"]["final_pass"]
        self.assertEqual(report["stopped_by"], "deadline")
        self.assertEqual(report["steps"], [])
        self.assertEqual(report["skipped"], list(STEPS))
        self.assertFalse(any(o.get("final_pass") for o in result["outcomes"]))

    def test_control_with_no_time_left_or_the_pass_off_the_run_is_as_today(self):
        off, off_sweeps, _ = self._investigate({"investigation_seconds": 900})
        late, late_sweeps, _ = self._investigate({
            "investigation_seconds": 900, "final_pass": {"enabled": True}},
            first_sweep_seconds=850.0)
        self.assertEqual(off["crawl_loop"]["final_pass"], {"enabled": False})
        self.assertEqual(len(off_sweeps), len(late_sweeps))
        self.assertEqual([o["path"] for o in off["outcomes"]], [o["path"] for o in late["outcomes"]])
        self.assertNotIn("legs_done", off_sweeps[0])           # the ledger is not wired when off

    def test_control_without_sqlmap_the_report_is_none(self):
        with patch.object(sqlmap_targeting, "run_report", return_value=None):
            result, _, _ = self._investigate({"investigation_seconds": 900})
        self.assertIn("sqlmap_targeting", result["instrumentation"])
        self.assertIsNone(result["instrumentation"]["sqlmap_targeting"])

    # ---------------------------------------------------------- experiments_final
    # R11-4b: the final experiment pass is bounded by the coverage deadline AND the
    # investigation deadline less the finalise reserve; past that bound the phase
    # is recorded as skipped, with why (phase_timings and the handoff).
    def test_experiments_final_is_bounded_by_the_deadline_less_the_finalise_reserve(self):
        # No coverage_drive_seconds: before R11-4b it got no deadline at all.
        seen = []
        result, _, start = self._investigate({"investigation_seconds": 900},
                                             experiments_final=seen)
        self.assertEqual(seen, [{"deadline": start + 900 - 60, "now": start + 10}])
        record = self._timing(result, "experiments_final")
        self.assertEqual(record["budget_s"], 900 - 10 - 60)
        self.assertNotIn("skipped", record)

    def test_experiments_final_never_runs_past_the_run_deadline_on_a_long_drive_deadline(self):
        # The coverage deadline (2010 s) lies past the investigation deadline (900 s).
        seen = []
        result, _, start = self._investigate(
            {"investigation_seconds": 900, "coverage_drive_seconds": 2000}, experiments_final=seen)
        self.assertEqual(seen[0]["deadline"], start + 900 - 60)
        self.assertEqual(self._timing(result, "experiments_final")["budget_s"], 830.0)

    def test_control_experiments_final_runs_within_the_drive_deadline_when_time_remains(self):
        seen = []
        result, _, start = self._investigate(
            {"investigation_seconds": 900, "coverage_drive_seconds": 100}, experiments_final=seen)
        self.assertEqual(seen, [{"deadline": start + 10 + 100, "now": start + 10}])
        record = self._timing(result, "experiments_final")
        self.assertEqual((record["budget_s"], record.get("skipped")), (100.0, None))

    def test_experiments_final_is_skipped_once_only_the_finalise_reserve_is_left(self):
        seen = []
        result, _, start = self._investigate({"investigation_seconds": 900},
                                             first_sweep_seconds=870.0, experiments_final=seen,
                                             handoff=True)
        record = self._timing(result, "experiments_final")
        self.assertIn("investigation deadline less the finalise reserve (60 s)", record["skipped"])
        self.assertEqual((record["elapsed_s"], record["budget_s"]), (0.0, None))
        # The pass is told the bound that passed, so it sends nothing and defers.
        self.assertEqual(seen, [{"deadline": start + 840, "now": start + 870}])
        self.assertEqual(result["experiment_final_pass"]["skipped"], record["skipped"])
        phases = self.rc.handoff.snapshot()["phases"]
        self.assertEqual(phases["skipped"], [{"phase": "experiments_final",
                                              "reason": record["skipped"]}])
        self.assertNotIn("experiments_final", phases["begun"])
        self.assertNotIn("experiments_final", phases["not_applicable"])
        self.assertIn("finalise", phases["begun"])

    def test_experiments_final_is_skipped_once_the_final_pass_ran_past_the_drive_deadline(self):
        seen = []
        result, _, start = self._investigate(
            {"investigation_seconds": 900, "coverage_drive_seconds": 100,
             "final_pass": {"enabled": True, "reserve_seconds": 60}},
            later_sweep_seconds=200.0, experiments_final=seen)
        self.assertEqual(seen, [{"deadline": start + 110, "now": start + 210}])
        self.assertEqual(self._timing(result, "experiments_final")["skipped"],
                         "the coverage stage's deadline has passed")

    def test_control_on_without_a_deadline_runs_no_pass(self):
        result, sweeps, _ = self._investigate({"final_pass": {"enabled": True}})
        self.assertEqual(len(sweeps), 1)
        self.assertEqual(result["crawl_loop"]["final_pass"]["stopped_by"], "no_deadline")


if __name__ == "__main__":
    unittest.main()
