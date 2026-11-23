"""The final pass's drive_legs and held_replays steps, end to end (R11-4b).

test_final_pass drives those two steps on the coverage tracker directly, and its
caller tests stub the coverage drive, so neither step ran through
investigate_engagement. Here the coverage drive is the real one (as in
test_coverage_replay_dedupe's DriveCallerTests: worklist stubbed out, two legs
recorded instead of judged), and orchestrator_chain's and coverage_tracker's
clocks are one fake clock that a recorded leg moves forward.

- drive_legs: the drive stops at its coverage_drive_seconds with legs queued and
  never attempted; the final pass sends those legs before the job ends.
- held_replays: the per-endpoint check share holds a capture's replay; the final
  pass sends that replay, once, and the cell's held list empties.
Negative controls for both: the pass off; the investigation deadline gone; only
the finalise reserve left (deadline minus reserve passed).
"""
from __future__ import annotations

import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from harness import final_pass as final_pass_mod
from harness.test_coverage_replay_dedupe import _seeded
from harness.test_engagement_transport_callers import _ROLES, _EngagementCallerBase, _config
from harness.validators.base import ValidationResult
from harness.chain_stage_patch import chain_patch

ALICE = "Bearer alice-token"
START = 1000.0


class _Clock:
    def __init__(self, now=START):
        self.now = now

    def __call__(self):
        return self.now


class FinalPassDriveCallerTests(_EngagementCallerBase, unittest.TestCase):

    def _investigate(self, captures, *, engagement_cfg, leg_seconds, worklist_seconds=0.0):
        target = self._target()
        clock = _Clock()
        calls: list[dict] = []
        phase = {"name": "before"}
        real_final = final_pass_mod.run_final_pass

        async def final(*args, **kwargs):
            phase["name"] = "final_pass"
            try:
                return await real_final(*args, **kwargs)
            finally:
                phase["name"] = "after"

        def recorder(name):
            async def validate(self, finding, exchange, *args, **kwargs):
                calls.append({"leg": name, "url": exchange.url, "now": clock.now,
                              "auth": exchange.request_headers.get("Authorization", ""),
                              "phase": phase["name"]})
                clock.now += leg_seconds
                return ValidationResult(name, "not_confirmed", "idor", summary="recorded")
            return validate

        def drive_config(*, mutating):
            cfg = _config(mutating=mutating)
            cfg["engagement"]["coverage_drive_legs"] = True
            cfg["engagement"].update(engagement_cfg)
            return cfg

        async def worklist(*args, **kwargs):
            clock.now += worklist_seconds     # the time the earlier phases used
            return []

        fake_time = SimpleNamespace(monotonic=clock, time=time.time)
        patches = [patch("harness.engagement_builder.build_engagement", side_effect=_seeded(captures)),
                   patch("harness.worklist_investigator.investigate_worklist", worklist),
                   patch("harness.final_pass.run_final_pass", final),
                   chain_patch("time", fake_time),
                   patch("harness.coverage_tracker.time", fake_time),
                   patch("harness.validators.cross_identity_validator.CrossIdentityValidator.validate",
                         new=recorder("cross_identity")),
                   patch("harness.validators.command_injection_validator.CommandInjectionValidator.validate",
                         new=recorder("command_injection"))]
        with patch("harness.test_engagement_transport_callers._config", drive_config):
            result, _rc, _model = self._run(target, max_requests=800, roles=list(_ROLES),
                                            extra_patches=patches)
        return result, calls

    @staticmethod
    def _step(result, name):
        return next((s for s in result["crawl_loop"]["final_pass"].get("steps") or []
                     if s["step"] == name), None)

    # ---------------------------------------------------------------- drive_legs
    _DRIVE = [(f"/api/items/{i}?q=lamp", {}) for i in (7, 8, 9)] + [
        (f"/api/list{i}?q=lamp", {}) for i in range(4)]

    def _drive(self, final_pass, *, worklist_seconds=0.0):
        cfg = {"investigation_seconds": 3600, "coverage_drive_seconds": 100,
               "coverage_endpoint_check_share": 0}
        if final_pass is not None:
            cfg["final_pass"] = final_pass
        return self._investigate(self._DRIVE, engagement_cfg=cfg, leg_seconds=30.0,
                                 worklist_seconds=worklist_seconds)

    def test_a_queued_drive_leg_the_drive_never_attempted_is_sent_by_the_final_pass(self):
        result, calls = self._drive({"enabled": True, "reserve_seconds": 60})
        first = [c for c in calls if c["phase"] == "before"]
        final = [c for c in calls if c["phase"] == "final_pass"]
        self.assertTrue(first)
        self.assertTrue(final, calls)
        # The drive stopped at its own deadline; the pass went on from there, before
        # the investigation deadline less the reserve.
        self.assertGreaterEqual(final[0]["now"], START + 100)
        self.assertTrue(all(c["now"] < START + 3600 - 60 for c in final))
        # Nothing the drive sent is sent again.
        sent = {(c["leg"], c["url"], c["auth"]) for c in first}
        self.assertFalse(sent & {(c["leg"], c["url"], c["auth"]) for c in final})
        step = self._step(result, "drive_legs")
        self.assertGreater(step["result"]["dispatches"], 0)
        self.assertGreater(step["result"]["cells_attempted"], 0)
        self.assertEqual(result["coverage"]["final_pass"]["drive_legs"], step["result"])

    def test_control_drive_legs_with_the_pass_off_stay_queued(self):
        on, on_calls = self._drive({"enabled": True, "reserve_seconds": 60})
        off, off_calls = self._drive(None)
        self.assertEqual(off["crawl_loop"]["final_pass"], {"enabled": False})
        self.assertFalse([c for c in off_calls if c["phase"] != "before"])
        self.assertEqual(len(off_calls), len([c for c in on_calls if c["phase"] == "before"]))
        self.assertGreater(off["coverage"]["queued_not_attempted"],
                           on["coverage"]["queued_not_attempted"])

    def test_control_no_drive_leg_is_sent_with_no_time_or_only_the_reserve_left(self):
        # The earlier phases used the run (3700 s > 3600 s) or all but the reserve
        # (3570 s: 30 s left of a 60 s reserve); the drive still has its own 100 s.
        for used in (3700.0, 3570.0):
            with self.subTest(used=used):
                result, calls = self._drive({"enabled": True, "reserve_seconds": 60},
                                            worklist_seconds=used)
                report = result["crawl_loop"]["final_pass"]
                self.assertEqual(report["stopped_by"], "deadline")
                self.assertIn("drive_legs", report["skipped"])
                self.assertFalse([c for c in calls if c["phase"] == "final_pass"])

    # ---------------------------------------------------------------- held_replays
    # A 120 s drive with a 0.0025 share: 0.3 s per (endpoint, check). Each replay
    # takes 0.4 s, so each check of /api/items/{id} runs one capture and holds the
    # rest. Across the checks, alice's cross_identity leg sends 7 and 8 in the drive
    # (a verdict one check got is reused by the next) and 9 is held by all of them.
    _HELD = [(f"/api/items/{i}", {}) for i in (7, 8, 9)]

    def _held(self, final_pass, *, worklist_seconds=0.0):
        cfg = {"investigation_seconds": 3600, "coverage_drive_seconds": 120,
               "coverage_endpoint_check_share": 0.0025}
        if final_pass is not None:
            cfg["final_pass"] = final_pass
        return self._investigate(self._HELD, engagement_cfg=cfg, leg_seconds=0.4,
                                 worklist_seconds=worklist_seconds)

    @staticmethod
    def _alice_items(calls, phase):
        return [c["url"] for c in calls if c["phase"] == phase and c["leg"] == "cross_identity"
                and c["auth"] == ALICE and "/api/items/" in c["url"]]

    def test_a_held_replay_is_sent_by_the_final_pass(self):
        result, calls = self._held({"enabled": True, "reserve_seconds": 60})
        first = self._alice_items(calls, "before")
        final = self._alice_items(calls, "final_pass")
        self.assertEqual(len(first), 2, calls)
        self.assertEqual(len(final), 1, calls)
        self.assertNotIn(final[0], first)                      # only the held capture
        self.assertTrue(final[0].endswith("/api/items/9"), final)
        step = self._step(result, "held_replays")["result"]
        self.assertGreaterEqual(step["cells_run"], 1)
        self.assertGreaterEqual(step["replays"], 2)
        self.assertEqual((step["cells_still_held"], step["replays_still_held"]), (0, 0))
        self.assertIsNone(step["stopped_by"])
        self.assertEqual(result["coverage"]["final_pass"]["held_replays"], step)

    def test_control_held_replays_stay_held_with_the_pass_off(self):
        result, calls = self._held(None)
        self.assertEqual(len(self._alice_items(calls, "before")), 2)
        self.assertFalse([c for c in calls if c["phase"] != "before"])
        capped = result["coverage"]["endpoint_check_time_capped"]
        self.assertTrue(any(c["endpoint"] == "GET /api/items/{id}" and c["replays_not_run"] >= 1
                            for c in capped), capped)

    def test_control_no_held_replay_is_sent_with_no_time_or_only_the_reserve_left(self):
        for used in (3700.0, 3570.0):
            with self.subTest(used=used):
                result, calls = self._held({"enabled": True, "reserve_seconds": 60},
                                           worklist_seconds=used)
                report = result["crawl_loop"]["final_pass"]
                self.assertEqual(report["stopped_by"], "deadline")
                self.assertIn("held_replays", report["skipped"])
                self.assertFalse(self._alice_items(calls, "final_pass"))


if __name__ == "__main__":
    unittest.main()
