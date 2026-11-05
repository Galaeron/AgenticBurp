"""Retry rounds -- a time-boxed engagement keeps working, with growing budgets, until
its deadline (harness/retry_rounds.py).

The loop is driven with a fake clock and fake sweep/review callables; the worklist's
`legs_done` set and capture review's `model_failed` set are driven for real; and
investigate_engagement is driven with its phases stubbed, as in test_crawl_loop.
Every behaviour has a negative control (the feature off, no deadline, or nothing
left to retry).
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from harness import (cache, config_schema, coverage_tracker, engagement_builder,
                     evidence_ledger, retry_rounds, safety_gate, store, worklist_investigator)
from harness.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState
from harness.models import AgentReport, HttpExchange
from harness.orchestrator import Orchestrator
from harness.orchestrator_helpers import review_captured_exchanges
from harness.retry_rounds import RetryLedger, RetryRoundsConfig, is_settled, round_budgets
from harness.role_crawl import RoleSession
from harness.run_context import RunContext
from harness.test_deterministic_first import BASE, _config
from harness.test_stage_reservations import _build
from harness.test_worklist_investigator import BENIGN, OBJ, ROLES, _nothing, _state_with

BASE_BUDGETS = {"max_nodes": 10, "step_budget": 64, "max_precondition_legs": 24, "max_reviews": 200}


class _Clock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now


def _outcome(stop, *, findings=0, confirmed=False, specialty="idor", **extra):
    return dict({"path": "/n", "specialty": specialty, "stop_reason": stop, "confirmed": confirmed,
                 "findings_detail": [{"vulnerability_class": "idor", "confirmed": confirmed}
                                     for _ in range(findings)]}, **extra)


# ------------------------------------------------------------------ config + pieces
class ConfigTests(unittest.TestCase):
    def test_shipped_config_keeps_retry_rounds_off_and_passive_forces_them_off(self):
        cfg = _config()
        self.assertFalse(RetryRoundsConfig.from_config(cfg).enabled)
        self.assertIn("engagement.retry_rounds.enabled", config_schema._PASSIVE_FORCE_OFF_KNOBS)
        cfg["engagement"]["retry_rounds"]["enabled"] = True
        effective = config_schema.resolve_operating_profile(cfg, "passive-only")
        self.assertIs(effective["engagement"]["retry_rounds"]["enabled"], False)

    def test_values_are_read_and_clamped(self):
        cfg = RetryRoundsConfig.from_config({"engagement": {"retry_rounds": {
            "enabled": True, "growth": 0.5, "max_rounds": -1, "reserve_seconds": 60,
            "max_step_budget": 256, "max_idle_rounds": 0}}})
        self.assertTrue(cfg.enabled)
        self.assertEqual((cfg.growth, cfg.max_rounds, cfg.reserve_seconds), (1.0, 0, 60.0))
        self.assertEqual((cfg.max_step_budget, cfg.max_idle_rounds), (256, 0))
        self.assertEqual(RetryRoundsConfig.from_config({"engagement": {"retry_rounds": "on"}}),
                         RetryRoundsConfig())


class BudgetTests(unittest.TestCase):
    def test_each_round_multiplies_every_budget_and_caps_the_step_budget(self):
        cfg = RetryRoundsConfig(enabled=True, growth=2, max_step_budget=200)
        self.assertEqual(round_budgets(BASE_BUDGETS, cfg, 1),
                         {"max_nodes": 20, "step_budget": 128, "max_precondition_legs": 48,
                          "max_reviews": 400})
        self.assertEqual(round_budgets(BASE_BUDGETS, cfg, 3)["step_budget"], 200)
        self.assertEqual(round_budgets(BASE_BUDGETS, cfg, 3)["max_nodes"], 80)

    def test_a_base_step_budget_above_the_cap_is_never_lowered(self):
        cfg = RetryRoundsConfig(enabled=True, max_step_budget=8)
        self.assertEqual(round_budgets(BASE_BUDGETS, cfg, 2)["step_budget"], 64)

    def test_a_budget_turned_off_stays_off(self):
        cfg = RetryRoundsConfig(enabled=True)
        self.assertEqual(round_budgets(dict(BASE_BUDGETS, max_nodes=0), cfg, 3)["max_nodes"], 0)

    def test_many_rounds_do_not_overflow(self):
        cfg = RetryRoundsConfig(enabled=True, growth=10)
        self.assertEqual(round_budgets({"max_nodes": 1}, cfg, 400)["max_nodes"], 1_000_000)


class SettledTests(unittest.TestCase):
    def test_verdicts_settle_and_model_errors_or_spent_steps_do_not(self):
        for stop in ("found", "refused", "gave_up", "no_progress", "budget",
                     "repeated_duplicates", "target_distress"):
            self.assertTrue(is_settled(_outcome(stop)), stop)
        for stop in ("error", "exhausted_steps"):
            self.assertFalse(is_settled(_outcome(stop)), stop)
        self.assertTrue(is_settled(_outcome("error", confirmed=True)))      # proof stands
        self.assertFalse(is_settled(_outcome("found", error="boom")))       # the probe raised

    def test_a_node_whose_agent_never_ran_is_not_settled(self):
        self.assertFalse(is_settled(_outcome(None)))                  # agent was over budget
        self.assertTrue(is_settled(_outcome(None, specialty=None)))   # legs only, no hypothesis


class LedgerTests(unittest.TestCase):
    def test_wire_seeds_from_the_journal_and_keeps_recording_to_it(self):
        journal = []
        ledger = RetryLedger()
        kwargs = ledger.wire({"completed": {"a": _outcome("found")},
                              "on_outcome": lambda k, o: journal.append(k)})
        self.assertIs(kwargs["legs_done"], ledger.legs_done)
        kwargs["on_outcome"]("b", _outcome("error"))
        self.assertEqual(journal, ["b"])
        self.assertEqual(set(ledger.sweep_kwargs()["completed"]), {"a"})

    def test_out_of_steps_at_the_cap_settles(self):
        ledger = RetryLedger()
        ledger.record("a", _outcome("exhausted_steps"))
        ledger.step_capped = True
        ledger.record("b", _outcome("exhausted_steps"))
        self.assertEqual(set(ledger.settled()), {"b"})

    def test_reopen_takes_failed_reviews_out_of_seen(self):
        ledger = RetryLedger(review_failed={"x"})
        seen = {"x", "y"}
        self.assertEqual(ledger.reopen_reviews(seen), 1)
        self.assertEqual((seen, ledger.review_failed), ({"y"}, set()))


class BreakerTests(unittest.TestCase):
    def test_seconds_until_retry_counts_down_only_while_open(self):
        breaker = CircuitBreaker(CircuitBreakerConfig(timeout_seconds=60), name="t")
        self.assertEqual(breaker.seconds_until_retry(), 0.0)
        breaker._change_state(CircuitState.OPEN)
        self.assertGreater(breaker.seconds_until_retry(), 59)
        breaker._last_state_change -= 61
        self.assertEqual(breaker.seconds_until_retry(), 0.0)  # still OPEN, but a call goes through


# ------------------------------------------------------------------ the loop
class LoopTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, cfg, sweeps, *, deadline=1000.0, reviews=None, retry_after=None,
                   cancelled=None, ledger=None, seen=None, clock=None):
        clock = clock or _Clock()
        ledger = ledger or RetryLedger()
        calls = {"sweep": [], "review": [], "slept": []}

        async def sweep(budgets, stop_at):
            calls["sweep"].append((budgets, stop_at))
            fresh, summary, spent = (sweeps.pop(0) if sweeps else ([], {}, 1.0))
            clock.now += spent
            return fresh, summary

        async def review(budgets, stop_at):
            calls["review"].append(set(seen or ()))
            return (reviews.pop(0) if reviews else (0, 0))

        async def sleep(seconds):
            calls["slept"].append(seconds)
            clock.now += seconds

        report = await retry_rounds.run_retry_rounds(
            cfg, ledger, deadline=deadline, base_budgets=BASE_BUDGETS, sweep=sweep,
            review=review, reviewed=seen if seen is not None else set(),
            cancelled=cancelled or (lambda: False), retry_after=retry_after or (lambda: 0.0),
            clock=clock, sleep=sleep)
        return report, calls

    async def test_budgets_grow_each_round_until_nothing_is_left(self):
        cfg = RetryRoundsConfig(enabled=True, reserve_seconds=100)
        report, calls = await self._run(cfg, [
            ([_outcome("found", findings=1)], {"skipped_by_reason": {"budget_exhausted": 3}}, 10),
            ([_outcome("gave_up")], {}, 10),
            ([], {}, 1)])
        self.assertEqual(report["stopped_by"], "nothing_left")
        self.assertEqual([b["max_nodes"] for b, _ in calls["sweep"]], [20, 40, 80])
        self.assertEqual({stop for _, stop in calls["sweep"]}, {900.0})  # deadline - reserve
        self.assertEqual((report["findings"], len(report["rounds"])), (1, 3))
        self.assertEqual(report["rounds"][0]["budget_exhausted"], 3)

    async def test_rounds_run_until_the_deadline_less_the_reserve(self):
        cfg = RetryRoundsConfig(enabled=True, reserve_seconds=100, max_idle_rounds=0)
        busy = [([_outcome("error")], {}, 300) for _ in range(10)]
        report, calls = await self._run(cfg, busy)
        self.assertEqual(report["stopped_by"], "deadline")
        self.assertEqual(len(calls["sweep"]), 3)       # starts at 0, 300, 600; 900 is the stop

    async def test_an_open_breaker_is_waited_for_but_never_past_the_deadline(self):
        cfg = RetryRoundsConfig(enabled=True, reserve_seconds=0, breaker_wait_seconds=120)
        report, calls = await self._run(cfg, [([_outcome("found")], {}, 1)], retry_after=lambda: 42.0,
                                        deadline=1000.0)
        self.assertAlmostEqual(sum(calls["slept"][:9]), 42.0)
        self.assertEqual(report["rounds"][0]["waited_s"], 42.0)
        short, calls = await self._run(cfg, [], retry_after=lambda: 500.0, deadline=30.0)
        self.assertEqual(sum(calls["slept"]), 30.0)
        self.assertEqual((short["stopped_by"], calls["sweep"]), ("deadline", []))

    async def test_control_a_closed_breaker_waits_for_nothing(self):
        cfg = RetryRoundsConfig(enabled=True)
        _, calls = await self._run(cfg, [])
        self.assertEqual(calls["slept"], [])

    async def test_idle_rounds_stop_the_loop(self):
        cfg = RetryRoundsConfig(enabled=True, max_idle_rounds=2)
        errored = [([_outcome("error")], {}, 1) for _ in range(5)]
        report, calls = await self._run(cfg, errored)
        self.assertEqual((report["stopped_by"], len(calls["sweep"])), ("no_progress", 2))

    async def test_control_a_round_that_settles_work_resets_the_idle_count(self):
        cfg = RetryRoundsConfig(enabled=True, max_idle_rounds=2, max_rounds=4)
        mixed = [([_outcome("error")], {}, 1), ([_outcome("gave_up")], {}, 1),
                 ([_outcome("error")], {}, 1), ([_outcome("found")], {}, 1)]
        report, _ = await self._run(cfg, mixed)
        self.assertEqual(report["stopped_by"], "max_rounds")

    async def test_cancellation_and_max_rounds_stop_the_loop(self):
        report, calls = await self._run(RetryRoundsConfig(enabled=True), [],
                                        cancelled=lambda: True)
        self.assertEqual((report["stopped_by"], calls["sweep"]), ("cancelled", []))
        report, calls = await self._run(RetryRoundsConfig(enabled=True, max_rounds=1),
                                        [([_outcome("found")], {}, 1)])
        self.assertEqual((report["stopped_by"], len(calls["sweep"])), ("max_rounds", 1))

    async def test_control_no_deadline_runs_no_round(self):
        report, calls = await self._run(RetryRoundsConfig(enabled=True), [], deadline=None)
        self.assertEqual((report["stopped_by"], calls["sweep"]), ("no_deadline", []))

    async def test_failed_reviews_are_reopened_before_each_round(self):
        seen = {"ok", "failed"}
        ledger = RetryLedger(review_failed={"failed"})
        report, calls = await self._run(RetryRoundsConfig(enabled=True, max_rounds=1), [],
                                        reviews=[(1, 1)], ledger=ledger, seen=seen)
        self.assertEqual(calls["review"], [{"ok"}])
        self.assertEqual(report["rounds"][0]["reviews_reopened"], 1)
        self.assertEqual(report["reviews_with_findings"], 1)

    async def test_retry_outcomes_are_tagged_with_their_round(self):
        fresh = [_outcome("found")]
        await self._run(RetryRoundsConfig(enabled=True, max_rounds=1), [(fresh, {}, 1)])
        self.assertEqual(fresh[0]["retry_round"], 1)


# ------------------------------------------------------------------ worklist legs_done
class LegsDoneTests(unittest.IsolatedAsyncioTestCase):
    """investigate_worklist does not send a node's deterministic legs twice in a run."""

    async def _sweep(self, st, legs, *, legs_done, completed=None, max_legs=24, on_outcome=None,
                     probe=None):
        async def precondition(node, exchange):
            legs.append(node["path"])
            return []

        async def default_probe(exchange, hypothesis, specialty, step_budget):
            return _nothing()

        return await worklist_investigator.investigate_worklist(
            probe or default_probe, st, "http://t", ROLES, precondition_fn=precondition,
            max_precondition_legs=max_legs, legs_done=legs_done, completed=completed,
            on_outcome=on_outcome)

    async def test_legs_run_once_and_a_second_sweep_spends_no_leg_budget_on_them(self):
        st = _state_with([BENIGN, dict(BENIGN, path="/api/status")])
        legs, done = [], set()
        await self._sweep(st, legs, legs_done=done, max_legs=1)
        self.assertEqual(len(legs), 1)
        await self._sweep(st, legs, legs_done=done, max_legs=1)
        self.assertEqual(sorted(legs), ["/api/health", "/api/status"])  # the other node's turn
        await self._sweep(st, legs, legs_done=done, max_legs=1)
        self.assertEqual(len(legs), 2)                                 # nothing sent again

    async def test_control_without_legs_done_the_legs_are_sent_again(self):
        st = _state_with([BENIGN])
        legs = []
        await self._sweep(st, legs, legs_done=None)
        await self._sweep(st, legs, legs_done=None)
        self.assertEqual(legs, ["/api/health", "/api/health"])

    async def test_a_leg_that_raised_is_tried_again(self):
        st = _state_with([BENIGN])
        done, tries = set(), []

        async def flaky(node, exchange):
            tries.append(node["path"])
            if len(tries) == 1:
                raise RuntimeError("connection reset")
            return []

        for _ in range(3):
            await worklist_investigator.investigate_worklist(
                AsyncMock(), st, "http://t", ROLES, precondition_fn=flaky, legs_done=done)
        self.assertEqual(len(tries), 2)

    async def test_an_errored_probe_is_probed_again_without_its_legs(self):
        st = _state_with([OBJ])
        legs = []
        stops = iter(["error", "found"])
        probes = []

        async def probe(exchange, hypothesis, specialty, step_budget):
            probes.append(step_budget)
            return {"iterative_result": {"stop_reason": next(stops), "findings": []}}

        ledger = RetryLedger()
        kwargs = ledger.wire({})
        await worklist_investigator.investigate_worklist(
            probe, st, "http://t", ROLES, precondition_fn=self._leg(legs), **kwargs)
        out = await worklist_investigator.investigate_worklist(
            probe, st, "http://t", ROLES, precondition_fn=self._leg(legs), step_budget=32,
            **ledger.sweep_kwargs())
        self.assertEqual((legs, probes), (["/api/tickets/{id}"], [16, 32]))
        self.assertEqual(out[0]["stop_reason"], "found")
        # Settled now: a third sweep resumes it instead of probing.
        out = await worklist_investigator.investigate_worklist(
            probe, st, "http://t", ROLES, precondition_fn=self._leg(legs), **ledger.sweep_kwargs())
        self.assertEqual((len(probes), out[0].get("resumed")), (2, True))

    @staticmethod
    def _leg(legs):
        async def precondition(node, exchange):
            legs.append(node["path"])
            return []
        return precondition


# ------------------------------------------------------------------ review model_failed
class ReviewModelFailedTests(unittest.IsolatedAsyncioTestCase):
    def _orch(self, reports=None, raises=False):
        analyze = AsyncMock(side_effect=RuntimeError("boom")) if raises else AsyncMock(
            return_value=SimpleNamespace(agent_reports=reports or []))
        return SimpleNamespace(analyze=analyze), SimpleNamespace(record_template=lambda *a: None)

    @staticmethod
    def _captured():
        return [HttpExchange(url="http://127.0.0.1:3002/api/a?id=1", method="GET",
                             response_status=200, response_body='{"a": 1}')]

    async def test_an_agent_raw_error_or_a_raise_marks_the_capture(self):
        for orch, state in (self._orch([AgentReport(agent="a", model="m", findings=[],
                                                    raw_error="OllamaError: empty body")]),
                            self._orch(raises=True)):
            failed, seen = set(), set()
            await review_captured_exchanges(orch, state, self._captured(), seen=seen,
                                            errors=[], model_failed=failed)
            self.assertEqual(len(failed), 1)
            self.assertEqual(failed, seen)   # still seen until a retry round reopens it

    async def test_control_a_clean_review_marks_nothing(self):
        orch, state = self._orch([AgentReport(agent="a", model="m", findings=[])])
        failed = set()
        await review_captured_exchanges(orch, state, self._captured(), seen=set(),
                                        model_failed=failed)
        self.assertEqual(failed, set())


# ------------------------------------------------------------------ orchestrator caller
class RetryRoundsCallerTests(unittest.TestCase):
    """investigate_engagement runs retry rounds after the coverage drive."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="retry_rounds_", dir=Path(__file__).parent.parent
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

    def _investigate(self, engagement=None, **investigate):
        cfg = _config()
        cfg["engagement"].update(engagement or {})
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["shop.test"]
        rc = RunContext.create(allowed_hosts=["shop.test"], max_requests=100, config=cfg)
        sweeps, reviews = [], []

        async def worklist(probe, st, base, roles, **kwargs):
            sweeps.append(kwargs)
            on_outcome, completed = kwargs.get("on_outcome"), kwargs.get("completed") or {}
            if len(sweeps) == 1:
                # The first pass: the probe on /a ended on a model error, another node
                # was over budget, and /a's legs were attempted.
                out = _outcome("error", path="/a")
                if on_outcome is not None:
                    on_outcome("GET|/a", out)
                if kwargs.get("legs_done") is not None:
                    kwargs["legs_done"].add("GET|/a")
                kwargs["summary_out"].update({"skipped_by_reason": {"budget_exhausted": 1}})
                return [out]
            if "GET|/a" in completed:
                return [dict(completed["GET|/a"], resumed=True)]
            out = _outcome("found", findings=1, path="/a")
            on_outcome("GET|/a", out)
            return [out]

        async def review(orch_, state, captured, **kwargs):
            reviews.append({"seen": set(kwargs["seen"]), "max_reviews": kwargs["max_reviews"],
                            "model_failed": kwargs.get("model_failed")})
            if len(reviews) == 1:
                kwargs["seen"].add("cap-1")
                if kwargs.get("model_failed") is not None:
                    kwargs["model_failed"].add("cap-1")   # its model call failed
            elif len(reviews) == 2:
                kwargs["stats"]["reviewed"] += 1              # reviewed again, cleanly
            return 0

        patches = [patch.object(engagement_builder, "build_engagement", new=_build),
                   patch.object(worklist_investigator, "investigate_worklist", new=worklist),
                   patch.object(coverage_tracker, "build_coverage_driven",
                                new=AsyncMock(return_value={})),
                   patch("harness.orchestrator_chain.review_captured_exchanges", new=review),
                   patch("harness.orchestrator_chain.universal_header_audit",
                         new=AsyncMock(return_value=0)),
                   patch("harness.browser_driver.default_driver", return_value=None),
                   patch.object(retry_rounds, "_breaker_retry_after", return_value=0.0)]

        async def go():
            try:
                async with rc:
                    return await orch.investigate_engagement(
                        BASE, [RoleSession("anonymous", {})], max_nodes=1, step_budget=16,
                        max_chain_rounds=0, discovery_max_probes=1, run_context=rc,
                        **investigate)
            finally:
                await rc.aclose()

        for p in patches:
            p.start()
        try:
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        return result, sweeps, reviews

    def test_time_left_goes_to_escalated_rounds_over_the_work_left(self):
        result, sweeps, reviews = self._investigate({
            "investigation_seconds": 900, "capture_review_limit": 5,
            "max_precondition_legs": 24, "retry_rounds": {"enabled": True}})
        self.assertEqual(len(sweeps), 3)
        first, retry, last = sweeps
        self.assertEqual((first["max_nodes"], first["step_budget"],
                          first["max_precondition_legs"]), (1, 16, 24))
        self.assertEqual((retry["max_nodes"], retry["step_budget"],
                          retry["max_precondition_legs"]), (2, 32, 48))
        self.assertNotIn("GET|/a", retry["completed"])   # the errored probe is retried
        self.assertIn("GET|/a", last["completed"])       # and is settled after it
        self.assertIs(retry["legs_done"], first["legs_done"])
        self.assertEqual(first["legs_done"], {"GET|/a"})
        # The capture whose model review failed is reviewed again, at double the limit.
        self.assertNotIn("cap-1", reviews[1]["seen"])
        self.assertEqual((reviews[0]["max_reviews"], reviews[1]["max_reviews"]), (5, 10))
        report = result["crawl_loop"]["retry_rounds"]
        self.assertEqual((report["stopped_by"], len(report["rounds"]), report["findings"]),
                         ("nothing_left", 2, 1))
        retried = [o for o in result["outcomes"] if o.get("retry_round")]
        self.assertEqual([o["stop_reason"] for o in retried], ["found"])

    def test_control_off_the_run_sweeps_once_and_records_nothing(self):
        result, sweeps, reviews = self._investigate({"investigation_seconds": 900})
        self.assertEqual(len(sweeps), 1)
        self.assertNotIn("legs_done", sweeps[0])
        self.assertIsNone(reviews[0]["model_failed"])
        self.assertEqual(result["crawl_loop"]["retry_rounds"], {"enabled": False})

    def test_control_on_without_a_deadline_runs_no_round(self):
        result, sweeps, _ = self._investigate({"retry_rounds": {"enabled": True}})
        self.assertEqual(len(sweeps), 1)
        self.assertNotIn("legs_done", sweeps[0])
        self.assertEqual(result["crawl_loop"]["retry_rounds"]["stopped_by"], "no_deadline")


if __name__ == "__main__":
    unittest.main()
