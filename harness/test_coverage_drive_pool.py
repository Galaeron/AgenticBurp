"""Coverage drive worker pool (engagement.coverage_drive_workers).

The drive sent one cell at a time; r10 ended with 912 cells budget_exhausted.
`coverage_tracker._run_drive_pool` lets several cells be in flight. What is held:

- 1 worker (the default) is the former sequential drive: same dispatch order, same
  report keys. N workers overlap (an asyncio.Barrier only N concurrent legs pass);
  1 worker never does (control).
- Exclusive lane: a timing/state leg (sqlmap, race, writes, browser legs, any cell
  on a write method) never overlaps another dispatch. Control: classifying every
  leg as shared lets them overlap, and the check sees it.
- One identity has at most one shared cell in flight. Control: without that rule,
  one identity's cells overlap.
- Each cell is claimed once; the leg budget is never overspent (legs and
  per-parameter cases); the run's RequestBudget is never overspent through a real
  transport (control: a budget whose reserve yields between check and use
  overspends under the same pool); the deadline stops every worker; cancelling
  the drive cancels every in-flight leg; final cell states equal the sequential
  run's for the same inputs.
- Session state: a refresh is not repeated by concurrent sends that saw the same
  stale window (control: the former feedback refreshes twice), and a send that
  raced a refresh does not count against the new credentials.
- Caller level: investigate_engagement passes the configured worker count to the
  drive and the drive's legs overlap; the default does not.
- Throughput: cells per second at 1 vs N workers against a 127.0.0.1 fixture
  that adds latency, through the real transport (`python -m
  harness.test_coverage_drive_pool` prints the table).

Synthetic loopback fixtures only; nothing is sent to a live target.
"""
from __future__ import annotations

import asyncio
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch

from harness import coverage_tracker
from harness.coverage_model import CHECKS_BY_ID
from harness.coverage_tracker import (_EXCLUSIVE_LEG_CONFIRMATIONS, _LEG_CONFIRMATIONS,
                                      _PASSIVE_LEG_CONFIRMATIONS, _SHARED_LEG_CONFIRMATIONS,
                                      build_coverage_cases_driven, build_coverage_driven)
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.role_crawl import RoleSession
from harness.run_context import RequestBudget, RunContext, TypedRequest

BASE = "http://127.0.0.1:9/"
_LANE = coverage_tracker._drive_lane   # the real classification, whatever a test patches
ROLES = [RoleSession("anonymous", {}),
         RoleSession("alice", {"Authorization": "Bearer a"}, name="alice"),
         RoleSession("bob", {"Authorization": "Bearer b"}, name="bob"),
         RoleSession("carol", {"Authorization": "Bearer c"}, name="carol")]


def _state(reads=6, searches=0, writes=0, roles=ROLES, params=("term",)):
    """GET /api/page{i} (CORS applies), GET /api/search{i}?<params> (injection legs
    apply) and POST /api/form{i}, each reached by every role."""
    state = EngagementState(host="127.0.0.1")
    eps = ([("GET", f"/api/page{i}") for i in range(reads)]
           + [("GET", f"/api/search{i}") for i in range(searches)]
           + [("POST", f"/api/form{i}") for i in range(writes)])
    state.ingest_role_crawl({"endpoints": [
        {"method": m, "path": p, "by_role": {r.role: 200 for r in roles},
         "reachable_roles": [r.role for r in roles], "object_scoped": False} for m, p in eps]})
    query = "&".join(f"{p}=x" for p in params)
    for i in range(searches):
        url = f"{BASE}api/search{i}?{query}"
        state.record_template(url, "GET", HttpExchange(url=url, method="GET", response_status=200))
    return state


class _Legs:
    """Instrumented stub legs: what is in flight, per call, and in what order."""

    def __init__(self, seconds=0.01, barrier=None, status="not_confirmed"):
        self.seconds, self.barrier, self.status = seconds, barrier, status
        self.in_flight: list = []
        self.calls: list = []
        self.max_in_flight = 0
        self.exclusive_overlaps: list = []
        self.identity_overlaps: list = []
        self.barrier_passed = 0
        self.started_at: list = []
        self.cancelled = 0

    async def _run(self, identity, method, path, check, case=None):
        cell = (identity, f"{method} {path}", check.id, getattr(case, "parameter_name", None))
        lane = _LANE(f"{method} {path}", check)
        for other in self.in_flight:
            if lane == "exclusive" or other[1] == "exclusive":
                self.exclusive_overlaps.append((cell, other[0]))
            if lane == "shared" and other[1] == "shared" and other[0][0] == identity:
                self.identity_overlaps.append((cell, other[0]))
        entry = (cell, lane)
        self.in_flight.append(entry)
        self.calls.append(cell)
        self.started_at.append(time.monotonic())
        self.max_in_flight = max(self.max_in_flight, len(self.in_flight))
        try:
            if self.barrier is not None:
                try:
                    await asyncio.wait_for(self.barrier.wait(), timeout=0.5)
                    self.barrier_passed += 1
                except (asyncio.TimeoutError, asyncio.BrokenBarrierError):
                    pass
            await asyncio.sleep(self.seconds)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        finally:
            self.in_flight.remove(entry)
        tested = ((case.parameter_location, case.parameter_name),) if case is not None else ()
        return SimpleNamespace(status=self.status, sent_count=1, summary="stub leg",
                               tested_parameters=tested)

    async def run_leg(self, identity, method, path, check):
        return await self._run(identity, method, path, check)

    async def run_case(self, identity, method, path, check, case, **kwargs):
        return await self._run(identity, method, path, check, case)


def _drive(state, legs, *, cases=False, roles=ROLES, **kwargs):
    out = []
    builder = build_coverage_cases_driven if cases else build_coverage_driven
    runner = legs.run_case if cases else legs.run_leg
    report = asyncio.run(builder(state, roles, runner, tracker_out=out, **kwargs))
    return report, out[0]


def _statuses(tracker):
    return {key: (cell.status, cell.executed) for key, cell in tracker.matrix.cells().items()}


def _case_statuses(tracker):
    out = {}
    for key in tracker.matrix.cells():
        for case, res in tracker.matrix.cases_for_cell(*key):
            out[(key, case.coord_id())] = (res.status, res.executed)
    return out


class LaneClassificationTests(unittest.TestCase):
    def test_every_leg_has_one_lane(self):
        lanes = (_PASSIVE_LEG_CONFIRMATIONS, _SHARED_LEG_CONFIRMATIONS, _EXCLUSIVE_LEG_CONFIRMATIONS)
        for a in range(3):
            for b in range(a + 1, 3):
                self.assertFalse(lanes[a] & lanes[b])
        self.assertEqual(set(_LEG_CONFIRMATIONS), set().union(*lanes))

    def test_timing_and_state_legs_are_exclusive(self):
        for name in ("race_condition", "toctou", "rate_limit", "sqlmap", "file_upload",
                     "write_integrity", "verb_tamper", "csrf", "stored_xss", "http_request_smuggling"):
            self.assertIn(name, _EXCLUSIVE_LEG_CONFIRMATIONS)

    def test_a_write_method_cell_is_exclusive_and_an_unknown_leg_too(self):
        cors = SimpleNamespace(confirmation="cors")
        self.assertEqual(coverage_tracker._drive_lane("GET /a", cors), "shared")
        for method in ("POST", "PUT", "PATCH", "DELETE", "TRACE"):
            self.assertEqual(coverage_tracker._drive_lane(f"{method} /a", cors), "exclusive")
        self.assertEqual(coverage_tracker._drive_lane("GET /a", SimpleNamespace(confirmation="new_leg")),
                         "exclusive")
        self.assertEqual(coverage_tracker._drive_lane(
            "POST /a", SimpleNamespace(confirmation="security_headers")), "passive")

    def test_workers_must_be_an_integer_of_at_least_one(self):
        for bad in (0, -1, True, 2.0, "2"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                _drive(_state(reads=1), _Legs(), driveable={"cors"}, workers=bad)


class OverlapTests(unittest.TestCase):
    def test_n_workers_overlap(self):
        legs = _Legs(barrier=asyncio.Barrier(3))
        report, _t = _drive(_state(reads=3), legs, driveable={"cors"}, workers=3)
        self.assertGreaterEqual(legs.barrier_passed, 3)
        self.assertEqual(legs.max_in_flight, 3)
        self.assertEqual(report["drive_pool"]["max_in_flight"], 3)

    def test_control_one_worker_never_overlaps(self):
        legs = _Legs(barrier=asyncio.Barrier(3), seconds=0)
        report, _t = _drive(_state(reads=2), legs, driveable={"cors"})
        self.assertEqual(legs.barrier_passed, 0)
        self.assertEqual(legs.max_in_flight, 1)
        self.assertNotIn("drive_pool", report)   # one worker reports as before

    def test_one_worker_dispatches_in_the_drive_order(self):
        for deadline in (None, 10**9):
            with self.subTest(deadline=deadline):
                state = _state(reads=3, searches=2, writes=2)
                legs = _Legs(seconds=0)
                tracker = coverage_tracker.CoverageTracker()
                endpoints = coverage_tracker.endpoint_view(state)
                idents, roles = coverage_tracker._identities_of(ROLES)
                tracker.build(endpoints, idents, roles)
                pending = tracker.pending_leg_cells({"cors", "sqlmap", "csp"})
                expected = [(i, e, c.id, None) for i, e, c in coverage_tracker._drive_order(
                    pending, tracker._unauthenticated(), None if deadline is None else {})]
                # A frozen clock: every dispatch takes 0 s, so the time-fair order
                # read during the drive is the one computed here.
                with patch.object(coverage_tracker, "time", SimpleNamespace(monotonic=lambda: 1000.0)):
                    _drive(state, legs, driveable={"cors", "sqlmap", "csp"}, budget=10**6,
                           deadline=None if deadline is None else 1000.0 + deadline)
                self.assertEqual(legs.calls, expected)


class ExclusiveLaneTests(unittest.TestCase):
    DRIVEABLE = {"cors", "sqlmap", "csp"}

    def run_mixed(self, workers=4, cases=False):
        legs = _Legs(seconds=0.005)
        report, tracker = _drive(_state(reads=4, searches=2, writes=2), legs, cases=cases,
                                 driveable=self.DRIVEABLE, workers=workers, budget=10**6)
        return legs, report

    def test_exclusive_legs_never_overlap_anything(self):
        for cases in (False, True):
            with self.subTest(cases=cases):
                legs, report = self.run_mixed(cases=cases)
                lanes = {coverage_tracker._drive_lane(c[1], CHECKS_BY_ID[c[2]]) for c in legs.calls}
                self.assertIn("exclusive", lanes)          # sqlmap cells and POST cells ran
                self.assertEqual(legs.exclusive_overlaps, [])
                self.assertGreater(legs.max_in_flight, 1)  # shared cells still overlapped
                self.assertGreater(report["drive_pool"]["exclusive_dispatches"], 0)

    def test_control_without_the_lane_exclusive_legs_overlap(self):
        def everything_shared(endpoint, check):
            lane = _LANE(endpoint, check)
            return "shared" if lane == "exclusive" else lane
        with patch.object(coverage_tracker, "_drive_lane", everything_shared):
            legs, _report = self.run_mixed()
        self.assertNotEqual(legs.exclusive_overlaps, [])


class IdentityTests(unittest.TestCase):
    def test_one_identity_has_one_shared_cell_in_flight(self):
        legs = _Legs(seconds=0.005)
        _drive(_state(reads=6), legs, driveable={"cors", "csp"}, workers=8)
        self.assertEqual(legs.identity_overlaps, [])
        self.assertGreater(legs.max_in_flight, 1)
        self.assertLessEqual(legs.max_in_flight, len(ROLES))

    def test_one_identity_alone_is_never_overlapped(self):
        legs = _Legs(seconds=0.005)
        _drive(_state(reads=6, roles=ROLES[:1]), legs, roles=ROLES[:1], driveable={"cors", "csp"},
               workers=8)
        self.assertEqual(legs.max_in_flight, 1)

    def test_control_without_the_identity_rule_one_identity_overlaps(self):
        real_pool = coverage_tracker._run_drive_pool

        async def no_identity_rule(order, workers, claim, dispatch, cell_of, stats):
            # Every cell under its own key: the identity rule never applies.
            keyed = lambda item: (object(), *cell_of(item)[1:])   # noqa: E731
            return await real_pool(order, workers, claim, dispatch, keyed, stats)
        legs = _Legs(seconds=0.005)
        with patch.object(coverage_tracker, "_run_drive_pool", no_identity_rule):
            _drive(_state(reads=6), legs, driveable={"cors", "csp"}, workers=8)
        self.assertNotEqual(legs.identity_overlaps, [])


class ClaimBudgetDeadlineTests(unittest.TestCase):
    def test_each_cell_runs_once_and_states_equal_the_sequential_run(self):
        for cases in (False, True):
            with self.subTest(cases=cases):
                kwargs = dict(cases=cases, driveable={"cors", "csp", "sqlmap", "ssti"},
                              budget=10**6)
                seq_legs, par_legs = _Legs(seconds=0), _Legs(seconds=0.002)
                seq_report, seq = _drive(_state(reads=4, searches=3, writes=2,
                                                params=("a", "b", "c")), seq_legs, **kwargs)
                par_report, par = _drive(_state(reads=4, searches=3, writes=2,
                                                params=("a", "b", "c")), par_legs, workers=5,
                                         **kwargs)
                self.assertEqual(len(par_legs.calls), len(set(par_legs.calls)))
                self.assertEqual(sorted(par_legs.calls, key=repr), sorted(seq_legs.calls, key=repr))
                self.assertEqual(_statuses(par), _statuses(seq))
                self.assertEqual(_case_statuses(par), _case_statuses(seq))
                key = "cases_driven" if cases else "legs_driven"
                self.assertEqual(par_report[key], seq_report[key])
                self.assertGreater(par_legs.max_in_flight, 1)

    def test_control_a_cell_offered_twice_is_seen(self):
        real = coverage_tracker._drive_order

        def twice(items, unauthenticated, spent=None):
            for item in real(items, unauthenticated, spent):
                yield item
                yield item
        legs = _Legs(seconds=0.002)
        with patch.object(coverage_tracker, "_drive_order", twice):
            _drive(_state(reads=3), legs, driveable={"cors"}, workers=3, budget=10**6)
        self.assertNotEqual(len(legs.calls), len(set(legs.calls)))

    def test_leg_budget_is_never_overspent(self):
        for workers in (1, 4, 16):
            with self.subTest(workers=workers):
                legs = _Legs(seconds=0.003)
                report, tracker = _drive(_state(reads=8), legs, driveable={"cors", "csp"},
                                         budget=7, workers=workers)
                self.assertEqual(len(legs.calls), 7)
                self.assertEqual(report["legs_driven"], 7)
                self.assertEqual(report["drive_stopped_by"], "leg budget")

    def test_per_parameter_case_budget_is_never_overspent(self):
        for workers in (1, 3, 8):
            for budget in (1, 4, 9, 13):
                with self.subTest(workers=workers, budget=budget):
                    legs = _Legs(seconds=0.002)
                    report, _t = _drive(_state(reads=0, searches=4, params=("a", "b", "c")), legs,
                                        cases=True, driveable={"ssti", "command_injection"},
                                        budget=budget, workers=workers)
                    self.assertLessEqual(len(legs.calls), budget)
                    self.assertEqual(report["cases_driven"], len(legs.calls))

    def test_per_parameter_budget_is_used_as_the_sequential_run_uses_it(self):
        # A finished cell hands back the units it held and did not use, so the
        # pool spends the budget as fully as one worker does.
        seq_legs, par_legs = _Legs(seconds=0), _Legs(seconds=0.002)
        kwargs = dict(cases=True, driveable={"ssti", "command_injection"}, budget=11)
        seq, _ = _drive(_state(reads=0, searches=4, params=("a", "b")), seq_legs, **kwargs)
        par, _ = _drive(_state(reads=0, searches=4, params=("a", "b")), par_legs, workers=4, **kwargs)
        self.assertEqual(par["cases_driven"], seq["cases_driven"])
        self.assertEqual(par["cases_driven"], 11)

    def test_control_a_leg_that_ignores_its_units_overspends(self):
        original = coverage_tracker.CoverageTracker._drive_parameter_cases

        async def ignores_units(self, run_case, ident, ep_key, check, cks, rep, targets, deadline,
                                remaining, field_cap):
            return await original(self, run_case, ident, ep_key, check, cks, rep, targets,
                                  deadline, 10**6, field_cap)
        legs = _Legs(seconds=0.002)
        with patch.object(coverage_tracker.CoverageTracker, "_drive_parameter_cases", ignores_units):
            _drive(_state(reads=0, searches=4, params=("a", "b", "c")), legs, cases=True,
                   driveable={"ssti", "command_injection"}, budget=4, workers=4)
        self.assertGreater(len(legs.calls), 4)

    def test_deadline_stops_every_worker(self):
        for cases in (False, True):
            with self.subTest(cases=cases):
                legs = _Legs(seconds=0.05)
                deadline = time.monotonic() + 0.12
                report, tracker = _drive(_state(reads=10), legs, cases=cases,
                                         driveable={"cors", "csp"}, budget=10**6,
                                         deadline=deadline, workers=4)
                self.assertEqual(report["drive_stopped_by"], "time budget")
                self.assertTrue(all(t < deadline for t in legs.started_at))
                self.assertGreater(report["queued_not_attempted"], 0)
                self.assertEqual(legs.in_flight, [])

    def test_control_without_a_deadline_every_cell_runs(self):
        legs = _Legs(seconds=0.002)
        report, _t = _drive(_state(reads=10), legs, driveable={"cors", "csp"}, budget=10**6,
                            workers=4)
        self.assertIsNone(report["drive_stopped_by"])
        self.assertEqual(report["queued_not_attempted"], 0)

    def test_cancelling_the_drive_cancels_every_worker(self):
        legs = _Legs(seconds=10)

        async def go():
            task = asyncio.ensure_future(build_coverage_driven(
                _state(reads=6), ROLES, legs.run_leg, driveable={"cors", "csp"}, workers=4))
            while legs.max_in_flight < 4:
                await asyncio.sleep(0.01)
            started = len(legs.calls)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await asyncio.sleep(0.05)
            return started
        started = asyncio.run(go())
        self.assertEqual(legs.cancelled, 4)
        self.assertEqual(len(legs.calls), started)
        self.assertEqual(legs.in_flight, [])

    def test_a_worker_that_raises_stops_the_drive(self):
        legs = _Legs(seconds=0.01)
        calls = []

        async def boom(*args, **kwargs):
            raise KeyError("recording bug")
        with patch.object(coverage_tracker.CoverageTracker, "_drive_leg_cell",
                          lambda self, run_leg, *a: (calls.append(a), boom())[1]):
            with self.assertRaises(KeyError):
                _drive(_state(reads=6), legs, driveable={"cors"}, workers=3)
        self.assertLessEqual(len(calls), 3 + 3)


# ----------------------------------------------------------------- real transport
class _LatencyServer:
    """A 127.0.0.1 server that answers every GET after `latency` seconds."""

    def __init__(self, latency):
        self.count = 0
        lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                with lock:
                    outer.count += 1
                time.sleep(latency)
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _transport_drive(server, *, workers, reads=8, sends_per_cell=2, max_requests=None,
                     budget_cls=None, throttle_rps=0):
    """Drive CORS+CSP cells whose leg sends `sends_per_cell` GETs through the run's
    real TargetTransport. Returns (cells, seconds, ctx, report)."""
    from harness import global_throttle
    ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=max_requests,
                            gate_config={"active_enabled": True})
    if budget_cls is not None:
        ctx.budget = budget_cls(max_requests)

    async def run_leg(identity, method, path, check):
        # As the validators do: the global throttle is acquired by the leg before
        # each send (TargetTransport itself does not acquire it).
        ex = ctx.executor()
        outcomes = []
        for _ in range(sends_per_cell):
            await global_throttle.acquire()
            outcomes.append(await ex.send("GET", server.base + path, capability=check.confirmation))
        return SimpleNamespace(status="not_confirmed" if all(o.ok for o in outcomes) else "error",
                               sent_count=sum(o.ok for o in outcomes), summary="transport leg")

    async def go():
        async with ctx:
            started = time.perf_counter()
            report = await build_coverage_driven(_state(reads=reads), ROLES, run_leg,
                                                 driveable={"cors", "csp"}, budget=10**6,
                                                 workers=workers)
            return report, time.perf_counter() - started
    # A fresh process throttle per drive: its asyncio.Lock binds to the first event
    # loop that contends for it, and each drive here runs in a loop of its own.
    throttle = global_throttle.GlobalRequestThrottle()
    throttle.configure(throttle_rps)
    with patch.object(global_throttle, "throttle", throttle):
        report, seconds = asyncio.run(go())
    return report["legs_driven"] + report["passive_legs_judged"], seconds, ctx, report


class _LateCountBudget(RequestBudget):
    """Defect injection: a budget that checks before the send but records the use
    only once the answer is back (10 ms later; the fixture answers in 20 ms). One
    worker never notices; concurrent sends all pass the same check."""

    def reserve(self, n=1, label=""):
        if self._max is not None and self._used + n > self._max:
            return False
        asyncio.get_running_loop().call_later(0.01, self._count, n)
        return True

    def _count(self, n):
        self._used += n


class RequestBudgetTests(unittest.TestCase):
    def setUp(self):
        self.server = _LatencyServer(0.02)
        self.addCleanup(self.server.close)

    def test_the_run_request_budget_is_never_overspent(self):
        for workers in (1, 4, 8):
            with self.subTest(workers=workers):
                before = self.server.count
                _cells, _s, ctx, _r = _transport_drive(self.server, workers=workers, max_requests=9)
                self.assertEqual(ctx.budget.used, 9)
                self.assertEqual(self.server.count - before, 9)

    def test_control_a_budget_that_counts_late_overspends_only_under_the_pool(self):
        before = self.server.count
        _transport_drive(self.server, workers=1, max_requests=10, budget_cls=_LateCountBudget)
        self.assertEqual(self.server.count - before, 10)
        before = self.server.count
        _transport_drive(self.server, workers=8, max_requests=10, budget_cls=_LateCountBudget)
        self.assertGreater(self.server.count - before, 10)


class SessionRaceTests(unittest.TestCase):
    _FRESH = {"transport": {"session_freshness": {
        "enabled": True, "window": 6, "min_denials": 3, "min_routes": 2, "denial_rate": 0.5}}}

    def _ctx(self):
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], config=self._FRESH,
                                gate_config={"active_enabled": True})
        session = ctx.sessions.register("s1", "alice", {"Authorization": "Bearer T1"},
                                        allowed_origins=["http://127.0.0.1:9"], name="alice")
        refreshes = []

        async def refresh():
            refreshes.append(1)
            await asyncio.sleep(0.02)
            return {"Authorization": f"Bearer T{len(refreshes) + 1}"}
        ctx.sessions.set_refresh("s1", refresh)
        monitor = ctx.freshness()
        for path in ("/a", "/b"):
            monitor.observe(session, "GET", "http://127.0.0.1:9" + path, 200)
        return ctx, session, refreshes

    def _concurrent_denials(self, feedback):
        ctx, session, refreshes = self._ctx()
        ex = ctx.executor()

        async def go():
            await asyncio.gather(*(feedback(ex, session, "GET", f"http://127.0.0.1:9/{p}", 403)
                                   for p in "abababab"))
        asyncio.run(go())
        return session, refreshes

    def test_concurrent_sends_that_saw_one_stale_window_refresh_once(self):
        session, refreshes = self._concurrent_denials(
            lambda ex, *a: ex._freshness_feedback(*a))
        self.assertEqual(len(refreshes), 1)
        self.assertEqual(session.generation, 1)
        self.assertEqual(session.health, "healthy")

    def test_control_the_former_feedback_refreshes_again(self):
        async def former(ex, session, method, url, status):
            monitor = ex.ctx.freshness()
            if monitor is None or session.health in ("expired", "stale"):
                return
            if monitor.observe(session, method, url, status):
                async with session.health_lock():
                    await ex._session_stale(session, monitor)
        _session, refreshes = self._concurrent_denials(former)
        self.assertGreater(len(refreshes), 1)

    def test_a_send_that_raced_a_refresh_does_not_count_against_the_new_login(self):
        hold = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hold.wait(2)
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        base = f"http://127.0.0.1:{httpd.server_address[1]}"

        def run(refresh_mid_flight):
            hold.clear()
            ctx = RunContext.create(allowed_hosts=["127.0.0.1"], gate_config={"active_enabled": True})
            session = ctx.sessions.register("s1", "alice", {"Authorization": "Bearer T1"},
                                            allowed_origins=[base], name="alice")

            async def go():
                send = asyncio.ensure_future(ctx.executor().execute(
                    TypedRequest("GET", base + "/x"), capability="probe", session_ref="s1"))
                await asyncio.sleep(0.1)
                if refresh_mid_flight:
                    ctx.sessions.replace_headers("s1", {"Authorization": "Bearer T2"})
                hold.set()
                out = await send
                await ctx.aclose()
                return out
            out = asyncio.run(go())
            return out, session
        out, session = run(True)
        self.assertEqual(out.status, 401)
        self.assertEqual((session.auth_failures, session.health), (0, "healthy"))
        out, session = run(False)   # control: the same 401 on current credentials counts
        self.assertEqual(out.status, 401)
        self.assertEqual(session.auth_failures, 1)


# ------------------------------------------------------------------- throughput
def measure(latency=0.05, workers=(1, 2, 4, 8), reads=8, throttle_rps=0):
    server = _LatencyServer(latency)
    try:
        rows = []
        for n in workers:
            before = server.count
            cells, seconds, _ctx, report = _transport_drive(server, workers=n, reads=reads,
                                                            throttle_rps=throttle_rps)
            errors = sum(c["observation_status"] == "error"
                         for c in report["phase_ledger"]["cells"])
            rows.append({"workers": n, "cells": cells, "sends": server.count - before,
                         "error_cells": errors, "seconds": round(seconds, 3),
                         "cells_per_second": round(cells / seconds, 2),
                         "max_in_flight": report.get("drive_pool", {}).get("max_in_flight", 1)})
        return rows
    finally:
        server.close()


class ThroughputTests(unittest.TestCase):
    def test_more_workers_drive_more_cells_per_second_at_the_default_throttle(self):
        rows = {r["workers"]: r for r in measure(latency=0.05, workers=(1, 4), reads=6)}
        self.assertEqual(rows[1]["cells"], rows[4]["cells"])
        self.assertEqual(rows[1]["sends"], rows[4]["sends"])
        self.assertEqual(rows[4]["sends"], 2 * rows[4]["cells"])
        self.assertEqual(rows[4]["error_cells"], 0)
        # 4 identities, one shared cell each in flight: ideally 4x; allow slack.
        self.assertGreater(rows[4]["cells_per_second"], 2.0 * rows[1]["cells_per_second"], rows)

    def test_control_a_global_throttle_bounds_the_pool(self):
        # 2 sends per cell at 20 requests/s caps the drive near 10 cells/s at any
        # worker count once the one-second burst is spent (unthrottled, one worker
        # does about 50 cells/s here).
        rows = {r["workers"]: r for r in measure(latency=0.01, workers=(1, 4), reads=2,
                                                 throttle_rps=20)}
        self.assertEqual(rows[4]["sends"], 2 * rows[4]["cells"])
        self.assertEqual(rows[4]["error_cells"], 0)
        self.assertLess(rows[4]["cells_per_second"], 1.5 * rows[1]["cells_per_second"], rows)


class CallerTests(unittest.TestCase):
    """investigate_engagement with the drive on: the configured worker count reaches
    the drive, and its legs overlap; the default does not."""

    def _investigate(self, workers):
        from harness import test_coverage_replay_dedupe as dedupe
        seen = {"workers": [], "max": 0, "now": 0}
        real = coverage_tracker.build_coverage_driven

        async def drive(state, roles, run_leg, **kwargs):
            seen["workers"].append(kwargs.get("workers", 1))

            async def timed(*args):
                seen["now"] += 1
                seen["max"] = max(seen["max"], seen["now"])
                try:
                    await asyncio.sleep(0.01)
                    return await run_leg(*args)
                finally:
                    seen["now"] -= 1
            return await real(state, roles, timed, **kwargs)

        cfg = {} if workers is None else {"coverage_drive_workers": workers}
        case = dedupe.DriveCallerTests("test_the_drive_replays_a_repeated_capture_once")
        case.setUp() if hasattr(case, "setUp") else None
        try:
            with patch("harness.coverage_tracker.build_coverage_driven", drive):
                result, _calls = case._investigate(
                    [("/api/items/7", {}), ("/api/items/8", {}), ("/api/items/9", {}),
                     ("/api/items/7", {"headers": {}}), ("/api/items/8", {"headers": {}})],
                    engagement_cfg=cfg)
        finally:
            case.doCleanups()
        return result, seen

    def test_the_configured_workers_reach_the_drive_and_overlap(self):
        result, seen = self._investigate(3)
        self.assertEqual(seen["workers"], [3])
        self.assertGreater(seen["max"], 1, seen)
        self.assertEqual(result["coverage"]["drive_pool"]["workers"], 3)

    def test_control_the_default_drives_one_cell_at_a_time(self):
        result, seen = self._investigate(None)
        self.assertEqual(seen["workers"], [1])
        self.assertEqual(seen["max"], 1)
        self.assertNotIn("drive_pool", result["coverage"])

    def test_cell_states_equal_between_one_and_three_workers(self):
        one, _ = self._investigate(None)
        three, _ = self._investigate(3)

        def states(result):
            return {(c["identity"], c["endpoint"], c["check"]): c["observation_status"]
                    for c in result["coverage"]["phase_ledger"]["cells"]}
        self.assertEqual(states(one), states(three))


if __name__ == "__main__":   # the throughput table recorded in HANDOFF.md
    import json
    print(json.dumps({"default_throttle_latency_50ms": measure(latency=0.05),
                      "throttle_20rps_latency_10ms": measure(latency=0.01, reads=2,
                                                             throttle_rps=20)}, indent=1))
