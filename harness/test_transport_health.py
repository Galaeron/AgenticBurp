"""E5a -- session health, the deterministic-5xx route circuit, request attribution.

Everything runs through the real run Executor (RunContext.executor()) against a
127.0.0.1 ThreadingHTTPServer that counts, server-side, what actually reached it.
Each behaviour has a negative control, and a sabotage test proves the control is
able to fail: with the new logic replaced by a broken variant, the control
scenario reports the violation.
"""
from __future__ import annotations

import asyncio
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from harness import evidence_ledger, run_context
from harness.run_context import ExecutionOutcome, RunContext, TargetTransport, TransportHealth

EXPIRED_EVENT = ("session alice expired: its credentials were rejected by the health probe; "
                 "refresh or re-authenticate this identity to resume its tests")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        srv = self.server
        path = self.path.split("?", 1)[0]
        auth = self.headers.get("Authorization")
        with srv.lock:
            srv.received.append((path, auth))
            status, text = srv.respond(path, auth, srv)
        data = text.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _Target:
    """`respond(path, authorization, server) -> (status, body)` decides every answer."""

    def __init__(self, respond):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.received = []
        self.httpd.lock = threading.Lock()
        self.httpd.respond = respond
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def count(self, path=None) -> int:
        with self.httpd.lock:
            return sum(1 for p, _ in self.httpd.received if path is None or p == path)

    def auths(self, path) -> list:
        with self.httpd.lock:
            return [a for p, a in self.httpd.received if p == path]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._t.join(5)


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _ctx(**kw):
    kw.setdefault("allowed_hosts", ["127.0.0.1"])
    kw.setdefault("gate_config", {"active_enabled": True, "allow_mutating_replay": True})
    return RunContext.create(**kw)


def _expiring_target(limit=2):
    """T1 is accepted for `limit` requests (any path), then rejected; T2 always works."""
    served = {"t1": 0}

    def respond(path, auth, srv):
        if auth == "Bearer T2":
            return 200, "ok"
        if auth == "Bearer T1" and served["t1"] < limit:
            served["t1"] += 1
            return 200, "ok"
        return 401, "unauthorized"
    return _Target(respond)


async def _get(ex, base, path, *, session="s1", capability="probe", case_ref=""):
    return await ex.execute(run_context.TypedRequest("GET", base + path), capability=capability,
                            session_ref=session, case_ref=case_ref)


class SessionExpiryTests(unittest.TestCase):
    def setUp(self):
        self.srv = _expiring_target(limit=2)
        self.addCleanup(self.srv.close)

    def _session(self, ctx, probe=True, name="alice"):
        ctx.sessions.register("s1", "alice", {"Authorization": "Bearer T1"},
                              allowed_origins=[self.srv.base], name=name)
        if probe:
            ctx.sessions.register_health_probe("s1", "GET", self.srv.base + "/whoami")
        return ctx.sessions.get("s1")

    def test_probe_failure_refreshes_and_later_sends_use_the_new_token(self):
        ctx, refreshed = _ctx(), []

        async def refresh():
            refreshed.append(1)
            return {"Authorization": "Bearer T2"}

        session = self._session(ctx)
        ctx.sessions.set_refresh("s1", refresh)

        async def go():
            ex = ctx.executor()
            first = [await _get(ex, self.srv.base, "/data") for _ in range(2)]
            third = await _get(ex, self.srv.base, "/data")      # T1 now rejected
            after = await _get(ex, self.srv.base, "/data")
            await ctx.aclose()
            return first, third, after

        first, third, after = asyncio.run(go())
        self.assertEqual([o.status for o in first], [200, 200])
        self.assertEqual((third.outcome, third.status), ("ok", 401))   # caller's outcome unchanged
        self.assertEqual(self.srv.count("/whoami"), 1)                 # exactly one probe
        self.assertEqual(len(refreshed), 1)                            # exactly one refresh
        self.assertEqual((session.generation, session.health), (1, "healthy"))
        self.assertEqual((after.outcome, after.status), ("ok", 200))
        self.assertEqual(self.srv.auths("/data")[-1], "Bearer T2")
        self.assertEqual(ctx.budget.by_label.get("session_health"), 1)
        self.assertEqual(ctx.health.events(), [])                      # a recovery is not an event

    def test_probe_failure_without_a_refresh_expires_the_session_unsent(self):
        ctx = _ctx()
        session = self._session(ctx)

        async def go():
            ex = ctx.executor()
            for _ in range(3):
                await _get(ex, self.srv.base, "/data")                 # the third is the 401
            reached = self.srv.count()
            refused = [await _get(ex, self.srv.base, "/data") for _ in range(3)]
            await ctx.aclose()
            return reached, refused

        reached, refused = asyncio.run(go())
        self.assertEqual(session.health, "expired")
        for out in refused:
            self.assertEqual(out.outcome, "session_expired")
            self.assertFalse(out.ok)
            self.assertFalse(out.executed)
            self.assertIn("refresh or re-authenticate", out.error)
        self.assertEqual(self.srv.count(), reached)                    # none reached the server
        events = ctx.health.events()
        self.assertEqual([e["message"] for e in events], [EXPIRED_EVENT])   # exactly one
        report = ctx.health_report()
        self.assertEqual(report["sessions"][0]["health"], "expired")
        self.assertEqual(report["events"][0]["kind"], "session_expired")

    def test_refresh_attempts_are_limited_then_the_session_expires(self):
        ctx = _ctx(config={"transport": {"max_session_refreshes": 2}})
        session = self._session(ctx)
        calls = []

        async def failing_refresh():
            calls.append(1)
            return None

        ctx.sessions.set_refresh("s1", failing_refresh)

        async def go():
            ex = ctx.executor()
            for _ in range(2):
                await _get(ex, self.srv.base, "/data")
            for _ in range(4):                  # every 401 re-checks until refreshes run out
                await _get(ex, self.srv.base, "/data")
            await ctx.aclose()

        asyncio.run(go())
        self.assertEqual(len(calls), 2)
        self.assertEqual(session.health, "expired")
        self.assertEqual(len(ctx.health.events()), 1)

    def test_probe_from_config_needs_no_registration(self):
        ctx = _ctx(config={"transport": {"session_probe": {"path": "/whoami"}}})
        session = self._session(ctx, probe=False)

        async def go():
            ex = ctx.executor()
            for _ in range(3):
                await _get(ex, self.srv.base, "/data")
            await ctx.aclose()

        asyncio.run(go())
        self.assertEqual(self.srv.count("/whoami"), 1)
        self.assertEqual(session.health, "expired")


def _route_specific_401():
    """Control scenario: /admin refuses this user (401) while the probe says the
    session is fine. Returns what a correct transport must show."""
    srv = _Target(lambda path, auth, s: (401, "no") if path == "/admin" else (200, "ok"))
    ctx = _ctx()
    ctx.sessions.register("s1", "alice", {"Authorization": "Bearer T1"},
                          allowed_origins=[srv.base], name="alice")
    ctx.sessions.register_health_probe("s1", "GET", srv.base + "/whoami")
    clock = _Clock()

    async def go():
        ex = ctx.executor()
        outs = [await _get(ex, srv.base, "/data"), await _get(ex, srv.base, "/admin"),
                await _get(ex, srv.base, "/data"), await _get(ex, srv.base, "/admin")]
        probes_in_window = srv.count("/whoami")
        clock.now += 31                                 # the recheck window has passed
        outs.append(await _get(ex, srv.base, "/admin"))
        outs.append(await _get(ex, srv.base, "/data"))
        await ctx.aclose()
        return outs, probes_in_window

    try:
        with patch.object(run_context, "_clock", clock):
            outs, probes_in_window = asyncio.run(go())
        return {"statuses": [o.status for o in outs], "health": ctx.sessions.get("s1").health,
                "probes_in_window": probes_in_window, "probes": srv.count("/whoami"),
                "failures": ctx.sessions.get("s1").auth_failures, "events": ctx.health.events()}
    finally:
        srv.close()


class RouteSpecific401Tests(unittest.TestCase):
    def test_a_route_that_refuses_this_user_does_not_expire_the_session(self):
        seen = _route_specific_401()
        self.assertEqual(seen["statuses"], [200, 401, 200, 401, 401, 200])   # sends continued
        self.assertEqual(seen["health"], "healthy")
        self.assertEqual(seen["events"], [])
        self.assertEqual(seen["failures"], 3)
        self.assertEqual(seen["probes_in_window"], 1)       # the second 401 reused the check
        self.assertEqual(seen["probes"], 2)                 # re-probed once the window passed

    def test_control_can_fail_when_the_probe_verdict_is_forced_to_rejected(self):
        # Sabotage: a transport that reads "route refused" as "session dead".
        async def always_rejected(self, session, probe):
            return "rejected"
        with patch.object(TargetTransport, "_run_health_probe", always_rejected):
            seen = _route_specific_401()
        self.assertEqual(seen["health"], "expired")         # the control above would have failed
        self.assertTrue(seen["events"])


class NoProbeTests(unittest.TestCase):
    def test_a_session_without_a_probe_costs_no_extra_requests_and_never_expires(self):
        srv = _Target(lambda path, auth, s: (401, "no"))
        self.addCleanup(srv.close)
        ctx = _ctx()
        session = ctx.sessions.register("s1", "alice", {"Authorization": "Bearer T1"},
                                        allowed_origins=[srv.base])
        calls = 7

        async def go():
            ex = ctx.executor()
            outs = [await _get(ex, srv.base, f"/p{i}") for i in range(calls)]
            await ctx.aclose()
            return outs

        outs = asyncio.run(go())
        self.assertEqual(srv.count(), calls)                       # nothing but the callers' sends
        self.assertTrue(all(o.outcome == "ok" and o.status == 401 for o in outs))
        self.assertEqual((session.health, session.auth_failures), ("suspect", calls))
        self.assertEqual(ctx.health.events(), [])
        self.assertNotIn("session_health", ctx.budget.by_label)

    def test_a_later_accepted_send_clears_the_suspicion(self):
        srv = _Target(lambda path, auth, s: (401, "no") if path == "/denied" else (200, "ok"))
        self.addCleanup(srv.close)
        ctx = _ctx()
        session = ctx.sessions.register("s1", "alice", {"Authorization": "Bearer T1"},
                                        allowed_origins=[srv.base])

        async def go():
            ex = ctx.executor()
            await _get(ex, srv.base, "/denied")
            suspect = session.health
            await _get(ex, srv.base, "/fine")
            await ctx.aclose()
            return suspect

        self.assertEqual(asyncio.run(go()), "suspect")
        self.assertEqual(session.health, "healthy")
        self.assertGreater(session.last_ok_at, 0)

    def test_control_can_fail_when_a_probe_is_assumed(self):
        # Sabotage: a transport that invents a probe for every session would add requests.
        srv = _Target(lambda path, auth, s: (401, "no"))
        self.addCleanup(srv.close)
        ctx = _ctx()
        ctx.sessions.register("s1", "alice", {"Authorization": "Bearer T1"},
                              allowed_origins=[srv.base])
        invented = run_context.HealthProbe("GET", srv.base + "/whoami", (200,))

        async def go():
            ex = ctx.executor()
            await _get(ex, srv.base, "/p")
            await ctx.aclose()

        with patch.object(TargetTransport, "_probe_for", lambda self, session, url: invented):
            asyncio.run(go())
        self.assertGreater(srv.count(), 1)       # the "equal to calls" assertion would fail


class RouteCircuitTests(unittest.TestCase):
    def _drive(self, srv, paths, ctx=None):
        ctx = ctx or _ctx()

        async def go():
            ex = ctx.executor()
            outs = [await ex.execute(run_context.TypedRequest("GET", srv.base + p),
                                     capability="probe") for p in paths]
            await ctx.aclose()
            return outs
        return ctx, asyncio.run(go())

    def test_a_route_that_only_ever_answers_5xx_is_paused_after_the_threshold(self):
        srv = _Target(lambda path, auth, s: (500, "boom"))
        self.addCleanup(srv.close)
        ctx, outs = self._drive(srv, ["/broken"] * 12)
        self.assertEqual([o.outcome for o in outs], ["ok"] * 8 + ["route_unavailable"] * 4)
        self.assertEqual(srv.count("/broken"), 8)                  # the 9th never reached it
        for out in outs[8:]:
            self.assertFalse(out.ok)
            self.assertFalse(out.executed)
            self.assertIsNone(out.status)
        self.assertEqual([e["message"] for e in ctx.health.events()],
                         ["route GET /broken returned 5xx on all 8 requests; further probes skipped"])
        self.assertEqual([r["route"] for r in ctx.health_report()["routes_paused"]],
                         ["GET /broken"])

    def test_id_segments_share_one_route_template(self):
        srv = _Target(lambda path, auth, s: (500, "boom"))
        self.addCleanup(srv.close)
        ctx, outs = self._drive(srv, [f"/items/{n}" for n in range(1, 11)])
        self.assertEqual(outs[8].outcome, "route_unavailable")
        self.assertEqual(srv.count(), 8)
        self.assertIn("GET /items/{id}", ctx.health.events()[0]["message"])

    def test_payload_induced_5xx_on_a_route_that_answers_is_never_paused(self):
        # Control: /ok answers once, then 500s to every payload -- 21 sends, all of them go.
        state = {"n": 0}

        def respond(path, auth, s):
            state["n"] += 1
            return (200, "fine") if state["n"] == 1 else (500, "boom")
        srv = _Target(respond)
        self.addCleanup(srv.close)
        ctx, outs = self._drive(srv, ["/ok"] * 21)
        self.assertEqual(srv.count("/ok"), 21)
        self.assertTrue(all(o.outcome == "ok" for o in outs))
        self.assertEqual(ctx.health.events(), [])
        self.assertEqual(ctx.health_report()["routes_paused"], [])

    def test_control_can_fail_when_the_never_answered_guard_is_removed(self):
        # Sabotage: count 5xx per route without remembering a non-5xx ever happened.
        def naive(self, key, status, threshold):
            state = self._routes.setdefault(key, run_context._RouteState())
            if status >= 500:
                state.errors_5xx += 1
                if state.errors_5xx >= threshold:
                    state.open, state.opened_at = True, run_context._clock()
        state = {"n": 0}

        def respond(path, auth, s):
            state["n"] += 1
            return (200, "fine") if state["n"] == 1 else (500, "boom")
        srv = _Target(respond)
        self.addCleanup(srv.close)
        with patch.object(TransportHealth, "route_observed", naive):
            _, outs = self._drive(srv, ["/ok"] * 21)
        self.assertIn("route_unavailable", [o.outcome for o in outs])   # the control would fail

    def test_after_the_cooldown_one_probe_goes_out_and_a_non_5xx_closes_it_for_good(self):
        mode = {"fixed": False}
        srv = _Target(lambda path, auth, s: (200, "fixed") if mode["fixed"] else (500, "boom"))
        self.addCleanup(srv.close)
        ctx, clock = _ctx(), _Clock()

        async def go():
            ex = ctx.executor()
            send = lambda: ex.execute(run_context.TypedRequest("GET", srv.base + "/broken"),
                                      capability="probe")
            outs = {"opened": [(await send()).outcome for _ in range(9)]}
            clock.now += 299
            outs["before_cooldown"] = (await send()).outcome
            clock.now += 2                                            # 301 s since it opened
            outs["half_open"] = (await send()).outcome                # still 5xx: stays open
            outs["right_after"] = (await send()).outcome              # cooldown restarted
            mode["fixed"] = True
            clock.now += 301
            outs["recovering"] = (await send()).status                # the probe: a 200
            outs["closed"] = [(await send()).status for _ in range(3)]
            await ctx.aclose()
            return outs

        with patch.object(run_context, "_clock", clock):
            outs = asyncio.run(go())
        self.assertEqual(outs["opened"], ["ok"] * 8 + ["route_unavailable"])
        self.assertEqual(outs["before_cooldown"], "route_unavailable")
        self.assertEqual(outs["half_open"], "ok")
        self.assertEqual(outs["right_after"], "route_unavailable")
        self.assertEqual(outs["recovering"], 200)
        self.assertEqual(outs["closed"], [200, 200, 200])
        self.assertEqual(srv.count("/broken"), 8 + 1 + 1 + 3)        # 8, one half-open, the fix, 3 more
        self.assertEqual(len(ctx.health.events()), 1)                # still the single event

    def test_threshold_and_cooldown_are_configurable(self):
        srv = _Target(lambda path, auth, s: (503, "down"))
        self.addCleanup(srv.close)
        ctx, outs = self._drive(srv, ["/x"] * 4,
                                ctx=_ctx(config={"transport": {"route_5xx_threshold": 2}}))
        self.assertEqual([o.outcome for o in outs],
                         ["ok", "ok", "route_unavailable", "route_unavailable"])


class RoutePerIdentityTests(unittest.TestCase):
    """A route that answers 5xx to anonymous but 200 to alice is paused for
    anonymous only (review of E5a): alice's IDOR leg still reaches it."""

    def _run(self):
        srv = _Target(lambda path, auth, s: (200, "mine") if auth == "Bearer A" else (500, "boom"))
        self.addCleanup(srv.close)
        ctx = _ctx()

        async def go():
            ctx.sessions.register("s1", "alice", headers={"Authorization": "Bearer A"},
                                  allowed_origins=[srv.base])
            ex = ctx.executor()
            anon = [(await ex.execute(run_context.TypedRequest("GET", srv.base + f"/api/users/{i}"),
                                      capability="probe")).outcome for i in range(9)]
            alice = (await _get(ex, srv.base, "/api/users/9")).outcome
            await ctx.aclose()
            return anon, alice
        return srv, asyncio.run(go())

    def _check(self):
        srv, (anon, alice) = self._run()
        self.assertEqual(anon[-1], "route_unavailable")
        self.assertEqual(alice, "ok")
        self.assertEqual(srv.auths("/api/users/9"), ["Bearer A"])

    def test_anonymous_5xx_does_not_pause_the_route_for_alice(self):
        self._check()

    def test_control_one_circuit_for_every_identity_pauses_alice_too(self):
        with patch.object(TransportHealth, "route_key_for",
                          staticmethod(lambda m, u, s: TransportHealth.route_key(m, u))):
            with self.assertRaises(AssertionError):
                self._check()


class AttributionTests(unittest.TestCase):
    def test_budget_counts_per_capability_and_matches_the_total(self):
        srv = _Target(lambda path, auth, s: (200, "ok"))
        self.addCleanup(srv.close)
        ctx = _ctx(max_requests=7)

        async def go():
            ex = ctx.executor()
            for capability, n in (("alpha", 3), ("beta", 2), ("gamma", 1)):
                for _ in range(n):
                    await ex.execute(run_context.TypedRequest("GET", srv.base + "/a"),
                                     capability=capability)
            assert ctx.budget.reserve(1)                       # an unlabelled caller still works
            denied = await ex.execute(run_context.TypedRequest("GET", srv.base + "/a"),
                                      capability="alpha")      # the 8th is over the ceiling
            await ctx.aclose()
            return denied

        denied = asyncio.run(go())
        self.assertEqual(denied.outcome, "budget_exhausted")
        self.assertEqual(ctx.budget.by_label, {"alpha": 3, "beta": 2, "gamma": 1, "unlabelled": 1})
        self.assertEqual(sum(ctx.budget.by_label.values()), ctx.budget.used)
        self.assertEqual(srv.count(), 6)
        self.assertEqual(ctx.health_report()["budget_by_label"], ctx.budget.by_label)

    def test_a_driver_child_budget_forwards_the_label_to_the_run(self):
        from harness.orchestrator_chain import _driver_scope
        srv = _Target(lambda path, auth, s: (200, "ok"))
        self.addCleanup(srv.close)
        ctx = _ctx(max_requests=50)

        async def go():
            async with _driver_scope(ctx, 5) as child:
                await child.executor().execute(
                    run_context.TypedRequest("GET", srv.base + "/a"), capability="driver_leg")
            await ctx.aclose()

        asyncio.run(go())
        self.assertEqual(ctx.budget.by_label, {"driver_leg": 1})

    def test_ok_execution_events_carry_capability_elapsed_and_bytes(self):
        srv = _Target(lambda path, auth, s: (200, "twelve bytes"))
        self.addCleanup(srv.close)
        ctx = _ctx()
        evidence_ledger.reset_default_ledger()

        async def go():
            out = await ctx.executor().execute(
                run_context.TypedRequest("GET", srv.base + "/a"), capability="recon_x",
                case_ref="E5A-CASE")
            await ctx.aclose()
            return out

        with patch("harness.store.persist_ledger_event"), \
                patch("harness.store.put_evidence_blob", return_value="blob"):
            out = asyncio.run(go())
        self.assertTrue(out.ok)
        events = [e for e in evidence_ledger.get_default_ledger().events_for("E5A-CASE")
                  if e.event_type == evidence_ledger.EventType.EXECUTION]
        self.assertEqual(len(events), 1)
        data = events[0].data
        self.assertEqual((data["capability"], data["bytes"]), ("recon_x", 12))
        self.assertGreaterEqual(data["elapsed_ms"], 0)

    def test_the_health_probe_is_not_recorded_under_the_callers_case(self):
        srv = _expiring_target(limit=1)
        self.addCleanup(srv.close)
        ctx = _ctx()
        ctx.sessions.register("s1", "alice", {"Authorization": "Bearer T1"},
                              allowed_origins=[srv.base])
        ctx.sessions.register_health_probe("s1", "GET", srv.base + "/whoami")
        evidence_ledger.reset_default_ledger()

        async def go():
            ex = ctx.executor()
            for _ in range(2):
                await _get(ex, srv.base, "/data", case_ref="E5A-CASE")
            await ctx.aclose()

        with patch("harness.store.persist_ledger_event"), \
                patch("harness.store.put_evidence_blob", return_value="blob"):
            asyncio.run(go())
        urls = [e.data.get("request", "") for e in
                evidence_ledger.get_default_ledger().events_for("E5A-CASE")]
        self.assertTrue(any("/data" in u for u in urls))
        self.assertFalse(any("/whoami" in u for u in urls))        # the probe belongs to no case
        self.assertEqual(srv.count("/whoami"), 1)


class NotSentOutcomeTests(unittest.TestCase):
    def test_new_outcomes_are_never_ok_or_executed(self):
        for outcome in ("session_expired", "route_unavailable"):
            out = ExecutionOutcome(outcome=outcome)
            self.assertFalse(out.ok)
            self.assertFalse(out.executed)

    def test_the_tool_proxy_ends_a_scan_on_a_paused_route_instead_of_answering_403(self):
        import httpx
        from harness.tool_proxy import ToolProxy
        srv = _Target(lambda path, auth, s: (500, "boom") if path == "/broken" else (200, "ok"))
        self.addCleanup(srv.close)
        ctx = _ctx()

        async def go():
            async with ToolProxy(ctx, srv.base + "/", capability="sqlmap_tool") as proxy:
                async with httpx.AsyncClient(trust_env=False) as client:
                    # Control: an answering route never stops the tool.
                    await client.get(proxy.url_for(srv.base + "/ok"))
                    stopped_by_ok = proxy.stop_requested
                    statuses = [(await client.get(proxy.url_for(srv.base + "/broken"))).status_code
                                for _ in range(9)]
                    result = (stopped_by_ok, statuses, proxy.stop_requested, proxy.stop_reason)
            await ctx.aclose()
            return result

        stopped_by_ok, statuses, stopped, reason = asyncio.run(go())
        self.assertFalse(stopped_by_ok)
        self.assertEqual(statuses, [500] * 8 + [503])        # relayed, then the run's refusal
        self.assertTrue(stopped)
        self.assertEqual(reason, "route_unavailable")
        self.assertEqual(srv.count("/broken"), 8)


if __name__ == "__main__":
    unittest.main()
