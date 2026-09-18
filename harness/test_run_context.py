"""Tests for Astra T03 -- run-scoped policy executor + scoped transport.

Uses a REAL loopback HTTP fixture (not a transport mock) so the assertions are on
what the target actually received: cookies never cross sessions, an off-scope
redirect is blocked before the destination is contacted, credentials are not
forwarded across an origin boundary, budget/cancel stop dispatch, and a gate denial
produces blocked evidence with no send.
"""
from __future__ import annotations

import asyncio
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harness.run_context import RunContext, ScopePolicy, TypedRequest
from harness.safety_gate import get_default_gate, reset_default_gate


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep test output clean
        pass

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.server.received.append({
            "path": self.path.split("?", 1)[0], "method": self.command,
            "authorization": self.headers.get("Authorization"),
            "cookie": self.headers.get("Cookie"),
            "body": self.rfile.read(length).decode("utf-8", "replace") if length else "",
        })

    def _reply(self, status, body=b"", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self._record()
        path = self.path.split("?", 1)[0]
        if path == "/set-cookie":
            self._reply(200, b"ok", {"Set-Cookie": "sess=SERVERVAL; Path=/"})
        elif path == "/redirect":
            self._reply(302, b"", {"Location": self.server.redirect_location})
        else:
            self._reply(200, b"OK-BODY-1234567890")

    def do_POST(self):
        self._record()
        if self.path.split("?", 1)[0] == "/redirect":
            self._reply(self.server.redirect_status, b"", {"Location": self.server.redirect_location})
        else:
            self._reply(200, b"posted")

    def do_PUT(self):
        self._record()
        self._reply(200, b"updated")


class _Fixture:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.received = []
        self.httpd.redirect_location = ""
        self.httpd.redirect_status = 302
        self.port = self.httpd.server_address[1]
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def paths(self):
        return [r["path"] for r in self.httpd.received]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _ctx(**over):
    kw = dict(allowed_hosts=["127.0.0.1"], gate_config={"active_enabled": True, "allow_mutating_replay": True})
    kw.update(over)
    return RunContext.create(**kw)


class ScopeAndIsolationTests(unittest.TestCase):
    def test_two_contexts_do_not_contaminate(self):
        c1 = RunContext.create(allowed_hosts=["a.test"], max_requests=1)
        c2 = RunContext.create(allowed_hosts=["b.test"], max_requests=9)
        self.assertTrue(c1.scope.in_scope("http://a.test/x"))
        self.assertFalse(c2.scope.in_scope("http://a.test/x"))   # c2 scope is independent
        self.assertIsNot(c1.gate, c2.gate)                        # per-run gate (the #3 fix)
        self.assertIsNot(c1.budget, c2.budget)
        c1.budget.reserve(1)
        self.assertEqual(c1.budget.used, 1)
        self.assertEqual(c2.budget.used, 0)                      # budgets are not shared

    def test_configuration_and_cache_namespace_are_invocation_local(self):
        source = {"runs": {"cache_namespace": "run-a"}, "nested": {"limit": 2}}
        c1 = RunContext.create(run_id="a", allowed_hosts=["a.test"], config=source)
        source["runs"]["cache_namespace"] = "mutated"
        source["nested"]["limit"] = 99
        c2 = RunContext.create(run_id="b", allowed_hosts=["b.test"], config=source)
        self.assertEqual(c1.config["nested"]["limit"], 2)
        self.assertEqual(c1.cache_namespace, "run-a:a")
        self.assertEqual(c2.config["nested"]["limit"], 99)
        self.assertEqual(c2.cache_namespace, "mutated:b")
        self.assertIsNot(c1.config, c2.config)

    def test_scope_fails_closed_on_empty_allowlist(self):
        empty = ScopePolicy()
        self.assertFalse(empty.in_scope("http://anything.test/"))

    def test_origin_normalizes_default_ports_but_not_distinct_ports(self):
        self.assertEqual(ScopePolicy.origin_of("http://A.test/x"),
                         ScopePolicy.origin_of("http://a.test:80/y"))
        self.assertEqual(ScopePolicy.origin_of("https://a.test/x"),
                         ScopePolicy.origin_of("https://a.test:443/y"))
        self.assertNotEqual(ScopePolicy.origin_of("https://a.test/x"),
                            ScopePolicy.origin_of("https://a.test:444/y"))

    def test_out_of_scope_request_is_never_sent(self):
        ctx = _ctx()

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", "http://evil.example/secret"), capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertFalse(out.executed)
        self.assertEqual(out.artifact.transport_outcome, "out_of_scope")


class GateBudgetCancelTests(unittest.TestCase):
    def setUp(self):
        self.srv = _Fixture()

    def tearDown(self):
        self.srv.close()

    def test_gate_denial_blocks_and_records_no_send(self):
        # active_enabled False -> a mutating POST must be denied by the gate.
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], gate_config={"active_enabled": False})

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("POST", f"{self.srv.base}/thing", body="x=1"), capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "blocked")
        self.assertEqual(out.artifact.transport_outcome, "blocked")
        self.assertNotIn("/thing", self.srv.paths())   # target never received the POST

    def test_budget_exhausted_stops_dispatch(self):
        ctx = _ctx(max_requests=1)

        async def scenario():
            a = await ctx.executor().execute(TypedRequest("GET", f"{self.srv.base}/one"), capability="probe")
            b = await ctx.executor().execute(TypedRequest("GET", f"{self.srv.base}/two"), capability="probe")
            await ctx.aclose()
            return a, b

        a, b = asyncio.run(scenario())
        self.assertEqual(a.outcome, "ok")
        self.assertEqual(b.outcome, "budget_exhausted")
        self.assertIn("/one", self.srv.paths())
        self.assertNotIn("/two", self.srv.paths())     # second send never happened

    def test_cancel_stops_dispatch(self):
        ctx = _ctx()
        ctx.cancel.cancel()

        async def scenario():
            out = await ctx.executor().execute(TypedRequest("GET", f"{self.srv.base}/x"), capability="probe")
            await ctx.aclose()
            return out

        self.assertEqual(asyncio.run(scenario()).outcome, "cancelled")
        self.assertEqual(self.srv.paths(), [])

    def test_unknown_session_reference_is_rejected_without_send(self):
        ctx = _ctx()

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", f"{self.srv.base}/unknown"), capability="probe",
                session_ref="missing")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "unknown_session")
        self.assertFalse(out.executed)
        self.assertEqual(self.srv.paths(), [])

    def test_credentials_without_session_are_rejected(self):
        ctx = _ctx()

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", f"{self.srv.base}/leak",
                             headers={"Authorization": "Bearer SECRET"}),
                capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "blocked")
        self.assertEqual(self.srv.paths(), [])


class AmbientGateAcrossInvocationsTests(unittest.TestCase):
    """2026-09-17 coverage-recovery plan, Step 1, at the production seam: a
    RunContext installs ITS gate as the ambient default (safety_gate.get_default_gate)
    for its whole lifetime, so a validator with no run_context wiring at its own send
    site -- CSRF's `GatedAsyncClient(get_default_gate(), ...)`, SQLMap's
    `get_default_gate()` fallback -- still sees THIS run's policy, not a stale gate
    left by an earlier, unrelated run (or none at all)."""

    def setUp(self):
        self.srv = _Fixture()
        reset_default_gate()

    def tearDown(self):
        self.srv.close()
        reset_default_gate()

    def test_active_run_makes_bare_get_default_gate_calls_see_its_policy(self):
        # A prior, unrelated safe/default call (e.g. a standalone script) first.
        reset_default_gate()
        get_default_gate({"active_enabled": False})

        async def scenario():
            # `async with` (not bare create()+aclose()) is what installs the
            # ambient gate -- exactly how server.py's job/probe endpoints use a
            # RunContext for the duration of the actual work.
            async with RunContext.create(
                    allowed_hosts=["127.0.0.1"],
                    gate_config={"active_enabled": True, "allow_mutating_replay": True}):
                # No run_context passed to authorize() -- this is exactly CSRF/
                # SQLMap's own fallback expression when they have no run_context.
                return get_default_gate().authorize(
                    validator_name="csrf", method="POST", url=f"{self.srv.base}/register")

        decision = asyncio.run(scenario())
        self.assertTrue(decision.allowed, decision.reason)

    def test_later_safe_run_is_not_contaminated_by_an_earlier_active_one(self):
        async def scenario():
            async with RunContext.create(
                    allowed_hosts=["127.0.0.1"],
                    gate_config={"active_enabled": True, "allow_mutating_replay": True}):
                pass  # active run does its work and closes

            async with RunContext.create(allowed_hosts=["127.0.0.1"],
                                         gate_config={"active_enabled": False}):
                return get_default_gate().authorize(
                    validator_name="sqlmap", method="POST", url=f"{self.srv.base}/login")

        decision = asyncio.run(scenario())
        self.assertFalse(decision.allowed)

    def test_active_run_without_allow_mutating_replay_still_blocks_the_send(self):
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"],
                                gate_config={"active_enabled": True, "allow_mutating_replay": False})

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("POST", f"{self.srv.base}/login", body="u=1"), capability="sqlmap")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "blocked")
        self.assertNotIn("/login", self.srv.paths())

    def test_off_scope_target_denied_even_inside_an_active_run(self):
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"],
                                gate_config={"active_enabled": True, "allow_mutating_replay": True})

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("POST", "http://evil.example/login", body="u=1"), capability="sqlmap")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertEqual(self.srv.paths(), [])

    def test_closing_a_run_restores_the_ambient_gate_that_preceded_it(self):
        outer_default = get_default_gate({"active_enabled": False})

        async def scenario():
            ctx = RunContext.create(allowed_hosts=["127.0.0.1"], gate_config={"active_enabled": True})
            async with ctx:
                self.assertIs(get_default_gate(), ctx.gate)
            return get_default_gate()

        after_close = asyncio.run(scenario())
        self.assertIs(after_close, outer_default)

    def test_bare_create_and_manual_aclose_do_not_touch_the_ambient_gate(self):
        # No `async with` -- __aenter__ never runs, so this must be a complete
        # no-op for the ambient scope (unchanged from before this fix), which is
        # what keeps the ~70 existing tests that construct a RunContext directly
        # and never close it safe from leaking a gate into unrelated tests.
        outer_default = get_default_gate({"active_enabled": False})
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], gate_config={"active_enabled": True})
        self.assertIs(get_default_gate(), outer_default)

        async def scenario():
            await ctx.aclose()  # must not raise even though __aenter__ never ran

        asyncio.run(scenario())
        self.assertIs(get_default_gate(), outer_default)


class CookieAndRedirectTests(unittest.TestCase):
    def setUp(self):
        self.srv = _Fixture()

    def tearDown(self):
        self.srv.close()

    def test_cookies_do_not_cross_sessions(self):
        ctx = _ctx()
        ctx.sessions.register("s1", "alice", allowed_origins=[self.srv.base])
        ctx.sessions.register("s2", "bob", allowed_origins=[self.srv.base])

        async def scenario():
            ex = ctx.executor()
            await ex.execute(TypedRequest("GET", f"{self.srv.base}/set-cookie"), capability="probe", session_ref="s1")
            await ex.execute(TypedRequest("GET", f"{self.srv.base}/collect"), capability="probe", session_ref="s1")
            await ex.execute(TypedRequest("GET", f"{self.srv.base}/collect"), capability="probe", session_ref="s2")
            await ctx.aclose()

        asyncio.run(scenario())
        collects = [r for r in self.srv.httpd.received if r["path"] == "/collect"]
        self.assertEqual(len(collects), 2)
        s1_collect, s2_collect = collects[0], collects[1]
        self.assertIn("sess=SERVERVAL", s1_collect["cookie"] or "")   # s1 carried its cookie back
        self.assertIsNone(s2_collect["cookie"])                        # s2's jar is isolated

    def test_off_scope_redirect_blocked_before_destination(self):
        # allowed host is 127.0.0.1; the redirect points at "localhost" (a different
        # host string) on the SAME fixture -> must be blocked before it is contacted.
        self.srv.httpd.redirect_location = f"http://localhost:{self.srv.port}/secret"
        ctx = _ctx()

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", f"{self.srv.base}/redirect"), capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertIn("/redirect", self.srv.paths())
        self.assertNotIn("/secret", self.srv.paths())   # destination never contacted

    def test_credentials_not_forwarded_across_origin(self):
        # Two origins on the same host (different port) -> both in scope by host, but
        # cross-origin, so the session's Authorization must NOT reach the second.
        other = _Fixture()
        try:
            self.srv.httpd.redirect_location = f"http://127.0.0.1:{other.port}/collect"
            ctx = _ctx()
            ctx.sessions.register("s1", "alice", headers={"Authorization": "Bearer SECRET"},
                                  allowed_origins=[self.srv.base])

            async def scenario():
                await ctx.executor().execute(
                    TypedRequest("GET", f"{self.srv.base}/redirect"), capability="probe", session_ref="s1")
                await ctx.aclose()

            asyncio.run(scenario())
            first = self.srv.httpd.received[0]
            collected = [r for r in other.httpd.received if r["path"] == "/collect"]
            self.assertEqual(first["authorization"], "Bearer SECRET")   # own origin: creds sent
            self.assertEqual(len(collected), 1)
            self.assertIsNone(collected[0]["authorization"])            # cross-origin: creds stripped
        finally:
            other.close()

    def test_cookie_jar_not_used_on_unauthorized_redirect_origin(self):
        other = _Fixture()
        try:
            self.srv.httpd.redirect_location = f"http://127.0.0.1:{other.port}/collect"
            ctx = _ctx()
            ctx.sessions.register("s1", "alice", allowed_origins=[self.srv.base])

            async def scenario():
                ex = ctx.executor()
                await ex.execute(TypedRequest("GET", f"{self.srv.base}/set-cookie"),
                                 capability="probe", session_ref="s1")
                out = await ex.execute(TypedRequest("GET", f"{self.srv.base}/redirect"),
                                       capability="probe", session_ref="s1")
                await ctx.aclose()
                return out

            self.assertEqual(asyncio.run(scenario()).outcome, "ok")
            collected = [r for r in other.httpd.received if r["path"] == "/collect"]
            self.assertEqual(len(collected), 1)
            self.assertIsNone(collected[0]["cookie"])
        finally:
            other.close()

    def test_session_cannot_be_started_on_different_allowed_origin(self):
        other = _Fixture()
        try:
            ctx = _ctx()
            ctx.sessions.register("s1", "alice", headers={"Authorization": "Bearer SECRET"},
                                  allowed_origins=[self.srv.base])

            async def scenario():
                out = await ctx.executor().execute(
                    TypedRequest("GET", f"{other.base}/collect"), capability="probe",
                    session_ref="s1")
                await ctx.aclose()
                return out

            out = asyncio.run(scenario())
            self.assertEqual(out.outcome, "blocked")
            self.assertEqual(other.paths(), [])
        finally:
            other.close()

    def test_cross_origin_redirect_does_not_forward_request_body(self):
        other = _Fixture()
        try:
            self.srv.httpd.redirect_status = 307
            self.srv.httpd.redirect_location = f"http://127.0.0.1:{other.port}/collect"
            ctx = _ctx()
            ctx.sessions.register("s1", "alice", allowed_origins=[self.srv.base])

            async def scenario():
                out = await ctx.executor().execute(
                    TypedRequest("POST", f"{self.srv.base}/redirect", body="secret=form-value"),
                    capability="probe", session_ref="s1")
                await ctx.aclose()
                return out

            self.assertEqual(asyncio.run(scenario()).outcome, "ok")
            self.assertEqual(other.httpd.received[0]["method"], "POST")
            self.assertEqual(other.httpd.received[0]["body"], "")
        finally:
            other.close()


class CrossIdentityExecutorMigrationTests(unittest.TestCase):
    """T03b: the cross-identity probe (a production caller) now sends through the
    RunContext executor -- asserted by the TARGET-side counter, not a mock."""

    def setUp(self):
        self.srv = _Fixture()

    def tearDown(self):
        self.srv.close()

    def _validator(self, ctx):
        from harness.validators.cross_identity_validator import CrossIdentityValidator
        return CrossIdentityValidator(allowed_hosts=["127.0.0.1"], run_context=ctx)

    def test_probe_sends_through_executor_and_counts_budget(self):
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=5)
        ctx.sessions.register("alice-session", "alice", headers={"Authorization": "Bearer X"},
                              allowed_origins=[self.srv.base])
        v = self._validator(ctx)

        async def scenario():
            p = await v._probe(f"{self.srv.base}/probe", {"Authorization": "Bearer X"},
                               "alice-session")
            await ctx.aclose()
            return p

        p = asyncio.run(scenario())
        self.assertEqual(p.status, 200)
        self.assertIn("/probe", self.srv.paths())     # the executor actually sent it (target-side)
        self.assertEqual(ctx.budget.used, 1)          # and it counted against the run budget

    def test_probe_out_of_scope_is_not_sent(self):
        ctx = RunContext.create(allowed_hosts=["only.allowed.test"])  # fixture host not allowed
        v = self._validator(ctx)

        async def scenario():
            p = await v._probe(f"{self.srv.base}/blocked", {})
            await ctx.aclose()
            return p

        p = asyncio.run(scenario())
        self.assertEqual(p.status, 0)                 # policy-declined -> not reached
        self.assertEqual(self.srv.paths(), [])        # target never contacted


if __name__ == "__main__":
    unittest.main()
