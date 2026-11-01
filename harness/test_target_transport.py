"""W-16 -- the single TargetTransport: naming, the is_host_allowed scope bridge,
standalone-context construction, and credential-forwarding via send_creds.

Hermetic: no network. The one send-path test stubs TargetTransport.execute so it
exercises the session/credential resolution, not a real socket.
"""
import asyncio
import unittest

import harness.run_context as rc


def _run(coro):
    return asyncio.run(coro)


class NamingTests(unittest.TestCase):
    def test_executor_is_targettransport_alias(self):
        # Back-compat: the 37 `.executor()` / `Executor(...)` call sites keep working.
        self.assertIs(rc.Executor, rc.TargetTransport)

    def test_runcontext_exposes_target_transport(self):
        ctx = rc.RunContext.create(allowed_hosts=["example.com"])
        self.assertIsInstance(ctx.target_transport(), rc.TargetTransport)
        # `.executor()` is the back-compat name and returns the same type.
        self.assertIsInstance(ctx.executor(), rc.TargetTransport)


class HostAllowScopeTests(unittest.TestCase):
    def test_empty_hosts_fail_open_in_passive_mode(self):
        # Matches scope_discovery.is_host_allowed: no configured scope + passive = open.
        scope = rc.HostAllowScope(hosts=(), active_mode=False)
        self.assertTrue(scope.in_scope("http://anything.example/x"))

    def test_empty_hosts_fail_closed_in_active_mode(self):
        scope = rc.HostAllowScope(hosts=(), active_mode=True)
        self.assertFalse(scope.in_scope("http://anything.example/x"))

    def test_subdomain_and_out_of_scope(self):
        scope = rc.HostAllowScope(hosts=("example.com",))
        self.assertTrue(scope.in_scope("http://example.com/x"))
        self.assertFalse(scope.in_scope("http://api.example.com/x"))  # bare host is exact
        wildcard = rc.HostAllowScope(hosts=("*.example.com",))
        # Reviewed containment contract (docs/SCOPE_POLICY.md): the strict intersection
        # denies wildcard entries in EVERY adapter, including HostAllowScope, so an
        # explicit "*.example.com" grants no subdomain authority. (Superseded permissive
        # expectation migrated; coverage preserved per SCOPE_POLICY.md migration note.)
        self.assertFalse(wildcard.in_scope("http://api.example.com/x"))
        self.assertFalse(scope.in_scope("http://evil.test/x"))
        # same_origin/origin_of inherited from the base ScopePolicy, unchanged.
        self.assertTrue(scope.same_origin("http://example.com/a", "http://example.com:80/b"))


class StandaloneContextTests(unittest.TestCase):
    def test_standalone_uses_hostallowscope(self):
        ctx = rc.standalone_context(["example.com"])
        self.assertIsInstance(ctx.scope, rc.HostAllowScope)
        self.assertTrue(ctx.scope.in_scope("http://example.com/x"))
        self.assertFalse(ctx.scope.in_scope("http://evil.test/x"))

    def test_standalone_gate_override(self):
        sentinel = object()
        ctx = rc.standalone_context(["example.com"], gate=sentinel)
        self.assertIs(ctx.gate, sentinel)

    def test_transport_for_ownership(self):
        # No run of its own -> a standalone context is created and returned as owned.
        tt, owned = rc.transport_for(None, allowed_hosts=["example.com"])
        self.assertIsInstance(tt, rc.TargetTransport)
        self.assertIsNotNone(owned)
        _run(owned.aclose())
        # A provided run is used directly and must NOT be owned/closed by the caller.
        ctx = rc.standalone_context(["example.com"])
        tt2, owned2 = rc.transport_for(ctx, allowed_hosts=["example.com"])
        self.assertIsInstance(tt2, rc.TargetTransport)
        self.assertIsNone(owned2)


class SendCredsTests(unittest.TestCase):
    def _transport_with_capture(self, ctx):
        tt = ctx.target_transport()
        seen = {}

        async def fake_execute(req, *, capability, session_ref=None, **kw):
            seen["session_ref"] = session_ref
            seen["headers"] = dict(req.headers)
            seen["method"], seen["url"] = req.method, req.url
            return rc.ExecutionOutcome(outcome="ok", status=200, body="ok")

        tt.execute = fake_execute
        return tt, seen

    def test_credentials_register_ephemeral_session_and_are_stripped(self):
        ctx = rc.standalone_context(["example.com"])
        tt, seen = self._transport_with_capture(ctx)
        out = _run(tt.send_creds("GET", "http://example.com/a", capability="probe",
                                 headers={"Authorization": "Bearer T", "X-Foo": "1"}))
        self.assertTrue(out.ok)
        self.assertIsNotNone(seen["session_ref"])                 # a session was bound
        self.assertNotIn("Authorization", seen["headers"])        # credential not sent inline
        self.assertEqual(seen["headers"].get("X-Foo"), "1")       # non-credential header kept
        # the ephemeral session is registered in the context's SessionManager
        self.assertTrue(any(s.session_id == seen["session_ref"] for s in ctx.sessions.all()))

    def test_no_credentials_uses_no_session(self):
        ctx = rc.standalone_context(["example.com"])
        tt, seen = self._transport_with_capture(ctx)
        _run(tt.send_creds("GET", "http://example.com/a", capability="probe",
                           headers={"X-Only": "y"}))
        self.assertIsNone(seen["session_ref"])

    def test_existing_session_is_reused_not_duplicated(self):
        ctx = rc.standalone_context(["example.com"])
        ctx.sessions.register("known", "user", headers={"Authorization": "Bearer T"},
                              allowed_origins=["http://example.com"])
        before = len(ctx.sessions.all())
        tt, seen = self._transport_with_capture(ctx)
        _run(tt.send_creds("GET", "http://example.com/a", capability="probe",
                           headers={"Authorization": "Bearer T"}))
        self.assertEqual(seen["session_ref"], "known")            # resolved to the existing session
        self.assertEqual(len(ctx.sessions.all()), before)         # no ephemeral duplicate


class DecodedConsumerResponseTests(unittest.TestCase):
    """Real compressed HTTP -> executor -> each validator's own send helper.

    The transport decodes the body; a consumer response that still carries the
    wire Content-Encoding makes httpx decompress it a second time."""

    BODY = b"fixture shared response body"

    def _serve(self, encoding):
        import gzip
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import brotli
        wire = {"plain": self.BODY, "gzip": gzip.compress(self.BODY),
                "br": brotli.compress(self.BODY), "malformed": b"not gzip"}[encoding]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.server.received.append(self.command)
                self.send_response(200)
                if encoding != "plain":
                    self.send_header("Content-Encoding", "gzip" if encoding == "malformed" else encoding)
                self.send_header("Content-Length", str(len(wire)))
                self.end_headers()
                self.wfile.write(wire)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.received = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.addCleanup(close)
        return server, f"http://127.0.0.1:{server.server_port}/r"

    def _senders(self):
        from harness.validators.http_request_smuggling_validator import HttpRequestSmugglingValidator
        from harness.validators.recon_validator import ReconValidator
        from harness.validators.web_cache_poisoning_validator import WebCachePoisoningValidator
        return {
            "smuggling": lambda ctx, url: HttpRequestSmugglingValidator(
                run_context=ctx, allowed_hosts=["127.0.0.1"])._send_raw_request("GET", url),
            "recon": lambda ctx, url: ReconValidator(
                run_context=ctx, allowed_hosts=["127.0.0.1"])._send_request(url),
            "cache_poisoning": lambda ctx, url: WebCachePoisoningValidator(
                run_context=ctx, allowed_hosts=["127.0.0.1"])._send(url),
        }

    def _send(self, sender, url, in_scope=True):
        ctx = rc.RunContext.create(allowed_hosts=["127.0.0.1"] if in_scope else ["denied.invalid"],
                                   max_requests=10, gate_config={"active_enabled": True})

        async def run():
            async with ctx:
                return await sender(ctx, url)
        return _run(run()), ctx

    def test_compressed_and_plain_responses_read_the_same_body(self):
        for name, sender in self._senders().items():
            for encoding in ("plain", "gzip", "br"):
                with self.subTest(caller=name, encoding=encoding):
                    server, url = self._serve(encoding)
                    response, ctx = self._send(sender, url)
                    self.assertIsNotNone(response)
                    self.assertEqual(response.text, self.BODY.decode())
                    self.assertEqual(server.received, ["GET"])     # exactly one send
                    self.assertTrue(response.extensions.get("harness_artifact_id"))

    def test_original_wire_headers_survive_beside_the_consumer_view(self):
        server, url = self._serve("gzip")
        ctx = rc.RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=10,
                                   gate_config={"active_enabled": True})

        async def run():
            async with ctx:
                return await ctx.executor().execute(rc.TypedRequest("GET", url), capability="recon")
        outcome = _run(run())
        response = outcome.to_httpx_response("GET", url)
        self.assertEqual(response.text, self.BODY.decode())
        self.assertNotIn("content-encoding", {k.lower() for k in response.headers})
        self.assertEqual({k.lower(): v for k, v in outcome.headers.items()}["content-encoding"], "gzip")
        self.assertEqual(response.extensions["harness_artifact_id"], outcome.artifact_id)

    def test_malformed_encoding_is_a_failure_not_a_response(self):
        for name, sender in self._senders().items():
            with self.subTest(caller=name):
                server, url = self._serve("malformed")
                response, ctx = self._send(sender, url)
                self.assertIsNone(response)
                self.assertEqual(server.received, ["GET"])         # no retry send

    def test_blocked_send_reaches_no_server(self):
        for name, sender in self._senders().items():
            with self.subTest(caller=name):
                server, url = self._serve("gzip")
                response, ctx = self._send(sender, url, in_scope=False)
                self.assertIsNone(response)
                self.assertEqual(server.received, [])


if __name__ == "__main__":
    unittest.main()
