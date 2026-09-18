"""P0.8: credential-isolation + cancellation loopback tests.

Most of this ground is already covered in test_run_context.py
(test_credentials_not_forwarded_across_origin strips Authorization alone,
test_cookie_jar_not_used_on_unauthorized_redirect_origin strips the cookie
jar alone, test_cancel_stops_dispatch proves CancelToken stops a send) --
this file adds the ONE real gap: a single cross-origin redirect carrying
BOTH a cookie AND an Authorization header at once (the combined case a
fix that only patched one credential type could still miss), plus an
explicit "cancel mid-run stops a SUBSEQUENT owned op" scenario distinct
from "cancel before the first send". Off-scope SEND (a different host
entirely) is already covered by scope_lock.py/test_offscope_host_lock.py;
this is specifically the cross-ORIGIN (same host, different port)
credential-forwarding boundary RunContext's transport enforces.

Real loopback HTTP fixtures throughout -- assertions are on what the target
actually received, not on a mocked transport.
"""
from __future__ import annotations

import asyncio
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harness.run_context import RunContext, TypedRequest


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _record(self):
        self.server.received.append({
            "path": self.path.split("?", 1)[0],
            "authorization": self.headers.get("Authorization"),
            "cookie": self.headers.get("Cookie"),
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
        if path == "/redirect":
            self._reply(302, b"", {"Location": self.server.redirect_location})
        else:
            self._reply(200, b"OK")


class _Fixture:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.received = []
        self.httpd.redirect_location = ""
        self.port = self.httpd.server_address[1]
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _ctx(**over):
    kw = dict(allowed_hosts=["127.0.0.1"], gate_config={"active_enabled": True})
    kw.update(over)
    return RunContext.create(**kw)


class CombinedCredentialIsolationTest(unittest.TestCase):
    """Two real loopback listeners on the same host, different ports (two
    ORIGINS, both within server.allowed_hosts=["127.0.0.1"]). A session
    authorized only for the FIRST origin carries both an Authorization
    header and a cookie; a redirect to the SECOND origin must arrive with
    NEITHER."""

    def setUp(self):
        self.in_scope = _Fixture()
        self.off_origin = _Fixture()

    def tearDown(self):
        self.in_scope.close()
        self.off_origin.close()

    def test_cross_origin_redirect_strips_both_cookie_and_authorization(self):
        self.in_scope.httpd.redirect_location = f"http://127.0.0.1:{self.off_origin.port}/collect"
        ctx = _ctx()
        ctx.sessions.register(
            "s1", "alice", headers={"Authorization": "Bearer SECRET-TOKEN"},
            allowed_origins=[self.in_scope.base])
        # Simulate an already-set session cookie by seeding the session's own
        # httpx client cookie jar directly (same effect as a prior response
        # setting it) so this one request exercises both credential kinds.
        ctx.sessions.get("s1").client(ctx.timeout).cookies.set(
            "sess", "COOKIEVAL", domain="127.0.0.1")

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", f"{self.in_scope.base}/redirect"),
                capability="probe", session_ref="s1")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "ok")

        own_origin_hit = self.in_scope.httpd.received[0]
        self.assertEqual(own_origin_hit["authorization"], "Bearer SECRET-TOKEN")

        cross_origin_hits = [r for r in self.off_origin.httpd.received if r["path"] == "/collect"]
        self.assertEqual(len(cross_origin_hits), 1)
        self.assertIsNone(cross_origin_hits[0]["authorization"])
        self.assertIsNone(cross_origin_hits[0]["cookie"])


class CancelStopsOwnedOpTest(unittest.TestCase):
    """Cancelling a run mid-flight must stop a SUBSEQUENT send on that same
    run before it ever reaches the target -- not just a cancel set before
    the very first call (test_run_context.py's test_cancel_stops_dispatch)."""

    def setUp(self):
        self.srv = _Fixture()

    def tearDown(self):
        self.srv.close()

    def test_cancel_after_first_send_stops_the_next_owned_send(self):
        ctx = _ctx()

        async def scenario():
            ex = ctx.executor()
            first = await ex.execute(TypedRequest("GET", f"{self.srv.base}/one"), capability="probe")
            ctx.cancel.cancel()  # operator cancels the run mid-flight
            second = await ex.execute(TypedRequest("GET", f"{self.srv.base}/two"), capability="probe")
            await ctx.aclose()
            return first, second

        first, second = asyncio.run(scenario())
        self.assertEqual(first.outcome, "ok")
        self.assertEqual(second.outcome, "cancelled")
        received_paths = [r["path"] for r in self.srv.httpd.received]
        self.assertIn("/one", received_paths)
        self.assertNotIn("/two", received_paths)  # cancelled -- never sent


if __name__ == "__main__":
    unittest.main()
