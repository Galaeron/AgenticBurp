"""The route feed does not learn routes from the harness's own payload URLs (r9 review).

In r9 a path-traversal probe sent `PUT /<api route>/..%2f..%2fetc/passwd`. The app's
auth layer answers 401 for any path under its API prefix, and the feed counts a 401
as "the route exists", so the probe URL went back to the worklist. The recrawl then
investigated it, its own probes echoed new payload paths back (`....//....//etc/...`,
`//windows/win.ini`, ...), and 62 worklist units grew out of one route. Hours 11-12
spent ~9k requests on them.

Drives the production caller: the run's transport (RunContext executor) offering each
response to an installed RouteFeed, against a generic loopback app. Controls: a clean
route first seen in the same way is still queued, and without the probe-path check
the payload URLs come back as new routes.
"""
from __future__ import annotations

import asyncio
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from harness import route_feed
from harness.route_feed import RouteFeed, probe_path
from harness.run_context import RunContext, TypedRequest

PAYLOAD_PATHS = (
    "/api/items/..%2f..%2f..%2fetc/passwd",
    "/api/items/%2e%2e/%2e%2e/windows/win.ini",
    "/api/items/....//....//etc/passwd",
    "/api/items//etc/passwd",            # what a stripped traversal leaves behind
    "/api/items/%252e%252e%252fsecret",  # double-encoded
    "/api/items/%3Csvg%20onload%3D1%3E",
    "/api/items/%7B%7B7*7%7D%7D",
)
CLEAN_PATH = "/api/reports"


class _Handler(BaseHTTPRequestHandler):
    """An app whose auth layer answers 401 for any path under /api/ without a valid
    session, and 404 elsewhere."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        status = 401 if self.path.startswith("/api/") else 404
        data = b'{"error": "unauthorized"}' if status == 401 else b"no"
        self.send_response(status)
        self.send_header("Content-Type", "application/json" if status == 401 else "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = _answer


class TransportProbePathTests(unittest.TestCase):

    def setUp(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        thread.start()

        def close():
            self.httpd.shutdown()
            self.httpd.server_close()
            thread.join(5)
        self.addCleanup(close)

    def _send(self):
        """A traversal-style validator sends its payload URLs, then an agent request
        finds a clean new route; returns the feed after both went through the run."""
        ctx = RunContext.create(config={}, allowed_hosts=["127.0.0.1"],
                                gate_config={"active_enabled": True,
                                             "allow_mutating_replay": True})
        ctx.route_feed = RouteFeed(origin=self.base, in_scope=ctx.scope.in_scope,
                                   known={("GET", "/api/items")})

        async def go():
            ex = ctx.executor()
            for path in PAYLOAD_PATHS:
                await ex.execute(TypedRequest("PUT", self.base + path, body='{"x": 1}',
                                              headers={"Content-Type": "application/json"}),
                                 capability="path_traversal")
            await ex.execute(TypedRequest("GET", self.base + CLEAN_PATH),
                             capability="iterative_agent")
            await ctx.aclose()
        asyncio.run(go())
        return ctx.route_feed

    def test_payload_urls_are_not_learned_as_routes(self):
        feed = self._send()
        self.assertEqual([o.path for o in feed.drain()], [CLEAN_PATH])
        self.assertEqual(feed.refused.get("probe_path"), len(PAYLOAD_PATHS))
        self.assertEqual(feed.stats()["refused"]["probe_path"], len(PAYLOAD_PATHS))

    def test_control_without_the_check_the_payload_urls_become_routes(self):
        with patch.object(route_feed, "probe_path", lambda url: False):
            feed = self._send()
        learned = [o.path for o in feed.drain()]
        self.assertIn(CLEAN_PATH, learned)
        self.assertGreaterEqual(len(learned), len(PAYLOAD_PATHS))   # the r9 failure
        self.assertNotIn("probe_path", feed.refused)


class ProbePathPredicateTests(unittest.TestCase):
    """The predicate on its own: payload shapes in, ordinary route shapes out."""

    def test_payload_shapes(self):
        backslash = chr(92)
        for path in PAYLOAD_PATHS + (
                "/api/items/..%5c..%5cboot.ini",
                "/api/items/.." + backslash + "secret",
                "/api/items/%24%7B7*7%7D",
                "/api/items/a%00b",
                "/api/items/%2fproc%2fself%2fenviron"):
            self.assertTrue(probe_path("http://h" + path), path)

    def test_control_ordinary_routes(self):
        for path in ("/", "/api/orders/7", "/api/v1.2/items", "/static/app.min.js",
                     "/api/files/my%20doc.pdf", "/a/b;jsessionid=X", "/.well-known/openid",
                     "/api/hosts", "/etc/config", "/api/users/{id}"):
            self.assertFalse(probe_path("http://h" + path), path)

    def test_offer_exchange_refuses_a_payload_path_from_any_source(self):
        feed = RouteFeed(origin="http://shop.test", in_scope=lambda u: True)
        self.assertFalse(feed.offer_exchange(
            {"method": "GET", "url": "http://shop.test/api/x/..%2fetc/passwd",
             "response_status": 200}, source="browser"))
        self.assertTrue(feed.offer_exchange(
            {"method": "GET", "url": "http://shop.test/api/x", "response_status": 200},
            source="browser"))
        self.assertEqual(feed.refused, {"probe_path": 1})


if __name__ == "__main__":
    unittest.main()
