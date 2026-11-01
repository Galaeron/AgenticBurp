"""Unit test for harness.driver_capture (LB-2) -- the capture shape itself.

Exercises capture_requests()/discover() against a tiny local page served by a
bare stdlib HTTP server (no Flask dependency here -- the fixture-level
integration test in test_leg_live_verification.py covers the real XXE
capture-to-confirm path against testing/leg-verification/vuln_fixture.py).
The page's inline JS issues a fetch() POST; a plain <img> tag is also on the
page to prove non-xhr/fetch resource types are correctly left uncaptured.

Guarded by skipUnless(playwright_available()) per the instructions, but this
is expected to actually RUN (not silently skip) in this session -- Playwright
and a Chromium binary are confirmed installed and working offline.
"""
from __future__ import annotations

import asyncio
import http.server
import threading
import unittest

from harness import browser_driver
from harness import driver_capture
from harness.testing_fixtures.loopback_port import CHROMIUM_RESTRICTED_PORTS, bind_browser_safe

_PIXEL_GIF = bytes.fromhex(
    "47494638396101000100800000ffffff00000021f90401000000002c00000000"
    "010001000002024401003b")

_PAGE = b"""<html><body>
<img src="/pixel.gif">
<script>
fetch('/echo', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({hello: 'world'})
});
</script>
</body></html>"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/pixel.gif":
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(_PIXEL_GIF)))
            self.end_headers()
            self.wfile.write(_PIXEL_GIF)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(_PAGE)))
        self.end_headers()
        self.wfile.write(_PAGE)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence default stderr request logging
        pass


@unittest.skipUnless(browser_driver.playwright_available(), "playwright not installed")
class DriverCaptureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._srv = bind_browser_safe(lambda: http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler))
        cls._port = cls._srv.server_address[1]
        cls._thread = threading.Thread(target=cls._srv.serve_forever, daemon=True)
        cls._thread.start()
        cls._base = f"http://127.0.0.1:{cls._port}"

    @classmethod
    def tearDownClass(cls):
        cls._srv.shutdown()
        cls._srv.server_close()   # shutdown() only ends the serve loop; release the socket too
        cls._thread.join(timeout=5.0)

    def test_captures_js_issued_fetch_as_http_exchange_dict(self):
        obs = asyncio.run(driver_capture.capture_requests(f"{self._base}/", wait_ms=800))
        self.assertEqual(obs.load_error, "", f"capture failed to load the page: {obs.load_error}")
        matches = [e for e in obs.exchanges if e["url"].endswith("/echo")]
        self.assertEqual(len(matches), 1, f"expected exactly one /echo capture, got: {obs.exchanges}")
        ex = matches[0]
        # Exact HttpExchange.model_dump() shape (harness/models.py).
        self.assertEqual(
            set(ex.keys()),
            {"url", "method", "request_headers", "request_body", "response_status",
             "response_headers", "response_body", "analyst_note", "capture_id"})
        self.assertEqual(ex["method"], "POST")
        content_types = {v.lower() for k, v in ex["request_headers"].items()
                         if k.lower() == "content-type"}
        self.assertIn("application/json", content_types)
        self.assertEqual(ex["request_body"], '{"hello":"world"}')
        self.assertEqual(ex["response_status"], 200)
        self.assertEqual(ex["response_body"], '{"hello":"world"}')

    def test_real_browser_capture_reaches_engagement_worklist(self):
        from unittest.mock import AsyncMock, patch
        from harness import crawler, engagement_builder, role_crawl
        from harness.run_context import RunContext

        async def run():
            ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=10,
                                    gate_config={"active_enabled": True, "allow_mutating_replay": True})
            try:
                with patch("harness.crawler.crawl", AsyncMock(return_value=crawler.CrawlResult(self._base))):
                    state, result = await engagement_builder.build_engagement(
                        self._base + "/", [role_crawl.RoleSession("anonymous", {})],
                        allowed_hosts=["127.0.0.1"], active_discovery=False, run_context=ctx,
                        driver_capture_config={"enabled": True, "wait_ms": 800})
                self.assertFalse(result.errors, result.errors)
                self.assertTrue(any(e.path == "/echo" and e.method == "POST"
                                    for e in state.endpoints.values()))
                self.assertTrue(any(e["request_body"] == '{"hello":"world"}' for e in result.captured))
                self.assertGreater(ctx.budget.used, 0)
                self.assertLessEqual(ctx.budget.used, 10)
            finally:
                await ctx.aclose()
        asyncio.run(run())

    def test_only_xhr_and_fetch_resource_types_are_captured(self):
        # The navigation document itself and the plain <img> must NOT appear --
        # only JS-issued XHR/fetch requests are what this module exists to capture.
        obs = asyncio.run(driver_capture.capture_requests(f"{self._base}/", wait_ms=800))
        urls = [e["url"] for e in obs.exchanges]
        self.assertFalse(any(u.endswith("/pixel.gif") for u in urls), urls)
        self.assertFalse(any(u.rstrip("/").endswith(f":{self._port}") for u in urls), urls)

    def test_discover_lands_captures_into_a_rolecrawlresult_like_object(self):
        class _FakeRc:
            def __init__(self):
                self.captured: list = []

        rc = _FakeRc()
        asyncio.run(driver_capture.discover(rc, f"{self._base}/", wait_ms=800))
        self.assertTrue(rc.captured, "discover() did not land any captures into rc.captured")
        self.assertTrue(any(e["url"].endswith("/echo") for e in rc.captured))

        # Re-running discover() against the SAME page must not duplicate an
        # identical (method, url, body) capture.
        before = len(rc.captured)
        asyncio.run(driver_capture.discover(rc, f"{self._base}/", wait_ms=800))
        self.assertEqual(len(rc.captured), before, "discover() duplicated an identical capture")


class _FakeServer:
    """What a server that bound `port` looks like to bind_browser_safe."""

    def __init__(self, port):
        self.server_address = ("127.0.0.1", port)
        self.closed = False

    def server_close(self):
        self.closed = True


class BrowserSafePortTests(unittest.TestCase):
    """The helper behind the server above: Chromium refuses some ports (2049 came
    up once as the OS's pick), so such a bind is closed and redone."""

    @staticmethod
    def _binder(ports):
        made = []
        pending = iter(ports)

        def bind():
            made.append(_FakeServer(next(pending)))
            return made[-1]
        return bind, made

    def test_a_restricted_port_is_closed_and_rebound(self):
        bind, made = self._binder([2049, 54321])
        server = bind_browser_safe(bind)
        self.assertIs(server, made[1])
        self.assertEqual(server.server_address[1], 54321)
        self.assertEqual([s.closed for s in made], [True, False])

    def test_a_safe_port_is_kept_at_once(self):
        bind, made = self._binder([54321, 2049])
        self.assertIs(bind_browser_safe(bind), made[0])
        self.assertEqual(len(made), 1)
        self.assertFalse(made[0].closed)

    def test_retries_are_bounded_and_every_refused_bind_is_closed(self):
        bind, made = self._binder([2049] * 5)
        with self.assertRaises(RuntimeError):
            bind_browser_safe(bind, attempts=3)
        self.assertEqual(len(made), 3)
        self.assertTrue(all(s.closed for s in made))

    def test_the_list_holds_the_ports_that_failed_a_run_and_not_ordinary_ones(self):
        self.assertTrue({2049, 4045, 6000, 6667} <= CHROMIUM_RESTRICTED_PORTS)
        self.assertFalse({80, 3000, 8080, 8443, 54321} & CHROMIUM_RESTRICTED_PORTS)


if __name__ == "__main__":
    unittest.main()
