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
        cls._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls._port = cls._srv.server_address[1]
        cls._thread = threading.Thread(target=cls._srv.serve_forever, daemon=True)
        cls._thread.start()
        cls._base = f"http://127.0.0.1:{cls._port}"

    @classmethod
    def tearDownClass(cls):
        cls._srv.shutdown()
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


if __name__ == "__main__":
    unittest.main()
