"""A browser context is closed after its route handlers end (r9 review).

r9 logged 174 "Task was destroyed but it is pending!" for Playwright's
BrowserContext._on_route: the identity router's handler sends each page request
through the run and fulfills it, and contexts were closed while handlers were
still awaiting. Every close site now goes through _close_context, which waits for
the handlers (bounded) before closing.

The r9 symptom (a pending task garbage-collected on the server's long-lived loop)
did not reproduce on a loopback page here, so these tests pin the close order on
a recorded context, and the real-browser test only checks that a visit with
handlers still in flight completes and leaves no pending route task behind.
Controls: an older Playwright without unroute_all still closes, and a drain past
the bound releases the handlers instead of hanging the visit.
"""
from __future__ import annotations

import asyncio
import gc
import logging
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from harness import browser_driver


class _Context:
    def __init__(self, *, drain_seconds=0.0, has_unroute=True):
        self.calls: list[str] = []
        self.drain_seconds = drain_seconds
        if not has_unroute:
            self.unroute_all = None

    async def unroute_all(self, behavior=None):
        self.calls.append(f"unroute_all:{behavior}")
        if behavior == "wait":
            await asyncio.sleep(self.drain_seconds)

    async def close(self):
        self.calls.append("close")


class CloseOrderTests(unittest.TestCase):

    def test_route_handlers_are_waited_for_before_the_close(self):
        context = _Context()
        asyncio.run(browser_driver._close_context(context))
        self.assertEqual(context.calls, ["unroute_all:wait", "close"])

    def test_control_a_drain_past_the_bound_releases_the_handlers(self):
        context = _Context(drain_seconds=5)
        with patch.object(browser_driver, "_ROUTE_DRAIN_SECONDS", 0.05):
            started = time.monotonic()
            asyncio.run(browser_driver._close_context(context))
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(context.calls, ["unroute_all:wait", "unroute_all:ignoreErrors", "close"])

    def test_control_a_playwright_without_unroute_all_still_closes(self):
        context = _Context(has_unroute=False)
        asyncio.run(browser_driver._close_context(context))
        self.assertEqual(context.calls, ["close"])

    def test_every_close_site_uses_the_draining_close(self):
        import inspect
        source = inspect.getsource(browser_driver)
        self.assertNotIn("await context.close()", source.replace(
            "await _quietly(context.close())", ""))
        self.assertEqual(source.count("await _close_context(context)"), 4)


def _chromium_available() -> bool:
    try:
        from playwright.async_api import async_playwright

        async def probe():
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                await browser.close()
        asyncio.run(probe())
        return True
    except Exception:
        return False


class _Slow(BaseHTTPRequestHandler):
    hits: list[str] = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/slow"):
            _Slow.hits.append(self.path)
            time.sleep(1.5)
        body = (b"<html><body>" + b"".join(b'<img src="/slow%d">' % i for i in range(3))
                + b"</body></html>") if self.path == "/" else b"x"
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if self.path == "/" else "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(_chromium_available(), "headless Chromium is not installed")
class RealBrowserCloseTests(unittest.TestCase):

    def test_a_visit_with_handlers_in_flight_leaves_no_pending_route_task(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Slow)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        _Slow.hits = []
        messages: list[str] = []

        class Grab(logging.Handler):
            def emit(self, record):
                messages.append(record.getMessage())
        grab = Grab()
        logging.getLogger("asyncio").addHandler(grab)
        self.addCleanup(logging.getLogger("asyncio").removeHandler, grab)

        async def go():
            obs = await browser_driver.PlaywrightDriver().visit(url, wait_ms=100)
            pending = [t for t in asyncio.all_tasks() if "_on_route" in repr(t)]
            gc.collect()
            await asyncio.sleep(0.2)
            return obs, pending
        _obs, pending = asyncio.run(go())
        self.assertTrue(_Slow.hits)              # handlers were still sending at close
        self.assertEqual(pending, [])
        self.assertFalse([m for m in messages if "destroyed but it is pending" in m])


if __name__ == "__main__":
    unittest.main()
