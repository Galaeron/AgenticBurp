"""The SPA crawl's script bodies are bounded in bytes, not by a count of six.

crawl_spa(declared_views=...) reads the router config from the same-origin scripts
the views load (browser_driver._IdentityRouter.script_bodies). It used to keep the
first six to finish. A bundled app loads its runtime, polyfills and small chunks
first and they finish before the large script that holds the router config; the
six were spent on them, the config was dropped and no declared view was visited.

The fixture is a generic loopback single-page app: its shell loads eight small
scripts, then the router bundle (served last, after a delay). The bundle is the
one test_spa_declared_views uses: hash routing, `reports` declared and unlinked,
firing `/api/reports`.

Covered here, through build_engagement with a real browser:
  - the declared view behind eight earlier scripts is visited and its API captured;
  - control: with the old count of six (patched back), the same app yields no
    declared view, so the fixture does exercise the bound;
  - control: a total byte budget too small for the bundle keeps it out.
"""
import asyncio
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

from harness import browser_driver, cache, engagement_builder, store
from harness.role_crawl import RoleSession
from harness.test_spa_declared_views import _APP_JS, _CHROMIUM, _config

LOW = RoleSession("user", {"Authorization": "Bearer low-token"}, name="low-user")
_SMALL = 8
_SHELL = ("<!doctype html><html><head><meta charset=\"utf-8\"><title>Desk</title></head>"
          "<body><nav><a href=\"#/about\">About</a></nav><main id=\"view\"></main>"
          + "".join(f"<script src=\"/static/part{i}.js\"></script>" for i in range(_SMALL))
          + "<script src=\"/static/app.js\"></script></body></html>")


class _Handler(BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):
        path = urlsplit(self.path).path
        _Handler.seen.append(path)
        if path == "/":
            self._reply(_SHELL, "text/html")
        elif path.startswith("/static/part"):
            self._reply("window.__parts = (window.__parts || 0) + 1;", "application/javascript")
        elif path == "/static/app.js":
            time.sleep(0.4)       # the large router bundle finishes last
            self._reply(_APP_JS, "application/javascript")
        elif path.startswith("/api/"):
            self._reply(json.dumps({"view": path[5:]}), "application/json")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _reply(self, text, ctype):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class ScriptBudgetCrawlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="spa_script_budget_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _build(self):
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config()
        _Handler.seen = []

        async def build():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                return await engagement_builder.build_engagement(
                    self.base, [LOW], allowed_hosts=["127.0.0.1"], crawl_max_pages=4,
                    active_discovery=False, run_context=ctx,
                    driver_capture_config={"enabled": True, "spa_navigation": True,
                                           "wait_ms": 800, "max_views": 8,
                                           "declared_views": 6})
        state, result = asyncio.run(build())
        spa = next(v for v in result.spa_views if v["principal"] == "low-user")
        return state, spa

    def test_the_router_bundle_behind_eight_earlier_scripts_is_read(self):
        state, spa = self._build()
        self.assertIn("/#/reports", spa["declared"], spa)
        self.assertIn("GET /api/reports", state.endpoints, sorted(state.endpoints))
        self.assertIn("/api/reports", _Handler.seen)

    def test_control_a_count_of_six_drops_the_router_bundle(self):
        with mock.patch.object(browser_driver, "_MAX_SCRIPT_BODIES", 6):
            _state, spa = self._build()
        self.assertEqual(spa["declared"], [], spa)
        self.assertNotIn("/api/reports", _Handler.seen)

    def test_control_a_byte_budget_too_small_for_the_bundle_keeps_it_out(self):
        with mock.patch.object(browser_driver, "_SCRIPT_BYTES_TOTAL", len(_APP_JS) - 1):
            _state, spa = self._build()
        self.assertEqual(spa["declared"], [], spa)


if __name__ == "__main__":
    unittest.main()
