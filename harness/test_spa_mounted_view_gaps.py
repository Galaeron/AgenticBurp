"""Two SPA crawl gaps on views a router keeps mounted (driver_capture).

1. A route probe reached its view by a hash change. A router that keeps the
   same view mounted when only the route query changes never re-runs the view,
   so a view that reads its query once, when it mounts, never saw the probe's
   markers: no route input was found. The probe is now a new document.
2. A file input in a script-driven form (no POST method; the page uploads from
   its own submit handler) was never submitted, so no upload was observed. Its
   empty text fields now get benign values and its submit control is clicked;
   every write stays held, and nothing reaches the server.

The fixture is a generic loopback single-page app (hash routes). Its router
re-renders only when the route path changes. Its home view links to:
  - #/order: reads `ref` from the route query when it mounts and fetches
    /api/orders/<ref>;
  - #/complain: a form (no method) with a required textarea, a file input
    (accept .pdf) and a submit button disabled until the textarea has text; on
    submit the script posts the form's FormData to /api/complaint-file;
  - #/attach: a form with a file input and no submit control.

Covered here (skipped without Chromium):
  - the probe finds `ref` on #/order (the view fetched the marker);
  - control: the same probe by a hash change finds nothing;
  - the complaint form's upload is captured (held: no upload reaches the
    server), with the filled text field and the benign .pdf;
  - control: a form with no submit control is a recorded skip, with the reason;
  - the crawl keeps each script URL once (the probes load the bundle again).
"""
import asyncio
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

import yaml

from harness import cache, engagement_builder, spa_navigation, store
from harness.role_crawl import RoleSession
from harness.spa_navigation import UPLOAD_CAPABILITY

_HARNESS = Path(__file__).resolve().parent
LOW = RoleSession("user", {"Authorization": "Bearer low-token"}, name="low-user")

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>Desk</title></head>
<body><main id="view"></main><script src="/static/app.js"></script></body></html>"""

_APP_JS = """(function () {
  var views = {
    "": '<a href="#/order">Order</a> <a href="#/complain">Complain</a> <a href="#/attach">Attach</a>',
    "order": '<h1>Order</h1><p id="o"></p>',
    "complain": '<form id="c"><textarea name="msg" required></textarea>' +
                '<input type="file" name="doc" accept=".pdf">' +
                '<button type="submit" id="go" disabled>Send</button></form>',
    "attach": '<form><input type="file" name="extra" accept=".pdf"></form>'
  };
  var mounted = null;
  function render() {
    var hash = location.hash || "#/";
    var at = hash.indexOf("?");
    var path = (at < 0 ? hash : hash.slice(0, at)).replace(/^#\\/?/, "");
    if (path === mounted) return;          // the same view stays mounted
    mounted = path;
    document.getElementById("view").innerHTML = views[path] || views[""];
    if (path === "order") {
      var qs = at < 0 ? "" : hash.slice(at + 1);
      var ref = new URLSearchParams(qs).get("ref") || "none";
      fetch("/api/orders/" + encodeURIComponent(ref));
    }
    var form = document.getElementById("c");
    if (form) {
      var msg = form.querySelector("textarea"), go = document.getElementById("go");
      msg.addEventListener("input", function () { go.disabled = !msg.value; });
      form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        fetch("/api/complaint-file", {method: "POST", body: new FormData(form)})
          .catch(function () {});
      });
    }
  }
  window.addEventListener("hashchange", render);
  render();
})();
"""


class _Handler(BaseHTTPRequestHandler):
    seen: list = []
    posts: list = []

    def do_GET(self):
        parts = urlsplit(self.path)
        _Handler.seen.append(parts.path)
        if parts.path == "/":
            self._reply(_SHELL, "text/html")
        elif parts.path == "/static/app.js":
            self._reply(_APP_JS, "application/javascript")
        elif parts.path.startswith("/api/"):
            self._reply(json.dumps({"ok": True}), "application/json")
        else:
            self._reply("", "text/plain", 404)

    def do_POST(self):
        # Uploads only: the role crawl also probes the paths the bundle names,
        # with a placeholder JSON body.
        if b"harness-upload-" in self.rfile.read(int(self.headers.get("Content-Length") or 0)):
            _Handler.posts.append(urlsplit(self.path).path)
        self._reply("{}", "application/json")

    def _reply(self, text, ctype, code=200):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


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


def _config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    for name in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(name, {})["enabled"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    cfg.setdefault("validators", {}).update(active_enabled=True, allow_mutating_replay=True)
    return cfg


async def _hash_change_probe(adapter, target):
    await adapter.open(target)


@unittest.skipUnless(_chromium_available(), "Chromium (playwright) not available")
class MountedViewCrawlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="mounted_views_")
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

    def _crawl(self):
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config()
        _Handler.seen, _Handler.posts = [], []

        async def build():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                _state, result = await engagement_builder.build_engagement(
                    self.base, [LOW], allowed_hosts=["127.0.0.1"], crawl_max_pages=4,
                    active_discovery=False, run_context=ctx,
                    driver_capture_config={"enabled": True, "spa_navigation": True,
                                           "wait_ms": 600, "max_views": 8, "route_probes": 6,
                                           "file_uploads": True, "max_uploads": 4})
                return result
        result = asyncio.run(build())
        spa = next(v for v in result.spa_views if v["principal"] == "low-user")
        return result, spa

    @staticmethod
    def _probe_names(spa, view):
        return [p["names"] for p in spa["probes"] if p["view"] == view]

    def test_a_probe_reaches_a_view_that_reads_its_query_when_it_mounts(self):
        _result, spa = self._crawl()
        self.assertEqual(self._probe_names(spa, "/#/order"), [["ref"]], spa["probes"])
        self.assertTrue([p for p in _Handler.seen if p.startswith("/api/orders/")
                         and p != "/api/orders/none"], _Handler.seen)

    def test_control_a_hash_change_probe_never_reaches_the_mounted_view(self):
        with mock.patch.object(spa_navigation, "_open_probe", _hash_change_probe):
            _result, spa = self._crawl()
        self.assertEqual(self._probe_names(spa, "/#/order"), [[]], spa["probes"])

    def test_a_script_driven_form_uploads_on_its_submit_control_held_never_sent(self):
        result, spa = self._crawl()
        by_input = {u["input"]: u for u in spa["uploads"]}
        doc = by_input["doc"]
        self.assertEqual(doc["outcome"], "captured", spa["uploads"])
        self.assertEqual(doc["request"], "POST /api/complaint-file")
        captured = [c for c in result.captured if c.get("capture_source") == UPLOAD_CAPABILITY]
        self.assertEqual(len(captured), 1, captured)
        body = captured[0]["request_body"]
        self.assertRegex(body, r'name="doc"; filename="harness-upload-[0-9a-f]+\.pdf"')
        self.assertIn('name="msg"', body)
        self.assertIn("harness upload check", body)
        self.assertIsNone(captured[0]["response_status"])
        self.assertEqual(_Handler.posts, [])            # held in the browser, never sent

    def test_control_a_form_with_no_submit_control_is_a_recorded_skip(self):
        _result, spa = self._crawl()
        extra = {u["input"]: u for u in spa["uploads"]}["extra"]
        self.assertEqual(extra["outcome"], "skipped")
        self.assertIn("no submit control", extra["reason"])
        self.assertEqual(_Handler.posts, [])

    def test_each_script_url_is_kept_once(self):
        from harness import browser_driver
        kept: list = []
        real = browser_driver._IdentityRouter.__init__

        def spy(router, *a, **kw):
            real(router, *a, **kw)
            kept.append(router)
        with mock.patch.object(browser_driver._IdentityRouter, "__init__", spy):
            self._crawl()
        spa_routers = [r for r in kept if r._script_urls]
        self.assertTrue(spa_routers)
        self.assertTrue(all(r._scripts_kept == len(r._script_urls) == 1 for r in spa_routers))
        self.assertGreater(_Handler.seen.count("/static/app.js"), 1)   # loaded again by the probes


if __name__ == "__main__":
    unittest.main()
