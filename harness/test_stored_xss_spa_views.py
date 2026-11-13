"""Stored XSS that only a client view runs: the write lands in a JSON API, the
API's read returns it as JSON (no script runs on JSON), and a hash-routed view's
own script fetches that API and renders the value with `innerHTML`.

The fixture is a generic loopback app. `/` is the shell; its links open
`#/board` (fetches `/api/notes`, renders each note's text as HTML) and `#/memos`
(fetches `/api/memos`, renders as text). `/api/orphans` stores too, but no view
reads it. `/api/notes` escapes `<` and `>` as `\\u003c`/`\\u003e` in its JSON.

Covered here:
  - ClientRouteMap.api_views / views_for_api: a view's GET calls are kept by
    route (never a value), object ids collapse, the map persists and merges;
    controls: a POST call, another origin's API, an excluded view, a view on
    another origin;
  - through the production path (the SPA crawl of build_engagement builds the
    map; ValidatorRegistry.for_finding and bind_run_context dispatch the
    stored_xss leg; a real browser loads the view): the board view runs the
    stored payload (confirmed); with no run map, the host's stored snapshot
    gives the view; controls: the inert memo view, an API no view reads, and no
    map at all are not confirmed;
  - a recording browser: a view that raises a page error is a candidate, never
    a negative; no browser leaves a candidate; the identity headers, not the
    API call's Accept, go to the view load.
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
from urllib.parse import urlsplit

from harness import cache, engagement, engagement_builder, global_throttle, store
from harness.browser_driver import ExecutionObservation
from harness.client_routes import ClientRouteMap
from harness.models import Finding, HttpExchange
from harness.role_crawl import RoleSession
from harness.run_context import RunContext
from harness.test_spa_declared_views import _CHROMIUM, _config
from harness.validators import route_candidates
from harness.validators.registry import ValidatorRegistry
from harness.validators.stored_xss_validator import StoredXssValidator

LOW = RoleSession("user", {"Authorization": "Bearer low-token"}, name="low-user")

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>Board</title></head>
<body><nav><a href="#/board">Board</a> <a href="#/memos">Memos</a></nav>
<main id="view">home</main><script>
function render() {
  var path = (location.hash.slice(1) || "/").split("?")[0];
  var view = document.getElementById("view");
  if (path === "/board") {
    fetch("/api/notes").then(function (r) { return r.json(); }).then(function (list) {
      view.innerHTML = list.map(function (n) { return "<p>" + n.text + "</p>"; }).join("");
    });
  } else if (path === "/memos") {
    fetch("/api/memos").then(function (r) { return r.json(); }).then(function (list) {
      view.textContent = list.map(function (n) { return n.text; }).join(" ");
    });
  } else { view.textContent = "home"; }
}
window.addEventListener("hashchange", render); render();
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    stores = {"notes": [], "memos": [], "orphans": []}

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            return self._reply(_SHELL, "text/html")
        name = path.rsplit("/", 1)[-1]
        if path.startswith("/api/") and name in self.stores:
            text = json.dumps(self.stores[name])
            if name == "notes":
                text = text.replace("<", "\\u003c").replace(">", "\\u003e")
            return self._reply(text, "application/json")
        self._reply("", "text/plain", 404)

    def do_POST(self):
        path = urlsplit(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        name = path.rsplit("/", 1)[-1]
        if path.startswith("/api/") and name in self.stores:
            try:
                text = str((json.loads(body or b"{}") or {}).get("text", ""))
            except ValueError:
                return self._reply("", "text/plain", 400)
            self.stores[name].append({"text": text})
            return self._reply(json.dumps({"ok": True}), "application/json", 201)
        self._reply("", "text/plain", 404)

    def _reply(self, text, ctype, status=200):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _reset():
    for v in _Handler.stores.values():
        v.clear()


def _finding():
    return Finding(vulnerability_class="stored_xss", confidence=0.5, summary="stored xss candidate",
                   evidence="", suggested_test="plant and render", basis="assumed", severity="high")


def _write(base, path):
    return HttpExchange(url=f"{base}{path}", method="POST",
                        request_headers={"Content-Type": "application/json",
                                         "Accept": "application/json",
                                         "Authorization": "Bearer low-token"},
                        request_body='{"text": "hello"}', response_status=201,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"ok": true}')


# The run's own gate, built by RunContext.create with the run's scope folded in.
_GATE = {"active_enabled": True, "allow_mutating_replay": True}


class ApiViewsMapTest(unittest.TestCase):
    B = "http://board.test"

    def _map(self, view, calls):
        m = ClientRouteMap()
        m.add_url(f"{self.B}/", "crawl")
        m.add_view_calls(view, calls)
        m.finalize()
        return m

    def test_a_views_get_call_is_kept_by_route(self):
        m = self._map(f"{self.B}/#/board?sort=newest", [
            ("GET", f"{self.B}/api/notes?limit=20", ""),
            ("POST", f"{self.B}/api/notes", '{"text": "x"}')])
        self.assertEqual(m.views_for_api("GET", f"{self.B}/api/notes"), [f"{self.B}/#/board"])
        self.assertEqual(m.views_for_api("POST", f"{self.B}/api/notes"), [])
        self.assertNotIn("newest", json.dumps(m.to_dict()))

    def test_object_ids_collapse_and_the_map_persists_and_merges(self):
        m = self._map(f"{self.B}/board", [("GET", f"{self.B}/api/notes/42", "")])
        self.assertEqual(m.views_for_api("GET", f"{self.B}/api/notes/9"), [f"{self.B}/board"])
        again = ClientRouteMap.from_dict(json.loads(json.dumps(m.to_dict())))
        self.assertEqual(again.views_for_api("GET", f"{self.B}/api/notes/7"), [f"{self.B}/board"])
        merged = ClientRouteMap()
        merged.merge(again)
        self.assertEqual(merged.views_for_api("GET", f"{self.B}/api/notes/1"), [f"{self.B}/board"])

    def test_control_other_origins_and_excluded_views_are_not_kept(self):
        m = self._map(f"{self.B}/#/board", [("GET", "http://cdn.test/api/notes", "")])
        self.assertEqual(m.views_for_api("GET", f"{self.B}/api/notes"), [])
        m = self._map(f"{self.B}/#/logout", [("GET", f"{self.B}/api/notes", "")])
        self.assertEqual(m.views_for_api("GET", f"{self.B}/api/notes"), [])
        m = self._map("http://other.test/#/board", [("GET", "http://other.test/api/notes", "")])
        self.assertEqual(m.views_for_api("GET", "http://other.test/api/notes"), [])


class _Recorder:
    """A browser that loads nothing and records each view load and its headers."""
    def __init__(self, obs=None):
        self.calls, self._obs = [], obs or {}

    async def visit(self, url, *, wait_ms=1200, headers=None, **_kw):
        self.calls.append((url, dict(headers or {}), wait_ms))
        return ExecutionObservation(url=url, **self._obs)


class _NoBrowser:
    async def visit(self, url, **_kw):
        raise RuntimeError("no browser here")


class ViewSignalTest(unittest.TestCase):
    """The view branch with a recording browser over the real loopback API."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _reset()
        global_throttle.configure(0)

    def _validate(self, driver, path="/api/notes"):
        m = ClientRouteMap()
        m.add_url(f"{self.base}/", "crawl")
        m.add_view_calls(f"{self.base}/#/board", [("GET", f"{self.base}/api/notes", "")])
        m.finalize()

        async def run():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], gate_config=_GATE) as ctx:
                ctx.client_routes = m
                v = StoredXssValidator(allowed_hosts=["127.0.0.1"], driver=driver, run_context=ctx)
                return await v.validate(_finding(), _write(self.base, path))
        return asyncio.run(run())

    def test_the_view_is_loaded_with_the_identity_not_the_api_headers(self):
        rec = _Recorder()
        res = self._validate(rec)
        self.assertEqual(res.status, "not_confirmed", res.summary)
        self.assertIn("/#/board", res.evidence)
        self.assertTrue(rec.calls)
        url, headers, wait_ms = rec.calls[0]
        self.assertEqual(url, f"{self.base}/#/board")
        self.assertEqual(headers, {"Authorization": "Bearer low-token"})
        self.assertGreater(wait_ms, 1200)
        self.assertLessEqual(len(rec.calls), 3)      # one view, once per payload shape

    def test_a_page_error_in_the_view_is_a_candidate_not_a_negative(self):
        res = self._validate(_Recorder({"page_errors": ["TypeError: x is undefined"]}))
        self.assertEqual(res.status, "inconclusive", res.summary)
        self.assertIn("/#/board", res.summary)

    def test_no_browser_leaves_a_candidate(self):
        res = self._validate(_NoBrowser())
        self.assertEqual(res.status, "inconclusive", res.summary)

    def test_control_an_api_no_view_reads_loads_no_view(self):
        rec = _Recorder()
        res = self._validate(rec, "/api/orphans")
        self.assertEqual(res.status, "not_confirmed", res.summary)
        self.assertEqual(rec.calls, [])
        self.assertNotIn("client view", res.evidence)


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class StoredViewsCallerTest(unittest.TestCase):
    """The SPA crawl builds the map, the registry dispatches the leg, and a real
    browser loads the view."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="stored_views_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))
        route_candidates._STORED.clear()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        global_throttle.configure(0)
        from harness.orchestrator_helpers import per_run_gate_config
        cfg = _config()

        async def build():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                return await engagement_builder.build_engagement(
                    cls.base, [LOW], allowed_hosts=["127.0.0.1"], crawl_max_pages=4,
                    active_discovery=False, run_context=ctx,
                    driver_capture_config={"enabled": True, "spa_navigation": True,
                                           "wait_ms": 500, "max_views": 8})
        cls.state, _result = asyncio.run(build())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        route_candidates._STORED.clear()
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def setUp(self):
        _reset()
        global_throttle.configure(0)
        route_candidates._STORED.clear()

    def _dispatch(self, path, routes):
        reg = ValidatorRegistry({"validators": {"active_enabled": True,
                                                "allow_mutating_replay": True}})
        exchange = _write(self.base, path)
        matched = [v for v in reg.for_finding(_finding(), exchange) if v.name == "stored_xss"]
        self.assertTrue(matched, "the registry did not route the write to stored_xss")

        async def run():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], gate_config=_GATE) as ctx:
                ctx.client_routes = routes
                leg = reg.bind_run_context(matched, ctx)[0]
                return await leg.validate(_finding(), exchange)
        return asyncio.run(run())

    def test_the_crawl_saw_each_view_read_its_api(self):
        routes = self.state.client_routes
        self.assertEqual(routes.views_for_api("GET", f"{self.base}/api/notes"),
                         [f"{self.base}/#/board"])
        self.assertEqual(routes.views_for_api("GET", f"{self.base}/api/memos"),
                         [f"{self.base}/#/memos"])
        self.assertEqual(routes.views_for_api("GET", f"{self.base}/api/orphans"), [])

    def test_the_board_view_runs_the_payload_stored_in_the_json_api(self):
        res = self._dispatch("/api/notes", self.state.client_routes)
        self.assertEqual(res.status, "confirmed", f"{res.summary} | {res.evidence}")
        self.assertIn("client view /#/board", res.summary)

    def test_without_a_run_map_the_hosts_stored_snapshot_gives_the_view(self):
        engagement.persist_surface(self.state)
        res = self._dispatch("/api/notes", None)
        self.assertEqual(res.status, "confirmed", f"{res.summary} | {res.evidence}")

    def test_control_the_text_rendering_view_does_not_confirm(self):
        res = self._dispatch("/api/memos", self.state.client_routes)
        self.assertEqual(res.status, "not_confirmed", f"{res.summary} | {res.evidence}")
        self.assertIn("/#/memos", res.evidence)

    def test_control_an_api_no_view_reads_does_not_confirm(self):
        res = self._dispatch("/api/orphans", self.state.client_routes)
        self.assertEqual(res.status, "not_confirmed", f"{res.summary} | {res.evidence}")

    def test_control_no_route_map_does_not_confirm(self):
        kept, store._DB_PATH = store._DB_PATH, Path(self._tmp) / "empty.db"
        try:
            self.assertIsNone(route_candidates.stored_routes(f"{self.base}/api/notes"))
            res = self._dispatch("/api/notes", None)
        finally:
            store._DB_PATH = kept
            route_candidates._STORED.clear()
        self.assertEqual(res.status, "not_confirmed", f"{res.summary} | {res.evidence}")


if __name__ == "__main__":
    unittest.main()
