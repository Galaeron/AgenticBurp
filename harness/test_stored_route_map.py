"""A validator run without a route map of its own (no run context, or a run that
built none) reads the client route map the host's stored engagement snapshot
carries, so an API call is still tested through the page route that issued it.

The fixture is a generic loopback app: `/` is a hash-routed shell whose view
`#/lookup?ref=` writes `ref` into `innerHTML` and fetches `/api/lookup?code=<ref>`
(JSON). The API exchange alone can never run script; the page route can.

Covered here:
  - route_candidates.stored_routes: the map of the host's snapshot, None for no
    snapshot, another host or a snapshot without routes;
  - DomXssValidator with a recording browser: the mapped page route is loaded
    for the API exchange from the stored map; controls: no snapshot, another
    host's snapshot, and a run whose own map wins over the stored one;
  - a real browser, the snapshot written by engagement.persist_surface (what
    investigate_engagement calls): the standalone validation of the API
    exchange confirms DOM XSS through the route parameter; without the snapshot
    it does not.
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
from types import SimpleNamespace
from urllib.parse import urlsplit

from harness import cache, engagement, global_throttle, store
from harness.client_routes import ClientRouteMap
from harness.models import Finding, HttpExchange
from harness.test_spa_route_xss import _CHROMIUM
from harness.validators import route_candidates
from harness.validators.dom_xss_validator import DomXssValidator

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>Lookup</title></head>
<body><main id="view">home</main><script>
function render() {
  var frag = location.hash.slice(1) || "/", path = frag.split("?")[0];
  var ref = new URLSearchParams(frag.split("?")[1] || "").get("ref");
  var view = document.getElementById("view");
  if (path === "/lookup" && ref !== null) {
    view.innerHTML = "Result for " + ref;
    fetch("/api/lookup?code=" + encodeURIComponent(ref));
  } else { view.textContent = "home"; }
}
window.addEventListener("hashchange", render); render();
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            self._reply(_SHELL, "text/html")
        elif path == "/api/lookup":
            self._reply(json.dumps({"found": []}), "application/json")
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


def _map(base) -> ClientRouteMap:
    """The map a browser crawl builds after `#/lookup?ref=lamp` fired the API."""
    routes = ClientRouteMap()
    routes.add_url(f"{base}/", "crawl")
    routes.add_view_calls(f"{base}/#/lookup?ref=lamp",
                          [("GET", f"{base}/api/lookup?code=lamp", "")])
    routes.finalize()
    return routes


def _persist(base, routes=None):
    host = urlsplit(base).netloc
    state = engagement.EngagementState(host=host)
    state.client_routes = routes if routes is not None else _map(base)
    engagement.persist_surface(state)


def _api_exchange(base):
    url = f"{base}/api/lookup?code=lamp"
    return HttpExchange(url=url, method="GET", response_status=200,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"found": []}')


def _finding():
    return Finding(vulnerability_class="dom_xss", confidence=0.5, summary="xss candidate",
                   evidence="", suggested_test="load it in a browser", basis="assumed",
                   severity="high")


class _Recorder:
    """A browser that executes nothing and records what it was asked to load."""
    def __init__(self):
        self.visited = []

    async def visit(self, url, *, wait_ms=1500, headers=None, **_kw):
        from harness.browser_driver import ExecutionObservation
        self.visited.append(url)
        return ExecutionObservation(url=url)


class _Store(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="stored_route_map_")
        self._orig_db, self._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        route_candidates._STORED.clear()
        global_throttle.configure(0)

    def tearDown(self):
        store._DB_PATH, cache._cache = self._orig_db, self._orig_cache
        route_candidates._STORED.clear()
        shutil.rmtree(self._tmp, ignore_errors=True)


class StoredRoutesTest(_Store):
    BASE = "http://lookup.test"

    def test_the_snapshot_map_is_read_for_its_host(self):
        _persist(self.BASE)
        routes = route_candidates.stored_routes(f"{self.BASE}/api/lookup?code=x")
        self.assertIsNotNone(routes)
        links = [(r.endpoint_key, rp, ap) for r, rp, ap in
                 routes.routes_for_api("GET", f"{self.BASE}/api/lookup?code=x")]
        self.assertEqual(links, [("GET /#/lookup", "ref", "code")])

    def test_control_no_snapshot_another_host_or_no_routes_is_none(self):
        self.assertIsNone(route_candidates.stored_routes(f"{self.BASE}/api/lookup"))
        _persist("http://other.test")
        route_candidates._STORED.clear()
        self.assertIsNone(route_candidates.stored_routes(f"{self.BASE}/api/lookup"))
        engagement.persist_surface(engagement.EngagementState(host="bare.test"))
        self.assertIsNone(route_candidates.stored_routes("http://bare.test/api/lookup"))
        self.assertIsNone(route_candidates.stored_routes("not a url"))


class StandaloneCandidatesTest(_Store):
    BASE = "http://lookup.test"

    def _visited(self, run_context=None):
        rec = _Recorder()
        v = DomXssValidator(driver=rec, allowed_hosts=["lookup.test"], max_visits=12, wait_ms=100)
        if run_context is not None:
            v.run_context = run_context
        asyncio.run(v.validate(_finding(), _api_exchange(self.BASE)))
        return [u for u in rec.visited if "#/lookup?" in u]

    def test_a_standalone_run_loads_the_mapped_page_route(self):
        _persist(self.BASE)
        urls = self._visited()
        self.assertTrue(urls)
        for url in urls:
            self.assertTrue(url.startswith(f"{self.BASE}/#/lookup?ref="), url)

    def test_control_without_a_snapshot_no_page_route_is_loaded(self):
        self.assertEqual(self._visited(), [])

    def test_control_another_hosts_snapshot_is_not_used(self):
        _persist("http://other.test", _map("http://other.test"))
        self.assertEqual(self._visited(), [])

    def test_control_a_runs_own_map_wins_over_the_stored_one(self):
        _persist(self.BASE)
        own = ClientRouteMap()     # the run built a map, and it maps nothing here
        own.add_url(f"{self.BASE}/", "crawl")
        own.finalize()
        ctx = SimpleNamespace(client_routes=own)
        self.assertEqual(route_candidates.mapped_routes(
            _api_exchange(self.BASE), ["x"], ctx), [])
        self.assertTrue(route_candidates.mapped_routes(_api_exchange(self.BASE), ["x"], None))


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class StandaloneRealBrowserTest(_Store):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _validate(self):
        v = DomXssValidator(allowed_hosts=["127.0.0.1"], max_visits=8, wait_ms=600)
        return asyncio.run(v.validate(_finding(), _api_exchange(self.base)))

    def test_the_api_exchange_is_confirmed_through_the_stored_page_route(self):
        _persist(self.base)
        res = self._validate()
        self.assertEqual(res.status, "confirmed", res.summary)
        self.assertIn("fragment route parameter 'ref'", res.summary)

    def test_control_without_the_snapshot_the_api_exchange_is_not_confirmed(self):
        res = self._validate()
        self.assertNotEqual(res.status, "confirmed", res.summary)


if __name__ == "__main__":
    unittest.main()
