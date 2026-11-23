"""Path-segment route inputs: a router-declared `:name` segment (`/item/:id`) is an
input of its route, and the browser XSS legs test it with a payload in that segment.

The fixture is a generic loopback app:
  - `/` is a hash-routed shell. Its bundle (`/static/app.js`) configures hash
    routing and declares `item/:id` (the view writes the segment into
    `innerHTML`: a DOM sink), `doc/:name` (written with `textContent`: rendered
    safely), and three paths that are no segment input (a wildcard, a file, and
    a destructive-looking one). Nothing links to any of them.
  - `/page/<slug>` is a history-routed page whose script writes its own path
    segment into `innerHTML` (the server never echoes it); `/echo/<slug>` is
    one whose server reflects the segment raw into the HTML.

Covered here:
  - client_routes: the segment names of a route path, the router paths the
    bundle declares with one, the payload URL for a hash and a history route,
    the coverage template and its persistence, the case each leg can target;
  - candidates (a recording browser): a segment dispatch replaces the `:name`
    segment only, and a name the URL has no segment for is not tested;
  - a real browser: the history-route DOM sink is confirmed by dom_xss, the
    server reflection is browser_xss's (dom_xss says reflected);
  - through investigate_engagement (discovery is real, no browser crawl): the
    hash route's segment DOM sink is confirmed on its `segment` case, and the
    safely rendered one concludes clean.
"""
import asyncio
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html import escape
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import unquote, urlsplit

from harness import cache, global_throttle, store
from harness.client_routes import (HASH, SEGMENT, ClientRoute, ClientRouteMap, payload_url,
                                   route_segments, route_segments_of_template)
from harness.coverage_model import (CaseKey, CellStatus, CoverageMatrix,
                                    derive_input_cases_from_template)
from harness.models import Finding, HttpExchange
from harness.role_crawl import RoleSession
from harness.test_spa_route_xss import _CHROMIUM, _config
from harness.validators.browser_xss_validator import BrowserXssValidator
from harness.validators.dom_xss_validator import DomXssValidator
from harness.validators.injection_targets import NAMED_PARAMETER_UNTESTED, case_target
from harness.chain_stage_patch import chain_patch

ROLES = [RoleSession("anonymous", {})]
REFLECTED, DOM = "WSTG-INJT-01", "WSTG-CLNT-01"

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>Shelf</title></head>
<body><main id="view">home</main><script src="/static/app.js"></script></body></html>"""

_APP_JS = """(function () {
  var config = {useHash: true};
  var routes = [
    {path: "", view: "home"},
    {path: "item/:id", view: "item"},
    {path: "doc/:name?", view: "doc"},
    {path: "files/:file/raw.txt", view: "file"},
    {path: "account/:id/delete", view: "gone"},
    {path: ":rest*", view: "any"}
  ];
  function render() {
    var p = (location.hash.slice(1) || "/").split("?")[0], m;
    var view = document.getElementById("view");
    if ((m = p.match(/^\\/item\\/([^\\/]+)$/))) {
      view.innerHTML = "<h2>Item " + decodeURIComponent(m[1]) + "</h2>";
    } else if ((m = p.match(/^\\/doc\\/([^\\/]+)$/))) {
      view.textContent = "Doc " + decodeURIComponent(m[1]);
    } else {
      view.textContent = "home";
    }
  }
  window.addEventListener("hashchange", render);
  render();
})();
"""

_PAGE = """<!doctype html><html><body><div id="o"></div><script>
document.getElementById("o").innerHTML =
  "Page " + decodeURIComponent(location.pathname.split("/")[2] || "");
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            self._reply(_SHELL, "text/html")
        elif path == "/static/app.js":
            self._reply(_APP_JS, "application/javascript")
        elif path.startswith("/page/"):
            self._reply(_PAGE, "text/html")
        elif path.startswith("/echo/"):
            self._reply("<!doctype html><html><body><h1>"
                        + unquote(path.split("/", 2)[2]) + "</h1></body></html>", "text/html")
        elif path.startswith("/text/"):
            self._reply("<p>" + escape(unquote(path.split("/", 2)[2])) + "</p>", "text/html")
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


class _Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="spa_route_segments_")
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

    def setUp(self):
        global_throttle.configure(0)


def _bundle_map(base="http://shelf.test") -> ClientRouteMap:
    routes = ClientRouteMap()
    routes.add_url(f"{base}/", "crawl")
    routes.mine_script(_APP_JS)
    routes.finalize()
    return routes


# --------------------------------------------------------------------------
# client_routes
# --------------------------------------------------------------------------

class SegmentRoutesTest(unittest.TestCase):
    def test_the_segment_names_of_a_route_path(self):
        self.assertEqual(route_segments("/item/:id"), ["id"])
        self.assertEqual(route_segments("/a/:x/b/:y?"), ["x", "y"])
        self.assertEqual(route_segments("/item/42"), [])

    def test_the_bundle_declares_segment_routes_and_nothing_else_becomes_one(self):
        segs = {r.endpoint_key: r.segments for r in _bundle_map().inputs()}
        self.assertEqual(segs, {"GET /#/item/:id": ["id"], "GET /#/doc/:name": ["name"]})

    def test_a_payload_replaces_only_its_segment(self):
        self.assertEqual(payload_url("http://shelf.test/#/item/:id?tab=1", SEGMENT, "id", "<b>/x"),
                         "http://shelf.test/#/item/%3Cb%3E%2Fx?tab=1")
        self.assertEqual(payload_url("http://shelf.test/page/:slug?x=1#top", SEGMENT, "slug", "a b"),
                         "http://shelf.test/page/a%20b?x=1")
        self.assertIsNone(payload_url("http://shelf.test/#/item/:id", SEGMENT, "name", "x"))
        self.assertIsNone(payload_url("http://shelf.test/item/7", SEGMENT, "id", "x"))

    def test_the_template_case_and_persistence_carry_the_segment(self):
        route = ClientRoute(HASH, "/", "/item/:id")
        tmpl = route.template()
        self.assertEqual(route_segments_of_template(tmpl), ["id"])
        cases = derive_input_cases_from_template(tmpl)
        self.assertIn((SEGMENT, "id"), [(c.parameter_location, c.parameter_name) for c in cases])
        restored = ClientRouteMap.from_dict(_bundle_map().to_dict())
        self.assertEqual(sorted(r.endpoint_key for r in restored.inputs()),
                         ["GET /#/doc/:name", "GET /#/item/:id"])

    def test_a_merged_map_keeps_the_segment_routes(self):
        # build_engagement merges each role crawl's map into its own.
        crawled = ClientRouteMap()
        crawled.add_url("http://shelf.test/", "crawl")
        crawled.mine_script(_APP_JS)
        merged = ClientRouteMap()
        merged.merge(crawled)
        merged.finalize()
        self.assertEqual({r.endpoint_key: r.segments for r in merged.inputs()},
                         {"GET /#/item/:id": ["id"], "GET /#/doc/:name": ["name"]})

    def test_only_the_browser_legs_target_a_segment(self):
        ck = CaseKey(SEGMENT, "id", 0, "", "id")
        self.assertEqual(case_target("dom_xss", ck), (SEGMENT, "id"))
        self.assertEqual(case_target("browser_xss", ck), (SEGMENT, "id"))
        self.assertIsNone(case_target("sqlmap", ck))
        self.assertIsNone(case_target("path_traversal", ck))

    def test_control_a_route_without_a_segment_or_parameter_is_no_input(self):
        routes = ClientRouteMap()
        routes.add_url("http://shelf.test/#/item/42", "crawl")
        routes.mine_script("var routes = [{path: 'about'}, {path: 'item/42'}];")
        self.assertEqual(routes.inputs(), [])


# --------------------------------------------------------------------------
# Candidates (a recording browser)
# --------------------------------------------------------------------------

class _Recorder:
    """A browser that executes nothing and records what it was asked to load."""
    def __init__(self):
        self.visited = []

    async def visit(self, url, *, wait_ms=1500, headers=None, **_kw):
        from harness.browser_driver import ExecutionObservation
        self.visited.append(url)
        return ExecutionObservation(url=url)


def _finding(cls="dom_xss", **kw):
    return Finding(vulnerability_class=cls, confidence=0.5, summary="xss candidate",
                   evidence="", suggested_test="load it in a browser", basis="assumed",
                   severity="high", **kw)


def _segment(name):
    return dict(parameter_location=SEGMENT, parameter_name=name, parameter_only=True)


def _validate(validator_cls, url, *, driver=None, max_visits=4, **finding_kw):
    v = validator_cls(driver=driver, allowed_hosts=["127.0.0.1", "shelf.test"],
                      max_visits=max_visits, wait_ms=600)
    cls = "dom_xss" if validator_cls is DomXssValidator else "xss"
    ex = HttpExchange(url=url, method="GET", response_status=200, response_headers={})
    return asyncio.run(v.validate(_finding(cls, **finding_kw), ex))


class SegmentCandidateTest(unittest.TestCase):
    def test_a_segment_dispatch_replaces_the_segment_only(self):
        for validator_cls in (DomXssValidator, BrowserXssValidator):
            rec = _Recorder()
            res = _validate(validator_cls, "http://shelf.test/#/item/:id?tab=1", driver=rec,
                            **_segment("id"))
            self.assertTrue(rec.visited, validator_cls.__name__)
            for url in rec.visited:
                frag = urlsplit(url).fragment
                self.assertTrue(frag.startswith("/item/"), url)
                self.assertNotIn(":id", frag)
                self.assertTrue(frag.endswith("?tab=1"), url)
            self.assertEqual(res.tested_parameters, ((SEGMENT, "id"),))

    def test_control_a_name_without_a_segment_is_not_tested(self):
        for validator_cls in (DomXssValidator, BrowserXssValidator):
            rec = _Recorder()
            res = _validate(validator_cls, "http://shelf.test/#/item/7", driver=rec,
                            **_segment("id"))
            self.assertEqual(res.status, "skipped", validator_cls.__name__)
            self.assertEqual(res.control_outcome, NAMED_PARAMETER_UNTESTED)
            self.assertEqual(rec.visited, [])
            self.assertIn("path segment", res.summary)


# --------------------------------------------------------------------------
# A real browser
# --------------------------------------------------------------------------

@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class RealBrowserSegmentTest(_Server):
    def test_a_history_route_segment_written_to_the_dom_is_dom_xss(self):
        res = _validate(DomXssValidator, f"{self.base}/page/:slug", **_segment("slug"))
        self.assertEqual(res.status, "confirmed", res.summary)
        self.assertIn("route path segment :slug", res.summary)
        self.assertIn("location.pathname", res.evidence)

    def test_a_server_reflected_segment_is_browser_xss_not_dom_xss(self):
        res = _validate(BrowserXssValidator, f"{self.base}/echo/:slug", **_segment("slug"))
        self.assertEqual(res.status, "confirmed", res.summary)
        self.assertIn("route path segment :slug", res.summary)
        res = _validate(DomXssValidator, f"{self.base}/echo/:slug", **_segment("slug"))
        self.assertEqual(res.status, "inconclusive", res.summary)
        self.assertIn("reflected XSS", res.summary + res.evidence)

    def test_control_an_escaped_segment_executes_nothing(self):
        for validator_cls in (DomXssValidator, BrowserXssValidator):
            res = _validate(validator_cls, f"{self.base}/text/:slug", **_segment("slug"))
            self.assertEqual(res.status, "not_confirmed", f"{validator_cls.__name__}: {res.summary}")


# --------------------------------------------------------------------------
# Through investigate_engagement (real discovery)
# --------------------------------------------------------------------------

@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class SegmentCoverageCallerTest(_Server):
    """investigate_engagement over the fixture with its own discovery (the HTML
    crawl mines the bundle; no browser crawl): the agent probe is stubbed and
    every leg but the two browser XSS legs is off."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        global_throttle.configure(0)
        from harness.orchestrator import Orchestrator
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config()
        for leg in ("browser_xss", "dom_xss"):
            cfg["validators"][leg].update(wait_ms=500, max_visits=4)
        orch = Orchestrator(cfg)
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = True
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})

        async def investigate():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(
                                             cfg, orch.validator_registry)) as ctx:
                return await orch.investigate_engagement(
                    cls.base, ROLES, max_nodes=0, step_budget=4, max_chain_rounds=0,
                    run_context=ctx)

        with chain_patch("shape_precondition_legs", return_value=[]):
            cls.result = asyncio.run(investigate())
        coverage = cls.result.get("coverage") or {}
        assert "cases_driven" in coverage, "the case-driven coverage path did not run"
        cls.matrix = CoverageMatrix.from_dict(coverage["checkpoint"]["matrix"])

    def _case(self, ep_key, check):
        for ck, r in self.matrix.cases_for_cell("anonymous", ep_key, check):
            if ck.parameter_location == SEGMENT:
                return r
        self.fail(f"no segment case under {ep_key} {check}: "
                  f"{[c.label() for c, _ in self.matrix.cases_for_cell('anonymous', ep_key, check)]}")

    def test_the_hash_route_segment_dom_sink_is_confirmed(self):
        for check in (DOM, REFLECTED):
            r = self._case("GET /#/item/:id", check)
            self.assertEqual(r.status, CellStatus.CONFIRMED, f"{check}: {r.reason}")
        self.assertIn("route path segment :id", self._case("GET /#/item/:id", DOM).reason)
        confirmed = {(f.get("vulnerability_class"), urlsplit(f.get("url") or "").fragment[:6])
                     for f in self.result.get("findings") or [] if f.get("confirmed")}
        self.assertIn(("dom_xss", "/item/"), confirmed)

    def test_control_the_safely_rendered_segment_concludes_clean(self):
        for check in (DOM, REFLECTED):
            r = self._case("GET /#/doc/:name", check)
            self.assertEqual(r.status, CellStatus.NOT_DETECTED, f"{check}: {r.reason}")

    def test_control_no_excluded_path_became_an_endpoint(self):
        keys = {k for (_i, k, _c) in self.matrix.cells()}
        self.assertIn("GET /#/item/:id", keys)
        for left_out in ("raw.txt", "delete", ":rest"):
            self.assertFalse(any(left_out in k for k in keys), keys)


if __name__ == "__main__":
    unittest.main()
