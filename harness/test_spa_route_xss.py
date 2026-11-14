"""Client-side route inputs for the browser XSS legs, on a generic loopback SPA.

The fixture is a small single-page app on a loopback server:
  - `/` is a hash-routed shell. Its links name `#/find?term=` and `#/note?term=`,
    and its bundle (`/static/app.js`) routes them. `#/find` writes `term` into
    `innerHTML` (a DOM sink); `#/note` writes it with `textContent` (rendered
    safely). Each view fetches a JSON API (`/api/items?q=`, `/api/notes?term=`).
  - `/look?term=` is a history route whose server reflects `term` raw into the
    HTML (a reflected sink), linked from the shell.
  - `/legacy` writes the whole raw fragment into `innerHTML` (the shape the
    fragment-only candidates were built for).

Covered here:
  - discovery: the crawler mines the shell's links and bundle into routes
    (build_engagement), the browser crawl maps each API call back to the route
    of the view that fired it, the map persists and merges without values;
  - candidates: both legs keep their old candidates and add route candidates,
    bounded by max_visits and the scope check; a per-parameter dispatch tests
    its one route or page input;
  - coverage: route inputs get cells for the two browser legs only, and
    investigate_engagement's case drive confirms the hash-route DOM sink and the
    history-route reflected sink, with negative controls (the safely rendered
    route, the JSON API URL, the old fragment-only candidates).
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
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl, urlsplit

import yaml

from harness import cache, coverage_tracker, engagement, engagement_builder, store
from harness.client_routes import (HASH, HISTORY, PAGE, ROUTE, ClientRouteMap, fragment_route,
                                   payload_url)
from harness.coverage_model import (CHECKS_BY_ID, CellStatus, CoverageMatrix,
                                    derive_input_cases_from_template)
from harness.models import Finding, HttpExchange
from harness.role_crawl import RoleSession
from harness.validators.browser_xss_validator import BrowserXssValidator
from harness.validators.dom_xss_validator import DomXssValidator
from harness.validators.injection_targets import NAMED_PARAMETER_UNTESTED, case_target

_HARNESS = Path(__file__).resolve().parent
ROLES = [RoleSession("anonymous", {})]
REFLECTED, STORED, DOM, SQLI = "WSTG-INPV-01", "WSTG-INPV-02", "WSTG-CLNT-01", "WSTG-INPV-05"

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>Catalog</title></head>
<body><nav>
<a href="#/find?term=lamp">Find</a>
<a href="#/note?term=lamp">Notes</a>
<a href="/look?term=chair">Look</a>
<a href="https://elsewhere.invalid/#/away?term=x">Away</a>
</nav><main id="view"></main>
<script src="/static/app.js"></script></body></html>"""

# The router reads `term` from the fragment route's own query.
_APP_JS = """(function () {
  var routes = [{path: "find"}, {path: "note"}];
  function current() {
    var h = location.hash.slice(1), i = h.indexOf("?");
    var qs = i < 0 ? "" : h.slice(i + 1);
    return {path: i < 0 ? h : h.slice(0, i), term: new URLSearchParams(qs).get("term") || ""};
  }
  function render() {
    var r = current(), view = document.getElementById("view");
    if (r.path === "/find") {
      view.innerHTML = "<h2>Results for " + r.term + "</h2>";
      fetch("/api/items?q=" + encodeURIComponent(r.term)).then(function (x) { return x.json(); });
    } else if (r.path === "/note") {
      view.textContent = "Notes about " + r.term;
      fetch("/api/notes?term=" + encodeURIComponent(r.term)).then(function (x) { return x.json(); });
    }
  }
  window.addEventListener("hashchange", render);
  render();
})();
"""

_LEGACY = """<!doctype html><html><body><div id="o"></div><script>
document.getElementById("o").innerHTML = decodeURIComponent(location.hash.slice(1));
</script></body></html>"""


class _SpaHandler(BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):
        parts = urlsplit(self.path)
        _SpaHandler.seen.append(self.path)
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        if parts.path == "/":
            self._reply(_SHELL, "text/html")
        elif parts.path == "/static/app.js":
            self._reply(_APP_JS, "application/javascript")
        elif parts.path == "/legacy":
            self._reply(_LEGACY, "text/html")
        elif parts.path == "/private":
            # The same raw-hash sink, served only to the captured identity.
            if self.headers.get("Authorization") != "Bearer fixture-token":
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._reply(_LEGACY, "text/html")
        elif parts.path == "/look":
            # The reflected sink: the history route's server echoes `term` raw.
            self._reply(f"<!doctype html><html><body><h2>Looking for {params.get('term', '')}"
                        f"</h2></body></html>", "text/html")
        elif parts.path == "/api/items":
            self._reply(json.dumps({"q": params.get("q", ""), "items": []}), "application/json")
        elif parts.path == "/api/notes":
            self._reply(json.dumps({"term": params.get("term", ""), "notes": []}),
                        "application/json")
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


_CHROMIUM = _chromium_available()


def _config(enabled=("browser_xss", "dom_xss")) -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    validators = cfg.setdefault("validators", {})
    validators["active_enabled"] = True
    for name in ("sqlmap", "browser_xss", "stored_xss", "dom_xss", "command_injection", "xxe",
                 "ssrf", "nosql", "jwt_forge", "deserialization_oob", "path_traversal",
                 "sequence", "auth_sequence", "verb_tamper", "csrf", "file_upload", "rate_limit",
                 "reset_token", "toctou", "race_condition", "csp", "cors", "header_injection",
                 "http_request_smuggling", "ssti", "open_redirect", "cross_identity", "idor_read",
                 "security_headers", "error_handling", "content_exposure"):
        validators.setdefault(name, {})["enabled"] = name in enabled
    for name in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(name, {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


def _crawl(base):
    """What a browser crawl of the fixture records: the views it loaded, the links
    it saw, and the API call each view fired (with the values it sent)."""
    return SimpleNamespace(
        views=[f"{base}/", f"{base}/#/find?term=lamp", f"{base}/#/note?term=lamp"],
        links=[f"{base}/#/find?term=lamp", f"{base}/#/note?term=lamp", f"{base}/look?term=chair"],
        view_calls=[(f"{base}/#/find?term=lamp", "GET", f"{base}/api/items?q=lamp", ""),
                    (f"{base}/#/note?term=lamp", "GET", f"{base}/api/notes?term=lamp", "")])


def _route_map(base) -> ClientRouteMap:
    routes = ClientRouteMap()
    engagement_builder._collect_spa_routes(routes, _crawl(base))
    routes.finalize()
    return routes


def _keys(routes) -> dict:
    return {r.endpoint_key: r for r in routes.routes()}


class _Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="spa_route_xss_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _SpaHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

class RouteDiscoveryTest(_Server):
    def test_build_engagement_mines_the_shell_links_and_bundle(self):
        """The crawler's HTML and bundle mining, through build_engagement: both hash
        routes and the history route are inputs, the app is hash-routed, and neither
        a JSON API URL nor a cross-origin link becomes a route."""
        state, _rc = asyncio.run(engagement_builder.build_engagement(
            self.base, ROLES, allowed_hosts=["127.0.0.1"], crawl_max_pages=8,
            active_discovery=False))
        routes = state.client_routes
        self.assertIsNotNone(routes, "no client routes were collected")
        inputs = {r.endpoint_key: r for r in routes.inputs()}
        self.assertEqual(inputs["GET /#/find"].kind, HASH)
        self.assertEqual(inputs["GET /#/find"].params, ["term"])
        self.assertEqual(inputs["GET /#/note"].params, ["term"])
        self.assertEqual(inputs["GET /look"].kind, HISTORY)
        self.assertEqual(inputs["GET /look"].params, ["term"])
        self.assertTrue(routes.hash_routed())
        self.assertIn("term", routes.read_names, "the bundle's URLSearchParams read was not mined")
        self.assertFalse(any(k.startswith("GET /api/") for k in inputs), inputs)
        self.assertFalse(any("away" in k for k in inputs), "a cross-origin link became a route")

    def test_a_view_call_maps_back_to_the_route_that_fired_it(self):
        """The API call a view fired is linked to that view's route parameter by the
        value it carried (`term=lamp` -> `q=lamp`); the map keeps names, not values."""
        routes = _route_map(self.base)
        links = routes.routes_for_api("GET", f"{self.base}/api/items?q=anything")
        self.assertEqual([(r.endpoint_key, rp, ap) for r, rp, ap in links],
                         [("GET /#/find", "term", "q")])
        links = routes.routes_for_api("GET", f"{self.base}/api/notes?term=x")
        self.assertEqual([(r.endpoint_key, rp, ap) for r, rp, ap in links],
                         [("GET /#/note", "term", "term")])
        self.assertEqual(routes.routes_for_api("GET", f"{self.base}/api/other?q=1"), [])
        self.assertNotIn("lamp", json.dumps(routes.to_dict()))

    def test_a_call_with_no_matching_value_or_read_name_is_not_linked(self):
        routes = ClientRouteMap()
        routes.add_view_calls(f"{self.base}/#/find?term=lamp",
                              [("GET", f"{self.base}/api/items?q=other", ""),
                               ("GET", f"{self.base}/api/clock?ts=1731400000000", "")])
        routes.finalize()
        self.assertEqual(routes.api_links, {})
        self.assertEqual(_keys(routes)["GET /#/find"].params, ["term"])

    def test_a_volatile_route_value_is_not_an_input(self):
        routes = ClientRouteMap()
        routes.add_url(f"{self.base}/#/feed?since=1731400000000&tag=new", "crawl")
        self.assertEqual(_keys(routes)["GET /#/feed"].params, ["tag"])

    def test_the_map_persists_and_merges_with_the_engagement_state(self):
        state = engagement.EngagementState(host="127.0.0.1")
        state.client_routes = _route_map(self.base)
        restored = engagement.EngagementState.from_dict(
            json.loads(json.dumps(state.to_dict())))
        self.assertEqual(sorted(r.endpoint_key for r in restored.client_routes.inputs()),
                         ["GET /#/find", "GET /#/note", "GET /look"])
        self.assertEqual(len(restored.client_routes.routes_for_api(
            "GET", f"{self.base}/api/items?q=z")), 1)
        other = engagement.EngagementState(host="127.0.0.1")
        other.merge_from(restored)
        self.assertEqual(len(other.client_routes.inputs()), 3)

    def test_payload_urls_place_the_payload_in_the_named_input(self):
        url = f"{self.base}/#/find?term=lamp&page=2"
        out = payload_url(url, ROUTE, "term", "<x>")
        self.assertEqual(urlsplit(out).query, "")
        self.assertEqual(fragment_route(urlsplit(out).fragment)[2], "term=%3Cx%3E&page=2")
        self.assertIsNone(payload_url(f"{self.base}/api/items?q=1", ROUTE, "term", "<x>"))
        page = payload_url(f"{self.base}/look?term=chair#top", PAGE, "term", "<x>")
        self.assertEqual(page, f"{self.base}/look?term=%3Cx%3E")


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class BrowserCrawlDiscoveryTest(_Server):
    def test_the_browser_crawl_links_each_api_call_to_its_view_route(self):
        """build_engagement's browser crawl (driver capture, SPA navigation): the
        views it follows and the calls each fires map the JSON APIs to the routes."""
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config()

        async def build():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                return await engagement_builder.build_engagement(
                    self.base, ROLES, allowed_hosts=["127.0.0.1"], crawl_max_pages=8,
                    active_discovery=False, run_context=ctx,
                    driver_capture_config={"enabled": True, "spa_navigation": True,
                                           "wait_ms": 600, "max_views": 8})
        state, _rc = asyncio.run(build())
        routes = state.client_routes
        self.assertIsNotNone(routes)
        found = {(r.endpoint_key, rp, ap)
                 for r, rp, ap in routes.routes_for_api("GET", f"{self.base}/api/items?q=z")}
        self.assertIn(("GET /#/find", "term", "q"), found, routes.summary())
        found = {(r.endpoint_key, rp, ap)
                 for r, rp, ap in routes.routes_for_api("GET", f"{self.base}/api/notes?term=z")}
        self.assertIn(("GET /#/note", "term", "term"), found, routes.summary())


# --------------------------------------------------------------------------
# Candidates (fake driver)
# --------------------------------------------------------------------------

class _Recorder:
    """A browser that executes nothing and records what it was asked to load."""
    def __init__(self):
        self.visited = []

    async def visit(self, url, *, wait_ms=1500, headers=None, **_kw):
        from harness.browser_driver import ExecutionObservation
        self.visited.append(url)
        return ExecutionObservation(url=url)


def _rc(routes):
    """The two run-context seams the legs read: client routes, and a scope the
    fake browser accepts."""
    return SimpleNamespace(client_routes=routes, scope=None, gate=None, budget=None, cancel=None)


def _finding(**kw):
    return Finding(vulnerability_class="xss", confidence=0.5, summary="xss candidate",
                   evidence="", suggested_test="load it in a browser", basis="assumed",
                   severity="high", **kw)


class RouteCandidateTest(_Server):
    def _visits(self, validator_cls, url, rc=None, max_visits=8, response_headers=None,
                **finding_kw):
        driver = _Recorder()
        v = validator_cls(driver=driver, allowed_hosts=["127.0.0.1"], max_visits=max_visits,
                          run_context=rc)
        res = asyncio.run(v.validate(_finding(**finding_kw), HttpExchange(
            url=url, method="GET", response_headers=response_headers or {})))
        return res, driver.visited

    def test_dom_xss_keeps_the_raw_fragment_and_adds_the_route_parameter(self):
        res, visited = self._visits(DomXssValidator, f"{self.base}/#/find?term=lamp")
        raw = [u for u in visited if fragment_route(urlsplit(u).fragment) is None]
        routed = [u for u in visited if fragment_route(urlsplit(u).fragment) is not None]
        self.assertTrue(raw, "the old raw-fragment candidates were dropped")
        self.assertTrue(routed and all(urlsplit(u).fragment.startswith("/find?term=") and "lamp" not in u
                                       for u in routed), visited)
        self.assertEqual(visited[:2], [visited[0], visited[1]])
        self.assertLessEqual(len(visited), 8)
        self.assertEqual(res.status, "not_confirmed")
        self.assertIn("route", res.evidence)

    def test_max_visits_bounds_the_interleaved_candidates(self):
        _res, visited = self._visits(DomXssValidator, f"{self.base}/#/find?term=lamp",
                                     max_visits=2)
        self.assertEqual(len(visited), 2)
        self.assertEqual({fragment_route(urlsplit(u).fragment) is None for u in visited},
                         {True, False}, "each kind of input gets a visit before the cut")

    def test_a_json_api_url_loads_the_route_that_issued_it(self):
        routes = _route_map(self.base)
        url = f"{self.base}/api/items?q=lamp"
        _res, visited = self._visits(BrowserXssValidator, url, rc=_rc(routes))
        self.assertTrue(any(u.startswith(f"{self.base}/api/items?q=") for u in visited))
        self.assertTrue(any(u.startswith(f"{self.base}/#/find?term=%3C") for u in visited),
                        visited)
        # Without a route map the leg is what it was: the API URL's own query only.
        _res, visited = self._visits(BrowserXssValidator, url)
        self.assertTrue(visited and all(u.startswith(f"{self.base}/api/items?q=") for u in visited))

    def test_a_per_parameter_dispatch_tests_its_route_or_page_input_alone(self):
        res, visited = self._visits(DomXssValidator, f"{self.base}/#/find?term=",
                                    parameter_location=ROUTE, parameter_name="term",
                                    parameter_only=True)
        self.assertTrue(visited and all(urlsplit(u).fragment.startswith("/find?term=") and "lamp" not in u
                                        for u in visited), visited)
        self.assertEqual(res.tested_parameters, ((ROUTE, "term"),))
        res, visited = self._visits(BrowserXssValidator, f"{self.base}/look?term=",
                                    parameter_location=PAGE, parameter_name="term",
                                    parameter_only=True)
        self.assertTrue(visited and all(u.startswith(f"{self.base}/look?term=") and "chair" not in u for u in visited))
        self.assertEqual(res.tested_parameters, ((PAGE, "term"),))

    def test_a_route_input_the_url_cannot_carry_is_not_tested(self):
        for cls in (DomXssValidator, BrowserXssValidator):
            res, visited = self._visits(cls, f"{self.base}/api/items?q=1",
                                        parameter_location=ROUTE, parameter_name="term",
                                        parameter_only=True)
            self.assertEqual((res.status, res.control_outcome, visited),
                             ("skipped", NAMED_PARAMETER_UNTESTED, []), cls.__name__)
        # dom_xss reads a query parameter from location.search only in a page: a
        # JSON answer runs no page script, so its query parameter is not loaded.
        res, visited = self._visits(DomXssValidator, f"{self.base}/api/items?q=1",
                                    response_headers={"Content-Type": "application/json"},
                                    parameter_location="query", parameter_name="q",
                                    parameter_only=True)
        self.assertEqual((res.status, res.control_outcome, visited),
                         ("skipped", NAMED_PARAMETER_UNTESTED, []))
        self.assertIn("location.search", res.summary)

    def test_every_candidate_url_has_an_origin_the_driver_can_tell(self):
        """The browser driver sends the captured identity's cookies and headers only
        to the visit URL's own origin, and refuses the page outright without a run
        scope, when it cannot parse that origin; a raw space in a payload made it
        unparseable."""
        from harness.run_context import ScopePolicy
        routes = _route_map(self.base)
        for cls, url in ((DomXssValidator, f"{self.base}/#/find?term=lamp"),
                         (DomXssValidator, f"{self.base}/legacy"),
                         (BrowserXssValidator, f"{self.base}/api/items?q=lamp")):
            _res, visited = self._visits(cls, url, rc=_rc(routes))
            self.assertTrue(visited)
            for u in visited:
                self.assertEqual(ScopePolicy.origin_of(u), self.base, u)

    def test_an_out_of_scope_page_is_never_loaded(self):
        driver = _Recorder()
        v = DomXssValidator(driver=driver, allowed_hosts=["other.invalid"])
        res = asyncio.run(v.validate(_finding(), HttpExchange(
            url=f"{self.base}/#/find?term=x", method="GET")))
        self.assertEqual((res.status, driver.visited), ("skipped", []))


# --------------------------------------------------------------------------
# Coverage cells
# --------------------------------------------------------------------------

class RouteCoverageCellsTest(_Server):
    def _state(self):
        state = engagement.EngagementState(host="127.0.0.1")
        state.ingest_role_crawl({"endpoints": [{
            "method": "GET", "path": "/api/items", "by_role": {"anonymous": 200},
            "reachable_roles": ["anonymous"], "object_scoped": False}], "idor_findings": []})
        state.client_routes = _route_map(self.base)
        return state

    def test_route_inputs_are_cells_of_the_browser_legs_only(self):
        endpoints = coverage_tracker.endpoint_view(self._state())
        ep = endpoints["GET /#/find"]
        self.assertTrue(ep["client_route_only"])
        cases = derive_input_cases_from_template(ep["template"])
        self.assertEqual([(c.parameter_location, c.parameter_name) for c in cases],
                         [(ROUTE, "term")])
        self.assertTrue(CHECKS_BY_ID[DOM].applies(ep)[0])
        self.assertTrue(CHECKS_BY_ID[REFLECTED].applies(ep)[0])
        for check_id in (SQLI, STORED):
            self.assertFalse(CHECKS_BY_ID[check_id].applies(ep)[0], check_id)
        self.assertEqual(case_target("dom_xss", cases[0]), (ROUTE, "term"))
        self.assertEqual(case_target("browser_xss", cases[0]), (ROUTE, "term"))
        self.assertIsNone(case_target("sqlmap", cases[0]))
        self.assertEqual(derive_input_cases_from_template(endpoints["GET /look"]["template"])[0]
                         .parameter_location, PAGE)

    def test_only_the_browser_legs_fan_out_over_a_route_input(self):
        state = self._state()
        endpoints = coverage_tracker.endpoint_view(state)
        # A captured history page that also reads a page parameter of its own.
        endpoints["GET /api/items"]["template"] = {
            "method": "GET", "query": "q=lamp", "body": "", "content_type": "",
            "client_route": {"kind": HISTORY, "location": PAGE, "params": ["q", "sort"]}}
        tracker = coverage_tracker.CoverageTracker()
        tracker.build(endpoints, ["anonymous"], {"anonymous": "anonymous"})
        tracker.expand_parameter_cases(endpoints)
        cases = lambda check: sorted((c.parameter_location, c.parameter_name)  # noqa: E731
                                     for c, _r in tracker.matrix.cases_for_cell(
                                         "anonymous", "GET /api/items", check))
        self.assertEqual(cases(REFLECTED), [("", ""), ("page", "sort"), ("query", "q")])
        self.assertEqual(cases(SQLI), [("", ""), ("query", "q")])


# --------------------------------------------------------------------------
# Real browser: the validators, then the production coverage drive
# --------------------------------------------------------------------------

@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class RealBrowserRouteXssTest(_Server):
    def _run(self, validator_cls, url, rc=None, **finding_kw):
        v = validator_cls(allowed_hosts=["127.0.0.1"], wait_ms=500, run_context=rc)
        return asyncio.run(v.validate(_finding(**finding_kw), HttpExchange(url=url, method="GET")))

    def test_the_hash_route_dom_sink_is_confirmed_by_both_legs(self):
        r = self._run(DomXssValidator, f"{self.base}/#/find?term=lamp")
        self.assertEqual(r.status, "confirmed", r.evidence)
        self.assertIn("fragment route parameter 'term'", r.summary)
        r = self._run(BrowserXssValidator, f"{self.base}/#/find?term=lamp")
        self.assertEqual(r.status, "confirmed", r.evidence)
        self.assertIn("DOM-based", r.summary)

    def test_the_safely_rendered_route_is_not_confirmed(self):
        for cls in (DomXssValidator, BrowserXssValidator):
            r = self._run(cls, f"{self.base}/#/note?term=lamp")
            self.assertEqual(r.status, "not_confirmed", f"{cls.__name__}: {r.summary}")

    def test_the_old_fragment_candidates_miss_the_route_and_still_find_a_raw_hash_sink(self):
        v = DomXssValidator(allowed_hosts=["127.0.0.1"], wait_ms=500)
        v._candidates = lambda ex, a, b, only, loc, rc: v._fragment_candidates(ex, a, b)
        r = asyncio.run(v.validate(_finding(), HttpExchange(url=f"{self.base}/#/find?term=lamp", method="GET")))
        self.assertEqual(r.status, "not_confirmed", "raw fragments reached the route parameter")
        r = self._run(DomXssValidator, f"{self.base}/legacy")
        self.assertEqual(r.status, "confirmed", r.evidence)
        self.assertIn("URL FRAGMENT", r.evidence)

    def test_a_raw_hash_sink_behind_the_identity_is_loaded_as_that_identity(self):
        """Under the run's own context, the raw-fragment candidates carry the
        captured identity's Authorization to the page that needs it."""
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config()

        async def run():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                v = DomXssValidator(allowed_hosts=["127.0.0.1"], wait_ms=500, run_context=ctx)
                return await v.validate(_finding(), HttpExchange(
                    url=f"{self.base}/private", method="GET",
                    request_headers={"Authorization": "Bearer fixture-token"}))
        r = asyncio.run(run())
        self.assertEqual(r.status, "confirmed", r.evidence)
        self.assertIn("URL FRAGMENT", r.evidence)

    def test_the_history_route_reflection_is_browser_xss_not_dom_xss(self):
        kw = dict(parameter_location=PAGE, parameter_name="term", parameter_only=True)
        r = self._run(BrowserXssValidator, f"{self.base}/look?term=", **kw)
        self.assertEqual(r.status, "confirmed", r.evidence)
        self.assertIn("page query parameter 'term'", r.summary)
        self.assertIn("server reflection", r.evidence)
        r = self._run(DomXssValidator, f"{self.base}/look?term=", **kw)
        self.assertEqual(r.status, "inconclusive", r.summary)
        self.assertIn("reflected XSS", r.summary)

    def test_a_json_api_url_confirms_only_through_its_mapped_route(self):
        url = f"{self.base}/api/items?q=lamp"
        for cls in (DomXssValidator, BrowserXssValidator):
            self.assertEqual(self._run(cls, url).status, "not_confirmed", cls.__name__)
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config()

        async def mapped():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                ctx.client_routes = _route_map(self.base)
                v = DomXssValidator(allowed_hosts=["127.0.0.1"], wait_ms=500, run_context=ctx)
                return await v.validate(_finding(), HttpExchange(url=url, method="GET"))
        r = asyncio.run(mapped())
        self.assertEqual(r.status, "confirmed", r.evidence)
        self.assertIn("/#/find", r.summary)


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class SpaRouteCoverageCallerTest(_Server):
    """investigate_engagement's case drive over the fixture. Discovery is canned:
    the two JSON APIs as captured endpoints, and the route map the browser crawl
    builds (through build_engagement's own collection). The agent probe is stubbed
    and every leg but the two browser XSS legs is off."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.matrix = cls._drive()

    @classmethod
    def _drive(cls):
        from harness.orchestrator import Orchestrator
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        base = cls.base

        def canned(base_url, roles, **kw):
            state = engagement.EngagementState(host="127.0.0.1")
            for path in ("/api/items", "/api/notes"):
                state.ingest_role_crawl({"endpoints": [{
                    "method": "GET", "path": path, "by_role": {"anonymous": 200},
                    "reachable_roles": ["anonymous"], "object_scoped": False}],
                    "idor_findings": []})
            for url in (f"{base}/api/items?q=lamp", f"{base}/api/notes?term=lamp"):
                state.record_template(url, "GET", HttpExchange(
                    method="GET", url=url, request_headers={}, response_status=200,
                    response_headers={"Content-Type": "application/json"}, response_body="{}"))
            state.client_routes = _route_map(base)
            for r in roles:
                state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")
            return state, SimpleNamespace(auth_bypass_candidates=[], idor_candidates=[],
                                          idor_findings=[])

        cfg = _config()
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
                    base, ROLES, max_nodes=0, step_budget=4, max_chain_rounds=0, run_context=ctx)

        with patch("harness.engagement_builder.build_engagement", side_effect=canned), \
                patch("harness.orchestrator_chain.shape_precondition_legs", return_value=[]):
            result = asyncio.run(investigate())
        coverage = result.get("coverage") or {}
        cls.result = result
        assert "cases_driven" in coverage, "the case-driven coverage path did not run"
        return CoverageMatrix.from_dict(coverage["checkpoint"]["matrix"])

    def _case(self, ep_key, check, location="", name=""):
        for ck, r in self.matrix.cases_for_cell("anonymous", ep_key, check):
            if (ck.parameter_location, ck.parameter_name) == (location, name):
                return r
        self.fail(f"no {location}:{name} case under {ep_key} {check}: "
                  f"{[c.label() for c, _ in self.matrix.cases_for_cell('anonymous', ep_key, check)]}")

    def test_the_hash_route_dom_sink_is_confirmed_on_its_route_input(self):
        for check in (DOM, REFLECTED):
            r = self._case("GET /#/find", check, ROUTE, "term")
            self.assertEqual(r.status, CellStatus.CONFIRMED, f"{check}: {r.reason}")
        self.assertIn("fragment route parameter 'term'", self._case(
            "GET /#/find", DOM, ROUTE, "term").reason)

    def test_the_history_route_reflection_is_confirmed_on_its_page_input(self):
        r = self._case("GET /look", REFLECTED, PAGE, "term")
        self.assertEqual(r.status, CellStatus.CONFIRMED, r.reason)
        r = self._case("GET /look", DOM, PAGE, "term")
        self.assertEqual(r.status, CellStatus.INCONCLUSIVE, r.reason)

    def test_the_safely_rendered_route_concludes_clean(self):
        for check in (DOM, REFLECTED):
            r = self._case("GET /#/note", check, ROUTE, "term")
            self.assertEqual(r.status, CellStatus.NOT_DETECTED, f"{check}: {r.reason}")

    def test_a_json_api_query_is_not_xss_but_its_call_maps_to_the_route(self):
        r = self._case("GET /api/items", REFLECTED, "query", "q")
        self.assertEqual(r.status, CellStatus.NOT_DETECTED, r.reason)
        # dom_xss tests the API endpoint at request level, through the route of the
        # view that issued the call.
        r = self._case("GET /api/items", DOM)
        self.assertEqual(r.status, CellStatus.CONFIRMED, r.reason)
        r = self._case("GET /api/notes", DOM)
        self.assertEqual(r.status, CellStatus.NOT_DETECTED, r.reason)

    def test_no_other_leg_gets_a_route_cell(self):
        cell = self.matrix.get("anonymous", "GET /#/find", SQLI)
        self.assertEqual(cell.status, CellStatus.NOT_APPLICABLE)

    def test_the_confirmed_route_xss_enters_the_finding_pipeline(self):
        confirmed = {(f.get("vulnerability_class"), urlsplit(f.get("url") or "").fragment.split("?")[0])
                     for f in self.result.get("findings") or [] if f.get("confirmed")}
        self.assertIn(("dom_xss", "/find"), confirmed)
        self.assertFalse(any(route == "/note" for _c, route in confirmed), confirmed)


if __name__ == "__main__":
    unittest.main()
