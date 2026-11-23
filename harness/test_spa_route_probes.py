"""Route probes: the SPA crawl loads a view once more with a marker value in each
route parameter name the app's scripts read, and a name whose marker the view
shows or sends becomes a route input, though no link or API call named it.

The fixture is a generic loopback single-page app. Its shell links to three hash
routes, none with a parameter (`#/about`, `#/search`, `#/lookup`). Its bundle
(`/static/app.js`) reads three names from the route's query:
  - `term`: `#/search` writes it into `innerHTML` (shown, and a DOM sink); no
    API call ever carries it;
  - `ref`: `#/lookup` sends it to an API whose path the bundle builds at run time
    (`/api/lookup?code=`), and shows nothing of it;
  - `debug`: read, but no view shows or sends it.

Covered here:
  - the client_routes helpers: the names a bundle reads, a probe URL for a hash
    and a history view, and the route map folding a probe in (the shown or sent
    names only; the API call it fired is mapped back to the route by value);
  - crawl_views with a fake adapter: shown and sent names, the cap, a name the
    view URL already carries, a probe the app redirects, and the default (0)
    leaving the walk unchanged;
  - through build_engagement with a real browser: `term` and `ref` become route
    inputs, the API `ref` feeds is captured and linked to its route, `debug` is
    no input anywhere; with the config at its default none of that exists;
  - through investigate_engagement (real discovery, with probes on): the DOM sink
    on `#/search` is confirmed on its probed `term` input.
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

from harness import cache, engagement_builder, store
from harness.client_routes import (ClientRouteMap, fragment_route, probe_url, read_names_of)
from harness.role_crawl import RoleSession
from harness.spa_navigation import crawl_views, view_key
from harness.chain_stage_patch import chain_patch

_HARNESS = Path(__file__).resolve().parent
ROLES = [RoleSession("anonymous", {})]
DOM = "WSTG-CLNT-01"

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>Desk</title></head>
<body><nav><a href="#/about">About</a> <a href="#/search">Search</a>
<a href="#/lookup">Lookup</a></nav><main id="view"></main>
<script src="/static/app.js"></script></body></html>"""

# The API path is built at run time: the crawler finds no API literal in the
# bundle, so the lookup endpoint can only come from a call the browser saw.
_APP_JS = """(function () {
  function render() {
    var h = location.hash.slice(1), i = h.indexOf("?");
    var path = i < 0 ? h : h.slice(0, i), qs = i < 0 ? "" : h.slice(i + 1);
    var view = document.getElementById("view");
    if (new URLSearchParams(qs).get("debug")) { window.__debug = true; }
    if (path === "/search") {
      view.innerHTML = "<h2>Results for " + (new URLSearchParams(qs).get("term") || "") + "</h2>";
    } else if (path === "/lookup") {
      var ref = new URLSearchParams(qs).get("ref");
      view.textContent = "Lookup";
      if (ref) {
        fetch(["", "api", "lookup"].join("/") + "?code=" + encodeURIComponent(ref))
          .then(function (x) { return x.json(); });
      }
    } else {
      view.textContent = path || "home";
    }
  }
  window.addEventListener("hashchange", render);
  render();
})();
"""


class _Handler(BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):
        parts = urlsplit(self.path)
        _Handler.seen.append(self.path)
        if parts.path == "/":
            self._reply(_SHELL, "text/html")
        elif parts.path == "/static/app.js":
            self._reply(_APP_JS, "application/javascript")
        elif parts.path == "/api/lookup":
            self._reply(json.dumps({"found": dict(parse_qsl(parts.query)).get("code")}),
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

        async def check():
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                await browser.close()
        asyncio.run(check())
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
    for name, leg in list(validators.items()):
        if isinstance(leg, dict) and "enabled" in leg:
            leg["enabled"] = name in enabled
    for name in enabled:
        validators.setdefault(name, {})["enabled"] = True
    for name in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(name, {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


def _inputs(routes) -> dict:
    return {r.endpoint_key: set(r.params) for r in routes.inputs()} if routes is not None else {}


# --------------------------------------------------------------------------
# The client_routes helpers
# --------------------------------------------------------------------------

class ProbeHelpersTest(unittest.TestCase):
    def test_the_names_a_bundle_reads(self):
        self.assertEqual(read_names_of(_APP_JS), ["debug", "term", "ref"])
        self.assertEqual(read_names_of("this.route.snapshot.queryParams.page; "
                                       "route.queryParams.subscribe(f); queryParams.get('x')"),
                         ["page"])
        self.assertEqual(read_names_of(""), [])

    def test_a_probe_url_sets_route_inputs_where_the_view_reads_them(self):
        self.assertEqual(probe_url("http://desk.test/#/find?page=2", {"term": "abc"}),
                         "http://desk.test/#/find?page=2&term=abc")
        self.assertEqual(probe_url("http://desk.test/look?x=1#top", {"term": "abc"}),
                         "http://desk.test/look?x=1&term=abc")
        self.assertIsNone(probe_url("http://desk.test/#/find", {}))

    def test_the_map_keeps_only_the_names_the_view_showed_or_sent(self):
        routes = ClientRouteMap()
        routes.add_probe("http://desk.test/#/lookup?term=aaa&ref=bbb&debug=ccc", ["ref"],
                         [("GET", "http://desk.test/api/lookup?code=bbb", "")])
        routes.add_probe("http://desk.test/#/about?term=ddd", [], [])
        routes.finalize()
        self.assertEqual(_inputs(routes), {"GET /#/lookup": {"ref"}})
        found = {(r.endpoint_key, rp, ap)
                 for r, rp, ap in routes.routes_for_api("GET", "http://desk.test/api/lookup?code=z")}
        self.assertEqual(found, {("GET /#/lookup", "ref", "code")})

    def test_control_a_probe_off_origin_or_of_no_route_adds_nothing(self):
        routes = ClientRouteMap()
        routes.add_url("http://desk.test/", "crawl")
        routes.add_probe("http://elsewhere.invalid/#/x?term=aaa", ["term"], [])
        routes.add_probe("http://desk.test/assets/logo.png?term=aaa", ["term"], [])
        routes.finalize()
        self.assertEqual(_inputs(routes), {})


# --------------------------------------------------------------------------
# crawl_views with a fake adapter
# --------------------------------------------------------------------------

def _query(url):
    parts = urlsplit(url)
    fr = fragment_route(parts.fragment)
    return dict(parse_qsl(fr[2] if fr is not None else parts.query))


class _ProbeApp:
    """An adapter over view key -> {"links", "shows" (names it renders), "sends"
    (name -> API path it fires with that name's value)}. `landing` maps a view key
    the app redirects to another; the shell loads `bundle` with the first view."""

    def __init__(self, views, bundle, landing=None):
        self.views, self.bundle, self.landing = views, bundle, landing or {}
        self.opened, self.cur, self.loaded, self.script_calls = [], "", False, 0

    def _view(self):
        return self.views.get(view_key(self.cur), {})

    async def open(self, url):
        self.opened.append(url)
        target = self.landing.get(view_key(url))
        self.cur = url if target is None else urlsplit(url)._replace(
            fragment=target.partition("#")[2], query="").geturl()

    async def links(self):
        return list(self._view().get("links", ()))

    async def drain(self):
        params = _query(self.cur)
        return [{"method": "GET", "url": f"http://desk.test{api}?code={params[name]}",
                 "request_body": ""}
                for name, api in self._view().get("sends", {}).items() if name in params]

    async def text(self):
        params = _query(self.cur)
        return "Results for " + " ".join(params[n] for n in self._view().get("shows", ())
                                         if n in params)

    def current_url(self):
        return self.cur

    async def scripts(self):
        self.script_calls += 1
        if self.loaded:
            return []
        self.loaded = True
        return [self.bundle]


_VIEWS = {
    "/#/": {"links": ["#/search", "#/lookup", "#/find?term=lamp", "#/away"]},
    "/#/search": {"shows": ["term"]},
    "/#/lookup": {"sends": {"ref": "/api/lookup"}},
    "/#/find": {"shows": ["term", "page"]},
    "/#/away": {"shows": ["term"]},
}
_BUNDLE = ("new URLSearchParams(qs).get('term'); new URLSearchParams(qs).get('ref');"
           " new URLSearchParams(qs).get('debug'); route.snapshot.queryParams.page;")


class CrawlRouteProbesTest(unittest.TestCase):
    def _crawl(self, landing=None, **kw):
        app = _ProbeApp(_VIEWS, _BUNDLE, landing=landing)
        res = asyncio.run(crawl_views(app, "http://desk.test/#/",
                                      in_scope=lambda u: "desk.test" in u, **kw))
        return app, res

    def test_a_name_the_view_shows_or_sends_is_recorded(self):
        _app, res = self._crawl(route_probes=8)
        by_view = {p["view"]: p for p in res.probes}
        self.assertEqual(by_view["/#/search"]["names"], ["term"])
        self.assertEqual(by_view["/#/lookup"]["names"], ["ref"])
        self.assertEqual(by_view["/#/"]["names"], [])
        probe = urlsplit(by_view["/#/search"]["url"])
        self.assertEqual(fragment_route(probe.fragment)[1], "/search")
        self.assertEqual(sorted(_query(by_view["/#/search"]["url"])),
                         ["debug", "page", "ref", "term"])
        # The call the probe fired is captured as an exchange of its view.
        sent = [e for e in res.exchanges if "/api/lookup" in e["url"]]
        self.assertEqual(len(sent), 1)
        self.assertIn("view /#/lookup (route probe)", sent[0]["analyst_note"])
        self.assertEqual(by_view["/#/lookup"]["calls"][0][1], sent[0]["url"])

    def test_a_name_the_view_url_already_carries_is_not_probed(self):
        _app, res = self._crawl(route_probes=8)
        find = next(p for p in res.probes if p["view"] == "/#/find")
        self.assertEqual(_query(find["url"])["term"], "lamp")
        self.assertEqual(find["names"], ["page"])

    def test_the_cap_bounds_the_probes_apart_from_max_views(self):
        app, res = self._crawl(route_probes=1)
        self.assertEqual([p["view"] for p in res.probes], ["/#/"])
        # Each view once, and the one probe.
        self.assertEqual(len(app.opened), len(_VIEWS) + 1)
        self.assertEqual(res.stopped_by, "exhausted")

    def test_control_a_probe_the_app_redirects_records_nothing(self):
        # The app sends any view carrying a query back home.
        app = _ProbeApp(_VIEWS, _BUNDLE)
        real_open = app.open

        async def open_(url):
            await real_open(url)
            if _query(url):
                app.cur = "http://desk.test/#/"
        app.open = open_
        res = asyncio.run(crawl_views(app, "http://desk.test/#/", in_scope=lambda u: True,
                                      route_probes=8))
        self.assertEqual([p for p in res.probes if p["view"] != "/#/"], [])
        self.assertGreater(res.skipped.get("probe_redirected", 0), 0)

    def test_control_the_default_leaves_the_walk_unchanged(self):
        app, res = self._crawl()
        self.assertEqual(res.probes, [])
        self.assertEqual(app.script_calls, 0)
        self.assertFalse(any(_query(u) and "find" not in u for u in app.opened), app.opened)

    def test_control_an_adapter_without_text_still_records_sent_names(self):
        app = _ProbeApp(_VIEWS, _BUNDLE)
        plain = SimpleNamespace(open=app.open, links=app.links, drain=app.drain,
                                current_url=app.current_url, scripts=app.scripts)
        res = asyncio.run(crawl_views(plain, "http://desk.test/#/", in_scope=lambda u: True,
                                      route_probes=8))
        by_view = {p["view"]: p["names"] for p in res.probes}
        self.assertEqual(by_view["/#/lookup"], ["ref"])
        self.assertEqual(by_view["/#/search"], [])


# --------------------------------------------------------------------------
# Through build_engagement and investigate_engagement, with a real browser
# --------------------------------------------------------------------------

class _Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="spa_route_probes_")
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


_CAPTURE = {"enabled": True, "spa_navigation": True, "wait_ms": 500, "max_views": 8}


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class BuildEngagementRouteProbesTest(_Server):
    def _build(self, capture):
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config()
        _Handler.seen = []

        async def build():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                return await engagement_builder.build_engagement(
                    self.base, ROLES, allowed_hosts=["127.0.0.1"], crawl_max_pages=4,
                    active_discovery=False, run_context=ctx,
                    driver_capture_config={**_CAPTURE, **capture})
        return asyncio.run(build())

    def test_a_shown_and_a_sent_name_become_route_inputs(self):
        state, result = self._build({"route_probes": 6})
        inputs = _inputs(state.client_routes)
        self.assertEqual(inputs.get("GET /#/search"), {"term"}, inputs)
        self.assertEqual(inputs.get("GET /#/lookup"), {"ref"}, inputs)
        # The API `ref` feeds was captured from the probe and maps back to its route.
        self.assertIn("GET /api/lookup", state.endpoints, sorted(state.endpoints))
        found = {(r.endpoint_key, rp, ap) for r, rp, ap in state.client_routes.routes_for_api(
            "GET", f"{self.base}/api/lookup?code=z")}
        self.assertIn(("GET /#/lookup", "ref", "code"), found)
        probes = {p["view"]: p["names"] for v in result.spa_views for p in v["probes"]}
        self.assertEqual(probes.get("/#/search"), ["term"], probes)

    def test_control_a_name_no_view_shows_or_sends_is_no_input(self):
        state, _result = self._build({"route_probes": 6})
        for names in _inputs(state.client_routes).values():
            self.assertNotIn("debug", names)
        self.assertNotIn("term", _inputs(state.client_routes).get("GET /#/lookup", set()))

    def test_control_the_default_config_probes_nothing(self):
        state, result = self._build({})
        inputs = _inputs(state.client_routes)
        self.assertNotIn("GET /#/search", inputs)
        self.assertNotIn("GET /#/lookup", inputs)
        self.assertNotIn("GET /api/lookup", state.endpoints)
        self.assertFalse(any(p.startswith("/api/") for p in _Handler.seen), _Handler.seen)
        self.assertEqual([p for v in result.spa_views for p in v["probes"]], [])


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class ProbedRouteCoverageCallerTest(_Server):
    """investigate_engagement with driver capture, SPA navigation and route probes
    on (discovery is real): the DOM sink on `#/search`, which no link or API call
    names a parameter of, is confirmed on the input the probe found. The agent
    probe is stubbed and every leg but the two browser XSS legs is off."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from harness.coverage_model import CoverageMatrix
        from harness.orchestrator import Orchestrator
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config()
        cfg["driver_capture"] = {**(cfg.get("driver_capture") or {}), **_CAPTURE,
                                 "route_probes": 6}
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

    def _cases(self, ep_key):
        return {(ck.parameter_location, ck.parameter_name): r
                for ck, r in self.matrix.cases_for_cell("anonymous", ep_key, DOM)}

    def test_the_probed_route_input_is_confirmed(self):
        from harness.coverage_model import CellStatus
        cases = self._cases("GET /#/search")
        self.assertIn(("route", "term"), cases, list(cases))
        self.assertEqual(cases[("route", "term")].status, CellStatus.CONFIRMED,
                         cases[("route", "term")].reason)
        confirmed = {(f.get("vulnerability_class"), urlsplit(f.get("url") or "").fragment.split("?")[0])
                     for f in self.result.get("findings") or [] if f.get("confirmed")}
        self.assertIn(("dom_xss", "/search"), confirmed)

    def test_control_the_sent_only_input_is_not_a_dom_sink(self):
        from harness.coverage_model import CellStatus
        cases = self._cases("GET /#/lookup")
        self.assertIn(("route", "ref"), cases, list(cases))
        self.assertEqual(cases[("route", "ref")].status, CellStatus.NOT_DETECTED,
                         cases[("route", "ref")].reason)


if __name__ == "__main__":
    unittest.main()
