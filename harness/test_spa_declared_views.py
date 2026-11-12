"""Router-declared views: the SPA crawl visits the parameter-less routes the app's
router config declares even when no page links to them.

The fixture is a generic loopback single-page app. Its shell links to one view
only (`#/about`). Its bundle (`/static/app.js`) configures hash routing and
declares more routes, none of them linked:
  - `reports`: open; the view fires `/api/reports`;
  - `console`: a guard cancels the navigation, and the URL goes back to the view
    the app was on (`/api/console` is never fired);
  - `settings`: a guard redirects to the login route (`#/login`);
  - `item/:id` (a path parameter), `signout` (destructive-looking) and
    `assets/logo.png` (a file): never visited.

Covered here:
  - the client_routes helper that lists a bundle's declared parameter-less routes;
  - crawl_views with a fake adapter: the declared cap, its independence from
    max_views, history vs hash resolution, an error status and a redirect as
    guarded, and the default (0) leaving today's walk unchanged;
  - through build_engagement with a real browser: the open declared view's API
    call is captured as the crawling (low-privilege) identity and becomes an
    endpoint with that principal's access cell, while the guard-cancelled and
    login-redirecting routes are reported as guarded and never as views. With
    the config at its default nothing declared is visited.
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

import yaml

from harness import cache, engagement_builder, store
from harness.client_routes import declared_views
from harness.role_crawl import RoleSession
from harness.spa_navigation import crawl_views, view_key

_HARNESS = Path(__file__).resolve().parent
LOW = RoleSession("user", {"Authorization": "Bearer low-token"}, name="low-user")

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>Desk</title></head>
<body><nav><a href="#/about">About</a></nav><main id="view"></main>
<script src="/static/app.js"></script></body></html>"""

# A small hash router: a guard either cancels (the URL goes back to the view the
# app was on, as a router restores it) or redirects to the login route. Each view's
# API path is built at run time, so the crawler finds no API literal in the bundle:
# an API endpoint here comes from the browser's capture alone.
_APP_JS = """(function () {
  var config = {useHash: true};
  var routes = [
    {path: "", view: "home", api: 1},
    {path: "about", view: "about", api: 1},
    {path: "login", view: "login"},
    {path: "reports", view: "reports", api: 1},
    {path: "console", view: "console", api: 1, guard: "cancel"},
    {path: "settings", view: "settings", api: 1, guard: "login"},
    {path: "item/:id", view: "item"},
    {path: "signout", view: "signout", api: 1},
    {path: "assets/logo.png", view: "file"},
    {path: "**", redirectTo: ""}
  ];
  var last = "#/";
  function render() {
    var h = location.hash || "#/";
    var p = h.replace(/^#\\/?/, "").split("?")[0];
    var r = routes.filter(function (x) { return x.path === p; })[0];
    if (!r) { location.hash = "#/"; return; }
    if (r.guard === "cancel") { history.replaceState(null, "", last); return; }
    if (r.guard === "login") { location.hash = "#/login"; return; }
    last = h;
    document.getElementById("view").textContent = r.view;
    if (r.api) {
      fetch(["", "api", r.view].join("/")).then(function (x) { return x.json(); });
    }
  }
  window.addEventListener("hashchange", render);
  render();
})();
"""


class _Handler(BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):
        path = urlsplit(self.path).path
        _Handler.seen.append((path, self.headers.get("Authorization")))
        if path == "/":
            self._reply(_SHELL, "text/html")
        elif path == "/static/app.js":
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


def _config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    for name in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(name, {})["enabled"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


# --------------------------------------------------------------------------
# The bundle helper
# --------------------------------------------------------------------------

class DeclaredViewsHelperTest(unittest.TestCase):
    def test_lists_the_parameter_less_routes_in_order(self):
        paths, hashed = declared_views(_APP_JS)
        self.assertEqual(paths, ["/about", "/login", "/reports", "/console", "/settings"])
        self.assertTrue(hashed)

    def test_control_parameters_files_wildcards_destructive_and_root_are_left_out(self):
        paths, _ = declared_views(_APP_JS)
        for left_out in ("/", "/item", "/item/:id", "/signout", "/assets/logo.png", "/**"):
            self.assertNotIn(left_out, paths)
        self.assertEqual(declared_views("var x = {path: 'a'};", limit=0), ([], False))
        self.assertEqual(declared_views(""), ([], False))


# --------------------------------------------------------------------------
# crawl_views with a fake adapter
# --------------------------------------------------------------------------

def _api(path):
    return {"method": "GET", "url": f"http://desk.test{path}", "request_body": ""}


class _FakeApp:
    """An adapter over view key -> (links, calls). `landing` maps a requested view
    key to where the app lands instead (a guard); `statuses` to the document status
    a navigation answers; the shell loads `bundle` with the first view."""

    def __init__(self, views, bundle, *, landing=None, statuses=None):
        self.views, self.bundle = views, bundle
        self.landing, self.statuses = landing or {}, statuses or {}
        self.opened, self.cur, self.code, self.loaded = [], "", None, False
        self.script_calls = 0

    async def open(self, url):
        self.opened.append(url)
        self.code = self.statuses.get(view_key(url), 200)
        target = self.landing.get(view_key(url))
        self.cur = url if target is None else urlsplit(url)._replace(
            path=target.split("#", 1)[0], fragment=target.partition("#")[2]).geturl()

    async def links(self):
        return self.views.get(view_key(self.cur), ([], []))[0]

    async def drain(self):
        return [dict(e) for e in self.views.get(view_key(self.cur), ([], []))[1]]

    def current_url(self):
        return self.cur

    def status(self):
        return self.code

    async def scripts(self):
        self.script_calls += 1
        if self.loaded:
            return []
        self.loaded = True
        return [self.bundle]


_HASH_VIEWS = {
    "/#/": (["#/about"], [_api("/api/home")]),
    "/#/about": ([], [_api("/api/about")]),
    "/#/login": ([], []),
    "/#/reports": (["#/reports/archive"], [_api("/api/reports")]),
}
_BUNDLE = ("useHash: true; [{path: ''}, {path: 'about'}, {path: 'login'}, {path: 'reports'},"
           " {path: 'console'}, {path: 'settings'}, {path: 'logout'}]")


class CrawlDeclaredViewsTest(unittest.TestCase):
    def _crawl(self, views=_HASH_VIEWS, bundle=_BUNDLE, start="http://desk.test/#/", **kw):
        app = _FakeApp(views, bundle, landing=kw.pop("landing", None),
                       statuses=kw.pop("statuses", None))
        res = asyncio.run(crawl_views(app, start, in_scope=lambda u: "desk.test" in u, **kw))
        return app, res

    def test_declared_views_are_visited_and_their_calls_captured(self):
        app, res = self._crawl(declared_views=5,
                               landing={"/#/console": "/#/about", "/#/settings": "/#/login"})
        self.assertEqual(res.declared, ["/#/login", "/#/reports"])
        self.assertEqual(res.guarded, ["/#/console -> /#/about", "/#/settings -> /#/login"])
        self.assertEqual([view_key(v) for v in res.views],
                         ["/#/", "/#/about", "/#/login", "/#/reports", "/#/reports/archive"])
        urls = {e["url"] for e in res.exchanges}
        self.assertIn("http://desk.test/api/reports", urls)
        note = next(e for e in res.exchanges if e["url"].endswith("/api/reports"))["analyst_note"]
        self.assertIn("view /#/reports", note)
        # A declared view's own links are followed like any view's (under
        # max_views); a declared view is never a link target, nor destructive.
        self.assertIn("http://desk.test/#/reports/archive", app.opened)
        self.assertEqual([u for u in res.links if "reports" in u],
                         ["http://desk.test/#/reports/archive"])
        self.assertFalse(any("logout" in u for u in app.opened))

    def test_a_guarded_view_is_never_a_view_and_its_calls_carry_the_landed_view(self):
        views = dict(_HASH_VIEWS)
        views["/#/login"] = ([], [_api("/api/whoami")])
        _, res = self._crawl(views=views, declared_views=5,
                             landing={"/#/reports": "/#/login"})
        self.assertIn("/#/reports -> /#/login", res.guarded)
        self.assertNotIn("/#/reports", res.declared)
        self.assertNotIn("/#/reports", [view_key(v) for v in res.views])
        calls = [view_key(v) for v, _m, u, _b in res.view_calls if u.endswith("/api/whoami")]
        self.assertEqual(set(calls), {"/#/login"})

    def test_an_error_status_is_guarded(self):
        views = {"/": (["/about"], [_api("/api/home")]), "/about": ([], []),
                 "/reports": ([], [_api("/api/reports")])}
        app, res = self._crawl(views=views, bundle="[{path: 'about'}, {path: 'reports'}]",
                               start="http://desk.test/", declared_views=5,
                               statuses={"/reports": 403})
        # No hash routing anywhere: a declared path is a history route.
        self.assertIn("http://desk.test/reports", app.opened)
        self.assertEqual(res.guarded, ["/reports -> status 403"])
        self.assertEqual(res.declared, [])

    def test_the_cap_bounds_declared_views_apart_from_max_views(self):
        app, res = self._crawl(declared_views=1, max_views=1)
        self.assertEqual([view_key(v) for v in res.views], ["/#/", "/#/login"])
        self.assertEqual(res.declared, ["/#/login"])
        self.assertEqual(res.stopped_by, "max_views")
        # A linked view stays under max_views even when a declared one is left.
        self.assertNotIn("http://desk.test/#/about", app.opened)

    def test_a_bundle_hash_hint_makes_declared_paths_hash_routes(self):
        views = {"/": ([], []), "/#/reports": ([], [_api("/api/reports")])}
        app, res = self._crawl(views=views, bundle="useHash: true; [{path: 'reports'}]",
                               start="http://desk.test/", declared_views=2)
        self.assertEqual(app.opened, ["http://desk.test/", "http://desk.test/#/reports"])
        self.assertEqual(res.declared, ["/#/reports"])

    def test_the_view_the_start_page_landed_on_is_not_visited_again(self):
        views = {"/#/home": ([], [_api("/api/home")]), "/#/reports": ([], [])}
        app, res = self._crawl(views=views, start="http://desk.test/",
                               bundle="useHash: true; [{path: 'home'}, {path: 'reports'}]",
                               declared_views=2, landing={"/": "/#/home"})
        self.assertEqual(app.opened, ["http://desk.test/", "http://desk.test/#/reports"])
        self.assertEqual(res.declared, ["/#/reports"])

    def test_control_the_default_leaves_the_walk_unchanged(self):
        app, res = self._crawl(landing={"/#/console": "/#/about"})
        self.assertEqual(app.opened, ["http://desk.test/#/", "http://desk.test/#/about"])
        self.assertEqual((res.declared, res.guarded, app.script_calls), ([], [], 0))
        self.assertEqual(res.stopped_by, "exhausted")

    def test_control_an_adapter_without_scripts_visits_nothing_declared(self):
        app = _FakeApp(_HASH_VIEWS, _BUNDLE)
        plain = SimpleNamespace(open=app.open, links=app.links, drain=app.drain,
                                current_url=app.current_url)
        res = asyncio.run(crawl_views(plain, "http://desk.test/#/",
                                      in_scope=lambda u: True, declared_views=5))
        self.assertEqual(res.declared, [])
        self.assertEqual(app.opened, ["http://desk.test/#/", "http://desk.test/#/about"])


# --------------------------------------------------------------------------
# Through build_engagement, with a real browser
# --------------------------------------------------------------------------

def _low(result) -> dict:
    """The low-privilege identity's crawl summary (an anonymous crawl runs too)."""
    return next(v for v in result.spa_views if v["principal"] == "low-user")


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class BuildEngagementDeclaredViewsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="spa_declared_")
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

    def _build(self, capture):
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
                                           "wait_ms": 500, "max_views": 8, **capture})
        return asyncio.run(build())

    def test_an_open_declared_view_is_captured_as_the_low_privilege_identity(self):
        state, result = self._build({"declared_views": 6})
        spa = _low(result)
        self.assertIn("/#/reports", spa["declared"], spa)
        # The API the unlinked view fires is an endpoint, seen as the crawling identity.
        ep = state.endpoints.get("GET /api/reports")
        self.assertIsNotNone(ep, sorted(state.endpoints))
        self.assertEqual(ep.access_by_principal["low-user"]["source"], "seed_capture")
        self.assertIn(("/api/reports", "Bearer low-token"), _Handler.seen)

    def test_control_a_guarded_or_login_redirecting_route_is_not_reachable(self):
        state, result = self._build({"declared_views": 6})
        spa = _low(result)
        guarded = " | ".join(spa["guarded"])
        self.assertIn("/#/console -> ", guarded, spa)
        self.assertIn("/#/settings -> /#/login", guarded, spa)
        for path in ("/#/console", "/#/settings"):
            self.assertNotIn(path, spa["declared"])
        # Nothing was fired for the guarded views, and they are no route of the app.
        self.assertNotIn("GET /api/console", state.endpoints)
        self.assertNotIn("GET /api/settings", state.endpoints)
        routes = {r.endpoint_key for r in state.client_routes.routes()} \
            if state.client_routes is not None else set()
        self.assertFalse({"GET /#/console", "GET /#/settings"} & routes, routes)
        # Never a path parameter, a file or a destructive-looking route.
        fired = {p for p, _a in _Handler.seen}
        self.assertNotIn("/api/signout", fired)

    def test_control_the_default_config_visits_no_declared_view(self):
        state, result = self._build({})
        spa = _low(result)
        self.assertEqual((spa["declared"], spa["guarded"]), ([], []))
        self.assertNotIn("GET /api/reports", state.endpoints)
        self.assertNotIn("/api/reports", {p for p, _a in _Handler.seen})
        self.assertIn("GET /api/about", state.endpoints)


if __name__ == "__main__":
    unittest.main()
