"""Router-declared views, two refinements:
  - a child route (an object in another route's `children: [...]`) is declared
    under its parent's path (`admin` + `reports` is `admin/reports`), not as a
    top-level route of its own;
  - a declared view the app stays on but renders a denial in place ("Access
    denied") is guarded, not a view, when the first view did not show that phrase.

The fixture is a generic loopback single-page app. Its shell links to `#/about`
only. Its bundle configures hash routing and declares, none of them linked:
  - `admin` with the children `reports` (fires `/api/admin-reports`) and
    `item/:id` (a path segment);
  - `vault`: the router stays on it and the view renders "Access denied";
  - `notes`: open, fires `/api/notes`.

Covered here:
  - client_routes: children joined to their parents (Angular-, Vue- and
    React-Router-style configs), brackets in strings, comments and regex literals
    leave the nesting alone, and a script with no `children` reads as before;
  - crawl_views with a fake adapter: an in-place denial is guarded, and the
    controls (the phrase on the first view too, an adapter without text());
  - through build_engagement with a real browser: the child view's API is
    captured and the child route is no top-level route; the in-place denial is
    guarded and never a view.
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

from harness import cache, engagement_builder, store
from harness.client_routes import ClientRouteMap, declared_views
from harness.role_crawl import RoleSession
from harness.spa_navigation import crawl_views, view_key
from harness.test_spa_declared_views import _CHROMIUM, _config

LOW = RoleSession("user", {"Authorization": "Bearer low-token"}, name="low-user")


# --------------------------------------------------------------------------
# client_routes: child routes
# --------------------------------------------------------------------------

class ChildRoutesTest(unittest.TestCase):
    def test_an_angular_style_child_is_declared_under_its_parent(self):
        body = ("const routes=[{path:'',component:H},{path:'admin',canActivate:[G],"
                "children:[{path:'users',component:U},{path:'logs',component:L},"
                "{path:'',redirectTo:'users',pathMatch:'full'}]},{path:'about',component:A}];")
        paths, _ = declared_views(body)
        self.assertEqual(paths, ["/admin", "/admin/users", "/admin/logs", "/about"])
        self.assertNotIn("/users", paths)

    def test_a_vue_absolute_child_stays_absolute_and_nesting_goes_deep(self):
        body = ("routes:[{path:'/shop',component:S,children:[{path:'/cart'},"
                "{path:'list',children:[{path:'top'}]}]}]")
        self.assertEqual(declared_views(body)[0], ["/shop", "/cart", "/shop/list", "/shop/list/top"])

    def test_a_layout_route_without_a_path_adds_nothing(self):
        body = '{element:L,children:[{path:"team",children:[{path:"roster"}]}]}'
        self.assertEqual(declared_views(body)[0], ["/team", "/team/roster"])

    def test_a_key_after_children_and_a_segment_parent(self):
        routes = ClientRouteMap()
        routes.add_url("http://desk.test/#/", "crawl")
        routes.mine_script("useHash:true;x=[{children:[{path:'edit'}],path:'item/:id'}]")
        routes.finalize()
        self.assertEqual({r.endpoint_key: r.segments for r in routes.inputs()},
                         {"GET /#/item/:id/edit": ["id"], "GET /#/item/:id": ["id"]})

    def test_brackets_in_strings_comments_and_regex_literals_leave_the_nesting_alone(self):
        body = ("var re=/[{]/g, s='{[', t=\"]}\"; /* {[ */ // ]}\n"
                "var u = `a ${1} {`; [{path:'a', children:[{path:'b'}]}]; [{path:'c'}]")
        self.assertEqual(declared_views(body)[0], ["/a", "/a/b", "/c"])

    def test_control_without_children_the_config_reads_flat(self):
        body = "[{path:'a', items:[{path:'b'}]}, {path:'c', children: kids}]"
        self.assertEqual(declared_views(body)[0], ["/a", "/b", "/c"])
        self.assertEqual(declared_views("[{path:'a'},{path:'b'}]")[0], ["/a", "/b"])


# --------------------------------------------------------------------------
# crawl_views with a fake adapter: in-place denials
# --------------------------------------------------------------------------

def _api(path):
    return {"method": "GET", "url": f"http://desk.test{path}", "request_body": ""}


class _TextApp:
    """An adapter over view key -> (links, calls, text); the router stays on every
    view. The shell loads `bundle` with the first view."""

    def __init__(self, views, bundle):
        self.views, self.bundle = views, bundle
        self.opened, self.cur, self.loaded = [], "", False

    def _view(self):
        return self.views.get(view_key(self.cur), ([], [], ""))

    async def open(self, url):
        self.opened.append(url)
        self.cur = url

    async def links(self):
        return self._view()[0]

    async def drain(self):
        return [dict(e) for e in self._view()[1]]

    async def text(self):
        return self._view()[2]

    def current_url(self):
        return self.cur

    async def scripts(self):
        if self.loaded:
            return []
        self.loaded = True
        return [self.bundle]


_BUNDLE = "useHash: true; [{path: ''}, {path: 'about'}, {path: 'vault'}, {path: 'notes'}]"


def _views(home_text="Desk\nhome"):
    return {
        "/#/": (["#/about"], [_api("/api/home")], home_text),
        "/#/about": ([], [], "Desk\nabout"),
        "/#/vault": (["#/vault/keys"], [_api("/api/vault")], "Desk\nAccess  Denied\nGo back"),
        "/#/notes": ([], [_api("/api/notes")], "Desk\nnotes"),
    }


class InPlaceDenialCrawlTest(unittest.TestCase):
    def _crawl(self, app):
        return asyncio.run(crawl_views(app, "http://desk.test/#/",
                                       in_scope=lambda u: "desk.test" in u, declared_views=5))

    def test_a_declared_view_that_renders_a_denial_is_guarded(self):
        app = _TextApp(_views(), _BUNDLE)
        res = self._crawl(app)
        self.assertEqual(res.guarded, ["/#/vault -> denied in place (access denied)"])
        self.assertEqual(res.declared, ["/#/notes"])
        self.assertNotIn("http://desk.test/#/vault", res.views)
        # Its links are not followed; the call it fired is captured, tagged with it.
        self.assertNotIn("http://desk.test/#/vault/keys", app.opened)
        notes = {e["url"]: e["analyst_note"] for e in res.exchanges}
        self.assertIn("view /#/vault", notes["http://desk.test/api/vault"])

    def test_control_a_phrase_the_first_view_shows_too_is_no_denial(self):
        res = self._crawl(_TextApp(_views("Desk\nhome\naccess denied? read the FAQ"), _BUNDLE))
        self.assertEqual(res.guarded, [])
        self.assertEqual(res.declared, ["/#/vault", "/#/notes"])

    def test_control_an_adapter_without_text_keeps_the_view(self):
        app = _TextApp(_views(), _BUNDLE)
        plain = SimpleNamespace(open=app.open, links=app.links, drain=app.drain,
                                current_url=app.current_url, scripts=app.scripts)
        res = self._crawl(plain)
        self.assertEqual((res.guarded, res.declared), ([], ["/#/vault", "/#/notes"]))

    def test_control_a_linked_view_is_never_judged_by_its_text(self):
        views = _views()
        views["/#/about"] = ([], [], "Desk\nPermission denied")
        res = self._crawl(_TextApp(views, _BUNDLE))
        self.assertIn("http://desk.test/#/about", res.views)
        self.assertEqual(res.guarded, ["/#/vault -> denied in place (access denied)"])


# --------------------------------------------------------------------------
# Through build_engagement, with a real browser
# --------------------------------------------------------------------------

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>Desk</title></head>
<body><nav><a href="#/about">About</a></nav><main id="view"></main>
<script src="/static/app.js"></script></body></html>"""

# Each view's API path is built at run time, so the crawler finds no API literal
# in the bundle: an API endpoint here comes from the browser's capture alone.
_APP_JS = """(function () {
  var config = {useHash: true};
  var routes = [
    {path: "", view: "home"},
    {path: "about", view: "about"},
    {path: "admin", view: "admin", children: [
      {path: "reports", view: "admin-reports", api: 1},
      {path: "item/:id", view: "admin-item"}
    ]},
    {path: "vault", view: "vault", denied: 1},
    {path: "notes", view: "notes", api: 1}
  ];
  var flat = {};
  routes.forEach(function (r) {
    flat[r.path] = r;
    (r.children || []).forEach(function (c) { flat[r.path + "/" + c.path] = c; });
  });
  function render() {
    var p = (location.hash || "#/").replace(/^#\\/?/, "").split("?")[0];
    var r = flat[p] || flat[""];
    var el = document.getElementById("view");
    if (r.denied) { el.textContent = "Access denied"; return; }
    el.textContent = r.view;
    if (r.api) { fetch(["", "api", r.view].join("/")).then(function (x) { return x.json(); }); }
  }
  window.addEventListener("hashchange", render);
  render();
})();
"""


class _Handler(BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):
        path = urlsplit(self.path).path
        _Handler.seen.append(path)
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


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class BuildEngagementChildrenTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="spa_children_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.state, cls.result = cls._build()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    @classmethod
    def _build(cls):
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config()
        _Handler.seen = []

        async def build():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                return await engagement_builder.build_engagement(
                    cls.base, [LOW], allowed_hosts=["127.0.0.1"], crawl_max_pages=4,
                    active_discovery=False, run_context=ctx,
                    driver_capture_config={"enabled": True, "spa_navigation": True,
                                           "wait_ms": 500, "max_views": 8,
                                           "declared_views": 6})
        return asyncio.run(build())

    def _low(self):
        return next(v for v in self.result.spa_views if v["principal"] == "low-user")

    def test_the_child_view_is_visited_under_its_parent_and_its_api_captured(self):
        spa = self._low()
        self.assertIn("/#/admin/reports", spa["declared"], spa)
        self.assertIn("/#/notes", spa["declared"], spa)
        self.assertIn("GET /api/admin-reports", self.state.endpoints, sorted(self.state.endpoints))
        self.assertIn("/api/admin-reports", _Handler.seen)

    def test_the_child_segment_route_is_an_input_under_its_parent(self):
        keys = {r.endpoint_key for r in self.state.client_routes.inputs()}
        self.assertIn("GET /#/admin/item/:id", keys)
        self.assertNotIn("GET /#/item/:id", keys)

    def test_control_the_child_is_no_top_level_route(self):
        spa = self._low()
        self.assertNotIn("/#/reports", spa["declared"] + spa["guarded"], spa)
        self.assertNotIn("/api/reports", _Handler.seen)

    def test_control_the_in_place_denial_is_guarded_and_never_a_view(self):
        spa = self._low()
        self.assertIn("/#/vault -> denied in place (access denied)", spa["guarded"], spa)
        self.assertNotIn("/#/vault", spa["declared"], spa)


if __name__ == "__main__":
    unittest.main()
