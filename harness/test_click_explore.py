"""Click exploration in the SPA crawl (driver_capture.click_explore).

The fixture is a generic loopback hash-routed app. Its home view links to
#/products and #/about:
  - #/products lists two product cards (list items styled with a pointer and a
    script click handler, no id). A click opens a dialog that fetches
    /api/reviews?product=N and renders each review's text with innerHTML. The view
    also has "Open details" (GET /hit/open), "Delete" (GET /hit/delete), a
    "Logout" anchor with href="#" (GET /hit/logout), "Peek" (GET to a second
    loopback server, not in scope), "Star" (POST /api/star), and a "Preview"
    button inside a form (GET /hit/inform);
  - #/about fires POST /api/visit on load (no click).

Covered here:
  - click_refusal: destructive and state-changing words in text, aria-label,
    id and class hints (camelCase split), forms, submit controls, disabled;
    controls: neutral labels are allowed;
  - crawl_views with a fake adapter: per-view, per-crawl and time budgets, one
    try per control across views, restore after a click that changed the view;
    control: the default (0) never asks for candidates;
  - a real Chromium crawl (PlaywrightDriver.crawl_spa): the dialog's reviews call
    is captured and recorded with the option on, not off; Delete, Logout and the
    in-form button are never clicked (their hit counts stay 0) while "Open details"
    is; the off-scope call is blocked by the router (the second server sees
    nothing; control: with it in scope the same click reaches it); the POST a
    click fires is held, never sent, even when the gate allows writes (control:
    the page-load POST of #/about is sent under that gate, as before); the click's
    read carried the crawling identity; budgets stop clicking and the crawl still
    completes;
  - through build_engagement: the click's capture feeds discovery and the route
    map keeps the "open view, click control" recipe; control: the switch off;
  - the stored_xss read-back replays the recipe: a review stored in the JSON API
    runs when the product dialog renders it (confirmed); control: a route map
    from a crawl without clicks has no view for the API and does not confirm.
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
from urllib.parse import urlsplit

from harness import cache, config_schema, engagement_builder, global_throttle, store
from harness.browser_driver import PlaywrightDriver
from harness.client_routes import ClientRouteMap
from harness.models import Finding, HttpExchange
from harness.role_crawl import RoleSession
from harness.run_context import RunContext, ScopePolicy
from harness.safety_gate import ActionRiskTier, AuthorizationDecision
from harness.spa_navigation import click_hints, click_refusal, crawl_views, view_key
from harness.test_spa_declared_views import _CHROMIUM, _config
from harness.validators import route_candidates
from harness.validators.registry import ValidatorRegistry

TOKEN = "CLICK-EXPLORE-TOKEN"
IDENTITY = {"Authorization": f"Bearer {TOKEN}"}
LOW = RoleSession("user", IDENTITY, name="low-user")
_GATE = {"active_enabled": True, "allow_mutating_replay": True}


# --------------------------------------------------------------------------
# click_refusal
# --------------------------------------------------------------------------

class ClickRefusalTest(unittest.TestCase):
    def _d(self, **kw):
        return {"selector": "#x", **kw}

    def test_destructive_and_state_changing_controls_are_refused(self):
        cases = [
            self._d(text="Delete"), self._d(text="Remove item"), self._d(aria="Log out"),
            self._d(id="logoutButton"), self._d(cls="mat-button btn-delete"),
            self._d(text="Sign out"), self._d(id="signOut"), self._d(text="Unsubscribe"),
            self._d(text="Pay now"), self._d(text="Checkout"), self._d(text="Place order"),
            self._d(text="Submit"), self._d(text="Reset password"), self._d(text="Clear basket"),
            self._d(aria="Add to Basket"), self._d(title="Erase my data"),
            self._d(name="destroySession"), self._d(text="SAVE"), self._d(onclick="removeRow(3)"),
            self._d(data="data-action empty-cart"), self._d(text="mat-icon delete"),
        ]
        for desc in cases:
            with self.subTest(desc=desc):
                self.assertIn("destructive or state-changing", click_refusal(desc))

    def test_forms_submit_controls_and_disabled_controls_are_refused(self):
        self.assertIn("inside a form", click_refusal(self._d(text="Preview", in_form=True)))
        self.assertIn("submit", click_refusal(self._d(text="Go", type="submit")))
        self.assertIn("reset", click_refusal(self._d(text="Go", type="reset")))
        self.assertEqual(click_refusal(self._d(text="Go", disabled=True)), "disabled")
        self.assertEqual(click_refusal({"text": "Open"}), "no selector names it")

    def test_control_neutral_controls_are_allowed(self):
        for desc in (self._d(text="Open details"), self._d(text="Apple juice (1000ml)"),
                     self._d(aria="Show the shopping cart"), self._d(text="Reviews"),
                     self._d(text="Display options"), self._d(cls="mat-card product-card"),
                     self._d(text="Menu"), self._d(text="Next page")):
            with self.subTest(desc=desc):
                self.assertEqual(click_refusal(desc), "")

    def test_hints_split_camel_case_and_separators(self):
        self.assertEqual(click_hints({"id": "logoutButton", "cls": "btn-delete_now"}),
                         "logout button btn delete now")


# --------------------------------------------------------------------------
# crawl_views with a fake adapter
# --------------------------------------------------------------------------

class _FakeClicks:
    """Views with links and click candidates; clicking a selector in `fires`
    returns those calls and changes the view."""

    def __init__(self, links, candidates, fires=(), slow=0.0):
        self.links_by, self.cands, self.fires, self.slow = links, candidates, dict(fires), slow
        self.cur, self.asked, self.clicked, self.restored, self._pending = "", 0, [], [], []

    async def open(self, url):
        self.cur = url

    async def links(self):
        return self.links_by.get(view_key(self.cur), [])

    async def drain(self):
        out, self._pending = self._pending, []
        return out

    def current_url(self):
        return self.cur

    async def click_candidates(self):
        self.asked += 1
        return [dict(d) for d in self.cands.get(view_key(self.cur), [])]

    async def click(self, desc):
        if self.slow:
            time.sleep(self.slow)
        self.clicked.append((view_key(self.cur), desc["selector"]))
        calls = self.fires.get(desc["selector"], [])
        self._pending = [{"method": m, "url": u, "request_body": ""} for m, u in calls]
        return {"clicked": True, "revealed": 10 if calls else 0, "dialog": bool(calls)}

    async def restore(self, url):
        self.restored.append(view_key(url))
        self.cur = url

    async def end_click(self):
        return {"held": [], "blocked": []}


B = "http://app.test"


def _cands(*names):
    return [{"selector": f"#{n}", "text": n} for n in names]


class CrawlViewsClicksTest(unittest.TestCase):
    def _run(self, adapter, **kw):
        return asyncio.run(crawl_views(adapter, f"{B}/#/", in_scope=lambda u: True, **kw))

    def _adapter(self, **kw):
        return _FakeClicks(
            {"/#/": ["#/a", "#/b"]},
            {"/#/": _cands("menu"), "/#/a": _cands("menu", "one", "two", "delete", "three"),
             "/#/b": _cands("four", "five")},
            fires={"#one": [("GET", f"{B}/api/one?x=1")]}, **kw)

    def test_clicks_are_recorded_and_the_view_restored(self):
        fake = self._adapter()
        res = self._run(fake, clicks_per_view=8, max_clicks=20)
        self.assertEqual(fake.clicked, [("/#/", "#menu"), ("/#/a", "#one"), ("/#/a", "#two"),
                                        ("/#/a", "#three"), ("/#/b", "#four"), ("/#/b", "#five")])
        one = next(c for c in res.clicks if c["selector"] == "#one")
        self.assertEqual(one["calls"], ["GET /api/one"])
        self.assertTrue(one["dialog"])
        self.assertEqual(fake.restored, ["/#/a"])          # only the click that changed it
        self.assertIn(f"{B}/api/one?x=1", [e["url"] for e in res.exchanges])
        self.assertIn("click on #one", next(e for e in res.exchanges
                                            if e["url"].endswith("x=1"))["analyst_note"])
        self.assertEqual(res.click_calls, [(f"{B}/#/a", "#one", "GET", f"{B}/api/one?x=1", "")])
        self.assertEqual([s["label"] for s in res.click_skips], ["delete"])
        self.assertEqual(res.click_stopped_by, "")
        # A view's calls stay the view's: the click call is not a view call.
        self.assertFalse([c for c in res.view_calls if "api/one" in c[2]])

    def test_the_per_view_and_per_crawl_budgets_stop_clicking(self):
        fake = self._adapter()
        res = self._run(fake, clicks_per_view=1, max_clicks=20)
        self.assertEqual(fake.clicked, [("/#/", "#menu"), ("/#/a", "#one"), ("/#/b", "#four")])
        fake = self._adapter()
        res = self._run(fake, clicks_per_view=8, max_clicks=3)
        self.assertEqual(len(fake.clicked), 3)
        self.assertEqual(res.click_stopped_by, "max_clicks")
        self.assertEqual(len(res.views), 3)                # the crawl went on
        self.assertEqual(res.stopped_by, "exhausted")

    def test_the_time_budget_stops_clicking(self):
        fake = self._adapter(slow=0.06)
        res = self._run(fake, clicks_per_view=8, max_clicks=20, click_seconds=0.1)
        self.assertLess(len(fake.clicked), 6)
        self.assertEqual(res.click_stopped_by, "click_seconds")
        self.assertEqual(len(res.views), 3)

    def test_control_the_default_never_asks_for_candidates(self):
        fake = self._adapter()
        res = self._run(fake)
        self.assertEqual((fake.asked, fake.clicked, res.clicks), (0, [], []))
        res = self._run(fake, clicks_per_view=8, max_clicks=0)
        self.assertEqual((fake.asked, fake.clicked), (0, []))


class ClickRecipeMapTest(unittest.TestCase):
    def test_a_click_recipe_is_kept_by_route_and_persists(self):
        m = ClientRouteMap()
        m.add_url(f"{B}/", "crawl")
        m.add_click(f"{B}/#/products?sort=new", "#view > ul > li:nth-of-type(1)",
                    [("GET", f"{B}/api/reviews?product=7", ""), ("POST", f"{B}/api/star", "{}"),
                     ("GET", "http://cdn.test/x", "")])
        want = [(f"{B}/#/products", "#view > ul > li:nth-of-type(1)")]
        self.assertEqual(m.clicks_for_api("GET", f"{B}/api/reviews"), want)
        self.assertEqual(m.clicks_for_api("POST", f"{B}/api/star"), [])
        self.assertEqual(list(m.api_clicks), ["GET /api/reviews"])
        self.assertNotIn("new", json.dumps(m.api_clicks))
        again = ClientRouteMap.from_dict(json.loads(json.dumps(m.to_dict())))
        self.assertEqual(again.clicks_for_api("GET", f"{B}/api/reviews"), want)
        merged = ClientRouteMap()
        merged.merge(again)
        self.assertEqual(merged.clicks_for_api("GET", f"{B}/api/reviews"), want)

    def test_control_no_click_leaves_the_snapshot_as_before(self):
        m = ClientRouteMap()
        m.add_url(f"{B}/", "crawl")
        self.assertNotIn("api_clicks", m.to_dict())
        m.add_click("http://other.test/#/x", "#a", [("GET", "http://other.test/api/r", "")])
        m.add_click(f"{B}/#/logout", "#a", [("GET", f"{B}/api/r", "")])
        self.assertEqual(m.api_clicks, {})


class ClickConfigTest(unittest.TestCase):
    def test_off_by_default_and_forced_off_by_passive_only(self):
        import yaml
        with open(Path(__file__).resolve().parent / "config.yaml") as f:
            cfg = yaml.safe_load(f)
        self.assertIs(cfg["driver_capture"]["click_explore"], False)
        self.assertIn("driver_capture.click_explore", config_schema._PASSIVE_FORCE_OFF_KNOBS)
        self.assertEqual(engagement_builder._click_kwargs(cfg["driver_capture"]), {})
        on = dict(cfg["driver_capture"], click_explore=True)
        self.assertEqual(engagement_builder._click_kwargs(on),
                         {"clicks_per_view": 8, "max_clicks": 60, "click_seconds": 120.0})


# --------------------------------------------------------------------------
# The loopback fixture
# --------------------------------------------------------------------------

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>Shop</title>
<style>.card { cursor: pointer; padding: 4px; }</style></head>
<body><nav><a href="#/products">Products</a> <a href="#/about">About</a></nav>
<main id="view"></main><script src="/static/app.js"></script></body></html>"""

_APP_JS = """(function () {
  var OFF = "__OFF__";
  var views = {
    "": '<p>home</p>',
    "products": '<ul class="cards"><li class="card" data-product="1">Apple juice</li>' +
      '<li class="card" data-product="2">Lemon juice</li></ul>' +
      '<button id="open">Open details</button>' +
      '<button class="btn-delete">Delete</button>' +
      '<a href="#" id="logout">Logout</a>' +
      '<button id="peek">Peek</button>' +
      '<button id="star">Star</button>' +
      '<form><button type="button" id="inform">Preview</button></form>',
    "about": '<p>About us</p>'
  };
  function hit(name) { fetch("/hit/" + name); }
  function openDialog(id) {
    var d = document.createElement("div");
    d.setAttribute("role", "dialog");
    d.id = "dlg";
    document.body.appendChild(d);
    fetch("/api/reviews?product=" + id).then(function (r) { return r.json(); })
      .then(function (list) {
        d.innerHTML = "<h2>Reviews</h2>" + list.map(function (x) {
          return "<p>" + x.text + "</p>"; }).join("");
      });
  }
  function render() {
    var p = (location.hash || "#/").replace(/^#\\/?/, "").split("?")[0];
    document.getElementById("view").innerHTML = views[p] || views[""];
    document.querySelectorAll(".card").forEach(function (c) {
      c.addEventListener("click", function () { openDialog(c.getAttribute("data-product")); });
    });
    var on = function (id, f) { var e = document.getElementById(id); if (e) e.addEventListener("click", f); };
    on("open", function () { hit("open"); });
    on("logout", function (ev) { ev.preventDefault(); hit("logout"); });
    on("peek", function () { fetch(OFF + "/beacon").catch(function () {}); });
    on("star", function () { fetch("/api/star", {method: "POST", body: "{}"}).catch(function () {}); });
    on("inform", function () { hit("inform"); });
    var del = document.querySelector(".btn-delete");
    if (del) del.addEventListener("click", function () { hit("delete"); });
    if (p === "about") fetch("/api/visit", {method: "POST", body: "{}"}).catch(function () {});
  }
  window.addEventListener("hashchange", render);
  render();
})();
"""


class _Handler(BaseHTTPRequestHandler):
    log: list = []
    reviews: list = []
    off_port = 0

    def do_GET(self):
        parts = urlsplit(self.path)
        _Handler.log.append(("GET", parts.path, self.headers.get("Authorization")))
        if parts.path == "/":
            return self._reply(_SHELL, "text/html")
        if parts.path == "/static/app.js":
            return self._reply(_APP_JS.replace("__OFF__", f"http://127.0.0.2:{_Handler.off_port}"),
                               "application/javascript")
        if parts.path == "/api/reviews":
            return self._reply(json.dumps(_Handler.reviews), "application/json")
        if parts.path.startswith(("/api/", "/hit/")):
            return self._reply("{}", "application/json")
        self._reply("", "text/plain", 404)

    def do_POST(self):
        parts = urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        _Handler.log.append(("POST", parts.path, self.headers.get("Authorization")))
        if parts.path == "/api/reviews":
            try:
                text = str((json.loads(body or b"{}") or {}).get("text", ""))
            except ValueError:
                return self._reply("", "text/plain", 400)
            _Handler.reviews.append({"text": text})
            return self._reply(json.dumps({"ok": True}), "application/json", 201)
        self._reply("{}", "application/json")

    def _reply(self, text, ctype, status=200):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _OffHandler(BaseHTTPRequestHandler):
    hits: list = []

    def do_GET(self):
        _OffHandler.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def log_message(self, *args):
        pass


def _hits(method, path):
    return [e for e in _Handler.log if e[0] == method and e[1] == path]


class _Gate:
    """A gate that allows (or denies) every write and records what it was asked."""

    def __init__(self, allow):
        self.allow, self.asked = allow, []

    def authorize(self, *, validator_name, method, url, **_kw):
        self.asked.append((validator_name, method, urlsplit(url).path))
        return AuthorizationDecision(allowed=self.allow, tier=ActionRiskTier.SAFE,
                                     reason="ok" if self.allow else "writes are off")


class _Servers:
    @classmethod
    def start(cls, owner):
        owner.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        owner.base = f"http://127.0.0.1:{owner.server.server_address[1]}"
        threading.Thread(target=owner.server.serve_forever, daemon=True).start()
        owner.off_server = ThreadingHTTPServer(("127.0.0.2", 0), _OffHandler)
        _Handler.off_port = owner.off_server.server_address[1]
        threading.Thread(target=owner.off_server.serve_forever, daemon=True).start()

    @classmethod
    def stop(cls, owner):
        for srv in (owner.server, owner.off_server):
            srv.shutdown()
            srv.server_close()


def _reset():
    _Handler.log.clear()
    _Handler.reviews.clear()
    _OffHandler.hits.clear()


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class PlaywrightClickCrawlTest(unittest.TestCase):
    """PlaywrightDriver.crawl_spa with clicks, a real browser on the loopback app."""

    @classmethod
    def setUpClass(cls):
        _Servers.start(cls)

    @classmethod
    def tearDownClass(cls):
        _Servers.stop(cls)

    def setUp(self):
        _reset()

    def _crawl(self, *, hosts=("127.0.0.1",), gate=None, **kw):
        scope = ScopePolicy(allowed_hosts=frozenset(hosts))
        kw.setdefault("clicks_per_view", 8)
        kw.setdefault("max_clicks", 30)
        return asyncio.run(PlaywrightDriver().crawl_spa(
            f"{self.base}/#/", wait_ms=400, headers=IDENTITY, scope=scope, gate=gate, **kw))

    def _clicks(self, res):
        return {c["label"]: c for c in res.clicks}

    def test_the_dialog_a_click_opens_is_recorded(self):
        res = self._crawl()
        self.assertEqual(res.errors, [])
        clicks = self._clicks(res)
        apple = clicks["Apple juice"]
        self.assertEqual(apple["outcome"], "clicked", apple)
        self.assertEqual(apple["calls"], ["GET /api/reviews"])
        self.assertTrue(apple["dialog"])
        self.assertGreater(apple["revealed"], 0)
        self.assertEqual(apple["view"], "/#/products")
        reviews = [e for e in res.exchanges if "/api/reviews" in e["url"]]
        self.assertEqual({urlsplit(e["url"]).query for e in reviews}, {"product=1", "product=2"})
        self.assertIn("click on", reviews[0]["analyst_note"])
        # The click's read went through the identity router: it carried the identity.
        self.assertTrue(_hits("GET", "/api/reviews"))
        self.assertTrue(all(a == f"Bearer {TOKEN}" for _m, _p, a in _hits("GET", "/api/reviews")))
        self.assertEqual(reviews[0]["request_headers"].get("Authorization"), f"Bearer {TOKEN}")
        recipe = [c for c in res.click_calls if "/api/reviews" in c[3]]
        self.assertEqual(recipe[0][0], f"{self.base}/#/products")
        self.assertTrue(recipe[0][1])

    def test_control_without_the_option_no_click_is_made(self):
        res = self._crawl(clicks_per_view=0, max_clicks=0)
        self.assertEqual(res.clicks, [])
        self.assertFalse([e for e in res.exchanges if "/api/reviews" in e["url"]])
        self.assertEqual(_hits("GET", "/api/reviews"), [])
        self.assertEqual(_hits("GET", "/hit/open"), [])
        self.assertIn(f"{self.base}/#/products", res.views)

    def test_delete_logout_and_form_controls_are_never_clicked(self):
        res = self._crawl()
        self.assertEqual(_hits("GET", "/hit/delete"), [])
        self.assertEqual(_hits("GET", "/hit/logout"), [])
        self.assertEqual(_hits("GET", "/hit/inform"), [])
        skipped = {s["label"]: s["reason"] for s in res.click_skips}
        self.assertIn("destructive", skipped["Delete"])
        self.assertIn("destructive", skipped["Logout"])
        self.assertIn("inside a form", skipped["Preview"])
        # Control: a neutral control on the same view is clicked, and reaches the server.
        self.assertEqual(len(_hits("GET", "/hit/open")), 1)
        self.assertEqual(self._clicks(res)["Open details"]["calls"], ["GET /hit/open"])

    def test_an_off_scope_call_a_click_fires_is_blocked(self):
        res = self._crawl()
        self.assertEqual(_OffHandler.hits, [])
        peek = self._clicks(res)["Peek"]
        self.assertTrue(any("127.0.0.2" in b and "not in scope" in b for b in peek["blocked"]),
                        peek)

    def test_control_the_same_click_reaches_a_host_in_scope(self):
        res = self._crawl(hosts=("127.0.0.1", "127.0.0.2"))
        self.assertEqual(_OffHandler.hits, ["/beacon"])
        self.assertEqual(self._clicks(res)["Peek"]["blocked"], [])

    def test_a_post_a_click_fires_is_held_even_when_the_gate_allows_writes(self):
        gate = _Gate(allow=True)
        res = self._crawl(gate=gate)
        self.assertEqual(_hits("POST", "/api/star"), [])
        star = self._clicks(res)["Star"]
        self.assertTrue(any("/api/star" in h and "never sends a write" in h for h in star["held"]),
                        star)
        self.assertIn(("browser", "POST", "/api/star"), gate.asked)
        # Control: the page-load write of #/about takes today's path and is sent.
        self.assertEqual(len(_hits("POST", "/api/visit")), 1)

    def test_a_post_a_click_fires_is_refused_by_a_closed_gate(self):
        res = self._crawl(gate=_Gate(allow=False))
        self.assertEqual(_hits("POST", "/api/star"), [])
        star = self._clicks(res)["Star"]
        self.assertTrue(any("gate denied" in h for h in star["held"]), star)
        self.assertEqual(_hits("POST", "/api/visit"), [])

    def _visit(self, clicks, gate=None):
        scope = ScopePolicy(allowed_hosts=frozenset({"127.0.0.1"}))
        return asyncio.run(PlaywrightDriver().visit(
            f"{self.base}/#/products", wait_ms=400, headers=IDENTITY, scope=scope, gate=gate,
            clicks=clicks))

    def test_a_recipe_replay_clicks_and_holds_its_writes(self):
        obs = self._visit(["#view > ul:nth-of-type(1) > li:nth-of-type(1)", "#star"],
                          gate=_Gate(allow=True))
        self.assertEqual(obs.load_error, "")
        self.assertTrue(all(c.endswith(": clicked") for c in obs.clicks), obs.clicks)
        self.assertEqual(len(_hits("GET", "/api/reviews")), 1)
        self.assertEqual(_hits("POST", "/api/star"), [])
        self.assertTrue(any("/api/star" in h for h in obs.held_writes), obs.held_writes)

    def test_control_a_recipe_naming_a_destructive_control_is_refused(self):
        obs = self._visit([".btn-delete"])
        self.assertIn("refused: destructive", obs.clicks[0])
        self.assertEqual(_hits("GET", "/hit/delete"), [])

    def test_budgets_stop_clicking_and_the_crawl_completes(self):
        res = self._crawl(max_clicks=2)
        self.assertEqual(len(res.clicks), 2)
        self.assertEqual(res.click_stopped_by, "max_clicks")
        self.assertEqual(_hits("GET", "/hit/open"), [])
        self.assertIn(f"{self.base}/#/about", res.views)
        self.assertEqual(res.stopped_by, "exhausted")
        _reset()
        res = self._crawl(click_seconds=0)
        self.assertEqual(res.clicks, [])
        self.assertEqual(res.click_stopped_by, "click_seconds")
        self.assertIn(f"{self.base}/#/about", res.views)
        # Control: a per-view budget of 3 clicks three controls of #/products.
        _reset()
        res = self._crawl(clicks_per_view=3)
        self.assertEqual([c["label"] for c in res.clicks],
                         ["Apple juice", "Lemon juice", "Open details"])


# --------------------------------------------------------------------------
# Through build_engagement, and the stored_xss read-back
# --------------------------------------------------------------------------

def _finding():
    return Finding(vulnerability_class="stored_xss", confidence=0.5, summary="stored xss candidate",
                   evidence="", suggested_test="plant and render", basis="assumed", severity="high")


def _write(base):
    return HttpExchange(url=f"{base}/api/reviews", method="POST",
                        request_headers={"Content-Type": "application/json",
                                         "Accept": "application/json",
                                         "Authorization": f"Bearer {TOKEN}"},
                        request_body='{"text": "hello"}', response_status=201,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"ok": true}')


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class BuildEngagementClicksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="click_explore_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))
        route_candidates._STORED.clear()
        _Servers.start(cls)
        global_throttle.configure(0)
        cls.on = cls._build({"click_explore": True})
        cls.off = cls._build({})

    @classmethod
    def tearDownClass(cls):
        _Servers.stop(cls)
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        route_candidates._STORED.clear()
        shutil.rmtree(cls._tmp, ignore_errors=True)

    @classmethod
    def _build(cls, extra):
        from harness.orchestrator_helpers import per_run_gate_config
        cfg = _config()
        _reset()

        async def build():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                return await engagement_builder.build_engagement(
                    cls.base, [LOW], allowed_hosts=["127.0.0.1"], crawl_max_pages=4,
                    active_discovery=False, run_context=ctx,
                    driver_capture_config={"enabled": True, "spa_navigation": True,
                                           "wait_ms": 500, "max_views": 8, **extra})
        state, result = asyncio.run(build())
        return state, result, list(_Handler.log)

    def setUp(self):
        _reset()
        global_throttle.configure(0)
        route_candidates._STORED.clear()

    @staticmethod
    def _click_captures(result):
        return [c for c in result.captured if "click on" in (c.get("analyst_note") or "")]

    def test_the_click_capture_feeds_discovery_and_the_recipe_is_mapped(self):
        state, result, _log = self.on
        spa = next(v for v in result.spa_views if v["principal"] == "low-user")
        self.assertTrue(spa["clicks"], spa)
        captures = self._click_captures(result)
        self.assertIn("/api/reviews", {urlsplit(c["url"]).path for c in captures})
        self.assertIn("GET /api/reviews", state.endpoints)
        recipes = state.client_routes.clicks_for_api("GET", f"{self.base}/api/reviews")
        self.assertTrue(recipes)
        self.assertEqual(recipes[0][0], f"{self.base}/#/products")
        self.assertIn("li", recipes[0][1])

    def test_control_the_switch_off_makes_no_click(self):
        state, result, log = self.off
        spa = next(v for v in result.spa_views if v["principal"] == "low-user")
        self.assertNotIn("clicks", spa)
        self.assertEqual(self._click_captures(result), [])
        self.assertFalse([e for e in log if e[1] == "/hit/open"])
        routes = getattr(state, "client_routes", None)
        self.assertEqual(routes.clicks_for_api("GET", f"{self.base}/api/reviews") if routes else [],
                         [])

    def _dispatch(self, routes):
        reg = ValidatorRegistry({"validators": {"active_enabled": True,
                                                "allow_mutating_replay": True}})
        exchange = _write(self.base)
        matched = [v for v in reg.for_finding(_finding(), exchange) if v.name == "stored_xss"]
        self.assertTrue(matched, "the registry did not route the write to stored_xss")

        async def run():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], gate_config=_GATE) as ctx:
                ctx.client_routes = routes
                leg = reg.bind_run_context(matched, ctx)[0]
                return await leg.validate(_finding(), exchange)
        return asyncio.run(run())

    def test_the_read_back_replays_the_click_recipe(self):
        res = self._dispatch(self.on[0].client_routes)
        self.assertEqual(res.status, "confirmed", f"{res.summary} | {res.evidence}")
        self.assertIn("client view /#/products", res.summary)
        self.assertIn("After clicking", res.evidence)

    def test_control_without_a_recipe_the_read_back_does_not_confirm(self):
        res = self._dispatch(getattr(self.off[0], "client_routes", None) or ClientRouteMap())
        self.assertEqual(res.status, "not_confirmed", f"{res.summary} | {res.evidence}")
        self.assertNotIn("After clicking", res.evidence)


if __name__ == "__main__":
    unittest.main()
