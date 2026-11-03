"""Crawl loop -- the run sees the attack surface continuously, not once.

Five pieces, each behind its own config key and off by default:
  - SPA navigation (driver_capture.spa_navigation): the browser walks the app's
    client-side views and records each view's XHR/fetch calls;
  - route feedback + re-crawl (engagement.recrawl): routes first seen after
    discovery go back to the worklist under a dedup and budget guard;
  - per-principal crawl (engagement.crawl_per_principal): two same-role users are
    two sweeps;
  - session freshness (transport.session_freshness): a sustained 401/403 rate on
    routes a session was served refreshes it, else marks it stale;
  - phase time-slices (engagement.phase_slices) under investigation_seconds.

Fixtures: a fake hash-routed SPA and an expiring-token target on 127.0.0.1. Every
behaviour has a negative control (the feature off, or the trigger absent).
"""
from __future__ import annotations

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
from unittest.mock import AsyncMock, patch

from harness import (cache, config_schema, coverage_tracker, driver_capture, engagement_builder,
                     evidence_ledger, role_crawl, safety_gate, store, worklist_investigator)
from harness.browser_driver import PlaywrightDriver, playwright_available
from harness.engagement import EngagementState
from harness.orchestrator import Orchestrator
from harness.phase_schedule import PhaseSchedule
from harness.role_crawl import RoleSession
from harness.route_feed import RecrawlConfig, RouteFeed
from harness.run_context import RunContext, ScopePolicy, TypedRequest
from harness.session_freshness import FreshnessConfig, SessionFreshness, login_refresher
from harness.spa_navigation import crawl_views, resolve_view, view_key
from harness.test_deterministic_first import BASE, _config
from harness.test_stage_reservations import _build

TOKEN = "CRAWL-LOOP-TOKEN"
IDENTITY = {"Authorization": f"Bearer {TOKEN}"}


# ------------------------------------------------------------------ fixtures
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _answer(self):
        srv = self.server
        path = self.path.split("?", 1)[0]
        auth = self.headers.get("Authorization")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        with srv.lock:
            srv.received.append((self.command, path, auth))
            status, ctype, text = srv.respond(self.command, path, auth, body)
        data = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _answer


class _Target:
    """`respond(method, path, authorization, body) -> (status, content_type, text)`."""

    def __init__(self, respond):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.received, self.httpd.lock, self.httpd.respond = [], threading.Lock(), respond
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def received(self, path=None) -> list:
        with self.httpd.lock:
            return [r for r in self.httpd.received if path is None or r[1] == path]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._t.join(5)


def _ctx(config=None, **kw):
    kw.setdefault("allowed_hosts", ["127.0.0.1"])
    kw.setdefault("gate_config", {"active_enabled": True, "allow_mutating_replay": True})
    return RunContext.create(config=config or {}, **kw)


_FRESHNESS = {"transport": {"session_freshness": {
    "enabled": True, "window": 6, "min_denials": 3, "min_routes": 2, "denial_rate": 0.5}}}


# ------------------------------------------------------------------ 1. SPA navigation
class ResolveViewTests(unittest.TestCase):
    def test_hash_routes_and_router_paths_in_a_hash_routed_app(self):
        cur = "http://shop.test/#/home"
        self.assertEqual(resolve_view(cur, "#/basket"), "http://shop.test/#/basket")
        self.assertEqual(resolve_view(cur, "/orders"), "http://shop.test/#/orders")
        self.assertEqual(resolve_view(cur, "orders?x=1"), "http://shop.test/#/orders?x=1")
        self.assertEqual(resolve_view("http://shop.test/#!/a", "b"), "http://shop.test/#!/b")

    def test_non_views_are_dropped(self):
        cur = "http://shop.test/page"
        for raw in ("", "#", "#!", "#top", "javascript:void(0)", "mailto:a@b", "data:x"):
            self.assertIsNone(resolve_view(cur, raw), raw)
        # An in-page anchor on a server route keeps the route, not the anchor.
        self.assertEqual(resolve_view(cur, "/about#team"), "http://shop.test/about")

    def test_view_key_ignores_query_values(self):
        self.assertEqual(view_key("http://s/#/track?id=1"), view_key("http://s/#/track?id=2"))
        self.assertNotEqual(view_key("http://s/#/a"), view_key("http://s/#/b"))


class _FakeSpa:
    """An adapter over a dict view -> (links, exchanges fired)."""

    def __init__(self, views):
        self.views, self.opened, self.cur = views, [], ""

    async def open(self, url):
        self.opened.append(url)
        self.cur = url

    async def links(self):
        return self.views.get(view_key(self.cur), ([], []))[0]

    async def drain(self):
        return [dict(e) for e in self.views.get(view_key(self.cur), ([], []))[1]]

    def current_url(self):
        return self.cur


def _api(path):
    return {"method": "GET", "url": f"http://shop.test{path}", "request_body": ""}


SPA_VIEWS = {
    "/#/home": (["#/basket", "/orders", "#/logout", "http://evil.test/#/x", "/a.pdf", "#top"],
                [_api("/api/home")]),
    "/#/basket": (["#/home", "#/basket/delete"], [_api("/api/basket"), _api("/api/home")]),
    "/#/orders": (["#/orders/2"], [_api("/api/orders")]),
    "/#/orders/2": ([], [_api("/api/orders/2")]),
}


class CrawlViewsTests(unittest.TestCase):
    def _crawl(self, **kw):
        spa = _FakeSpa(SPA_VIEWS)
        res = asyncio.run(crawl_views(spa, "http://shop.test/#/home",
                                      in_scope=lambda u: "shop.test" in u, **kw))
        return spa, res

    def test_walks_every_in_scope_view_and_records_its_calls(self):
        spa, res = self._crawl()
        self.assertEqual([view_key(v) for v in res.views],
                         ["/#/home", "/#/basket", "/#/orders", "/#/orders/2"])
        self.assertEqual(sorted(e["url"] for e in res.exchanges),
                         sorted(f"http://shop.test{p}" for p in
                                ("/api/home", "/api/basket", "/api/orders", "/api/orders/2")))
        self.assertEqual(res.stopped_by, "exhausted")
        note = next(e for e in res.exchanges if e["url"].endswith("/api/basket"))["analyst_note"]
        self.assertIn("view /#/basket", note)
        # logout and delete are destructive, the other origin out of scope.
        self.assertEqual(res.skipped["destructive"], 2)
        self.assertEqual(res.skipped["out_of_scope"], 1)
        self.assertFalse(any("logout" in u or "delete" in u for u in spa.opened))

    def test_control_one_view_is_the_old_single_page_load(self):
        spa, res = self._crawl(max_views=1)
        self.assertEqual(spa.opened, ["http://shop.test/#/home"])
        self.assertEqual([e["url"] for e in res.exchanges], ["http://shop.test/api/home"])
        self.assertEqual(res.stopped_by, "max_views")

    def test_depth_budget_and_cancel_bound_the_walk(self):
        _, res = self._crawl(max_depth=1)
        self.assertNotIn("/#/orders/2", [view_key(v) for v in res.views])
        _, res = self._crawl(budget=type("B", (), {"remaining": 0})())
        self.assertEqual((res.views, res.stopped_by), ([], "budget"))
        _, res = self._crawl(cancel=lambda: True)
        self.assertEqual(res.stopped_by, "cancelled")

    def test_extra_views_seed_the_queue(self):
        spa, _ = self._crawl(extra_views=["#/orders/2"], max_depth=0)
        self.assertIn("http://shop.test/#/orders/2", spa.opened)


_SPA_PAGE = """<!doctype html><html><body>
<nav><a href="#/basket">Basket</a> <span routerlink="orders">Orders</span>
<a href="#/logout">Logout</a> <a href="http://127.0.0.9/#/away">Away</a></nav>
<script>
function load() {
  const view = (location.hash.replace(/^#\\//, '') || 'home').split('/')[0];
  fetch('/api/' + view).then(r => r.text()).then(t => { document.title = t; });
}
window.addEventListener('hashchange', load);
load();
</script></body></html>"""


def _spa_respond(method, path, auth, body):
    if path == "/":
        return 200, "text/html", _SPA_PAGE
    if path.startswith("/api/"):
        return 200, "application/json", json.dumps({"view": path[5:]})
    return 404, "text/plain", "no"


@unittest.skipUnless(playwright_available(), "Playwright Chromium is not installed")
class PlaywrightSpaCrawlTests(unittest.TestCase):
    """A real browser against a fake hash-routed SPA."""

    def setUp(self):
        self.srv = _Target(_spa_respond)
        self.addCleanup(self.srv.close)

    def _crawl(self, **kw):
        scope = ScopePolicy(allowed_hosts=frozenset({"127.0.0.1"}))
        return asyncio.run(PlaywrightDriver().crawl_spa(
            f"{self.srv.base}/#/home", wait_ms=400, headers=IDENTITY, scope=scope, **kw))

    def test_every_view_fires_its_calls_with_the_identity(self):
        res = self._crawl()
        self.assertEqual(res.errors, [])
        api = {p for _, p, _ in self.srv.received() if p.startswith("/api/")}
        self.assertEqual(api, {"/api/home", "/api/basket", "/api/orders"})
        self.assertEqual(self.srv.received("/api/logout"), [])
        # The browser's calls carried the run identity, and the captures say so.
        self.assertTrue(all(a == f"Bearer {TOKEN}" for _, p, a in self.srv.received()
                            if p.startswith("/api/")))
        captured = {e["url"].split(self.srv.base, 1)[1]: e for e in res.exchanges}
        self.assertEqual(set(captured), {"/api/home", "/api/basket", "/api/orders"})
        self.assertEqual(captured["/api/orders"]["request_headers"].get("Authorization"),
                         f"Bearer {TOKEN}")

    def test_control_one_view_fetches_the_start_view_only(self):
        res = self._crawl(max_views=1)
        api = {p for _, p, _ in self.srv.received() if p.startswith("/api/")}
        self.assertEqual(api, {"/api/home"})
        self.assertEqual(res.stopped_by, "max_views")


def _two_users():
    return [RoleSession("anonymous", {}),
            RoleSession("user", {"Authorization": "Bearer U1"}, name="eval-user-1"),
            RoleSession("user", {"Authorization": "Bearer U2"}, name="eval-user-2")]


class BuildEngagementSpaCallerTests(unittest.TestCase):
    """build_engagement runs the SPA crawl per principal and binds its captures."""

    def _build(self, capture_cfg, *, per_principal=True):
        calls = {"spa": [], "single": []}

        async def crawl_spa(url, **kw):
            from harness.spa_navigation import SpaCrawlResult
            calls["spa"].append(kw["headers"])
            res = SpaCrawlResult(start_url=url, views=[url, url + "#/basket"],
                                 stopped_by="exhausted")
            if kw["headers"]:
                res.exchanges.append({"method": "GET", "url": f"{BASE}api/basket",
                                      "request_headers": dict(kw["headers"]),
                                      "response_status": 200, "response_body": "{}"})
            return res

        async def capture_requests(url, **kw):
            calls["single"].append(kw["headers"])
            return type("Obs", (), {"exchanges": [], "load_error": ""})()

        async def crawl_roles(base_url, roles, **kw):
            return role_crawl.RoleCrawlResult(base_url=base_url)

        rc = RunContext.create(allowed_hosts=["shop.test"], config={})

        async def go():
            try:
                return await engagement_builder.build_engagement(
                    BASE, _two_users(), allowed_hosts=["shop.test"], run_context=rc,
                    driver_capture_config=capture_cfg, per_principal=per_principal)
            finally:
                await rc.aclose()

        with patch.object(driver_capture, "crawl_spa", new=crawl_spa), \
                patch.object(driver_capture, "capture_requests", new=capture_requests), \
                patch.object(role_crawl, "crawl_roles", new=crawl_roles):
            state, result = asyncio.run(go())
        return calls, state, result

    def test_spa_crawl_runs_per_principal_and_binds_each_capture(self):
        calls, state, result = self._build({"enabled": True, "spa_navigation": True})
        self.assertEqual(len(calls["spa"]), 3)
        self.assertEqual(calls["single"], [])
        ep = state.endpoints["GET /api/basket"]
        self.assertEqual(set(ep.access_by_principal),
                         {"eval-user-1", "eval-user-2"})
        self.assertEqual([v["views"] for v in result.spa_views], [2, 2, 2])

    def test_control_spa_off_keeps_the_single_page_capture(self):
        calls, state, result = self._build({"enabled": True})
        self.assertEqual(calls["spa"], [])
        self.assertEqual(len(calls["single"]), 3)
        self.assertNotIn("GET /api/basket", state.endpoints)

    def test_control_same_role_principals_collapse_without_per_principal(self):
        calls, _, _ = self._build({"enabled": True, "spa_navigation": True},
                                  per_principal=False)
        # The 8-hour run's "swept 1 role": same-feature roles collapse to one crawl.
        self.assertEqual(len(calls["spa"]), 1)


# ------------------------------------------------------------------ 3. per-principal
class PerPrincipalRolesTests(unittest.TestCase):
    def test_one_crawl_per_registered_principal_authenticated_first(self):
        picked = role_crawl.crawl_roles_for(_two_users(), per_principal=True)
        self.assertEqual([r.principal_id() for r in picked],
                         ["eval-user-1", "eval-user-2", "anonymous"])

    def test_control_default_collapses_same_role_users(self):
        picked = role_crawl.crawl_roles_for(_two_users())
        self.assertEqual(len(picked), 1)


# ------------------------------------------------------------------ 2. route feed
def _feed(**kw):
    kw.setdefault("known", {("GET", "/api/known")})
    return RouteFeed(origin="http://shop.test", in_scope=lambda u: "/private" not in u, **kw)


def _offer(feed, path, method="GET", principal=None):
    return feed.offer_exchange({"method": method, "url": f"http://shop.test{path}",
                                "response_status": 200}, source="test", principal_id=principal)


class RouteFeedTests(unittest.TestCase):
    def test_new_routes_are_accepted_once_per_principal(self):
        feed = _feed()
        self.assertTrue(_offer(feed, "/api/orders/7", principal="u1"))
        self.assertFalse(_offer(feed, "/api/orders/8", principal="u1"))   # same template
        self.assertTrue(_offer(feed, "/api/orders/8", principal="u2"))
        self.assertEqual(feed.refused, {"duplicate": 1})
        drained = feed.drain()
        self.assertEqual([o.principal_id for o in drained], ["u1", "u2"])
        self.assertEqual(feed.pending(), 0)
        self.assertFalse(_offer(feed, "/api/orders/9", principal="u3"))   # now known

    def test_scope_origin_known_and_budget_guards(self):
        feed = _feed(max_new_routes=1)
        self.assertFalse(_offer(feed, "/api/known"))
        self.assertFalse(_offer(feed, "/private/x"))
        self.assertFalse(feed.offer_exchange({"url": "http://evil.test/api/x"}, source="t"))
        self.assertTrue(_offer(feed, "/api/a"))
        self.assertFalse(_offer(feed, "/api/b"))
        self.assertEqual(feed.refused, {"known": 1, "out_of_scope": 1, "off_origin": 1,
                                        "budget": 1})

    def test_responses_count_only_when_they_say_the_route_exists(self):
        feed = _feed()

        def see(path, status, ctype="application/json", capability="probe"):
            return feed.observe_response(
                capability=capability, method="GET", url=f"http://shop.test{path}",
                status=status, request_headers={"Authorization": "Bearer X", "Accept": "*/*"},
                request_body=None, response_headers={"Content-Type": ctype,
                                                     "Set-Cookie": "sid=1"},
                response_body=lambda: "{}")

        self.assertFalse(see("/spa/shell", 200, "text/html"))   # SPA fallback shell
        self.assertFalse(see("/api/missing", 404))
        self.assertFalse(see("/api/health", 200, capability="session_health"))
        self.assertTrue(see("/api/admin", 403))
        self.assertTrue(see("/api/data", 200))
        ex = feed.drain()[1].exchange
        self.assertEqual(ex["request_headers"], {"Accept": "*/*"})        # no credential
        self.assertNotIn("Set-Cookie", ex["response_headers"])


class TransportRouteFeedTests(unittest.TestCase):
    """The transport offers every response of the run to an installed feed."""

    def setUp(self):
        self.srv = _Target(lambda m, p, a, b: (200, "application/json", "{}")
                           if p.startswith("/api/") else (404, "text/plain", "no"))
        self.addCleanup(self.srv.close)

    def _send(self, install):
        ctx = _ctx()
        if install:
            ctx.route_feed = RouteFeed(origin=self.srv.base, in_scope=ctx.scope.in_scope)

        async def go():
            ex = ctx.executor()
            for path in ("/api/new", "/nothing"):
                await ex.execute(TypedRequest("GET", self.srv.base + path), capability="probe")
            await ctx.aclose()
        asyncio.run(go())
        return ctx

    def test_a_route_first_seen_in_a_response_is_queued(self):
        ctx = self._send(install=True)
        self.assertEqual([o.path for o in ctx.route_feed.drain()], ["/api/new"])

    def test_control_without_a_feed_nothing_is_offered(self):
        self.assertIsNone(self._send(install=False).route_feed)


class RecrawlStateTests(unittest.TestCase):
    """A fed-back route is re-crawled as every principal; access is per principal."""

    def test_authenticated_only_route_enters_with_the_principal_that_reached_it(self):
        srv = _Target(lambda m, p, a, b: (200, "application/json", "{}")
                      if a == "Bearer U1" else (401, "application/json", "{}"))
        self.addCleanup(srv.close)
        ctx = _ctx()
        roles = [RoleSession("anonymous", {}),
                 RoleSession("user", {"Authorization": "Bearer U1"}, name="u1")]
        engagement_builder.register_role_sessions(ctx, srv.base, roles)
        feed = RouteFeed(origin=srv.base, in_scope=ctx.scope.in_scope)
        feed.offer_exchange({"method": "GET", "url": f"{srv.base}/api/cards/3",
                             "response_status": 200}, source="test")

        async def go():
            try:
                return await engagement_builder.recrawl_state(srv.base, roles, feed.drain(),
                                                              run_context=ctx)
            finally:
                await ctx.aclose()
        state, captured = asyncio.run(go())
        obs = state.endpoints["GET /api/cards/{id}"].access_by_principal
        self.assertTrue(obs["u1"]["reachable"])
        self.assertFalse(obs["anonymous"]["reachable"])
        self.assertEqual(len(captured), 1)
        self.assertEqual(len(srv.received()), 2)            # one GET per principal


# ------------------------------------------------------------------ 4. session freshness
class _Session:
    def __init__(self, sid="s1"):
        self.session_id, self.name, self.generation = sid, sid, 0


class SessionFreshnessUnitTests(unittest.TestCase):
    def _monitor(self):
        return SessionFreshness(FreshnessConfig.from_config(_FRESHNESS))

    def test_denials_on_routes_once_served_make_the_session_stale(self):
        mon, s = self._monitor(), _Session()
        for path in ("/a", "/b/1"):
            self.assertFalse(mon.observe(s, "GET", f"http://t{path}", 200))
        verdicts = [mon.observe(s, "GET", f"http://t{p}", 401) for p in ("/a", "/b/2", "/a")]
        self.assertEqual(verdicts, [False, False, True])
        self.assertEqual(mon.evidence(s), {"window": 5, "denials": 3, "denied_routes": 2,
                                           "known_good_routes": 2})

    def test_control_denials_on_never_served_routes_are_access_control(self):
        mon, s = self._monitor(), _Session()
        mon.observe(s, "GET", "http://t/a", 200)
        self.assertFalse(any(mon.observe(s, "GET", f"http://t/admin/{p}", 403)
                             for p in ("x", "y", "z", "w", "v")))

    def test_control_one_route_denied_repeatedly_is_not_a_dead_session(self):
        mon, s = self._monitor(), _Session()
        mon.observe(s, "GET", "http://t/a", 200)
        mon.observe(s, "GET", "http://t/b", 200)
        self.assertFalse(any(mon.observe(s, "GET", "http://t/a", 401) for _ in range(4)))

    def test_feature_off_by_default(self):
        self.assertFalse(FreshnessConfig.from_config({}).enabled)
        self.assertIsNone(_ctx().freshness())


def _expiring(limit):
    """T1 is served `limit` requests, then rejected on every route; T2 always works."""
    served = {"t1": 0}

    def respond(method, path, auth, body):
        if method == "POST" and path == "/login":
            return 200, "application/json", json.dumps({"auth": {"token": "T2"}})
        if auth == "Bearer T2":
            return 200, "application/json", "{}"
        if auth == "Bearer T1" and served["t1"] < limit:
            served["t1"] += 1
            return 200, "application/json", "{}"
        return 401, "application/json", "{}"
    return _Target(respond)


class SessionFreshnessTransportTests(unittest.TestCase):
    """Through the real executor against a target whose token expires mid-run."""

    def setUp(self):
        self.srv = _expiring(limit=2)
        self.addCleanup(self.srv.close)

    def _run(self, config, refresh=None, paths=("/a", "/b", "/a", "/b", "/a", "/b")):
        ctx = _ctx(config)
        ctx.sessions.register("s1", "alice", {"Authorization": "Bearer T1"},
                              allowed_origins=[self.srv.base], name="alice")
        if refresh is not None:
            ctx.sessions.set_refresh("s1", refresh(ctx))

        async def go():
            ex = ctx.executor()
            outs = [await ex.execute(TypedRequest("GET", self.srv.base + p), capability="probe",
                                     session_ref="s1") for p in paths]
            await ctx.aclose()
            return outs
        return ctx, asyncio.run(go())

    def test_stale_session_is_refreshed_through_the_login_flow(self):
        login = {"method": "POST", "path": "/login", "body": {"email": "a", "password": "b"},
                 "token_pointer": "/auth/token"}
        ctx, outs = self._run(_FRESHNESS,
                              refresh=lambda c: login_refresher(c, login, self.srv.base))
        self.assertEqual([o.status for o in outs], [200, 200, 401, 401, 401, 200])
        self.assertEqual(len(self.srv.received("/login")), 1)
        self.assertEqual(self.srv.received()[-1][2], "Bearer T2")
        session = ctx.sessions.get("s1")
        self.assertEqual((session.health, session.generation), ("healthy", 1))
        events = [e for e in ctx.health.events() if e["kind"] == "session_refresh"]
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]["ok"])
        self.assertNotIn("T2", json.dumps(ctx.health.events()))       # no credential logged

    def test_without_a_refresh_the_session_is_stale_and_its_sends_refused(self):
        ctx, outs = self._run(_FRESHNESS)
        self.assertEqual([o.status for o in outs[:5]], [200, 200, 401, 401, 401])
        self.assertEqual(outs[5].outcome, "session_expired")          # refused unsent
        self.assertEqual(len(self.srv.received()), 5)
        self.assertEqual(ctx.sessions.get("s1").health, "stale")
        self.assertEqual([e["kind"] for e in ctx.health.events()], ["session_stale"])
        self.assertEqual([e["kind"] for e in ctx.freshness().events], ["session_stale"])

    def test_control_feature_off_keeps_sending_and_logs_nothing(self):
        ctx, outs = self._run({})
        self.assertEqual([o.status for o in outs], [200, 200, 401, 401, 401, 401])
        self.assertEqual(ctx.health.events(), [])
        self.assertNotEqual(ctx.sessions.get("s1").health, "stale")   # E5a may suspect it

    def test_control_denials_on_routes_never_served_are_not_staleness(self):
        ctx, outs = self._run(_FRESHNESS, paths=("/a", "/a", "/x", "/y", "/z", "/w"))
        self.assertNotEqual(ctx.sessions.get("s1").health, "stale")
        self.assertEqual(outs[-1].status, 401)
        self.assertEqual(ctx.health.events(), [])


class LoginRefresherTests(unittest.TestCase):
    def test_role_login_is_registered_as_the_session_refresh(self):
        ctx = _ctx()
        roles = [RoleSession("user", {"Authorization": "Bearer T1"}, name="u1",
                             login={"path": "/login", "token_pointer": "/auth/token"}),
                 RoleSession("user", {"Authorization": "Bearer U2"}, name="u2")]
        refs = engagement_builder.register_role_sessions(ctx, "http://127.0.0.1:1", roles)
        self.assertIsNotNone(ctx.sessions.get(refs[0])._refresh_fn)
        self.assertIsNone(ctx.sessions.get(refs[1])._refresh_fn)
        self.assertNotIn("login", repr(roles[0]))
        asyncio.run(ctx.aclose())

    def test_failed_login_returns_none(self):
        srv = _Target(lambda m, p, a, b: (401, "application/json", "{}"))
        self.addCleanup(srv.close)
        ctx = _ctx()

        async def go():
            try:
                return await login_refresher(ctx, {"path": "/login", "token_pointer": "/t"},
                                             srv.base)()
            finally:
                await ctx.aclose()
        self.assertIsNone(asyncio.run(go()))


# ------------------------------------------------------------------ 5. phase schedule
class _FakeClock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now


class PhaseScheduleTests(unittest.TestCase):
    def test_each_phase_gets_its_share_of_what_is_left(self):
        clock = _FakeClock()
        sched = PhaseSchedule(1000.0, {"worklist": 2, "capture_review": 1, "chain_rounds": 1},
                              clock=clock)
        self.assertEqual(sched.deadline_for("worklist"), 500.0)
        clock.now = 200.0                       # the worklist left 300 s unused
        self.assertEqual(sched.deadline_for("capture_review"), 600.0)
        clock.now = 600.0
        self.assertEqual(sched.deadline_for("chain_rounds"), 1000.0)

    def test_an_explicit_cap_still_binds(self):
        sched = PhaseSchedule(1000.0, {"capture_review": 1, "chain_rounds": 1},
                              clock=_FakeClock())
        self.assertEqual(sched.deadline_for("capture_review", 30.0), 30.0)

    def test_control_without_slices_or_a_deadline_nothing_changes(self):
        self.assertIsNone(PhaseSchedule(1000.0, {}).deadline_for("worklist"))
        self.assertEqual(PhaseSchedule(None, {"worklist": 1}).deadline_for("worklist", 7.0), 7.0)
        self.assertEqual(PhaseSchedule(1000.0, {"chain_rounds": 1}).deadline_for(
            "worklist", 900.0), 900.0)              # unsliced phase keeps its own bound
        self.assertFalse(PhaseSchedule.from_config(_config(), 1000.0).active)


# ------------------------------------------------------------------ orchestrator callers
class CrawlLoopCallerTests(unittest.TestCase):
    """investigate_engagement wires the feed, the re-crawl rounds and the slices."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="crawl_loop_", dir=Path(__file__).parent.parent
                                     / ".test-work")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()

    def tearDown(self):
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _investigate(self, engagement=None, offer_route=True):
        cfg = _config()
        cfg["engagement"].update(engagement or {})
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["shop.test"]
        rc = RunContext.create(allowed_hosts=["shop.test"], max_requests=100, config=cfg)
        seen = {"worklist": [], "recrawled": []}

        async def worklist(probe, st, base, roles, **kwargs):
            seen["worklist"].append((sorted(st.endpoints), kwargs.get("deadline")))
            if offer_route and rc.route_feed is not None and len(seen["worklist"]) == 1:
                # A validator probe meets a route the discovery never saw.
                rc.route_feed.offer_exchange({"method": "GET", "url": f"{BASE}api/late/1",
                                              "response_status": 200}, source="test")
            return []

        async def recrawl_state(base_url, roles, observations, **kw):
            seen["recrawled"].append([o.path for o in observations])
            st = EngagementState(host="shop.test")
            for o in observations:
                st._ep(o.method, o.path)
            return st, []

        async def review(*args, **kwargs):
            seen["review_deadline"] = kwargs.get("deadline")
            return 0

        patches = [patch.object(engagement_builder, "build_engagement", new=_build),
                   patch.object(engagement_builder, "recrawl_state", new=recrawl_state),
                   patch.object(worklist_investigator, "investigate_worklist", new=worklist),
                   patch.object(coverage_tracker, "build_coverage_driven",
                                new=AsyncMock(return_value={})),
                   patch("harness.orchestrator_chain.review_captured_exchanges", new=review),
                   patch("harness.orchestrator_chain.universal_header_audit",
                         new=AsyncMock(return_value=0)),
                   patch("harness.browser_driver.default_driver", return_value=None)]

        async def go():
            try:
                async with rc:
                    return await orch.investigate_engagement(
                        BASE, [RoleSession("anonymous", {})], max_nodes=1, max_chain_rounds=0,
                        discovery_max_probes=1, run_context=rc)
            finally:
                await rc.aclose()

        for p in patches:
            p.start()
        try:
            seen["started"] = time.monotonic()
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        return result, seen

    def test_a_route_seen_during_the_worklist_is_recrawled_and_investigated(self):
        result, seen = self._investigate({"recrawl": {"enabled": True}})
        self.assertEqual(seen["recrawled"], [["/api/late/{id}"]])
        self.assertEqual(len(seen["worklist"]), 2)
        self.assertEqual(seen["worklist"][1][0], ["GET /api/late/{id}"])
        loop = result["crawl_loop"]["recrawl"]
        self.assertEqual((loop["rounds"], loop["routes"]), (1, 1))

    def test_control_recrawl_off_installs_no_feed_and_runs_one_worklist(self):
        result, seen = self._investigate()
        self.assertEqual(seen["recrawled"], [])
        self.assertEqual(len(seen["worklist"]), 1)
        self.assertEqual(result["crawl_loop"]["recrawl"]["rounds"], 0)

    def test_control_no_new_route_no_round(self):
        result, seen = self._investigate({"recrawl": {"enabled": True}}, offer_route=False)
        self.assertEqual(seen["recrawled"], [])
        self.assertEqual(result["crawl_loop"]["recrawl"]["rounds"], 0)

    def test_phase_slices_keep_time_for_review_and_the_chain_rounds(self):
        _, seen = self._investigate({"investigation_seconds": 900, "phase_slices": {
            "worklist": 1, "capture_review": 1, "chain_rounds": 1}})
        worklist_deadline = seen["worklist"][0][1]
        self.assertAlmostEqual(worklist_deadline - seen["started"], 300, delta=30)
        self.assertLess(seen["review_deadline"], seen["started"] + 900 - 300 + 30)
        self.assertGreater(seen["review_deadline"], worklist_deadline)

    def test_control_without_slices_the_worklist_gets_the_whole_bound(self):
        _, seen = self._investigate({"investigation_seconds": 900})
        self.assertAlmostEqual(seen["worklist"][0][1] - seen["started"], 900, delta=30)
        self.assertEqual(seen["review_deadline"], seen["worklist"][0][1])

    def test_an_explicit_review_cap_still_binds_under_slices(self):
        _, seen = self._investigate({"investigation_seconds": 900, "capture_review_seconds": 5,
                                     "phase_slices": {"capture_review": 1, "chain_rounds": 1}})
        self.assertLess(seen["review_deadline"], time.monotonic() + 5)


class DefaultsTests(unittest.TestCase):
    def test_shipped_config_keeps_every_new_behaviour_off(self):
        cfg = _config()
        self.assertFalse(RecrawlConfig.from_config(cfg).enabled)
        self.assertFalse(FreshnessConfig.from_config(cfg).enabled)
        self.assertFalse(cfg["driver_capture"]["spa_navigation"])
        self.assertFalse(cfg["engagement"]["crawl_per_principal"])
        self.assertEqual(cfg["engagement"]["phase_slices"], {})
        for knob in ("engagement.recrawl.enabled", "engagement.crawl_per_principal"):
            self.assertIn(knob, config_schema._PASSIVE_FORCE_OFF_KNOBS)


if __name__ == "__main__":
    unittest.main()
