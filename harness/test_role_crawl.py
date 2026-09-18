"""Tests for role-aware crawl -> access matrix (mocked network)."""
import asyncio
import unittest
from unittest.mock import patch

from harness import global_throttle
from harness import role_crawl
from harness.role_crawl import RoleSession, _distinct_discovery_roles, _feature_key
from harness.run_context import RunContext, ScopePolicy
from harness.test_run_context import _Fixture


class DiscoverySweepRoleSelectionTests(unittest.TestCase):
    """Discovery must sweep AS each distinct-feature role, so a role-gated
    (agent/manager-only) endpoint is reached -- not just the highest-trust one."""

    def test_dedup_by_feature_not_trust(self):
        # VulnCorp-shaped labels: 3 users (dup feature), one agent, one manager,
        # one admin -- all authenticated. Expect one sweep per FEATURE, users
        # collapsed, agent+manager+admin each kept.
        roles = [
            RoleSession("anonymous", {}),
            RoleSession("alice-user-org1", {"Authorization": "a"}),
            RoleSession("bob-user-org1", {"Authorization": "b"}),
            RoleSession("carol-agent-org1", {"Authorization": "c"}),
            RoleSession("dave-manager-org1", {"Authorization": "d"}),
            RoleSession("admin", {"Authorization": "e"}),
            RoleSession("eve-user-org2", {"Authorization": "f"}),
        ]
        keys = {_feature_key(r.role) for r in _distinct_discovery_roles(roles)}
        self.assertEqual(keys, {"user", "agent", "manager", "admin"})

    def test_anonymous_only_falls_back(self):
        roles = [RoleSession("anonymous", {})]
        picked = _distinct_discovery_roles(roles)
        self.assertEqual([r.role for r in picked], ["anonymous"])

    def test_cap_bounds_fanout(self):
        roles = [RoleSession(f"role{i}-agent", {"Authorization": str(i)}) for i in range(20)]
        # all share feature "agent" -> collapse to one sweep
        self.assertEqual(len(_distinct_discovery_roles(roles)), 1)


class _Resp:
    def __init__(self, status, text):
        self.status_code, self.text = status, text


def _auth_of(headers):
    return (headers or {}).get("Authorization", "")


def _fake_crawl(endpoints):
    async def fake(base_url, headers=None, allowed_hosts=None, max_pages=40, max_depth=2,
                   timeout=15.0, **kwargs):
        from harness.crawler import CrawlResult
        r = CrawlResult(base_url=base_url)
        r.endpoints = set(endpoints)
        return r
    return fake


def _fake_probe(matrix):
    """matrix: (path) -> function(authHeader) -> (status, body)."""
    async def fake_request(self, method, url, headers=None, **kwargs):
        # recover the path key from the url
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        # map concrete id back to {id} for lookup convenience
        key = path
        fn = matrix.get(key)
        if fn is None:
            return _Resp(404, "")
        status, body = fn(_auth_of(headers))
        return _Resp(status, body)
    return fake_request


class RoleCrawlTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    def _run(self, endpoints, matrix, roles, **kw):
        kw.setdefault("allowed_hosts", ["shop.test"])
        with patch("harness.crawler.crawl", _fake_crawl(endpoints)), \
             patch("httpx.AsyncClient.request", _fake_probe(matrix)):
            return asyncio.run(role_crawl.crawl_roles("http://shop.test/", roles, **kw))

    def test_auth_bypass_when_anonymous_reaches(self):
        roles = [RoleSession("anonymous", {}), RoleSession("admin", {"Authorization": "Bearer admintok"})]
        # /api/report returns data to everyone incl. anonymous
        matrix = {"/api/report": lambda auth: (200, '{"secret":1}')}
        r = self._run(["/api/report"], matrix, roles)
        self.assertTrue(any(c["class"] == "missing_authentication" for c in r.auth_bypass_candidates))
        access = r.endpoints[0]
        self.assertIn("anonymous", access.reachable_roles)
        self.assertIn("admin", access.reachable_roles)

    def test_no_bypass_when_anonymous_blocked(self):
        roles = [RoleSession("anonymous", {}), RoleSession("admin", {"Authorization": "Bearer admintok"})]
        matrix = {"/api/report": lambda auth: (200, '{"secret":1}') if auth else (401, "no")}
        r = self._run(["/api/report"], matrix, roles)
        self.assertFalse(any(c["class"] == "missing_authentication" for c in r.auth_bypass_candidates))
        self.assertEqual(r.endpoints[0].reachable_roles, ["admin"])

    def test_idor_candidate_for_object_scoped(self):
        roles = [RoleSession("user", {"Authorization": "Bearer u"}),
                 RoleSession("admin", {"Authorization": "Bearer a"})]
        # /api/orders/{id} -> concrete /api/orders/1, reachable by authed roles
        matrix = {"/api/orders/1": lambda auth: (200, '{"order":1}') if auth else (401, "")}
        r = self._run(["/api/orders/{id}"], matrix, roles)
        self.assertTrue(any(c["class"] == "idor" for c in r.idor_candidates))
        self.assertEqual(r.idor_candidates[0]["path"], "/api/orders/{id}")

    def test_no_idor_for_non_object_scoped(self):
        roles = [RoleSession("user", {"Authorization": "Bearer u"})]
        matrix = {"/api/profile": lambda auth: (200, '{"me":1}')}
        r = self._run(["/api/profile"], matrix, roles)
        self.assertEqual(r.idor_candidates, [])

    def test_authz_inverted_privilege_direction(self):
        # user reaches /admin/panel but admin does not (inverted) -> authz candidate.
        roles = [RoleSession("user", {"Authorization": "Bearer u"}),
                 RoleSession("admin", {"Authorization": "Bearer a"})]
        matrix = {"/admin/panel": lambda auth: (200, "panel") if auth == "Bearer u" else (403, "no")}
        r = self._run(["/admin/panel"], matrix, roles)
        self.assertTrue(any(c["class"] == "authz" for c in r.auth_bypass_candidates))

    def test_access_matrix_records_all_roles(self):
        roles = [RoleSession("anonymous", {}), RoleSession("user", {"Authorization": "Bearer u"})]
        matrix = {"/x": lambda auth: (200, "d") if auth else (401, "")}
        r = self._run(["/x"], matrix, roles)
        by = r.endpoints[0].by_role
        self.assertEqual(by["anonymous"], 401)
        self.assertEqual(by["user"], 200)

    def test_empty_roles_errors(self):
        with patch("harness.crawler.crawl", _fake_crawl([])):
            r = asyncio.run(role_crawl.crawl_roles("http://shop.test/", [], allowed_hosts=["shop.test"]))
        self.assertTrue(any("no roles" in e for e in r.errors))

    def test_run_context_requires_explicit_session_mapping(self):
        ctx = RunContext.create(allowed_hosts=["shop.test"])
        with patch("harness.crawler.crawl", _fake_crawl(["/x"])):
            r = asyncio.run(role_crawl.crawl_roles(
                "http://shop.test/", [RoleSession("user", {})],
                allowed_hosts=["shop.test"], run_context=ctx))
        self.assertEqual(r.endpoints, [])
        self.assertIn("explicit session reference", r.errors[0])

    def test_access_matrix_replay_uses_run_context_real_transport(self):
        fixture = _Fixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=2,
            gate_config={"active_enabled": True})
        origin = ScopePolicy.origin_of(fixture.base)
        ctx.sessions.register("alice", "alice", {"Authorization": "Bearer alice"},
                              allowed_origins=[origin], role="user")
        ctx.sessions.register("bob", "bob", {"Authorization": "Bearer bob"},
                              allowed_origins=[origin], role="user")
        roles = [RoleSession("alice", {"Authorization": "ignored"}),
                 RoleSession("bob", {"Authorization": "ignored"})]

        async def scenario():
            with patch("harness.crawler.crawl", _fake_crawl(["/matrix"])):
                result = await role_crawl.crawl_roles(
                    fixture.base, roles, allowed_hosts=["127.0.0.1"],
                    run_context=ctx, session_refs=["alice", "bob"])
            await ctx.aclose()
            return result

        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.endpoints[0].by_role, {"alice": 200, "bob": 200})
            self.assertEqual([r["authorization"] for r in fixture.httpd.received],
                             ["Bearer alice", "Bearer bob"])
            self.assertEqual(ctx.budget.used, 2)
        finally:
            fixture.close()

    def test_cross_identity_same_object_flags_bola(self):
        # Same object id returns identical data to user AND admin -> BOLA finding.
        roles = [RoleSession("user", {"Authorization": "Bearer u"}),
                 RoleSession("admin", {"Authorization": "Bearer a"})]
        matrix = {"/api/orders/1": lambda auth: (200, '{"order":1,"owner":"alice"}')}
        r = self._run(["/api/orders/{id}"], matrix, roles)
        self.assertTrue(r.idor_findings)
        f = r.idor_findings[0]
        self.assertEqual(f["vulnerability_class"], "idor")
        self.assertFalse(f["confirmed"])
        self.assertIn("cross_identity_compare:/api/orders/{id}", f["validation_hints"])

    def test_cross_identity_different_object_no_finding(self):
        # Each identity gets DIFFERENT data for the same id -> per-identity scoped, no finding.
        roles = [RoleSession("user", {"Authorization": "Bearer u"}),
                 RoleSession("admin", {"Authorization": "Bearer a"})]
        matrix = {"/api/orders/1": lambda auth: (200, '{"owner":"alice"}') if auth == "Bearer u"
                  else (200, '{"owner":"bob"}')}
        r = self._run(["/api/orders/{id}"], matrix, roles)
        self.assertEqual(r.idor_findings, [])

    def test_max_endpoints_bounds_probing(self):
        roles = [RoleSession("user", {"Authorization": "Bearer u"})]
        endpoints = [f"/api/e{i}" for i in range(20)]
        matrix = {f"/api/e{i}": (lambda auth: (200, "d")) for i in range(20)}
        r = self._run(endpoints, matrix, roles, max_endpoints=5)
        self.assertLessEqual(len(r.endpoints), 5)
        self.assertTrue(any("truncated" in e for e in r.errors))

    # --- Phase 0.1: substantive 2xx responses become analyzable captures ------

    def test_captures_substantive_responses(self):
        # Every substantive 2xx is retained as an HttpExchange so content-level
        # review can reach it -- even one correctly scoped to its own identity.
        roles = [RoleSession("user", {"Authorization": "Bearer u"})]
        matrix = {
            "/api/config": lambda auth: (200, '{"aws":"AKIAIOSFODNN7EXAMPLE"}'),  # leaky
            "/api/health": lambda auth: (200, '{"ok":true}'),                     # benign 2xx
            "/api/empty":  lambda auth: (200, ''),                                # not substantive
            "/api/denied": lambda auth: (403, "no"),                              # not 2xx
        }
        r = self._run(list(matrix), matrix, roles)
        urls = {c["url"] for c in r.captured}
        self.assertIn("http://shop.test/api/config", urls)
        self.assertIn("http://shop.test/api/health", urls)
        self.assertNotIn("http://shop.test/api/empty", urls)   # empty body dropped
        self.assertNotIn("http://shop.test/api/denied", urls)  # non-2xx dropped
        cfg = next(c for c in r.captured if c["url"].endswith("/api/config"))
        self.assertIn("AKIA", cfg["response_body"])            # real body carried through
        self.assertEqual(cfg["method"], "GET")
        self.assertEqual(cfg["response_status"], 200)
        # captured exchanges are also exported for the /crawl-roles endpoint.
        self.assertEqual({c["url"] for c in r.to_dict()["captured"]}, urls)

    def test_capture_dedupes_identical_content_across_roles(self):
        # The same body returned to two identities is ONE exchange for content
        # review (the cross-identity lens owns the "same body, two roles" signal).
        roles = [RoleSession("user", {"Authorization": "Bearer u"}),
                 RoleSession("admin", {"Authorization": "Bearer a"})]
        matrix = {"/api/shared": lambda auth: (200, '{"same":"content"}')}
        r = self._run(["/api/shared"], matrix, roles)
        shared = [c for c in r.captured if c["url"].endswith("/api/shared")]
        self.assertEqual(len(shared), 1)

    def test_capture_bound_respected(self):
        roles = [RoleSession("user", {"Authorization": "Bearer u"})]
        endpoints = [f"/api/e{i}" for i in range(10)]
        matrix = {f"/api/e{i}": (lambda auth, i=i: (200, f'{{"n":{i}}}')) for i in range(10)}
        r = self._run(endpoints, matrix, roles, max_captured=3)
        self.assertLessEqual(len(r.captured), 3)


class RoleCrawlEndpointTests(unittest.TestCase):
    def setUp(self):
        import harness.server as server_module
        self.server_module = server_module
        server_module.orchestrator.allowed_hosts = ["shop.test"]
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def test_endpoint_runs(self):
        with patch("harness.crawler.crawl", _fake_crawl(["/api/report"])), \
             patch("httpx.AsyncClient.request", _fake_probe({"/api/report": lambda a: (200, '{"x":1}')})):
            resp = self.client.post("/crawl-roles", json={
                "base_url": "http://shop.test/",
                "roles": [{"role": "anonymous", "headers": {}},
                          {"role": "admin", "headers": {"Authorization": "Bearer a"}}],
                "register_identities": False})  # identity store isolation is covered separately
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["endpoint_count"], 1)
        self.assertTrue(body["auth_bypass_candidates"])

    def test_empty_roles_is_400(self):
        resp = self.client.post("/crawl-roles", json={"base_url": "http://shop.test/", "roles": []})
        self.assertEqual(resp.status_code, 400)

    def test_endpoint_registers_identities(self):
        import tempfile
        from harness import store
        from pathlib import Path
        tmp = tempfile.TemporaryDirectory()
        orig = store._DB_PATH
        store._DB_PATH = Path(tmp.name) / "t.db"
        try:
            with patch("harness.crawler.crawl", _fake_crawl(["/api/orders/{id}"])), \
                 patch("httpx.AsyncClient.request", _fake_probe({"/api/orders/1": lambda a: (200, '{"o":1}')})):
                resp = self.client.post("/crawl-roles", json={
                    "base_url": "http://shop.test/",
                    "roles": [{"role": "user", "headers": {"Authorization": "Bearer u"}},
                              {"role": "admin", "headers": {"Authorization": "Bearer a"}}],
                    "register_identities": True})
            body = resp.json()
            names = {i["name"] for i in body["registered_identities"]}
            self.assertEqual(names, {"rolecrawl:user", "rolecrawl:admin"})
            # persisted + idempotent: a second run registers none new
            with patch("harness.crawler.crawl", _fake_crawl(["/api/orders/{id}"])), \
                 patch("httpx.AsyncClient.request", _fake_probe({"/api/orders/1": lambda a: (200, '{"o":1}')})):
                resp2 = self.client.post("/crawl-roles", json={
                    "base_url": "http://shop.test/",
                    "roles": [{"role": "user", "headers": {"Authorization": "Bearer u"}}],
                    "register_identities": True})
            self.assertEqual(resp2.json()["registered_identities"], [])
        finally:
            store._DB_PATH = orig
            tmp.cleanup()


class ProbeSynthesisHelperTests(unittest.TestCase):
    """Pure helpers behind the method/body/query fix -- no network."""

    def test_resolve_prefers_post_over_put_when_both_declared(self):
        self.assertEqual(role_crawl._resolve_probe_method({"PUT", "POST", "OPTIONS"}), "POST")

    def test_resolve_defaults_to_get_when_get_declared(self):
        self.assertEqual(role_crawl._resolve_probe_method({"GET", "POST"}), "GET")
        self.assertEqual(role_crawl._resolve_probe_methods({"GET", "PUT", "OPTIONS"}),
                         ("GET", "PUT"))

    def test_resolve_defaults_to_get_with_no_method_info(self):
        # No entry in path_methods (passive JS/HTML crawl only) -- must not
        # invent a non-GET method out of nothing.
        self.assertEqual(role_crawl._resolve_probe_method(None), "GET")
        self.assertEqual(role_crawl._resolve_probe_method(set()), "GET")

    def test_resolve_refuses_destructive_or_unknown_method(self):
        self.assertIsNone(role_crawl._resolve_probe_method({"DELETE"}))
        self.assertIsNone(role_crawl._resolve_probe_method({"CONNECT"}))

    def test_synthesize_body_is_empty_for_get(self):
        self.assertEqual(role_crawl._synthesize_body("GET", "/api/anything"), ("", ""))

    def test_synthesize_body_guesses_login_shape(self):
        body, ctype = role_crawl._synthesize_body("POST", "/api/login")
        self.assertIn("password", body)
        self.assertEqual(ctype, "application/json")

    def test_synthesize_body_falls_back_generic(self):
        body, ctype = role_crawl._synthesize_body("POST", "/api/widgets")
        self.assertEqual(body, role_crawl._GENERIC_JSON_BODY)
        self.assertEqual(ctype, "application/json")

    def test_synthesize_query_only_for_search_like_paths(self):
        self.assertEqual(role_crawl._synthesize_query("/api/tickets/search"), "q=test")
        self.assertEqual(role_crawl._synthesize_query("/api/tickets"), "")
        self.assertEqual(role_crawl._synthesize_query("/api/tickets/search?q=1"), "")


class ActiveDiscoveryMethodPropagationTests(unittest.TestCase):
    """role_crawl.py bug: active discovery correctly learns a route's real
    accepted methods (an Allow-header introspection), but crawl_roles threw
    that away and always probed GET -- a POST/PUT-only endpoint (login,
    register, mass-assignment writes) got a uniform wrong-method error across
    every role and was misread as unreachable, masking whatever real
    vulnerability the correct method+body would have reached."""

    def setUp(self):
        global_throttle.configure(0)

    def test_declared_post_only_route_needs_gated_run_context(self):
        from harness.api_surface_discovery import Route, SurfaceResult

        async def fake_discover(self):
            return SurfaceResult(
                base_url=self.base_url,
                routes=[Route(path="/api/register", status=405, methods=("POST", "OPTIONS"))])

        sent = []

        async def fake_request(self, method, url, headers=None, content=None):
            sent.append((method, url, content))
            if method == "GET":
                return _Resp(405, '{"error": "method not allowed"}')
            return _Resp(201, '{"ok": true}')

        roles = [RoleSession("user", {"Authorization": "Bearer u"})]
        with patch("harness.crawler.crawl", _fake_crawl([])), \
             patch("harness.api_surface_discovery.SurfaceDiscovery.discover", fake_discover), \
             patch("httpx.AsyncClient.request", fake_request):
            r = asyncio.run(role_crawl.crawl_roles(
                "http://shop.test/", roles, allowed_hosts=["shop.test"], active_discovery=True))

        ep = next(e for e in r.endpoints if e.path == "/api/register")
        # NEGATIVE CONTROL baked into the assertion itself: before the fix this
        # was unconditionally "GET" and by_role["user"] was 405 for everyone.
        self.assertEqual(ep.method, "POST")
        self.assertIsNone(ep.by_role["user"])
        posts = [s for s in sent if s[0] == "POST" and s[1].endswith("/api/register")]
        self.assertEqual(posts, [], "direct HTTP path must not send inferred writes")
        gets = [s for s in sent if s[0] == "GET" and s[1].endswith("/api/register")]
        self.assertEqual(gets, [], "must not also probe the known-wrong GET method")

    def test_declared_get_only_route_still_uses_get(self):
        from harness.api_surface_discovery import Route, SurfaceResult

        async def fake_discover(self):
            return SurfaceResult(
                base_url=self.base_url,
                routes=[Route(path="/api/health", status=200, methods=("GET",))])

        roles = [RoleSession("user", {"Authorization": "Bearer u"})]
        matrix = {"/api/health": lambda auth: (200, '{"ok":true}')}
        with patch("harness.crawler.crawl", _fake_crawl([])), \
             patch("harness.api_surface_discovery.SurfaceDiscovery.discover", fake_discover), \
             patch("httpx.AsyncClient.request", _fake_probe(matrix)):
            r = asyncio.run(role_crawl.crawl_roles(
                "http://shop.test/", roles, allowed_hosts=["shop.test"], active_discovery=True))

        ep = next(e for e in r.endpoints if e.path == "/api/health")
        self.assertEqual(ep.method, "GET")
        self.assertEqual(ep.by_role["user"], 200)

    def test_live_transport_carries_post_template_and_gate_negative_control(self):
        from harness.api_surface_discovery import Route, SurfaceResult

        async def fake_discover(self):
            return SurfaceResult(base_url=self.base_url,
                                 routes=[Route(path="/api/register", status=405,
                                               methods=("POST", "OPTIONS"))])

        fixture = _Fixture()
        role = RoleSession("user", {"Authorization": "Bearer registered"})
        origin = ScopePolicy.origin_of(fixture.base)

        async def scenario(allow_mutation):
            ctx = RunContext.create(
                allowed_hosts=["127.0.0.1"], max_requests=2,
                gate_config={"active_enabled": True,
                             "allow_mutating_replay": allow_mutation})
            ctx.sessions.register("user", "user", role.norm_headers(),
                                  allowed_origins=[origin])
            try:
                with patch("harness.crawler.crawl", _fake_crawl([])), \
                     patch("harness.api_surface_discovery.SurfaceDiscovery.discover",
                           fake_discover):
                    return await role_crawl.crawl_roles(
                        fixture.base, [role], allowed_hosts=["127.0.0.1"],
                        active_discovery=True, run_context=ctx,
                        session_refs=["user"])
            finally:
                await ctx.aclose()

        try:
            positive = asyncio.run(scenario(True))
            self.assertEqual(positive.endpoints[0].method, "POST")
            self.assertEqual(positive.endpoints[0].by_role["user"], 200)
            self.assertEqual(len(fixture.httpd.received), 1)
            sent = fixture.httpd.received[0]
            self.assertEqual(sent["method"], "POST")
            self.assertIn("username", sent["body"])
            self.assertEqual(sent["authorization"], "Bearer registered")
            self.assertEqual(positive.captured[0]["request_body"], sent["body"])

            fixture.httpd.received.clear()
            blocked = asyncio.run(scenario(False))
            self.assertIsNone(blocked.endpoints[0].by_role["user"])
            self.assertEqual(fixture.httpd.received, [])
            self.assertEqual(blocked.captured, [])
        finally:
            fixture.close()

    def test_live_transport_preserves_get_and_put_operations(self):
        from harness.api_surface_discovery import Route, SurfaceResult

        async def fake_discover(self):
            return SurfaceResult(base_url=self.base_url,
                                 routes=[Route(path="/api/account/profile", status=200,
                                               methods=("GET", "PUT", "OPTIONS"))])

        fixture = _Fixture()
        role = RoleSession("user", {"Authorization": "Bearer profile"})
        origin = ScopePolicy.origin_of(fixture.base)

        async def scenario(allow_mutation):
            ctx = RunContext.create(
                allowed_hosts=["127.0.0.1"], max_requests=3,
                gate_config={"active_enabled": True,
                             "allow_mutating_replay": allow_mutation})
            ctx.sessions.register("user", "user", role.norm_headers(),
                                  allowed_origins=[origin])
            try:
                with patch("harness.crawler.crawl", _fake_crawl([])), \
                     patch("harness.api_surface_discovery.SurfaceDiscovery.discover",
                           fake_discover):
                    return await role_crawl.crawl_roles(
                        fixture.base, [role], allowed_hosts=["127.0.0.1"],
                        active_discovery=True, run_context=ctx,
                        session_refs=["user"])
            finally:
                await ctx.aclose()

        try:
            positive = asyncio.run(scenario(True))
            self.assertEqual({e.method for e in positive.endpoints}, {"GET", "PUT"})
            self.assertEqual([r["method"] for r in fixture.httpd.received],
                             ["GET", "PUT"])
            put = next(c for c in positive.captured if c["method"] == "PUT")
            self.assertIn("name", put["request_body"])

            fixture.httpd.received.clear()
            blocked = asyncio.run(scenario(False))
            self.assertEqual([r["method"] for r in fixture.httpd.received], ["GET"])
            self.assertIsNone(next(e for e in blocked.endpoints
                                   if e.method == "PUT").by_role["user"])
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
