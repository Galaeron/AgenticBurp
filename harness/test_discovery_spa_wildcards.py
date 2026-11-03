"""Production discovery callers with synthetic HTTP; never contact a target."""
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from harness import crawler, engagement_builder, role_crawl
from harness.api_surface_discovery import SurfaceDiscovery
from harness.models import HttpExchange


class SpaDiscoveryCallerTests(unittest.IsolatedAsyncioTestCase):
    async def test_browser_capture_is_wired_to_run_and_worklist(self):
        from harness.run_context import RunContext
        from harness.browser_driver import CaptureObservation
        ctx = RunContext.create(allowed_hosts=["app.test"], max_requests=4)
        ex = HttpExchange(url="https://app.test/runtime/computed", method="POST",
                          request_body='{"runtime":"value"}', response_status=200)
        try:
            with patch("harness.crawler.crawl", AsyncMock(return_value=crawler.CrawlResult("https://app.test"))), patch(
                    "harness.driver_capture.capture_requests", AsyncMock(return_value=CaptureObservation(
                        url="https://app.test", exchanges=[ex.model_dump()]))) as capture:
                state, result = await engagement_builder.build_engagement(
                    "https://app.test", [role_crawl.RoleSession("anonymous", {})],
                    allowed_hosts=["app.test"], active_discovery=False, run_context=ctx,
                    driver_capture_config={"enabled": True})
            self.assertIs(capture.call_args.kwargs["budget"], ctx.budget)
            self.assertIs(capture.call_args.kwargs["cancel"], ctx.cancel)
            self.assertIs(capture.call_args.kwargs["scope"], ctx.scope)
            self.assertIs(capture.call_args.kwargs["gate"], ctx.gate)
            self.assertEqual(result.captured[0]["request_body"], ex.request_body)
            self.assertTrue(any(e.path == "/runtime/computed" and e.method == "POST"
                                for e in state.endpoints.values()))
        finally:
            await ctx.aclose()

    async def test_browser_disabled_or_missing_context_never_launches(self):
        for config in ({}, {"enabled": True}):
            with patch("harness.crawler.crawl", AsyncMock(return_value=crawler.CrawlResult("https://app.test"))), patch(
                    "harness.driver_capture.capture_requests", AsyncMock()) as capture:
                _, result = await engagement_builder.build_engagement(
                    "https://app.test", [role_crawl.RoleSession("anonymous", {})],
                    allowed_hosts=["app.test"], active_discovery=False, driver_capture_config=config)
            capture.assert_not_awaited()
            if config:
                self.assertTrue(any("RunContext required" in e for e in result.errors))

    async def test_module_generated_api_method_reaches_engagement(self):
        pages = {
            "https://app.test/": '<script type="module" src="/assets/main.js"></script>',
            "https://app.test/robots.txt": "",
            "https://app.test/assets/main.js": 'import("./chunks/api.js"); import("https://outside.test/no.js");',
            "https://app.test/assets/chunks/api.js": 'fetch("/api/profile", {method: "POST"});',
        }
        async def get(url, **kwargs):
            self.assertIn(url, pages)
            return SimpleNamespace(text=pages[url], url=url, status_code=200)
        with patch("httpx.AsyncClient.get", side_effect=get) as fetch, patch(
                "harness.role_crawl._probe", AsyncMock(return_value=(200, '{"ok":true}', {}))) as probe:
            state, result = await engagement_builder.build_engagement(
                "https://app.test/", [role_crawl.RoleSession("anonymous", {})],
                allowed_hosts=["app.test"], active_discovery=False)
        self.assertIn("https://app.test/assets/chunks/api.js", [c.args[0] for c in fetch.call_args_list])
        self.assertIn(("POST", "/api/profile"), [(e.method, e.path) for e in result.endpoints])
        self.assertIn("POST", [c.args[0] for c in probe.call_args_list])
        self.assertTrue(any(e.path == "/api/profile" for e in state.endpoints.values()))

    async def test_script_depth_and_fetch_cap_are_enforced(self):
        async def get(url, **kwargs):
            body = '<script src="/main.js"></script>' if url.endswith("/") else 'import("./next.js")'
            return SimpleNamespace(text=body, url=url, status_code=200)
        with patch("httpx.AsyncClient.get", side_effect=get) as fetch:
            await crawler.crawl("https://app.test/", allowed_hosts=["app.test"], max_pages=3, max_depth=0)
        self.assertEqual(fetch.call_count, 3)
        self.assertNotIn("https://app.test/next.js", [c.args[0] for c in fetch.call_args_list])

    async def test_captured_runtime_api_keeps_shape_and_identity_without_replay(self):
        ex = HttpExchange(url="https://app.test/api/profile?mode=full", method="POST",
                          request_headers={"Authorization": "Bearer synthetic", "Content-Type": "application/json"},
                          request_body='{"displayName":"example"}', response_status=200, response_body='{"ok":true}')
        roles = [role_crawl.RoleSession("anonymous", {}),
                 role_crawl.RoleSession("member", {"Authorization": "Bearer synthetic"})]
        with patch("harness.crawler.crawl", AsyncMock(return_value=crawler.CrawlResult("https://app.test"))), patch(
                "harness.role_crawl._probe", AsyncMock()) as probe:
            state, result = await engagement_builder.build_engagement(
                "https://app.test", roles, allowed_hosts=["app.test"], active_discovery=False,
                seed_exchanges=[ex, ex.model_copy(update={"url": "https://outside.test/api/profile"})])
        probe.assert_not_awaited()
        self.assertEqual(len(result.captured), 1)
        self.assertEqual(result.captured[0]["request_body"], ex.request_body)
        ep = next(e for e in state.endpoints.values() if e.path == "/api/profile")
        self.assertEqual(ep.reachable_roles, ["member"])
        self.assertEqual(ep.method, "POST")
        self.assertTrue(any("outside" in e for e in result.errors))

    async def test_custom_identity_header_does_not_grant_anonymous_access(self):
        ex = HttpExchange(url="https://app.test/api/private", method="GET",
                          request_headers={"X-Tenant-Session": "synthetic"}, response_status=200)
        with patch("harness.crawler.crawl", AsyncMock(return_value=crawler.CrawlResult("https://app.test"))):
            state, _ = await engagement_builder.build_engagement(
                "https://app.test", [role_crawl.RoleSession("anonymous", {}),
                                     role_crawl.RoleSession("member", {"X-Tenant-Session": "synthetic"})],
                allowed_hosts=["app.test"], active_discovery=False, seed_exchanges=[ex])
        self.assertEqual(next(iter(state.endpoints.values())).reachable_roles, ["member"])


class WildcardDiscoveryCallerTests(unittest.IsolatedAsyncioTestCase):
    async def test_ffuf_catchall_hit_is_rejected(self):
        from harness.ffuf_runner import FfufResult
        from harness.api_surface_discovery import Route
        disc = SurfaceDiscovery("https://app.test", allowed_hosts=["app.test"],
                                prefixes=[], nouns=[], collections=[], actions=[], sensitive_files=[],
                                use_ffuf=True, max_probes=50)
        async def probe(method, path):
            return (200, "OK", "") if path.startswith("/health/") else (404, "not found", "")
        with patch.object(disc, "_probe", side_effect=probe), patch(
                "harness.ffuf_runner.ffuf_available", return_value=(True, "ok")), patch(
                "harness.ffuf_runner.ffuf_discover", AsyncMock(return_value=FfufResult(
                    routes=[Route(path="/health/fake", status=200)], returncode=0))):
            result = await disc.discover()
        self.assertNotIn("/health/fake", result.paths())
        self.assertIn("/health/", result.wildcard_prefixes)

    async def test_nested_catchall_is_not_expanded_but_referenced_real_route_survives(self):
        requests = []
        async def probe(method, path):
            requests.append((method, path))
            if path == "/health/details":
                return 200, '{"version":"distinct-service"}', "GET"
            if path.startswith("/health/"):
                return 200, "OK", ""
            return 404, "not found", ""
        disc = SurfaceDiscovery("https://app.test", allowed_hosts=["app.test"],
                                prefixes=["/health/"], nouns=[f"candidate{i}" for i in range(100)],
                                collections=[], actions=[], sensitive_files=[],
                                seed_paths=["/health/details"], use_ffuf=False, max_probes=500)
        with patch.object(disc, "_probe", side_effect=probe):
            result = await disc.discover()
        self.assertEqual([r.path for r in result.routes], ["/health/details"])
        self.assertIn("/health/", result.wildcard_prefixes)
        guesses = [p for _, p in requests if p.startswith("/health/candidate")]
        self.assertLessEqual(len(guesses), 1)
        self.assertLessEqual(result.probes_sent, 500)
        self.assertGreater(result.wildcard_candidates_suppressed, 0)

    async def test_distinct_routes_are_not_removed_by_shared_status(self):
        async def probe(method, path):
            if path in ("/api/users", "/api/orders"):
                return 200, '{"resource":"' + path + '"}', "GET"
            if path.startswith("/api/"):
                return 200, "fallback", ""
            return 404, "not found", ""
        disc = SurfaceDiscovery("https://app.test", allowed_hosts=["app.test"],
                                prefixes=[], nouns=[], collections=[], actions=[], sensitive_files=[],
                                seed_paths=["/api/users", "/api/orders"], use_ffuf=False, max_probes=100)
        with patch.object(disc, "_probe", side_effect=probe):
            result = await disc.discover()
        self.assertTrue({"/api/users", "/api/orders"}.issubset(set(result.paths())))

    async def test_soft404_needs_matching_content_type(self):
        # Same status and body but a different content type is not the catch-all.
        disc = SurfaceDiscovery("https://app.test", prefixes=[], nouns=[], collections=[],
                                actions=[], sensitive_files=[], seed_paths=["/data/export"],
                                use_ffuf=False, max_probes=20)
        async def probe(method, path):
            disc._content_types[path] = "text/csv" if path == "/data/export" else "text/html"
            return 200, "same-body", ""
        with patch.object(disc, "_probe", side_effect=probe):
            result = await disc.discover()
        self.assertIsNotNone(disc._soft404)
        self.assertIn("/data/export", result.paths())

    async def test_calibration_obeys_zero_budget(self):
        disc = SurfaceDiscovery("https://app.test", max_probes=0, use_ffuf=False)
        with patch.object(disc, "_probe", AsyncMock()) as probe:
            result = await disc.discover()
        probe.assert_not_awaited()
        self.assertEqual(result.probes_sent, 0)


class _SpaCatchAll:
    """A real local single-page-app server: /api/items and /admin/real-panel are
    the only routes; every other GET answers HTTP 200 with the index shell, which
    carries a per-request nonce of fixed length (as a CSP nonce would)."""

    def __init__(self):
        import secrets as _secrets
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        fixture = self
        self.requests: list[str] = []

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                fixture.requests.append(self.path)
                path = self.path.split("?", 1)[0]
                if path in ("/api/config", "/api/items", "/admin/real-panel", "/v1/items"):
                    body, ctype = b'{"items":[{"name":"widget"}]}', "application/json"
                else:
                    body = ('<!doctype html><html><head><script nonce="%s"></script></head>'
                            '<body><app-root></app-root></body></html>' % _secrets.token_hex(8)).encode()
                    ctype = "text/html; charset=UTF-8"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class SpaSoft404PruningTests(unittest.IsolatedAsyncioTestCase):
    NOUNS = [f"noun{i}" for i in range(40)] + ["items"]

    def _discovery(self, base, **kwargs):
        return SurfaceDiscovery(base, allowed_hosts=["127.0.0.1"], nouns=self.NOUNS,
                                prefixes=["/api/", "/admin/", "/v1/", "/"],
                                collections=["users", "admin"], actions=[], sensitive_files=[],
                                seed_paths=["/admin/real-panel", "/api/config"], use_ffuf=False,
                                max_probes=3000, **kwargs)

    async def test_spa_catchall_branches_are_pruned_and_real_routes_kept(self):
        server = _SpaCatchAll()
        try:
            pruned = await self._discovery(server.base).discover()
            pruned_requests = len(server.requests)
            pruned_v1 = sum(p.startswith("/v1/") for p in server.requests)
            server.requests.clear()
            # Negative control: the same sweep without pruning.
            unpruned = await self._discovery(server.base, soft404_prune_after=10**6).discover()
            unpruned_requests = len(server.requests)
        finally:
            server.close()
        # A namespace the app references stays live, so its late guesses still run.
        self.assertEqual(pruned.paths(), ["/admin/real-panel", "/api/config", "/api/items"])
        # Trade-off: an unreferenced namespace whose first guesses all hit the
        # catch-all is dropped, so a real route late in its wordlist is missed.
        self.assertEqual(unpruned.paths(), ["/admin/real-panel", "/api/config", "/api/items", "/v1/items"])
        self.assertIn("/v1/", pruned.soft404_pruned_prefixes)
        self.assertNotIn("/api/", pruned.soft404_pruned_prefixes)
        self.assertNotIn("/admin/", pruned.soft404_pruned_prefixes)  # a live route sits there
        self.assertGreater(pruned.soft404_candidates_pruned, 0)
        self.assertEqual(unpruned.soft404_pruned_prefixes, [])
        self.assertLessEqual(pruned_requests, pruned.probes_sent)  # GETs; OPTIONS not recorded
        # The dead /v1/ branch stops at the prune threshold (16 guesses); the
        # unpruned sweep spends ~250 requests there.
        self.assertLessEqual(pruned_v1, 16)
        self.assertGreater(sum(p.startswith("/v1/") for p in server.requests), 200)
        self.assertLess(pruned_requests, unpruned_requests * 0.6)
