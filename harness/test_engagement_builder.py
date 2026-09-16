"""Tests for the graph-driven engagement builder (Milestone A): active API
discovery -> per-role access matrix -> fused EngagementState worklist. Network
and discovery are stubbed; the ordering + fusion are what's under test."""
import asyncio
import unittest
from unittest.mock import patch

from harness import global_throttle
from harness import role_crawl
from harness import engagement_builder
from harness.role_crawl import RoleSession, _template_ids


class _Resp:
    def __init__(self, status, text):
        self.status_code, self.text = status, text


def _fake_crawl_empty():
    async def fake(base_url, headers=None, allowed_hosts=None, max_pages=40, max_depth=2, timeout=15.0):
        from harness.crawler import CrawlResult
        return CrawlResult(base_url=base_url)  # JS crawler finds nothing on an API
    return fake


def _fake_discovery(paths):
    class _FakeDisc:
        def __init__(self, base_url, headers=None, allowed_hosts=None, max_probes=6000, **kw):
            self.base_url = base_url
        async def discover(self):
            from harness.api_surface_discovery import SurfaceResult, Route
            return SurfaceResult(base_url=self.base_url,
                                 routes=[Route(path=p) for p in paths], probes_sent=len(paths))
    return _FakeDisc


def _fake_probe(matrix):
    async def fake_request(self, method, url, headers=None):
        from urllib.parse import urlsplit
        fn = matrix.get(urlsplit(url).path)
        if fn is None:
            return _Resp(404, "")
        return _Resp(*fn((headers or {}).get("Authorization", "")))
    return fake_request


ROLES = [RoleSession(role="anonymous", headers={}),
         RoleSession(role="user", headers={"Authorization": "Bearer u"}),
         RoleSession(role="admin", headers={"Authorization": "Bearer a"})]


class TemplateIdTests(unittest.TestCase):
    def test_numeric_segments_templated(self):
        self.assertEqual(_template_ids("/api/tickets/1"), "/api/tickets/{id}")
        self.assertEqual(_template_ids("/api/tickets/12/comments"), "/api/tickets/{id}/comments")
        self.assertEqual(_template_ids("/api/v1/users/me"), "/api/v1/users/me")  # non-numeric untouched


class ActiveDiscoveryInjectionTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    def test_discovery_augments_surface(self):
        matrix = {"/api/tickets/1": lambda a: (200, '{"id":1}') if a else (401, ""),
                  "/api/admin/users": lambda a: (200, "[]") if a else (401, "")}
        with patch("harness.crawler.crawl", _fake_crawl_empty()), \
             patch("harness.api_surface_discovery.SurfaceDiscovery", _fake_discovery(["/api/tickets/1", "/api/admin/users"])), \
             patch("httpx.AsyncClient.request", _fake_probe(matrix)):
            res = asyncio.run(role_crawl.crawl_roles(
                "http://shop.test/", ROLES, allowed_hosts=["shop.test"], active_discovery=True))
        probed = {e.path for e in res.endpoints}
        self.assertIn("/api/tickets/{id}", probed)   # concrete id templated
        self.assertIn("/api/admin/users", probed)
        self.assertTrue(any(e.path == "/api/tickets/{id}" and e.object_scoped for e in res.endpoints))

    def test_discovery_off_by_default_keeps_js_only(self):
        with patch("harness.crawler.crawl", _fake_crawl_empty()), \
             patch("harness.api_surface_discovery.SurfaceDiscovery", _fake_discovery(["/api/should_not_appear"])), \
             patch("httpx.AsyncClient.request", _fake_probe({})):
            res = asyncio.run(role_crawl.crawl_roles("http://shop.test/", ROLES, allowed_hosts=["shop.test"]))
        self.assertEqual(res.endpoints, [])  # nothing discovered, discovery not run


class BuildEngagementTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    def test_builds_prioritised_worklist_over_discovered_surface(self):
        # /api/admin/users: a low-trust 'user' reaches an admin-looking endpoint (BFLA).
        # /api/tickets/{id}: same object identical to user+admin (IDOR/BOLA candidate).
        matrix = {
            "/api/admin/users": lambda a: (200, '[{"u":1}]') if a in ("Bearer u", "Bearer a") else (401, ""),
            "/api/tickets/1": lambda a: (200, '{"id":1}') if a in ("Bearer u", "Bearer a") else (401, ""),
        }
        with patch("harness.crawler.crawl", _fake_crawl_empty()), \
             patch("harness.api_surface_discovery.SurfaceDiscovery", _fake_discovery(["/api/admin/users", "/api/tickets/1"])), \
             patch("httpx.AsyncClient.request", _fake_probe(matrix)):
            state, result = asyncio.run(engagement_builder.build_engagement(
                "http://shop.test/", ROLES, allowed_hosts=["shop.test"]))

        wl = state.worklist(50)
        paths = {w["path"] for w in wl}
        self.assertIn("/api/admin/users", paths)
        self.assertIn("/api/tickets/{id}", paths)
        # the harness owns the ranking: every worklist row carries a score + reasons
        self.assertTrue(all("score" in w and "reasons" in w for w in wl))
        # the object-scoped endpoint produced a deterministic IDOR finding
        self.assertTrue(any(f.get("vulnerability_class") == "idor" for f in result.idor_findings))
        # identities were registered into the graph
        self.assertTrue(any(i["role"] == "admin" for i in state.identities))


if __name__ == "__main__":
    unittest.main()
