"""Tests for the site-map crawler (mocked network)."""
import asyncio
import unittest
from unittest.mock import patch

from harness import global_throttle
from harness import crawler
from harness.run_context import RunContext, ScopePolicy
from harness.test_run_context import _Fixture


class _Resp:
    def __init__(self, text):
        self.text = text


def _fake_pages(mapping):
    async def fake_get(self, url, headers=None):
        key = url.split("#", 1)[0]
        return _Resp(mapping.get(key, ""))
    return fake_get


class CrawlerTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)  # off, so tests don't block

    def _crawl(self, pages, **kw):
        with patch("httpx.AsyncClient.get", _fake_pages(pages)):
            return asyncio.run(crawler.crawl("http://t.test/", allowed_hosts=["t.test"], **kw))

    def test_mines_js_bundle_referenced_by_html(self):
        pages = {
            "http://t.test/": '<html><script src="/main.js"></script></html>',
            "http://t.test/main.js": 'fetch("/api/tickets"); axios.get("/api/users/1");',
        }
        r = self._crawl(pages)
        self.assertEqual(r.pages_fetched, 1)
        self.assertEqual(r.scripts_mined, 1)
        self.assertIn("/api/tickets", r.endpoints)
        self.assertIn("/api/users/{id}", r.endpoints)
        self.assertIn("/api/tickets", r.from_request_calls)

    def test_scope_gating_blocks_offsite_base(self):
        r = asyncio.run(crawler.crawl("http://evil.test/", allowed_hosts=["t.test"]))
        self.assertTrue(any("out of scope" in e for e in r.errors))
        self.assertEqual(r.pages_fetched, 0)

    def test_does_not_follow_external_scripts(self):
        pages = {
            "http://t.test/": '<script src="https://cdn.evil/x.js"></script><script src="/app.js"></script>',
            "http://t.test/app.js": '"/api/internal"',
        }
        r = self._crawl(pages)
        # only the same-origin script is mined
        self.assertEqual(r.scripts_mined, 1)
        self.assertIn("/api/internal", r.endpoints)

    def test_max_pages_bound(self):
        pages = {"http://t.test/": '<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>'}
        for p in ("a", "b", "c"):
            pages[f"http://t.test/{p}"] = f'<a href="/{p}/deep">x</a>'
        r = self._crawl(pages, max_pages=2, max_depth=3)
        self.assertLessEqual(r.pages_fetched + r.scripts_mined, 2)

    def test_follows_same_origin_links_to_depth(self):
        pages = {
            "http://t.test/": '<a href="/page2">p2</a>',
            "http://t.test/page2": 'fetch("/api/deep")',
        }
        r = self._crawl(pages, max_depth=1)
        self.assertIn("/api/deep", r.endpoints)

    def test_unsupported_scheme(self):
        r = asyncio.run(crawler.crawl("ftp://t.test/", allowed_hosts=["t.test"]))
        self.assertTrue(any("unsupported scheme" in e for e in r.errors))

    def test_run_context_routes_actual_fetch_with_session_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        ctx.sessions.register("user", "user", {"Authorization": "Bearer crawl"},
                              allowed_origins=[ScopePolicy.origin_of(fixture.base)])
        async def scenario():
            result = await crawler.crawl(
                fixture.base, headers={"Authorization": "Bearer crawl"},
                allowed_hosts=["127.0.0.1"], max_pages=1,
                run_context=ctx, session_ref="user")
            await ctx.aclose()
            return result
        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.pages_fetched, 1)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(fixture.httpd.received[0]["authorization"], "Bearer crawl")
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
