"""Tests for the site-map crawler (mocked network)."""
import asyncio
import unittest
from unittest.mock import patch

from harness import global_throttle
from harness import crawler
from harness.run_context import RunContext, ScopePolicy
from harness.test_run_context import _Fixture


class _Resp:
    def __init__(self, text, url=None):
        self.text = text
        self.url = url


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

    def test_empty_scope_fails_closed(self):
        # Active crawling must refuse to fetch ANYTHING when no scope is
        # configured -- an empty allow-list previously fetched any host (a real
        # safety bug). Guard both the predicate and the end-to-end crawl, and
        # ensure no network call is even attempted.
        self.assertFalse(crawler._host_allowed("http://anything.test/", []))
        self.assertFalse(crawler._host_allowed("http://anything.test/", None))

        async def _boom(self, url, headers=None):
            raise AssertionError(f"empty-scope crawl attempted a network fetch: {url}")

        with patch("httpx.AsyncClient.get", _boom):
            for scope in ([], None):
                r = asyncio.run(crawler.crawl("http://t.test/", allowed_hosts=scope))
                self.assertEqual(r.pages_fetched, 0)
                self.assertTrue(any("no server.allowed_hosts configured" in e for e in r.errors))

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

    def test_robots_disallow_path_is_crawled_as_application_surface(self):
        pages = {
            "http://t.test/": "<html>home</html>",
            "http://t.test/robots.txt": "User-agent: *\nDisallow: /administrator-panel\n",
            "http://t.test/administrator-panel": '<a href="/administrator-panel/delete?username=alice">delete</a>',
        }
        r = self._crawl(pages, max_pages=3, max_depth=1)
        self.assertIn("/administrator-panel", r.endpoints)
        self.assertNotIn("/administrator-panel/delete?username=alice", r.endpoints)
        self.assertIn("/administrator-panel/delete?username=alice", r.suppressed_navigation)

    def test_destructive_get_link_is_recorded_but_never_fetched(self):
        pages = {
            "http://t.test/": '<a href="/admin/delete?username=alice">delete</a>',
            "http://t.test/admin/delete?username=alice": 'fetch("/proof/delete-link-was-fetched")',
        }
        r = self._crawl(pages, max_pages=3, max_depth=2)
        self.assertIn("/admin/delete?username=alice", r.suppressed_navigation)
        self.assertNotIn("/admin/delete?username=alice", r.endpoints)
        self.assertNotIn("/proof/delete-link-was-fetched", r.endpoints)
        self.assertEqual(r.pages_fetched, 1)

    def test_robots_ignores_external_and_wildcard_directives(self):
        pages = {
            "http://t.test/": "<html>home</html>",
            "http://t.test/robots.txt": (
                "Disallow: https://evil.test/admin\n"
                "Disallow: /*.bak$\n"
                "Disallow: /\n"
            ),
        }
        r = self._crawl(pages, max_pages=2, max_depth=1)
        self.assertNotIn("https://evil.test/admin", r.endpoints)
        self.assertFalse(any("*" in endpoint for endpoint in r.endpoints))

    def test_records_server_rendered_anchor_surface_and_preserves_query_when_following(self):
        pages = {
            "http://t.test/": '<a href="/filter?category=Pets">pets</a>',
            "http://t.test/filter?category=Pets": '"/api/from-filter"',
        }
        r = self._crawl(pages, max_depth=1)
        self.assertIn("/filter?category=Pets", r.endpoints)
        self.assertIn("/api/from-filter", r.endpoints)

    def test_records_dynamic_image_handler_with_filename_query(self):
        pages = {
            "http://t.test/": (
                '<img src="/image?filename=25.jpg">'
                '<img src="/resources/logo.png?rev=1">'
            ),
        }
        r = self._crawl(pages, max_pages=1)
        self.assertIn("/image?filename=25.jpg", r.endpoints)
        self.assertNotIn("/resources/logo.png?rev=1", r.endpoints)

    def test_records_form_shape_without_submitting_it(self):
        pages = {
            "http://t.test/": (
                '<form method="POST" action="/product/stock">'
                '<input type="hidden" name="productId" value="1">'
                '<select name="storeId"><option value="1">one</option></select>'
                '</form>'
            ),
        }
        with patch("httpx.AsyncClient.request") as send:
            r = self._crawl(pages, max_pages=1)
        self.assertEqual(len(r.forms), 1)
        self.assertEqual(r.forms[0].method, "POST")
        self.assertEqual(r.forms[0].action, "http://t.test/product/stock")
        self.assertEqual(r.forms[0].body(), "productId=1&storeId=1")
        send.assert_not_called()  # passive discovery did not submit the form

    def test_destructive_form_action_is_recorded_but_not_captured(self):
        # A form whose action deletes state must never become a replay template:
        # a probing run must not attempt POST /admin/delete. A benign form on the
        # same page is still captured, proving the guard is action-specific.
        pages = {
            "http://t.test/": (
                '<form method="POST" action="/admin/delete-user">'
                '<input type="hidden" name="username" value="carlos"></form>'
                '<form method="POST" action="/product/stock">'
                '<input name="productId" value="1"></form>'
            ),
        }
        r = self._crawl(pages, max_pages=1)
        actions = {f.action for f in r.forms}
        self.assertIn("http://t.test/product/stock", actions)
        self.assertNotIn("http://t.test/admin/delete-user", actions)
        self.assertIn("http://t.test/admin/delete-user", r.suppressed_navigation)

    def test_preserves_final_redirect_query_as_input_surface(self):
        async def redirected(self, url, headers=None):
            return _Resp("<html>out of stock</html>",
                         "http://t.test/?message=Unfortunately+out+of+stock")
        with patch("httpx.AsyncClient.get", redirected):
            r = asyncio.run(crawler.crawl(
                "http://t.test/product?productId=1", allowed_hosts=["t.test"], max_pages=1))
        self.assertIn("/?message=Unfortunately+out+of+stock", r.endpoints)

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
