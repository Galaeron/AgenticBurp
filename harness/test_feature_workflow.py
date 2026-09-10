"""Tests for feature_workflow: driving an app's real workflows as an
authenticated role and capturing the credential-bearing, workflow-shaped
exchanges route-guessing can't reach."""
import asyncio
import unittest
from run_context import RunContext, ScopePolicy
from test_run_context import _Fixture

import feature_workflow as fw


class _Resp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {"content-type": "text/html"}


class _FakeApp:
    """An in-memory app double: routes keyed by (METHOD, path) -> _Resp (or a
    callable(headers, body) -> _Resp). Records every call so a test can assert
    what the crawler actually drove."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    async def fetch(self, method, url, headers, body):
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        self.calls.append((method, path, dict(headers or {}), body))
        r = self.routes.get((method, path))
        if r is None:
            return _Resp(404, "not found", {"content-type": "text/plain"})
        return r(headers, body) if callable(r) else r


# --- pure extraction ---------------------------------------------------------

class ExtractionTests(unittest.TestCase):
    def test_extract_forms_fields_and_types(self):
        html = """<html><body>
          <form method="post" action="/api/tickets">
            <input type="hidden" name="csrf" value="tok123">
            <input type="text" name="subject">
            <textarea name="body"></textarea>
            <input type="email" name="cc">
          </form></body></html>"""
        forms = fw.extract_forms(html, "http://t.test/new")
        self.assertEqual(len(forms), 1)
        f = forms[0]
        self.assertEqual(f.method, "POST")
        self.assertEqual(f.action, "http://t.test/api/tickets")
        names = {fld.name for fld in f.fields}
        self.assertEqual(names, {"csrf", "subject", "body", "cc"})
        body = f.body()
        # hidden token preserved, benign defaults for the rest
        self.assertIn("csrf=tok123", body)
        self.assertIn("cc=probe%40example.com", body)

    def test_extract_links_skips_non_navigable(self):
        html = ('<a href="/dashboard">d</a><a href="#top">t</a>'
                '<a href="javascript:void(0)">j</a><a href="/tickets/1">one</a>')
        links = fw.extract_links(html, "http://t.test/")
        self.assertIn("http://t.test/dashboard", links)
        self.assertIn("http://t.test/tickets/1", links)
        self.assertEqual(len(links), 2)

    def test_extract_json_links_hateoas(self):
        body = '{"items":[{"id":1,"href":"/api/tickets/1"}],"_links":{"next":{"url":"/api/tickets?page=2"}}}'
        links = fw.extract_json_links(body, "http://t.test/api/tickets")
        self.assertIn("http://t.test/api/tickets/1", links)
        self.assertIn("http://t.test/api/tickets?page=2", links)


# --- the workflow driver -----------------------------------------------------

class CrawlTests(unittest.TestCase):
    def _ticket_app(self):
        index = _Resp(200, """<html><body>
            <a href="/new">new ticket</a>
            <a href="http://evil.test/out">off-site</a>
          </body></html>""")
        new = _Resp(200, """<html><body>
            <form method="post" action="/api/tickets">
              <input type="hidden" name="csrf" value="tok">
              <input type="text" name="subject">
              <textarea name="body"></textarea>
            </form></body></html>""")

        def create(headers, body):
            # the workflow-driving submit: redirects to the created object
            return _Resp(302, "", {"location": "/tickets/1", "content-type": "text/html"})

        ticket = _Resp(200, "<html><body>ticket #1 created</body></html>")
        return _FakeApp({
            ("GET", "/"): index,
            ("GET", "/new"): new,
            ("POST", "/api/tickets"): create,
            ("GET", "/tickets/1"): ticket,
        })

    def test_drives_create_ticket_workflow(self):
        app = self._ticket_app()
        sess = {"Cookie": "session=alice-token"}
        res = asyncio.run(fw.crawl_features(
            "http://t.test", "user", sess, fetch_fn=app.fetch,
            allowed_hosts=["t.test"], max_steps=20, max_depth=3))
        methods_paths = {(m, p) for m, p, _, _ in app.calls}
        # it reached /new via the link, POSTed the create, and followed to /tickets/1
        self.assertIn(("GET", "/new"), methods_paths)
        self.assertIn(("POST", "/api/tickets"), methods_paths)
        self.assertIn(("GET", "/tickets/1"), methods_paths)
        self.assertEqual(res.forms_submitted, 1)

    def test_captured_exchanges_carry_session(self):
        """Every captured exchange must carry the role's session headers -- the
        whole point: the create-ticket POST body + the authenticated cookie are
        what the confirmation legs consume."""
        app = self._ticket_app()
        sess = {"Cookie": "session=alice-token"}
        res = asyncio.run(fw.crawl_features(
            "http://t.test", "user", sess, fetch_fn=app.fetch, allowed_hosts=["t.test"]))
        post = [e for e in res.captured if e.method == "POST"]
        self.assertTrue(post, "no workflow submit captured")
        self.assertEqual(post[0].request_headers.get("Cookie"), "session=alice-token")
        self.assertIn("subject=", post[0].request_body)

    def test_stays_in_scope(self):
        app = self._ticket_app()
        res = asyncio.run(fw.crawl_features(
            "http://t.test", "user", {}, fetch_fn=app.fetch, allowed_hosts=["t.test"]))
        hosts = {p for m, p, _, _ in app.calls}
        self.assertNotIn("/out", hosts)  # off-site link never followed

    def test_submit_forms_false_is_read_only(self):
        """Negative control: with submit_forms disabled, no mutating request is
        ever sent -- a safe passive walk."""
        app = self._ticket_app()
        res = asyncio.run(fw.crawl_features(
            "http://t.test", "user", {}, fetch_fn=app.fetch, allowed_hosts=["t.test"],
            submit_forms=False))
        methods = {m for m, _, _, _ in app.calls}
        self.assertEqual(methods, {"GET"})
        self.assertEqual(res.forms_submitted, 0)

    def test_bounded_by_max_steps(self):
        # an app that always returns a fresh link would loop forever without a cap
        def infinite(headers, body):
            import random
            return _Resp(200, '<a href="/p/%d">next</a>' % random.randint(0, 1_000_000))
        app = _FakeApp({("GET", "/"): infinite})
        # every /p/N also resolves to a fresh page
        orig_fetch = app.fetch

        async def fetch(method, url, headers, body):
            from urllib.parse import urlsplit
            if urlsplit(url).path.startswith("/p/"):
                import random
                app.calls.append((method, urlsplit(url).path, headers, body))
                return _Resp(200, '<a href="/p/%d">n</a>' % random.randint(0, 1_000_000))
            return await orig_fetch(method, url, headers, body)

        res = asyncio.run(fw.crawl_features(
            "http://t.test", "user", {}, fetch_fn=fetch, allowed_hosts=["t.test"],
            max_steps=7, max_depth=50))
        self.assertLessEqual(res.steps, 7)


class BuilderIntegrationTests(unittest.TestCase):
    """engagement_builder.feature_crawl_captures runs the crawl as each distinct
    role and unions/dedups the exchanges."""

    def test_unions_and_dedups_across_roles(self):
        import engagement_builder
        from role_crawl import RoleSession

        # a shared public index (same body to all roles) + a per-role page
        async def app_fetch(method, url, headers, body):
            from urllib.parse import urlsplit
            path = urlsplit(url).path
            if path == "/":
                return _Resp(200, '<a href="/me">me</a>')
            if path == "/me":
                who = (headers or {}).get("X-Role", "anon")
                return _Resp(200, f"<html>profile {who}</html>")
            return _Resp(404, "nf")

        roles = [
            RoleSession(role="user", headers={"X-Role": "user"}),
            RoleSession(role="admin", headers={"X-Role": "admin"}),
        ]
        from urllib.parse import urlsplit
        caps = asyncio.run(engagement_builder.feature_crawl_captures(
            "http://t.test", roles, fetch_fn=app_fetch, allowed_hosts=["t.test"],
            submit_forms=False))
        paths = [urlsplit(e.url).path for e in caps]
        # "/" fetched as both roles has identical body -> collapses to one capture;
        # "/me" differs per role -> two captures. So 3 total, not 4.
        self.assertEqual(paths.count("/"), 1)
        self.assertEqual(paths.count("/me"), 2)


class CrossSeedTests(unittest.TestCase):
    """feature_crawl_captures with seed_paths starts from discovered routes,
    not just /."""

    def test_seed_paths_reach_deeper_surface(self):
        import engagement_builder
        from role_crawl import RoleSession

        async def app_fetch(method, url, headers, body):
            from urllib.parse import urlsplit
            path = urlsplit(url).path
            if path == "/":
                return _Resp(200, "<html>index</html>")
            if path == "/web/admin":
                return _Resp(200, '<html><a href="/web/admin/tools">tools</a></html>')
            if path == "/web/admin/tools":
                return _Resp(200, "<html>admin tools</html>")
            return _Resp(404, "nf")

        roles = [RoleSession(role="admin", headers={"X-Role": "admin"})]
        caps = asyncio.run(engagement_builder.feature_crawl_captures(
            "http://t.test", roles, fetch_fn=app_fetch, allowed_hosts=["t.test"],
            submit_forms=False, seed_paths=["/", "/web/admin"]))
        from urllib.parse import urlsplit
        paths = [urlsplit(e.url).path for e in caps]
        self.assertIn("/web/admin", paths)
        self.assertIn("/web/admin/tools", paths)


class RunContextFeatureTransportTests(unittest.TestCase):
    def test_actual_feature_fetch_uses_session_and_budget(self):
        import feature_workflow
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        ctx.sessions.register("user", "user", {"Authorization": "Bearer feature"},
                              allowed_origins=[ScopePolicy.origin_of(fixture.base)])
        fetch = feature_workflow.run_context_fetch_fn(ctx, "user")
        async def scenario():
            result = await feature_workflow.crawl_features(
                fixture.base, "user", {"Authorization": "Bearer feature"},
                fetch_fn=fetch, allowed_hosts=["127.0.0.1"], max_steps=1)
            await ctx.aclose()
            return result
        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.steps, 1)
            self.assertEqual(len(result.captured), 1)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(fixture.httpd.received[0]["authorization"], "Bearer feature")
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
