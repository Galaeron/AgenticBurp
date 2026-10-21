"""Tests for the path-traversal and open-redirect confirmation legs. Network is
stubbed with a simulated target; each leg has a negative control (a
non-vulnerable endpoint must come back not_confirmed)."""
import asyncio
import unittest
from urllib.parse import urlsplit, parse_qsl
from unittest.mock import patch

import httpx

from harness.models import Finding, HttpExchange
from harness.categories import canonicalize
from harness.run_context import RunContext
from harness.validators.path_traversal_validator import PathTraversalValidator
from harness.validators.open_redirect_validator import OpenRedirectValidator, _SENTINEL_HOST
from harness.testing_fixtures.sent_probe import CountingResponder


def _f(vc):
    return Finding(vulnerability_class=vc, confidence=0.5, severity="high", summary=vc,
                   evidence="e", suggested_test="t", basis="derived")


class _Resp:
    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}


class _GateActive(unittest.TestCase):
    def setUp(self):
        from harness import safety_gate
        safety_gate.reset_default_gate()
        # Seed scope: the gate fails closed on an empty active scope (3c622c3),
        # so without this the leg's send is refused before it can run.
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                                      "allowed_hosts": ["t.test"]})

    def tearDown(self):
        from harness import safety_gate
        safety_gate.reset_default_gate()


class CategoryTests(unittest.TestCase):
    def test_path_traversal_now_canonicalizes(self):
        # The detection hole this leg closes: these labels used to map to nothing.
        for label in ("path traversal", "Directory Traversal", "LFI", "local file inclusion"):
            self.assertEqual(canonicalize(label), "path_traversal")


def _qval(url, key):
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)).get(key, "")


class PathTraversalTests(_GateActive):
    def _exchange(self):
        return HttpExchange(url="http://t.test/download?file=report.pdf", method="GET",
                            request_headers={}, request_body="", response_status=200, response_body="ok")

    def test_confirms_on_passwd_contents(self):
        async def _req(self, method, url, content=None, headers=None, **kw):
            payload = _qval(url, "file")
            if "etc/passwd" in payload:
                return _Resp("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
            return _Resp("not found", status=404)
        v = PathTraversalValidator(allowed_hosts=["t.test"])
        responder = CountingResponder(_req)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("path traversal"), self._exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_not_confirmed_when_traversal_blocked(self):
        async def _req(self, method, url, content=None, headers=None, **kw):
            return _Resp("Access denied", status=403)  # a hardened endpoint
        v = PathTraversalValidator(allowed_hosts=["t.test"])
        responder = CountingResponder(_req)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("path traversal"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertGreaterEqual(responder.count, 1, responder.why())  # the probe was sent, just blocked

    def test_skips_without_file_param(self):
        ex = HttpExchange(url="http://t.test/api/status?verbose=1", method="GET",
                          request_headers={}, request_body="", response_status=200, response_body="ok")
        v = PathTraversalValidator(allowed_hosts=["t.test"])
        # no file-shaped param, and finding class doesn't apply -> not applicable
        self.assertFalse(v.applies(_f("misconfig"), ex))

    def test_confirms_via_path_segment(self):
        # VulnCorp shape: file served by path segment (/uploads/<id>), no query param.
        ex = HttpExchange(url="http://t.test/uploads/1", method="GET", request_headers={},
                          request_body="", response_status=200, response_body="binary")

        async def _req(self, method, url, content=None, headers=None, **kw):
            # the traversal is injected into the path (spanning segments); a
            # vulnerable server resolves it and serves /etc/passwd
            low = url.lower()
            if "etc/passwd" in low or "etc%2fpasswd" in low:
                return _Resp("root:x:0:0:root:/root:/bin/bash")
            return _Resp("not found", status=404)
        v = PathTraversalValidator(allowed_hosts=["t.test"])
        responder = CountingResponder(_req)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("path traversal"), ex))
        self.assertEqual(r.status, "confirmed")
        self.assertIn("path segment", r.summary)
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_fileish_segment_makes_it_applicable(self):
        ex = HttpExchange(url="http://t.test/uploads/1", method="GET", request_headers={},
                          request_body="", response_status=200, response_body="x")
        # applies even with an unrelated finding class, purely on the file-ish segment
        self.assertTrue(PathTraversalValidator(allowed_hosts=["t.test"]).applies(_f("misconfig"), ex))

    def test_run_context_owns_confirmation_send_and_budget(self):
        sent = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent.append(str(request.url))
            return httpx.Response(
                200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")

        async def run():
            ctx = RunContext.create(allowed_hosts=["t.test"], max_requests=2)
            ctx._default_client = httpx.AsyncClient(
                transport=httpx.MockTransport(handler), follow_redirects=False)
            try:
                result = await PathTraversalValidator(
                    allowed_hosts=["t.test"], run_context=ctx
                ).validate(_f("path traversal"), self._exchange())
                return result, ctx.budget.used
            finally:
                await ctx.aclose()

        result, used = asyncio.run(run())
        self.assertEqual(result.status, "confirmed")
        self.assertEqual(used, 1)
        self.assertEqual(len(sent), 1)
        self.assertIn("etc%2Fpasswd", sent[0])

    def test_run_context_budget_exhaustion_sends_nothing(self):
        sent = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent.append(str(request.url))
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")

        async def run():
            ctx = RunContext.create(allowed_hosts=["t.test"], max_requests=0)
            ctx._default_client = httpx.AsyncClient(
                transport=httpx.MockTransport(handler), follow_redirects=False)
            try:
                return await PathTraversalValidator(
                    allowed_hosts=["t.test"], run_context=ctx
                ).validate(_f("path traversal"), self._exchange())
            finally:
                await ctx.aclose()

        result = asyncio.run(run())
        self.assertEqual(result.status, "skipped")
        self.assertIn("budget_exhausted", result.summary)
        self.assertEqual(sent, [])


class OpenRedirectTests(_GateActive):
    def _exchange(self):
        return HttpExchange(url="http://t.test/login?next=/dashboard", method="GET",
                            request_headers={}, request_body="", response_status=302, response_body="")

    def test_confirms_on_offorigin_location(self):
        async def _req(self, method, url, content=None, headers=None, **kw):
            nxt = _qval(url, "next")
            if _SENTINEL_HOST in nxt:  # vulnerable: reflects the attacker target into Location
                return _Resp(status=302, headers={"location": nxt})
            return _Resp(status=302, headers={"location": "/dashboard"})
        v = OpenRedirectValidator(allowed_hosts=["t.test"])
        responder = CountingResponder(_req)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("open redirect"), self._exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_not_confirmed_when_redirect_stays_onorigin(self):
        async def _req(self, method, url, content=None, headers=None, **kw):
            return _Resp(status=302, headers={"location": "/dashboard"})  # ignores the param
        v = OpenRedirectValidator(allowed_hosts=["t.test"])
        responder = CountingResponder(_req)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("open redirect"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertGreaterEqual(responder.count, 1, responder.why())  # probed; target ignored it

    def test_skips_without_redirect_param(self):
        ex = HttpExchange(url="http://t.test/api/items?q=shoes", method="GET",
                          request_headers={}, request_body="", response_status=200, response_body="[]")
        v = OpenRedirectValidator(allowed_hosts=["t.test"])
        r = asyncio.run(v.validate(_f("open redirect"), ex))
        self.assertEqual(r.status, "skipped")


if __name__ == "__main__":
    unittest.main()
