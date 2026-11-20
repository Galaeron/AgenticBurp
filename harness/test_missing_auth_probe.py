"""Tests for the missing-authentication probe (mocked network)."""
import asyncio
import unittest
from unittest.mock import patch

from harness import global_throttle
import harness.missing_auth_probe as map_
from harness.js_endpoint_extractor import CallShape
from harness.safety_gate import SafetyGate, SafetyGateConfig
from harness.run_context import RunContext, standalone_context
from harness.test_run_context import _Fixture


class _Resp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = {}
        self.url = "http://t.test/"
        self.http_version = "HTTP/1.1"


def _with_run(fn, *, gate=None, hosts=("t.test",)):
    """Run `fn(ctx)` against a standalone run context (ARC-7: the probe sends only
    through a run). The tests patch httpx.AsyncClient.request, which that run's
    transport uses, so no socket is opened."""
    async def go():
        ctx = standalone_context(list(hosts), gate=gate, active_mode=True)
        try:
            return await fn(ctx)
        finally:
            await ctx.aclose()
    return asyncio.run(go())


def _has_auth(headers) -> bool:
    return bool(headers) and any(k.lower() == "authorization" for k in headers)


def _fake(mapping):
    """mapping: (METHOD, url) -> {"unauth": (status, body), "garbage": (status, body)}.
    Missing "garbage" defaults to the same as "unauth"."""
    async def fake_request(self, method, url, headers=None, **kw):
        entry = mapping.get((method.upper(), url))
        if entry is None:
            return _Resp(404, "")
        key = "garbage" if _has_auth(headers) else "unauth"
        status, body = entry.get(key, entry["unauth"])
        return _Resp(status, body)
    return fake_request


class MissingAuthProbeTests(unittest.TestCase):
    BASE = "http://t.test"

    def setUp(self):
        global_throttle.configure(0)  # off, so tests don't block

    def _probe(self, mapping, shape, *, gate=None, **kw):
        kw.setdefault("allowed_hosts", ["t.test"])
        with patch("httpx.AsyncClient.request", _fake(mapping)):
            return _with_run(lambda ctx: map_.probe(self.BASE, shape, run_context=ctx, **kw),
                             gate=gate)

    # --- the core positive: data served with no credentials ---
    def test_unauth_2xx_substantive_is_missing_auth(self):
        m = {("GET", "http://t.test/api/report"): {"unauth": (200, '{"salary": 90000}')}}
        o = self._probe(m, CallShape("GET", "/api/report"), expected_protected=True)
        self.assertEqual(o.classification, "missing_auth")
        self.assertIsNotNone(o.finding)
        self.assertEqual(o.finding.vulnerability_class, "missing_authentication")
        self.assertTrue(o.finding.confirmed)
        self.assertEqual(o.finding.severity, "high")

    def test_unauth_2xx_on_undeclared_endpoint_is_only_a_candidate(self):
        # RV-G R15: data served anonymously is not missing authentication unless
        # the endpoint is known to need it; a public catalogue looks the same.
        m = {("GET", "http://t.test/api/report"): {"unauth": (200, '{"salary": 90000}')}}
        o = self._probe(m, CallShape("GET", "/api/report"))
        self.assertEqual(o.classification, "unauthenticated_access")
        self.assertIsNotNone(o.finding)
        self.assertFalse(o.finding.confirmed)
        self.assertIn("not declared protected", o.finding.summary)

    def test_expected_protected_raises_confidence(self):
        m = {("GET", "http://t.test/api/report"): {"unauth": (200, '{"x": 1}')}}
        base = self._probe(m, CallShape("GET", "/api/report"))
        exp = self._probe(m, CallShape("GET", "/api/report"), expected_protected=True)
        self.assertGreater(exp.finding.confidence, base.finding.confidence)

    # --- the true-negative that motivates the whole probe (blind-target-2) ---
    def test_unauth_401_is_protected_no_finding(self):
        m = {("GET", "http://t.test/api/tickets"): {"unauth": (401, "Unauthorized")}}
        o = self._probe(m, CallShape("GET", "/api/tickets"))
        self.assertEqual(o.classification, "protected")
        self.assertIsNone(o.finding)

    def test_302_login_redirect_is_protected(self):
        m = {("GET", "http://t.test/admin"): {"unauth": (302, "")}}
        o = self._probe(m, ("GET", "/admin"))
        self.assertEqual(o.classification, "protected")
        self.assertIsNone(o.finding)

    def test_200_login_page_is_not_a_leak(self):
        html = '<html><form action="/login"><input type="password" name="password"></form></html>'
        m = {("GET", "http://t.test/dashboard"): {"unauth": (200, html)}}
        o = self._probe(m, ("GET", "/dashboard"))
        self.assertNotEqual(o.classification, "missing_auth")
        self.assertIsNone(o.finding)

    def test_authenticated_form_with_login_css_class_is_substantive(self):
        # Some applications reuse a `login-form` CSS class for account forms.
        # A class-name substring alone must not discard an authenticated page.
        html = ('<p>Your email: probe@example.com</p>'
                '<form class="login-form" name="change-email-form" '
                'action="/my-account/change-email"><input name="email"></form>')
        self.assertTrue(map_._substantive(200, html))

    def test_empty_2xx_body_is_not_substantive(self):
        m = {("GET", "http://t.test/api/items"): {"unauth": (200, "[]")}}
        o = self._probe(m, ("GET", "/api/items"), send_garbage_token=False)
        self.assertNotEqual(o.classification, "missing_auth")
        self.assertIsNone(o.finding)

    # --- garbage-token dimension: any token accepted ---
    def test_garbage_token_accepted_flags_broken_auth(self):
        m = {("GET", "http://t.test/api/report"): {
            "unauth": (401, "Unauthorized"),
            "garbage": (200, '{"salary": 90000}'),
        }}
        o = self._probe(m, CallShape("GET", "/api/report"))
        self.assertEqual(o.classification, "any_token_accepted")
        self.assertIsNotNone(o.finding)
        self.assertEqual(o.finding.vulnerability_class, "missing_authentication")
        self.assertLess(o.finding.confidence, 0.75)  # weaker than a raw unauth leak

    def test_garbage_token_also_rejected_is_protected(self):
        m = {("GET", "http://t.test/api/report"): {
            "unauth": (401, "no"), "garbage": (401, "no"),
        }}
        o = self._probe(m, ("GET", "/api/report"))
        self.assertEqual(o.classification, "protected")
        self.assertIsNone(o.finding)

    # --- scope + id fill + methods ---
    def test_out_of_scope_is_skipped(self):
        m = {}
        o = self._probe(m, ("GET", "/x"), allowed_hosts=["other.test"])
        self.assertEqual(o.classification, "skipped")
        self.assertIn("out of scope", o.note)

    def test_id_placeholder_is_filled(self):
        m = {("GET", "http://t.test/api/users/1"): {"unauth": (200, '{"name":"admin"}')}}
        o = self._probe(m, CallShape("GET", "/api/users/{id}"), expected_protected=True)
        self.assertEqual(o.url, "http://t.test/api/users/1")
        self.assertEqual(o.classification, "missing_auth")

    def test_mutating_method_not_probed_by_default(self):
        m = {("DELETE", "http://t.test/api/users/1"): {"unauth": (200, "deleted")}}
        o = self._probe(m, CallShape("DELETE", "/api/users/{id}"))
        self.assertEqual(o.classification, "skipped")
        self.assertIn("mutating", o.note)
        self.assertIsNone(o.finding)

    def test_mutating_method_blocked_by_gate_when_opted_in(self):
        # active testing off -> gate blocks even with include_mutating.
        gate = SafetyGate(SafetyGateConfig(active_enabled=False))
        m = {("POST", "http://t.test/api/x"): {"unauth": (200, "ok data here")}}
        o = self._probe(m, ("POST", "/api/x"), include_mutating=True, gate=gate)
        self.assertEqual(o.classification, "error")     # the run's gate refused the send
        self.assertIn("blocked", o.note)

    def test_mutating_method_probed_when_gate_allows(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True,
                                           allowed_hosts={"t.test"}))
        m = {("POST", "http://t.test/api/x"): {"unauth": (200, '{"created": true, "id": 7}')}}
        o = self._probe(m, ("POST", "/api/x"), include_mutating=True, gate=gate,
                        expected_protected=True)
        self.assertEqual(o.classification, "missing_auth")

    def test_baseline_auth_headers_are_stripped(self):
        seen = {}

        async def spy(self, method, url, headers=None, **kw):
            seen["headers"] = dict(headers or {})
            return _Resp(401, "no")

        with patch("httpx.AsyncClient.request", spy):
            _with_run(lambda ctx: map_.probe(
                self.BASE, ("GET", "/api/x"), allowed_hosts=["t.test"],
                baseline_headers={"Authorization": "Bearer real", "Cookie": "s=1", "Accept": "application/json"},
                send_garbage_token=False, run_context=ctx,
            ))
        keys = {k.lower() for k in seen["headers"]}
        self.assertNotIn("authorization", keys)
        self.assertNotIn("cookie", keys)
        self.assertIn("accept", keys)  # non-auth header preserved

    def test_transport_error_is_error(self):
        async def boom(self, method, url, headers=None, **kw):
            import httpx
            raise httpx.ConnectError("refused")

        with patch("httpx.AsyncClient.request", boom):
            o = _with_run(lambda ctx: map_.probe(
                self.BASE, ("GET", "/x"), allowed_hosts=["t.test"], run_context=ctx))
        self.assertEqual(o.classification, "error")
        self.assertIsNone(o.finding)

    def test_run_context_actual_anonymous_probe_has_no_credentials(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        async def scenario():
            result = await map_.probe(
                fixture.base, ("GET", "/public-data"),
                allowed_hosts=["127.0.0.1"],
                baseline_headers={"Authorization": "Bearer real"},
                send_garbage_token=False, expected_protected=True, run_context=ctx)
            await ctx.aclose()
            return result
        try:
            outcome = asyncio.run(scenario())
            self.assertEqual(outcome.classification, "missing_auth")
            self.assertIsNone(fixture.httpd.received[0]["authorization"])
            self.assertEqual(ctx.budget.used, 1)
        finally:
            fixture.close()

    def test_run_context_blocked_mutation_sends_nothing(self):
        fixture = _Fixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=1,
            gate_config={"active_enabled": True, "allow_mutating_replay": False})
        async def scenario():
            result = await map_.probe(
                fixture.base, ("POST", "/change"),
                allowed_hosts=["127.0.0.1"], include_mutating=True,
                send_garbage_token=False, run_context=ctx)
            await ctx.aclose()
            return result
        try:
            outcome = asyncio.run(scenario())
            self.assertEqual(outcome.classification, "error")
            self.assertEqual(fixture.httpd.received, [])
            self.assertEqual(ctx.budget.used, 0)
        finally:
            fixture.close()

    # --- ARC-7: no raw fallback; a run is required ---
    def test_a_missing_run_context_is_a_type_error(self):
        """Negative control for the signature: forgetting the run cannot silently
        fall back to a private client."""
        with self.assertRaises(TypeError):
            asyncio.run(map_.probe(self.BASE, ("GET", "/x"), allowed_hosts=["t.test"]))

    def test_run_context_none_sends_nothing(self):
        sent = []

        async def spy(self, method, url, headers=None, **kw):
            sent.append(url)
            return _Resp(200, '{"leak": 1}')

        with patch("httpx.AsyncClient.request", spy):
            o = asyncio.run(map_.probe(self.BASE, ("GET", "/api/x"), allowed_hosts=["t.test"],
                                       run_context=None))
        self.assertEqual(o.classification, "error")
        self.assertIn("no run context", o.note)
        self.assertEqual(sent, [])

    # --- a1 open item: an empty scope fails closed (zero sends) ---
    def _empty_scope_probe(self, fixture, allowed_hosts):
        # The run itself admits the loopback host: only the probe's own scope check
        # stands between an empty `allowed_hosts` and a send.
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=5,
                                gate_config={"active_enabled": True})

        async def scenario():
            try:
                return await map_.probe(fixture.base, ("GET", "/public-data"),
                                        allowed_hosts=allowed_hosts, expected_protected=True,
                                        send_garbage_token=False, run_context=ctx)
            finally:
                await ctx.aclose()
        return asyncio.run(scenario()), ctx

    def test_empty_scope_sends_nothing(self):
        fixture = _Fixture()
        try:
            for empty in ([], None):
                o, ctx = self._empty_scope_probe(fixture, empty)
                self.assertEqual(o.classification, "skipped")
                self.assertIn("no scope configured", o.note)
                self.assertEqual(ctx.budget.used, 0)
            self.assertEqual(fixture.httpd.received, [])
        finally:
            fixture.close()

    def test_control_the_old_open_scope_check_sends(self):
        """Negative control: with the pre-fix `_host_allowed` (True on an empty scope)
        the same call reaches the target, so the zero-send test above is not vacuous."""
        fixture = _Fixture()
        try:
            with patch.object(map_, "_host_allowed", lambda url, hosts: True):
                o, ctx = self._empty_scope_probe(fixture, [])
            self.assertEqual(o.classification, "missing_auth")
            self.assertEqual(len(fixture.httpd.received), 1)
            self.assertEqual(ctx.budget.used, 1)
        finally:
            fixture.close()

    def test_a_scoped_host_is_still_probed(self):
        fixture = _Fixture()
        try:
            o, ctx = self._empty_scope_probe(fixture, ["127.0.0.1"])
            self.assertEqual(o.classification, "missing_auth")
            self.assertEqual(len(fixture.httpd.received), 1)
        finally:
            fixture.close()

    # --- batch ---
    def test_batch_dedupes_and_collects_findings(self):
        m = {
            ("GET", "http://t.test/api/a"): {"unauth": (200, '{"leak": 1}')},
            ("GET", "http://t.test/api/b"): {"unauth": (401, "no")},
        }
        shapes = [CallShape("GET", "/api/a"), CallShape("GET", "/api/a"), CallShape("GET", "/api/b")]
        with patch("httpx.AsyncClient.request", _fake(m)):
            outcomes = _with_run(lambda ctx: map_.probe_call_shapes(
                self.BASE, shapes, allowed_hosts=["t.test"], send_garbage_token=False,
                run_context=ctx))
        self.assertEqual(len(outcomes), 2)  # /api/a deduped
        findings = map_.findings_from(outcomes)
        self.assertEqual(len(findings), 1)
        self.assertIn("/api/a", findings[0].summary)


if __name__ == "__main__":
    unittest.main()
