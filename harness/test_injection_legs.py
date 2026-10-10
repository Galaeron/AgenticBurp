"""Tests for the parameter-injection confirmation legs: command injection (OOB
collaborator) and SSTI (in-band arithmetic differential). Network is stubbed; each
leg has a negative control (a non-vulnerable endpoint must come back
not_confirmed), per the project's green-tests-dead-pipeline discipline."""
import asyncio
import json
import unittest
from unittest.mock import patch

from harness.models import Finding, HttpExchange
from harness.validators.command_injection_validator import CommandInjectionValidator
from harness.validators.ssti_validator import SstiValidator, _PRODUCT, _EXPR
from harness.validators.injection_targets import param_targets
from harness.run_context import RunContext
from harness.testing_fixtures.sent_probe import CountingResponder, seed_gate_scope


def _f(vc):
    return Finding(vulnerability_class=vc, confidence=0.5, severity="high", summary=vc,
                   evidence="e", suggested_test="t", basis="derived")


class _FakeCollab:
    def __init__(self, hit): self._hit = hit; self._n = 0
    def token(self): self._n += 1; return f"oob{self._n}"
    def url(self, t): return f"http://collab.test/{t}"
    async def wait_for_hit(self, t, timeout=6.0): return self._hit


class _Resp:
    def __init__(self, text): self.text = text; self.status_code = 200


async def _noop_request(self, method, url, content=None, headers=None, **kw):
    return _Resp("ok")


class _GateAllowsMutating(unittest.TestCase):
    def setUp(self):
        # Seed the fixture host in scope: the gate fails closed on an empty active
        # scope (3c622c3), so without this every send below is refused before the
        # leg runs and the test "passes" having sent nothing.
        seed_gate_scope(["t.test"])

    def tearDown(self):
        from harness import safety_gate
        safety_gate.reset_default_gate()


class ParamTargetsTests(unittest.TestCase):
    def test_enumerates_query_then_body(self):
        ex = HttpExchange(url="http://t.test/run?cmd=ls&x=1", method="POST",
                          request_headers={"Content-Type": "application/json"},
                          request_body='{"host":"a","note":"b"}', response_status=200, response_body="{}")
        got = param_targets(ex)
        self.assertEqual(got[:2], [("query", "cmd"), ("query", "x")])
        self.assertIn(("body", "host"), got)
        self.assertIn(("body", "note"), got)


class CommandInjectionTests(_GateAllowsMutating):
    def _exchange(self):
        return HttpExchange(url="http://t.test/api/ping", method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"host":"127.0.0.1"}', response_status=200, response_body="{}")

    def test_confirms_on_callback(self):
        v = CommandInjectionValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        responder = CountingResponder(_noop_request)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("command injection"), self._exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        # The payload-carrying request must actually have cleared the gate -- a
        # confirmed verdict off zero sends would be a vacuous pass. (_FakeCollab is
        # the OOB listener, not the send, so we count the real request here.)
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_not_confirmed_without_callback(self):
        v = CommandInjectionValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False))
        responder = CountingResponder(_noop_request)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("command injection"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")
        # Negative control still sends: not_confirmed must mean "sent, no callback",
        # not "never sent" (the exact vacuous pass this guards).
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_skips_without_params(self):
        ex = HttpExchange(url="http://t.test/api/x", method="GET", request_headers={},
                          request_body="", response_status=200, response_body="{}")
        v = CommandInjectionValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        self.assertFalse(v.applies(_f("command injection"), ex))

    def test_out_of_scope_host_skipped(self):
        v = CommandInjectionValidator(allowed_hosts=["only.test"], collaborator=_FakeCollab(hit=True))
        responder = CountingResponder(_noop_request)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("command injection"), self._exchange()))
        self.assertEqual(r.status, "skipped")
        # The sent-counter sits BELOW the scope decision: an out-of-scope host
        # reaches the responder zero times, so a seeded scope can never make this
        # pass vacuously.
        self.assertEqual(responder.count, 0, responder.why())

    def test_run_context_zero_budget_prevents_network_send(self):
        ctx = RunContext.create(
            allowed_hosts=["t.test"], max_requests=0,
            gate_config={"active_enabled": True, "allow_mutating_replay": True})
        v = CommandInjectionValidator(
            allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False),
            run_context=ctx)
        with patch("httpx.AsyncClient.request") as send:
            r = asyncio.run(v.validate(_f("command injection"), self._exchange()))
        self.assertEqual(r.status, "skipped")
        self.assertEqual(ctx.budget.used, 0)
        send.assert_not_called()


def _ssti_responder(evaluate: bool):
    """Simulate a template engine (evaluate=True) or a plain reflector
    (evaluate=False), keyed on the injected `q` value in the request body."""
    async def _req(self, method, url, content=None, headers=None, **kw):
        payload = json.loads(content).get("q", "") if content else ""
        if evaluate and _EXPR in payload:
            nonce = payload[:6]  # matches the validator's payload[:6] nonce
            return _Resp(f"<html>result {nonce}{_PRODUCT}{nonce} done</html>")
        return _Resp(f"<html>echo {payload}</html>")  # literal reflection
    return _req


class SstiTests(_GateAllowsMutating):
    def _exchange(self):
        return HttpExchange(url="http://t.test/render", method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"q":"hello"}', response_status=200, response_body="")

    def test_confirms_on_evaluated_expression(self):
        v = SstiValidator(allowed_hosts=["t.test"])
        responder = CountingResponder(_ssti_responder(evaluate=True))
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("ssti"), self._exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_not_confirmed_on_literal_reflection(self):
        # Reflected but NOT evaluated (e.g. reflected-XSS sink) must not confirm SSTI.
        v = SstiValidator(allowed_hosts=["t.test"])
        responder = CountingResponder(_ssti_responder(evaluate=False))
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("ssti"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_run_context_follows_same_origin_redirect_to_rendered_result(self):
        """A stored template editor commonly redirects after POST.  The proof is
        on the rendered GET page, so the central transport must perform that
        bounded same-origin readback."""
        stored = {"payload": ""}

        class RedirectResp:
            def __init__(self, status, text="", headers=None):
                self.status_code = status
                self.text = text
                self.headers = headers or {}

        async def request(_client, method, url, content=None, headers=None, **kw):
            if method == "POST":
                from urllib.parse import parse_qs
                stored["payload"] = parse_qs(content or "").get("template", [""])[0]
                return RedirectResp(302, headers={"location": "/rendered"})
            payload = stored["payload"]
            if _EXPR in payload:
                nonce = payload[:6]
                return RedirectResp(200, f"<html>{nonce}{_PRODUCT}{nonce}</html>")
            return RedirectResp(200, "<html>literal</html>")

        ex = HttpExchange(
            url="http://t.test/template?productId=1", method="POST",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="template=hello", response_status=302, response_body="")
        ctx = RunContext.create(
            allowed_hosts=["t.test"], max_requests=30,
            gate_config={"active_enabled": True, "allow_mutating_replay": True})
        v = SstiValidator(allowed_hosts=["t.test"], run_context=ctx)

        async def run():
            async with ctx:
                return await v.validate(_f("ssti"), ex)

        with patch("httpx.AsyncClient.request", request):
            r = asyncio.run(run())
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)

    def test_confirms_stored_expression_on_separate_discovered_render_and_restores(self):
        from urllib.parse import parse_qs
        stored = {"display": "user.name"}

        class Resp:
            def __init__(self, text="ok"):
                self.status_code = 200
                self.text = text
                self.headers = {}

        async def request(_client, method, url, content=None, headers=None, **kw):
            if method == "POST":
                stored["display"] = parse_qs(content or "").get(
                    "blog-post-author-display", [""])[0]
                return Resp("saved")
            rendered = _PRODUCT if stored["display"] == _EXPR else "Wiener"
            return Resp(f"<html>author: {rendered}</html>")

        ex = HttpExchange(
            url="http://t.test/my-account/change-blog-post-author-display",
            method="POST",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="blog-post-author-display=user.name&csrf=token",
            response_status=200, response_body="saved")
        ctx = RunContext.create(
            allowed_hosts=["t.test"], max_requests=80,
            gate_config={"active_enabled": True, "allow_mutating_replay": True})
        v = SstiValidator(allowed_hosts=["t.test"], run_context=ctx,
                          readback_urls=["http://t.test/post?postId=1"])

        async def run():
            async with ctx:
                return await v.validate(_f("ssti"), ex)

        with patch("httpx.AsyncClient.request", request):
            r = asyncio.run(run())
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertEqual(stored["display"], "user.name")

    def test_stored_readback_requires_product_absent_from_baseline(self):
        class Resp:
            status_code = 200
            headers = {}
            text = f"unrelated existing number {_PRODUCT}"

        async def request(_client, method, url, content=None, headers=None, **kw):
            return Resp()

        ex = HttpExchange(
            url="http://t.test/settings", method="POST",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="display=user.name", response_status=200, response_body="")
        ctx = RunContext.create(
            allowed_hosts=["t.test"], max_requests=100,
            gate_config={"active_enabled": True, "allow_mutating_replay": True})
        v = SstiValidator(allowed_hosts=["t.test"], run_context=ctx,
                          readback_urls=["http://t.test/post?postId=1"])

        async def run():
            async with ctx:
                return await v.validate(_f("ssti"), ex)

        with patch("httpx.AsyncClient.request", request):
            r = asyncio.run(run())
        self.assertEqual(r.status, "not_confirmed")

    def test_skips_without_params(self):
        ex = HttpExchange(url="http://t.test/x", method="GET", request_headers={},
                          request_body="", response_status=200, response_body="")
        v = SstiValidator(allowed_hosts=["t.test"])
        self.assertFalse(v.applies(_f("ssti"), ex))

    def test_run_context_zero_budget_prevents_network_send(self):
        ctx = RunContext.create(
            allowed_hosts=["t.test"], max_requests=0,
            gate_config={"active_enabled": True, "allow_mutating_replay": True})
        v = SstiValidator(allowed_hosts=["t.test"], run_context=ctx)
        with patch("httpx.AsyncClient.request") as send:
            r = asyncio.run(v.validate(_f("ssti"), self._exchange()))
        self.assertEqual(r.status, "skipped")
        self.assertEqual(ctx.budget.used, 0)
        send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
