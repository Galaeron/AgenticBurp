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
        from harness import safety_gate
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True})

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
        with patch("httpx.AsyncClient.request", _noop_request):
            r = asyncio.run(v.validate(_f("command injection"), self._exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)

    def test_not_confirmed_without_callback(self):
        v = CommandInjectionValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False))
        with patch("httpx.AsyncClient.request", _noop_request):
            r = asyncio.run(v.validate(_f("command injection"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")

    def test_skips_without_params(self):
        ex = HttpExchange(url="http://t.test/api/x", method="GET", request_headers={},
                          request_body="", response_status=200, response_body="{}")
        v = CommandInjectionValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        self.assertFalse(v.applies(_f("command injection"), ex))

    def test_out_of_scope_host_skipped(self):
        v = CommandInjectionValidator(allowed_hosts=["only.test"], collaborator=_FakeCollab(hit=True))
        with patch("httpx.AsyncClient.request", _noop_request):
            r = asyncio.run(v.validate(_f("command injection"), self._exchange()))
        self.assertEqual(r.status, "skipped")


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
        with patch("httpx.AsyncClient.request", _ssti_responder(evaluate=True)):
            r = asyncio.run(v.validate(_f("ssti"), self._exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)

    def test_not_confirmed_on_literal_reflection(self):
        # Reflected but NOT evaluated (e.g. reflected-XSS sink) must not confirm SSTI.
        v = SstiValidator(allowed_hosts=["t.test"])
        with patch("httpx.AsyncClient.request", _ssti_responder(evaluate=False)):
            r = asyncio.run(v.validate(_f("ssti"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")

    def test_skips_without_params(self):
        ex = HttpExchange(url="http://t.test/x", method="GET", request_headers={},
                          request_body="", response_status=200, response_body="")
        v = SstiValidator(allowed_hosts=["t.test"])
        self.assertFalse(v.applies(_f("ssti"), ex))


if __name__ == "__main__":
    unittest.main()
