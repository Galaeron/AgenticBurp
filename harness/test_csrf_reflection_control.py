"""I04: a reflecting endpoint must never confirm CSRF.

LB-CSRF-REPLAY: the csrf leg used to replay a token-bearing form write as a
tokenless GET and confirm (0.95) when that same response contained a submitted
value. A server that merely echoes its query string -- no state change, no
browser, the cookie attached by the harness itself -- satisfied that test. These
drive the real CsrfValidator through a real run transport against an owned
loopback target that only reflects, and against one that changes nothing at all.
"""
from __future__ import annotations

import asyncio
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote_plus, urlsplit

from harness import safety_gate
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators.base import ValidationResult
from harness.validators.csrf_validator import CsrfValidator


class _Reflector:
    """Echoes the request's query string into an HTML page and stores nothing."""

    def __init__(self):
        self.requests: list[tuple[str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _page(self, text: str) -> None:
                data = f"<html><body>Saved: {text}</body></html>".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.requests.append(("GET", self.path))
                self._page(unquote_plus(urlsplit(self.path).query))

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests.append(("POST", self.path))
                self._page("")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


def _capture(base: str) -> HttpExchange:
    return HttpExchange(
        url=f"{base}/account/email", method="POST",
        request_headers={"Cookie": "session=victim-session",
                         "Content-Type": "application/x-www-form-urlencoded"},
        request_body="email=probe%40example.com&csrf_token=abc123",
        response_status=200, response_body="ok")


def _finding() -> Finding:
    return Finding(vulnerability_class="csrf", severity="medium", confidence=0.3,
                   summary="csrf precondition", evidence="", suggested_test="", basis="derived")


class _RetiredDecisionDouble(CsrfValidator):
    """Test double of the retired LB-CSRF-REPLAY decision, sent only through the
    run's gated transport to the owned reflector."""

    async def validate(self, finding, exchange):
        from urllib.parse import parse_qsl, urlencode
        fields = [(k, v) for k, v in parse_qsl(exchange.request_body or "") if "csrf" not in k]
        outcome = await self.run_context.target_transport().send_creds(
            "GET", f"{exchange.url}?{urlencode(fields)}", capability=self.name,
            headers={"Cookie": exchange.request_headers.get("Cookie", "")})
        hit = outcome.ok and any(len(v) >= 5 and v in (outcome.body or "") for _, v in fields)
        return ValidationResult(self.name, "confirmed" if hit else "not_confirmed", "csrf",
                                confidence=0.95 if hit else 0.0, confirmed=hit)


class ReflectingEndpointNeverConfirmsCsrfTests(unittest.TestCase):
    def setUp(self):
        safety_gate.reset_default_gate()
        self.target = _Reflector()
        self.addCleanup(self.target.close)

    def _validate(self, *, mutating: bool, validator_cls=CsrfValidator):
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=20,
                               gate_config={"active_enabled": True,
                                            "allow_mutating_replay": mutating})
        # As in an engagement: the victim's identity is a registered run session,
        # so the harness itself can attach its cookie to a replay.
        rc.sessions.register("victim", "victim", headers={"Cookie": "session=victim-session"},
                             allowed_origins=[self.target.base])
        validator = validator_cls(allowed_hosts=["127.0.0.1"], run_context=rc)

        async def go():
            try:
                async with rc:
                    return await validator.validate(_finding(), _capture(self.target.base))
            finally:
                await rc.aclose()
        return asyncio.run(go()), rc

    def _assert_reflection_never_confirms(self, result):
        self.assertFalse(result.confirmed, result.summary)
        self.assertLessEqual(result.confidence, 0.4)

    def test_reflection_only_target_does_not_confirm_with_mutation_off(self):
        result, rc = self._validate(mutating=False)
        self._assert_reflection_never_confirms(result)
        # Default-off mutation: the write is never replayed in any method --
        # including as a state-changing GET the gate would classify as safe.
        self.assertEqual(self.target.requests, [])

    def test_reflection_only_target_does_not_confirm_with_mutation_on(self):
        result, rc = self._validate(mutating=True)
        self._assert_reflection_never_confirms(result)
        self.assertNotIn(("GET", "/account/email?email=probe%40example.com"), self.target.requests)

    def test_reinstated_same_response_decision_is_caught(self):
        """Fault injection: restore the retired decision (tokenless GET, confirm when
        that same response contains a submitted value). The reflector must expose
        it, so the negative-control assertion above has to fail."""
        result, rc = self._validate(mutating=False, validator_cls=_RetiredDecisionDouble)
        with self.assertRaises(AssertionError):
            self._assert_reflection_never_confirms(result)



class CsrfManualVerificationGuidanceTests(unittest.TestCase):
    """I04 follow-up (owner request): when CSRF cannot be confirmed, the operator
    gets a plain indication plus copy-ready steps and a click-to-submit form."""

    def _guidance(self, headers, body):
        from harness.validators.csrf_validator import CsrfValidator as V, _manual_verification
        ex = HttpExchange(url="http://127.0.0.1:1/account/email", method="POST",
                          request_headers=headers, request_body=body)
        return V._guided(ValidationResult("csrf", "skipped", "csrf"), ex,
                         {k.lower(): v for k, v in headers.items()}).manual_verification

    def test_cookie_form_gets_steps_and_a_test_form_without_the_token(self):
        text = self._guidance({"Cookie": "session=s", "Content-Type": "application/x-www-form-urlencoded"},
                              "email=probe%40example.com&password=hunter22&csrf_token=abc123")
        self.assertIn("NEEDS MANUAL CHECK", text)
        self.assertIn('<form action="http://127.0.0.1:1/account/email" method="POST">', text)
        self.assertIn('name="email" value="probe@example.com"', text)
        self.assertIn('name="password" value="REPLACE_ME"', text)   # secrets never echoed
        self.assertNotIn("csrf_token", text)
        self.assertNotIn("abc123", text)
        self.assertNotIn("hunter22", text)

    def test_json_body_gets_json_specific_steps(self):
        text = self._guidance({"Cookie": "session=s", "Content-Type": "application/json"},
                              '{"email": "probe@example.com"}')
        self.assertIn("JSON body", text)
        self.assertNotIn("<form", text)

    def test_bearer_only_request_gets_no_guidance(self):
        self.assertEqual(self._guidance({"Authorization": "Bearer t"}, "email=a%40b.c"), "")


class CsrfManualCheckAnalyzeCallerTests(unittest.TestCase):
    """Through Orchestrator.analyze (silent model, mutation off): a cookie-authenticated
    form write is reported as a low-severity NEEDS MANUAL CHECK candidate with the
    steps as its next step; a SameSite=Lax capture is not."""

    def setUp(self):
        import os, shutil, tempfile
        from pathlib import Path
        from harness import cache, store
        self._tmp = tempfile.mkdtemp(prefix="i04_analyze_")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        self.addCleanup(lambda: (setattr(store, "_DB_PATH", self._orig[0]),
                                 setattr(cache, "_cache", self._orig[1]),
                                 shutil.rmtree(self._tmp, ignore_errors=True)))

    def _analyze(self, response_headers):
        from unittest.mock import patch
        from harness.orchestrator import Orchestrator
        from harness.test_engagement_transport_callers import _Model, _config, _install_model
        target = _Reflector()
        self.addCleanup(target.close)
        orch = Orchestrator(_config(mutating=False))
        orch.allowed_hosts = ["127.0.0.1"]
        _install_model(orch, _Model([]))
        exchange = _capture(target.base).model_copy(update={"response_headers": response_headers})
        with patch("harness.browser_driver.default_driver", return_value=None):
            response = asyncio.run(orch.analyze(exchange, engagement_id="i04-manual-check"))
        return [f for report in response.agent_reports for f in report.findings
                if f.vulnerability_class == "csrf"], target

    def test_cookie_form_write_is_a_visible_manual_check_candidate(self):
        findings, target = self._analyze({"Set-Cookie": "session=s; Path=/"})
        self.assertTrue(findings, "the CSRF candidate disappeared")
        f = findings[0]
        self.assertFalse(f.confirmed)
        self.assertEqual(f.severity, "low")
        self.assertIn("NEEDS MANUAL CHECK", f.summary)
        self.assertIn("csrf-test.html", f.suggested_test)
        self.assertNotIn(("POST", "/account/email"), target.requests)   # mutation off: no replay

    def test_samesite_lax_capture_is_not_a_candidate(self):
        findings, _ = self._analyze({"Set-Cookie": "session=s; Path=/; SameSite=Lax"})
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
