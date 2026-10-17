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


class ReflectingEndpointNeverConfirmsCsrfTests(unittest.TestCase):
    def setUp(self):
        safety_gate.reset_default_gate()
        self.target = _Reflector()
        self.addCleanup(self.target.close)

    def _validate(self, *, mutating: bool):
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=20,
                               gate_config={"active_enabled": True,
                                            "allow_mutating_replay": mutating})
        # As in an engagement: the victim's identity is a registered run session,
        # so the harness itself can attach its cookie to a replay.
        rc.sessions.register("victim", "victim", headers={"Cookie": "session=victim-session"},
                             allowed_origins=[self.target.base])
        validator = CsrfValidator(allowed_hosts=["127.0.0.1"], run_context=rc)

        async def go():
            try:
                async with rc:
                    return await validator.validate(_finding(), _capture(self.target.base))
            finally:
                await rc.aclose()
        return asyncio.run(go()), rc

    def test_reflection_only_target_does_not_confirm_with_mutation_off(self):
        result, rc = self._validate(mutating=False)
        self.assertFalse(result.confirmed, result.summary)
        # Default-off mutation: the write is never replayed in any method --
        # including as a state-changing GET the gate would classify as safe.
        self.assertEqual(self.target.requests, [])

    def test_reflection_only_target_does_not_confirm_with_mutation_on(self):
        result, rc = self._validate(mutating=True)
        self.assertFalse(result.confirmed, result.summary)
        self.assertNotIn(("GET", "/account/email?email=probe%40example.com"), self.target.requests)
        self.assertLessEqual(result.confidence, 0.4)


if __name__ == "__main__":
    unittest.main()
