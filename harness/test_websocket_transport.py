"""T08 WebSocket raw-socket policy-adapter controls."""
import socketserver
import threading
import unittest

from run_context import RunContext, ScopePolicy
from validators.websocket_validator import WebsocketValidator


class _HandshakeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096)
        self.server.received.append(data.decode("latin1", "replace"))
        self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")


class _TcpFixture:
    def __init__(self):
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _HandshakeHandler)
        self.server.received = []
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class WebsocketTransportTests(unittest.TestCase):
    def test_actual_raw_handshake_uses_policy_and_budget(self):
        fixture = _TcpFixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = WebsocketValidator(run_context=ctx)
        try:
            result = validator._attempt_handshake(
                f"ws://127.0.0.1:{fixture.port}/socket", None)
            self.assertTrue(result.checked)
            self.assertFalse(result.vulnerable)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(len(fixture.server.received), 1)
            self.assertIn("Origin: https://attacker-controlled-cswsh-probe.example",
                          fixture.server.received[0])
        finally:
            fixture.close()

    def test_off_scope_handshake_never_connects_or_uses_budget(self):
        fixture = _TcpFixture()
        ctx = RunContext.create(allowed_hosts=["elsewhere.test"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = WebsocketValidator(run_context=ctx)
        try:
            result = validator._attempt_handshake(
                f"ws://127.0.0.1:{fixture.port}/socket", None)
            self.assertFalse(result.checked)
            self.assertEqual(ctx.budget.used, 0)
            self.assertEqual(fixture.server.received, [])
        finally:
            fixture.close()

    def test_unregistered_cookie_fails_closed_before_connect(self):
        fixture = _TcpFixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = WebsocketValidator(run_context=ctx)
        try:
            result = validator._attempt_handshake(
                f"ws://127.0.0.1:{fixture.port}/socket", "sid=unknown")
            self.assertFalse(result.checked)
            self.assertEqual(ctx.budget.used, 0)
            self.assertEqual(fixture.server.received, [])
        finally:
            fixture.close()

    def test_registered_cookie_is_allowed_and_preserved(self):
        fixture = _TcpFixture()
        http_origin = f"http://127.0.0.1:{fixture.port}"
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        ctx.sessions.register("user", "user", {"Cookie": "sid=owned"},
                              allowed_origins=[ScopePolicy.origin_of(http_origin)])
        validator = WebsocketValidator(run_context=ctx)
        try:
            result = validator._attempt_handshake(
                f"ws://127.0.0.1:{fixture.port}/socket", "sid=owned")
            self.assertTrue(result.checked)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(len(fixture.server.received), 1)
            self.assertIn("Cookie: sid=owned", fixture.server.received[0])
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
