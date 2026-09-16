"""Tests for the TOCTOU privilege-escalation race leg (V19), with mocked GET
reads and a mocked concurrent burst. The distinguishing oracle: a privileged
field flips ONLY under concurrency (>=2 clean successes) + an independent re-read."""
import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, patch, MagicMock

from harness.models import Finding, HttpExchange
from harness.safety_gate import get_default_gate, reset_default_gate
from harness.run_context import RunContext, ScopePolicy
from harness.validators.toctou_validator import ToctouValidator


def _finding(vc="toctou"):
    return Finding(vulnerability_class=vc, severity="high", confidence=0.6,
                   summary="t", evidence="t", suggested_test="t", basis="derived")


def _ex(url="http://target.test/api/account/role", method="POST",
        body='{"name":"alice"}', headers=None):
    return HttpExchange(url=url, method=method, request_body=body,
                        request_headers=headers or {"Content-Type": "application/json"},
                        response_status=200, response_body="")


def _resp(status=200, text="ok"):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


class _StateHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _reply(self, status, body):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.server.received.append(("GET", self.headers.get("Authorization")))
        self._reply(200, json.dumps({"role": self.server.role}))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.received.append(("POST", self.headers.get("Authorization")))
        if self.server.allow_flip:
            self.server.role = body.get("role", self.server.role)
        self._reply(200, '{"ok":true}')


class _StateFixture:
    def __init__(self, *, allow_flip=True):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _StateHandler)
        self.httpd.received = []
        self.httpd.role = "user"
        self.httpd.allow_flip = allow_flip
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/account"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ToctouTests(unittest.TestCase):
    def setUp(self):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                          "max_burst_size": 12})

    def tearDown(self):
        reset_default_gate()

    def test_skip_on_get(self):
        v = ToctouValidator(allowed_hosts=["target.test"])
        self.assertFalse(v.applies(_finding(), _ex(method="GET")))

    def test_skip_out_of_scope(self):
        v = ToctouValidator(allowed_hosts=["target.test"])
        r = asyncio.run(v.validate(_finding(), _ex(url="http://evil.test/x")))
        self.assertEqual(r.status, "skipped")

    def test_run_context_actual_transport_preserves_session_and_budget(self):
        fixture = _StateFixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=6,
            gate_config={"active_enabled": True, "allow_mutating_replay": True,
                         "max_burst_size": 4})
        ctx.sessions.register("user", "user", {"Authorization": "Bearer race"},
                              allowed_origins=[ScopePolicy.origin_of(fixture.url)])
        validator = ToctouValidator(
            allowed_hosts=["127.0.0.1"], burst_size=4, run_context=ctx)

        async def scenario():
            result = await validator.validate(
                _finding(), _ex(url=fixture.url, headers={"Authorization": "Bearer race"}))
            await ctx.aclose()
            return result

        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.status, "confirmed")
            self.assertEqual(ctx.budget.used, 6)
            self.assertEqual([m for m, _ in fixture.httpd.received].count("POST"), 4)
            self.assertTrue(all(auth == "Bearer race" for _, auth in fixture.httpd.received))
        finally:
            fixture.close()

    def test_run_context_denied_burst_sends_no_mutation(self):
        fixture = _StateFixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=6,
            gate_config={"active_enabled": True, "allow_mutating_replay": False,
                         "max_burst_size": 4})
        validator = ToctouValidator(
            allowed_hosts=["127.0.0.1"], burst_size=4, run_context=ctx)

        async def scenario():
            result = await validator.validate(_finding(), _ex(url=fixture.url))
            await ctx.aclose()
            return result

        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.status, "skipped")
            self.assertEqual([m for m, _ in fixture.httpd.received].count("POST"), 0)
            self.assertEqual(ctx.budget.used, 1)  # baseline GET only
        finally:
            fixture.close()

    def test_skip_when_burst_ceiling_below_two(self):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True, "max_burst_size": 1})
        v = ToctouValidator(allowed_hosts=["target.test"])
        # baseline read must return JSON with a non-privileged authority field
        with patch.object(v, "_get_json", new=AsyncMock(return_value=(200, {"role": "user"}))):
            r = asyncio.run(v.validate(_finding(), _ex()))
        self.assertEqual(r.status, "skipped")
        self.assertIn("max_burst_size", r.summary)

    @patch("harness.validators.toctou_validator.httpx.AsyncClient")
    @patch("harness.global_throttle.acquire", new_callable=AsyncMock)
    def test_confirms_when_field_flips_under_concurrency(self, _t, mock_cls):
        v = ToctouValidator(allowed_hosts=["target.test"], burst_size=4)
        reads = iter([(200, {"role": "user"}),      # baseline: not privileged
                      (200, {"role": "admin"})])    # verify: flipped
        # burst client: every concurrent request returns a clean 200
        client = AsyncMock()
        client.request = AsyncMock(return_value=_resp(200, "ok"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        with patch.object(v, "_get_json", new=AsyncMock(side_effect=lambda *a, **k: next(reads))):
            r = asyncio.run(v.validate(_finding(), _ex()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertIn("role", r.summary)

    @patch("harness.validators.toctou_validator.httpx.AsyncClient")
    @patch("harness.global_throttle.acquire", new_callable=AsyncMock)
    def test_single_success_is_mass_assign_not_race(self, _t, mock_cls):
        # field flips, but only ONE concurrent request succeeds cleanly (rest
        # rejected) -> that's mass-assignment (sequence's case), not a race.
        v = ToctouValidator(allowed_hosts=["target.test"], burst_size=4)
        reads = iter([(200, {"role": "user"}), (200, {"role": "admin"})])
        calls = {"n": 0}

        async def _req(*a, **k):
            calls["n"] += 1
            return _resp(200, "ok") if calls["n"] == 1 else _resp(409, "already applied")
        client = AsyncMock()
        client.request = _req
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        with patch.object(v, "_get_json", new=AsyncMock(side_effect=lambda *a, **k: next(reads))):
            r = asyncio.run(v.validate(_finding(), _ex()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertIn("mass-assignment", r.summary)

    @patch("harness.validators.toctou_validator.httpx.AsyncClient")
    @patch("harness.global_throttle.acquire", new_callable=AsyncMock)
    def test_not_confirmed_when_no_flip(self, _t, mock_cls):
        v = ToctouValidator(allowed_hosts=["target.test"], burst_size=4)
        reads = iter([(200, {"role": "user"}), (200, {"role": "user"})])  # never flips
        client = AsyncMock()
        client.request = AsyncMock(return_value=_resp(200, "ok"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        with patch.object(v, "_get_json", new=AsyncMock(side_effect=lambda *a, **k: next(reads))):
            r = asyncio.run(v.validate(_finding(), _ex()))
        self.assertEqual(r.status, "not_confirmed")

    def test_registered_and_active(self):
        from harness.validators.registry import ValidatorRegistry
        reg = ValidatorRegistry({"validators": {"active_enabled": True}})
        self.assertIn("toctou", reg.validators)
        self.assertTrue(reg.validators["toctou"].active)


if __name__ == "__main__":
    unittest.main()
