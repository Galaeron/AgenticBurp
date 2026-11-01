"""CORS-specific scope and safe-method controls; shared transport is in test_validator_transport."""
import asyncio
import unittest

from harness.run_context import RunContext
from harness.test_run_context import _Fixture
from harness.validators.cors_validator import CorsValidator


class CorsTransportTests(unittest.TestCase):


    def test_validate_skips_host_outside_allowed_scope(self):
        """W-1: validate() has its own in-validator scope guard now. On a host
        outside allowed_hosts it returns skipped without ever attempting a send
        (so an unscoped construction can't leak live traffic)."""
        from harness.models import Finding, HttpExchange
        validator = CorsValidator(allowed_hosts=["good.example"])
        finding = Finding(vulnerability_class="cors", confidence=0.5, summary="s",
                          evidence="e", suggested_test="t", basis="assumed")
        exchange = HttpExchange(url="http://evil.example/api", method="GET")
        result = asyncio.run(validator.validate(finding, exchange))
        self.assertEqual(result.status, "skipped")
        self.assertFalse(result.confirmed)
        self.assertIn("out of scope", result.summary)

    def test_full_validate_sends_no_mutating_method(self):
        """W-1: a full CORS validate() pass must never send a mutating method
        to the target. The preflight-bypass probe used to POST; it is now a
        simple GET, so the target only ever sees safe (GET/OPTIONS) requests."""
        from harness.models import Finding, HttpExchange
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=50,
                                gate_config={"active_enabled": True})
        validator = CorsValidator(run_context=ctx, allowed_hosts=["127.0.0.1"])
        finding = Finding(vulnerability_class="cors", confidence=0.5, summary="s",
                          evidence="e", suggested_test="t", basis="assumed")
        exchange = HttpExchange(url=fixture.base + "/cors", method="GET")

        async def scenario():
            r = await validator.validate(finding, exchange)
            await ctx.aclose()
            return r

        try:
            asyncio.run(scenario())
            self.assertTrue(fixture.httpd.received, "validator sent nothing at all")
            methods = {r["method"] for r in fixture.httpd.received}
            for mutating in ("POST", "PUT", "PATCH", "DELETE"):
                self.assertNotIn(
                    mutating, methods,
                    f"CORS validator sent a {mutating} to the target: {methods}")
        finally:
            fixture.close()




class CorsDecodedResponseTests(unittest.TestCase):
    """Real HTTP -> TargetTransport -> CORS consumer, including failed sends."""

    def _run(self, encoding, reflected=True, in_scope=True, conversion_error=False, standalone=False):
        import gzip
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from unittest.mock import patch
        import brotli
        from harness.models import Finding, HttpExchange
        from harness.validators import cors_validator as cors

        body = b'fixture CORS response'
        wire = {"plain": body, "gzip": gzip.compress(body),
                "br": brotli.compress(body), "malformed": b'not gzip'}[encoding]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.server.received.append(self.command)
                self.send_response(200)
                if encoding != "plain":
                    self.send_header("Content-Encoding", "gzip" if encoding == "malformed" else encoding)
                self.send_header("Content-Length", str(len(wire)))
                if reflected:
                    self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
                    self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Vary", "Origin")
                self.end_headers()
                self.wfile.write(wire)

            do_OPTIONS = do_GET

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.received = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}/cors'
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"] if in_scope else ["denied.invalid"], max_requests=50,
                                gate_config={"active_enabled": True})
        validator = CorsValidator(run_context=None if standalone else ctx, allowed_hosts=["127.0.0.1"])
        finding = Finding(vulnerability_class="cors", confidence=0.5, summary="s",
                          evidence="e", suggested_test="t", basis="assumed")
        events = []
        policies = []
        original_probe = cors._note_probe

        def observe_probe(outcome):
            events.append(outcome)
            original_probe(outcome)

        original_policy = cors._note_policy

        def observe_policy(sent, received):
            policies.append(dict(received))
            original_policy(sent, received)

        async def scenario():
            try:
                return await validator.validate(finding, HttpExchange(url=url, method="GET"))
            finally:
                await ctx.aclose()

        try:
            with patch.object(cors, "get_default_gate", return_value=ctx.gate), patch.object(cors, "_note_probe", side_effect=observe_probe), patch.object(
                    cors, "_note_policy", side_effect=observe_policy):
                if conversion_error:
                    # Leave the real executor and HTTP client intact; fail only
                    # consumer processing after a successful real send.
                    with patch.object(cors, "_note_policy", side_effect=ValueError("consumer failure")):
                        result = asyncio.run(scenario())
                else:
                    result = asyncio.run(scenario())
            return result, events, list(server.received), policies
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_compressed_and_plain_grants_agree(self):
        results = []
        for encoding in ("plain", "gzip", "br"):
            with self.subTest(encoding=encoding):
                result, events, received, policies = self._run(encoding)
                self.assertTrue(result.confirmed, result.summary)
                self.assertEqual(events, ["ok"] * len(received))
                self.assertTrue(result.attack_artifact_id)
                if encoding != "plain":
                    self.assertTrue(any(p.get("content-encoding") == encoding for p in policies))
                results.append((result.status, result.header_fingerprint, result.raw_output))
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])

    def test_compressed_and_plain_secure_controls_agree(self):
        for encoding in ("plain", "gzip", "br"):
            with self.subTest(encoding=encoding):
                result, events, received, _ = self._run(encoding, reflected=False)
                self.assertEqual(result.status, "safe", result.summary)
                self.assertFalse(result.confirmed)
                self.assertEqual(events, ["ok"] * len(received))

    def test_malformed_encoding_is_incomplete(self):
        result, events, received, _ = self._run("malformed")
        self.assertEqual(result.status, "inconclusive")
        self.assertFalse(result.confirmed)
        self.assertGreater(len(received), 0)
        self.assertEqual(events, ["error"] * len(received))

    def test_blocked_has_no_send(self):
        result, events, received, _ = self._run("gzip", in_scope=False)
        self.assertEqual(result.status, "blocked")
        self.assertFalse(result.confirmed)
        self.assertEqual(received, [])
        self.assertTrue(events)
        self.assertEqual(set(events), {"blocked"})

    def test_consumer_error_has_one_terminal_event(self):
        result, events, received, _ = self._run("plain", conversion_error=True)
        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(events, ["error"] * len(received))

    def test_standalone_consumer_error_has_one_terminal_event(self):
        result, events, received, _ = self._run("plain", conversion_error=True, standalone=True)
        self.assertGreater(len(received), 0)
        self.assertEqual(result.status, "inconclusive")
        self.assertFalse(result.confirmed)
        self.assertEqual(events, ["error"] * len(received))

    def test_standalone_secure_control_has_one_terminal_event(self):
        result, events, received, _ = self._run("plain", reflected=False, standalone=True)
        self.assertGreater(len(received), 0)
        self.assertEqual(result.status, "safe")
        self.assertFalse(result.confirmed)
        self.assertEqual(events, ["ok"] * len(received))


if __name__ == "__main__":
    unittest.main()
