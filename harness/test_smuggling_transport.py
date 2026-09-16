"""T08 request-smuggling anomaly-sampler transport controls.

These tests deliberately make no raw-desync claim: the validator remains
observation-only until a framing-capable adapter and paired proxy fixture exist.
"""
import asyncio
import unittest

from harness.run_context import RunContext
from harness.test_run_context import _Fixture
from harness.validators.http_request_smuggling_validator import HttpRequestSmugglingValidator


class SmugglingTransportTests(unittest.TestCase):
    def test_actual_sampler_send_uses_executor_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=1,
            gate_config={"active_enabled": True, "allow_mutating_replay": True})
        validator = HttpRequestSmugglingValidator(run_context=ctx)

        async def scenario():
            response = await validator._send_raw_request(
                "POST", fixture.base + "/probe", headers={"X-Probe": "ordinary"},
                body="benign")
            await ctx.aclose()
            return response

        try:
            response = asyncio.run(scenario())
            self.assertEqual(response.status_code, 200)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(len(fixture.httpd.received), 1)
        finally:
            fixture.close()

    def test_denied_mutation_sends_nothing_and_uses_no_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=1,
            gate_config={"active_enabled": True, "allow_mutating_replay": False})
        validator = HttpRequestSmugglingValidator(run_context=ctx)

        async def scenario():
            response = await validator._send_raw_request(
                "POST", fixture.base + "/probe", body="benign")
            await ctx.aclose()
            return response

        try:
            self.assertIsNone(asyncio.run(scenario()))
            self.assertEqual(ctx.budget.used, 0)
            self.assertEqual(fixture.httpd.received, [])
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
