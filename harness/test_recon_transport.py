"""T08 recon fetch executor controls."""
import asyncio
import unittest

from harness.run_context import RunContext
from harness.test_run_context import _Fixture
from harness.validators.recon_validator import ReconValidator


class ReconTransportTests(unittest.TestCase):
    def test_actual_fetch_uses_executor_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = ReconValidator(run_context=ctx)

        async def scenario():
            response = await validator._send_request(fixture.base + "/robots.txt")
            await ctx.aclose()
            return response

        try:
            response = asyncio.run(scenario())
            self.assertEqual(response.status_code, 200)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(len(fixture.httpd.received), 1)
        finally:
            fixture.close()

    def test_off_scope_fetch_sends_nothing_and_uses_no_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["elsewhere.test"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = ReconValidator(run_context=ctx)

        async def scenario():
            response = await validator._send_request(fixture.base + "/.env")
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
