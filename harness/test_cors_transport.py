"""T08 CORS validator executor-routing controls."""
import asyncio
import unittest

from run_context import RunContext
from test_run_context import _Fixture
from validators.cors_validator import CorsValidator


class CorsTransportTests(unittest.TestCase):
    def test_actual_read_uses_executor_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = CorsValidator(run_context=ctx)

        async def scenario():
            response = await validator._send_request(
                fixture.base + "/cors", headers={"Origin": "https://evil.test"})
            await ctx.aclose()
            return response

        try:
            response = asyncio.run(scenario())
            self.assertEqual(response.status_code, 200)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(len(fixture.httpd.received), 1)
        finally:
            fixture.close()

    def test_off_scope_control_sends_nothing_and_uses_no_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["elsewhere.test"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = CorsValidator(run_context=ctx)

        async def scenario():
            response = await validator._send_request(fixture.base + "/cors")
            await ctx.aclose()
            return response

        try:
            response = asyncio.run(scenario())
            self.assertIsNone(response)
            self.assertEqual(ctx.budget.used, 0)
            self.assertEqual(fixture.httpd.received, [])
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
