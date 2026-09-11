"""T08 CSP/clickjacking fresh-fetch executor controls."""
import asyncio
import unittest

from models import HttpExchange
from run_context import RunContext
from test_run_context import _Fixture
from validators.csp_validator import CspValidator


class CspTransportTests(unittest.TestCase):
    def test_actual_fresh_fetch_uses_executor_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = CspValidator(run_context=ctx)
        exchange = HttpExchange(url=fixture.base + "/page", method="GET")

        async def scenario():
            headers = await validator._fetch_fresh_headers(exchange)
            await ctx.aclose()
            return headers

        try:
            headers = asyncio.run(scenario())
            self.assertIsInstance(headers, dict)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(len(fixture.httpd.received), 1)
        finally:
            fixture.close()

    def test_off_scope_fresh_fetch_uses_no_transport_or_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["elsewhere.test"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = CspValidator(run_context=ctx)
        exchange = HttpExchange(url=fixture.base + "/page", method="GET")

        async def scenario():
            headers = await validator._fetch_fresh_headers(exchange)
            await ctx.aclose()
            return headers

        try:
            self.assertIsNone(asyncio.run(scenario()))
            self.assertEqual(ctx.budget.used, 0)
            self.assertEqual(fixture.httpd.received, [])
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
