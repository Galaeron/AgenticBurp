"""T08 CRLF/header-injection executor controls."""
import asyncio
import unittest

from harness.models import HttpExchange
from harness.run_context import RunContext
from harness.test_run_context import _Fixture
from harness.validators.header_injection_validator import HeaderInjectionValidator


class HeaderInjectionTransportTests(unittest.TestCase):
    def test_actual_probe_uses_executor_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = HeaderInjectionValidator(run_context=ctx)
        exchange = HttpExchange(url=fixture.base + "/redirect?next=home", method="GET")

        async def scenario():
            result = await validator._probe_param(exchange, "next")
            await ctx.aclose()
            return result

        try:
            result = asyncio.run(scenario())
            self.assertFalse(result.vulnerable)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(len(fixture.httpd.received), 1)
        finally:
            fixture.close()

    def test_off_scope_probe_sends_nothing(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["elsewhere.test"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = HeaderInjectionValidator(run_context=ctx)
        exchange = HttpExchange(url=fixture.base + "/redirect?next=home", method="GET")

        async def scenario():
            result = await validator._probe_param(exchange, "next")
            await ctx.aclose()
            return result

        try:
            result = asyncio.run(scenario())
            self.assertFalse(result.vulnerable)
            self.assertEqual(ctx.budget.used, 0)
            self.assertEqual(fixture.httpd.received, [])
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
