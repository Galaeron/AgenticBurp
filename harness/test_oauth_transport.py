"""T08 OAuth redirect_uri probe executor controls."""
import asyncio
import unittest

from models import HttpExchange
from run_context import RunContext
from test_run_context import _Fixture
from validators.oauth_validator import OAuthValidator


def _exchange(base):
    return HttpExchange(
        url=(base + "/authorize?response_type=code&client_id=web&state=abcdefgh"
             "&redirect_uri=" + base + "%2Fcallback"), method="GET")


class OAuthTransportTests(unittest.TestCase):
    def test_actual_redirect_probe_uses_executor_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = OAuthValidator(run_context=ctx)

        async def scenario():
            result = await validator._check_redirect_uri_validation(_exchange(fixture.base))
            await ctx.aclose()
            return result

        try:
            result = asyncio.run(scenario())
            self.assertTrue(result.checked)
            self.assertFalse(result.vulnerable)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(len(fixture.httpd.received), 1)
        finally:
            fixture.close()

    def test_off_scope_redirect_probe_sends_nothing(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["elsewhere.test"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = OAuthValidator(run_context=ctx)

        async def scenario():
            result = await validator._check_redirect_uri_validation(_exchange(fixture.base))
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
