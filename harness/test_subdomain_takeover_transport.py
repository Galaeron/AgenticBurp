"""T08 subdomain-takeover fingerprint executor controls."""
import asyncio
import unittest

from harness.run_context import RunContext
from harness.test_run_context import _Fixture
from harness.validators.subdomain_takeover_validator import SubdomainTakeoverValidator


class _LoopbackValidator(SubdomainTakeoverValidator):
    def __init__(self, url, **kwargs):
        super().__init__(**kwargs)
        self.url = url

    def _fingerprint_url(self, host):
        return self.url


class TakeoverTransportTests(unittest.TestCase):
    def test_actual_fingerprint_fetch_uses_executor_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = _LoopbackValidator(fixture.base + "/", run_context=ctx)

        async def scenario():
            result = await validator._check_fingerprint("unused.github.io")
            await ctx.aclose()
            return result

        try:
            result = asyncio.run(scenario())
            self.assertFalse(result.vulnerable)
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(len(fixture.httpd.received), 1)
        finally:
            fixture.close()

    def test_off_scope_fingerprint_fetch_sends_nothing(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["elsewhere.test"], max_requests=1,
                                gate_config={"active_enabled": True})
        validator = _LoopbackValidator(fixture.base + "/", run_context=ctx)

        async def scenario():
            result = await validator._check_fingerprint("unused.github.io")
            await ctx.aclose()
            return result

        try:
            result = asyncio.run(scenario())
            self.assertFalse(result.checked)
            self.assertEqual(ctx.budget.used, 0)
            self.assertEqual(fixture.httpd.received, [])
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
