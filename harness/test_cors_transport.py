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


if __name__ == "__main__":
    unittest.main()
