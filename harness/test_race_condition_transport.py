"""T08 race-condition transport routing and invocation-isolation controls."""
import asyncio
import unittest

from harness.models import Finding, HttpExchange
from harness.run_context import RunContext, ScopePolicy
from harness.test_run_context import _Fixture
from harness.validators.race_condition_validator import RaceConditionValidator
from harness.validators.registry import ValidatorRegistry


def _finding():
    return Finding(vulnerability_class="race_condition", severity="medium", confidence=0.5,
                   summary="race", evidence="candidate", suggested_test="burst",
                   basis="derived")


def _exchange(url, headers=None):
    return HttpExchange(url=url, method="POST", request_headers=headers or {},
                        request_body='{"claim":true}', response_status=200,
                        response_body="posted")


class RaceTransportTests(unittest.TestCase):
    def test_actual_burst_uses_bound_session_and_exact_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=3,
            gate_config={"active_enabled": True, "allow_mutating_replay": True,
                         "max_burst_size": 3})
        ctx.sessions.register("user", "user", {"Authorization": "Bearer racer"},
                              allowed_origins=[ScopePolicy.origin_of(fixture.base)])
        validator = RaceConditionValidator(burst_size=3, run_context=ctx)

        async def scenario():
            result = await validator.validate(
                _finding(), _exchange(fixture.base + "/claim",
                                      {"Authorization": "Bearer racer"}))
            await ctx.aclose()
            return result

        try:
            result = asyncio.run(scenario())
            # Repeated 200s are a lead, not proof: no state read-back exists.
            self.assertEqual(result.status, "not_confirmed")
            self.assertFalse(result.confirmed)
            self.assertIn("read-back", result.limitation)
            self.assertEqual(ctx.budget.used, 3)
            self.assertEqual(len(fixture.httpd.received), 3)
            self.assertTrue(all(r["authorization"] == "Bearer racer"
                                for r in fixture.httpd.received))
        finally:
            fixture.close()

    def _burst(self, path, body='{"claim":true}'):
        fixture = _Fixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=12,
            gate_config={"active_enabled": True, "allow_mutating_replay": True,
                         "max_burst_size": 12})
        registry = ValidatorRegistry({"validators": {"active_enabled": True}})
        exchange = HttpExchange(url=fixture.base + path, method="POST", request_headers={},
                                request_body=body, response_status=200,
                                response_body="posted")
        validator = next(v for v in registry.bind_run_context(
            registry.for_finding(_finding(), exchange), ctx)
            if v.name == "race_condition_validator")
        validator.burst_size = 12

        async def scenario():
            result = await validator.validate(_finding(), exchange)
            await ctx.aclose()
            return result

        try:
            return asyncio.run(scenario()), len(fixture.httpd.received)
        finally:
            fixture.close()

    def test_login_burst_is_not_applicable_and_sends_nothing(self):
        result, sent = self._burst("/rest/user/login",
                                   '{"email":"a@b.test","password":"pw"}')
        self.assertEqual(result.status, "skipped")
        self.assertFalse(result.confirmed)
        self.assertEqual(sent, 0)

    def test_token_grant_burst_is_not_applicable(self):
        result, sent = self._burst("/connect", "grant_type=password&username=a&password=b")
        self.assertEqual(result.status, "skipped")
        self.assertEqual(sent, 0)

    def test_twelve_successes_without_readback_is_a_lead_not_confirmed(self):
        result, sent = self._burst("/api/coupons/redeem")
        self.assertEqual(sent, 12)
        self.assertEqual(result.status, "not_confirmed")
        self.assertFalse(result.confirmed)
        self.assertLess(result.confidence, 0.5)
        self.assertIn("12 of 12 concurrent requests", result.summary)  # lead evidence kept
        self.assertIn("read-back", result.limitation)
        self.assertTrue(result.manual_verification)

    def test_denied_burst_sends_nothing_and_uses_no_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=3,
            gate_config={"active_enabled": True, "allow_mutating_replay": False,
                         "max_burst_size": 3})
        validator = RaceConditionValidator(burst_size=3, run_context=ctx)

        async def scenario():
            result = await validator.validate(_finding(), _exchange(fixture.base + "/claim"))
            await ctx.aclose()
            return result

        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.status, "blocked")
            self.assertEqual(ctx.budget.used, 0)
            self.assertEqual(fixture.httpd.received, [])
        finally:
            fixture.close()

    def test_registry_binds_context_on_copy_not_shared_validator(self):
        registry = ValidatorRegistry({"validators": {"active_enabled": True}})
        original = registry.validators["race_condition"]
        c1 = RunContext.create(allowed_hosts=["one.test"])
        c2 = RunContext.create(allowed_hosts=["two.test"])
        exchange = _exchange("http://one.test/claim")
        b1 = next(v for v in registry.bind_run_context(
                  registry.for_finding(_finding(), exchange), c1)
                  if v.name == "race_condition_validator")
        b2 = next(v for v in registry.bind_run_context(
                  registry.for_finding(_finding(), exchange), c2)
                  if v.name == "race_condition_validator")
        self.assertIsNot(b1, original)
        self.assertIsNot(b2, original)
        self.assertIs(b1.run_context, c1)
        self.assertIs(b2.run_context, c2)
        self.assertIsNone(original.run_context)


if __name__ == "__main__":
    unittest.main()
