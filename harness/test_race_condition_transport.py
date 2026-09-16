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
            self.assertEqual(result.status, "confirmed")
            self.assertEqual(ctx.budget.used, 3)
            self.assertEqual(len(fixture.httpd.received), 3)
            self.assertTrue(all(r["authorization"] == "Bearer racer"
                                for r in fixture.httpd.received))
        finally:
            fixture.close()

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
