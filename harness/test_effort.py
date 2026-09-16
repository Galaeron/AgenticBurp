import unittest
from harness.effort import (
    BudgetMode, CallKind, EffortLedger, EffortBudget,
    UrlEstimateInput, estimate_for_urls, _DEFAULT_TOKEN_ESTIMATE,
)


class EffortLedgerTests(unittest.TestCase):
    def test_average_falls_back_to_unmeasured_prior_before_any_real_call(self):
        ledger = EffortLedger()
        self.assertEqual(ledger.average_tokens(CallKind.AGENT_DISPATCH),
                          float(_DEFAULT_TOKEN_ESTIMATE[CallKind.AGENT_DISPATCH]))
        self.assertFalse(ledger.has_real_data_for(CallKind.AGENT_DISPATCH))

    def test_average_uses_real_calls_once_recorded(self):
        ledger = EffortLedger()
        ledger.record(CallKind.AGENT_DISPATCH, "llama3.1:8b", prompt_tokens=1000, completion_tokens=200)
        ledger.record(CallKind.AGENT_DISPATCH, "llama3.1:8b", prompt_tokens=1400, completion_tokens=400)
        self.assertTrue(ledger.has_real_data_for(CallKind.AGENT_DISPATCH))
        self.assertEqual(ledger.average_tokens(CallKind.AGENT_DISPATCH), (1200 + 1800) / 2)

    def test_breakdown_sums_by_kind(self):
        ledger = EffortLedger()
        ledger.record(CallKind.ROUTING, "m", 100, 50)
        ledger.record(CallKind.ROUTING, "m", 100, 50)
        ledger.record(CallKind.CRITIQUE, "m", 300, 100)
        b = ledger.breakdown()
        self.assertEqual(b["routing"], 300)
        self.assertEqual(b["critique"], 400)


class EffortBudgetTests(unittest.TestCase):
    def test_unlimited_budget_never_blocks(self):
        budget = EffortBudget(mode=BudgetMode.HARD, total_tokens=None)
        budget.record(CallKind.AGENT_DISPATCH, "m", 100000, 100000)
        allowed, reason = budget.allow()
        self.assertTrue(allowed)
        self.assertEqual(reason, "")

    def test_hard_mode_blocks_at_exhaustion_and_ignores_confirmation(self):
        budget = EffortBudget(mode=BudgetMode.HARD, total_tokens=100)
        budget.record(CallKind.AGENT_DISPATCH, "m", 80, 30)  # 110 > 100
        allowed, reason = budget.allow()
        self.assertFalse(allowed)
        self.assertIn("hard mode", reason)
        budget.confirm_overspend()  # must NOT unblock hard mode
        allowed2, _ = budget.allow()
        self.assertFalse(allowed2, "hard mode must not be talked past by confirm_overspend")

    def test_soft_mode_blocks_until_confirmed_then_allows(self):
        budget = EffortBudget(mode=BudgetMode.SOFT, total_tokens=100)
        budget.record(CallKind.AGENT_DISPATCH, "m", 80, 30)
        allowed, reason = budget.allow()
        self.assertFalse(allowed)
        self.assertIn("soft mode", reason)
        budget.confirm_overspend()
        allowed2, reason2 = budget.allow()
        self.assertTrue(allowed2)
        self.assertIn("operator confirmation", reason2)

    def test_remaining_and_exhausted(self):
        budget = EffortBudget(mode=BudgetMode.SOFT, total_tokens=1000)
        budget.record(CallKind.ROUTING, "m", 100, 100)
        self.assertEqual(budget.remaining, 800)
        self.assertFalse(budget.exhausted())
        budget.record(CallKind.ROUTING, "m", 500, 400)
        self.assertTrue(budget.exhausted())
        self.assertEqual(budget.remaining, 0)


class EstimateForUrlsTests(unittest.TestCase):
    def test_uses_unmeasured_priors_when_ledger_empty(self):
        result = estimate_for_urls([UrlEstimateInput(url="https://a.test/x")], EffortLedger())
        self.assertFalse(result["calibrated_from_real_calls"])
        self.assertGreater(result["estimated_total_tokens"], 0)

    def test_uses_real_calibration_once_ledger_has_data(self):
        ledger = EffortLedger()
        ledger.record(CallKind.AGENT_DISPATCH, "m", 100, 100)  # 200, far below the 1600 prior
        result = estimate_for_urls([UrlEstimateInput(url="https://a.test/x")], ledger)
        self.assertTrue(result["calibrated_from_real_calls"])
        # Should be meaningfully cheaper than the all-priors estimate, since
        # agent_dispatch dominates and is now calibrated far below its prior.
        baseline = estimate_for_urls([UrlEstimateInput(url="https://a.test/x")], EffortLedger())
        self.assertLess(result["estimated_total_tokens"], baseline["estimated_total_tokens"])

    def test_high_risk_urls_cost_more_than_low_risk(self):
        ledger = EffortLedger()
        high = estimate_for_urls([UrlEstimateInput(url="https://a.test/x", risk_score=0.9)], ledger)
        low = estimate_for_urls([UrlEstimateInput(url="https://a.test/y", risk_score=0.1)], ledger)
        self.assertGreater(high["estimated_total_tokens"], low["estimated_total_tokens"])

    def test_more_urls_cost_more_monotonically(self):
        ledger = EffortLedger()
        one = estimate_for_urls([UrlEstimateInput(url="https://a.test/1")], ledger)
        ten = estimate_for_urls([UrlEstimateInput(url=f"https://a.test/{i}") for i in range(10)], ledger)
        self.assertGreater(ten["estimated_total_tokens"], one["estimated_total_tokens"] * 5)

    def test_breakdown_sums_to_total(self):
        ledger = EffortLedger()
        urls = [UrlEstimateInput(url=f"https://a.test/{i}", risk_score=0.8 if i % 2 == 0 else 0.2) for i in range(6)]
        result = estimate_for_urls(urls, ledger)
        self.assertEqual(sum(result["breakdown"].values()), result["estimated_total_tokens"])

    def test_zero_urls_is_zero_cost_not_an_error(self):
        result = estimate_for_urls([], EffortLedger())
        self.assertEqual(result["estimated_total_tokens"], 0)
        self.assertEqual(result["urls_total"], 0)


if __name__ == "__main__":
    unittest.main()
