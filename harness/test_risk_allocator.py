import unittest
from harness.risk_allocator import RiskScore, rank, allocate_retry_budget


class RiskScoreTests(unittest.TestCase):
    def test_expected_risk_is_probability_times_severity_weight(self):
        s = RiskScore(category="sqli", url="https://a.test/x", probability=0.8, severity="critical")
        self.assertAlmostEqual(s.expected_risk, 0.8)  # critical weight = 1.0

    def test_probability_clamped_to_0_1(self):
        s_high = RiskScore(category="c", url="u", probability=5.0, severity="high")
        s_low = RiskScore(category="c", url="u", probability=-2.0, severity="high")
        self.assertAlmostEqual(s_high.expected_risk, 0.75)
        self.assertAlmostEqual(s_low.expected_risk, 0.0)

    def test_unknown_severity_falls_back_to_info_weight_not_error(self):
        s = RiskScore(category="c", url="u", probability=1.0, severity="not_a_real_severity")
        s_info = RiskScore(category="c", url="u", probability=1.0, severity="info")
        self.assertAlmostEqual(s.expected_risk, s_info.expected_risk)


class RankTests(unittest.TestCase):
    def test_sorted_descending_by_expected_risk(self):
        scores = [
            RiskScore(category="a", url="u1", probability=0.2, severity="low"),
            RiskScore(category="b", url="u2", probability=0.9, severity="critical"),
            RiskScore(category="c", url="u3", probability=0.5, severity="medium"),
        ]
        ranked = rank(scores)
        self.assertEqual([s.category for s in ranked], ["b", "c", "a"])


class AllocateRetryBudgetTests(unittest.TestCase):
    def test_top_fraction_gets_more_rounds_than_the_rest(self):
        scores = [
            RiskScore(category=f"cat{i}", url=f"https://a.test/{i}",
                      probability=1.0 - (i * 0.1), severity="high")
            for i in range(10)
        ]
        budget = allocate_retry_budget(scores, max_rounds_top=5, max_rounds_rest=1, top_fraction=0.3)
        ranked = rank(scores)
        top_keys = [(s.category, s.url) for s in ranked[:3]]
        rest_keys = [(s.category, s.url) for s in ranked[3:]]
        self.assertTrue(all(budget[k] == 5 for k in top_keys))
        self.assertTrue(all(budget[k] == 1 for k in rest_keys))

    def test_empty_input_returns_empty_dict(self):
        self.assertEqual(allocate_retry_budget([]), {})

    def test_single_finding_still_gets_top_treatment(self):
        scores = [RiskScore(category="a", url="u", probability=0.9, severity="critical")]
        budget = allocate_retry_budget(scores, max_rounds_top=5, max_rounds_rest=1)
        self.assertEqual(budget[("a", "u")], 5)

    def test_every_finding_appears_exactly_once(self):
        scores = [RiskScore(category=f"c{i}", url=f"u{i}", probability=0.5, severity="medium") for i in range(7)]
        budget = allocate_retry_budget(scores)
        self.assertEqual(len(budget), 7)


class CostWeightedRankingTests(unittest.TestCase):
    def test_default_cost_of_one_reproduces_risk_only_ranking(self):
        scores = [
            RiskScore(category="a", url="u1", probability=0.9, severity="high"),
            RiskScore(category="b", url="u2", probability=0.3, severity="high"),
        ]
        ranked = rank(scores)
        self.assertEqual(ranked[0].category, "a")

    def test_expensive_finding_ranks_below_cheaper_equal_risk_finding(self):
        cheap = RiskScore(category="cheap", url="u1", probability=0.6, severity="high", cost=1.0)
        expensive = RiskScore(category="expensive", url="u2", probability=0.6, severity="high", cost=10.0)
        self.assertAlmostEqual(cheap.expected_risk, expensive.expected_risk)  # same risk
        ranked = rank([expensive, cheap])
        self.assertEqual(ranked[0].category, "cheap", "cheaper finding with equal risk should rank first by value_density")

    def test_high_risk_expensive_finding_can_still_outrank_low_risk_cheap_one(self):
        # value_density isn't "always prefer cheap" -- a high enough risk gap should still win.
        high_risk_expensive = RiskScore(category="a", url="u1", probability=0.95, severity="critical", cost=5.0)
        low_risk_cheap = RiskScore(category="b", url="u2", probability=0.1, severity="low", cost=1.0)
        ranked = rank([low_risk_cheap, high_risk_expensive])
        self.assertEqual(ranked[0].category, "a")

    def test_zero_cost_uses_neutral_fallback_not_absurd_density(self):
        """Zero cost should fall back to neutral cost (1.0), not create extreme density."""
        # A low-severity info finding with zero cost
        zero_cost_info = RiskScore(category="a", url="u", probability=0.5, severity="info", cost=0.0)
        # Expected risk for info at 0.5 probability = 0.5 * 0.1 = 0.05
        # With neutral fallback cost of 1.0, value_density = 0.05 / 1.0 = 0.05
        self.assertAlmostEqual(zero_cost_info.value_density, 0.05, places=5)
        
        # A high-severity critical finding with normal cost
        normal_cost_critical = RiskScore(category="b", url="u", probability=0.5, severity="critical", cost=1.0)
        # Expected risk for critical at 0.5 probability = 0.5 * 1.0 = 0.5
        # value_density = 0.5 / 1.0 = 0.5
        self.assertAlmostEqual(normal_cost_critical.value_density, 0.5, places=5)
        
        # The zero-cost info finding should NOT outrank the normal-cost critical finding
        ranked = rank([zero_cost_info, normal_cost_critical])
        self.assertEqual(ranked[0].category, "b", 
                        "Normal-cost critical should outrank zero-cost info")

    def test_negative_cost_also_uses_neutral_fallback(self):
        """Negative cost should also fall back to neutral cost (1.0)."""
        neg_cost = RiskScore(category="a", url="u", probability=0.5, severity="high", cost=-1.0)
        # Expected risk = 0.5 * 0.75 = 0.375
        # With neutral fallback, value_density = 0.375 / 1.0 = 0.375
        self.assertAlmostEqual(neg_cost.value_density, 0.375, places=5)

    def test_zero_cost_does_not_divide_by_zero(self):
        """Legacy test: ensure no division by zero error."""
        s = RiskScore(category="a", url="u", probability=0.5, severity="high", cost=0.0)
        self.assertTrue(s.value_density > 0)  # must not raise ZeroDivisionError or be inf/nan
        # Additionally, verify it's a reasonable value (not absurdly large)
        self.assertLess(s.value_density, 10.0, 
                       "Zero-cost density should not be absurdly large")


if __name__ == "__main__":
    unittest.main()
