"""Tests for F5 per-vulnerability resource governance."""
import unittest

import harness.resource_governor as rg
from harness.effort import EffortBudget, EffortLedger, BudgetMode, CallKind


def _cand(id, vc, sev, conf=0.5, url="https://t.test/x", priority=None):
    return rg.AllocationCandidate(id=id, vulnerability_class=vc, url=url,
                                  severity=sev, confidence=conf, priority=priority)


class PolicyTests(unittest.TestCase):
    def test_from_dict_defaults_and_cap(self):
        p = rg.VulnBudgetPolicy.from_dict({"max_retries": 5, "max_tokens_per_vuln": 10000})
        self.assertEqual(p.max_retries, 5)
        self.assertEqual(p.max_passes, 6)
        self.assertEqual(p.max_tokens_per_vuln, 10000)

    def test_from_dict_zero_cap_is_none(self):
        # 0 / falsy means "no per-vuln cap", not "cap of zero".
        p = rg.VulnBudgetPolicy.from_dict({"max_tokens_per_vuln": 0})
        self.assertIsNone(p.max_tokens_per_vuln)

    def test_merged_with_overrides_only_provided(self):
        p = rg.VulnBudgetPolicy(max_retries=2, max_agents=3)
        m = p.merged_with({"max_retries": 9, "max_agents": None})
        self.assertEqual(m.max_retries, 9)
        self.assertEqual(m.max_agents, 3)  # None override ignored
        self.assertEqual(p.max_retries, 2)  # original unchanged


class PerVulnSpendTests(unittest.TestCase):
    def test_retry_cap_stops_loop(self):
        s = rg.PerVulnSpend(policy=rg.VulnBudgetPolicy(max_retries=1, max_agents=99))
        ok, _ = s.can_start_round()
        self.assertTrue(ok)
        s.record_round(agents_run=1, tokens_spent=100)  # pass 1
        ok, _ = s.can_start_round()
        self.assertTrue(ok)
        s.record_round(agents_run=1, tokens_spent=100)  # pass 2 (the 1 retry)
        ok, reason = s.can_start_round()
        self.assertFalse(ok)
        self.assertIn("retry cap", reason)

    def test_agent_cap_stops_loop(self):
        s = rg.PerVulnSpend(policy=rg.VulnBudgetPolicy(max_retries=99, max_agents=2))
        s.record_round(agents_run=2, tokens_spent=10)
        ok, reason = s.can_start_round(planned_agents=1)
        self.assertFalse(ok)
        self.assertIn("agent cap", reason)

    def test_per_vuln_token_cap_stops_loop(self):
        s = rg.PerVulnSpend(policy=rg.VulnBudgetPolicy(max_retries=99, max_agents=99,
                                                       max_tokens_per_vuln=500))
        s.record_round(agents_run=1, tokens_spent=600)
        ok, reason = s.can_start_round()
        self.assertFalse(ok)
        self.assertIn("token cap", reason)

    def test_stop_on_found(self):
        s = rg.PerVulnSpend(policy=rg.VulnBudgetPolicy(max_retries=99, max_agents=99))
        s.record_round(agents_run=1, tokens_spent=10, found=True)
        ok, reason = s.can_start_round()
        self.assertFalse(ok)
        self.assertIn("stop_on_found", reason)

    def test_global_budget_stops_loop(self):
        gb = EffortBudget(mode=BudgetMode.HARD, total_tokens=100)
        gb.record(CallKind.AGENT_DISPATCH, "m", 80, 40)  # 120 > 100 -> exhausted
        s = rg.PerVulnSpend(policy=rg.VulnBudgetPolicy(max_retries=99, max_agents=99), global_budget=gb)
        ok, reason = s.can_start_round()
        self.assertFalse(ok)
        self.assertIn("global budget", reason)

    def test_granted_tokens_subcap(self):
        s = rg.PerVulnSpend(policy=rg.VulnBudgetPolicy(max_retries=99, max_agents=99),
                            granted_tokens=300)
        s.record_round(agents_run=1, tokens_spent=350)
        ok, reason = s.can_start_round()
        self.assertFalse(ok)
        self.assertIn("token cap", reason)


class AllocationTests(unittest.TestCase):
    def setUp(self):
        self.policy = rg.VulnBudgetPolicy(max_retries=2, max_agents=3)  # 3 passes
        self.round_cost = 1000  # -> full cost = 3000 tokens/vuln

    def test_no_cap_everyone_full(self):
        cands = [_cand("a", "sqli", "high"), _cand("b", "xss", "low")]
        plan = rg.plan_allocation(cands, None, self.policy, self.round_cost)
        self.assertTrue(all(a.action == "full" for a in plan.allocations))
        self.assertEqual(plan.counts["full"], 2)

    def test_priority_orders_by_severity(self):
        cands = [_cand("low1", "xss", "low"), _cand("crit1", "rce", "critical"),
                 _cand("med1", "idor", "medium")]
        plan = rg.plan_allocation(cands, None, self.policy, self.round_cost)
        order = [a.candidate.severity for a in plan.allocations]
        self.assertEqual(order, ["critical", "medium", "low"])

    def test_tight_budget_defers_lowest_priority(self):
        # Budget for exactly one full vuln (3000). Two candidates; only the
        # higher-severity one is funded full, the other deferred.
        cands = [_cand("hi", "sqli", "critical"), _cand("lo", "xss", "low")]
        plan = rg.plan_allocation(cands, 3000, self.policy, self.round_cost)
        by_id = {a.candidate.id: a for a in plan.allocations}
        self.assertEqual(by_id["hi"].action, "full")
        self.assertEqual(by_id["lo"].action, "deferred")
        self.assertTrue(any("Deferred" in g for g in plan.guidance))

    def test_partial_budget_reduces(self):
        # 4000 tokens, full cost 3000: first vuln full (3000 left 1000),
        # second gets a reduced 1-pass (1000).
        cands = [_cand("hi", "sqli", "critical"), _cand("mid", "idor", "high")]
        plan = rg.plan_allocation(cands, 4000, self.policy, self.round_cost)
        by_id = {a.candidate.id: a for a in plan.allocations}
        self.assertEqual(by_id["hi"].action, "full")
        self.assertEqual(by_id["mid"].action, "reduced")
        self.assertEqual(by_id["mid"].granted_tokens, 1000)
        self.assertEqual(by_id["mid"].granted_retries, 0)

    def test_planned_tokens_never_exceeds_budget(self):
        cands = [_cand(str(i), "sqli", "high") for i in range(10)]
        plan = rg.plan_allocation(cands, 5500, self.policy, self.round_cost)
        self.assertLessEqual(plan.planned_tokens, 5500)

    def test_explicit_priority_overrides_severity(self):
        cands = [_cand("a", "xss", "low", priority=99.0), _cand("b", "rce", "critical", priority=1.0)]
        plan = rg.plan_allocation(cands, None, self.policy, self.round_cost)
        self.assertEqual(plan.allocations[0].candidate.id, "a")  # priority wins over severity

    def test_estimate_round_cost_uses_ledger(self):
        ledger = EffortLedger()
        ledger.record(CallKind.AGENT_DISPATCH, "m", 1000, 1000)  # 2000 observed
        ledger.record(CallKind.CRITIQUE, "m", 500, 500)          # 1000 observed
        cost = rg.estimate_round_cost(ledger, avg_agents_per_round=2.0, critique_fraction=0.5)
        self.assertEqual(cost, int(2 * 2000 + 0.5 * 1000))


if __name__ == "__main__":
    unittest.main()
