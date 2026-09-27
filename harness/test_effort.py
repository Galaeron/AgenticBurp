import threading
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


class _FakeClock:
    """Deterministic, test-controlled stand-in for time.monotonic --
    starts at 0 and only advances when the test tells it to. No real
    sleeps anywhere in these tests."""
    def __init__(self):
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class EffortBudgetDurationTests(unittest.TestCase):
    def test_hard_mode_blocks_past_deadline_and_ignores_confirmation(self):
        clock = _FakeClock()
        budget = EffortBudget(mode=BudgetMode.HARD, max_duration_s=10, clock=clock)
        budget.record(CallKind.AGENT_DISPATCH, "m", 10, 10)  # deadline set at t=0 -> 10
        clock.advance(11)
        allowed, reason = budget.allow()
        self.assertFalse(allowed)
        self.assertIn("duration limit", reason)
        budget.confirm_overspend()  # must NOT unblock hard mode
        allowed2, _ = budget.allow()
        self.assertFalse(allowed2, "hard mode duration limit must not be talked past by confirm_overspend")

    def test_soft_mode_blocks_past_deadline_until_confirmed_then_allows(self):
        clock = _FakeClock()
        budget = EffortBudget(mode=BudgetMode.SOFT, max_duration_s=10, clock=clock)
        budget.record(CallKind.AGENT_DISPATCH, "m", 10, 10)
        clock.advance(11)
        allowed, reason = budget.allow()
        self.assertFalse(allowed)
        self.assertIn("soft mode", reason)
        self.assertIn("duration limit", reason)
        budget.confirm_overspend()
        allowed2, reason2 = budget.allow()
        self.assertTrue(allowed2)
        self.assertIn("operator confirmation", reason2)

    def test_no_duration_limit_is_behaviorally_identical_to_today(self):
        clock = _FakeClock()
        budget = EffortBudget(mode=BudgetMode.HARD, max_duration_s=None, clock=clock)
        budget.record(CallKind.AGENT_DISPATCH, "m", 10, 10)
        clock.advance(10_000_000)  # arbitrarily far past any plausible deadline
        allowed, reason = budget.allow()
        self.assertTrue(allowed)
        self.assertEqual(reason, "")

    def test_allow_true_before_deadline_reached(self):
        clock = _FakeClock()
        budget = EffortBudget(mode=BudgetMode.HARD, max_duration_s=10, clock=clock)
        budget.record(CallKind.AGENT_DISPATCH, "m", 10, 10)  # deadline at t=10
        clock.advance(5)  # still before the deadline
        allowed, reason = budget.allow()
        self.assertEqual((allowed, reason), (True, ""))

    def test_deadline_set_at_construction_not_first_spend(self):
        """
        SC-8 contract inversion, not a weakening: the test this replaces
        (test_deadline_set_on_first_spend_not_construction) asserted the
        PRE-SC-8 contract -- that the deadline armed only on the first
        record(), so an idle budget with max_duration_s set could never
        expire from time alone before any work was dispatched. SC-8
        deliberately inverts that: __post_init__ now sets the deadline at
        construction, so a budget is live (and can expire) from the
        moment it exists. This is harder-not-looser (a stalled/idle
        dispatcher can no longer sit past its wall-clock budget
        unnoticed), so the old assertion (allowed, reason) == (True, "")
        with no record() call is now REQUIRED to fail once time passes
        the deadline -- which is what this test checks.
        """
        clock = _FakeClock()
        budget = EffortBudget(mode=BudgetMode.HARD, max_duration_s=10, clock=clock)
        clock.advance(11)  # past the deadline set at construction (t=0 -> 10)
        # record() never called -- construction alone must be enough to arm it.
        allowed, reason = budget.allow()
        self.assertFalse(allowed)
        self.assertIn("duration limit", reason)

    def test_reserve_blocks_past_construction_deadline(self):
        """reserve() must observe the same construction-time deadline as
        allow() -- an idle, never-recorded budget still blocks a
        reservation once real time passes it."""
        clock = _FakeClock()
        budget = EffortBudget(mode=BudgetMode.HARD, max_duration_s=10, clock=clock)
        clock.advance(11)
        ok, reason = budget.reserve(1)
        self.assertFalse(ok)
        self.assertIn("duration limit", reason)


class EffortBudgetReservationTests(unittest.TestCase):
    """SC-8: atomic reservation primitive (reserve/commit/release) on top
    of EffortBudget. allow()/record() are untouched by this class's
    subject matter and are exercised elsewhere; these tests only cover
    the additive reserve/commit/release surface."""

    def test_concurrent_reservations_are_serialized_and_exact(self):
        """
        Deterministic via a barrier, not timing: all 10 threads call
        reserve(1) at effectively the same instant against a
        total_tokens=3 HARD budget. Without a lock serializing
        check-then-increment, multiple threads could all observe
        spent(0) + _reserved(0) < 3 and all succeed, jointly overshooting
        the budget -- the exact race SC-8 closes. With the lock,
        reservation k is admitted only while spent(0) + _reserved(k-1) < 3
        (k = 1, 2, 3), so exactly 3 of the 10 succeed, deterministically,
        every run.
        """
        budget = EffortBudget(mode=BudgetMode.HARD, total_tokens=3)
        barrier = threading.Barrier(10)
        results: list[bool] = []
        results_lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            ok, _ = budget.reserve(1)
            with results_lock:
                results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sum(1 for ok in results if ok), 3)
        self.assertEqual(budget._reserved, 3)

    def test_reserve_commit_matches_bare_record_of_actuals(self):
        """A reserve() -> commit() pair must leave the ledger identical to
        a bare record() of the actuals, and must return _reserved to 0."""
        budget = EffortBudget(mode=BudgetMode.HARD, total_tokens=1000)
        ok, _ = budget.reserve(1600)
        self.assertTrue(ok)
        budget.commit(CallKind.AGENT_DISPATCH, "m", 100, 100, reserved=1600)
        self.assertEqual(budget.spent, 200)
        self.assertEqual(budget._reserved, 0)
        self.assertEqual(budget.remaining, 1000 - 200)

        twin = EffortBudget(mode=BudgetMode.HARD, total_tokens=1000)
        twin.record(CallKind.AGENT_DISPATCH, "m", 100, 100)
        self.assertEqual(budget.allow(), twin.allow())
        self.assertEqual(budget.spent, twin.spent)

    def test_reserve_then_release_leaves_no_trace(self):
        """release() is a full refund for a failed/aborted call -- no
        ledger write, and _reserved returns to 0."""
        budget = EffortBudget(mode=BudgetMode.HARD, total_tokens=1000)
        ok, _ = budget.reserve(500)
        self.assertTrue(ok)
        budget.release(500)
        self.assertEqual(budget.spent, 0)
        self.assertEqual(budget._reserved, 0)


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
