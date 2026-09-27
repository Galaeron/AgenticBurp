"""SC-7 (OFFLINE half) -- browser-plane gate/budget accounting.

`evaluate_browser_request` (harness/browser_driver.py) previously allowed a
same-origin non-GET subrequest with NO gate decision and NO budget accounting,
so browser-originated mutating traffic bypassed the single RunContext
capability/budget policy that `TargetTransport.execute` enforces for every
other outbound send (scope -> gate -> budget, run_context.py). These tests
drive `evaluate_browser_request` directly (pure, no Playwright, no browser)
and lock in the new opt-in `gate`/`budget` parameters:

  - a same-origin MUTATING subrequest is denied by default (active testing
    off) and does not reserve budget;
  - it is allowed and accounted for once active testing + mutating replay are
    both enabled;
  - an out-of-scope target is still blocked before the gate/budget are ever
    consulted (negative control) -- a blocked request never reserves budget;
  - a benign in-scope GET succeeds and IS accounted against the budget (GET
    still costs budget; it only skips the mutating-method gate);
  - budget exhaustion denies a further otherwise-allowed request;
  - with gate=None and budget=None (every caller before SC-7,
    `test_browser_interception_gate.py`'s negative control included) the
    function is byte-for-byte behavior-identical to before these two
    parameters existed.

The live-browser wiring/health/doctor half (actually passing a run's real
gate/budget into `PlaywrightDriver.visit` from a live RunContext) is OUT OF
SCOPE here -- this file only exercises the pure policy function.
"""
from __future__ import annotations

import re
import unittest

from harness.browser_driver import evaluate_browser_request
from harness.run_context import RequestBudget, ScopePolicy
from harness.safety_gate import SafetyGate, SafetyGateConfig

_SCOPE = ScopePolicy(allowed_hosts=frozenset({"app.example"}))
_RUN_ORIGIN = "http://app.example"


def _gate(active_enabled: bool = False, allow_mutating_replay: bool = False) -> SafetyGate:
    return SafetyGate(SafetyGateConfig.from_dict({
        "active_enabled": active_enabled,
        "allow_mutating_replay": allow_mutating_replay,
    }))


class TestBrowserBudgetGate(unittest.TestCase):
    def test_same_origin_mutation_gated_by_default(self):
        budget = RequestBudget(10)
        decision = evaluate_browser_request(
            url="http://app.example/x", method="POST", resource_type="fetch",
            is_navigation=False, run_origin=_RUN_ORIGIN, scope=_SCOPE,
            gate=_gate(), budget=budget)
        self.assertFalse(decision.allow)
        self.assertTrue(re.search(r"gate|mutating", decision.reason, re.IGNORECASE),
                         decision.reason)
        self.assertEqual(budget.used, 0, "a gate-denied request must not reserve budget")

    def test_same_origin_mutation_allowed_and_accounted_when_active(self):
        budget = RequestBudget(10)
        decision = evaluate_browser_request(
            url="http://app.example/x", method="POST", resource_type="fetch",
            is_navigation=False, run_origin=_RUN_ORIGIN, scope=_SCOPE,
            gate=_gate(active_enabled=True, allow_mutating_replay=True), budget=budget)
        self.assertTrue(decision.allow, decision.reason)
        self.assertEqual(budget.used, 1)

    def test_out_of_scope_navigation_blocked_before_gate_or_budget(self):
        budget = RequestBudget(10)
        decision = evaluate_browser_request(
            url="http://evil.example/x", method="GET", resource_type="document",
            is_navigation=True, run_origin=_RUN_ORIGIN, scope=_SCOPE,
            gate=_gate(active_enabled=True, allow_mutating_replay=True), budget=budget)
        self.assertFalse(decision.allow)
        self.assertEqual(budget.used, 0, "a scope-blocked request must not reserve budget")

    def test_benign_in_scope_get_succeeds_and_is_accounted(self):
        budget = RequestBudget(10)
        decision = evaluate_browser_request(
            url="http://app.example/page", method="GET", resource_type="document",
            is_navigation=True, run_origin=_RUN_ORIGIN, scope=_SCOPE,
            gate=_gate(), budget=budget)
        self.assertTrue(decision.allow, decision.reason)
        self.assertEqual(budget.used, 1)

    def test_budget_exhaustion_denies_a_further_otherwise_allowed_request(self):
        budget = RequestBudget(1)
        first = evaluate_browser_request(
            url="http://app.example/page", method="GET", resource_type="document",
            is_navigation=True, run_origin=_RUN_ORIGIN, scope=_SCOPE,
            gate=_gate(), budget=budget)
        self.assertTrue(first.allow, first.reason)
        self.assertEqual(budget.used, 1)

        second = evaluate_browser_request(
            url="http://app.example/page2", method="GET", resource_type="document",
            is_navigation=True, run_origin=_RUN_ORIGIN, scope=_SCOPE,
            gate=_gate(), budget=budget)
        self.assertFalse(second.allow)
        self.assertIn("budget", second.reason.lower())
        self.assertIn("exhausted", second.reason.lower())

    def test_behavior_preserving_when_gate_and_budget_are_both_none(self):
        decision = evaluate_browser_request(
            url="http://app.example/x", method="POST", resource_type="fetch",
            is_navigation=False, run_origin=_RUN_ORIGIN, scope=_SCOPE,
            gate=None, budget=None)
        self.assertTrue(decision.allow, decision.reason)
        self.assertTrue(decision.attach_credentials)


if __name__ == "__main__":
    unittest.main()
