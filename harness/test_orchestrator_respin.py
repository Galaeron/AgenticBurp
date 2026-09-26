"""Focused tests for the orchestrator's adaptive re-spin GATING logic.

The full Orchestrator is expensive to construct (agents, DB, ollama), so
these exercise the two pure-ish methods -- _has_actionable_finding and
_maybe_adaptive_respin -- by calling them unbound against a lightweight
stand-in `self`. That keeps the important control flow (default-off, cloud
gate, actionable short-circuit, budget bound, max_rounds bound) under test
without a live model.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from harness.orchestrator import Orchestrator
from harness.models import HttpExchange, AgentReport, Finding, StageOutcome
from harness.effort import EffortBudget, BudgetMode, CallKind


def _finding(conf):
    return Finding(
        vulnerability_class="business_logic", confidence=conf, severity="medium",
        summary="s", evidence="e", suggested_test="t", basis="derived",
    )


def _report(confs):
    return AgentReport(agent="a", model="m", findings=[_finding(c) for c in confs])


def _exchange():
    return HttpExchange(url="https://shop.test/api/checkout", method="POST", response_status=200)


class HasActionableFindingTests(unittest.TestCase):
    def _self(self, threshold=0.4):
        return SimpleNamespace(adaptive_respin_min_confidence=threshold)

    def test_true_when_a_finding_meets_threshold(self):
        s = self._self(0.4)
        self.assertTrue(Orchestrator._has_actionable_finding(s, [_report([0.1, 0.5])]))

    def test_false_when_all_below_threshold(self):
        s = self._self(0.4)
        self.assertFalse(Orchestrator._has_actionable_finding(s, [_report([0.1, 0.3])]))

    def test_false_on_no_findings(self):
        s = self._self(0.4)
        self.assertFalse(Orchestrator._has_actionable_finding(s, [_report([])]))


class MaybeAdaptiveRespinTests(unittest.IsolatedAsyncioTestCase):
    def _self(self, *, enabled, cloud_primary, budget=None, suggest=None, round_reports=None):
        coordinator = SimpleNamespace(
            cloud_primary=cloud_primary,
            cloud_model="gemma4:31b-cloud",
            suggest_followup_agents=AsyncMock(
                return_value=(suggest if suggest is not None else [], "r", 10, 2)
            ),
        )
        pipeline = SimpleNamespace(
            # 4-tuple (reports, n_reviewed, n_rejected, critique_outcome) since
            # R08/PR-7 added the typed StageOutcome return -- see
            # AnalysisPipeline.run_full_analysis.
            run_full_analysis=AsyncMock(
                return_value=(round_reports if round_reports is not None else [], 0, 0,
                              StageOutcome(name="critique", status="completed"))
            )
        )
        s = SimpleNamespace(
            adaptive_respin_enabled=enabled,
            adaptive_respin_max_rounds=1,
            adaptive_respin_min_confidence=0.4,
            coordinator=coordinator,
            analysis_pipeline=pipeline,
            agent_manager=SimpleNamespace(
                get_enabled_agents=lambda: ["sqli", "xss", "idor", "business_logic"]
            ),
            effort_budget=budget or EffortBudget(mode=BudgetMode.SOFT, total_tokens=None),
            max_body_chars=6000,
        )
        # Bind the real helper the method under test calls on self.
        s._has_actionable_finding = lambda reports: Orchestrator._has_actionable_finding(s, reports)
        return s

    async def test_noop_when_disabled(self):
        s = self._self(enabled=False, cloud_primary=True, suggest=["business_logic"])
        out = await Orchestrator._maybe_adaptive_respin(s, _exchange(), [], ["sqli"], "")
        self.assertEqual(out, [])
        s.coordinator.suggest_followup_agents.assert_not_awaited()

    async def test_noop_when_not_cloud_primary(self):
        s = self._self(enabled=True, cloud_primary=False, suggest=["business_logic"])
        out = await Orchestrator._maybe_adaptive_respin(s, _exchange(), [], ["sqli"], "")
        self.assertEqual(out, [])
        s.coordinator.suggest_followup_agents.assert_not_awaited()

    async def test_noop_when_first_pass_already_actionable(self):
        s = self._self(enabled=True, cloud_primary=True, suggest=["business_logic"])
        reports = [_report([0.9])]  # actionable
        out = await Orchestrator._maybe_adaptive_respin(s, _exchange(), reports, ["sqli"], "")
        self.assertEqual(out, [])
        s.coordinator.suggest_followup_agents.assert_not_awaited()

    async def test_dispatches_suggested_agent_and_records_escalation(self):
        extra = [_report([0.8])]
        s = self._self(enabled=True, cloud_primary=True,
                       suggest=["business_logic"], round_reports=extra)
        out = await Orchestrator._maybe_adaptive_respin(s, _exchange(), [_report([0.1])], ["sqli"], "")
        self.assertEqual(out, extra)
        s.analysis_pipeline.run_full_analysis.assert_awaited_once()
        # Escalation token cost recorded against the ledger.
        self.assertEqual(s.effort_budget.ledger.breakdown().get(CallKind.ESCALATION.value), 12)

    async def test_stops_when_budget_exhausted(self):
        budget = EffortBudget(mode=BudgetMode.HARD, total_tokens=5)
        budget.record(CallKind.AGENT_DISPATCH, "m", 5, 0)  # already at cap
        s = self._self(enabled=True, cloud_primary=True,
                       suggest=["business_logic"], budget=budget)
        out = await Orchestrator._maybe_adaptive_respin(s, _exchange(), [_report([0.1])], ["sqli"], "")
        self.assertEqual(out, [])
        s.coordinator.suggest_followup_agents.assert_not_awaited()

    async def test_stops_when_no_followup_suggested(self):
        s = self._self(enabled=True, cloud_primary=True, suggest=[])
        out = await Orchestrator._maybe_adaptive_respin(s, _exchange(), [_report([0.1])], ["sqli"], "")
        self.assertEqual(out, [])
        s.analysis_pipeline.run_full_analysis.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
