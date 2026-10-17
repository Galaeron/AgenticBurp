"""R07 benign caller controls. No target sends or active confirmation."""
import asyncio
import unittest
from types import SimpleNamespace

from harness.agent_manager import AgentManager
from harness.agents.base_agent import BaseAgent
from harness.analysis_pipeline import AnalysisPipeline
from harness.effort import BudgetMode, EffortBudget
from harness.models import HttpExchange
from harness.ollama_client import OllamaError


class OrdinaryAgent(BaseAgent):
    specialty_prompt = "Describe an ordinary captured HTTP response."

    def __init__(self, provider, name):
        super().__init__(provider, "synthetic-model")
        self.name = name


class FakeProvider:
    def __init__(self, *, fail=False, wait=False):
        self.calls = 0
        self.unmetered_calls = 0
        self.fail = fail
        self.wait = wait
        self.started = asyncio.Event()
        self.finish = asyncio.Event()

    async def chat_json_metered(self, **kwargs):
        self.calls += 1
        self.started.set()
        if self.wait:
            await self.finish.wait()
        else:
            await asyncio.sleep(0)
        if self.fail:
            raise OllamaError("Synthetic connection failure")
        return SimpleNamespace(data={"findings": []}, prompt_tokens=20, completion_tokens=5)

    async def chat_json(self, **kwargs):
        self.unmetered_calls += 1
        return {"findings": []}


def manager_for(provider, routing="agents", names=("cors", "csp")):
    # Real manager dispatch methods; omit registration of unrelated specialists.
    manager = AgentManager.__new__(AgentManager)
    manager.routing_mode = routing
    manager._agent_semaphore = None
    manager.agents = {name: OrdinaryAgent(provider, name) for name in names}
    return manager


def pipeline_for(manager, budget, provider):
    return AnalysisPipeline(manager, budget, None,
                            {"critique": {"enabled": False}}, ollama_client=provider)


class PassiveBudgetCallerTests(unittest.IsolatedAsyncioTestCase):
    exchange = HttpExchange(url="https://ordinary.invalid/status", method="GET",
                            response_status=200, response_body="Service is available")

    async def call_pipeline(self, manager, budget, provider):
        return await pipeline_for(manager, budget, provider).run_full_analysis(
            self.exchange, list(manager.agents), "", 6000)

    async def test_pipeline_records_every_specialist_call(self):
        provider = FakeProvider()
        manager = manager_for(provider)
        budget = EffortBudget(BudgetMode.HARD, total_tokens=4000)
        reports, _, _, _ = await self.call_pipeline(manager, budget, provider)
        self.assertEqual(provider.calls, 2)
        self.assertEqual(provider.unmetered_calls, 0)
        self.assertEqual(len(budget.ledger.records), 2)
        self.assertEqual(budget.spent, 50)
        self.assertEqual(budget._reserved, 0)
        self.assertTrue(all(not r.raw_error and not r.findings for r in reports))

    async def test_pipeline_accounts_family_once_and_solo_fallback(self):
        provider = FakeProvider()
        manager = manager_for(provider, "families", ("cors", "csp", "ordinary_custom"))
        budget = EffortBudget(BudgetMode.HARD, total_tokens=4000)
        reports, _, _, _ = await self.call_pipeline(manager, budget, provider)
        self.assertEqual({r.agent for r in reports}, {"family:config_headers", "ordinary_custom"})
        self.assertEqual(provider.calls, 2)
        self.assertEqual(provider.unmetered_calls, 0)
        self.assertEqual(budget.spent, 50)
        self.assertEqual(len(budget.ledger.records), 2)
        self.assertEqual(budget._reserved, 0)

    async def test_concurrent_admission_rejects_second_estimate(self):
        provider = FakeProvider(wait=True)
        manager = manager_for(provider)
        budget = EffortBudget(BudgetMode.HARD, total_tokens=1600)
        task = asyncio.create_task(self.call_pipeline(manager, budget, provider))
        await provider.started.wait()
        await asyncio.sleep(0)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(budget._reserved, 1600)
        provider.finish.set()
        reports, _, _, _ = await task
        self.assertEqual(sum(r.raw_error is not None for r in reports), 1)
        self.assertEqual(budget.spent, 25)
        self.assertEqual(budget._reserved, 0)

    async def test_separate_runs_share_manager_without_sharing_budget(self):
        provider = FakeProvider()
        manager = manager_for(provider)
        first, second = EffortBudget(BudgetMode.HARD), EffortBudget(BudgetMode.HARD)
        await asyncio.gather(self.call_pipeline(manager, first, provider),
                             self.call_pipeline(manager, second, provider))
        self.assertEqual((first.spent, second.spent), (50, 50))
        self.assertEqual((len(first.ledger.records), len(second.ledger.records)), (2, 2))
        self.assertFalse(hasattr(manager, "_effort_budget"))

    async def test_failed_provider_releases_without_inventing_tokens(self):
        provider = FakeProvider(fail=True)
        manager = manager_for(provider)
        budget = EffortBudget(BudgetMode.HARD)
        reports, _, _, _ = await self.call_pipeline(manager, budget, provider)
        self.assertEqual(provider.calls, 2)
        self.assertTrue(all(r.raw_error and not r.findings for r in reports))
        self.assertEqual(budget.spent, 0)
        self.assertEqual(budget._reserved, 0)
        self.assertEqual(len(budget.ledger.records), 2)
        self.assertTrue(all(r.total_tokens is None and r.outcome == "error"
                            and not r.completed for r in budget.ledger.records))

    async def test_cancelled_caller_releases_reservations(self):
        provider = FakeProvider(wait=True)
        manager = manager_for(provider)
        budget = EffortBudget(BudgetMode.HARD)
        task = asyncio.create_task(self.call_pipeline(manager, budget, provider))
        await provider.started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(budget.spent, 0)
        self.assertEqual(budget._reserved, 0)

    async def test_missing_budget_is_explicitly_unmetered(self):
        provider = FakeProvider()
        manager = manager_for(provider)
        with self.assertLogs("harness.passive_inference", level="WARNING") as logged:
            reports = await manager.run_multiple_agents(list(manager.agents), self.exchange)
        self.assertEqual(provider.calls, 0)
        self.assertEqual(provider.unmetered_calls, 2)
        self.assertIn("unmetered", logged.output[0])
        self.assertTrue(all(not r.raw_error for r in reports))

    async def test_budget_drop_defect_is_detected_by_caller_control(self):
        provider = FakeProvider()
        manager = manager_for(provider)
        original = manager.run_multiple_agents

        async def dropped(names, exchange, max_body_chars, prior_context, effort_budget):
            return await original(names, exchange, max_body_chars, prior_context)

        manager.run_multiple_agents = dropped
        budget = EffortBudget(BudgetMode.HARD)
        with self.assertLogs("harness.passive_inference", level="WARNING"):
            await self.call_pipeline(manager, budget, provider)
        self.assertEqual(provider.calls, 0)
        self.assertEqual(provider.unmetered_calls, 2)
        self.assertEqual(budget.spent, 0)
        self.assertNotEqual(len(budget.ledger.records), 2)
