"""Actual overlapping captured analyze callers; no target/model service."""
import asyncio
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from harness import cache, store
from harness.effort import BudgetMode
from harness.models import HttpExchange
from harness.run_context import TargetTransport
from harness.test_smoke_phase0_capture_review import _build


class OverlapProvider:
    def __init__(self):
        self.calls = 0
        self.started = asyncio.Event()
        self.both = asyncio.Event()
        self.release = asyncio.Event()

    async def chat_json_metered(self, **kwargs):
        self.calls += 1
        self.started.set()
        if self.calls == 2:
            self.both.set()
        await self.release.wait()
        tokens = 10 if '/one' in kwargs['user_prompt'] else 30
        return SimpleNamespace(data={'findings': [], 'components': []},
                               prompt_tokens=tokens, completion_tokens=1)


class ActualRunInferenceOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def overlapping_calls(self, *, drop_binding=False):
        from contextlib import nullcontext
        from harness import run_inference
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(store, '_DB_PATH', Path(tmp) / 'state.db'), \
             patch.object(cache, '_cache', cache.ExchangeCache(db_path=str(Path(tmp) / 'cache.db'))):
            orch = _build()
            provider = OverlapProvider()
            orch.agent_manager.agents['csp'].ollama = provider
            orch.agent_manager._agent_semaphore = asyncio.Semaphore(2)
            orch.effort_budget.mode = BudgetMode.HARD
            orch.effort_budget.total_tokens = 4000
            with patch.object(TargetTransport, 'execute', new_callable=AsyncMock,
                              side_effect=AssertionError('target forbidden')), \
                 patch.object(httpx.AsyncClient, 'request', side_effect=AssertionError('raw I/O forbidden')), \
                 patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
                 patch.object(socket.socket, 'connect', side_effect=AssertionError('connect forbidden')), \
                 (patch.object(run_inference, 'current', return_value=None) if drop_binding else nullcontext()):
                tasks = [asyncio.create_task(orch.analyze(
                    HttpExchange(url='http://localhost/' + name, method='GET',
                                 response_status=200, response_body='ordinary'),
                    force_agents=['csp'], bypass_cache=True)) for name in ('one', 'two')]
                try:
                    await asyncio.wait_for(provider.both.wait(), 5)
                    provider.release.set()
                    results = await asyncio.gather(*tasks)
                finally:
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
            summaries = [store.ledger_events_for(record.run_id) for record in orch.effort_budget.ledger.records
                         if record.run_id]
            return orch, results, summaries

    async def test_same_orchestrator_overlapping_root_calls_have_distinct_usage(self):
        orch, results, summaries = await self.overlapping_calls()
        self.assertEqual([r.effort_spent_tokens for r in results], [11, 31])
        self.assertEqual(orch.effort_budget.spent, 42)
        self.assertEqual(len(orch.effort_budget.ledger.records), 2)
        self.assertEqual(len({r.run_id for r in orch.effort_budget.ledger.records}), 2)
        self.assertEqual(orch.effort_budget._reserved, 0)
        self.assertEqual(sorted(row['data']['known_tokens'] for events in summaries for row in events
                                if row['event_type'] == 'run_summary'), [11, 31])

    async def test_dropped_binding_recreates_cross_run_contamination(self):
        orch, results, _ = await self.overlapping_calls(drop_binding=True)
        self.assertNotEqual([r.effort_spent_tokens for r in results], [11, 31])
        self.assertEqual([r.effort_spent_tokens for r in results], [42, 42])
        self.assertEqual(orch.effort_budget.spent, 42)

    async def one_orchestrator(self, action):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(store, '_DB_PATH', Path(tmp) / 'state.db'), \
             patch.object(cache, '_cache', cache.ExchangeCache(db_path=str(Path(tmp) / 'cache.db'))):
            orch = _build()
            provider = OverlapProvider()
            orch.agent_manager.agents['csp'].ollama = provider
            orch.agent_manager._agent_semaphore = asyncio.Semaphore(2)
            with patch.object(TargetTransport, 'execute', new_callable=AsyncMock,
                              side_effect=AssertionError('target forbidden')), \
                 patch.object(httpx.AsyncClient, 'request', side_effect=AssertionError('raw I/O forbidden')), \
                 patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
                 patch.object(socket.socket, 'connect', side_effect=AssertionError('connect forbidden')):
                await action(orch, provider)

    @staticmethod
    def call(orch, path, **kwargs):
        return orch.analyze(HttpExchange(url='http://localhost/' + path, method='GET',
                                        response_status=200, response_body='ordinary'),
                            force_agents=['csp'], bypass_cache=True, **kwargs)

    async def test_aggregate_hard_cap_is_not_reset_per_root_call(self):
        async def action(orch, provider):
            orch.effort_budget.mode = BudgetMode.HARD
            orch.effort_budget.total_tokens = 1600
            first = asyncio.create_task(self.call(orch, 'one'))
            try:
                await asyncio.wait_for(provider.started.wait(), 5)
                second = await self.call(orch, 'two')
                self.assertEqual(provider.calls, 1)
                self.assertEqual(second.effort_spent_tokens, 0)
                self.assertTrue(any(r.raw_error for r in second.agent_reports))
                provider.release.set()
                result = await first
                self.assertEqual(result.effort_spent_tokens, 11)
                self.assertEqual(orch.effort_budget.spent, 11)
                self.assertEqual(orch.effort_budget._reserved, 0)
            finally:
                if not first.done():
                    first.cancel()
                await asyncio.gather(first, return_exceptions=True)
        await self.one_orchestrator(action)

    async def test_explicit_same_context_retains_its_owner_across_calls(self):
        from harness.run_context import RunContext
        async def action(orch, provider):
            ctx = RunContext.create(allowed_hosts=orch.allowed_hosts, config=orch.config)
            provider.release.set()
            first = await self.call(orch, 'one', run_context=ctx)
            owner = ctx._inference_owners[orch._inference_owner_id]
            second = await self.call(orch, 'two', run_context=ctx)
            self.assertIs(owner, ctx._inference_owners[orch._inference_owner_id])
            self.assertEqual((first.effort_spent_tokens, second.effort_spent_tokens), (11, 42))
            self.assertEqual(owner.budget.spent, 42)
            self.assertEqual(len(owner.budget.ledger.records), 2)
            self.assertTrue(all(r.run_id == ctx.run_id for r in owner.budget.ledger.records))
            self.assertEqual(orch.effort_budget.spent, 42)
            await ctx.aclose()
        await self.one_orchestrator(action)

    async def test_cancellation_releases_aggregate_and_restores_context(self):
        from harness import run_inference
        async def action(orch, provider):
            aggregate = orch.effort_budget
            task = asyncio.create_task(self.call(orch, 'one'))
            await asyncio.wait_for(provider.started.wait(), 5)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertIs(orch.effort_budget, aggregate)
            self.assertIsNone(run_inference.current(orch))
            self.assertEqual(aggregate._reserved, 0)
            self.assertEqual(aggregate.spent, 0)
            self.assertEqual(len(aggregate.ledger.records), 1)
            self.assertEqual(aggregate.ledger.records[0].outcome, 'cancelled')
        await self.one_orchestrator(action)
