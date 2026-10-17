"""R08 caller controls using benign responses and a no-network MockTransport."""
import asyncio
import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import httpx

from harness.effort import BudgetMode, CallKind, EffortBudget
from harness.ollama_client import OllamaClient, OllamaError, OllamaResult
from harness.passive_inference import metered_passive_call
from harness.provider_trace import traced_call
from harness.test_remediation_inference_budget import manager_for, pipeline_for


class Gate:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class RateGate(Gate):
    def __init__(self):
        self.usage = []

    def record_usage(self, prompt_tokens, completion_tokens):
        self.usage.append((prompt_tokens, completion_tokens))


class UsageCallerTests(unittest.IsolatedAsyncioTestCase):
    def client(self, handler):
        client = OllamaClient("http://provider.invalid")
        client.audit_logger = Mock()
        client.rate_limiter = RateGate()
        real_client = httpx.AsyncClient
        transport = httpx.MockTransport(handler)
        patcher = patch("harness.ollama_client.httpx.AsyncClient",
                        side_effect=lambda **kw: real_client(transport=transport, **kw))
        patcher.start()
        self.addCleanup(patcher.stop)
        breaker = patch("harness.ollama_client.circuit_breaker.current_ollama_breaker",
                        return_value=Gate())
        breaker.start()
        self.addCleanup(breaker.stop)
        return client

    @staticmethod
    def response(content='{"findings": []}', **usage):
        return httpx.Response(200, json={"message": {"content": content}, "done": True, **usage})

    async def call(self, client, budget):
        return await metered_passive_call(client, budget, model="synthetic-model",
                                         system_prompt="Describe ordinary response metadata.",
                                         user_prompt="HTTP 200 service available")

    async def test_malformed_provider_response_consumes_without_finding(self):
        secret = "synthetic-private-response-marker"
        client = self.client(lambda request: self.response(secret, prompt_eval_count=12, eval_count=7))
        budget = EffortBudget(BudgetMode.HARD)
        manager = manager_for(client, names=("cors",))
        from harness.models import HttpExchange
        reports, _, _, _ = await pipeline_for(manager, budget, client).run_full_analysis(
            HttpExchange(url="https://ordinary.invalid/status", method="GET"), ["cors"], "", 6000)
        self.assertTrue(reports[0].raw_error)
        self.assertEqual(reports[0].findings, [])
        self.assertEqual(budget.spent, 19)
        record = budget.ledger.records[0]
        self.assertTrue(record.completed)
        self.assertFalse(record.usable)
        self.assertEqual(record.outcome, "error")
        self.assertEqual(client.rate_limiter.usage, [(12, 7)])
        self.assertEqual((client.model_attempted_count, client.model_completed_count,
                          client.model_call_count, client.model_error_count), (1, 1, 0, 1))
        self.assertNotIn(secret, reports[0].raw_error)
        self.assertNotIn(secret, repr(client.audit_logger.log_llm_error.call_args_list))

    async def test_unknown_usage_remains_unknown_and_blocks_repeat_admission(self):
        client = self.client(lambda request: self.response())
        budget = EffortBudget(BudgetMode.HARD, total_tokens=1600)
        result = await self.call(client, budget)
        self.assertIsNone(result.prompt_tokens)
        self.assertIsNone(result.completion_tokens)
        self.assertEqual(budget.spent, 0)
        self.assertEqual(budget.accounting()["unmeasured_admission_tokens"], 1600)
        self.assertFalse(budget.accounting()["usage_complete"])
        self.assertIsNone(budget.ledger.trace()[0]["total_tokens"])
        self.assertFalse(budget.ledger.has_real_data_for(CallKind.AGENT_DISPATCH))
        with self.assertRaises(OllamaError):
            await self.call(client, budget)
        self.assertEqual(client.model_attempted_count, 1)
        self.assertEqual(budget._reserved, 0)

    async def test_partial_usage_counts_only_known_lower_bound(self):
        client = self.client(lambda request: self.response(prompt_eval_count=40))
        budget = EffortBudget(BudgetMode.HARD, total_tokens=1600)
        await self.call(client, budget)
        self.assertEqual(budget.spent, 40)
        self.assertEqual(budget.accounting()["unmeasured_admission_tokens"], 1560)
        self.assertIsNone(budget.ledger.records[0].total_tokens)

    async def test_consumption_and_timing_reconcile_success_and_parse_failure(self):
        calls = []
        def handler(request):
            calls.append(request)
            return self.response('{"findings": []}' if len(calls) == 1 else "invalid",
                                 prompt_eval_count=20, eval_count=5, eval_duration=3_000_000)
        client = self.client(handler)
        budget = EffortBudget(BudgetMode.HARD)
        await self.call(client, budget)
        with self.assertRaises(OllamaError):
            await self.call(client, budget)
        self.assertEqual(budget.spent, 50)
        self.assertEqual(client.model_prompt_tokens + client.model_completion_tokens, 50)
        self.assertEqual(budget.accounting()["attempted_calls"], 2)
        self.assertEqual(budget.accounting()["completed_calls"], 2)
        self.assertEqual(budget.accounting()["usable_calls"], 1)
        for row in budget.ledger.trace():
            self.assertEqual(row["generation_ms"], 3.0)
            self.assertGreaterEqual(row["queue_ms"], 0)
            self.assertGreaterEqual(row["wall_ms"], row["queue_ms"])
            self.assertIsNone(row["connection_ms"])
            self.assertEqual(row["missing_timings"], ["connection_ms"])

    async def test_transport_failure_records_unknown_and_refunds(self):
        def handler(request):
            raise httpx.ConnectError("synthetic failure", request=request)
        client = self.client(handler)
        budget = EffortBudget(BudgetMode.HARD, total_tokens=1600)
        with self.assertRaises(OllamaError):
            await self.call(client, budget)
        self.assertEqual(budget.spent, 0)
        self.assertEqual(budget._reserved, 0)
        self.assertEqual(budget.accounting()["unmeasured_admission_tokens"], 0)
        self.assertEqual(budget.accounting()["completed_calls"], 0)
        self.assertIsNone(budget.ledger.records[0].total_tokens)

    async def test_cancelled_provider_call_has_distinct_trace(self):
        started = asyncio.Event()
        async def handler(request):
            started.set()
            await asyncio.Event().wait()
        client = self.client(handler)
        budget = EffortBudget(BudgetMode.HARD)
        task = asyncio.create_task(self.call(client, budget))
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(budget.accounting()["cancelled_calls"], 1)
        self.assertEqual(client.model_cancelled_count, 1)
        self.assertEqual(budget._reserved, 0)
        self.assertEqual(budget.spent, 0)

    async def test_provider_retry_records_each_attempt_without_double_count(self):
        calls = 0
        class Provider:
            async def chat_json(self, *args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    error = OllamaError("synthetic malformed output")
                    error.inference_usage = {"prompt_tokens": 15, "completion_tokens": 5,
                                             "completed": True, "usable": False}
                    raise error
                return OllamaResult({"findings": []}, 10, 3)
        budget = EffortBudget(BudgetMode.HARD)
        outcome = await traced_call(Provider(), budget, kind=CallKind.ROUTING, model="synthetic-model",
                                    system_prompt="ordinary", user_prompt="status", estimate=100,
                                    max_retries=1)
        self.assertTrue(outcome.ok)
        self.assertEqual(budget.spent, 33)
        self.assertEqual([r.total_tokens for r in budget.ledger.records], [20, 13])
        self.assertEqual([r.outcome for r in budget.ledger.records], ["error", "ok"])
        self.assertEqual(budget._reserved, 0)

    async def test_routing_and_critique_use_explicit_run_budget(self):
        from harness.coordinator import Coordinator
        from harness.models import AgentReport, Finding, HttpExchange
        client = self.client(lambda request: self.response(
            json.dumps({"dispatch": ["cors"], "reason": "ordinary headers", "reviews": []}),
            prompt_eval_count=20, eval_count=5))
        budget = EffortBudget(BudgetMode.HARD)
        exchange = HttpExchange(url="https://ordinary.invalid/status", method="GET")
        dispatch, _ = await Coordinator(client, {"coordinator": {"model": "synthetic-model"}}).choose_agents(
            exchange, ["cors"], effort_budget=budget)
        self.assertEqual(dispatch, ["cors"])
        pipeline = pipeline_for(manager_for(client), budget, client)
        pipeline.config.update({"critique": {"enabled": True}, "coordinator": {"model": "synthetic-model"}})
        report = AgentReport(agent="cors", model="synthetic-model", findings=[Finding(
            vulnerability_class="cors", confidence=0.6, summary="ordinary header observation",
            evidence="header exists", suggested_test="analyst review", basis="observed")])
        await pipeline._critique(exchange, [report])
        self.assertEqual([r.kind for r in budget.ledger.records], [CallKind.ROUTING, CallKind.CRITIQUE])
        self.assertEqual(budget.spent, 50)

    async def test_missing_instrumentation_defect_is_detected(self):
        client = self.client(lambda request: self.response("invalid", prompt_eval_count=12, eval_count=7))
        budget = EffortBudget(BudgetMode.HARD)
        original = client._chat
        async def drop_receipt(*args, **kwargs):
            try:
                return await original(*args, **kwargs)
            except OllamaError as exc:
                del exc.inference_usage
                raise
        client._chat = drop_receipt
        with self.assertRaises(OllamaError):
            await self.call(client, budget)
        self.assertEqual(client.model_prompt_tokens + client.model_completion_tokens, 19)
        self.assertNotEqual(budget.spent, 19)
        self.assertFalse(budget.ledger.usage_complete)

    async def test_real_rate_limiter_retains_unknown_marker_and_known_counts(self):
        from harness.rate_limiter import TokenRateLimiter, RateLimitConfig
        client = self.client(lambda request: self.response(prompt_eval_count=40))
        limiter = TokenRateLimiter(RateLimitConfig(enabled=False))
        client.rate_limiter = limiter
        budget = EffortBudget(BudgetMode.HARD)
        await self.call(client, budget)
        stats = limiter.get_stats()
        self.assertEqual(stats["recent_usage_60s"], 40)
        self.assertEqual(stats["unknown_usage_calls_60s"], 1)
        self.assertFalse(stats["usage_complete_60s"])
        limiter.reset()
        self.assertTrue(limiter.get_stats()["usage_complete_60s"])
        self.assertEqual(limiter.get_recent_usage(), 0)

    async def test_actual_analysis_exports_unknown_usage_in_status_and_summary(self):
        from harness import cache, store, evidence_ledger
        from harness.models import HttpExchange
        from harness.orchestrator import Orchestrator
        from harness.test_agent_concurrency import TestOrchestratorConcurrencyCaller
        client = self.client(lambda request: self.response(prompt_eval_count=40))
        with tempfile.TemporaryDirectory(prefix="r08_usage_exports_") as disposable:
            with patch.object(store, "_DB_PATH", Path(disposable) / "state.db"), patch.object(cache, "_cache", None):
                cache.init_cache(db_path=str(Path(disposable) / "cache.db"))
                config = TestOrchestratorConcurrencyCaller._config()
                orchestrator = Orchestrator(config)
                manager = manager_for(client, names=("cors",))
                orchestrator.agent_manager = manager
                orchestrator.analysis_pipeline.agent_manager = manager
                with patch.object(evidence_ledger, "emit") as emit:
                    response = await orchestrator.analyze(
                        HttpExchange(url="https://one.test/status", method="GET",
                                     response_status=200, response_body="ordinary service available"),
                        force_agents=["cors"], bypass_cache=True)
                self.assertFalse(response.agent_reports[0].findings)
                self.assertEqual(response.effort_spent_tokens, 40)
                self.assertIs(response.effort_usage_complete, False)
                status = orchestrator.effort_status().model_dump()
                self.assertEqual(status["spent_tokens"], 40)
                self.assertFalse(status["usage_complete"])
                self.assertTrue(status["tokens_lower_bound"])
                self.assertGreater(status["unmeasured_admission_tokens"], 0)
                summaries = [call for call in emit.call_args_list
                             if call.args[0] == evidence_ledger.EventType.RUN_SUMMARY]
                self.assertEqual(len(summaries), 1)
                summary = summaries[0].kwargs["data"]
                self.assertEqual(summary["tokens_total"], 40)
                self.assertFalse(summary["usage_complete"])
                self.assertTrue(summary["tokens_lower_bound"])
                self.assertIn("usage incomplete", summaries[0].args[2])

    async def test_actual_audit_response_preserves_nullable_counts(self):
        from harness.audit_logger import AuditLogger
        # Exercise the production audit caller with a sink spy; no host log file.
        logger = AuditLogger.__new__(AuditLogger)
        logger.log = Mock(return_value="synthetic-event")
        logger.log_llm_response("synthetic-model", "ordinary output", None, 5)
        data = logger.log.call_args.kwargs["data"]
        self.assertIsNone(data["prompt_tokens"])
        self.assertIsNone(data["total_tokens"])
        self.assertEqual(data["known_tokens"], 5)
        self.assertFalse(data["usage_complete"])
        self.assertNotIn("ordinary output", repr(data))
        logger.log_llm_response("synthetic-model", "ordinary output", 10, 5)
        data = logger.log.call_args.kwargs["data"]
        self.assertEqual(data["total_tokens"], 15)
        self.assertTrue(data["usage_complete"])
