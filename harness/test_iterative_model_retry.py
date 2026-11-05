"""Model-failure retry in the iterative agent: a transient failure is retried in
the step, a 429 within its Retry-After, and an open Ollama breaker is waited out.

Measured motivation (job 0574e29a0799, r3): 28 of 44 iterative probes stopped on
ONE model error and lost every step they had taken; most were the shared breaker
fast-failing the call (2,130 of 3,097 calls never reached the model).

Caller level: the real IterativeAgent drives the real OllamaClient and its real
circuit breaker. The fake sits on the network boundary (httpx.AsyncClient.request):
`/api/chat` answers from a script, any other URL is the target. Both backoff
sleeps are patched out and recorded. The breaker registry is fresh per test. A
429 needs the rate-limit error the client is gaining (OllamaRateLimitedError);
until it lands, a stand-in with the same shape is raised from a scripted model.
The breaker wait needs CircuitBreaker.seconds_until_retry (PR #29); every test
pins it, absent unless the test sets it.

Controls: a persistent error still stops with "error" after one retry; an empty
reply, a non-transient error and a quota-length Retry-After are not retried; the
breaker is not waited out without seconds_until_retry, past the run's deadline,
on the last step, or in a cancelled run, and a breaker that stays open uses up
the step budget; with the retry patched away the recovery check fails;
`model_error_retries: 0` from config turns it off.
"""
from __future__ import annotations

import asyncio
import json
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
import yaml

from harness import circuit_breaker as cb
from harness import iterative_agent as ia
from harness import ollama_client as oc
from harness import safety_gate
from harness.circuit_breaker import CircuitState
from harness.effort import BudgetMode, EffortBudget
from harness.iterative_agent import IterativeAgent
from harness.models import HttpExchange
from harness.ollama_client import OllamaClient
from harness.orchestrator_confirm import ConfirmMixin
from harness.run_context import CancelToken, standalone_context

_CONFIG = Path(__file__).resolve().parent / "config.yaml"
_FINDING = {"vulnerability_class": "sqli", "confidence": 0.85, "severity": "high",
            "summary": "SQLi in q", "evidence": "db error", "suggested_test": "x",
            "basis": "derived"}
_MUTATE = {"action": "mutate", "location": "query", "param": "q", "value": "' OR '1'='1"}
_FOUND = {"action": "stop", "verdict": "found", "thought": "error surfaced", "finding": _FINDING}
_EMPTY = ""


class _RateLimitedStandIn(oc.OllamaTransientError):
    """OllamaClient's HTTP 429, until the client raises its own."""

    def __init__(self, message: str = "", *, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


_RateLimited = getattr(oc, "OllamaRateLimitedError", _RateLimitedStandIn)


class _Resp:
    def __init__(self, status, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class _Wire:
    """Fake network for both ends. A model step is a dict (HTTP 200 whose message
    content is that JSON), a str (HTTP 200 with that raw content; _EMPTY is an
    empty reply), an int (that HTTP status), or an exception to raise. The last
    step repeats once the script runs out. Any other URL is the target, which
    answers with a database error."""

    def __init__(self, *chat_steps):
        self.steps = list(chat_steps)
        self.chat_calls = 0
        self.target_sends = []

    async def request(self, method, url, headers=None, content=None, **kw):
        url = str(url)
        if not url.endswith("/api/chat"):
            self.target_sends.append((method, url))
            return _Resp(500, "SQL syntax error near 'OR'")
        step = self.steps[min(self.chat_calls, len(self.steps) - 1)]
        self.chat_calls += 1
        if isinstance(step, BaseException):
            raise step
        if isinstance(step, int):
            return httpx.Response(step, text="synthetic upstream body")
        text = step if isinstance(step, str) else json.dumps(step)
        return httpx.Response(200, json={"message": {"content": text}, "done": True,
                                         "prompt_eval_count": 5, "eval_count": 3})


class _ScriptedModel:
    """A model client for errors the real client cannot raise yet: each chat_json
    call returns the next action, or raises it when it is an exception."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.chat_calls = 0

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.2):
        step = self.steps[min(self.chat_calls, len(self.steps) - 1)]
        self.chat_calls += 1
        if isinstance(step, BaseException):
            raise step
        return step


class _OpenGate:
    """Stands in for the shared token rate limiter."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def record_usage(self, prompt_tokens, completion_tokens):
        pass


def _exchange():
    return HttpExchange(url="http://localhost:5002/api/search?q=widget", method="GET",
                        request_headers={"User-Agent": "x"}, request_body="",
                        response_status=200, response_body="results")


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()
        self.fresh_breakers()
        self.breaker_reports(None)
        self.client_delays: list[float] = []
        self.agent_delays: list[float] = []
        self.on_agent_sleep = None

        async def client_sleep(seconds):
            self.client_delays.append(seconds)

        async def agent_sleep(seconds, cancel=None):
            self.agent_delays.append(seconds)
            if self.on_agent_sleep is not None:
                self.on_agent_sleep(seconds)

        for p in (patch.object(oc, "_backoff_sleep", client_sleep),
                  patch.object(ia, "_backoff_sleep", agent_sleep)):
            p.start()
            self.addCleanup(p.stop)

    def fresh_breakers(self):
        previous = cb._registry
        cb._registry = None
        self.addCleanup(setattr, cb, "_registry", previous)

    def breaker_reports(self, seconds):
        """Pin CircuitBreaker.seconds_until_retry: None is a breaker without it."""
        p = patch.object(cb.CircuitBreaker, "seconds_until_retry",
                         None if seconds is None else (lambda _self: seconds), create=True)
        p.start()
        self.addCleanup(p.stop)

    def let_the_breaker_time_out_while_waiting(self):
        """Each agent wait ages the breaker past its timeout, as the real wait would."""
        def age(_seconds):
            breaker = self.breaker()
            breaker._last_state_change -= breaker.config.timeout_seconds
        self.on_agent_sleep = age

    @staticmethod
    def client(**kwargs) -> OllamaClient:
        # Built before any breaker read, so the shared breaker gets the client's
        # own config (its excluded exceptions), as in production.
        client = OllamaClient("http://fake-ollama:11434", **kwargs)
        client.rate_limiter = _OpenGate()
        client.audit_logger = Mock()
        return client

    @staticmethod
    def breaker():
        return cb.current_ollama_breaker("ollama")

    def open_the_breaker(self, client):
        cb._set_state(self.breaker(), CircuitState.OPEN, 3, 0, 0)
        return client

    async def probe(self, wire, client=None, effort_budget=None, step_budget=6, **agent_kwargs):
        agent = IterativeAgent(client or self.client(), "m", ["localhost"], **agent_kwargs)
        with patch("httpx.AsyncClient.request", wire.request):
            return await agent.run(_exchange(), "SQLi in q", "sqli", step_budget=step_budget,
                                   effort_budget=effort_budget)


class TransientFailureRecoveryTests(_Base):
    async def _check_one_failure_continues_to_the_verdict(self, failure, client=None,
                                                          effort_budget=None):
        # Step 1 sends a request; step 2's model call fails once and is retried
        # in place, and its answer is the verdict, with step 1 still on record.
        # Client transport retries off, so the fault reaches the agent as is.
        wire = _Wire(_MUTATE, failure, _FOUND)
        result = await self.probe(wire, client or self.client(transient_retries=0), effort_budget)
        self.assertEqual(result.stop_reason, "found", result.handoff_note)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.steps_used, 1)
        self.assertEqual(wire.chat_calls, 3, "step 1, step 2, the retry of step 2")
        self.assertEqual(len(wire.target_sends), 1)
        self.assertEqual([(s.n, s.response_status) for s in result.transcript],
                         [(1, 500), (2, None)])
        self.assertEqual(result.diagnostics["model_error_retries"], 1)
        self.assertEqual(result.to_dict()["diagnostics"]["model_error_retries"], 1)
        self.assertEqual(result.diagnostics["breaker_waits"], 0)
        self.assertEqual(self.agent_delays, [ia._MODEL_ERROR_BACKOFF_SECONDS])

    async def test_timeouts_connection_errors_and_5xx_are_retried(self):
        faults = {"http_500": 500, "http_503": 503,
                  "timeout": httpx.ReadTimeout("synthetic timeout"),
                  "connect": httpx.ConnectError("synthetic refused"),
                  "dropped": httpx.RemoteProtocolError("synthetic drop")}
        for name, fault in faults.items():
            with self.subTest(fault=name):
                self.fresh_breakers()
                self.agent_delays.clear()
                with self.assertLogs("harness.iterative_agent", level="WARNING") as logs:
                    await self._check_one_failure_continues_to_the_verdict(fault)
                self.assertTrue(any("OllamaTransientError" in line and "retry 1/1" in line
                                    for line in logs.output), logs.output)

    async def test_the_agent_retries_after_the_client_has_spent_its_own_retries(self):
        # Default client: three HTTP 503s exhaust ollama.transient_retries (2);
        # the agent's one retry is the fifth request and recovers.
        wire = _Wire(_MUTATE, 503, 503, 503, _FOUND)
        result = await self.probe(wire)
        self.assertEqual(result.stop_reason, "found", result.handoff_note)
        self.assertEqual(wire.chat_calls, 5)
        self.assertEqual(self.client_delays, [1.0, 2.0])
        self.assertEqual(self.agent_delays, [ia._MODEL_ERROR_BACKOFF_SECONDS])
        self.assertEqual(result.diagnostics["model_error_retries"], 1)
        stats = self.breaker().get_stats()
        self.assertEqual((stats.total_failures, stats.total_successes), (1, 2))

    async def test_the_metered_call_path_is_retried_too(self):
        await self._check_one_failure_continues_to_the_verdict(
            503, effort_budget=EffortBudget(mode=BudgetMode.HARD, total_tokens=1_000_000))

    async def test_control_recovery_needs_the_in_step_retry(self):
        with patch.object(IterativeAgent, "_retry_wait", lambda *a: None):
            with self.assertRaises(AssertionError):
                await self._check_one_failure_continues_to_the_verdict(503)


class RateLimitTests(_Base):
    async def test_a_429_is_retried_after_its_retry_after(self):
        model = _ScriptedModel(_MUTATE, _RateLimited("Ollama returned HTTP 429", retry_after=12.0),
                               _FOUND)
        result = await self.probe(_Wire(), model)
        self.assertEqual(result.stop_reason, "found", result.handoff_note)
        self.assertEqual(model.chat_calls, 3)
        self.assertEqual(self.agent_delays, [12.0], "the server's Retry-After, not the 2 s backoff")
        self.assertEqual(result.diagnostics["model_error_retries"], 1)

    async def test_a_429_without_retry_after_gets_the_backoff(self):
        model = _ScriptedModel(_MUTATE, _RateLimited("Ollama returned HTTP 429"), _FOUND)
        result = await self.probe(_Wire(), model)
        self.assertEqual(result.stop_reason, "found", result.handoff_note)
        self.assertEqual(self.agent_delays, [ia._MODEL_ERROR_BACKOFF_SECONDS])

    async def test_control_a_quota_length_retry_after_fails_the_probe_clearly(self):
        # Exhausted credits do not clear within the run: no wait, no retry.
        model = _ScriptedModel(_MUTATE, _RateLimited("Ollama returned HTTP 429", retry_after=3600.0),
                               _FOUND)
        result = await self.probe(_Wire(), model)
        self.assertEqual(result.stop_reason, "error")
        self.assertIn("LLM call failed at step 2", result.handoff_note)
        self.assertIn("quota or exhausted credits", result.handoff_note)
        self.assertEqual(model.chat_calls, 2)
        self.assertEqual(result.diagnostics["model_error_retries"], 0)
        self.assertEqual(self.agent_delays, [])

    async def test_control_a_retry_after_that_passes_the_deadline_is_not_waited(self):
        model = _ScriptedModel(_MUTATE, _RateLimited("Ollama returned HTTP 429", retry_after=20.0),
                               _FOUND)
        result = await self.probe(_Wire(), model, deadline=time.monotonic() + 10.0)
        self.assertEqual(result.stop_reason, "error")
        self.assertEqual(self.agent_delays, [])


class BreakerWaitTests(_Base):
    async def test_an_open_breaker_is_waited_out_and_the_probe_reaches_its_verdict(self):
        self.breaker_reports(40.0)
        self.let_the_breaker_time_out_while_waiting()
        client = self.open_the_breaker(self.client())
        wire = _Wire(_MUTATE, _FOUND)
        result = await self.probe(wire, client)
        self.assertEqual(result.stop_reason, "found", result.handoff_note)
        self.assertEqual(self.agent_delays, [40.0])
        self.assertEqual(result.diagnostics["breaker_waits"], 1)
        self.assertEqual(result.diagnostics["model_error_retries"], 0)
        self.assertEqual(wire.chat_calls, 2, "step 1 was refused by the breaker, not sent")
        self.assertEqual([(s.n, s.response_status) for s in result.transcript],
                         [(2, 500), (3, None)], "the wait took step 1's place")

    async def test_a_failure_that_opens_the_breaker_is_waited_out_not_retried_at_once(self):
        self.breaker_reports(60.0)
        self.let_the_breaker_time_out_while_waiting()
        client = self.client(transient_retries=0)
        breaker = self.breaker()
        breaker._consecutive_failures = 2  # this call's 503 is the third
        wire = _Wire(503, _FOUND)
        result = await self.probe(wire, client)
        self.assertEqual(result.stop_reason, "found", result.handoff_note)
        self.assertEqual(wire.chat_calls, 2)
        self.assertEqual(result.diagnostics["model_error_retries"], 0)
        self.assertEqual(result.diagnostics["breaker_waits"], 1)
        self.assertEqual(self.agent_delays, [60.0])

    async def test_a_breaker_with_no_time_left_still_gets_the_backoff(self):
        # A HALF_OPEN breaker refuses calls past its trial slot with 0 s to go.
        self.breaker_reports(0.0)
        self.let_the_breaker_time_out_while_waiting()
        result = await self.probe(_Wire(_FOUND), self.open_the_breaker(self.client()))
        self.assertEqual(result.stop_reason, "found", result.handoff_note)
        self.assertEqual(self.agent_delays, [ia._MODEL_ERROR_BACKOFF_SECONDS])

    async def test_control_a_breaker_that_stays_open_uses_up_the_step_budget(self):
        self.breaker_reports(40.0)
        wire = _Wire(_FOUND)
        result = await self.probe(wire, self.open_the_breaker(self.client()), step_budget=4)
        self.assertEqual(result.stop_reason, "error")
        self.assertIn("LLM call failed at step 4", result.handoff_note)
        self.assertIn("is OPEN", result.handoff_note)
        self.assertEqual(result.diagnostics["breaker_waits"], 3, "steps 1-3 waited; step 4 has none after it")
        self.assertEqual(wire.chat_calls, 0)

    async def test_control_without_seconds_until_retry_an_open_breaker_fails_fast(self):
        wire = _Wire(_FOUND)
        result = await self.probe(wire, self.open_the_breaker(self.client()))
        self.assertEqual(result.stop_reason, "error")
        self.assertIn("LLM call failed at step 1", result.handoff_note)
        self.assertIn("is OPEN", result.handoff_note)
        self.assertEqual(wire.chat_calls, 0, "the breaker refused the call; nothing reached Ollama")
        self.assertEqual(result.diagnostics["breaker_waits"], 0)
        self.assertEqual(self.agent_delays, [])

    async def test_control_no_wait_runs_past_the_run_deadline(self):
        self.breaker_reports(40.0)
        result = await self.probe(_Wire(_FOUND), self.open_the_breaker(self.client()),
                                  deadline=time.monotonic() + 30.0)
        self.assertEqual(result.stop_reason, "error")
        self.assertEqual(result.diagnostics["breaker_waits"], 0)
        self.assertEqual(self.agent_delays, [])

    async def test_control_a_cancelled_run_does_not_wait(self):
        self.breaker_reports(40.0)
        ctx = standalone_context(["localhost"], max_requests=5)
        ctx.cancel.cancel()
        try:
            result = await self.probe(_Wire(_FOUND), self.open_the_breaker(self.client()),
                                      run_context=ctx)
        finally:
            await ctx.aclose()
        self.assertEqual(result.stop_reason, "error")
        self.assertEqual(result.diagnostics["breaker_waits"], 0)

    async def test_control_a_non_transient_error_is_not_waited_out_under_an_open_breaker(self):
        # The breaker is open from other calls; this call's own fault is permanent.
        self.breaker_reports(40.0)
        self.open_the_breaker(self.client())
        model = _ScriptedModel(oc.OllamaModelNotFoundError("Model 'm' not found"), _FOUND)
        result = await self.probe(_Wire(), model)
        self.assertEqual(result.stop_reason, "error")
        self.assertEqual(result.diagnostics["breaker_waits"], 0)


class RetryBoundaryControls(_Base):
    async def test_a_persistent_error_still_stops_with_error_after_one_retry(self):
        wire = _Wire(_MUTATE, 503)
        result = await self.probe(wire, self.client(transient_retries=0))
        self.assertEqual(result.stop_reason, "error")
        self.assertIn("LLM call failed at step 2", result.handoff_note)
        self.assertIn("HTTP 503", result.handoff_note)
        self.assertEqual(wire.chat_calls, 3, "step 1, step 2, one retry of step 2")
        self.assertEqual(result.diagnostics["model_error_retries"], 1)
        self.assertEqual(len(wire.target_sends), 1, "the step taken before the error is kept")

    async def test_an_empty_reply_is_not_retried(self):
        # Same prompt, same context window: the reply comes back empty again.
        wire = _Wire(_MUTATE, _EMPTY, _FOUND)
        result = await self.probe(wire)
        self.assertEqual(result.stop_reason, "error")
        self.assertIn("empty message body", result.handoff_note)
        self.assertEqual(wire.chat_calls, 2)
        self.assertEqual(result.diagnostics["model_error_retries"], 0)
        self.assertEqual(self.agent_delays, [])

    async def test_a_non_transient_error_is_not_retried(self):
        for status in (404, 400):  # model not found; another 4xx
            with self.subTest(status=status):
                self.fresh_breakers()
                wire = _Wire(status, _FOUND)
                result = await self.probe(wire)
                self.assertEqual(result.stop_reason, "error")
                self.assertEqual(wire.chat_calls, 1)
                self.assertEqual(result.diagnostics["model_error_retries"], 0)
        self.assertEqual(self.agent_delays, [])

    async def test_invalid_json_stays_a_parse_error_step_not_a_retry(self):
        wire = _Wire("not json at all", _FOUND)
        result = await self.probe(wire)
        self.assertEqual(result.stop_reason, "found")
        self.assertEqual(result.diagnostics["parse_errors"], 1)
        self.assertEqual(result.diagnostics["model_error_retries"], 0)
        self.assertEqual(self.agent_delays, [])

    async def test_the_retry_count_is_bounded_and_zero_turns_it_off(self):
        self.assertEqual(IterativeAgent(None, "m", []).model_error_retries, 1)
        self.assertEqual(IterativeAgent(None, "m", [], model_error_retries=None).model_error_retries, 1)
        self.assertEqual(IterativeAgent(None, "m", [], model_error_retries=-2).model_error_retries, 0)
        self.assertEqual(IterativeAgent(None, "m", [], model_error_retries=10 ** 6).model_error_retries,
                         ia._MAX_MODEL_ERROR_RETRIES)
        wire = _Wire(503, _FOUND)
        result = await self.probe(wire, self.client(transient_retries=0), model_error_retries=0)
        self.assertEqual(result.stop_reason, "error")
        self.assertEqual(wire.chat_calls, 1)

    async def test_a_cancelled_run_is_not_retried(self):
        ctx = standalone_context(["localhost"], max_requests=5)
        ctx.cancel.cancel()
        wire = _Wire(503, _FOUND)
        try:
            result = await self.probe(wire, self.client(transient_retries=0), run_context=ctx)
        finally:
            await ctx.aclose()
        self.assertEqual(result.stop_reason, "error")
        self.assertEqual(wire.chat_calls, 1)

    async def test_an_effort_budget_that_refuses_more_spend_is_not_retried(self):
        # The step was admitted; by the time its call fails the budget is spent.
        budget = Mock()
        budget.allow.side_effect = [(True, ""), (False, "duration limit reached")]
        wire = _Wire(503, _FOUND)
        result = await self.probe(wire, self.client(transient_retries=0), effort_budget=budget)
        self.assertEqual(result.stop_reason, "error")
        self.assertEqual(wire.chat_calls, 1)
        self.assertEqual(result.diagnostics["model_error_retries"], 0)


class CancellableWaitTests(unittest.IsolatedAsyncioTestCase):
    async def test_the_wait_ends_when_the_run_is_cancelled(self):
        cancel = CancelToken()
        loop = asyncio.get_running_loop()
        loop.call_later(0.05, cancel.cancel)
        started = time.monotonic()
        await ia._backoff_sleep(30.0, cancel)
        self.assertLess(time.monotonic() - started, 5.0)

    async def test_control_an_uncancelled_wait_runs_its_length(self):
        started = time.monotonic()
        await ia._backoff_sleep(0.2, CancelToken())
        self.assertGreaterEqual(time.monotonic() - started, 0.19)


class _ProbeHost(ConfirmMixin):
    """Just enough orchestrator surface for ConfirmMixin.run_active_probe."""

    def __init__(self, config, ollama):
        self.config = config
        self.allowed_hosts = ["localhost"]
        self.ollama = ollama
        self.iterative_agent_enabled = True
        self.iterative_agent_max_steps = 6
        self.effort_budget = None

    def reasoning_model(self):
        return "m"


class ConfiguredRetryThroughRunActiveProbeTests(_Base):
    async def _probe_via_orchestrator(self, iterative_agent_cfg, **probe_kwargs):
        wire = _Wire(_MUTATE, 503, _FOUND)
        host = _ProbeHost({"iterative_agent": iterative_agent_cfg}, self.client(transient_retries=0))
        with patch("httpx.AsyncClient.request", wire.request), patch(
                "harness.pivot_memory.integrate",
                AsyncMock(return_value=SimpleNamespace(to_dict=lambda: {}))):
            out = await host.run_active_probe(_exchange(), "SQLi in q", "sqli", step_budget=6,
                                              **probe_kwargs)
        return out["iterative_result"]

    async def test_the_committed_default_recovers_through_run_active_probe(self):
        committed = yaml.safe_load(_CONFIG.read_text(encoding="utf-8"))["iterative_agent"]
        self.assertEqual(committed["model_error_retries"], ia.DEFAULT_MODEL_ERROR_RETRIES)
        result = await self._probe_via_orchestrator(committed)
        self.assertEqual(result["stop_reason"], "found", result["handoff_note"])
        self.assertEqual(result["diagnostics"]["model_error_retries"], 1)

    async def test_control_config_zero_turns_the_retry_off_through_run_active_probe(self):
        result = await self._probe_via_orchestrator({"model_error_retries": 0})
        self.assertEqual(result["stop_reason"], "error")
        self.assertEqual(result["diagnostics"]["model_error_retries"], 0)

    async def test_control_the_run_deadline_reaches_the_agent(self):
        result = await self._probe_via_orchestrator({}, deadline=time.monotonic() + 1.0)
        self.assertEqual(result["stop_reason"], "error", "a 2 s backoff would end past the deadline")
        self.assertEqual(result["diagnostics"]["model_error_retries"], 0)


if __name__ == "__main__":
    unittest.main()
