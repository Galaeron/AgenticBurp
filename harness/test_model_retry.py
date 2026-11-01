"""E6: bounded transient model-call retry, failure-rate breaker, the escalation
model fallback and the investigate probe cap.

Measured motivation (job 383f0ebff8e8): 24 of 126 critique calls hit an Ollama
HTTP 500 and none was retried, so each shipped its findings unreviewed; the
3-consecutive-failure breaker never tripped because the failures were never
consecutive.

Everything here is no-network: a scripted ``httpx.MockTransport`` stands in for
Ollama, the backoff sleep is patched out, and the server tests use the same
fake-orchestrator TestClient fixtures the other server tests use.

Negative controls follow one pattern: the check is written once as a helper,
the real test runs it, and the ``test_control_*`` twin patches the fix away
IN-PROCESS and asserts the same check now FAILS.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
import yaml

from harness import active_verification
from harness import circuit_breaker as cb
from harness import ollama_client as oc
from harness import store
from harness.circuit_breaker import (
    CircuitBreaker, CircuitBreakerConfig, CircuitOpenError, CircuitState, OllamaCircuitBreaker,
)
from harness.ollama_client import (
    OllamaClient, OllamaError, OllamaInvalidJSONError, OllamaModelNotFoundError, OllamaTransientError,
)

_REAL_ASYNC_CLIENT = httpx.AsyncClient
_WORKTREE = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# Fake Ollama
# --------------------------------------------------------------------------
class Wire:
    """Scripted fake Ollama. Each step answers one HTTP request; the last step
    repeats once the script runs out. A step is an int (HTTP status with a stub
    body), "ok", "badjson", "empty", a dict (200 whose message content is that
    JSON), or a callable(request) returning the httpx exception to raise."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        step = self.steps[min(self.calls, len(self.steps) - 1)]
        self.calls += 1
        if callable(step):
            raise step(request)
        content = None
        if step == "ok":
            content = json.dumps({"ok": True})
        elif step == "badjson":
            content = "this is not json"
        elif step == "empty":
            content = ""
        elif isinstance(step, dict):
            content = json.dumps(step)
        if content is not None:
            return httpx.Response(200, json={"message": {"content": content}, "done": True,
                                             "prompt_eval_count": 5, "eval_count": 3})
        return httpx.Response(step, text="synthetic upstream body")


class _CountingGate:
    """Stands in for the shared token rate limiter: counts entries."""

    def __init__(self):
        self.entered = 0

    async def __aenter__(self):
        self.entered += 1
        return self

    async def __aexit__(self, *exc):
        return False

    def record_usage(self, prompt_tokens, completion_tokens):
        pass


class RetryTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # A fresh shared breaker registry per test (no state leaks in or out).
        previous = cb._registry
        cb._registry = None
        self.addCleanup(setattr, cb, "_registry", previous)
        self.delays: list[float] = []

        async def recorded_sleep(seconds):
            self.delays.append(seconds)

        sleep = patch.object(oc, "_backoff_sleep", recorded_sleep)
        sleep.start()
        self.addCleanup(sleep.stop)

    def client(self, wire, **kwargs) -> OllamaClient:
        client = OllamaClient("http://fake-ollama:11434", **kwargs)
        client.rate_limiter = _CountingGate()
        client.audit_logger = Mock()
        transport = httpx.MockTransport(wire)
        route = patch("harness.ollama_client.httpx.AsyncClient",
                      side_effect=lambda **kw: _REAL_ASYNC_CLIENT(transport=transport, **kw))
        route.start()
        self.addCleanup(route.stop)
        return client

    @staticmethod
    def breaker() -> OllamaCircuitBreaker:
        return cb.current_ollama_breaker("ollama")

    async def call(self, client):
        return await client.chat_json("m", "system text", "user text")


# --------------------------------------------------------------------------
# 1. Bounded transient retry in OllamaClient
# --------------------------------------------------------------------------
class TransientRetryTests(RetryTestBase):
    async def _check_500_then_200_recovers(self):
        wire = Wire(500, "ok")
        client = self.client(wire)
        with self.assertLogs("harness.ollama_client", level="WARNING") as logs:
            result = await self.call(client)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(wire.calls, 2)
        self.assertEqual(self.delays, [1.0])
        # Each retry is visible: counters and a log line.
        self.assertEqual((client.model_retry_count, client.model_retry_recovered_count), (1, 1))
        self.assertTrue(any("retry 1/2 in 1.0s" in line for line in logs.output), logs.output)
        # The logical call is one attempt / one usable result / no error.
        self.assertEqual((client.model_attempted_count, client.model_call_count,
                          client.model_error_count), (1, 1, 0))
        # A recovered retry is a breaker SUCCESS, not a failure.
        stats = self.breaker().get_stats()
        self.assertEqual((stats.total_failures, stats.total_successes, stats.consecutive_failures),
                         (0, 1, 0))
        self.assertTrue(self.breaker().is_closed)
        # Each attempt is audited and re-enters the rate limiter.
        self.assertEqual(client.audit_logger.log_llm_error.call_count, 1)
        self.assertEqual(client.audit_logger.log_llm_prompt.call_count, 2)
        self.assertEqual(client.audit_logger.log_llm_response.call_count, 1)
        self.assertEqual(client.rate_limiter.entered, 2)

    async def test_500_then_200_retries_once_and_records_no_breaker_failure(self):
        await self._check_500_then_200_recovers()

    async def test_control_recovery_needs_the_transient_classification(self):
        with patch.object(oc, "_is_transient_status", lambda code: False):
            with self.assertRaises((AssertionError, OllamaError)):
                await self._check_500_then_200_recovers()

    async def _check_exhausted_retries_fail_once(self):
        wire = Wire(500)
        client = self.client(wire)
        with self.assertRaises(OllamaError) as caught:
            await self.call(client)
        self.assertEqual(str(caught.exception), "Ollama returned HTTP 500")
        self.assertEqual(wire.calls, 3, "1 attempt + exactly 2 retries")
        self.assertEqual(self.delays, [1.0, 2.0])
        self.assertEqual((client.model_retry_count, client.model_retry_recovered_count), (2, 0))
        self.assertEqual((client.model_attempted_count, client.model_call_count,
                          client.model_error_count), (1, 0, 1))
        # Exactly ONE breaker failure for the whole call.
        stats = self.breaker().get_stats()
        self.assertEqual((stats.total_failures, stats.total_successes, stats.consecutive_failures),
                         (1, 0, 1))
        self.assertTrue(self.breaker().is_closed)
        self.assertEqual(client.audit_logger.log_llm_error.call_count, 3)
        self.assertEqual(client.audit_logger.log_llm_prompt.call_count, 3)

    async def test_500_500_500_raises_after_three_attempts_with_one_breaker_failure(self):
        await self._check_exhausted_retries_fail_once()

    async def test_control_retries_are_bounded_by_the_retry_budget(self):
        # Emulate "no bound" (capped at 6 only so the control terminates).
        with patch.object(OllamaClient, "_may_retry", lambda self, done: done < 6):
            with self.assertRaises(AssertionError):
                await self._check_exhausted_retries_fail_once()

    async def test_configured_retry_count_is_clamped_to_a_hard_ceiling(self):
        self.assertEqual(OllamaClient("http://x").transient_retries, 2)
        self.assertEqual(OllamaClient("http://x", transient_retries=None).transient_retries, 2)
        self.assertEqual(OllamaClient("http://x", transient_retries=-3).transient_retries, 0)
        self.assertEqual(OllamaClient("http://x", transient_retries=10 ** 6).transient_retries, 5)

    async def _check_huge_config_value_still_stops(self):
        wire = Wire(500)
        client = self.client(wire, transient_retries=10 ** 6)
        with self.assertRaises(OllamaError):
            await self.call(client)
        self.assertEqual(wire.calls, 6)
        self.assertEqual(self.delays, [1.0, 2.0, 4.0, 8.0, 8.0])

    async def test_a_huge_configured_retry_count_still_stops(self):
        await self._check_huge_config_value_still_stops()

    async def test_control_clamp_removed_would_retry_far_longer(self):
        with patch.object(oc, "_MAX_TRANSIENT_RETRIES", 50):
            with self.assertRaises(AssertionError):
                await self._check_huge_config_value_still_stops()

    async def test_zero_retries_turns_retrying_off(self):
        wire = Wire(500, "ok")
        client = self.client(wire, transient_retries=0)
        with self.assertRaises(OllamaError):
            await self.call(client)
        self.assertEqual(wire.calls, 1)
        self.assertEqual(self.delays, [])
        self.assertEqual(client.model_retry_count, 0)

    async def _check_permanent_statuses_are_not_retried(self):
        for status, expected in ((404, OllamaModelNotFoundError), (400, OllamaError),
                                 (401, OllamaError), (422, OllamaError)):
            wire = Wire(status, "ok")
            client = self.client(wire)
            with self.assertRaises(expected) as caught:
                await self.call(client)
            self.assertNotIsInstance(caught.exception, OllamaTransientError, status)
            self.assertEqual(wire.calls, 1, f"HTTP {status} must not be retried")
            self.assertEqual(client.model_retry_count, 0)
        self.assertEqual(self.delays, [])

    async def test_404_and_other_4xx_are_not_retried(self):
        await self._check_permanent_statuses_are_not_retried()

    async def test_control_status_classification_decides_what_is_retried(self):
        with patch.object(oc, "_is_transient_status", lambda code: True):
            with self.assertRaises(AssertionError):
                await self._check_permanent_statuses_are_not_retried()

    async def test_404_still_does_not_touch_the_breaker(self):
        client = self.client(Wire(404))
        with self.assertRaises(OllamaModelNotFoundError):
            await self.call(client)
        self.assertEqual(self.breaker().get_stats().total_failures, 0)

    async def _check_invalid_json_and_empty_body_are_not_retried(self):
        for step, expected in (("badjson", OllamaInvalidJSONError), ("empty", OllamaError)):
            wire = Wire(step, "ok")
            client = self.client(wire)
            with self.assertRaises(expected):
                await self.call(client)
            self.assertEqual(wire.calls, 1, step)
            self.assertEqual(client.model_retry_count, 0)

    async def test_invalid_json_and_empty_body_are_not_retried(self):
        await self._check_invalid_json_and_empty_body_are_not_retried()

    async def test_control_retrying_every_ollama_error_would_be_caught(self):
        # A naive "retry any OllamaError" loop: widen the caught type.
        with patch.object(oc, "OllamaTransientError", OllamaError):
            with self.assertRaises(AssertionError):
                await self._check_invalid_json_and_empty_body_are_not_retried()

    async def _check_transport_faults_and_gateway_statuses_recover(self):
        faults = {
            "connect": lambda r: httpx.ConnectError("synthetic refused", request=r),
            "timeout": lambda r: httpx.ReadTimeout("synthetic timeout", request=r),
            "protocol": lambda r: httpx.RemoteProtocolError("synthetic closed", request=r),
            "502": 502, "503": 503, "504": 504,
        }
        for name, fault in faults.items():
            wire = Wire(fault, "ok")
            client = self.client(wire)
            self.assertEqual(await self.call(client), {"ok": True}, name)
            self.assertEqual((wire.calls, client.model_retry_count,
                              client.model_retry_recovered_count), (2, 1, 1), name)
        # When they keep failing the caller still sees an OllamaError, never a
        # raw httpx exception, after exactly 3 attempts (2 for a timeout,
        # which gets at most MAX_TIMEOUT_RETRIES retry).
        for name, fault in faults.items():
            cb.reset_ollama_circuit_breaker()  # each failing call is a breaker failure
            wire = Wire(fault)
            client = self.client(wire)
            with self.assertRaises(OllamaError) as caught:
                await self.call(client)
            self.assertIsInstance(caught.exception, OllamaTransientError, name)
            self.assertEqual(wire.calls, 2 if name == "timeout" else 3, name)

    async def test_timeouts_connection_faults_and_gateway_statuses_are_transient(self):
        await self._check_transport_faults_and_gateway_statuses_recover()

    # -- timeouts get at most one retry -------------------------------------
    async def _check_timeouts_are_retried_once(self):
        timeout = lambda r: httpx.ReadTimeout("synthetic timeout", request=r)
        wire = Wire(timeout, timeout, "ok")
        client = self.client(wire)
        with self.assertRaises(OllamaTransientError) as caught:
            await self.call(client)
        self.assertTrue(caught.exception.timeout)
        self.assertEqual((wire.calls, client.model_retry_count), (2, 1))
        # A non-timeout fault does not use up the timeout allowance.
        cb.reset_ollama_circuit_breaker()
        wire = Wire(500, timeout, "ok")
        client = self.client(wire)
        self.assertEqual(await self.call(client), {"ok": True})
        self.assertEqual((wire.calls, client.model_retry_recovered_count), (3, 1))

    async def test_a_second_timeout_is_not_retried(self):
        await self._check_timeouts_are_retried_once()

    async def test_control_without_the_timeout_cap_the_second_timeout_is_retried(self):
        with patch.object(oc, "MAX_TIMEOUT_RETRIES", 2):
            with self.assertRaises(AssertionError):
                await self._check_timeouts_are_retried_once()

    async def test_control_no_retry_means_transport_faults_are_not_recovered(self):
        with patch.object(OllamaClient, "_may_retry", lambda self, done: False):
            with self.assertRaises((AssertionError, OllamaError)):
                await self._check_transport_faults_and_gateway_statuses_recover()

    # -- cancellation ------------------------------------------------------
    async def _check_cancel_during_backoff_makes_no_further_attempt(self):
        wire = Wire(500, "ok")
        client = self.client(wire)
        waiting = asyncio.Event()

        async def hanging_sleep(seconds):
            waiting.set()
            await asyncio.Event().wait()

        with patch.object(oc, "_backoff_sleep", hanging_sleep):
            task = asyncio.create_task(self.call(client))
            await waiting.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(wire.calls, 1, "no attempt after the cancellation")
        self.assertEqual((client.model_retry_count, client.model_retry_recovered_count), (0, 0))
        self.assertEqual((client.model_cancelled_count, client.model_error_count), (1, 0))

    async def test_cancellation_during_backoff_stops_retrying(self):
        await self._check_cancel_during_backoff_makes_no_further_attempt()

    async def test_control_a_loop_that_swallows_cancellation_is_caught(self):
        waiting_holder = {}

        async def swallowing_sleep(seconds):
            waiting_holder["event"].set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                pass

        # The legacy shape: sleep eats the cancel and the retry gate ignores it.
        wire = Wire(500, "ok")
        client = self.client(wire)
        waiting_holder["event"] = asyncio.Event()
        with patch.object(oc, "_backoff_sleep", swallowing_sleep), \
                patch.object(OllamaClient, "_may_retry",
                             lambda self, done: done < self.transient_retries):
            task = asyncio.create_task(self.call(client))
            await waiting_holder["event"].wait()
            task.cancel()
            with self.assertRaises(AssertionError):
                with self.assertRaises(asyncio.CancelledError):
                    await task
        self.assertEqual(wire.calls, 2, "the control really did retry after the cancel")

    async def _check_cancellation_during_the_request_is_not_retried(self):
        started = asyncio.Event()
        calls = []

        async def handler(request):
            calls.append(1)
            if len(calls) == 1:
                started.set()
                await asyncio.Event().wait()  # first request hangs until cancelled
            return httpx.Response(200, json={"message": {"content": json.dumps({"ok": True})}, "done": True})

        client = self.client(handler)
        task = asyncio.create_task(self.call(client))
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(len(calls), 1)
        self.assertEqual((client.model_retry_count, client.model_cancelled_count), (0, 1))

    async def test_cancellation_during_the_request_is_not_retried(self):
        await self._check_cancellation_during_the_request_is_not_retried()

    async def test_control_treating_a_cancel_as_transient_would_retry_it(self):
        real_send = OllamaClient._send_once

        async def cancel_as_transient(self, *args, **kwargs):
            try:
                return await real_send(self, *args, **kwargs)
            except asyncio.CancelledError:
                raise OllamaTransientError("synthetic: cancel misclassified as transient")

        with patch.object(OllamaClient, "_send_once", cancel_as_transient), \
                patch.object(oc, "_cancellation_requested", lambda: False):
            with self.assertRaises(AssertionError):
                await self._check_cancellation_during_the_request_is_not_retried()

    async def _check_pending_cancellation_blocks_the_retry(self):
        calls = []
        holder = {}

        def handler(request):
            calls.append(1)
            if len(calls) == 1:
                holder["task"].cancel()  # the cancel lands with the 500
            return httpx.Response(500, text="x")

        client = self.client(handler)
        task = asyncio.create_task(self.call(client))
        holder["task"] = task
        try:
            await task
        except (OllamaError, asyncio.CancelledError):
            pass
        self.assertEqual(len(calls), 1, "a cancelled caller must not get a retry")
        self.assertEqual(client.model_retry_count, 0)

    async def test_a_cancel_racing_the_failure_blocks_the_retry(self):
        await self._check_pending_cancellation_blocks_the_retry()

    async def test_control_retry_gate_that_ignores_cancellation_is_caught(self):
        with patch.object(oc, "_cancellation_requested", lambda: False):
            with self.assertRaises(AssertionError):
                await self._check_pending_cancellation_blocks_the_retry()


# --------------------------------------------------------------------------
# 2. Failure-rate breaker
# --------------------------------------------------------------------------
class FailureRateBreakerTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def config(**overrides):
        base = dict(failure_threshold=3, success_threshold=2, timeout_seconds=60.0,
                    half_open_max_requests=1, window_size=20, failure_rate_threshold=0.5)
        base.update(overrides)
        return CircuitBreakerConfig(**base)

    @staticmethod
    async def drive(breaker, pattern: str):
        """'S' = success, 'F' = failure, one breaker call per character."""
        for outcome in pattern:
            try:
                async with breaker:
                    if outcome == "F":
                        raise RuntimeError("synthetic failure")
            except RuntimeError:
                pass

    async def _check_alternating_failures_open_the_window_breaker(self):
        breaker = CircuitBreaker(self.config(), "rate")
        await self.drive(breaker, "SF" * 10)  # 20 calls, 10 failures, never 2 in a row
        self.assertLessEqual(max(len(r) for r in ("SF" * 10).split("S")), 1)
        self.assertEqual(breaker.get_stats().total_failures, 10)
        self.assertTrue(breaker.is_open)

    async def test_alternating_failures_over_a_full_window_open_the_breaker(self):
        await self._check_alternating_failures_open_the_window_breaker()

    async def test_same_pattern_with_the_window_off_stays_closed(self):
        # The ticket's negative control: window_size=0 is today's behaviour.
        breaker = CircuitBreaker(self.config(window_size=0), "off")
        await self.drive(breaker, "SF" * 20)
        self.assertEqual(breaker.get_stats().total_failures, 20)
        self.assertTrue(breaker.is_closed)
        self.assertFalse(CircuitBreakerConfig().window_size, "off by default")

    async def test_control_rate_rule_removed_in_process(self):
        with patch.object(CircuitBreaker, "_window_failure_rate_exceeded", lambda self: False):
            with self.assertRaises(AssertionError):
                await self._check_alternating_failures_open_the_window_breaker()

    async def test_needs_a_full_window_and_a_success_can_complete_it(self):
        breaker = CircuitBreaker(self.config(), "full")
        await self.drive(breaker, "FS" * 9 + "F")  # 19 calls, 10 failures: window not full
        self.assertTrue(breaker.is_closed)
        await self.drive(breaker, "S")  # 20th call (a success) fills the window at 10/20
        self.assertTrue(breaker.is_open)

    async def test_below_the_threshold_stays_closed(self):
        breaker = CircuitBreaker(self.config(), "below")
        await self.drive(breaker, "SSFSFSSFSFSSFSFSSFSF")  # 20 calls, 8 failures
        await self.drive(breaker, "SSFSSFSSFSSF")  # rolling: still < 50 percent
        self.assertTrue(breaker.is_closed)

    async def test_consecutive_failure_rule_is_unchanged(self):
        breaker = CircuitBreaker(self.config(), "consecutive")
        await self.drive(breaker, "FFF")
        self.assertTrue(breaker.is_open, "3 consecutive failures still open it with a small window")
        plain = CircuitBreaker(self.config(window_size=0), "plain")
        await self.drive(plain, "FFF")
        self.assertTrue(plain.is_open)

    async def test_recovery_reopens_on_a_failed_trial_and_does_not_instantly_retrip(self):
        breaker = CircuitBreaker(self.config(), "recover")
        await self.drive(breaker, "SF" * 10)
        self.assertTrue(breaker.is_open)
        breaker.config.timeout_seconds = 0.0
        await self.drive(breaker, "F")  # half-open trial fails -> OPEN again
        self.assertTrue(breaker.is_open)
        await self.drive(breaker, "SS")  # half-open, two successes -> CLOSED
        self.assertTrue(breaker.is_closed)
        await self.drive(breaker, "F")  # the stale window was discarded: no instant re-trip
        self.assertTrue(breaker.is_closed)

    async def test_control_failed_trial_does_not_reopen_without_the_window_rule(self):
        # Same forced-open start with the window OFF (today's behaviour): the
        # failed trial leaves the breaker HALF_OPEN, which is what the window
        # rule's explicit re-open fixes for rate-tripped breakers.
        for window, expected in ((0, CircuitState.HALF_OPEN), (20, CircuitState.OPEN)):
            breaker = CircuitBreaker(self.config(window_size=window, timeout_seconds=0.0), "trial")
            cb._set_state(breaker, CircuitState.OPEN, 0, 0, 0)
            await self.drive(breaker, "F")
            self.assertEqual(breaker.state, expected, f"window_size={window}")

    async def test_ollama_breaker_defaults_and_run_context_style_merge(self):
        self.assertEqual((OllamaCircuitBreaker().config.window_size,
                          OllamaCircuitBreaker().config.failure_rate_threshold), (20, 0.5))
        # RunContext builds its per-run breaker without window fields; the merge
        # must still give it the Ollama window.
        merged = OllamaCircuitBreaker("ollama", CircuitBreakerConfig(
            failure_threshold=3, success_threshold=2, timeout_seconds=60.0, half_open_max_requests=1))
        self.assertEqual((merged.config.window_size, merged.config.failure_rate_threshold), (20, 0.5))
        self.assertEqual(merged.config.failure_threshold, 3)
        self.assertEqual(OllamaClient("http://x").circuit_breaker.config.window_size, 20)

    async def test_explicit_zero_switches_the_ollama_window_off(self):
        off = OllamaCircuitBreaker("off", CircuitBreakerConfig(window_size=0))
        self.assertEqual(off.config.window_size, 0)
        await self.drive(off, "SF" * 10)
        self.assertTrue(off.is_closed)
        # Control: the same traffic with the window left unset (RunContext's
        # config) inherits 20 and opens.
        unset = OllamaCircuitBreaker("unset", CircuitBreakerConfig(failure_threshold=3))
        await self.drive(unset, "SF" * 10)
        self.assertTrue(unset.is_open)

    async def test_scoped_breaker_still_isolates_the_window(self):
        previous = cb._registry
        cb._registry = None
        self.addCleanup(setattr, cb, "_registry", previous)
        shared = cb.get_ollama_circuit_breaker("ollama")
        await self.drive(shared, "SF" * 5)
        before = list(shared._window)
        with cb.scoped_ollama_breaker():
            self.assertEqual(list(shared._window), [])
            await self.drive(shared, "SF")
        self.assertEqual(list(shared._window), before)


class FailureRateThroughTheClientTests(RetryTestBase):
    async def _run_incident(self, *, window_enabled: bool):
        """The incident shape: every other call fails for good (after its retries),
        so there are never 3 consecutive failures."""
        wire = Wire(*(["ok", 500, 500, 500] * 10))
        client = self.client(wire)
        breaker = self.breaker()
        if not window_enabled:
            patcher = patch.object(breaker.config, "window_size", 0)
            patcher.start()
            self.addCleanup(patcher.stop)
        for i in range(20):
            if i % 2 == 0:
                await self.call(client)
            else:
                with self.assertRaises(OllamaError):
                    await self.call(client)
        return client, wire, breaker

    async def test_non_consecutive_model_failures_open_the_ollama_breaker(self):
        client, wire, breaker = await self._run_incident(window_enabled=True)
        self.assertEqual(breaker.get_stats().total_failures, 10)
        self.assertLessEqual(breaker.get_stats().consecutive_failures, 1)
        self.assertTrue(breaker.is_open)
        sent = wire.calls
        with self.assertRaises(CircuitOpenError):
            await self.call(client)
        self.assertEqual(wire.calls, sent, "an open breaker sends nothing")

    async def test_control_same_traffic_with_the_window_off_never_opens(self):
        client, wire, breaker = await self._run_incident(window_enabled=False)
        self.assertTrue(breaker.is_closed)
        sent = wire.calls
        with self.assertRaises(OllamaError):  # goes out and fails like the others
            await self.call(client)
        self.assertGreater(wire.calls, sent)


# --------------------------------------------------------------------------
# 3. Critique stage inherits the client retry (no second retry layer)
# --------------------------------------------------------------------------
class CritiqueUsesClientRetryTests(RetryTestBase):
    REVIEWS = {"reviews": [{"index": 0, "verdict": "survived", "note": "n", "adjusted_confidence": 0.6}]}

    async def _critique(self, wire, **client_kwargs):
        from harness.effort import BudgetMode, EffortBudget
        from harness.models import AgentReport, Finding, HttpExchange
        from harness.test_remediation_inference_budget import manager_for, pipeline_for
        client = self.client(wire, **client_kwargs)
        pipeline = pipeline_for(manager_for(client), EffortBudget(BudgetMode.HARD), client)
        pipeline.config.update({"critique": {"enabled": True}, "coordinator": {"model": "synthetic-model"}})
        finding = Finding(vulnerability_class="cors", confidence=0.6, summary="ordinary header observation",
                          evidence="header exists", suggested_test="analyst review", basis="observed")
        report = AgentReport(agent="cors", model="synthetic-model", findings=[finding])
        outcome, reviewed, rejected = await pipeline._critique(
            HttpExchange(url="https://ordinary.invalid/status", method="GET"), [report])
        return client, outcome, reviewed, finding

    async def _check_one_500_does_not_ship_findings_unreviewed(self):
        wire = Wire(500, self.REVIEWS)
        client, outcome, reviewed, finding = await self._critique(wire)
        self.assertEqual(outcome.status, "completed")
        self.assertEqual(reviewed, 1)
        self.assertEqual(finding.review_verdict, "survived")
        self.assertEqual(wire.calls, 2, "one retry from the client; no second layer in the pipeline")
        self.assertEqual((client.model_retry_count, client.model_retry_recovered_count), (1, 1))

    async def test_critique_500_is_retried_once_and_the_findings_are_reviewed(self):
        await self._check_one_500_does_not_ship_findings_unreviewed()

    async def test_control_without_the_client_retry_the_critique_ships_unreviewed(self):
        with patch.object(OllamaClient, "_may_retry", lambda self, done: False):
            with self.assertRaises(AssertionError):
                await self._check_one_500_does_not_ship_findings_unreviewed()
        # ...and what that failure looks like at the pipeline (the measured symptom):
        wire = Wire(500, self.REVIEWS)
        _, outcome, reviewed, finding = await self._critique(wire, transient_retries=0)
        self.assertEqual((outcome.status, reviewed, wire.calls), ("failed", 0, 1))
        self.assertIsNone(getattr(finding, "review_verdict", None))

    async def test_persistent_critique_failure_is_bounded_and_still_reported_failed(self):
        wire = Wire(500)
        client, outcome, reviewed, _ = await self._critique(wire)
        self.assertEqual((outcome.status, reviewed, wire.calls), ("failed", 0, 3))


# --------------------------------------------------------------------------
# Config wiring: ollama.transient_retries reaches the clients
# --------------------------------------------------------------------------
class TransientRetriesConfigTests(unittest.TestCase):
    def test_config_yaml_ships_the_key_at_two(self):
        text = (_WORKTREE / "harness" / "config.yaml").read_text(encoding="utf-8")
        self.assertEqual(yaml.safe_load(text)["ollama"]["transient_retries"], 2)

    def _orchestrator(self, **ollama_overrides):
        from harness.orchestrator import Orchestrator
        from harness.test_smoke_detection import _test_config
        config = _test_config()
        config["ollama"].update(ollama_overrides)
        return Orchestrator(config)

    def _check_orchestrator_client_uses_the_configured_value(self):
        self.assertEqual(self._orchestrator(transient_retries=1).ollama.transient_retries, 1)
        self.assertEqual(self._orchestrator(transient_retries=0).ollama.transient_retries, 0)
        self.assertEqual(self._orchestrator().ollama.transient_retries, 2, "unset => the default")

    def test_orchestrator_client_uses_the_configured_value(self):
        self._check_orchestrator_client_uses_the_configured_value()

    def test_control_dropping_the_kwarg_is_detected(self):
        real_init = OllamaClient.__init__

        def init_without_retries(self, *args, **kwargs):
            kwargs.pop("transient_retries", None)
            real_init(self, *args, **kwargs)

        with patch.object(OllamaClient, "__init__", init_without_retries):
            with self.assertRaises(AssertionError):
                self._check_orchestrator_client_uses_the_configured_value()

    def test_standalone_pipeline_client_uses_the_configured_value(self):
        from harness.analysis_pipeline import AnalysisPipeline
        for value, expected in ((0, 0), (1, 1), (None, 2)):
            ollama = {"base_url": "http://fake-ollama:11434"}
            if value is not None:
                ollama["transient_retries"] = value
            pipeline = AnalysisPipeline(None, None, None, {"ollama": ollama, "critique": {"enabled": False}})
            self.assertEqual(pipeline.ollama_client.transient_retries, expected)


# --------------------------------------------------------------------------
# 4. Escalation model: configured model, never a hard-coded one
# --------------------------------------------------------------------------
class EscalationModelTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._dbs = 0
        db = patch.object(store, "_DB_PATH", str(Path(self._tmp.name) / "escalation-0.db"))
        db.start()
        self.addCleanup(db.stop)

    def _fresh_db(self):
        # Each lineage needs an empty store, or earlier attempts change the decision.
        self._dbs += 1
        store._DB_PATH = str(Path(self._tmp.name) / f"escalation-{self._dbs}.db")

    async def _lineage_at_escalation(self):
        from harness.test_active_verification import _make_plan, _submission
        plan = _make_plan(severity="critical", confidence=0.9)
        submission = _submission(plan.id, "not_confirmed")
        store.persist_retry_plan(plan)
        store.persist_validation_submission(submission)
        row = store.get_test_plan(plan.id)
        for _ in range(2):  # the two curated retries that precede ESCALATE
            step = await active_verification.decide_next_step(row, submission)
            submission = _submission(step.next_plan.id, "not_confirmed")
            store.persist_retry_plan(step.next_plan)
            store.persist_validation_submission(submission)
            row = store.get_test_plan(step.next_plan.id)
        return row, submission

    async def _escalate(self, **kwargs):
        row, submission = await self._lineage_at_escalation()
        client = AsyncMock()
        client.chat_json.return_value = {"payload": "<svg/onload=__CANARY__>", "rationale": "r"}
        step = await active_verification.decide_next_step(row, submission, ollama_client=client, **kwargs)
        return step, client

    @staticmethod
    def models_used(client):
        return [call.kwargs.get("model") for call in client.chat_json.await_args_list]

    async def _check_configured_model_is_used(self):
        step, client = await self._escalate(config={"coordinator": {"model": "qwen-selected:7b"}})
        self.assertTrue(step.next_plan is not None and step.next_plan.escalated)
        self.assertEqual(self.models_used(client), ["qwen-selected:7b"])
        self.assertNotIn("llama3.1:8b", self.models_used(client))

    async def test_no_call_uses_llama_when_the_config_selects_another_model(self):
        await self._check_configured_model_is_used()

    async def test_control_the_old_hidden_fallback_is_detected(self):
        legacy = lambda explicit, config: explicit or "llama3.1:8b"
        with patch.object(active_verification, "_resolve_escalation_model", legacy):
            with self.assertRaises(AssertionError):
                await self._check_configured_model_is_used()

    async def test_cloud_reasoning_seam_selects_the_cloud_model(self):
        config = {"coordinator": {"model": "local-x", "cloud_reasoning": True, "cloud_model": "cloud-y"}}
        _, client = await self._escalate(config=config)
        self.assertEqual(self.models_used(client), ["cloud-y"])

    async def test_explicit_escalation_model_wins_over_config(self):
        _, client = await self._escalate(escalation_model="explicit-z",
                                         config={"coordinator": {"model": "qwen-selected:7b"}})
        self.assertEqual(self.models_used(client), ["explicit-z"])

    async def _check_no_model_skips_the_escalation(self):
        for config in (None, {}, {"coordinator": {"model": ""}}):
            self._fresh_db()
            with self.assertLogs("harness.active_verification", level="WARNING") as logs:
                step, client = await self._escalate(config=config)
            self.assertIsNone(step.next_plan, config)
            self.assertIn("no model configured", step.note)
            client.chat_json.assert_not_awaited()
            self.assertTrue(any("no model is configured" in line for line in logs.output), logs.output)

    async def test_no_configured_model_skips_the_escalation_with_a_logged_reason(self):
        await self._check_no_model_skips_the_escalation()

    async def test_control_the_old_fallback_would_have_called_a_model_anyway(self):
        legacy = lambda explicit, config: explicit or "llama3.1:8b"
        with patch.object(active_verification, "_resolve_escalation_model", legacy):
            with self.assertRaises(AssertionError):
                await self._check_no_model_skips_the_escalation()


class EscalationModelThroughTheServerTests(unittest.TestCase):
    """/validation-results must hand decide_next_step the live config, or the
    escalation would now be skipped in production."""

    def setUp(self):
        from harness.test_pairing_contract import PairingCallerTests
        fixture = PairingCallerTests("test_health_is_liveness_and_pairing_requires_credential")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.server = fixture.server
        self.client = fixture.client
        self.client.headers.update(fixture.auth)
        self.chat = AsyncMock(return_value={"payload": "<svg/onload=__CANARY__>", "rationale": "r"})
        self.server.orchestrator.ollama = SimpleNamespace(chat_json=self.chat)
        self.server.orchestrator.config = {"coordinator": {"model": "qwen-selected:7b"}}

    def _walk_a_lineage_to_escalation(self):
        from harness.test_active_verification import _make_plan
        plan = _make_plan(severity="critical", confidence=0.9)
        store.persist_retry_plan(plan)
        plan_id, body = plan.id, None
        for _ in range(3):  # 2 curated retries, then the escalation
            reply = self.client.post("/validation-results", json={
                "plan_id": plan_id, "status": "not_confirmed", "confirmed": False,
                "executor": "burp:reflection_context_validation",
                "source_exchange_hash": "hash-abc", "context_tags": []})
            self.assertEqual(reply.status_code, 200, reply.text)
            body = reply.json()
            self.assertIn("next_plan", body, body)
            plan_id = body["next_plan"]["id"]
        return body

    def _check_server_escalates_with_the_configured_model(self):
        body = self._walk_a_lineage_to_escalation()
        self.assertTrue(body["next_plan"]["escalated"])
        models = [call.kwargs.get("model") for call in self.chat.await_args_list]
        self.assertEqual(models, ["qwen-selected:7b"])

    def test_validation_results_escalates_with_the_configured_model(self):
        self._check_server_escalates_with_the_configured_model()

    def test_control_route_that_drops_the_config_is_detected(self):
        real = active_verification.decide_next_step

        async def route_without_config(*args, **kwargs):
            kwargs.pop("config", None)
            return await real(*args, **kwargs)

        with patch.object(active_verification, "decide_next_step", route_without_config):
            with self.assertRaises(AssertionError):
                self._check_server_escalates_with_the_configured_model()


# --------------------------------------------------------------------------
# 5. InvestigateRequest.discovery_max_probes reaches investigate_engagement
# --------------------------------------------------------------------------
class InvestigateDiscoveryProbesTests(unittest.TestCase):
    def setUp(self):
        from harness.test_job_status_passive import DurableJobCallerTests
        self.fixture = DurableJobCallerTests("test_completed_job_survives_registry_loss_without_reexecution")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.captured: list[dict] = []

        async def capture(*args, **kwargs):
            self.captured.append(kwargs)
            return {"summary": {"ordinary_captures": 1}}

        self.fixture.server.orchestrator.investigate_engagement = capture

    def _probes_seen(self, **request_fields):
        body = {"base_url": "https://captured.example/ordinary", **request_fields}
        reply = self.fixture.client.post("/engagement/captured.example/investigate", json=body)
        self.assertEqual(reply.status_code, 200, reply.text)
        self.fixture.poll(reply.json()["job_id"], "done")
        return self.captured[-1].get("discovery_max_probes")

    def _check_value_reaches_investigate_engagement(self):
        self.assertEqual(self._probes_seen(), 6000, "omitting the field passes the 6000 default")
        self.assertEqual(self._probes_seen(discovery_max_probes=1234), 1234)
        self.assertEqual(self._probes_seen(discovery_max_probes=99999), 20000)
        self.assertEqual(self._probes_seen(discovery_max_probes=0), 1)
        self.assertEqual(self._probes_seen(discovery_max_probes=-5), 1)

    def test_discovery_max_probes_reaches_investigate_engagement_bounded(self):
        self._check_value_reaches_investigate_engagement()

    def test_control_an_endpoint_that_drops_the_kwarg_is_detected(self):
        real = self.fixture.server.orchestrator.investigate_engagement

        async def endpoint_without_the_fix(*args, **kwargs):
            kwargs.pop("discovery_max_probes", None)
            return await real(*args, **kwargs)

        self.fixture.server.orchestrator.investigate_engagement = endpoint_without_the_fix
        with self.assertRaises(AssertionError):
            self._check_value_reaches_investigate_engagement()


if __name__ == "__main__":
    unittest.main()
