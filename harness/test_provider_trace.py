"""SC-13: provider composition + unified cost/latency trace -- caller-level
tests + negative controls for the four acceptance criteria:

  1. every model path appears in the run ledger      (TraceCompletenessTests)
  2. concurrent reservations cannot exceed the SC-8 hard budget
                                                      (ConcurrentBudgetTests)
  3. failures and streaming are accounted             (FailureAndStreamingTests)
  4. role routing mechanism (measurement is OWNER/LIVE, not asserted here)
                                                      (RoutingTests)
"""
from __future__ import annotations

import asyncio
import threading
import unittest

from harness.effort import BudgetMode, CallKind, EffortBudget
from harness.ollama_client import OllamaResult
from harness.provider_trace import (
    ProviderBudgetError, ProviderRouter, RouteChoice, TracingProvider,
    traced_call, traced_route_call,
)


class _Clock:
    """Deterministic clock: each call advances by `step`, so one traced_call
    (two reads) yields a fixed latency without real time."""

    def __init__(self, start=0.0, step=0.5):
        self.t, self.step = float(start), float(step)

    def __call__(self):
        v = self.t
        self.t += self.step
        return v


class _FakeProvider:
    def __init__(self, *, name="fake", pt=60, ct=40, fail_times=0,
                 exc=None):
        self.name = name
        self.pt, self.ct = pt, ct
        self.fail_times = fail_times
        self.exc = exc or RuntimeError("boom")
        self.calls = 0
        self._lock = threading.Lock()

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1, **kw):
        with self._lock:
            self.calls += 1
            n = self.calls
        if n <= self.fail_times:
            raise self.exc
        return OllamaResult(data={"ok": True}, prompt_tokens=self.pt, completion_tokens=self.ct)


def _tracer_budget():
    return EffortBudget(mode=BudgetMode.SOFT, total_tokens=None)


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# Criterion 1: every model path appears in the run ledger, enriched
# --------------------------------------------------------------------------
class TraceCompletenessTests(unittest.TestCase):
    def test_successful_call_lands_one_enriched_record(self):
        budget = _tracer_budget()
        provider = _FakeProvider(name="fake", pt=60, ct=40)
        out = _run(traced_call(
            provider, budget, kind=CallKind.ROUTING, model="qwen3:8b",
            system_prompt="s", user_prompt="u", prompt_version="v7",
            case_ref="case-1", run_id="run-1", estimate=100, clock=_Clock()))
        self.assertTrue(out.ok)
        self.assertEqual(len(budget.ledger.records), 1)
        rec = budget.ledger.records[0]
        self.assertEqual(rec.provider, "fake")
        self.assertEqual(rec.model, "qwen3:8b")
        self.assertEqual(rec.kind, CallKind.ROUTING)
        self.assertEqual((rec.prompt_tokens, rec.completion_tokens), (60, 40))
        self.assertEqual(rec.prompt_version, "v7")
        self.assertEqual(rec.case_ref, "case-1")
        self.assertEqual(rec.run_id, "run-1")
        self.assertEqual(rec.outcome, "ok")
        self.assertAlmostEqual(rec.latency_ms, 500.0)  # one 0.5s clock step
        self.assertEqual(rec.retries, 0)
        # And it is exposed as a flat trace row for the run ledger.
        self.assertEqual(budget.ledger.trace()[0]["total_tokens"], 100)

    def test_reservation_is_settled_not_leaked(self):
        budget = _tracer_budget()
        _run(traced_call(_FakeProvider(), budget, kind=CallKind.ROUTING, model="m",
                         system_prompt="s", user_prompt="u", estimate=100))
        self.assertEqual(budget._reserved, 0)
        self.assertEqual(budget.spent, 100)

    def test_tracing_provider_is_a_drop_in_that_records(self):
        budget = _tracer_budget()
        inner = _FakeProvider(name="ollama", pt=10, ct=5)
        tp = TracingProvider(inner, budget, kind=CallKind.AGENT_DISPATCH,
                             prompt_version="p1")
        result = _run(tp.chat_json("m", "s", "u"))
        self.assertEqual((result.prompt_tokens, result.completion_tokens), (10, 5))
        self.assertEqual(len(budget.ledger.records), 1)
        self.assertEqual(budget.ledger.records[0].provider, "ollama")
        self.assertEqual(budget.ledger.records[0].prompt_version, "p1")
        # chat_json_metered is aliased so it also replaces a bare OllamaClient.
        _run(tp.chat_json_metered("m", "s", "u"))
        self.assertEqual(len(budget.ledger.records), 2)


# --------------------------------------------------------------------------
# Criterion 2: concurrent reservations cannot exceed the SC-8 hard budget
# --------------------------------------------------------------------------
class ConcurrentBudgetTests(unittest.TestCase):
    def test_concurrent_traced_calls_cannot_overshoot_hard_budget(self):
        # total 300, est==actual==100 -> at most 3 calls can ever be admitted.
        budget = EffortBudget(mode=BudgetMode.HARD, total_tokens=300)
        provider = _FakeProvider(pt=60, ct=40)  # 100 actual per call

        worker_count = 10
        barrier = threading.Barrier(worker_count)
        outcomes: list[str] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def worker():
            try:
                barrier.wait(timeout=5)
                out = asyncio.run(traced_call(
                    provider, budget, kind=CallKind.AGENT_DISPATCH, model="m",
                    system_prompt="s", user_prompt="u", estimate=100))
                with lock:
                    outcomes.append(out.outcome)
            except BaseException as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(worker_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        self.assertEqual(errors, [], f"worker raised: {errors}")
        self.assertEqual(outcomes.count("ok"), 3)
        self.assertEqual(outcomes.count("budget_blocked"), 7)
        self.assertLessEqual(budget.spent, 300)         # never overshoots
        self.assertEqual(budget.spent, 300)             # the 3 admitted did commit
        self.assertEqual(budget._reserved, 0)           # no leaked reservation

    def test_budget_blocked_never_touches_the_provider(self):
        budget = EffortBudget(mode=BudgetMode.HARD, total_tokens=50)
        provider = _FakeProvider()
        out = _run(traced_call(provider, budget, kind=CallKind.ROUTING, model="m",
                               system_prompt="s", user_prompt="u", estimate=100))
        self.assertEqual(out.outcome, "budget_blocked")
        self.assertEqual(provider.calls, 0)             # provider never called
        self.assertEqual(len(budget.ledger.records), 0)  # nothing recorded
        self.assertEqual(budget._reserved, 0)


# --------------------------------------------------------------------------
# Criterion 3: failures and streaming are accounted
# --------------------------------------------------------------------------
class FailureAndStreamingTests(unittest.TestCase):
    def test_failure_is_recorded_and_reservation_refunded(self):
        budget = _tracer_budget()
        provider = _FakeProvider(fail_times=1)  # fails, no retries
        out = _run(traced_call(provider, budget, kind=CallKind.CRITIQUE, model="m",
                               system_prompt="s", user_prompt="u", estimate=100,
                               clock=_Clock()))
        self.assertFalse(out.ok)
        self.assertEqual(out.outcome, "error")
        self.assertEqual(len(budget.ledger.records), 1)  # failed path still traced
        rec = budget.ledger.records[0]
        self.assertEqual(rec.outcome, "error")
        self.assertEqual(rec.total_tokens, 0)            # no usage on a failure
        self.assertEqual(budget.spent, 0)
        self.assertEqual(budget._reserved, 0)            # reservation refunded

    def test_retry_then_success_counts_retries(self):
        budget = _tracer_budget()
        provider = _FakeProvider(fail_times=1)  # first attempt fails
        out = _run(traced_call(provider, budget, kind=CallKind.VALIDATION_RETRY,
                               model="m", system_prompt="s", user_prompt="u",
                               estimate=100, max_retries=2))
        self.assertTrue(out.ok)
        self.assertEqual(out.retries, 1)
        self.assertEqual(budget.ledger.records[0].retries, 1)
        self.assertEqual(budget.spent, 100)

    def test_retries_exhausted_reports_error(self):
        budget = _tracer_budget()
        provider = _FakeProvider(fail_times=99)
        out = _run(traced_call(provider, budget, kind=CallKind.ESCALATION, model="m",
                               system_prompt="s", user_prompt="u", estimate=100,
                               max_retries=2))
        self.assertEqual(out.outcome, "error")
        self.assertEqual(out.retries, 2)
        self.assertEqual(provider.calls, 3)              # 1 + 2 retries
        self.assertEqual(budget.ledger.records[0].outcome, "error")

    def test_streaming_call_is_flagged_and_usage_accounted(self):
        budget = _tracer_budget()
        out = _run(traced_call(_FakeProvider(pt=200, ct=300), budget,
                               kind=CallKind.AGENT_DISPATCH, model="m",
                               system_prompt="s", user_prompt="u", estimate=100,
                               streamed=True))
        self.assertTrue(out.ok)
        rec = budget.ledger.records[0]
        self.assertTrue(rec.streamed)
        self.assertEqual(rec.total_tokens, 500)          # streamed usage still counted
        self.assertEqual(budget.spent, 500)

    def test_tracing_provider_reraises_underlying_error(self):
        budget = _tracer_budget()
        sentinel = ValueError("upstream 500")
        tp = TracingProvider(_FakeProvider(fail_times=1, exc=sentinel), budget,
                             kind=CallKind.CRITIQUE)
        with self.assertRaises(ValueError):
            _run(tp.chat_json("m", "s", "u"))
        # The failed path was still traced and the reservation refunded.
        self.assertEqual(budget.ledger.records[0].outcome, "error")
        self.assertEqual(budget._reserved, 0)

    def test_tracing_provider_raises_on_hard_budget_block(self):
        budget = EffortBudget(mode=BudgetMode.HARD, total_tokens=10)
        tp = TracingProvider(_FakeProvider(), budget, kind=CallKind.ROUTING, estimate=100)
        with self.assertRaises(ProviderBudgetError):
            _run(tp.chat_json("m", "s", "u"))


# --------------------------------------------------------------------------
# Criterion 4: role-routing mechanism (win/no-win measurement is OWNER/LIVE)
# --------------------------------------------------------------------------
class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.cheap = _FakeProvider(name="cheap")
        self.deep = _FakeProvider(name="deep")
        self.router = ProviderRouter(
            default=RouteChoice(self.cheap, "cheap-model"),
            routes={CallKind.ESCALATION: RouteChoice(self.deep, "deep-model")})

    def test_route_selection_is_deterministic(self):
        self.assertTrue(self.router.enabled)
        self.assertEqual(self.router.route(CallKind.ROUTING).model, "cheap-model")
        self.assertEqual(self.router.route(CallKind.ESCALATION).model, "deep-model")

    def test_disabled_router_always_uses_default(self):
        router = ProviderRouter(default=RouteChoice(self.cheap, "cheap-model"))
        self.assertFalse(router.enabled)
        self.assertEqual(router.route(CallKind.ESCALATION).provider, self.cheap)

    def test_routed_call_records_the_chosen_path_in_the_trace(self):
        budget = _tracer_budget()
        _run(traced_route_call(self.router, budget, kind=CallKind.ESCALATION,
                               system_prompt="s", user_prompt="u", estimate=100))
        _run(traced_route_call(self.router, budget, kind=CallKind.ROUTING,
                               system_prompt="s", user_prompt="u", estimate=100))
        by_provider = [(r.provider, r.model) for r in budget.ledger.records]
        self.assertIn(("deep", "deep-model"), by_provider)
        self.assertIn(("cheap", "cheap-model"), by_provider)


if __name__ == "__main__":
    unittest.main()
