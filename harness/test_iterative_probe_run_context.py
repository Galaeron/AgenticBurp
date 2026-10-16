"""ARCH-1 caller-level controls: the iterative probe must spend the OWNING run's
request budget / cancel token / scope and travel its ONE TargetTransport -- never a
throwaway per-send standalone client that escapes all parent accounting.

These drive the production probe component (IterativeAgent.run) with a scripted model
and a mocked network, plus run_active_probe's threading/ownership. The network is
patched at `httpx.AsyncClient.request`; `assert_not_called()` is the proof of "zero
target sends" (budget/scope/cancel all short-circuit before the client send).
"""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

import httpx

from harness.models import HttpExchange
from harness.iterative_agent import IterativeAgent
from harness.orchestrator_confirm import ConfirmMixin
from harness.run_context import standalone_context
from harness import safety_gate


class _ScriptedOllama:
    """Returns a preset sequence of action dicts, one per chat_json call."""
    def __init__(self, actions):
        self._actions = list(actions)
        self.calls = 0

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.2):
        self.calls += 1
        if self._actions:
            return self._actions.pop(0)
        return {"action": "stop", "verdict": "not_found", "thought": "out of ideas"}


class _Resp:
    def __init__(self, status, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _exchange(url="http://localhost:5002/api/search?q=widget"):
    return HttpExchange(url=url, method="GET", request_headers={"User-Agent": "x"},
                        request_body="", response_status=200, response_body="results")


def _mutate(value):
    return {"action": "mutate", "location": "query", "param": "q", "value": value}


class ArchOneBudgetEnforcementTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()

    async def test_exhausted_parent_budget_makes_zero_target_requests(self):
        ctx = standalone_context(["localhost"], max_requests=0)  # already exhausted
        agent = IterativeAgent(_ScriptedOllama([_mutate("x")]), "m", ["localhost"],
                               run_context=ctx)
        with patch("httpx.AsyncClient.request") as mock_req:
            r = await agent.run(_exchange(), "SQLi", "sqli", step_budget=1)
            mock_req.assert_not_called()
        self.assertEqual(ctx.budget.used, 0)
        self.assertTrue(any(s.blocked and "budget_exhausted" in (s.blocked or "")
                            for s in r.transcript))

    async def test_allowed_send_increments_the_parent_count(self):
        ctx = standalone_context(["localhost"], max_requests=5)
        agent = IterativeAgent(
            _ScriptedOllama([_mutate("x"), {"action": "stop", "verdict": "not_found", "thought": "d"}]),
            "m", ["localhost"], run_context=ctx)
        with patch("httpx.AsyncClient.request", return_value=_Resp(200, "ok")) as mock_req:
            await agent.run(_exchange(), "SQLi", "sqli", step_budget=5)
            self.assertEqual(mock_req.call_count, 1)
        self.assertEqual(ctx.budget.used, 1)  # the SHARED run budget moved, not a throwaway

    async def test_one_shared_budget_exhausts_across_sends(self):
        """Negative control for the _execute fix: two DISTINCT sends share the run's
        single budget (max_requests=1), so the second is blocked. Reverting _execute
        to transport_for(None, ...) gives each send a fresh unbounded context -> both
        send -> this fails."""
        ctx = standalone_context(["localhost"], max_requests=1)
        agent = IterativeAgent(
            _ScriptedOllama([_mutate("one"), _mutate("two"),
                             {"action": "stop", "verdict": "not_found", "thought": "d"}]),
            "m", ["localhost"], run_context=ctx)
        with patch("httpx.AsyncClient.request", return_value=_Resp(200, "ok")) as mock_req:
            r = await agent.run(_exchange(), "SQLi", "sqli", step_budget=5)
            self.assertEqual(mock_req.call_count, 1)  # only the first send fit the budget
        self.assertEqual(ctx.budget.used, 1)
        self.assertTrue(any(s.blocked and "budget_exhausted" in (s.blocked or "")
                            for s in r.transcript))

    async def test_run_scope_governs_the_probe_destination(self):
        """The RUN's allowed_hosts reach the transport: a send to a host the run does
        not allow is blocked, even though the agent's own allowed_hosts would permit it."""
        ctx = standalone_context(["localhost"], max_requests=5)  # run allows only localhost
        agent = IterativeAgent(_ScriptedOllama([_mutate("x")]), "m", ["evil.test"],
                               run_context=ctx)
        with patch("httpx.AsyncClient.request") as mock_req:
            r = await agent.run(_exchange("http://evil.test/api/search?q=w"), "SQLi", "sqli",
                                step_budget=1)
            mock_req.assert_not_called()
        self.assertEqual(ctx.budget.used, 0)
        self.assertTrue(any(s.blocked and "out of scope" in (s.blocked or "")
                            for s in r.transcript))

    async def test_cancelled_run_prevents_probe_sends(self):
        ctx = standalone_context(["localhost"], max_requests=5)
        ctx.cancel.cancel()
        agent = IterativeAgent(_ScriptedOllama([_mutate("x")]), "m", ["localhost"],
                               run_context=ctx)
        with patch("httpx.AsyncClient.request") as mock_req:
            r = await agent.run(_exchange(), "SQLi", "sqli", step_budget=1)
            mock_req.assert_not_called()
        self.assertEqual(ctx.budget.used, 0)
        self.assertTrue(any(s.blocked and "cancelled" in (s.blocked or "")
                            for s in r.transcript))


class _RecordingAgent:
    """Captures the run_context run_active_probe hands the agent; no real work."""
    last_run_context = "unset"

    def __init__(self, ollama, model, allowed_hosts, *, max_steps=250, run_context=None):
        type(self).last_run_context = run_context

    async def run(self, *a, **k):
        return SimpleNamespace(to_dict=lambda: {"stop_reason": "gave_up", "findings": []})


class _ProbeHost(ConfirmMixin):
    """Just enough orchestrator surface for ConfirmMixin.run_active_probe."""
    def __init__(self, config):
        self.config = config
        self.allowed_hosts = ["localhost"]
        self.ollama = object()
        self.iterative_agent_enabled = True
        self.iterative_agent_max_steps = 20
        self.effort_budget = None

    def reasoning_model(self):
        return "test-model"


class ArchOneThreadingOwnershipTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()
        _RecordingAgent.last_run_context = "unset"

    async def test_run_active_probe_forwards_the_owning_run_context(self):
        host = _ProbeHost({})
        borrowed = standalone_context(["localhost"], max_requests=3)
        with patch("harness.iterative_agent.IterativeAgent", _RecordingAgent), \
             patch("harness.pivot_memory.integrate",
                   new=AsyncMock(return_value=SimpleNamespace(to_dict=lambda: {}))):
            await host.run_active_probe(_exchange(), "h", "sqli", run_context=borrowed)
        self.assertIs(_RecordingAgent.last_run_context, borrowed)  # borrowed, not rebuilt

    async def test_standalone_probe_builds_one_ceilinged_owned_context(self):
        host = _ProbeHost({})
        with patch("harness.iterative_agent.IterativeAgent", _RecordingAgent), \
             patch("harness.pivot_memory.integrate",
                   new=AsyncMock(return_value=SimpleNamespace(to_dict=lambda: {}))):
            await host.run_active_probe(_exchange(), "h", "sqli", step_budget=10)
        built = _RecordingAgent.last_run_context
        self.assertIsNotNone(built)
        self.assertIsNot(built, "unset")
        self.assertIsNotNone(built.budget.remaining)  # an EXPLICIT ceiling, not unbounded

    async def test_config_max_requests_overrides_the_derived_ceiling(self):
        host = _ProbeHost({"iterative_agent": {"max_requests": 7}})
        with patch("harness.iterative_agent.IterativeAgent", _RecordingAgent), \
             patch("harness.pivot_memory.integrate",
                   new=AsyncMock(return_value=SimpleNamespace(to_dict=lambda: {}))):
            await host.run_active_probe(_exchange(), "h", "sqli", step_budget=10)
        self.assertEqual(_RecordingAgent.last_run_context.budget.remaining, 7)


if __name__ == "__main__":
    unittest.main()
