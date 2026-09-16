"""
Regression tests for concurrency.max_parallel_agents.

Covers the fix for unbounded agent concurrency: previously, every agent
in a dispatch list got fired as a simultaneous asyncio.create_task with
no limit -- a dispatch of several agents, or the coordinator failing
open to all 36, meant that many concurrent inference requests hit
Ollama at once, risking VRAM exhaustion on memory-constrained GPUs
(model swapping, spillover to CPU, or worse, OS-level disk paging).

These tests prove actual bounded concurrency -- that peak simultaneous
in-flight work never exceeds the configured limit -- not just that the
config value is read correctly.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from harness.agent_manager import AgentManager
from harness.models import AgentReport, HttpExchange


class DummyOllama:
    pass


class ConcurrencyTrackingAgentManager:
    """Wraps AgentManager.run_multiple_agents' bounding behavior without
    needing real agents or a real Ollama client: run_agent_async is
    replaced with a coroutine that records how many calls are
    simultaneously in flight, so the test can assert on peak
    concurrency directly rather than inferring it indirectly."""


def make_manager(max_parallel_agents=None, num_agents=6):
    config = {
        "ollama": {"base_url": "http://localhost:11434"},
        "coordinator": {"model": "llama3.1:8b"},
        "agent_defaults": {"model": "gemma2:9b"},
        "agents": {},
    }
    if max_parallel_agents is not None:
        config["concurrency"] = {"max_parallel_agents": max_parallel_agents}
    manager = AgentManager(config, DummyOllama())
    return manager


class TestAgentConcurrencyLimit(unittest.TestCase):
    def test_concurrency_never_exceeds_configured_limit(self):
        """With max_parallel_agents=2 and 6 agents dispatched, no more
        than 2 should ever be simultaneously in flight."""
        manager = make_manager(max_parallel_agents=2)
        agent_names = list(manager.agents.keys())[:6]

        current_in_flight = {"count": 0}
        peak_in_flight = {"value": 0}

        async def fake_run_agent_async(name, exchange, max_body_chars, prior_context):
            current_in_flight["count"] += 1
            peak_in_flight["value"] = max(peak_in_flight["value"], current_in_flight["count"])
            await asyncio.sleep(0.05)  # hold the "slot" long enough for overlap to be observable
            current_in_flight["count"] -= 1
            from harness.models import AgentReport
            return AgentReport(agent=name, model="test", findings=[])

        manager.run_agent_async = fake_run_agent_async

        asyncio.run(manager.run_multiple_agents(agent_names, exchange=None))

        self.assertLessEqual(peak_in_flight["value"], 2)
        self.assertGreater(peak_in_flight["value"], 0)  # sanity: it actually ran

    def test_all_agents_still_complete_under_the_limit(self):
        """Bounding concurrency must not drop any agent's result --
        every dispatched agent should still produce a report, just not
        all simultaneously."""
        manager = make_manager(max_parallel_agents=2)
        agent_names = list(manager.agents.keys())[:6]

        async def fake_run_agent_async(name, exchange, max_body_chars, prior_context):
            await asyncio.sleep(0.01)
            from harness.models import AgentReport
            return AgentReport(agent=name, model="test", findings=[])

        manager.run_agent_async = fake_run_agent_async

        results = asyncio.run(manager.run_multiple_agents(agent_names, exchange=None))

        self.assertEqual(len(results), 6)
        self.assertEqual({r.agent for r in results}, set(agent_names))

    def test_zero_or_unset_limit_means_unbounded(self):
        """concurrency.max_parallel_agents: 0, or omitting the section
        entirely, must preserve the old fully-concurrent behavior --
        this is an opt-in throttle, not a forced default that could
        surprise someone with real GPU headroom to spare."""
        manager = make_manager(max_parallel_agents=None)
        self.assertIsNone(manager._agent_semaphore)

        manager_zero = make_manager(max_parallel_agents=0)
        self.assertIsNone(manager_zero._agent_semaphore)

    def test_positive_limit_creates_a_real_semaphore(self):
        manager = make_manager(max_parallel_agents=3)
        self.assertIsNotNone(manager._agent_semaphore)
        self.assertIsInstance(manager._agent_semaphore, asyncio.Semaphore)


class TestOrchestratorConcurrencyCaller(unittest.TestCase):
    """W-13: prove the manager-scoped bound through the production caller.

    Two top-level ``Orchestrator.analyze`` invocations overlap, each dispatching
    two inert agents. A per-exchange semaphore would allow a peak of four; the
    shared manager semaphore must hold the combined peak to two.
    """

    def setUp(self):
        from harness import cache, store

        self._tmp = tempfile.mkdtemp(prefix="agent_concurrency_caller_")
        self._old_store = store._DB_PATH
        self._old_cache = cache._cache
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))

    def tearDown(self):
        from harness import cache, store

        store._DB_PATH = self._old_store
        cache._cache = self._old_cache
        shutil.rmtree(self._tmp, ignore_errors=True)

    @staticmethod
    def _config():
        import yaml

        with open(Path(__file__).resolve().parent / "config.yaml", encoding="utf-8") as stream:
            config = yaml.safe_load(stream) or {}
        config.setdefault("concurrency", {})["max_parallel_agents"] = 2
        config.setdefault("critique", {})["enabled"] = False
        config.setdefault("validators", {})["active_enabled"] = False
        config.setdefault("autonomous_discovery", {})["enabled"] = False
        config.setdefault("github_advisories", {})["enabled"] = False
        config.setdefault("kev_check", {})["enabled"] = False
        config.setdefault("package_registry_checks", {})["enabled"] = False
        config.setdefault("iterative_agent", {})["enabled"] = False
        config.setdefault("engagement", {})["auto_escalate"] = False
        config.setdefault("server", {})["allowed_hosts"] = ["one.test", "two.test"]
        return config

    def test_shared_manager_bounds_two_simultaneous_analyze_calls(self):
        from harness.orchestrator import Orchestrator

        orchestrator = Orchestrator(self._config())
        agent_names = list(orchestrator.agent_manager.agents)[:2]
        self.assertEqual(len(agent_names), 2, "test environment must load two inert agent slots")
        in_flight = 0
        peak = 0
        calls = 0

        async def inert_agent(name, exchange, max_body_chars, prior_context):
            nonlocal in_flight, peak, calls
            calls += 1
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.03)
            in_flight -= 1
            return AgentReport(agent=name, model="inert", findings=[])

        orchestrator.agent_manager.run_agent_async = inert_agent
        exchanges = [
            HttpExchange(url=f"http://{host}/resource", method="GET",
                         response_status=200, response_headers={}, response_body="ok")
            for host in ("one.test", "two.test")
        ]

        async def run_both():
            return await asyncio.gather(*[
                orchestrator.analyze(exchange, force_agents=agent_names, bypass_cache=True)
                for exchange in exchanges
            ])

        responses = asyncio.run(run_both())
        self.assertEqual(calls, 4)
        self.assertEqual(peak, 2)
        self.assertTrue(all(response.dispatched_agents == agent_names for response in responses))


if __name__ == "__main__":
    unittest.main()
