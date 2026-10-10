"""Regression: a run where every dispatched LLM agent fails (the model backend
unreachable / model not pulled) must NOT look like a normal run.

Before this guard, agent failures were recorded only in each agent's own
`raw_error` buried in `agent_reports`; the top-level response had no error, the
summary read normally, and `degraded` keyed only off the circuit breaker and the
critique stage -- so "ollama isn't running" presented as "it ran and found
almost nothing." This drives the REAL analyze() pipeline with a model stub that
always raises (exactly the ollama-down shape) and asserts the failure is
surfaced: `degraded` True, `agent_errors` populated, and an explicit WARNING
leading the summary. Deterministic findings (if any) still ship.

Model boundary stubbing reuses test_smoke_detection's config/exchange idioms,
the same approach as test_stage_health.py.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from harness import cache, store
from harness.circuit_breaker import get_ollama_circuit_breaker
from harness.ollama_client import OllamaError
from harness.orchestrator import Orchestrator
from harness.test_smoke_detection import _test_config, _sqli_exchange

_HOST = "silent-model-failure.smoke-test.local"


class _DeadModel:
    """Every model call raises, as if `ollama serve` were not running."""

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        raise OllamaError("synthetic: ollama backend unreachable (injected by test)")

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        raise OllamaError("synthetic: ollama backend unreachable (injected by test)")


def _build() -> Orchestrator:
    cfg = _test_config()
    cfg["server"]["allowed_hosts"] = list(cfg["server"].get("allowed_hosts", [])) + [_HOST]
    orch = Orchestrator(cfg)
    dead = _DeadModel()
    orch.ollama = dead
    for agent in orch.agent_manager.agents.values():
        agent.ollama = dead
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = dead
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = dead
    return orch


class SilentModelFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="silent_model_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def setUp(self):
        get_ollama_circuit_breaker("ollama").reset()

    def tearDown(self):
        get_ollama_circuit_breaker("ollama").reset()

    def test_all_agents_failed_is_degraded_and_surfaced(self):
        orch = _build()
        resp = asyncio.run(orch.analyze(
            _sqli_exchange(_HOST), force_agents=["sqli"], bypass_cache=True))

        # Every dispatched agent errored.
        self.assertTrue(resp.agent_reports, "no agent reports recorded")
        self.assertTrue(all(r.raw_error for r in resp.agent_reports),
                        "precondition: every dispatched agent must have failed")

        # The failure is surfaced at the TOP LEVEL, not just per-agent.
        self.assertTrue(resp.degraded, "all-agents-failed run must be marked degraded")
        self.assertTrue(resp.agent_errors, "agent_errors must mirror the per-agent failures")
        self.assertEqual(len(resp.agent_errors), len(resp.agent_reports))
        self.assertIn("WARNING: all", resp.summary)
        self.assertIn("deterministic checks only", resp.summary)


if __name__ == "__main__":
    unittest.main()
