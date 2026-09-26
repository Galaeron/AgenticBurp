"""Caller-level coverage for AnalysisResponse.agents_circuit_open (B2-1).

orchestrator_detect.py's analyze() stamps agents_circuit_open on the response
it builds by reading the shared ollama circuit breaker's `.is_open` via
harness.circuit_breaker.get_ollama_circuit_breaker("ollama") -- the same
process-wide singleton accessor the orchestrator's real agent dispatch and
critique pass share (see get_ollama_circuit_breaker's docstring). This module
exercises that wiring through the real Orchestrator.analyze() entry point,
mirroring test_orchestrator_detect.py's CoordinatorFallbackResponseFlagTests
structure. Offline: the model boundary (ollama) is stubbed, no live
Ollama/network, no answer-key/blind-target content is read.

Critical: the breaker is a process-wide singleton shared across the whole
test suite. setUp/tearDown here reset it explicitly so an OPEN state forced
by the positive test can never leak into unrelated tests.
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from harness import cache, store
from harness.circuit_breaker import get_ollama_circuit_breaker
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.test_smoke_detection import _test_config

_HARNESS = Path(__file__).resolve().parent


def _inert_exchange(host: str = "inert-circuit.test") -> HttpExchange:
    """Signal-free exchange -- content doesn't matter for this test, only
    that analyze() runs the real response-assembly path far enough to reach
    the AnalysisResponse(...) construction in orchestrator_detect.py."""
    return HttpExchange(
        url=f"http://{host}/hello",
        method="GET",
        request_headers={},
        request_body="",
        response_status=200,
        response_headers={},
        response_body="ok",
    )


class _InertStubOllama:
    """Every call (routing or per-agent detection) returns an empty, valid
    result -- no findings, no fail-open, so any degraded signal observed in
    these tests comes only from the circuit breaker, not from routing
    fallback or detection noise."""

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        if "coordinator in a security-testing harness" in system_prompt:
            return OllamaResult(
                data={"dispatch": ["misconfig"], "reason": "plausible config surface"},
                prompt_tokens=1, completion_tokens=1,
            )
        return OllamaResult(data={"findings": [], "components": []},
                            prompt_tokens=1, completion_tokens=1)

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        result = await self.chat_json_metered(model, system_prompt, user_prompt, temperature)
        return result.data


def _build(ollama) -> Orchestrator:
    cfg = _test_config()
    cfg["server"]["allowed_hosts"] = list(cfg["server"]["allowed_hosts"]) + ["inert-circuit.test"]
    orch = Orchestrator(cfg)
    orch.ollama = ollama
    for agent in orch.agent_manager.agents.values():
        agent.ollama = ollama
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = ollama
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = ollama
    return orch


class CircuitOpenResponseFlagTests(unittest.IsolatedAsyncioTestCase):
    """B2-1: the shared ollama circuit breaker being OPEN during a run must be
    observable on the AnalysisResponse itself (agents_circuit_open), not just
    inferred from silence/telemetry."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="b2_1_circuit_flag_")
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
        # Process-wide singleton -- always start each test from a known
        # CLOSED state so no prior test's breaker state leaks in.
        get_ollama_circuit_breaker("ollama").reset()

    def tearDown(self):
        # Critical: undo force_open() (or any trip) from this test so an
        # OPEN breaker never leaks into unrelated tests elsewhere in the
        # full suite.
        get_ollama_circuit_breaker("ollama").reset()

    async def test_breaker_open_sets_agents_circuit_open_true(self):
        # force_open() itself calls asyncio.run(), which cannot be invoked
        # from inside this already-running event loop (IsolatedAsyncioTestCase)
        # -- await the async variant directly instead.
        await get_ollama_circuit_breaker("ollama")._force_open_async()

        orch = _build(_InertStubOllama())
        resp = await orch.analyze(_inert_exchange(), bypass_cache=True)

        self.assertTrue(
            resp.agents_circuit_open,
            "AnalysisResponse.agents_circuit_open was not set True while the "
            "shared ollama circuit breaker was OPEN -- the flag is dead/inert.",
        )

    async def test_healthy_breaker_leaves_flag_false(self):
        # Negative control: a healthy (CLOSED) breaker must not read as open.
        self.assertFalse(get_ollama_circuit_breaker("ollama").is_open)

        orch = _build(_InertStubOllama())
        resp = await orch.analyze(_inert_exchange(), bypass_cache=True)

        self.assertFalse(
            resp.agents_circuit_open,
            "AnalysisResponse.agents_circuit_open was True for a healthy "
            "(CLOSED) circuit breaker -- false positive.",
        )


if __name__ == "__main__":
    unittest.main()
