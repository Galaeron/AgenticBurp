"""Caller-level coverage for AnalysisResponse.coordinator_fallback (RB-2 / P0.9).

orchestrator_detect.py's analyze() stamps coordinator_fallback on the response
it builds from coordinator.is_fallback_reason(reason), where reason comes from
_choose_agents' routing decision. test_coordinator.py's FallbackFlagTests
exercises is_fallback_reason and Coordinator.choose_agents directly; this
module is the missing caller-level leg -- through the real Orchestrator.
analyze() entry point -- so a regression in the *wiring* (not just the
predicate) would be caught. Offline: the model boundary (ollama) is stubbed,
no live Ollama/network, no answer-key/blind-target content is read.
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from harness import cache, coordinator, store
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.test_smoke_detection import _test_config

_HARNESS = Path(__file__).resolve().parent

# The substring that opens Coordinator._ROUTING_SYSTEM_PROMPT -- used to tell
# the coordinator's routing call apart from a per-agent detection call, both
# of which arrive at the same stub via ollama.chat_json_metered.
_COORDINATOR_ANCHOR = "coordinator in a security-testing harness"


def _inert_exchange(host: str = "inert.test") -> HttpExchange:
    """Deliberately signal-free: no query params, and a plain body/headers
    that don't match any fast_path pattern (URL, query, header or body), so
    fast_path_selector.select_agents returns None and _choose_agents falls
    through to the real coordinator.choose_agents LLM call -- the path this
    module needs to reach to exercise the fail-open branch."""
    return HttpExchange(
        url=f"http://{host}/hello",
        method="GET",
        request_headers={},
        request_body="",
        response_status=200,
        response_headers={},
        response_body="ok",
    )


class _RoutingStubOllama:
    """Controls only the coordinator's routing call. Every other (per-agent
    detection) call returns no findings, so this stays a routing test, not a
    detection test."""

    def __init__(self, *, fail_routing: bool):
        self._fail_routing = fail_routing

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        if _COORDINATOR_ANCHOR in system_prompt:
            if self._fail_routing:
                raise RuntimeError("simulated coordinator routing failure")
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
    cfg["server"]["allowed_hosts"] = list(cfg["server"]["allowed_hosts"]) + ["inert.test"]
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


class CoordinatorFallbackResponseFlagTests(unittest.IsolatedAsyncioTestCase):
    """RB-2: a coordinator fail-open must be observable on the AnalysisResponse
    itself (coordinator_fallback), not just in telemetry/logs."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="rb2_fallback_flag_")
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
        coordinator.reset_fail_open_stats()

    def tearDown(self):
        coordinator.reset_fail_open_stats()

    async def test_coordinator_routing_failure_sets_flag_and_increments_stats(self):
        orch = _build(_RoutingStubOllama(fail_routing=True))
        resp = await orch.analyze(_inert_exchange(), bypass_cache=True)

        self.assertTrue(
            resp.coordinator_fallback,
            "AnalysisResponse.coordinator_fallback was not set True on a forced "
            "coordinator routing failure -- the flag is dead/inert.",
        )
        stats = coordinator.fail_open_stats()
        self.assertEqual(
            stats["count"], 1,
            f"coordinator.fail_open_stats()['count'] did not increment for the "
            f"forced routing failure; got {stats!r}",
        )

    async def test_healthy_routing_leaves_flag_false(self):
        # Negative control: a normal routing decision (coordinator returns a
        # valid, non-empty dispatch) must NOT read as a fallback, and must not
        # touch the fail-open counters either.
        orch = _build(_RoutingStubOllama(fail_routing=False))
        resp = await orch.analyze(_inert_exchange(), bypass_cache=True)

        self.assertFalse(
            resp.coordinator_fallback,
            "AnalysisResponse.coordinator_fallback was True for a healthy routing "
            "decision -- false positive.",
        )
        self.assertEqual(coordinator.fail_open_stats()["count"], 0)


if __name__ == "__main__":
    unittest.main()
