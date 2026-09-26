"""Caller-level coverage for the ER-2 per-run trace summary.

orchestrator_detect.py's analyze() emits ONE evidence_ledger.EventType.RUN_SUMMARY
event at teardown, but ONLY for the call that owns (creates) its own
RunContext -- a nested/engagement call that has a run_context passed in must
emit zero, so a multi-exchange engagement never multiplies summaries per
exchange. This module exercises that wiring through the real
Orchestrator.analyze() entry point, mirroring test_degraded_circuit.py's
offline setup: the model boundary (ollama) is stubbed, no live Ollama/network,
no answer-key/blind-target content is read.

Critical: the ollama circuit breaker is a process-wide singleton shared
across the whole test suite. setUp/tearDown here reset it explicitly so an
OPEN state forced by the degraded-positive test can never leak into
unrelated tests. Likewise the default evidence ledger is process-wide;
these tests only ever read events for their own run_id, never assert on
the ledger's total contents.
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from harness import cache, store
from harness.circuit_breaker import get_ollama_circuit_breaker
from harness.evidence_ledger import EventType, get_default_ledger, reset_default_ledger
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext
from harness.test_smoke_detection import _test_config

_HARNESS = Path(__file__).resolve().parent


def _inert_exchange(host: str = "run-summary.test") -> HttpExchange:
    """Signal-free exchange -- content doesn't matter for this test, only
    that analyze() runs the real teardown path far enough to reach the
    RUN_SUMMARY emit in orchestrator_detect.py."""
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
    result with a known, non-zero token cost -- no findings, no fail-open,
    so tokens_total on the summary is deterministic and traceable to real
    recorded calls, not routing fallback or detection noise."""

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        if "coordinator in a security-testing harness" in system_prompt:
            return OllamaResult(
                data={"dispatch": ["misconfig"], "reason": "plausible config surface"},
                prompt_tokens=5, completion_tokens=5,
            )
        return OllamaResult(data={"findings": [], "components": []},
                            prompt_tokens=5, completion_tokens=5)

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        result = await self.chat_json_metered(model, system_prompt, user_prompt, temperature)
        return result.data


def _build(ollama) -> Orchestrator:
    cfg = _test_config()
    cfg["server"]["allowed_hosts"] = list(cfg["server"]["allowed_hosts"]) + ["run-summary.test"]
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


class RunSummaryLedgerTests(unittest.IsolatedAsyncioTestCase):
    """ER-2: one canonical RUN_SUMMARY event per standalone run, carrying the
    effort breakdown, elapsed wall-clock, the B2-1 degraded flag, and
    validator/leg dispatch counts -- and zero when analyze() is nested inside
    an engagement's shared run_context."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="er2_run_summary_")
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
        # Process-wide singletons -- always start each test from a known,
        # empty/CLOSED state so no prior test's breaker state or accumulated
        # ledger events leak in (the default ledger is shared across the
        # whole process/test suite; reset_default_ledger is the documented
        # seam for exactly this kind of per-test isolation).
        get_ollama_circuit_breaker("ollama").reset()
        reset_default_ledger()

    def tearDown(self):
        # Critical: undo force_open() (or any trip) from this test so an
        # OPEN breaker never leaks into unrelated tests elsewhere in the
        # full suite. Also leave the default ledger clean for whatever
        # runs next.
        get_ollama_circuit_breaker("ollama").reset()
        reset_default_ledger()

    def _run_summaries(self):
        ledger = get_default_ledger()
        return [e for e in ledger.to_dicts() if e["event_type"] == EventType.RUN_SUMMARY.value]

    async def test_standalone_run_emits_exactly_one_run_summary(self):
        orch = _build(_InertStubOllama())
        resp = await orch.analyze(_inert_exchange(), bypass_cache=True)

        summaries = self._run_summaries()
        self.assertEqual(
            len(summaries), 1,
            f"expected exactly one RUN_SUMMARY event for this standalone run, got {len(summaries)}",
        )
        ev = summaries[0]
        self.assertEqual(ev["data"]["tokens_total"], resp.effort_spent_tokens)
        self.assertEqual(ev["data"]["degraded"], resp.agents_circuit_open)

    async def test_healthy_run_reports_not_degraded_and_nonzero_elapsed(self):
        # Negative control: a healthy (CLOSED) breaker reports degraded=False
        # and elapsed_s must be non-zero (the clock genuinely spans the call).
        self.assertFalse(get_ollama_circuit_breaker("ollama").is_open)

        orch = _build(_InertStubOllama())
        await orch.analyze(_inert_exchange(), bypass_cache=True)

        summaries = self._run_summaries()
        self.assertEqual(len(summaries), 1)
        ev = summaries[0]
        self.assertFalse(ev["data"]["degraded"])
        self.assertGreater(ev["data"]["elapsed_s"], 0.0)
        self.assertIn("validator_count", ev["data"])
        self.assertIn("leg_count", ev["data"])
        self.assertIn("tokens_breakdown", ev["data"])

    async def test_degraded_run_reports_degraded_true(self):
        # force_open() itself calls asyncio.run(), which cannot be invoked
        # from inside this already-running event loop (IsolatedAsyncioTestCase)
        # -- await the async variant directly instead.
        await get_ollama_circuit_breaker("ollama")._force_open_async()

        orch = _build(_InertStubOllama())
        await orch.analyze(_inert_exchange(), bypass_cache=True)

        summaries = self._run_summaries()
        self.assertEqual(len(summaries), 1)
        self.assertTrue(summaries[0]["data"]["degraded"])

    async def test_engagement_nested_analyze_emits_zero_run_summaries(self):
        # Multiplication guard: an analyze() call that receives an ALREADY
        # existing run_context (mimicking the engagement path, where a single
        # run_context is shared across many per-exchange analyze() calls)
        # must not itself own the run, and must therefore emit zero
        # RUN_SUMMARY events -- never one per exchange.
        orch = _build(_InertStubOllama())
        shared_run_context = RunContext.create(
            allowed_hosts=orch.allowed_hosts, config=orch.config)

        await orch.analyze(
            _inert_exchange(), bypass_cache=True, run_context=shared_run_context)

        self.assertEqual(
            len(self._run_summaries()), 0,
            "a nested analyze() call sharing an engagement's run_context "
            "emitted a RUN_SUMMARY -- it must only be emitted by the call "
            "that owns (creates) the run, or summaries multiply per-exchange.",
        )


if __name__ == "__main__":
    unittest.main()
