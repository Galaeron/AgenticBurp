"""The model-call pacer every OllamaClient shares (O11 of the 2026-10-17 audit,
reviews/2026-10-17-dual-mode-audit-opus55/evidence/inference_efficiency.md).

Every OllamaClient takes the process-wide `rate_limiter.get_token_limiter("ollama")`
and enters it before each attempt (`_send_with_retries`). Each call costs 100
tokens whatever its size, so the bucket counts calls. Its shipped values
(rate_limiter.PACER_DEFAULTS, the ones it has always had) are a 10-call burst,
then one model call every 6 s, for every client in the process. `ollama.rate_limit`
sets them; a call not admitted within `max_wait_seconds` (300 s) fails unsent with
OllamaPacerTimeoutError; the run manifest records the values in force.

Most tests drive real OllamaClient calls against a fake Ollama. The pacer runs on
a virtual clock: its `time.time()` reads the clock and its 0.1 s poll advances it,
so a 60 s pace costs no real time. The fake records the virtual time at which
each request reached it."""
import asyncio
import contextlib
import json
import os
import shutil
import tempfile
import types
import unittest
from pathlib import Path

import httpx
import yaml

import harness.circuit_breaker as cb_module
import harness.ollama_client as mod
import harness.rate_limiter as rl
from harness.ollama_client import OllamaClient, OllamaPacerTimeoutError, parse_rate_limit
from harness.run_manifest import RunManifest

_REAL_ASYNC_CLIENT = httpx.AsyncClient
_REAL_SLEEP = asyncio.sleep
_CONFIG = Path(__file__).parent / "config.yaml"
_URL = "http://fake-ollama:11434"


def _fresh_registries(testcase) -> None:
    """A fresh pacer and breaker registry for this test, restored afterwards."""
    for owner in (rl, cb_module):
        testcase.addCleanup(setattr, owner, "_registry", owner._registry)
        owner._registry = None


class _VirtualPacer:
    """Fresh pacer and breaker registries, the pacer on a virtual clock, and a
    fake Ollama recording the virtual arrival time of each /api/chat request."""

    def setUp(self):
        super().setUp()
        self.now = 1_000_000.0

        async def virtual_sleep(delay, result=None):
            self.now += delay
            await _REAL_SLEEP(0)
            return result

        _fresh_registries(self)
        for name, value in (
                ("time", types.SimpleNamespace(time=lambda: self.now)),
                ("asyncio", types.SimpleNamespace(sleep=virtual_sleep, Lock=asyncio.Lock))):
            self.addCleanup(setattr, rl, name, getattr(rl, name))
            setattr(rl, name, value)
        self.arrivals: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.arrivals.append(self.now)
            return httpx.Response(200, json={
                "message": {"role": "assistant", "content": '{"ok": true}'}, "done": True,
                "done_reason": "stop", "prompt_eval_count": 40, "eval_count": 5})

        class PatchedAsyncClient(_REAL_ASYNC_CLIENT):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        self.addCleanup(setattr, mod.httpx, "AsyncClient", _REAL_ASYNC_CLIENT)
        mod.httpx.AsyncClient = PatchedAsyncClient

    def offsets(self) -> list[float]:
        return [round(t - self.arrivals[0], 1) for t in self.arrivals]

    async def call(self, client, n=1):
        for _ in range(n):
            await client.chat_json("qwen3:8b", "Reply with JSON.", "ping")

    async def advance_until(self, task, seconds):
        """Let `task` run until the virtual clock has moved `seconds` (or it ends)."""
        stop = self.now + seconds
        while self.now < stop and not task.done():
            await _REAL_SLEEP(0)

    async def call_within(self, client, seconds=600.0):
        """One call, run until it ends or `seconds` of virtual time pass; then
        await it. Fails (instead of hanging) when the call is still waiting."""
        task = asyncio.create_task(self.call(client))
        await self.advance_until(task, seconds)
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            self.fail(f"the call was still waiting after {seconds:g} virtual seconds")
        await task


class DefaultPacingTests(_VirtualPacer, unittest.IsolatedAsyncioTestCase):
    """The shipped values, which O11 keeps: a client with no `rate_limit`."""

    async def test_default_bucket_values(self):
        cfg = OllamaClient(_URL).rate_limiter.config
        self.assertEqual((cfg.enabled, cfg.max_tokens, cfg.tokens_per_request, cfg.max_wait_seconds),
                         (True, 1000, 100, 300.0))
        self.assertAlmostEqual(cfg.tokens_per_second, 1000.0 / 60.0)
        state = rl.pacer_state()
        self.assertEqual({k: state[k] for k in ("enabled", "burst_calls", "calls_per_minute",
                                                "max_wait_seconds", "poll_seconds")},
                         {"enabled": True, "burst_calls": 10, "calls_per_minute": 10,
                          "max_wait_seconds": 300.0, "poll_seconds": 0.1})

    async def test_ten_call_burst_then_one_call_every_six_seconds(self):
        client = OllamaClient(_URL)
        await self.call(client, 20)
        offsets = self.offsets()
        self.assertEqual(offsets[:10], [0.0] * 10)
        for before, after in zip(offsets[9:], offsets[10:]):
            self.assertAlmostEqual(after - before, 6.0, delta=0.15)
        self.assertAlmostEqual(offsets[19], 60.0, delta=1.0)
        state = rl.pacer_state()
        self.assertEqual((state["admitted"], state["waited"], state["timed_out"]), (20, 10, 0))
        self.assertAlmostEqual(state["wait_seconds_total"], 60.0, delta=1.5)

    async def test_every_client_in_the_process_shares_one_bucket(self):
        first = OllamaClient(_URL)
        second = OllamaClient("http://other-ollama:11434", timeout_seconds=30)
        self.assertIs(first.rate_limiter, second.rate_limiter)
        await self.call(first, 10)
        await self.call(second)
        # The second client never called before, yet its first call is paced.
        self.assertAlmostEqual(self.offsets()[10], 6.0, delta=0.15)


class WaitBoundTests(_VirtualPacer, unittest.IsolatedAsyncioTestCase):
    """The wait for a token ends at max_wait_seconds (it had no bound before O11)."""

    async def _drain(self):
        client = OllamaClient(_URL)
        await self.call(client, 10)
        client.rate_limiter.config.tokens_per_second = 0.0   # a bucket that never refills
        return client

    async def test_a_call_not_admitted_in_300_s_fails_unsent(self):
        client = await self._drain()
        started = self.now
        with self.assertRaises(OllamaPacerTimeoutError) as ctx:
            await self.call_within(client)
        self.assertAlmostEqual(self.now - started, 300.0, delta=0.5)
        self.assertEqual(ctx.exception.max_wait_seconds, 300.0)
        self.assertIn("ollama.rate_limit", str(ctx.exception))
        self.assertEqual(len(self.arrivals), 10, "nothing was sent")
        self.assertEqual(client.model_error_count, 1, "one failed call, not retried")
        receipt = ctx.exception.inference_usage
        # The wait is queue time (measured on the real monotonic clock, so small here).
        self.assertIsNotNone(receipt["queue_ms"])
        self.assertEqual(receipt["outcome"], "error")
        breaker = cb_module.current_ollama_breaker("ollama")
        self.assertEqual((breaker.is_open, breaker.get_stats().total_failures), (False, 0),
                         "a pacer timeout is not an outage")
        self.assertEqual(rl.pacer_state()["timed_out"], 1)

    async def test_the_breaker_would_count_it_without_the_exclusion(self):
        # NEGATIVE CONTROL for the exclusion: the same timeout, with
        # OllamaPacerTimeoutError dropped from the breaker's exclusions, is a failure.
        client = await self._drain()
        breaker = cb_module.current_ollama_breaker("ollama")
        breaker.config.excluded_exceptions = tuple(
            e for e in breaker.config.excluded_exceptions if e is not OllamaPacerTimeoutError)
        with self.assertRaises(OllamaPacerTimeoutError):
            await self.call_within(client)
        self.assertEqual(breaker.get_stats().total_failures, 1)

    async def test_without_a_bound_the_wait_never_ends(self):
        # NEGATIVE CONTROL: max_wait_seconds None (the generic limiter default,
        # and every model call before O11) still waits after 10 virtual minutes.
        client = await self._drain()
        client.rate_limiter.config.max_wait_seconds = None
        task = asyncio.create_task(self.call(client))
        await self.advance_until(task, 600.0)
        self.assertFalse(task.done())
        self.assertEqual(len(self.arrivals), 10)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task


class RateLimitConfigTests(_VirtualPacer, unittest.IsolatedAsyncioTestCase):
    """`ollama.rate_limit` sets the shared pacer."""

    def test_shipped_config_keeps_the_old_values(self):
        cfg = yaml.safe_load(_CONFIG.read_text(encoding="utf-8"))
        shipped = parse_rate_limit(cfg["ollama"]["rate_limit"])
        self.assertEqual(shipped, rl.pacer_config())
        self.assertEqual(shipped, rl.RateLimiterRegistry()._default_token_config)
        self.assertEqual((shipped.max_tokens, shipped.tokens_per_request, shipped.max_wait_seconds),
                         (1000, 100, 300.0))
        self.assertAlmostEqual(shipped.tokens_per_second, 1000.0 / 60.0)

    async def test_a_configured_pace_applies(self):
        client = OllamaClient(_URL, rate_limit={"burst_calls": 2, "calls_per_minute": 60})
        await self.call(client, 5)
        for got, want in zip(self.offsets(), [0.0, 0.0, 1.0, 2.0, 3.0]):
            self.assertAlmostEqual(got, want, delta=0.15)

    async def test_unconfigured_the_same_calls_all_start_at_once(self):
        # NEGATIVE CONTROL for the test above: the shipped 10-call burst.
        await self.call(OllamaClient(_URL), 5)
        self.assertEqual(self.offsets(), [0.0] * 5)

    async def test_disabled_admits_every_call(self):
        client = OllamaClient(_URL, rate_limit={"enabled": False})
        await self.call(client, 30)
        self.assertEqual(self.offsets(), [0.0] * 30)
        state = rl.pacer_state()
        self.assertEqual((state["enabled"], state["waited"]), (False, 0))

    def test_the_last_configured_client_sets_the_pace_for_all(self):
        first = OllamaClient(_URL, rate_limit={"burst_calls": 2, "calls_per_minute": 60})
        second = OllamaClient(_URL, rate_limit={"burst_calls": 5})
        OllamaClient(_URL)   # no rate_limit: leaves the pacer as it is
        self.assertIs(first.rate_limiter, second.rate_limiter)
        state = rl.pacer_state()
        self.assertEqual((state["burst_calls"], state["calls_per_minute"]), (5, 10))

    def test_bad_values_are_refused_and_leave_the_pacer_unchanged(self):
        OllamaClient(_URL, rate_limit={"burst_calls": 4})
        before = rl.pacer_state()
        for bad in ("fast", [], {"burst": 3}, {"enabled": "yes"}, {"burst_calls": 0},
                    {"burst_calls": 1.5}, {"burst_calls": True}, {"calls_per_minute": 0},
                    {"calls_per_minute": float("inf")}, {"calls_per_minute": "10"},
                    {"max_wait_seconds": -1}, {"max_wait_seconds": None},
                    {"max_wait_seconds": float("nan")}):
            with self.subTest(bad=bad), self.assertRaises(ValueError) as ctx:
                OllamaClient(_URL, rate_limit=bad)
            self.assertIn("ollama.rate_limit", str(ctx.exception))
        self.assertEqual(rl.pacer_state(), before)

    def test_valid_values_parse(self):
        # NEGATIVE CONTROL for the refusals: the nearest valid values are accepted.
        for good in ({}, {"enabled": False}, {"burst_calls": 1}, {"calls_per_minute": 0.5},
                     {"max_wait_seconds": 1}):
            with self.subTest(good=good):
                self.assertIsNotNone(parse_rate_limit(good))
        self.assertIsNone(parse_rate_limit(None))


class OrchestratorWiringTests(unittest.TestCase):
    """The orchestrator passes the config's `ollama.rate_limit` to its client."""

    @classmethod
    def setUpClass(cls):
        from harness import cache, store
        cls._tmp = tempfile.mkdtemp(prefix="model_pacer_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        from harness import cache, store
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def setUp(self):
        from harness.test_ollama_context_window import FakeOllama, _install
        _fresh_registries(self)
        _install(self, FakeOllama(prompt_eval_count=10))

    def _orchestrator(self, rate_limit):
        from harness import test_smoke_investigate as smoke
        from harness.orchestrator import Orchestrator
        cfg = smoke._test_config()
        if rate_limit is None:
            cfg["ollama"].pop("rate_limit", None)
        else:
            cfg["ollama"]["rate_limit"] = rate_limit
        return Orchestrator(cfg)

    def _pace(self):
        state = rl.pacer_state()
        return state["burst_calls"], state["calls_per_minute"], state["max_wait_seconds"]

    def test_the_config_block_sets_the_pacer(self):
        orch = self._orchestrator({"burst_calls": 3, "calls_per_minute": 30, "max_wait_seconds": 45})
        self.assertIs(orch.ollama.rate_limiter, rl.get_token_limiter(rl.PACER_NAME))
        self.assertEqual(self._pace(), (3, 30, 45))

    def test_without_the_block_the_shipped_values_apply(self):
        # NEGATIVE CONTROL: no block, the pacer keeps its shipped values.
        self._orchestrator(None)
        self.assertEqual(self._pace(), (10, 10, 300.0))

    def test_a_bad_block_stops_the_orchestrator(self):
        with self.assertRaises(ValueError):
            self._orchestrator({"calls_per_minute": -1})


class ManifestTests(_VirtualPacer, unittest.IsolatedAsyncioTestCase):
    """The run manifest records the pacer in force and the run's share of its counters."""

    async def test_manifest_records_live_values_and_the_runs_counters(self):
        # The live pacer, not the config dict handed to the manifest.
        client = OllamaClient(_URL, rate_limit={"burst_calls": 4, "calls_per_minute": 20,
                                                "max_wait_seconds": 60})
        await self.call(client, 2)          # before the run: 2 of the 4-call burst
        config = {"ollama": {"rate_limit": {"burst_calls": 10}}}
        with tempfile.TemporaryDirectory() as td:
            run = RunManifest.start(run_id="pacer", target_identifier="fixture", config=config,
                                    output_dir=td, repo_root=td)
            await self.call(client, 4)      # 2 from the burst, then 2 paced 3 s apart
            run.finish("completed")
            data = json.loads(Path(run.path).read_text(encoding="utf-8"))
        block = data["model_rate_limit"]
        start = block["at_start"]
        self.assertEqual({k: start[k] for k in ("enabled", "burst_calls", "calls_per_minute",
                                                "max_wait_seconds", "admitted", "waited")},
                         {"enabled": True, "burst_calls": 4, "calls_per_minute": 20,
                          "max_wait_seconds": 60, "admitted": 2, "waited": 0})
        self.assertEqual(block["at_finish"]["admitted"], 6)
        during = block["during_run"]
        self.assertEqual(set(during), set(rl.PACER_COUNTERS))
        self.assertEqual((during["admitted"], during["waited"], during["timed_out"]), (4, 2, 0))
        self.assertAlmostEqual(during["wait_seconds_total"], 6.0, delta=0.3)


if __name__ == "__main__":
    unittest.main()
