"""The model-call pacer every OllamaClient shares (O11 of the 2026-10-17 audit,
reviews/2026-10-17-dual-mode-audit-opus55/evidence/inference_efficiency.md).

Every OllamaClient takes the process-wide `rate_limiter.get_token_limiter("ollama")`
and enters it before each attempt (`_send_with_retries`). Its default is
`RateLimiterRegistry._default_token_config`: a 1000-token bucket refilled at
1000/60 tokens a second, 100 tokens a call. That is a 10-call burst, then one
model call every 6 s, for every client in the process.

These tests drive real OllamaClient calls against a fake Ollama. The pacer runs
on a virtual clock: its `time.time()` reads the clock and its 0.1 s poll advances
it, so a 60 s pace costs no real time. The fake records the virtual time at which
each request reached it."""
import asyncio
import types
import unittest

import httpx

import harness.circuit_breaker as cb_module
import harness.ollama_client as mod
import harness.rate_limiter as rl
from harness.ollama_client import OllamaClient

_REAL_ASYNC_CLIENT = httpx.AsyncClient
_REAL_SLEEP = asyncio.sleep


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

        for owner, name, value in (
                (rl, "_registry", None), (cb_module, "_registry", None),
                (rl, "time", types.SimpleNamespace(time=lambda: self.now)),
                (rl, "asyncio", types.SimpleNamespace(sleep=virtual_sleep, Lock=asyncio.Lock))):
            self.addCleanup(setattr, owner, name, getattr(owner, name))
            setattr(owner, name, value)
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


class CurrentPacingPinTests(_VirtualPacer, unittest.IsolatedAsyncioTestCase):
    """What every run gets today, with no config: these pin the pacing as it is."""

    async def test_default_bucket_values(self):
        cfg = OllamaClient("http://fake-ollama:11434").rate_limiter.config
        self.assertEqual((cfg.enabled, cfg.max_tokens, cfg.tokens_per_request),
                         (True, 1000, 100))
        self.assertAlmostEqual(cfg.tokens_per_second, 1000.0 / 60.0)

    async def test_ten_call_burst_then_one_call_every_six_seconds(self):
        client = OllamaClient("http://fake-ollama:11434")
        await self.call(client, 20)
        offsets = self.offsets()
        self.assertEqual(offsets[:10], [0.0] * 10)
        for before, after in zip(offsets[9:], offsets[10:]):
            self.assertAlmostEqual(after - before, 6.0, delta=0.15)
        self.assertAlmostEqual(offsets[19], 60.0, delta=1.0)

    async def test_every_client_in_the_process_shares_one_bucket(self):
        first = OllamaClient("http://fake-ollama:11434")
        second = OllamaClient("http://other-ollama:11434", timeout_seconds=30)
        self.assertIs(first.rate_limiter, second.rate_limiter)
        await self.call(first, 10)
        await self.call(second)
        # The second client never called before, yet its first call is paced.
        self.assertAlmostEqual(self.offsets()[10], 6.0, delta=0.15)

    async def test_the_wait_has_no_bound(self):
        client = OllamaClient("http://fake-ollama:11434")
        await self.call(client, 10)
        client.rate_limiter.config.tokens_per_second = 0.0   # a bucket that never refills
        task = asyncio.create_task(self.call(client))
        await self.advance_until(task, 600.0)
        self.assertFalse(task.done())            # still polling after 10 minutes
        self.assertEqual(len(self.arrivals), 10)  # and nothing was sent
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task


if __name__ == "__main__":
    unittest.main()
