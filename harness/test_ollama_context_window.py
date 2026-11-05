"""Context-window guard: a call Ollama cut to fit the model's context window is
counted and surfaced, never used as an answer.

Measured on job 0574e29a0799 (Juice Shop 10 h r3, Ollama 0.40.13, 4096-token
default window, gemma4): Ollama cut 88 prompts of 4,098-8,118 tokens to 2,051
(prompt_eval_count reports the length after the cut) and answered them; 86 of the
answers were logged as normal responses. Those prompts ran 13,342-20,097
characters; uncut prompts ran 2.46-4.11 characters per token. Live on 0.40.13
with num_ctx 512, a 16,689-character prompt came back as prompt_eval_count 258.

The fake Ollama below serves /api/chat and /api/ps with those numbers. Negative
controls: a prompt below the window, and a cloud model, are not flagged."""
import asyncio
import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

import harness.ollama_client as mod
from harness.ollama_client import (
    ESTIMATED_LARGEST_PROMPT_TOKENS,
    OllamaClient,
    OllamaContextTruncatedError,
    context_overflow,
    is_cloud_model,
    model_stage,
    recommended_num_ctx,
)

_REAL_ASYNC_CLIENT = httpx.AsyncClient
# 16,000 characters: inside the r3 band of cut prompts (13,342-20,097).
LONG_PROMPT = "word " * 3200


class FakeOllama:
    """/api/chat answers with the configured counts and content; /api/ps lists
    `loaded` ({model name: context_length}). Every request is recorded."""

    def __init__(self, *, prompt_eval_count, eval_count=600, content=None, loaded=None,
                 ps_status=200, done_reason="stop"):
        self.prompt_eval_count = prompt_eval_count
        self.eval_count = eval_count
        self.done_reason = done_reason
        self.content = json.dumps({"ok": True}) if content is None else content
        self.loaded = dict(loaded or {})
        self.ps_status = ps_status
        self.paths: list[str] = []
        self.chat_bodies: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        if request.url.path == "/api/ps":
            if self.ps_status != 200:
                return httpx.Response(self.ps_status, json={"error": "boom"})
            return httpx.Response(200, json={"models": [
                {"name": name, "model": name, "context_length": length, "runner": "llamacpp"}
                for name, length in self.loaded.items()]})
        if request.url.path != "/api/chat":
            return httpx.Response(404, json={"error": "not the fake's endpoint"})
        self.chat_bodies.append(json.loads(request.content))
        return httpx.Response(200, json={
            "message": {"role": "assistant", "content": self.content}, "done": True,
            "done_reason": self.done_reason, "prompt_eval_count": self.prompt_eval_count,
            "eval_count": self.eval_count})

    def count(self, path: str) -> int:
        return self.paths.count(path)


def _install(testcase, fake: FakeOllama) -> None:
    class PatchedAsyncClient(_REAL_ASYNC_CLIENT):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(fake)
            super().__init__(*args, **kwargs)

    mod.httpx.AsyncClient = PatchedAsyncClient
    testcase.addCleanup(setattr, mod.httpx, "AsyncClient", _REAL_ASYNC_CLIENT)


class _FreshBreaker:
    """A fresh shared breaker registry per test, so a test's failures cannot open
    the breaker another test (or this one's assertion) reads."""

    def setUp(self):
        import harness.circuit_breaker as cb_module
        self._original_registry = cb_module._registry
        cb_module._registry = None

    def tearDown(self):
        import harness.circuit_breaker as cb_module
        cb_module._registry = self._original_registry


class ContextOverflowRuleTests(unittest.TestCase):
    """The pure rule, on the measured numbers."""

    def test_r3_cut_prompt_is_flagged(self):
        # The smallest and largest cut prompts of r3, at the 2,051 they came back as.
        for chars in (13342, 20097):
            self.assertEqual(context_overflow(2051, 1606, chars, 4096), "prompt")

    def test_live_512_window_cut_is_flagged(self):
        self.assertEqual(context_overflow(258, 40, 16689, 512), "prompt")

    def test_prompt_that_reaches_the_window_is_flagged(self):
        # A runner that cuts to the full window rather than half of it.
        self.assertEqual(context_overflow(4090, 3, 9000, 4096), "prompt")

    def test_prompt_and_reply_filling_the_window_is_flagged(self):
        # The one r3 call whose prompt and reply filled the window: 3396 + 700.
        self.assertEqual(context_overflow(3396, 700, 10000, 4096), "reply")

    def test_largest_uncut_r3_prompt_is_not_flagged(self):
        # NEGATIVE CONTROL: r3's largest uncut prompt (3,784 tokens) with a reply
        # that still fits, at the median ratio and at the highest ratio any uncut
        # prompt reached.
        self.assertIsNone(context_overflow(3784, 200, int(3784 * 2.94), 4096))
        self.assertIsNone(context_overflow(3784, 200, int(3784 * 4.11), 4096))
        self.assertIsNone(context_overflow(2100, 300, int(2100 * 4.11), 4096))

    def test_no_verdict_without_window_or_count(self):
        self.assertIsNone(context_overflow(2051, 600, 20000, None))
        self.assertIsNone(context_overflow(None, 600, 20000, 4096))

    def test_cloud_model_names(self):
        for name in ("gemma4:31b-cloud", "gpt-oss:120b-cloud", "glm-4.6:cloud", "X-CLOUD"):
            self.assertTrue(is_cloud_model(name), name)
        for name in ("qwen3:8b", "gemma4:latest", "cloudy-model:7b", "", None):
            self.assertFalse(is_cloud_model(name), name)

    def test_recommended_window(self):
        self.assertEqual(recommended_num_ctx(ESTIMATED_LARGEST_PROMPT_TOKENS), 16384)
        self.assertEqual(recommended_num_ctx(4096), 8192)


class GuardCallerTests(_FreshBreaker, unittest.IsolatedAsyncioTestCase):
    """OllamaClient.chat_json_metered, the call every harness model call goes
    through, against a fake Ollama."""

    def _client(self, fake, **kw):
        _install(self, fake)
        return OllamaClient(base_url="http://fake-ollama:11434", **kw)

    async def test_r3_shaped_cut_prompt_is_counted_and_not_returned(self):
        fake = FakeOllama(prompt_eval_count=2051, eval_count=600, loaded={"qwen3:8b": 4096})
        client = self._client(fake)
        with model_stage("critique"):
            with self.assertRaises(OllamaContextTruncatedError) as ctx:
                await client.chat_json_metered(model="qwen3:8b", system_prompt="s",
                                               user_prompt=LONG_PROMPT)
        err = ctx.exception
        self.assertEqual((err.kind, err.window, err.window_source), ("prompt", 4096, "api_ps"))
        self.assertIn("ollama.num_ctx: 16384", str(err))
        self.assertEqual(err.inference_usage["outcome"], "context_truncated")
        snap = client.metrics_snapshot()
        self.assertEqual(snap["client"]["context_truncated"], 1)
        self.assertEqual(snap["client"]["usable"], 0)
        self.assertEqual(snap["client"]["errors"], 1)
        self.assertEqual(snap["stages"]["critique"]["context_truncated"], 1)
        self.assertEqual(snap["totals"]["context_truncated"], 1)
        self.assertEqual(snap["context"]["truncated"], {"prompt": 1, "reply": 0})
        self.assertEqual(snap["context"]["windows"],
                         [{"model": "qwen3:8b", "context_length": 4096, "source": "api_ps"}])

    async def test_repeated_cuts_do_not_open_the_breaker_and_probe_once(self):
        fake = FakeOllama(prompt_eval_count=2051, loaded={"qwen3:8b": 4096})
        client = self._client(fake)
        for _ in range(5):   # past the breaker's failure threshold of 3
            with self.assertRaises(OllamaContextTruncatedError):
                await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt=LONG_PROMPT)
        self.assertTrue(client.circuit_breaker.is_closed)
        self.assertEqual(fake.count("/api/ps"), 1, "the window is cached per model")
        self.assertEqual(fake.count("/api/chat"), 5, "a cut prompt is never retried")
        self.assertEqual(client.metrics_snapshot()["client"]["context_truncated"], 5)

    async def test_configured_num_ctx_is_the_window_without_a_lookup(self):
        fake = FakeOllama(prompt_eval_count=4090, eval_count=6)
        client = self._client(fake, num_ctx=4096)
        with self.assertRaises(OllamaContextTruncatedError) as ctx:
            await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt="u" * 9000)
        self.assertEqual((ctx.exception.window, ctx.exception.window_source), (4096, "num_ctx"))
        self.assertEqual(fake.count("/api/ps"), 0)
        self.assertEqual(fake.chat_bodies[0]["options"]["num_ctx"], 4096)

    async def test_empty_reply_that_filled_the_window_is_a_context_fault(self):
        # r3's 151 empty-body errors followed 7-15k character prompts.
        fake = FakeOllama(prompt_eval_count=3396, eval_count=700, content="",
                          loaded={"qwen3:8b": 4096})
        client = self._client(fake)
        with self.assertRaises(OllamaContextTruncatedError) as ctx:
            await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt="u" * 10000)
        self.assertEqual(ctx.exception.kind, "reply")
        self.assertEqual(client.metrics_snapshot()["context"]["truncated"], {"prompt": 0, "reply": 1})

    async def test_prompt_below_the_window_is_not_counted(self):
        # NEGATIVE CONTROL: r3's largest uncut prompt, at 2.94 characters per token.
        fake = FakeOllama(prompt_eval_count=3784, eval_count=200, loaded={"qwen3:8b": 4096})
        client = self._client(fake)
        result = await client.chat_json_metered(model="qwen3:8b", system_prompt="s",
                                                user_prompt="u" * 11125)
        self.assertEqual(result.data, {"ok": True})
        self.assertEqual(result.measurement["outcome"], "ok")
        snap = client.metrics_snapshot()
        self.assertEqual(snap["client"]["context_truncated"], 0)
        self.assertEqual(snap["client"]["usable"], 1)
        self.assertEqual(snap["totals"]["max_prompt_tokens"], 3784)

    async def test_cloud_model_is_never_flagged_or_looked_up(self):
        # NEGATIVE CONTROL: a cloud model ignores num_ctx and is not in /api/ps;
        # counts that would overflow any local window must not be flagged.
        for num_ctx in (None, 4096):
            with self.subTest(num_ctx=num_ctx):
                fake = FakeOllama(prompt_eval_count=9000, eval_count=4000,
                                  loaded={"qwen3:8b": 4096})
                client = self._client(fake, num_ctx=num_ctx)
                result = await client.chat_json_metered(model="gemma4:31b-cloud", system_prompt="s",
                                                        user_prompt=LONG_PROMPT)
                self.assertEqual(result.data, {"ok": True})
                self.assertEqual(fake.count("/api/ps"), 0)
                self.assertEqual(client.metrics_snapshot()["client"]["context_truncated"], 0)

    async def test_small_call_costs_no_lookup(self):
        fake = FakeOllama(prompt_eval_count=742, eval_count=100, loaded={"qwen3:8b": 4096})
        client = self._client(fake)
        await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt="u")
        self.assertEqual(fake.count("/api/ps"), 0)

    async def test_failed_lookup_gives_no_verdict_and_is_throttled(self):
        # Best-effort: a /api/ps that fails never fails the call, and is not
        # asked again on every call. The retry interval is widened so the
        # result does not depend on how fast this machine runs the calls.
        fake = FakeOllama(prompt_eval_count=2051, ps_status=500)
        client = self._client(fake)
        with patch.object(mod, "_CONTEXT_PROBE_RETRY_SECONDS", 3600.0):
            for _ in range(3):
                result = await client.chat_json_metered(model="qwen3:8b", system_prompt="s",
                                                        user_prompt=LONG_PROMPT)
                self.assertEqual(result.data, {"ok": True})
        self.assertEqual(fake.count("/api/ps"), 1)

    async def test_model_reloaded_with_a_larger_window_is_looked_up_again(self):
        fake = FakeOllama(prompt_eval_count=742, loaded={"qwen3:8b": 4096})
        client = self._client(fake)
        # A window cached from an earlier load (no lookup is pending for it).
        client._context_windows["qwen3:8b"] = 2048
        fake.prompt_eval_count = 3000        # larger than the cached window
        result = await client.chat_json_metered(model="qwen3:8b", system_prompt="s",
                                                user_prompt="u" * 9000)
        self.assertEqual(result.data, {"ok": True})
        self.assertEqual(fake.count("/api/ps"), 1)
        self.assertEqual(client._context_windows["qwen3:8b"], 4096)


class BreakerClassificationTests(_FreshBreaker, unittest.IsolatedAsyncioTestCase):
    """Only outages (transport failures, timeouts, 5xx) count toward the shared
    circuit breaker. On r3, 151 empty bodies counted as outages and the breaker
    fast-failed 2,130 of 3,097 prompts; a 429 from Ollama cloud would do the same."""

    def _client(self, handler, **kw):
        _install(self, handler)
        return OllamaClient(base_url="http://fake-ollama:11434", **kw)

    async def test_empty_body_does_not_open_the_breaker(self):
        from harness.ollama_client import OllamaEmptyResponseError, OllamaError
        fake = FakeOllama(prompt_eval_count=500, eval_count=0, content="")
        client = self._client(fake)
        for _ in range(5):
            with self.assertRaises(OllamaEmptyResponseError) as ctx:
                await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt="u")
            self.assertIsInstance(ctx.exception, OllamaError)   # callers' except clauses hold
        self.assertTrue(client.circuit_breaker.is_closed)

    async def test_local_reply_stopped_for_length_is_a_context_fault(self):
        fake = FakeOllama(prompt_eval_count=500, eval_count=80, done_reason="length",
                          content='{"ok": tr')
        client = self._client(fake)
        with self.assertRaises(OllamaContextTruncatedError) as ctx:
            await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt="u")
        self.assertEqual(ctx.exception.kind, "reply")
        # The counts do not show a full window, so the message says what Ollama
        # reported instead of claiming the window filled.
        self.assertIn("done_reason length", str(ctx.exception))
        self.assertNotIn("filled", str(ctx.exception))

    async def test_cloud_reply_stopped_for_length_is_not_a_context_fault(self):
        # NEGATIVE CONTROL: a cloud model's length stop is its provider's output
        # cap, not this host's window; num_ctx advice would be wrong.
        fake = FakeOllama(prompt_eval_count=500, eval_count=80, done_reason="length")
        client = self._client(fake)
        result = await client.chat_json(model="gpt-oss:120b-cloud", system_prompt="s", user_prompt="u")
        self.assertEqual(result, {"ok": True})

    async def test_429_waits_out_retry_after_then_recovers(self):
        statuses = [429, 200]

        def handler(request):
            status = statuses.pop(0)
            if status == 429:
                return httpx.Response(429, headers={"Retry-After": "3"}, json={"error": "rate limited"})
            return httpx.Response(200, json={"message": {"content": '{"ok": true}'}, "done": True,
                                             "prompt_eval_count": 10, "eval_count": 5})
        client = self._client(handler)
        sleep = AsyncMock()
        with patch.object(mod, "_backoff_sleep", sleep):
            result = await client.chat_json(model="gpt-oss:120b-cloud", system_prompt="s", user_prompt="u")
        self.assertEqual(result, {"ok": True})
        self.assertEqual([c.args[0] for c in sleep.await_args_list], [3.0])
        self.assertEqual(client.model_retry_recovered_count, 1)

    async def test_429_with_a_long_retry_after_fails_now_and_spares_the_breaker(self):
        from harness.ollama_client import OllamaRateLimitedError
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(429, headers={"Retry-After": "600"}, json={"error": "quota"})
        client = self._client(handler)
        sleep = AsyncMock()
        with patch.object(mod, "_backoff_sleep", sleep):
            for _ in range(5):
                with self.assertRaises(OllamaRateLimitedError) as ctx:
                    await client.chat_json(model="gpt-oss:120b-cloud", system_prompt="s", user_prompt="u")
        self.assertEqual(ctx.exception.retry_after, 600.0)
        sleep.assert_not_awaited()
        self.assertEqual(len(requests), 5, "a quota-length wait is not retried")
        self.assertTrue(client.circuit_breaker.is_closed)

    async def test_5xx_outage_still_opens_the_breaker(self):
        # NEGATIVE CONTROL: the breaker still protects against a real outage.
        def handler(request):
            return httpx.Response(503, json={"error": "down"})
        client = self._client(handler, transient_retries=0)
        for _ in range(3):
            with self.assertRaises(mod.OllamaTransientError):
                await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt="u")
        self.assertTrue(client.circuit_breaker.is_open)

    def test_retry_after_header_forms(self):
        from email.utils import format_datetime
        from datetime import datetime, timedelta, timezone
        self.assertEqual(mod._retry_after_seconds("5"), 5.0)
        when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=20), usegmt=True)
        self.assertTrue(15.0 <= mod._retry_after_seconds(when) <= 20.0)
        for value in (None, "", "soon"):
            self.assertIsNone(mod._retry_after_seconds(value))


class PreflightTests(unittest.IsolatedAsyncioTestCase):
    """OllamaClient.context_preflight: the engagement-start warning."""

    def _client(self, fake, **kw):
        _install(self, fake)
        return OllamaClient(base_url="http://fake-ollama:11434", **kw)

    async def test_small_loaded_window_warns_with_the_fix(self):
        fake = FakeOllama(prompt_eval_count=0, loaded={"qwen3:8b": 4096})
        client = self._client(fake)
        with self.assertLogs("harness.ollama_client", "WARNING") as logs:
            report = await client.context_preflight(["qwen3:8b", "gemma4:31b-cloud"])
        self.assertEqual(report["largest_prompt"],
                         {"tokens": ESTIMATED_LARGEST_PROMPT_TOKENS, "source": "estimated"})
        rows = {r["model"]: r for r in report["models"]}
        self.assertEqual(rows["qwen3:8b"]["status"], "too_small")
        self.assertEqual(rows["qwen3:8b"]["context_length"], 4096)
        self.assertEqual(rows["gemma4:31b-cloud"]["status"], "cloud")
        self.assertEqual(len(report["warnings"]), 1)
        warning = report["warnings"][0]
        for part in ("qwen3:8b", "4096", "8118", "ollama.num_ctx: 16384", "config.local.yaml"):
            self.assertIn(part, warning)
        self.assertIn("ollama.num_ctx: 16384", "\n".join(logs.output))

    async def test_too_small_configured_num_ctx_warns(self):
        fake = FakeOllama(prompt_eval_count=0)
        client = self._client(fake, num_ctx=4096)
        with self.assertLogs("harness.ollama_client", "WARNING"):
            report = await client.context_preflight(["qwen3:8b"])
        self.assertIn("ollama.num_ctx is 4096", report["warnings"][0])
        self.assertEqual(fake.count("/api/ps"), 0)

    async def test_large_enough_window_does_not_warn(self):
        # NEGATIVE CONTROL.
        fake = FakeOllama(prompt_eval_count=0, loaded={"qwen3:8b": 16384})
        client = self._client(fake)
        report = await client.context_preflight(["qwen3:8b"])
        self.assertEqual(report["warnings"], [])
        self.assertEqual(report["models"][0]["status"], "ok")

    async def test_cloud_models_only_do_not_warn_or_look_up(self):
        # NEGATIVE CONTROL.
        fake = FakeOllama(prompt_eval_count=0)
        client = self._client(fake)
        report = await client.context_preflight(["gemma4:31b-cloud", "gpt-oss:120b-cloud"])
        self.assertEqual(report["warnings"], [])
        self.assertEqual({r["status"] for r in report["models"]}, {"cloud"})
        self.assertEqual(fake.count("/api/ps"), 0)

    async def test_model_not_loaded_is_unknown_not_a_warning(self):
        fake = FakeOllama(prompt_eval_count=0, loaded={})
        client = self._client(fake)
        report = await client.context_preflight(["qwen3:8b"])
        self.assertEqual(report["models"][0]["status"], "unknown")
        self.assertEqual(report["warnings"], [])

    async def test_measured_prompt_larger_than_the_estimate_is_used(self):
        fake = FakeOllama(prompt_eval_count=9000, eval_count=50, loaded={"qwen3:8b": 32768})
        client = self._client(fake)
        await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt="u" * 27000)
        report = await client.context_preflight(["qwen3:8b"])
        self.assertEqual(report["largest_prompt"], {"tokens": 9000, "source": "measured"})
        self.assertEqual(report["warnings"], [])


class SurfacedInRunRecordTests(_FreshBreaker, unittest.IsolatedAsyncioTestCase):
    """The count reaches the run's errors (degraded), model metrics, run manifest
    and job status summary, built the way investigate_engagement builds them: the
    preflight and the error come from the client, the blocks from
    RunInstrumentation."""

    async def _run(self, fake, *, cut: bool):
        from types import SimpleNamespace
        from harness.instrumentation import RunInstrumentation
        _install(self, fake)
        client = OllamaClient(base_url="http://fake-ollama:11434")
        instr = RunInstrumentation(SimpleNamespace(ollama=client))
        self.before = mod.context_truncated_count(client)
        instr.context_preflight = await mod.run_context_preflight(client, ["qwen3:8b"])
        prompt = LONG_PROMPT if cut else "u" * 9000
        try:
            await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt=prompt)
        except OllamaContextTruncatedError:
            pass
        self.error = mod.context_window_error(client, self.before)
        return instr

    def _finish(self, result):
        from harness.run_manifest import RunManifest
        from harness.job_status import JobStatusStore
        tmp = Path(tempfile.mkdtemp(prefix="ctxwin_"))
        self.addCleanup(shutil.rmtree, tmp, True)
        manifest = RunManifest({"run_id": "r1"}, tmp)
        manifest.finish("done", result=result)
        store = JobStatusStore(tmp / "jobs.db", owner="test")
        job = {"job_id": "j1", "host": "localhost", "base_url": "http://localhost",
               "status": "running", "started_at": time.time()}
        store.create(job)
        job.update(status="done", finished_at=time.time(), result=result)
        store.update(job)
        return manifest.data, job["result_summary"]

    async def test_cut_call_degrades_the_run_and_reaches_every_record(self):
        fake = FakeOllama(prompt_eval_count=2051, loaded={"qwen3:8b": 4096})
        instr = await self._run(fake, cut=True)
        error = self.error
        self.assertEqual(error["phase"], "model_context")
        self.assertIn("16384", error["error"])
        self.assertIn("1 model call(s)", error["error"])
        blocks = instr.result_blocks()
        self.assertEqual(blocks["instrumentation"]["model_metrics"]["client"]["context_truncated"], 1)
        self.assertNotIn("context_truncated", blocks["costs"], "costs keeps the AR-10 COST_KEYS")
        self.assertEqual(blocks["instrumentation"]["context_preflight"]["models"][0]["status"],
                         "too_small")
        manifest, summary = self._finish({"errors": [error], "degraded": True, **blocks})
        self.assertTrue(manifest["degraded"])
        self.assertEqual(manifest["operational_errors"][0]["phase"], "model_context")
        self.assertEqual(manifest["model_metrics"]["client"]["context_truncated"], 1)
        self.assertEqual(manifest["context_preflight"]["models"][0]["status"], "too_small")
        self.assertEqual(summary["context_truncated"], 1)

    async def test_call_below_the_window_leaves_the_run_clean(self):
        # NEGATIVE CONTROL.
        fake = FakeOllama(prompt_eval_count=3000, eval_count=300, loaded={"qwen3:8b": 16384})
        instr = await self._run(fake, cut=False)
        self.assertIsNone(self.error)
        blocks = instr.result_blocks()
        self.assertEqual(blocks["instrumentation"]["model_metrics"]["client"]["context_truncated"], 0)
        manifest, summary = self._finish({"errors": [], **blocks})
        self.assertEqual(manifest["operational_errors"], [])
        self.assertEqual(manifest["context_preflight"]["warnings"], [])
        self.assertEqual(summary["context_truncated"], 0)


class InvestigateEngagementTests(_FreshBreaker, unittest.TestCase):
    """investigate_engagement itself: the preflight runs at engagement start, and a
    cut call made during the run lands in the result's errors (degraded) and its
    model metrics.
    Reuses the JWT smoke fixture (canned discovery, stubbed target responses)."""

    @classmethod
    def setUpClass(cls):
        import os
        from harness import cache, store
        cls._tmp = tempfile.mkdtemp(prefix="ctxwin_investigate_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        from harness import cache, store
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _run(self, *, cut: bool) -> dict:
        from harness import test_smoke_investigate as smoke
        from harness.orchestrator import Orchestrator
        fake = FakeOllama(prompt_eval_count=4090 if cut else 3000, eval_count=6)
        _install(self, fake)
        orch = Orchestrator(smoke._test_config())
        # A configured window: the smoke fixture patches AsyncClient.get, so the
        # /api/ps lookup is not what this test exercises.
        orch.ollama.num_ctx = 4096
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        real_preflight = orch.ollama.context_preflight
        calls = []

        async def preflight_then_call(models):
            # The engagement's first model call, made right after the preflight.
            calls.append(sorted(models))
            report = await real_preflight(models)
            try:
                await orch.ollama.chat_json(model="qwen3:8b", system_prompt="s",
                                            user_prompt="u" * 9000)
            except OllamaContextTruncatedError:
                pass
            return report

        orch.ollama.context_preflight = preflight_then_call
        with patch("harness.engagement_builder.build_engagement", side_effect=smoke._canned_engagement), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=smoke._responder(True)):
            result = asyncio.run(orch.investigate_engagement(
                smoke.BASE_URL, smoke.ROLES, max_nodes=4, step_budget=4, max_chain_rounds=0))
        self.assertEqual(len(calls), 1, "the preflight runs once, at engagement start")
        self.assertIn("qwen3:8b", calls[0])
        return result

    def test_cut_call_is_a_degrading_error_in_the_result(self):
        result = self._run(cut=True)
        self.assertTrue(result["degraded"])
        self.assertEqual([e["phase"] for e in result["errors"]], ["model_context"])
        self.assertEqual(result["instrumentation"]["model_metrics"]["client"]["context_truncated"], 1)
        self.assertEqual(result["instrumentation"]["context_preflight"]["num_ctx"], 4096)

    def test_call_that_fits_adds_no_error(self):
        # NEGATIVE CONTROL.
        result = self._run(cut=False)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["instrumentation"]["model_metrics"]["client"]["context_truncated"], 0)


if __name__ == "__main__":
    unittest.main()
