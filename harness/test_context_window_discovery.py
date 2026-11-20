"""TOK-4: the prompt budget is seeded from the context window the model's server
reports, and fails closed when none is known.

Caller level: AgentManager builds the agents from the shipped config.yaml with
`ollama.api: openai` and no `ollama.num_ctx` (the live llama.cpp backend shape);
a stub llama-server reports a small per-slot window on GET /props and refuses,
as llama-server does, a prompt larger than it (HTTP 400
exceed_context_size_error). Negative control: the old path (no budget when no
num_ctx is configured) sends the prompt unfitted and overflows.
"""
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import yaml

from harness import cache, prompt_budget, store
from harness.agent_manager import AgentManager
from harness.models import HttpExchange
from harness.ollama_client import OllamaClient, backend_options
from harness.test_ollama_context_window import _FreshBreaker, _install

_HARNESS = Path(__file__).resolve().parent
N_CTX = 4096
_BODY = json.dumps([{"id": i, "email": f"user{i}@example.test", "role": "customer",
                     "address": f"{i} Example Street, Springfield", "totp": None}
                    for i in range(900)])
_EXCHANGE = HttpExchange(
    method="GET", url="http://localhost/api/Users?page=1",
    request_headers={"Host": "localhost", "Authorization": "Bearer usertok"},
    response_status=200, response_headers={"Content-Type": "application/json"},
    response_body=_BODY)


class StubLlamaServer:
    """GET /props reports `n_ctx` (or `props_status`); POST /v1/chat/completions
    refuses a prompt whose estimated tokens exceed n_ctx, else answers with no
    findings. GET /api/ps and POST /api/show serve `loaded` / `show`."""

    def __init__(self, n_ctx=N_CTX, *, props_status=200, loaded=None, show=None):
        self.n_ctx = n_ctx
        self.props_status = props_status
        self.loaded = dict(loaded or {})
        self.show = dict(show or {})
        self.requests: list[tuple[str, str]] = []
        self.prompt_tokens: list[int] = []

    def count(self, method, path) -> int:
        return self.requests.count((method, path))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append((request.method, path))
        if path == "/props":
            if self.props_status != 200:
                return httpx.Response(self.props_status, json={"error": "no props"})
            return httpx.Response(200, json={"default_generation_settings": {"n_ctx": self.n_ctx}})
        if path == "/api/ps":
            return httpx.Response(200, json={"models": [
                {"name": n, "model": n, "context_length": c} for n, c in self.loaded.items()]})
        if path == "/api/show":
            name = json.loads(request.content).get("model")
            if name not in self.show:
                return httpx.Response(404, json={"error": "model not found"})
            return httpx.Response(200, json={"model_info": {
                "general.architecture": "gemma3", "gemma3.context_length": self.show[name]}})
        if path in ("/v1/chat/completions", "/api/chat"):
            body = json.loads(request.content)
            tokens = sum(prompt_budget.estimate_tokens(m.get("content") or "")
                         for m in body.get("messages") or []) + 32
            self.prompt_tokens.append(tokens)
            if tokens > self.n_ctx:
                return httpx.Response(400, json={"error": {
                    "code": 400, "type": "exceed_context_size_error",
                    "n_prompt_tokens": tokens, "n_ctx": self.n_ctx,
                    "message": "the request exceeds the available context size"}})
            content = json.dumps({"findings": [], "components": []})
            if path == "/api/chat":
                return httpx.Response(200, json={
                    "message": {"role": "assistant", "content": content}, "done": True,
                    "done_reason": "stop", "prompt_eval_count": tokens, "eval_count": 5})
            return httpx.Response(200, json={
                "id": "c1", "object": "chat.completion", "model": body.get("model"),
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": content}}],
                "usage": {"prompt_tokens": tokens, "completion_tokens": 5,
                          "total_tokens": tokens + 5}})
        return httpx.Response(404, json={"error": "not found"})


def _client(cfg: dict) -> OllamaClient:
    """The client the way Orchestrator builds it from the config."""
    o = cfg["ollama"]
    return OllamaClient(base_url=o["base_url"], num_ctx=o.get("num_ctx"),
                        transient_retries=o.get("transient_retries", 2), **backend_options(o))


def _config(**ollama) -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg = copy.deepcopy(cfg)
    cfg["ollama"].update({"base_url": "http://stub-llama:8089", "transient_retries": 0})
    assert not cfg["ollama"].get("num_ctx"), "the shipped default leaves num_ctx unset"
    cfg["ollama"].update(ollama)
    return cfg


class _StoreIsolation:
    @classmethod
    def setUpClass(cls):
        import os
        cls._tmp = tempfile.mkdtemp(prefix="ctx_discovery_")
        cls._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH, cache._cache = cls._orig
        shutil.rmtree(cls._tmp, ignore_errors=True)


class LlamaServerDiscoveryTests(_StoreIsolation, _FreshBreaker, unittest.IsolatedAsyncioTestCase):
    def _agent(self, stub, name="info_disclosure", **ollama):
        _install(self, stub)
        cfg = _config(api="openai", **ollama)
        client = _client(cfg)
        client.audit_logger = MagicMock()
        manager = AgentManager(cfg, client)
        return manager.agents[name], client

    async def test_small_reported_window_fits_the_prompt(self):
        stub = StubLlamaServer()
        agent, client = self._agent(stub)
        report = await agent.run(_EXCHANGE, 6000, "")
        self.assertIsNone(report.raw_error)
        self.assertEqual(client.metrics_snapshot()["client"]["context_truncated"], 0)
        self.assertEqual(stub.count("POST", "/v1/chat/completions"), 1)
        self.assertLessEqual(stub.prompt_tokens[0], N_CTX)
        self.assertTrue(report.prompt_fit["fits"])
        self.assertEqual((report.prompt_fit["context_tokens"], report.prompt_fit["source"]),
                         (N_CTX, "discovered:props"))

    async def test_old_path_sends_unfitted_and_overflows(self):
        # NEGATIVE CONTROL: the pre-TOK-4 budget (from_config: None without
        # num_ctx) sends the prompt as is and the server refuses it.
        stub = StubLlamaServer()
        agent, client = self._agent(stub)
        agent.prompt_budget = prompt_budget.from_config(_config(api="openai"))
        self.assertIsNone(agent.prompt_budget)
        report = await agent.run(_EXCHANGE, 6000, "")
        self.assertIsNotNone(report.raw_error)
        self.assertEqual(client.metrics_snapshot()["client"]["context_truncated"], 1)
        self.assertGreater(stub.prompt_tokens[0], N_CTX)

    async def test_window_is_looked_up_once_per_client(self):
        stub = StubLlamaServer()
        agent, client = self._agent(stub)
        other = AgentManager(_config(api="openai"), client).agents["sqli"]
        for a in (agent, other, agent):
            await a.run(_EXCHANGE, 6000, "")
        self.assertEqual(stub.count("GET", "/props"), 1)
        self.assertEqual(client.model_context_truncated_count, 0)

    async def test_unknown_window_fits_to_the_fallback(self):
        # /props fails: never sent unfitted; fitted to unknown_context_tokens.
        stub = StubLlamaServer(props_status=404)
        agent, client = self._agent(stub)
        with self.assertLogs("harness.prompt_budget", "WARNING"):
            report = await agent.run(_EXCHANGE, 6000, "")
        self.assertIsNone(report.raw_error)
        self.assertEqual(client.model_context_truncated_count, 0)
        self.assertEqual((report.prompt_fit["context_tokens"], report.prompt_fit["source"]),
                         (prompt_budget.UNKNOWN_CONTEXT_TOKENS,
                          "fallback:prompt_budget.unknown_context_tokens"))

    async def test_configured_num_ctx_larger_than_the_server_is_capped(self):
        # num_ctx says 16384 but the server's slot holds 4096: the smaller wins.
        stub = StubLlamaServer()
        agent, client = self._agent(stub, num_ctx=16384)
        report = await agent.run(_EXCHANGE, 6000, "")
        self.assertIsNone(report.raw_error)
        self.assertEqual(client.model_context_truncated_count, 0)
        self.assertEqual(report.prompt_fit["context_tokens"], N_CTX)

    async def test_configured_num_ctx_matching_the_server_is_kept(self):
        stub = StubLlamaServer(n_ctx=16384)
        agent, _client = self._agent(stub, num_ctx=16384)
        report = await agent.run(_EXCHANGE, 6000, "")
        self.assertIsNone(report.raw_error)
        if report.prompt_fit is not None:
            self.assertEqual(report.prompt_fit["source"], "ollama.num_ctx")


class OllamaDiscoveryTests(_FreshBreaker, unittest.IsolatedAsyncioTestCase):
    async def _resolve(self, stub, model, **ollama):
        _install(self, stub)
        cfg = _config(**ollama)
        client = _client(cfg)
        return await prompt_budget.for_run(cfg).resolve(client, model), client

    async def test_loaded_model_window_from_api_ps(self):
        stub = StubLlamaServer(loaded={"qwen3:8b": 8192})
        budget, _ = await self._resolve(stub, "qwen3:8b")
        self.assertEqual((budget.context_tokens, budget.source), (8192, "discovered:api_ps"))
        self.assertEqual(stub.count("POST", "/api/show"), 0)

    async def test_unloaded_model_falls_back_capped_by_its_maximum(self):
        stub = StubLlamaServer(show={"tiny:1b": 2048, "qwen3:8b": 40960})
        budget, _ = await self._resolve(stub, "tiny:1b")
        self.assertEqual(budget.context_tokens, 2048)
        budget, _ = await self._resolve(stub, "qwen3:8b")
        self.assertEqual((budget.context_tokens, budget.source),
                         (4096, "fallback:prompt_budget.unknown_context_tokens"))

    async def test_cloud_model_window_from_api_show(self):
        stub = StubLlamaServer(show={"gpt-oss:120b-cloud": 131072})
        budget, client = await self._resolve(stub, "gpt-oss:120b-cloud", allow_cloud_models=True)
        self.assertEqual((budget.context_tokens, budget.source), (131072, "discovered:api_show"))
        await prompt_budget.for_run(_config()).resolve(client, "gpt-oss:120b-cloud")
        self.assertEqual(stub.count("POST", "/api/show"), 1, "cached per model")

    def test_invalid_fallback_is_a_config_fault(self):
        for bad in (0, -1, "4096", True, 2.5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                prompt_budget.for_run({"prompt_budget": {"unknown_context_tokens": bad}})


if __name__ == "__main__":
    unittest.main()
