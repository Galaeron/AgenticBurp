"""`ollama.api: openai` (llama.cpp's llama-server and other OpenAI-compatible
servers) and `ollama.max_output_tokens`, caller-level.

Every test builds the real Orchestrator (or AnalysisPipeline / writeups caller)
from the shipped config.yaml, points `ollama.base_url` at a loopback fake server
that speaks both wire protocols, and drives the client the caller built. No real
model is called. Controls: with the new keys unset the bytes on the wire are
exactly the pre-existing Ollama payload; a reply that stops for length UNDER the
cap is still a context fault, not a capped reply; non-JSON content is still an
invalid-JSON fault; a 400 that is not a context-size refusal is a plain error.
"""
from __future__ import annotations

import copy
import json
import logging
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import yaml

from harness import circuit_breaker
from harness.ollama_client import (OllamaContextTruncatedError, OllamaError, OllamaInvalidJSONError,
                                   OllamaOutputCappedError, backend_setting)

_TRACE = "SENTINEL-REASONING-TRACE {\"verdict\": \"from-the-trace\"}"


def _openai_reply(content="{\"verdict\": \"ok\"}", *, finish="stop", prompt_tokens=7,
                  completion_tokens=3, reasoning=None) -> dict:
    message = {"role": "assistant", "content": content}
    if reasoning is not None:
        message["reasoning_content"] = reasoning
    return {"id": "chatcmpl-1", "object": "chat.completion", "model": "gpt-oss-20b",
            "choices": [{"index": 0, "finish_reason": finish, "message": message}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                      "total_tokens": prompt_tokens + completion_tokens},
            "timings": {"prompt_ms": 12.5, "predicted_ms": 40.0}}


class _FakeServer:
    """Loopback server speaking Ollama (/api/chat, /api/tags) and the
    OpenAI-compatible API (/v1/chat/completions, /v1/models, /props). Records
    every request as (method, path, raw body)."""

    def __init__(self):
        self.requests: list[tuple[str, str, bytes]] = []
        self.chat_status = 200
        self.chat_reply: dict = _openai_reply()
        self.ollama_reply: dict = {"message": {"role": "assistant", "content": "{\"verdict\": \"ok\"}"},
                                   "done": True, "prompt_eval_count": 7, "eval_count": 3}
        self.props: dict = {"default_generation_settings": {"n_ctx": 16384}}
        # Replies served in order before chat_reply / ollama_reply (one per POST).
        self.chat_replies: list[dict] = []
        self.ollama_replies: list[dict] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self, status, body):
                out = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_GET(self):
                fake.requests.append(("GET", self.path, b""))
                if self.path == "/v1/models":
                    self._answer(200, {"object": "list", "data": [{"id": "gpt-oss-20b", "object": "model"}]})
                elif self.path == "/props":
                    self._answer(200, fake.props)
                elif self.path == "/api/tags":
                    self._answer(200, {"models": [{"name": "m:latest"}]})
                else:
                    self._answer(404, {"error": "not found"})

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                fake.requests.append(("POST", self.path, body))
                if self.path == "/v1/chat/completions":
                    self._answer(fake.chat_status,
                                 fake.chat_replies.pop(0) if fake.chat_replies else fake.chat_reply)
                elif self.path == "/api/chat":
                    self._answer(200, fake.ollama_replies.pop(0) if fake.ollama_replies
                                 else fake.ollama_reply)
                else:
                    self._answer(404, {"error": "not found"})

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def paths(self, method="POST") -> list[str]:
        return [path for m, path, _ in self.requests if m == method]

    def bodies(self) -> list[dict]:
        return [json.loads(body) for m, _, body in self.requests if m == "POST"]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _shipped_config() -> dict:
    with open(Path(__file__).resolve().parent / "config.yaml", encoding="utf-8") as stream:
        return yaml.safe_load(stream) or {}


_OPENAI = {"api": "openai", "max_output_tokens": 2048, "reasoning_effort": "low", "num_ctx": 16384}


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fake = _FakeServer()
        self.addCleanup(self.fake.close)

    def _config(self, **ollama_overrides) -> dict:
        config = copy.deepcopy(_shipped_config())
        for key in ("api", "max_output_tokens", "reasoning_effort"):
            self.assertNotIn(key, config["ollama"], "the shipped default must stay unset")
        config["ollama"]["base_url"] = self.fake.base_url
        config["ollama"]["transient_retries"] = 0
        config["ollama"].update(ollama_overrides)
        return config

    def _orchestrator(self, **ollama_overrides):
        from harness.orchestrator import Orchestrator
        orchestrator = Orchestrator(self._config(**ollama_overrides))
        orchestrator.ollama.audit_logger = MagicMock()
        return orchestrator

    @staticmethod
    def _breaker_failures() -> int:
        return circuit_breaker.current_ollama_breaker("ollama").get_stats().total_failures


class OpenAIWireTests(_Base):
    async def test_payload_targets_chat_completions_with_json_mode_cap_and_effort(self):
        client = self._orchestrator(**_OPENAI).ollama
        parsed = await client.chat_json("gpt-oss-20b", "sys", "user", seed=7)
        self.assertEqual(parsed, {"verdict": "ok"})
        self.assertEqual(self.fake.paths(), ["/v1/chat/completions"])
        self.assertEqual(self.fake.bodies()[0], {
            "model": "gpt-oss-20b",
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "user"}],
            "stream": False, "temperature": 0.1, "response_format": {"type": "json_object"},
            "seed": 7, "max_tokens": 2048, "chat_template_kwargs": {"reasoning_effort": "low"}})

    async def test_minimal_openai_payload_sends_no_ollama_keys(self):
        client = self._orchestrator(api="openai").ollama
        await client.chat_json("gpt-oss-20b", "sys", "user")
        sent = self.fake.bodies()[0]
        self.assertEqual(set(sent), {"model", "messages", "stream", "temperature", "response_format"})

    async def test_usage_and_timings_feed_the_same_metrics_as_ollama(self):
        self.fake.chat_reply = _openai_reply(prompt_tokens=1200, completion_tokens=80)
        client = self._orchestrator(**_OPENAI).ollama
        result = await client.chat_json_metered("gpt-oss-20b", "sys", "user")
        self.assertEqual(result.data, {"verdict": "ok"})
        self.assertEqual((result.prompt_tokens, result.completion_tokens), (1200, 80))
        self.assertAlmostEqual(result.measurement["generation_ms"], 40.0)
        snapshot = client.metrics_snapshot()
        self.assertEqual(snapshot["totals"]["prompt_tokens"], 1200)
        self.assertEqual(snapshot["totals"]["completion_tokens"], 80)
        self.assertEqual(snapshot["client"]["completed"], 1)
        self.assertEqual(snapshot["backend"], {"api": "openai", "max_output_tokens": 2048,
                                               "reasoning_effort": "low", "allow_cloud_models": False})

    async def test_reasoning_content_is_dropped_and_only_its_length_kept(self):
        self.fake.chat_reply = _openai_reply(reasoning=_TRACE)
        client = self._orchestrator(**_OPENAI).ollama
        with self.assertLogs("harness", level=logging.DEBUG) as logs:
            logging.getLogger("harness").debug("capture start")
            parsed, raw = await client._chat("gpt-oss-20b", "sys", "user")
        self.assertEqual(parsed, {"verdict": "ok"})
        self.assertNotIn("thinking", raw["message"])
        self.assertNotIn("SENTINEL", json.dumps(raw, default=str))
        self.assertEqual(raw["_inference_measurement"]["thinking_chars"], len(_TRACE))
        self.assertNotIn("SENTINEL", "\n".join(logs.output))

    async def test_non_json_content_is_an_invalid_json_fault_not_a_capped_one(self):
        self.fake.chat_reply = _openai_reply(content="I think the answer is yes")
        client = self._orchestrator(**_OPENAI).ollama
        with self.assertRaises(OllamaInvalidJSONError) as caught:
            await client.chat_json("gpt-oss-20b", "sys", "user")
        self.assertNotIsInstance(caught.exception, OllamaOutputCappedError)
        self.assertEqual(client.metrics_snapshot()["client"]["output_capped"], 0)

    async def test_reply_without_choices_is_an_invalid_json_fault(self):
        self.fake.chat_reply = {"object": "chat.completion", "choices": []}
        client = self._orchestrator(**_OPENAI).ollama
        with self.assertRaises(OllamaInvalidJSONError):
            await client.chat_json("gpt-oss-20b", "sys", "user")


class OutputCapTests(_Base):
    async def test_openai_reply_at_the_cap_is_discarded_as_capped(self):
        # gpt-oss spent the whole budget reasoning: no content, finish length -- and
        # again when asked once more with twice the cap (test_capped_reply_retry).
        self.fake.chat_replies = [
            _openai_reply(content="", finish="length", prompt_tokens=900,
                          completion_tokens=cap, reasoning="x" * 4000) for cap in (2048, 4096)]
        client = self._orchestrator(**_OPENAI).ollama
        before = self._breaker_failures()
        with self.assertRaises(OllamaOutputCappedError) as caught:
            await client.chat_json("gpt-oss-20b", "sys", "user")
        # Every caller that bounds unusable output (the iterative agent) catches it.
        self.assertIsInstance(caught.exception, OllamaInvalidJSONError)
        snapshot = client.metrics_snapshot()
        self.assertEqual(snapshot["client"]["output_capped"], 2)
        self.assertEqual(snapshot["client"]["context_truncated"], 0)
        self.assertEqual(self._breaker_failures(), before, "a capped reply is not an outage")

    async def test_ollama_mode_sends_num_predict_and_raises_capped_at_the_cap(self):
        self.fake.ollama_replies = [
            {"message": {"role": "assistant", "content": "{\"a\": \"aaaa"}, "done": True,
             "done_reason": "length", "prompt_eval_count": 900, "eval_count": cap}
            for cap in (512, 1024)]
        client = self._orchestrator(max_output_tokens=512).ollama
        with self.assertRaises(OllamaOutputCappedError):
            await client.chat_json("m", "sys", "user")
        first, retry = self.fake.bodies()
        self.assertEqual(self.fake.paths(), ["/api/chat"] * 2)
        self.assertEqual(first["options"], {"temperature": 0.1, "num_predict": 512})
        self.assertEqual(retry["options"], {"temperature": 0.1, "num_predict": 1024})
        self.assertEqual(client.metrics_snapshot()["client"]["output_capped"], 2)

    async def test_length_stop_under_the_cap_is_still_a_context_fault(self):
        # Control: the cap was not reached, so only the window can have stopped it.
        self.fake.ollama_reply = {"message": {"role": "assistant", "content": ""},
                                  "done": True, "done_reason": "length",
                                  "prompt_eval_count": 900, "eval_count": 100}
        client = self._orchestrator(max_output_tokens=512).ollama
        with self.assertRaises(OllamaContextTruncatedError) as caught:
            await client.chat_json("m", "sys", "user")
        self.assertNotIsInstance(caught.exception, OllamaInvalidJSONError)
        self.assertEqual(caught.exception.kind, "reply")
        self.assertEqual(client.metrics_snapshot()["client"]["output_capped"], 0)


class OllamaDefaultControlTests(_Base):
    def _base_body(self, model: str) -> bytes:
        payload = {
            "model": model,
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "user"}],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1},
            "think": False,
        }
        return httpx.Request("POST", self.fake.base_url + "/api/chat", json=payload).content

    async def test_unset_keys_send_the_exact_ollama_payload_bytes(self):
        client = self._orchestrator().ollama
        await client.chat_json("m", "sys", "user")
        self.assertEqual([body for _, _, body in self.fake.requests], [self._base_body("m")])
        self.assertEqual(client.metrics_snapshot()["backend"],
                         {"api": "ollama", "max_output_tokens": None, "reasoning_effort": None,
                          "allow_cloud_models": False})

    async def test_explicit_ollama_api_sends_the_same_bytes(self):
        client = self._orchestrator(api="ollama").ollama
        await client.chat_json("m", "sys", "user")
        self.assertEqual([body for _, _, body in self.fake.requests], [self._base_body("m")])

    async def test_health_and_list_stay_on_api_tags(self):
        client = self._orchestrator().ollama
        health = await client.health_check()
        self.assertEqual((health["reachable"], health["models"]), (True, ["m:latest"]))
        self.assertEqual(await client.list_models(), ["m:latest"])
        self.assertEqual(self.fake.paths("GET"), ["/api/tags", "/api/tags"])


class OpenAIContextTests(_Base):
    async def test_context_size_refusal_is_a_prompt_truncation_kept_out_of_the_breaker(self):
        self.fake.chat_status = 400
        self.fake.chat_reply = {"error": {
            "code": 400, "type": "exceed_context_size_error", "n_prompt_tokens": 20000, "n_ctx": 16384,
            "message": "the request exceeds the available context size, try increasing it"}}
        client = self._orchestrator(**_OPENAI).ollama
        before = self._breaker_failures()
        with self.assertRaises(OllamaContextTruncatedError) as caught:
            await client.chat_json("gpt-oss-20b", "sys", "user")
        self.assertEqual((caught.exception.kind, caught.exception.window), ("prompt", 16384))
        snapshot = client.metrics_snapshot()
        self.assertEqual(snapshot["client"]["context_truncated"], 1)
        self.assertEqual(snapshot["context"]["truncated"], {"prompt": 1, "reply": 0})
        self.assertEqual(self._breaker_failures(), before)

    async def test_other_400_stays_a_plain_error(self):
        self.fake.chat_status = 400
        self.fake.chat_reply = {"error": {"code": 400, "type": "invalid_request_error",
                                          "message": "bad grammar"}}
        client = self._orchestrator(**_OPENAI).ollama
        with self.assertRaises(OllamaError) as caught:
            await client.chat_json("gpt-oss-20b", "sys", "user")
        self.assertNotIsInstance(caught.exception, (OllamaContextTruncatedError, OllamaInvalidJSONError))

    async def test_many_characters_per_token_is_not_read_as_a_silent_cut(self):
        # llama-server refuses an oversized prompt instead of cutting it, so the
        # characters-per-token heuristic for Ollama's silent cut must not fire.
        user = "word " * 2600     # 13,000 characters
        self.fake.chat_reply = _openai_reply(prompt_tokens=2100, completion_tokens=10)
        client = self._orchestrator(api="openai", num_ctx=4096).ollama
        self.assertEqual(await client.chat_json("gpt-oss-20b", "sys", user), {"verdict": "ok"})
        # Control: the same counts from Ollama are its silent half-window cut.
        self.fake.ollama_reply = {"message": {"role": "assistant", "content": "{\"verdict\": \"ok\"}"},
                                  "done": True, "prompt_eval_count": 2100, "eval_count": 10}
        ollama = self._orchestrator(num_ctx=4096).ollama
        with self.assertRaises(OllamaContextTruncatedError) as caught:
            await ollama.chat_json("m", "sys", user)
        self.assertEqual(caught.exception.kind, "prompt")

    async def test_window_comes_from_props_when_num_ctx_is_unset(self):
        self.fake.chat_reply = _openai_reply(prompt_tokens=9000, completion_tokens=7400)
        client = self._orchestrator(api="openai", max_output_tokens=8192).ollama
        with self.assertRaises(OllamaContextTruncatedError) as caught:
            await client.chat_json("gpt-oss-20b", "sys", "user")
        self.assertEqual((caught.exception.kind, caught.exception.window,
                          caught.exception.window_source), ("reply", 16384, "props"))
        self.assertIn("/props", self.fake.paths("GET"))
        self.assertNotIn("/api/ps", self.fake.paths("GET"))
        self.assertEqual(client.metrics_snapshot()["context"]["windows"],
                         [{"model": "*server*", "context_length": 16384, "source": "props"}])

    async def test_health_and_list_use_v1_models(self):
        client = self._orchestrator(**_OPENAI).ollama
        health = await client.health_check()
        self.assertEqual((health["reachable"], health["models"]), (True, ["gpt-oss-20b"]))
        self.assertEqual(await client.list_models(), ["gpt-oss-20b"])
        self.assertEqual(self.fake.paths("GET"), ["/v1/models", "/v1/models"])


class SettingsAndOtherCallerTests(_Base):
    def test_invalid_settings_fail_startup(self):
        for bad in ({"api": "llama"}, {"api": "OpenAI"}, {"max_output_tokens": "2048"},
                    {"max_output_tokens": True}, {"max_output_tokens": 0},
                    {"max_output_tokens": 2.5}, {"api": "openai", "reasoning_effort": "max"},
                    {"reasoning_effort": "low"}, {"api": "openai", "think": True},
                    {"api": "openai", "think": ["critique"]}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self._orchestrator(**bad)

    def test_think_off_is_accepted_with_openai(self):
        self.assertEqual(self._orchestrator(api="openai", think=False).ollama.api, "openai")

    async def test_standalone_analysis_pipeline_client_uses_the_same_backend(self):
        from harness.analysis_pipeline import AnalysisPipeline
        pipeline = AnalysisPipeline(None, None, None, self._config(**_OPENAI))
        client = pipeline.ollama_client
        client.audit_logger = MagicMock()
        self.assertEqual((client.api, client.max_output_tokens, client.reasoning_effort),
                         ("openai", 2048, "low"))
        await client.chat_json("gpt-oss-20b", "sys", "user")
        self.assertEqual(self.fake.paths(), ["/v1/chat/completions"])

    def test_writeup_phrasing_uses_the_configured_backend(self):
        from harness import writeups
        config = self._config(**_OPENAI)
        config["writeups"] = {"model_phrasing": True, "model": "gpt-oss-20b"}
        self.fake.chat_reply = _openai_reply(
            content=json.dumps({"impact": "Impact text.", "remediation": "Fix text."}))
        facts = {key: "" for key in ("vulnerability_class", "method", "endpoint_family", "object",
                                     "actor", "owner", "principals", "fields", "sensitive_fields",
                                     "parameter", "attack_status")}
        out = writeups._model_rephrase(facts, "impact", "remediation", config)
        self.assertEqual(self.fake.paths(), ["/v1/chat/completions"])
        self.assertEqual(out, {"impact": "Impact text.", "remediation": "Fix text."})

    def test_manifest_backend_setting(self):
        self.assertEqual(backend_setting(_shipped_config()["ollama"]),
                         {"api": "ollama", "max_output_tokens": None, "reasoning_effort": None})
        self.assertEqual(backend_setting(_OPENAI),
                         {"api": "openai", "max_output_tokens": 2048, "reasoning_effort": "low"})
        with self.assertRaises(ValueError):
            backend_setting({"api": "vllm"})


if __name__ == "__main__":
    unittest.main()
