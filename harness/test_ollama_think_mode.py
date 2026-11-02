"""AR-10 P2: opt-in thinking mode (`ollama.think`), caller-level.

Every test builds the real Orchestrator from the shipped config.yaml, points its
`ollama.base_url` at a loopback fake Ollama HTTP server, and drives the client the
orchestrator built. No real model is called. Controls: with the key unset or
false the bytes on the wire are exactly the base payload (`"think": false`).
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

from harness import ollama_client
from harness.ollama_client import OllamaInvalidJSONError, model_stage

_TRACE = "SENTINEL-REASONING-TRACE {\"verdict\": \"from-the-trace\"}"


class _FakeOllama:
    """Loopback /api/chat: records each raw request body, answers from `reply`."""

    def __init__(self):
        self.bodies: list[bytes] = []
        self.reply: dict = {"message": {"role": "assistant", "content": "{\"verdict\": \"ok\"}"},
                            "done": True, "prompt_eval_count": 7, "eval_count": 3}
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                fake.bodies.append(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                out = json.dumps(fake.reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _shipped_config() -> dict:
    with open(Path(__file__).resolve().parent / "config.yaml", encoding="utf-8") as stream:
        return yaml.safe_load(stream) or {}


class ThinkModeCallerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fake = _FakeOllama()
        self.addCleanup(self.fake.close)

    def _orchestrator(self, **ollama_overrides):
        from harness.orchestrator import Orchestrator
        config = copy.deepcopy(_shipped_config())
        self.assertNotIn("think", config["ollama"], "the shipped default must stay unset")
        config["ollama"]["base_url"] = self.fake.base_url
        config["ollama"]["transient_retries"] = 0
        config["ollama"].update(ollama_overrides)
        orchestrator = Orchestrator(config)
        orchestrator.ollama.audit_logger = MagicMock()
        return orchestrator

    def _base_body(self, model: str) -> bytes:
        """The exact bytes the pre-P2 client sent: same keys, same order,
        `"think": False`, encoded by httpx the way the client encodes it."""
        payload = {
            "model": model,
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "user"}],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1},
            "think": False,
        }
        return httpx.Request("POST", self.fake.base_url + "/api/chat", json=payload).content

    async def test_unset_key_sends_base_payload_bytes(self):
        orchestrator = self._orchestrator()
        await orchestrator.ollama.chat_json("m", "sys", "user")
        self.assertEqual(self.fake.bodies, [self._base_body("m")])

    async def test_explicit_false_sends_base_payload_bytes(self):
        orchestrator = self._orchestrator(think=False)
        with model_stage("critique"):
            await orchestrator.ollama.chat_json("m", "sys", "user")
        self.assertEqual(self.fake.bodies, [self._base_body("m")])

    async def test_true_sends_think_true_and_nothing_else_changes(self):
        orchestrator = self._orchestrator(think=True)
        await orchestrator.ollama.chat_json("m", "sys", "user")
        sent = json.loads(self.fake.bodies[0])
        self.assertIs(sent["think"], True)
        self.assertEqual({**sent, "think": False}, json.loads(self._base_body("m")))

    async def test_stage_list_turns_think_on_only_inside_listed_stages(self):
        orchestrator = self._orchestrator(think=["critique", "iterative"])
        with model_stage("critique"):
            await orchestrator.ollama.chat_json("m", "sys", "user")
        with model_stage("xss"):
            await orchestrator.ollama.chat_json("m", "sys", "user")
        await orchestrator.ollama.chat_json("m", "sys", "user")  # unlabelled
        self.assertEqual([json.loads(b)["think"] for b in self.fake.bodies], [True, False, False])
        self.assertEqual(self.fake.bodies[1], self._base_body("m"))

    def test_quoted_value_fails_startup_instead_of_reading_truthy(self):
        for bad in ("true", "false", 1, {"critique": True}, ["critique", ""]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self._orchestrator(think=bad)

    async def test_thinking_field_is_not_parsed_kept_or_logged(self):
        orchestrator = self._orchestrator(think=True)
        self.fake.reply["message"]["thinking"] = _TRACE
        with self.assertLogs("harness", level=logging.DEBUG) as logs:
            logging.getLogger("harness").debug("capture start")
            parsed, raw = await orchestrator.ollama._chat("m", "sys", "user")
            result = await orchestrator.ollama.chat_json_metered("m", "sys", "user")
        self.assertEqual(parsed, {"verdict": "ok"})
        self.assertEqual(result.data, {"verdict": "ok"})
        # The raw envelope handed back to callers no longer carries the trace...
        self.assertNotIn("thinking", raw["message"])
        self.assertNotIn("SENTINEL", json.dumps(raw, default=str))
        # ...only its length, on the measurement receipt.
        self.assertEqual(result.measurement["thinking_chars"], len(_TRACE))
        self.assertNotIn("SENTINEL", "\n".join(logs.output))
        self.assertNotIn("SENTINEL", repr(orchestrator.ollama.audit_logger.mock_calls))

    async def test_inline_think_block_is_not_parsed_as_the_answer(self):
        orchestrator = self._orchestrator(think=True)
        self.fake.reply["message"]["content"] = f"<think>{_TRACE}</think>\n{{\"verdict\": \"ok\"}}"
        result = await orchestrator.ollama.chat_json_metered("m", "sys", "user")
        self.assertEqual(result.data, {"verdict": "ok"})
        self.assertEqual(result.measurement["thinking_chars"],
                         len(f"<think>{_TRACE}</think>\n"))
        self.assertNotIn("SENTINEL", repr(orchestrator.ollama.audit_logger.mock_calls))

    async def test_control_without_inline_strip_the_trace_breaks_parsing(self):
        orchestrator = self._orchestrator(think=True)
        self.fake.reply["message"]["content"] = f"<think>{_TRACE}</think>\n{{\"verdict\": \"ok\"}}"
        original = ollama_client._strip_inline_thinking
        ollama_client._strip_inline_thinking = lambda content: (content, 0)
        self.addCleanup(setattr, ollama_client, "_strip_inline_thinking", original)
        with self.assertRaises(OllamaInvalidJSONError):
            await orchestrator.ollama.chat_json("m", "sys", "user")

    async def test_run_instrumentation_records_the_effective_setting(self):
        from harness.instrumentation import RunInstrumentation
        orchestrator = self._orchestrator(think=["critique"])
        instrumentation = RunInstrumentation(orchestrator)
        self.fake.reply["message"]["thinking"] = _TRACE
        with model_stage("critique"):
            await orchestrator.ollama.chat_json("m", "sys", "user")
        await orchestrator.ollama.chat_json("m", "sys", "user")
        think = instrumentation.snapshot()["model_metrics"]["think"]
        self.assertEqual(think, {"setting": "stages", "stages": ["critique"], "think_calls": 1,
                                 "traces": 2, "trace_chars": 2 * len(_TRACE)})

    async def test_run_instrumentation_says_off_when_unset(self):
        from harness.instrumentation import RunInstrumentation
        orchestrator = self._orchestrator()
        instrumentation = RunInstrumentation(orchestrator)
        await orchestrator.ollama.chat_json("m", "sys", "user")
        think = instrumentation.snapshot()["model_metrics"]["think"]
        self.assertEqual(think, {"setting": "off", "stages": [], "think_calls": 0,
                                 "traces": 0, "trace_chars": 0})


class ThinkSettingProvenanceTests(unittest.TestCase):
    def test_manifest_description_of_each_setting(self):
        self.assertEqual(ollama_client.think_setting(None), {"setting": "off", "stages": []})
        self.assertEqual(ollama_client.think_setting(False), {"setting": "off", "stages": []})
        self.assertEqual(ollama_client.think_setting([]), {"setting": "off", "stages": []})
        self.assertEqual(ollama_client.think_setting(True), {"setting": "on", "stages": []})
        self.assertEqual(ollama_client.think_setting(["iterative", "critique"]),
                         {"setting": "stages", "stages": ["critique", "iterative"]})

    def test_manifest_redaction_keeps_the_setting(self):
        from harness.run_manifest import redact
        self.assertEqual(redact({"think": ollama_client.think_setting(True)}),
                         {"think": {"setting": "on", "stages": []}})


if __name__ == "__main__":
    unittest.main()
