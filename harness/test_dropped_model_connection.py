"""A model connection dropped mid-request or mid-reply is a transient fault (E6).

Measured motivation: restarting llama-server mid-call raised httpx.ReadError,
which escaped OllamaClient raw and stopped an iterative auth probe with
stop=error after 2 steps. The HTTP 503s that followed while the model loaded
were retried, because 503 was already transient.

Caller level: the real Orchestrator is built from the shipped config.yaml with
`ollama.base_url` pointed at a loopback fake server, and the client it built is
driven over both wire protocols (Ollama's /api/chat, and /v1/chat/completions
with `ollama.api: openai`). For a scripted number of POSTs the fake resets the
TCP connection (SO_LINGER 0, so an RST, not a FIN) after reading the request or
after sending half the reply; then it answers. The backoff sleep is patched out
and recorded, and the breaker registry is fresh per test.

Controls: a permanent 4xx is still not retried; with `transient_retries: 0` the
drop surfaces as OllamaTransientError, not a raw httpx error, and its cause is
the httpx.ReadError the fake produced (so the fake exercises the new branch,
not RemoteProtocolError); with that branch patched away the same drop escapes
the client raw, as it did live.
"""
from __future__ import annotations

import copy
import json
import socket
import struct
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import yaml

from harness import circuit_breaker as cb
from harness import ollama_client as oc
from harness.ollama_client import OllamaError, OllamaTransientError

_DROPPED = "Ollama connection dropped mid-request"
_VERDICT = {"verdict": "ok"}


def _reply(path: str) -> dict:
    content = json.dumps(_VERDICT)
    if path == "/v1/chat/completions":
        return {"object": "chat.completion",
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": content}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}}
    return {"message": {"role": "assistant", "content": content}, "done": True,
            "prompt_eval_count": 7, "eval_count": 3}


class _DroppingServer:
    """Loopback model server for both wire protocols. The next `drops` POSTs are
    reset ("after_request": once the request body is read; "mid_reply": after the
    headers and half the body); every later POST answers with `status`. GETs (the
    best-effort context-window probes) get a 404."""

    def __init__(self):
        self.drops = 0
        self.mode = "after_request"
        self.status = 200
        self.posts: list[str] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                fake.posts.append(self.path)
                body = json.dumps(_reply(self.path) if fake.status == 200
                                  else {"error": "synthetic permanent error"}).encode()
                if fake.drops > 0:
                    fake.drops -= 1
                    if fake.mode == "mid_reply":
                        self._head(200, len(body))
                        self.wfile.write(body[: len(body) // 2])
                    self._reset()
                    return
                self._head(fake.status, len(body))
                self.wfile.write(body)

            def do_GET(self):
                self._head(404, 0)

            def _head(self, status, length):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(length))
                self.end_headers()

            def _reset(self):
                # Linger 0: closing sends an RST at once. The socket is closed
                # here, before socketserver's own shutdown(SHUT_WR) would send a FIN.
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                           struct.pack("ii", 1, 0))
                self.rfile.close()
                self.connection.close()
                self.close_connection = True

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class _OpenGate:
    """Stands in for the process-wide token rate limiter, whose bucket every
    attempt draws on: without it, later tests here wait for refills."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def record_usage(self, prompt_tokens, completion_tokens):
        pass


def _shipped_config() -> dict:
    with open(Path(__file__).resolve().parent / "config.yaml", encoding="utf-8") as stream:
        return yaml.safe_load(stream) or {}


class _Base(unittest.IsolatedAsyncioTestCase):
    API: dict = {}
    MODEL = ""
    PATH = ""

    def setUp(self):
        previous = cb._registry
        cb._registry = None
        self.addCleanup(setattr, cb, "_registry", previous)
        self.delays: list[float] = []

        async def recorded_sleep(seconds):
            self.delays.append(seconds)

        sleep = patch.object(oc, "_backoff_sleep", recorded_sleep)
        sleep.start()
        self.addCleanup(sleep.stop)
        self.fake = _DroppingServer()
        self.addCleanup(self.fake.close)

    def client(self, **ollama_overrides):
        from harness.orchestrator import Orchestrator
        config = copy.deepcopy(_shipped_config())
        self.assertEqual(config["ollama"]["transient_retries"], 2, "the shipped default")
        config["ollama"]["base_url"] = self.fake.base_url
        config["ollama"].update(self.API, **ollama_overrides)
        client = Orchestrator(config).ollama
        client.audit_logger = MagicMock()
        client.rate_limiter = _OpenGate()
        return client

    async def call(self, client):
        return await client.chat_json(self.MODEL, "system text", "user text")

    @staticmethod
    def breaker_stats():
        return cb.current_ollama_breaker("ollama").get_stats()


class OllamaWireDropTests(_Base):
    """Ollama's /api/chat. The subclass below reruns every test over the
    OpenAI-compatible API."""
    MODEL, PATH = "m", "/api/chat"

    async def _check_one_drop_recovers(self, mode):
        self.fake.drops, self.fake.mode = 1, mode
        client = self.client()
        with self.assertLogs("harness.ollama_client", level="WARNING") as logs:
            self.assertEqual(await self.call(client), _VERDICT)
        self.assertEqual(self.fake.posts, [self.PATH, self.PATH])
        self.assertEqual(self.delays, [1.0])
        self.assertEqual((client.model_retry_count, client.model_retry_recovered_count), (1, 1))
        self.assertTrue(any(_DROPPED in line and "retry 1/2" in line for line in logs.output),
                        logs.output)
        # A recovered drop is a breaker success, like any recovered transient fault.
        stats = self.breaker_stats()
        self.assertEqual((stats.total_failures, stats.total_successes), (0, 1))
        # The dropped attempt is audited with the safe summary only.
        self.assertEqual(client.audit_logger.log_llm_error.call_count, 1)
        audited = client.audit_logger.log_llm_error.call_args.kwargs["error"]
        self.assertIsInstance(audited, OllamaError)
        self.assertTrue(str(audited).startswith("ReadError: "), str(audited))
        self.assertNotIn(self.fake.base_url.rsplit(":", 1)[1], str(audited))

    async def test_a_reset_after_the_request_is_retried_and_the_call_recovers(self):
        await self._check_one_drop_recovers("after_request")

    async def test_a_reset_mid_reply_is_retried_and_the_call_recovers(self):
        await self._check_one_drop_recovers("mid_reply")

    async def test_two_drops_recover_within_the_budget_and_a_third_fails_once(self):
        self.fake.drops = 2
        client = self.client()
        self.assertEqual(await self.call(client), _VERDICT)
        self.assertEqual((len(self.fake.posts), self.delays), (3, [1.0, 2.0]))
        cb.reset_ollama_circuit_breaker()
        self.fake.posts.clear()
        self.delays.clear()
        self.fake.drops = 3
        with self.assertRaises(OllamaTransientError) as caught:
            await self.call(client)
        self.assertEqual(str(caught.exception), _DROPPED)
        self.assertEqual(len(self.fake.posts), 3, "1 attempt + transient_retries (2)")
        # One logical call, one breaker failure: the same as a refused connection.
        self.assertEqual(self.breaker_stats().total_failures, 1)

    # -- controls -----------------------------------------------------------
    async def test_control_a_permanent_4xx_is_not_retried(self):
        self.fake.status = 401
        client = self.client()
        with self.assertRaises(OllamaError) as caught:
            await self.call(client)
        self.assertNotIsInstance(caught.exception, OllamaTransientError)
        self.assertEqual(str(caught.exception), "Ollama returned HTTP 401")
        self.assertEqual((self.fake.posts, self.delays, client.model_retry_count),
                         ([self.PATH], [], 0))

    async def test_control_zero_retries_surfaces_the_drop_as_a_transient_error(self):
        self.fake.drops = 1
        client = self.client(transient_retries=0)
        with self.assertRaises(OllamaTransientError) as caught:
            await self.call(client)
        self.assertNotIsInstance(caught.exception, httpx.HTTPError)
        self.assertIsInstance(caught.exception.__cause__, httpx.ReadError)
        self.assertNotIsInstance(caught.exception.__cause__, httpx.RemoteProtocolError)
        self.assertEqual(str(caught.exception), _DROPPED)
        self.assertEqual((self.fake.posts, self.delays), ([self.PATH], []))
        self.assertEqual(self.breaker_stats().total_failures, 1)

    async def test_control_without_the_new_branch_the_drop_escapes_raw(self):
        self.fake.drops = 1
        client = self.client()
        with patch.object(oc, "_DROPPED_CONNECTION_ERRORS", ()):
            with self.assertRaises(httpx.ReadError):
                await self.call(client)
        self.assertEqual((self.fake.posts, self.delays), ([self.PATH], []))


class OpenAICompatibleWireDropTests(OllamaWireDropTests):
    API, MODEL, PATH = {"api": "openai"}, "gpt-oss-20b", "/v1/chat/completions"


if __name__ == "__main__":
    unittest.main()
