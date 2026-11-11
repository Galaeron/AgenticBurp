"""A reply that reached the output cap is asked once more with a larger cap (r9 review).

r9 ran gpt-oss-20b on llama-server with `ollama.max_output_tokens: 2048` and
reasoning effort low. 40 replies reached the cap unfinished and were discarded,
most of them the injection agent's step: each was one lost agent step. The cap stays
(it bounds a model stuck repeating itself); a capped reply is now asked once more
with twice the cap, within the context window, and only once.

Caller: the client the real Orchestrator builds from the shipped config, against a
loopback fake of both wire protocols (test_openai_compatible_backend). Controls: the
retry removed, a window with no room left, and a second capped reply.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from harness import ollama_client
from harness.ollama_client import OllamaOutputCappedError
from harness.test_openai_compatible_backend import _OPENAI, _Base, _openai_reply

_ANSWER = "{\"action\": \"done\"}"


def _capped(cap, *, prompt_tokens=900):
    return _openai_reply(content="", finish="length", prompt_tokens=prompt_tokens,
                         completion_tokens=cap, reasoning="x" * 4000)


class CappedReplyRetryTests(_Base):

    async def test_a_capped_reply_is_asked_again_with_twice_the_cap(self):
        self.fake.chat_replies = [_capped(2048), _openai_reply(_ANSWER, completion_tokens=2600)]
        client = self._orchestrator(**_OPENAI).ollama
        parsed = await client.chat_json("gpt-oss-20b", "sys", "user")
        self.assertEqual(parsed, {"action": "done"})
        self.assertEqual([b["max_tokens"] for b in self.fake.bodies()], [2048, 4096])
        counts = client.metrics_snapshot()["client"]
        self.assertEqual((counts["output_capped"], counts["output_capped_retried"],
                          counts["output_capped_recovered"], counts["usable"]), (1, 1, 1, 1))
        self.assertEqual(counts["context_truncated"], 0)

    async def test_control_without_the_retry_the_reply_is_lost(self):
        self.fake.chat_replies = [_capped(2048), _openai_reply(_ANSWER)]
        client = self._orchestrator(**_OPENAI).ollama
        with patch.object(ollama_client.OllamaClient, "_capped_retry_cap", lambda *a: None):
            with self.assertRaises(OllamaOutputCappedError):
                await client.chat_json("gpt-oss-20b", "sys", "user")
        self.assertEqual(len(self.fake.bodies()), 1)                  # the r9 behaviour

    async def test_control_a_second_capped_reply_is_not_asked_again(self):
        self.fake.chat_replies = [_capped(2048), _capped(4096), _openai_reply(_ANSWER)]
        client = self._orchestrator(**_OPENAI).ollama
        with self.assertRaises(OllamaOutputCappedError):
            await client.chat_json("gpt-oss-20b", "sys", "user")
        self.assertEqual([b["max_tokens"] for b in self.fake.bodies()], [2048, 4096])
        counts = client.metrics_snapshot()["client"]
        self.assertEqual((counts["output_capped"], counts["output_capped_retried"],
                          counts["output_capped_recovered"]), (2, 1, 0))

    async def test_the_larger_cap_stays_within_the_window(self):
        # 16384-token window, 13000-token prompt: room for 3368 more, not 4096.
        self.fake.chat_replies = [_capped(2048, prompt_tokens=13000), _openai_reply(_ANSWER)]
        client = self._orchestrator(**_OPENAI).ollama
        await client.chat_json("gpt-oss-20b", "sys", "user")
        self.assertEqual([b["max_tokens"] for b in self.fake.bodies()],
                         [2048, 16384 - 13000 - ollama_client._WINDOW_SLACK_TOKENS])

    async def test_control_a_full_window_leaves_no_room_to_retry(self):
        self.fake.chat_replies = [_capped(2048, prompt_tokens=14500), _openai_reply(_ANSWER)]
        client = self._orchestrator(**_OPENAI).ollama
        with self.assertRaises(OllamaOutputCappedError):
            await client.chat_json("gpt-oss-20b", "sys", "user")
        self.assertEqual(len(self.fake.bodies()), 1)

    async def test_without_a_cap_nothing_is_retried(self):
        # Control: no ollama.max_output_tokens, so no reply is ever capped.
        self.fake.ollama_reply = {"message": {"role": "assistant", "content": _ANSWER},
                                  "done": True, "prompt_eval_count": 900, "eval_count": 40}
        client = self._orchestrator().ollama
        await client.chat_json("m", "sys", "user")
        self.assertNotIn("num_predict", self.fake.bodies()[0]["options"])
        self.assertEqual(client.metrics_snapshot()["client"]["output_capped_retried"], 0)


if __name__ == "__main__":
    unittest.main()
