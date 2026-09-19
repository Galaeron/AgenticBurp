"""Hermetic tests for the multi-provider / BYO-LLM abstraction (P1.1).

No real API calls anywhere -- OpenAI/Anthropic HTTP calls are mocked at
httpx.AsyncClient.post, and no test reads a real environment API key (each
sets/clears its own via monkeypatching os.environ, restored in tearDown).
"""
from __future__ import annotations

import asyncio
import os
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from harness.llm_provider import (
    Provider, OllamaProvider, ProviderConfigError, build_provider,
)
from harness.ollama_client import OllamaResult
from harness.openai_provider import OpenAiProvider, ProviderCallError
from harness.anthropic_provider import AnthropicProvider


def run(coro):
    return asyncio.run(coro)


class _FakeOllamaClient:
    """Stands in for OllamaClient -- exposes only chat_json_metered, the real
    method every existing caller (coordinator.py, critique) actually calls."""

    def __init__(self):
        self.calls = []

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        self.calls.append((model, system_prompt, user_prompt, temperature))
        return OllamaResult(data={"dispatch": ["idor"]}, prompt_tokens=5, completion_tokens=2)


class _EnvVarSandbox(unittest.TestCase):
    """Base class: snapshot/restore the two provider API-key env vars so a
    test setting one never leaks into another test or the real environment."""

    _KEYS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY")

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in self._KEYS}
        for k in self._KEYS:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class TestBuildProviderDefault(_EnvVarSandbox):
    def test_default_config_builds_ollama_provider(self):
        client = _FakeOllamaClient()
        provider = build_provider({"model": "qwen3:8b"}, ollama_client=client)
        self.assertIsInstance(provider, OllamaProvider)

    def test_explicit_ollama_provider_key_also_builds_ollama_provider(self):
        client = _FakeOllamaClient()
        provider = build_provider({"provider": "ollama", "model": "qwen3:8b"}, ollama_client=client)
        self.assertIsInstance(provider, OllamaProvider)

    def test_ollama_provider_delegates_to_chat_json_metered(self):
        client = _FakeOllamaClient()
        provider = build_provider({}, ollama_client=client)
        result = run(provider.chat_json("qwen3:8b", "sys", "user"))
        self.assertEqual(result.data, {"dispatch": ["idor"]})
        self.assertEqual(len(client.calls), 1)
        # chat_json_metered alias is a drop-in for existing call sites.
        result2 = run(provider.chat_json_metered("qwen3:8b", "sys", "user"))
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(result2.prompt_tokens, 5)


class TestBuildProviderOpenAI(_EnvVarSandbox):
    def test_openai_with_key_present_builds_openai_provider(self):
        os.environ["OPENAI_API_KEY"] = "sk-test-key"
        client = _FakeOllamaClient()
        provider = build_provider({"provider": "openai", "model": "gpt-x"}, ollama_client=client)
        self.assertIsInstance(provider, OpenAiProvider)

    def test_openai_without_key_raises_and_does_not_fall_back(self):
        """Negative control: no $OPENAI_API_KEY -> ProviderConfigError, never a
        silent OllamaProvider fallback."""
        client = _FakeOllamaClient()
        with self.assertRaises(ProviderConfigError) as cm:
            build_provider({"provider": "openai", "model": "gpt-x"}, ollama_client=client)
        self.assertIn("OPENAI_API_KEY", str(cm.exception))
        self.assertEqual(client.calls, [])  # never touched -- no fallback call happened


class TestBuildProviderAnthropic(_EnvVarSandbox):
    def test_anthropic_with_key_present_builds_anthropic_provider(self):
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test-key"
        client = _FakeOllamaClient()
        provider = build_provider({"provider": "anthropic", "model": "claude-x"}, ollama_client=client)
        self.assertIsInstance(provider, AnthropicProvider)

    def test_anthropic_without_key_raises_and_does_not_fall_back(self):
        client = _FakeOllamaClient()
        with self.assertRaises(ProviderConfigError) as cm:
            build_provider({"provider": "anthropic", "model": "claude-x"}, ollama_client=client)
        self.assertIn("ANTHROPIC_API_KEY", str(cm.exception))


class TestBuildProviderUnknown(_EnvVarSandbox):
    def test_unknown_provider_name_raises(self):
        client = _FakeOllamaClient()
        with self.assertRaises(ProviderConfigError):
            build_provider({"provider": "some-other-vendor"}, ollama_client=client)


class TestOpenAiProviderCall(unittest.TestCase):
    def test_successful_call_parses_json_and_usage(self):
        provider = OpenAiProvider(api_key="sk-test", timeout=1.0)
        fake_response = httpx.Response(
            200, json={"choices": [{"message": {"content": '{"dispatch": ["sqli"]}'}}],
                       "usage": {"prompt_tokens": 10, "completion_tokens": 3}},
            request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"))
        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
            result = run(provider.chat_json("gpt-x", "sys", "user"))
        self.assertEqual(result.data, {"dispatch": ["sqli"]})
        self.assertEqual(result.prompt_tokens, 10)
        self.assertEqual(result.completion_tokens, 3)

    def test_timeout_raises_bounded_provider_call_error_not_a_hang(self):
        """A provider call that would otherwise hang must surface as a bounded,
        typed error -- proven here by mocking the transport to raise a timeout
        immediately rather than actually sleeping past a real timeout window."""
        provider = OpenAiProvider(api_key="sk-test", timeout=0.05)
        with patch("httpx.AsyncClient.post",
                   new=AsyncMock(side_effect=httpx.TimeoutException("simulated timeout"))):
            with self.assertRaises(ProviderCallError) as cm:
                run(provider.chat_json("gpt-x", "sys", "user"))
        self.assertIn("timed out", str(cm.exception))

    def test_requires_non_empty_api_key(self):
        with self.assertRaises(ValueError):
            OpenAiProvider(api_key="")


class TestAnthropicProviderCall(unittest.TestCase):
    def test_successful_call_parses_json_and_usage(self):
        provider = AnthropicProvider(api_key="sk-ant-test", timeout=1.0)
        fake_response = httpx.Response(
            200, json={"content": [{"type": "text", "text": '{"dispatch": ["idor"]}'}],
                       "usage": {"input_tokens": 8, "output_tokens": 4}},
            request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"))
        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
            result = run(provider.chat_json("claude-x", "sys", "user"))
        self.assertEqual(result.data, {"dispatch": ["idor"]})
        self.assertEqual(result.prompt_tokens, 8)
        self.assertEqual(result.completion_tokens, 4)

    def test_timeout_raises_bounded_provider_call_error_not_a_hang(self):
        provider = AnthropicProvider(api_key="sk-ant-test", timeout=0.05)
        with patch("httpx.AsyncClient.post",
                   new=AsyncMock(side_effect=httpx.TimeoutException("simulated timeout"))):
            with self.assertRaises(ProviderCallError) as cm:
                run(provider.chat_json("claude-x", "sys", "user"))
        self.assertIn("timed out", str(cm.exception))

    def test_requires_non_empty_api_key(self):
        with self.assertRaises(ValueError):
            AnthropicProvider(api_key="")


if __name__ == "__main__":
    unittest.main()
