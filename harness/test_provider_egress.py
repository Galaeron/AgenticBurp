"""Provider config/diagnostics + egress contract tests (P2.2, pairs with P1.1).

Hermetic: no real network, no live model. Covers the three things P1.1's own
test file didn't dedicate a contract test to: (1) explicit opt-in is
required for ANY remote data to leave the host, (2) diagnostics exposed to
an operator surface are redacted (never a key value), (3) a provider call
is bounded -- a timeout surfaces promptly as a typed error, never a hang.
"""
from __future__ import annotations

import asyncio
import os
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from harness.llm_provider import build_provider, provider_diagnostics, ProviderConfigError
from harness.openai_provider import OpenAiProvider, ProviderCallError
from harness.anthropic_provider import AnthropicProvider


def run(coro):
    return asyncio.run(coro)


class _FakeOllamaClient:
    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        raise AssertionError("should never be called -- remote opt-in tests must not fall back")


class _EnvVarSandbox(unittest.TestCase):
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


class TestExplicitOptInRequired(_EnvVarSandbox):
    def test_no_provider_key_never_sends_anything_remote(self):
        """Default config (no "provider" key at all) must never construct a
        remote provider, regardless of what env vars happen to be set."""
        os.environ["OPENAI_API_KEY"] = "sk-should-be-irrelevant"
        provider = build_provider({"model": "qwen3:8b"}, ollama_client=_FakeOllamaClient())
        self.assertEqual(getattr(provider, "name", ""), "ollama")

    def test_provider_key_alone_without_env_key_refuses(self):
        """Negative control: naming a remote provider in config is NOT enough
        on its own -- the matching API key must ALSO be present, or the
        request is refused before any egress is possible."""
        with self.assertRaises(ProviderConfigError):
            build_provider({"provider": "openai", "model": "gpt-x"}, ollama_client=_FakeOllamaClient())
        with self.assertRaises(ProviderConfigError):
            build_provider({"provider": "anthropic", "model": "claude-x"}, ollama_client=_FakeOllamaClient())

    def test_env_key_alone_without_provider_config_stays_local(self):
        """Negative control (the inverse): an API key merely being present in
        the environment must NOT, by itself, cause any egress -- config must
        explicitly opt in too. Two independent gates, both required."""
        os.environ["OPENAI_API_KEY"] = "sk-present-but-unused"
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-present-but-unused"
        provider = build_provider({"model": "qwen3:8b"}, ollama_client=_FakeOllamaClient())
        self.assertEqual(getattr(provider, "name", ""), "ollama")


class TestDiagnosticsAreRedacted(_EnvVarSandbox):
    def test_diagnostics_never_include_the_key_value(self):
        os.environ["OPENAI_API_KEY"] = "sk-super-secret-value-12345"
        diag = provider_diagnostics({"provider": "openai", "model": "gpt-x"})
        self.assertEqual(diag["provider"], "openai")
        self.assertEqual(diag["model"], "gpt-x")
        self.assertTrue(diag["remote"])
        self.assertEqual(diag["api_key_env_var"], "OPENAI_API_KEY")
        self.assertTrue(diag["api_key_present"])
        # The actual secret value must never appear anywhere in the dict.
        serialized = repr(diag)
        self.assertNotIn("sk-super-secret-value-12345", serialized)

    def test_diagnostics_report_absent_key_without_raising(self):
        """Unlike build_provider, diagnostics must be safe to call even when
        misconfigured -- an operator status panel must never 500 just
        because a key is missing."""
        diag = provider_diagnostics({"provider": "anthropic", "model": "claude-x"})
        self.assertFalse(diag["api_key_present"])
        self.assertEqual(diag["api_key_env_var"], "ANTHROPIC_API_KEY")

    def test_diagnostics_for_ollama_reports_not_remote(self):
        diag = provider_diagnostics({"model": "qwen3:8b"})
        self.assertEqual(diag["provider"], "ollama")
        self.assertFalse(diag["remote"])
        self.assertEqual(diag["api_key_env_var"], "")
        self.assertFalse(diag["api_key_present"])


class TestBoundedTimeout(unittest.TestCase):
    def test_openai_provider_has_a_finite_default_timeout(self):
        provider = OpenAiProvider(api_key="sk-test")
        self.assertIsInstance(provider._timeout, (int, float))
        self.assertGreater(provider._timeout, 0)

    def test_anthropic_provider_has_a_finite_default_timeout(self):
        provider = AnthropicProvider(api_key="sk-test")
        self.assertIsInstance(provider._timeout, (int, float))
        self.assertGreater(provider._timeout, 0)

    def test_openai_timeout_surfaces_promptly_as_typed_error(self):
        provider = OpenAiProvider(api_key="sk-test", timeout=0.05)
        with patch("httpx.AsyncClient.post",
                   new=AsyncMock(side_effect=httpx.TimeoutException("simulated"))):
            with self.assertRaises(ProviderCallError):
                run(provider.chat_json("gpt-x", "sys", "user"))

    def test_anthropic_timeout_surfaces_promptly_as_typed_error(self):
        provider = AnthropicProvider(api_key="sk-test", timeout=0.05)
        with patch("httpx.AsyncClient.post",
                   new=AsyncMock(side_effect=httpx.TimeoutException("simulated"))):
            with self.assertRaises(ProviderCallError):
                run(provider.chat_json("claude-x", "sys", "user"))


class TestSettingsEndpointExposesRedactedDiagnostics(_EnvVarSandbox):
    def test_get_settings_includes_llm_providers_without_key_values(self):
        import asyncio as _asyncio
        os.environ["OPENAI_API_KEY"] = "sk-should-never-appear"
        from harness import server

        result = _asyncio.run(server.get_settings(authorization=None))
        self.assertIn("llm_providers", result)
        self.assertIn("coordinator", result["llm_providers"])
        self.assertIn("critique", result["llm_providers"])
        self.assertNotIn("sk-should-never-appear", repr(result))


if __name__ == "__main__":
    unittest.main()
