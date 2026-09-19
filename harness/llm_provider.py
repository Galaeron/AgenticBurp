"""Multi-provider / BYO-LLM abstraction (P1.1).

Ollama stays the default for everything. This lets the COORDINATOR and
CRITIQUE roles optionally point at a stronger remote model per config,
while the 36 specialist agents always stay on local Ollama (unchanged --
nothing here touches `agent_manager`/`base_agent`). There is no silent
provider switch: a remote provider is only ever constructed when the
config explicitly names it AND the matching API-key environment variable
is set. Missing either raises immediately -- it never falls back to
Ollama quietly, which would be worse than erroring (a caller who asked for
a specific remote model and got local qwen3:8b without being told).

`Provider.chat_json` is the one abstraction method, matching
`OllamaClient.chat_json_metered`'s real signature and return type
(`OllamaResult`) since that is what every existing caller (coordinator.py,
critique's client) actually calls. `OllamaProvider` also answers to
`.chat_json_metered(...)` (an alias), so it is a drop-in replacement for
`self.ollama` at every existing call site with ZERO call-site edits.
"""
from __future__ import annotations

import logging
import os
from typing import Protocol

from harness.ollama_client import OllamaClient, OllamaError, OllamaResult

log = logging.getLogger("harness.llm_provider")


class Provider(Protocol):
    """One method: send a system/user prompt pair to a model, get JSON back
    plus real token usage. Every provider (local or remote) implements
    exactly this, so a caller (coordinator.py, critique) never branches on
    which provider it holds."""

    async def chat_json(
        self, model: str, system_prompt: str, user_prompt: str,
        temperature: float = 0.1, **kw,
    ) -> OllamaResult:
        ...


class ProviderConfigError(ValueError):
    """A remote provider was requested but cannot be constructed (missing
    API key, unknown provider name). Never caught to silently fall back to
    Ollama -- the caller must see this."""


class OllamaProvider:
    """Wraps an existing OllamaClient (or any object exposing
    chat_json_metered) -- the default, local, no-opt-in-required provider."""

    name = "ollama"

    def __init__(self, client: OllamaClient):
        self._client = client

    async def chat_json(
        self, model: str, system_prompt: str, user_prompt: str,
        temperature: float = 0.1, **kw,
    ) -> OllamaResult:
        return await self._client.chat_json_metered(
            model, system_prompt, user_prompt, temperature=temperature)

    # Back-compat alias: every existing caller (coordinator.py's three call
    # sites, critique) calls `.chat_json_metered(...)` on what used to be a
    # bare OllamaClient. Aliasing means this class is a drop-in replacement
    # with no call-site edits required.
    chat_json_metered = chat_json


def _require_env(var_name: str, provider_name: str) -> str:
    key = os.environ.get(var_name, "")
    if not key:
        raise ProviderConfigError(
            f"provider={provider_name!r} was requested but ${var_name} is not set -- "
            f"refusing to silently fall back to Ollama. Set ${var_name} or remove "
            f"'provider: {provider_name}' from config to use the local default.")
    return key


def build_provider(role_config: dict, *, ollama_client: OllamaClient) -> Provider:
    """Build the Provider for one role (coordinator or critique) from its own
    config block, e.g. `config.get("coordinator", {})`.

    - No `provider` key, or `provider: ollama` (the default): OllamaProvider
      wrapping `ollama_client` -- exactly today's behavior, zero config
      required.
    - `provider: openai`: requires $OPENAI_API_KEY. Missing -> ProviderConfigError,
      raised immediately, never swallowed into a silent Ollama fallback.
    - `provider: anthropic`: requires $ANTHROPIC_API_KEY, same contract.
    - Anything else: ProviderConfigError (unknown provider name).
    """
    provider_name = str((role_config or {}).get("provider", "ollama") or "ollama").lower()

    if provider_name == "ollama":
        return OllamaProvider(ollama_client)

    if provider_name == "openai":
        from harness.openai_provider import OpenAiProvider
        api_key = _require_env("OPENAI_API_KEY", "openai")
        return OpenAiProvider(api_key=api_key, base_url=role_config.get("base_url", ""))

    if provider_name == "anthropic":
        from harness.anthropic_provider import AnthropicProvider
        api_key = _require_env("ANTHROPIC_API_KEY", "anthropic")
        return AnthropicProvider(api_key=api_key, base_url=role_config.get("base_url", ""))

    raise ProviderConfigError(
        f"unknown provider {provider_name!r} -- expected 'ollama', 'openai', or 'anthropic'")
