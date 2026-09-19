"""OpenAI-compatible remote Provider (P1.1). Never constructed unless
llm_provider.build_provider was explicitly given `provider: openai` in
config AND $OPENAI_API_KEY is set -- see that module for the opt-in
contract. This module never reads the API key itself; the key is passed in
by the caller (already validated), so nothing here can silently pick up an
ambient key and switch providers on its own.
"""
from __future__ import annotations

import json
import logging

import httpx

from harness.ollama_client import OllamaResult

log = logging.getLogger("harness.openai_provider")

_DEFAULT_BASE_URL = "https://api.openai.com/v1"
_DEFAULT_TIMEOUT = 60.0


class ProviderCallError(RuntimeError):
    """A remote provider call failed (timeout, HTTP error, bad JSON) -- a
    bounded, honest error, never a hang and never a silent empty result."""


class OpenAiProvider:
    name = "openai"

    def __init__(self, *, api_key: str, base_url: str = "", timeout: float = _DEFAULT_TIMEOUT):
        if not api_key:
            raise ValueError("OpenAiProvider requires a non-empty api_key")
        self._api_key = api_key
        self._base_url = (base_url or _DEFAULT_BASE_URL).rstrip("/")
        self._timeout = timeout

    async def chat_json(
        self, model: str, system_prompt: str, user_prompt: str,
        temperature: float = 0.1, **kw,
    ) -> OllamaResult:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/chat/completions", headers=headers, json=payload)
                resp.raise_for_status()
                body = resp.json()
        except httpx.TimeoutException as e:
            raise ProviderCallError(f"openai call timed out after {self._timeout}s: {e}") from e
        except httpx.HTTPError as e:
            raise ProviderCallError(f"openai call failed: {e}") from e

        try:
            content = body["choices"][0]["message"]["content"]
            data = json.loads(content)
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            raise ProviderCallError(f"openai returned an unparseable response: {e}") from e

        usage = body.get("usage") or {}
        return OllamaResult(
            data=data,
            prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
            completion_tokens=int(usage.get("completion_tokens", 0) or 0),
        )

    chat_json_metered = chat_json
