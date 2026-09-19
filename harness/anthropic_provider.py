"""Anthropic remote Provider (P1.1). Never constructed unless
llm_provider.build_provider was explicitly given `provider: anthropic` in
config AND $ANTHROPIC_API_KEY is set -- see that module for the opt-in
contract. This module never reads the API key itself; the key is passed in
by the caller (already validated).
"""
from __future__ import annotations

import json
import logging
import re

import httpx

from harness.ollama_client import OllamaResult
from harness.openai_provider import ProviderCallError

log = logging.getLogger("harness.anthropic_provider")

_DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
_DEFAULT_TIMEOUT = 60.0
_ANTHROPIC_VERSION = "2023-06-01"


def _extract_json(text: str) -> dict:
    """Anthropic has no `response_format: json_object` mode -- the prompt asks
    for JSON and this extracts the first {...} block, matching
    ollama_client._strip_json_fence's tolerance for incidental prose/fencing."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    return json.loads(m.group(0) if m else text)


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, *, api_key: str, base_url: str = "", timeout: float = _DEFAULT_TIMEOUT):
        if not api_key:
            raise ValueError("AnthropicProvider requires a non-empty api_key")
        self._api_key = api_key
        self._base_url = (base_url or _DEFAULT_BASE_URL).rstrip("/")
        self._timeout = timeout

    async def chat_json(
        self, model: str, system_prompt: str, user_prompt: str,
        temperature: float = 0.1, **kw,
    ) -> OllamaResult:
        payload = {
            "model": model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "temperature": temperature,
            "max_tokens": int(kw.get("max_tokens", 4096)),
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(f"{self._base_url}/messages", headers=headers, json=payload)
                resp.raise_for_status()
                body = resp.json()
        except httpx.TimeoutException as e:
            raise ProviderCallError(f"anthropic call timed out after {self._timeout}s: {e}") from e
        except httpx.HTTPError as e:
            raise ProviderCallError(f"anthropic call failed: {e}") from e

        try:
            text = "".join(
                block.get("text", "") for block in body.get("content", [])
                if block.get("type") == "text")
            data = _extract_json(text)
        except (json.JSONDecodeError, TypeError, AttributeError) as e:
            raise ProviderCallError(f"anthropic returned an unparseable response: {e}") from e

        usage = body.get("usage") or {}
        return OllamaResult(
            data=data,
            prompt_tokens=int(usage.get("input_tokens", 0) or 0),
            completion_tokens=int(usage.get("output_tokens", 0) or 0),
        )

    chat_json_metered = chat_json
