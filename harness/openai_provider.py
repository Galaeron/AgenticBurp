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
import time

import httpx

from harness.ollama_client import OllamaResult
from harness import security

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
        system_prompt, user_prompt = security.sanitize_for_inference(system_prompt, user_prompt)
        started = time.monotonic()
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
            raise ProviderCallError(f"openai call timed out after {self._timeout}s") from None
        except httpx.HTTPError as e:
            raise ProviderCallError(f"openai call failed: {security.safe_error_summary(e)}") from None

        usage = body.get("usage") or {}
        def count(key):
            value = usage.get(key)
            return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
        receipt = {"attempted": True, "completed": True, "usable": False,
                   "prompt_tokens": count("prompt_tokens"), "completion_tokens": count("completion_tokens"),
                   "outcome": "error", "wall_ms": (time.monotonic() - started) * 1000.0}
        try:
            content = body["choices"][0]["message"]["content"]
            data = json.loads(content)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as e:
            error = ProviderCallError("openai returned an unparseable response")
            error.inference_usage = receipt
            raise error from None

        receipt.update(usable=True, outcome="ok")
        return OllamaResult(
            data=data,
            prompt_tokens=receipt["prompt_tokens"],
            completion_tokens=receipt["completion_tokens"], measurement=receipt,
        )

    chat_json_metered = chat_json
