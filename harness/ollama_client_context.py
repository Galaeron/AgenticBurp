"""Context-window guard (truncation detection, num_ctx advice, the engagement
preflight), split from ollama_client.py (ARC-9). Import these names from
harness.ollama_client.
"""
from __future__ import annotations

import asyncio

import httpx


# Context-window guard. Ollama does not say when it cuts a prompt: the reply
# carries prompt_eval_count, the tokens it actually evaluated (cached ones
# included, verified on 0.40.13). Measured on job 0574e29a0799 and live on
# 0.40.13: a prompt longer than the window is cut to about HALF the window
# (4096 -> 2051, 512 -> 258), so the count alone never reaches the window. What
# gives it away is the prompt's length: harness prompts run 2.46-4.11 characters
# per evaluated token on gemma4 (713 calls), cut ones 6.51-9.80 (86 calls).
_WINDOW_SLACK_TOKENS = 16
_MAX_CHARS_PER_TOKEN = 5.0
# No window is probed for a call too small to fill one this size (Ollama's
# smallest default context), so small calls never cost a lookup.
_MIN_PLAUSIBLE_WINDOW = 2048
# A failed or inconclusive /api/ps lookup is not repeated for this model sooner.
_CONTEXT_PROBE_RETRY_SECONDS = 10.0
_CONTEXT_PROBE_TIMEOUT = httpx.Timeout(2.0, connect=1.0)
# The engagement preflight's prompt size when this client has measured none
# larger: the largest prompt of job 0574e29a0799 (Ollama's own log, gemma4).
ESTIMATED_LARGEST_PROMPT_TOKENS = 8118
# The context-window cache key for an OpenAI-compatible server (one model).
_OPENAI_SERVER_KEY = "*server*"


def _model_key(model: str) -> str:
    """The name /api/ps lists a model under: an untagged name means `:latest`."""
    name = str(model or "").strip().lower()
    return name if ":" in name.rsplit("/", 1)[-1] else name + ":latest"


def context_overflow(prompt_tokens, completion_tokens, prompt_chars, window) -> str | None:
    """"prompt" when Ollama cut the prompt to fit `window`, "reply" when prompt plus
    reply filled it, else None. None too when the window or the prompt count is
    unknown: no verdict without both.

    A prompt is cut when its evaluated count reaches the window (runners that cut
    to the full window), or when the count sits at half the window or more while
    the prompt we sent has far more characters than that many tokens can hold
    (Ollama 0.40, which cuts to about half; see the constants above)."""
    if not window or not isinstance(prompt_tokens, int):
        return None
    full = window - _WINDOW_SLACK_TOKENS
    if prompt_tokens >= full:
        return "prompt"
    if (prompt_tokens >= window // 2 - _WINDOW_SLACK_TOKENS
            and prompt_chars > _MAX_CHARS_PER_TOKEN * prompt_tokens):
        return "prompt"
    if isinstance(completion_tokens, int) and prompt_tokens + completion_tokens >= full:
        return "reply"
    return None


def recommended_num_ctx(prompt_tokens: int) -> int:
    """A window that holds `prompt_tokens` and as much again for the reply (and a
    reasoning trace), rounded up to a power of two: 8118 -> 16384."""
    return 1 << max(2 * int(prompt_tokens) - 1, 1).bit_length()


def _announce_warning(message: str, **detail) -> None:
    """Show a context-window warning on the activity feed, where the operator
    watches the run. Observability only: a feed failure never fails the call."""
    try:
        from harness import activity_feed
        activity_feed.publish("note", message, level="warn", **detail)
    except Exception:
        _oc.log.debug("context window announcement failed", exc_info=True)


async def run_context_preflight(client, models, *, timeout: float = 5.0) -> dict | None:
    """`client.context_preflight(models)`, best-effort: a client without one, a slow
    Ollama or any failure returns None and the run goes on. investigate_engagement
    calls this whether or not run instrumentation is on, so both runs send the
    same requests (it asks Ollama's /api/ps, never the target)."""
    preflight = getattr(client, "context_preflight", None)
    if not callable(preflight):
        return None
    try:
        report = await asyncio.wait_for(preflight(models), timeout)
    except Exception as e:
        _oc.log.debug("context preflight failed: %s", e)
        return None
    return report if isinstance(report, dict) else None


def context_truncated_count(client) -> int:
    """The client's running count of calls that did not fit the context window
    (0 for a client that does not keep one)."""
    count = getattr(client, "model_context_truncated_count", 0)
    return count if type(count) is int else 0


def context_window_error(client, truncated_before: int) -> dict | None:
    """The run's `errors` entry when calls made since `truncated_before` (an earlier
    context_truncated_count) did not fit the context window: their replies were
    discarded, so the run is degraded."""
    count = context_truncated_count(client) - truncated_before
    if count <= 0:
        return None
    return {"phase": "model_context",
            "error": (f"{count} model call(s) did not fit the model's context window; their "
                      f"replies were discarded. Set ollama.num_ctx ("
                      f"{recommended_num_ctx(ESTIMATED_LARGEST_PROMPT_TOKENS)} holds the largest "
                      "prompt measured) in harness/config.local.yaml, or use a cloud model")}


# Bound last (ollama_client imports this module): read only at call time.
from harness import ollama_client as _oc  # noqa: E402
