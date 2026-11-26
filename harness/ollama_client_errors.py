"""Model-client error types and the bounded transient-retry helpers (E6),
split from ollama_client.py (ARC-9). Import these names from
harness.ollama_client; OllamaClient reads the retry knobs there, so a
patched `ollama_client.MAX_TIMEOUT_RETRIES` (etc.) still takes effect.
"""
from __future__ import annotations

import asyncio
import time

import httpx


class OllamaError(RuntimeError):
    pass


class OllamaModelNotFoundError(OllamaError):
    """The requested model tag doesn't exist (Ollama's real, verified
    behavior: HTTP 404 with {"error": "model '<name>' not found"} --
    confirmed directly against a live local Ollama instance, not assumed).
    This is a permanent, config-level problem -- retrying or waiting won't
    fix it -- unlike a real outage/timeout, which the shared circuit
    breaker below is meant to protect against. Deliberately excluded from
    that breaker's failure count (see OllamaClient.__init__): a coordinator
    or agent misconfigured with a nonexistent model tag would otherwise
    3-strike the SAME shared breaker every other agent uses, and start
    rejecting every unrelated, correctly-configured agent's calls too --
    found live, this session, tracing exactly that symptom."""
    pass


class OllamaInvalidJSONError(OllamaError):
    """Model returned non-JSON / fenced output. A formatting fault, not a
    service outage -- excluded from the circuit breaker."""
    pass


class OllamaOutputCappedError(OllamaInvalidJSONError):
    """The reply reached `ollama.max_output_tokens` before it finished, so it is
    not a complete answer and is discarded. Without a cap a model stuck repeating
    itself (qwen3:8b on a 14k-character JWT prompt: over 10 minutes of repeated
    base64) generates until the request timeout; with one, the call fails fast.
    A subclass of OllamaInvalidJSONError on purpose: every caller already treats
    an unusable reply as one bounded, counted failure, and the circuit breaker
    ignores it (a model-output fault, not an outage)."""


class OllamaTransientError(OllamaError):
    """A fault that is plausibly gone on the next attempt: HTTP 500/502/503/504,
    a request timeout, a refused/failed connection, or a connection dropped
    mid-response (E6). OllamaClient retries these a bounded number of times
    (`ollama.transient_retries`); when the retries run out the last one is
    re-raised unchanged -- still an OllamaError, so every existing
    `except OllamaError` caller behaves exactly as before. Permanent errors
    (404 model-not-found, other 4xx, invalid JSON, validation failures) are
    never this type and are never retried.

    `timeout` marks a request timeout: those already cost the full
    `timeout_seconds`, so at most MAX_TIMEOUT_RETRIES of them are retried."""

    def __init__(self, message: str = "", *, timeout: bool = False):
        super().__init__(message)
        self.timeout = timeout


class OllamaRateLimitedError(OllamaTransientError):
    """HTTP 429: the service is up and asked us to slow down (Ollama cloud's free
    tier does). Retried like any transient fault, after the server's Retry-After
    when it sends one; a Retry-After over _MAX_RETRY_AFTER_SECONDS is a quota, not
    a burst, so it is not waited out. Excluded from the circuit breaker: a rate
    limit is not an outage, and opening the breaker would fast-fail every model's
    calls, local ones included."""

    def __init__(self, message: str = "", *, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class OllamaEmptyResponseError(OllamaError):
    """HTTP 200 with an empty message body: a model-output fault, not an outage,
    so excluded from the circuit breaker. On job 0574e29a0799, 151 of these (after
    7-15k-character prompts, so most likely replies that ran out of window) were
    counted as outages: the shared breaker re-opened 61 times and 2,130 of 3,097
    prompts were fast-failed unsent. When the context guard can tell the window
    filled, the call raises OllamaContextTruncatedError instead."""


class OllamaContextTruncatedError(OllamaError):
    """The call did not fit the model's context window, so its reply is not an
    answer to the prompt that was sent. `kind` is "prompt" (Ollama cut the prompt
    before evaluating it) or "reply" (prompt plus reply filled the window, so the
    reply was stopped or generated after Ollama shifted the prompt out).

    Measured on job 0574e29a0799 (Ollama 0.40.13, 4096-token window): Ollama cut
    88 prompts of 4,098-8,118 tokens down to 2,051 and answered them; 86 of those
    answers were used as if the whole prompt had been read. Deterministic for a
    given prompt and window, so it is never retried, and excluded from the
    circuit breaker: one oversized prompt must not fast-fail every other call."""

    def __init__(self, message: str = "", *, kind: str, window: int | None,
                 window_source: str | None):
        super().__init__(message)
        self.kind = kind
        self.window = window
        self.window_source = window_source


class OllamaCloudModelRefusedError(OllamaError):
    """SEC-1: a call to an Ollama cloud model (`-cloud` / `:cloud` suffix) while
    `ollama.allow_cloud_models` is false. Such a model runs off-host, so the
    sanitised but real exchange content in the prompt would leave the machine.
    Raised before any request is sent; a config fault, never retried and kept
    out of the circuit breaker. `slots` names the config slots involved when the
    run-start check raised it (model_egress.refuse_cloud_models)."""

    def __init__(self, message: str = "", *, slots: list[dict] | None = None):
        super().__init__(message)
        self.slots = list(slots or [])


class OllamaPacerTimeoutError(OllamaError):
    """The process-wide model-call pacer (`ollama.rate_limit`, see
    rate_limiter.pacer_config) did not admit the call within its
    max_wait_seconds, so nothing was sent. A local backlog, not an outage: never
    retried and kept out of the circuit breaker."""

    def __init__(self, message: str = "", *, max_wait_seconds: float | None = None):
        super().__init__(message)
        self.max_wait_seconds = max_wait_seconds


# Exceptions that do not count as circuit-breaker failures: a config-level,
# per-prompt or rate-limit fault, not a service outage. What still counts: a
# transport failure, a timeout, a 5xx. Shared with RunContext's per-run breaker.
BREAKER_EXCLUDED_ERRORS = (OllamaModelNotFoundError, OllamaInvalidJSONError,
                           OllamaContextTruncatedError, OllamaEmptyResponseError,
                           OllamaRateLimitedError, OllamaCloudModelRefusedError,
                           OllamaPacerTimeoutError)


# Bounded transient retry (E6). Measured on job 383f0ebff8e8: 24 of 126
# critique calls got an Ollama HTTP 500 (3.2 s median time-to-fail) and none was
# ever retried, so each shipped its findings unreviewed.
_TRANSIENT_HTTP_STATUSES = frozenset({500, 502, 503, 504})
DEFAULT_TRANSIENT_RETRIES = 2
# A timed-out attempt already waited timeout_seconds (240 s live); with
# max_parallel_agents 1, two such retries would stall serial dispatch for ~12
# minutes. One retry still recovers a one-off slow load.
MAX_TIMEOUT_RETRIES = 1
# Hard ceiling on the configured retry count: a typo like `transient_retries:
# 500` must not turn one failing call into minutes of retrying.
_MAX_TRANSIENT_RETRIES = 5
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_CAP_SECONDS = 8.0
# Longest 429 Retry-After that is waited out before a retry; a longer one fails
# the call now rather than stalling it.
_MAX_RETRY_AFTER_SECONDS = 30.0
# A connection the server reset after accepting it: while the request was being
# sent (WriteError) or while the reply was being read (ReadError). Seen live when
# llama-server was restarted mid-call: the raw ReadError escaped the client and
# ended the caller's agent loop. A refused connection (ConnectError) and a close
# before the reply was complete (RemoteProtocolError) are handled separately.
# Not httpx.NetworkError as a whole: ConnectError has its own message.
_DROPPED_CONNECTION_ERRORS = (httpx.ReadError, httpx.WriteError)


def _retry_after_seconds(value) -> float | None:
    """A Retry-After header (delta-seconds or an HTTP-date) as seconds from now,
    or None when absent or unreadable."""
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def _is_transient_status(status_code: int) -> bool:
    """HTTP statuses worth retrying. 404 (model not found) and every other 4xx
    are permanent and deliberately absent."""
    return status_code in _TRANSIENT_HTTP_STATUSES


def _backoff_delay(retry_number: int) -> float:
    """Seconds to wait before retry number `retry_number` (1-based): 1 s before
    the first retry, 2 s before the second, doubling, capped."""
    return min(_BACKOFF_BASE_SECONDS * (2 ** (max(retry_number, 1) - 1)), _BACKOFF_CAP_SECONDS)


async def _backoff_sleep(seconds: float) -> None:
    """The retry backoff wait. A module-level seam so tests can patch it out;
    a CancelledError raised while waiting propagates (no retry after cancel)."""
    await asyncio.sleep(seconds)


def _cancellation_requested() -> bool:
    """True when the current task has a pending cancellation request, so a
    retry is never started on behalf of a caller that has already cancelled."""
    cancelling = getattr(asyncio.current_task(), "cancelling", None)
    return bool(cancelling and cancelling())


# Bound last (ollama_client imports this module): read only at call time.
from harness import ollama_client as _oc  # noqa: E402
