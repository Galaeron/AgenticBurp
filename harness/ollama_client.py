from __future__ import annotations
import json
import logging
import re
import asyncio
import time
import contextlib
import contextvars
import httpx
from dataclasses import dataclass

from harness import prompt_validator
from harness import circuit_breaker
from harness import rate_limiter
from harness import audit_logger

log = logging.getLogger("harness.ollama_client")

# E9 profiling label for the model calls made inside a `with model_stage(...)`
# block. A ContextVar, so it follows the awaiting task (and any task or thread
# copied from it) without a parameter threaded through every call site, and a
# call made outside any block lands in "unlabelled". The label is bookkeeping
# only: it never reaches the prompt, the payload, or any verdict.
_MODEL_STAGE: contextvars.ContextVar[str] = contextvars.ContextVar(
    "harness_model_stage", default="unlabelled")


@contextlib.contextmanager
def model_stage(label: str):
    """Attribute every OllamaClient call made inside the block to `label`."""
    token = _MODEL_STAGE.set(str(label or "unlabelled"))
    try:
        yield
    finally:
        _MODEL_STAGE.reset(token)


# Per-stage counters; the ms fields are floats, the rest ints. The max field is a
# high-water mark (the largest prompt the stage sent), not a counter.
_STAGE_COUNT_FIELDS = ("calls", "completed", "failed", "cancelled", "retried",
                       "prompt_tokens", "completion_tokens", "context_truncated")
_STAGE_MS_FIELDS = ("prompt_eval_ms", "eval_ms", "load_ms", "wall_ms")
_STAGE_MAX_FIELDS = ("max_prompt_tokens",)


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


# Exceptions that do not count as circuit-breaker failures: a config-level,
# per-prompt or rate-limit fault, not a service outage. What still counts: a
# transport failure, a timeout, a 5xx. Shared with RunContext's per-run breaker.
BREAKER_EXCLUDED_ERRORS = (OllamaModelNotFoundError, OllamaInvalidJSONError,
                           OllamaContextTruncatedError, OllamaEmptyResponseError,
                           OllamaRateLimitedError)


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


def is_cloud_model(model: str) -> bool:
    """True for an Ollama cloud model (`gemma4:31b-cloud`, `glm-4.6:cloud`). Those
    run off-host, ignore options.num_ctx and are not in /api/ps, so the context
    guard and the preflight leave them alone."""
    name = str(model or "").strip().lower()
    return name.endswith("-cloud") or name.endswith(":cloud")


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
        log.debug("context window announcement failed", exc_info=True)


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
        log.debug("context preflight failed: %s", e)
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


@dataclass
class OllamaResult:
    """Parsed response body plus real token usage from the same call --
    verified against Ollama's actual /api/chat response shape (top-level
    prompt_eval_count / eval_count fields alongside "message" and "done"),
    not assumed. See effort.EffortLedger, which is what these numbers are
    for."""
    data: dict
    prompt_tokens: int | None
    completion_tokens: int | None
    measurement: dict | None = None


def _strip_json_fence(s: str) -> str:
    s = s.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    m = re.search(r"\{.*\}", s, re.DOTALL)
    return m.group(0) if m else s


# The characters that may legally follow a backslash inside a JSON string.
_VALID_JSON_ESCAPE = set('"\\/bfnrtu')


def _repair_json_escapes(s: str) -> str:
    r"""Double any backslash that does NOT begin a legal JSON escape sequence.

    Root cause (investigated live this session against gemma4:31b-cloud): some
    models -- notably CLOUD-hosted ones reached through Ollama, which do NOT run
    under Ollama's output grammar, so `format: json`/`format: <schema>` is a
    silent no-op for them (verified: 18/18 responses came back markdown-fenced
    and free-generated) -- occasionally emit a RAW single backslash inside a
    JSON string value, e.g. a detection regex `\s`/`\d`/`\(` they forgot to
    double. That is illegal JSON (`json.JSONDecodeError: Invalid \escape`) and
    was silently dropping ~15-20% of that model's agent findings, including
    whole SQLi detections (the "green tests, dead pipeline" shape). qwen3:8b
    local honors `format: json` and never needs this.

    This turns `\s` -> `\\s` while leaving genuine escapes (`\"`, `\\`, `\n`,
    `\uXXXX`, ...) untouched, so it is idempotent on already-valid JSON. It is
    applied ONLY as a fallback after a strict parse fails (see `_loads_lenient`),
    so the reliable path is never touched. It is a best-effort repair, not a JSON
    grammar: if the model produced structurally-broken JSON (unbalanced braces,
    a bad `\uXX`), the retried parse still raises and the caller still sees
    OllamaInvalidJSONError -- we never fabricate a parse."""
    return re.sub(
        r"\\(.)",
        lambda m: ("\\" + m.group(1)) if m.group(1) in _VALID_JSON_ESCAPE
        else ("\\\\" + m.group(1)),
        s,
    )


def _loads_lenient(s: str) -> dict:
    """json.loads, but retried once through _repair_json_escapes if the strict
    parse fails on a stray backslash. Valid JSON parses on the first try and is
    never passed through the repair."""
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return json.loads(_repair_json_escapes(s))


# A thinking model can also put its trace inline, ahead of the answer, as a
# <think>...</think> block in `content` (Ollama's separate `message.thinking`
# field is the other shape). Only a LEADING block is the trace; braces inside it
# would otherwise be picked up by _strip_json_fence's `{.*}` as the answer.
_INLINE_THINK = re.compile(r"^\s*<think>.*?</think>\s*", re.DOTALL)


def _strip_inline_thinking(content: str) -> tuple[str, int]:
    """(content without a leading <think> block, length of the removed trace)."""
    m = _INLINE_THINK.match(content)
    if not m:
        return content, 0
    return content[m.end():], m.end()


def parse_think_setting(value) -> bool | frozenset[str]:
    """AR-10 P2: the `ollama.think` config key, normalised.

    Unset, null, false or an empty list => False: every call sends
    `"think": False`, exactly as before this key existed. `true` => every call
    sends `"think": True`. A list of model_stage labels (e.g. `[iterative,
    critique]`) => only calls made inside a `with model_stage(label)` block for
    one of those labels send `"think": True`, so a reasoning-stage arm can run
    with its trace while agents and routing stay fast. Strict on purpose, like
    privacy.external_lookups: a quoted "true"/"false" or any other type raises
    at startup instead of being read as truthy."""
    if value is None or value is False:
        return False
    if value is True:
        return True
    if isinstance(value, (list, tuple)) and all(
            isinstance(label, str) and label.strip() for label in value):
        return frozenset(label.strip() for label in value) or False
    raise ValueError(
        "invalid ollama config: ollama.think must be true, false (unquoted) or a "
        f"list of model_stage labels, got {type(value).__name__}")


def think_setting(value) -> dict:
    """Plain-data description of a think setting for run provenance:
    {"setting": "off" | "on" | "stages", "stages": [labels]}. Accepts the raw
    config value or an already-parsed one."""
    parsed = parse_think_setting(value if not isinstance(value, frozenset) else sorted(value))
    if parsed is True:
        return {"setting": "on", "stages": []}
    if parsed:
        return {"setting": "stages", "stages": sorted(parsed)}
    return {"setting": "off", "stages": []}


def _chat_options(temperature, num_ctx, seed) -> dict:
    """Build Ollama's `options` for a chat call.

    `temperature` is always present. `num_ctx` and `seed` are opt-in and gated on
    `is not None` (NOT truthiness) so that a deliberate `seed: 0` -- a perfectly
    valid, reproducible seed -- is passed through rather than silently dropped,
    and the payload stays byte-identical for every caller that sets neither.
    """
    options = {"temperature": temperature}
    if num_ctx:
        options["num_ctx"] = num_ctx
    if seed is not None:
        options["seed"] = seed
    return options


class OllamaClient:
    """
    Minimal wrapper around Ollama's /api/chat endpoint.
    Docs: https://github.com/ollama/ollama/blob/main/docs/api.md
    """

    def __init__(self, base_url: str, timeout_seconds: float = 120.0,
                 num_ctx: int | None = None, seed: int | None = None,
                 transient_retries: int | None = DEFAULT_TRANSIENT_RETRIES,
                 think: bool | list[str] | None = None):
        self.base_url = base_url.rstrip("/")
        # AR-10 P2: opt-in thinking mode (`ollama.think`, see
        # parse_think_setting). Default off, so every payload keeps
        # `"think": False` byte-identical unless a config sets it.
        self.think = parse_think_setting(think)
        self.timeout_seconds = timeout_seconds
        # Max retries (not attempts) after a transient failure; 0 disables.
        # Clamped to [0, _MAX_TRANSIENT_RETRIES] so the retry is always bounded.
        # None => the default, so an unset config value never means "unbounded".
        self.transient_retries = max(0, min(
            int(DEFAULT_TRANSIENT_RETRIES if transient_retries is None else transient_retries),
            _MAX_TRANSIENT_RETRIES))
        # Optional run-level Ollama seed (options.seed), a reproducibility control
        # for the decisive run -- NOT a guarantee of identical output across
        # hardware or Ollama/model versions. Because every model call in the
        # harness (agents, coordinator, critique, allocation) goes through one
        # OllamaClient, setting it here is the single, un-forgettable choke point
        # that seeds EVERY call; a per-call `seed=` on chat_json/_metered still
        # overrides it when a specific call wants a different seed. Gated on
        # `is not None` (NOT truthiness) so a deliberate `seed: 0` is kept, and
        # omitted entirely (payload byte-identical) when no seed is configured.
        self.seed = int(seed) if seed is not None else None
        # Optional per-request Ollama context window (options.num_ctx). Default
        # None => the key is NOT sent, so Ollama keeps its own server/model
        # default and every existing call site is byte-for-byte unchanged. Set
        # it (config.local.yaml's `ollama.num_ctx`) when that default is too
        # small for the harness's prompts: on job 0574e29a0799 Ollama's 4096
        # default cut every prompt over 4,096 tokens (the largest was 8,118),
        # so 16384 is the value to pin for a local model. Too large has a cost
        # too: on a VRAM-limited box a model loaded at 32768 (qwen3:8b, ~10 GB)
        # spills onto CPU and each call runs several times slower. Cloud models
        # ignore it. Never sent unless set, so this cannot change behavior for a
        # caller that leaves it unset; the context guard (context_overflow)
        # reports a call that did not fit either way.
        self.num_ctx = int(num_ctx) if num_ctx else None

        # Pure instrumentation (added for the P2-2 ablation cost axis): count
        # model calls and accumulate the real prompt/completion token usage this
        # client already reads off each response for logging. Every model call in
        # the harness (agents, coordinator, critique) goes through one
        # OllamaClient, so these totals capture a whole run's model cost without
        # Run-owned accounting lives in the caller's EffortBudget. These client
        # lifetime counters are diagnostics; token sums are known lower bounds
        # when model_unknown_usage_count is nonzero. model_call_count counts
        # usable JSON responses; attempted/completed/error/cancelled are separate.
        self.model_call_count = 0
        self.model_prompt_tokens = 0
        self.model_completion_tokens = 0
        self.model_attempted_count = 0
        self.model_completed_count = 0
        self.model_error_count = 0
        self.model_cancelled_count = 0
        self.model_unknown_usage_count = 0
        # E6 retry visibility. model_retry_count: resends made after a transient
        # failure (a call retried twice adds 2; one cancelled while backing off
        # adds 0).
        # model_retry_recovered_count: calls that needed >= 1 retry and then
        # returned a usable result. The attempted/error counters above stay
        # per LOGICAL call so run accounting is unchanged by retries.
        self.model_retry_count = 0
        self.model_retry_recovered_count = 0
        # AR-10 P2: calls that sent `"think": True`, and the reasoning traces
        # that came back. Counts and lengths only -- the trace text is dropped.
        self.model_think_call_count = 0
        self.model_thinking_trace_count = 0
        self.model_thinking_trace_chars = 0
        # E9: the same usage, split by the active model_stage label. Pure
        # bookkeeping read off values this client already has -- it adds no
        # request and changes no result.
        self.stage_metrics: dict[str, dict] = {}
        # Context-window guard (see context_overflow). Calls whose reply was
        # discarded because the call did not fit the window, by kind; the window
        # each local model is loaded with, from GET /api/ps (0 = Ollama does not
        # report one, so it is never asked again); when each model's window was
        # last looked up; the largest prompt each model was sent.
        self.model_context_truncated_count = 0
        self.model_context_truncated_by_kind = {"prompt": 0, "reply": 0}
        self._context_windows: dict[str, int] = {}
        self._context_probed_at: dict[str, float] = {}
        self._max_prompt_tokens: dict[str, int] = {}
        self._context_warned: set[tuple[str, str]] = set()

        # Initialize circuit breaker. Uses the shared-registry accessor
        # (not `OllamaCircuitBreaker(...)` directly) so that every
        # OllamaClient instance pointed at the same logical service shares
        # one breaker and its failure state -- otherwise a short-lived
        # client (e.g. one constructed per call) never accumulates
        # failures and the breaker can never trip for that call site,
        # even while a long-lived client's breaker is open. See
        # circuit_breaker.get_ollama_circuit_breaker's docstring.
        self.circuit_breaker = circuit_breaker.get_ollama_circuit_breaker(
            "ollama",
            # Every field spelled out explicitly, matching OllamaCircuitBreaker's
            # own hardcoded defaults exactly -- its merge logic uses `x or default`,
            # so passing a config with any field left at CircuitBreakerConfig's
            # own generic defaults (5/3/30.0/1) would silently override the
            # Ollama-specific ones (3/2/60.0/1) for THOSE fields too, not just
            # excluded_exceptions. Only real change here: exclude
            # BREAKER_EXCLUDED_ERRORS, see each class's docstring for why.
            circuit_breaker.CircuitBreakerConfig(
                failure_threshold=3,
                success_threshold=2,
                timeout_seconds=60.0,
                half_open_max_requests=1,
                excluded_exceptions=BREAKER_EXCLUDED_ERRORS,
                enabled=True,
                # E6 failure-rate rule: also open when >= half of the last 20
                # calls failed, even if never 3 in a row.
                window_size=20,
                failure_rate_threshold=0.5,
            ),
        )
        
        # Initialize rate limiter
        self.rate_limiter = rate_limiter.get_token_limiter("ollama")
        
        # Initialize prompt validator
        self.prompt_validator = prompt_validator.PromptValidator()
        
        # Initialize audit logger
        self.audit_logger = audit_logger.get_audit_logger()

    def _stage_row(self) -> dict:
        """The counters for the active model_stage label, created on first use."""
        label = _MODEL_STAGE.get()
        row = self.stage_metrics.get(label)
        if row is None:
            row = self.stage_metrics[label] = {
                **dict.fromkeys(_STAGE_COUNT_FIELDS, 0), **dict.fromkeys(_STAGE_MS_FIELDS, 0.0),
                **dict.fromkeys(_STAGE_MAX_FIELDS, 0)}
        return row

    def metrics_snapshot(self) -> dict:
        """Plain-data copy of the per-stage usage plus the client-wide counters,
        for the job result and run manifest (E9)."""
        stages = {label: {k: (round(v, 1) if isinstance(v, float) else v) for k, v in row.items()}
                  for label, row in self.stage_metrics.items()}
        totals = {k: sum(row[k] for row in stages.values())
                  for k in (*_STAGE_COUNT_FIELDS, *_STAGE_MS_FIELDS)}
        totals.update({k: round(totals[k], 1) for k in _STAGE_MS_FIELDS})
        totals.update({k: max((row[k] for row in stages.values()), default=0)
                       for k in _STAGE_MAX_FIELDS})
        return {"stages": stages, "totals": totals,
                "client": {"attempted": self.model_attempted_count,
                           "completed": self.model_completed_count,
                           "usable": self.model_call_count,
                           "errors": self.model_error_count,
                           "cancelled": self.model_cancelled_count,
                           "retries": self.model_retry_count,
                           "retry_recovered": self.model_retry_recovered_count,
                           "unknown_usage": self.model_unknown_usage_count,
                           "context_truncated": self.model_context_truncated_count},
                # Whether this run measured reasoning mode: the configured
                # setting plus the calls that actually sent think on.
                "think": {**think_setting(self.think),
                          "think_calls": self.model_think_call_count,
                          "traces": self.model_thinking_trace_count,
                          "trace_chars": self.model_thinking_trace_chars},
                # Calls that did not fit the context window, and the windows the
                # guard checked them against (a list, so it is not delta'd).
                "context": {"truncated": dict(self.model_context_truncated_by_kind),
                            "windows": self._context_window_rows()}}

    def _context_window_rows(self) -> list[dict]:
        if self.num_ctx:
            return [{"model": "*", "context_length": self.num_ctx, "source": "num_ctx"}]
        return [{"model": key, "context_length": length, "source": "api_ps"}
                for key, length in sorted(self._context_windows.items()) if length]

    async def _probe_context_windows(self) -> None:
        """One GET /api/ps: cache the context window of every model it lists.
        Best-effort and short-timeout; a failed lookup leaves the cache as it was
        and never fails the model call that asked for it."""
        try:
            async with httpx.AsyncClient(timeout=_CONTEXT_PROBE_TIMEOUT) as client:
                resp = await client.get(f"{self.base_url}/api/ps")
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log.debug("context window lookup (GET /api/ps) failed: %s", e)
            return
        rows = data.get("models") if isinstance(data, dict) else None
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            length = row.get("context_length")
            length = length if type(length) is int and length > 0 else 0
            for name in {row.get("name"), row.get("model")}:
                if isinstance(name, str) and name:
                    self._context_windows[_model_key(name)] = length

    async def _context_window(self, model: str, prompt_tokens=None) -> tuple[int | None, str | None]:
        """(window, source) a call to `model` runs in: the configured num_ctx, else
        the window /api/ps reports the model loaded with ("api_ps"). (None, None)
        for a cloud model and when the window is not known. A cached window is
        looked up again when a prompt larger than it came back (the model was
        reloaded), at most once per _CONTEXT_PROBE_RETRY_SECONDS."""
        if is_cloud_model(model):
            return None, None
        if self.num_ctx:
            return self.num_ctx, "num_ctx"
        key = _model_key(model)
        cached = self._context_windows.get(key)
        if cached == 0:
            return None, None
        if cached and not (isinstance(prompt_tokens, int) and prompt_tokens > cached):
            return cached, "api_ps"
        probed_at = self._context_probed_at.get(key)
        if probed_at is None or time.monotonic() - probed_at >= _CONTEXT_PROBE_RETRY_SECONDS:
            self._context_probed_at[key] = time.monotonic()
            await self._probe_context_windows()
            cached = self._context_windows.get(key)
        return (cached, "api_ps") if cached else (None, None)

    async def _check_context(self, model, payload, prompt_tokens, completion_tokens,
                             done_reason, measurement) -> None:
        """Raise OllamaContextTruncatedError when this call did not fit the model's
        context window (see context_overflow), or a local model's reply stopped
        for length (the harness never sets num_predict, so only the window can
        stop it); count and report it first. A call too small to fill any
        plausible window, and any cloud-model call, costs no lookup."""
        if is_cloud_model(model):
            return
        window = source = kind = None
        prompt_chars = sum(len(m.get("content") or "") for m in payload.get("messages") or []
                           if isinstance(m, dict))
        if isinstance(prompt_tokens, int) and (
                self.num_ctx or prompt_tokens + (completion_tokens or 0)
                >= _MIN_PLAUSIBLE_WINDOW // 2 - _WINDOW_SLACK_TOKENS):
            window, source = await self._context_window(model, prompt_tokens)
            kind = context_overflow(prompt_tokens, completion_tokens, prompt_chars, window)
        stopped_for_length = kind is None and done_reason == "length"
        if stopped_for_length:
            kind = "reply"
        if kind is None:
            return
        self.model_context_truncated_count += 1
        self.model_context_truncated_by_kind[kind] += 1
        self._stage_row()["context_truncated"] += 1
        measurement["outcome"] = "context_truncated"
        measurement["context_truncated"] = kind
        advice = (f"set ollama.num_ctx: {recommended_num_ctx(max(window or 0, ESTIMATED_LARGEST_PROMPT_TOKENS))} "
                  "in harness/config.local.yaml or use a cloud model")
        if kind == "prompt":
            what = (f"Ollama cut the {prompt_chars}-character prompt to {prompt_tokens} tokens "
                    f"to fit the {window}-token context window ({source})")
        elif not stopped_for_length:
            what = (f"prompt and reply filled the {window}-token context window ({source}): "
                    f"{prompt_tokens}+{completion_tokens} tokens")
        else:
            # Ollama reported the stop, but the counts do not show a full window
            # (unknown window, or one reported larger than the server used).
            what = (f"the reply stopped at the context limit (done_reason length, "
                    f"{prompt_tokens}+{completion_tokens} tokens"
                    + (f", {window}-token window per {source})" if window else ")"))
        err = OllamaContextTruncatedError(
            f"Model '{model}': {what}; reply discarded. {advice}",
            kind=kind, window=window, window_source=source)
        self.audit_logger.log_llm_error(model=model, error=err)
        first = (model, kind) not in self._context_warned
        self._context_warned.add((model, kind))
        log.log(logging.WARNING if first else logging.INFO, "%s", err)
        if first:
            _announce_warning(str(err), model=model, context_truncated=kind, window=window)
        raise err

    async def context_preflight(self, models) -> dict:
        """Engagement-start check that each local model's context window holds the
        harness's largest prompt: the largest this client has measured, or the
        r3 estimate when it has measured none larger. Logs a WARNING per model
        whose window is smaller. Reads only GET /api/ps; never loads a model or
        changes num_ctx. A model that is not loaded yet is "unknown": the
        per-call guard still checks every call it makes.

        Returns {num_ctx, largest_prompt: {tokens, source}, models: [{model,
        status (ok | too_small | unknown | cloud), context_length, source}],
        warnings: [str]}."""
        measured = max(self._max_prompt_tokens.values(), default=0)
        largest = max(measured, ESTIMATED_LARGEST_PROMPT_TOKENS)
        largest_source = "measured" if measured >= ESTIMATED_LARGEST_PROMPT_TOKENS else "estimated"
        names = sorted({str(m).strip() for m in models or () if m and str(m).strip()})
        if not self.num_ctx and any(not is_cloud_model(m) for m in names):
            await self._probe_context_windows()
        rows, warnings = [], []
        for name in names:
            if is_cloud_model(name):
                rows.append({"model": name, "status": "cloud", "context_length": None, "source": None})
                continue
            if self.num_ctx:
                window, source = self.num_ctx, "num_ctx"
            else:
                window = self._context_windows.get(_model_key(name)) or None
                source = "api_ps" if window else None
            status = "unknown" if window is None else ("too_small" if window < largest else "ok")
            rows.append({"model": name, "status": status, "context_length": window, "source": source})
            if status == "unknown":
                rows[-1]["note"] = ("not loaded at run start and ollama.num_ctx is unset: it loads "
                                    "at the Ollama server's default context (4096 on 0.40.13 unless "
                                    f"OLLAMA_CONTEXT_LENGTH is set), smaller than the {largest}-token "
                                    "prompts this harness sends")
            if status != "too_small":
                continue
            basis = ("measured on this server" if largest_source == "measured"
                     else "estimated: the largest prompt of job 0574e29a0799")
            where = (f"ollama.num_ctx is {window}" if source == "num_ctx" else
                     f"model {name} is loaded with a {window}-token context window and "
                     "ollama.num_ctx is unset")
            warnings.append(
                f"Context window too small: {where}, but harness prompts reach {largest} tokens "
                f"({basis}). Ollama cuts a longer prompt to about half the window and still "
                "answers it; on job 0574e29a0799 that cut 88 prompts. The guard now discards "
                "those replies, so the calls fail instead. Set ollama.num_ctx: "
                f"{recommended_num_ctx(largest)} in harness/config.local.yaml, or use a cloud model.")
        for warning in warnings:
            log.warning("%s", warning)
            _announce_warning(warning)
        if not warnings and any(r["status"] == "unknown" for r in rows):
            log.info("context preflight: %s not loaded yet; each call is checked as it returns",
                     ", ".join(r["model"] for r in rows if r["status"] == "unknown"))
        return {"num_ctx": self.num_ctx,
                "largest_prompt": {"tokens": largest, "source": largest_source},
                "models": rows, "warnings": warnings}

    def _think_for_call(self) -> bool:
        """The `think` value for a call made now: on for every call, or only
        inside a model_stage block whose label is listed."""
        if self.think is True:
            return True
        return bool(self.think) and _MODEL_STAGE.get() in self.think

    async def _chat(self, model, system_prompt, user_prompt, temperature=0.1, seed=None):
        """Keep consumption independent of successful JSON parsing."""
        started = time.monotonic()
        self.model_attempted_count += 1
        stage = self._stage_row()
        stage["calls"] += 1
        measurement = {"prompt_tokens": None, "completion_tokens": None,
                       "attempted": True, "completed": False, "usable": False,
                       "queue_ms": None, "connection_ms": None,
                       "generation_ms": None, "wall_ms": None, "outcome": "error"}
        try:
            parsed, raw = await self._chat_impl(model, system_prompt, user_prompt,
                                               temperature, measurement, seed=seed)
            measurement["usable"] = True
            measurement["outcome"] = "ok"
            self.model_call_count += 1
            return parsed, raw
        except BaseException as exc:
            if isinstance(exc, asyncio.CancelledError):
                measurement["outcome"] = "cancelled"
                self.model_cancelled_count += 1
                stage["cancelled"] += 1
            else:
                self.model_error_count += 1
                stage["failed"] += 1
            # This receipt contains only counts/timing/state, never response text.
            setattr(exc, "inference_usage", measurement)
            raise
        finally:
            measurement["wall_ms"] = (time.monotonic() - started) * 1000.0
            stage["wall_ms"] += measurement["wall_ms"]

    async def _chat_impl(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        measurement: dict | None = None,
        seed: int | None = None,
    ) -> tuple[dict, dict]:
        """Shared implementation. Returns (parsed_json_body, raw_response_dict)
        so callers needing usage fields don't have to make a second call.
        
        This method integrates:
        - Prompt validation (prevents injection attacks)
        - Circuit breaker (prevents cascading failures)
        - Rate limiting (prevents overloading)
        - Audit logging (tracks all LLM interactions)
        """
        from harness.security import sanitize_for_inference, safe_error_summary
        system_prompt, user_prompt = sanitize_for_inference(system_prompt, user_prompt)
        # Validate prompts
        try:
            validated_system = self.prompt_validator.validate_system_prompt(system_prompt)
            validated_user = self.prompt_validator.validate_user_prompt(user_prompt)
        except prompt_validator.ValidationError as e:
            self.audit_logger.log_security_event(
                event_type="prompt_validation_failed",
                message=f"Prompt validation failed: {safe_error_summary(e)}",
                severity="error",
            )
            raise OllamaError(f"Prompt validation failed: {safe_error_summary(e)}") from e
        
        # Log the prompt
        self.audit_logger.log_llm_prompt(
            model=model,
            system_prompt=validated_system,
            user_prompt=validated_user,
        )
        
        think = self._think_for_call()
        if think:
            self.model_think_call_count += 1
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": validated_system},
                {"role": "user", "content": validated_user},
            ],
            "format": "json",
            "stream": False,
            # options.num_ctx is included ONLY when self.num_ctx is set (opt-in,
            # see __init__); omitted otherwise so Ollama uses its own default and
            # the payload is unchanged for every caller that never sets it. The
            # same opt-in rule applies to options.seed: it is included exactly
            # when a seed was supplied -- `is not None`, NOT truthiness, so a
            # deliberate `seed: 0` (a valid, reproducible seed) is passed through
            # rather than silently dropped. A reproducibility control, not a
            # guarantee of identical output across hardware or Ollama versions.
            "options": _chat_options(
                temperature, self.num_ctx,
                # Per-call seed overrides the client's run-level default; when the
                # call supplies none, fall back to the client default. `is not
                # None` on both so seed=0 is honored at either level.
                seed if seed is not None else self.seed),
            # Every call site here wants fast, structured JSON classification
            # output, never a reasoning trace -- but a "thinking"-capable
            # model (Qwen3, Gemma 4, etc.) defaults to thinking ON when this
            # is omitted, silently generating a full hidden chain-of-thought
            # before ever producing content. Confirmed directly, live: the
            # exact same trivial one-word prompt against qwen3:8b on this
            # machine went from >130s (timed out) to 6s the moment this was
            # added -- previously misdiagnosed as a circuit-breaker /
            # model-config bug, when the real cause was thinking mode never
            # being disabled. Harmless no-op for non-thinking models
            # (llama3.1:8b, gemma2:9b) -- verified directly too, identical
            # output and latency with or without it.
            # AR-10 P2: True only when `ollama.think` opts this call in (all
            # calls, or listed model_stage labels); False otherwise, as before.
            "think": think,
        }
        url = f"{self.base_url}/api/chat"

        # Use circuit breaker and rate limiter. Resolved AT CALL TIME (not
        # self.circuit_breaker, cached at __init__) via current_ollama_breaker
        # (AR-2, LOOP half): when a RunContext has pushed a per-run breaker,
        # this call is governed by THAT run's isolated breaker; otherwise it
        # falls back to self.circuit_breaker -- the same process-wide shared
        # singleton this always used, unchanged for every no-run caller.
        #
        # E6 bounded transient retry: the retry loop lives INSIDE the breaker
        # context on purpose. The breaker sees one call and records one
        # outcome: a retry that recovers is a breaker SUCCESS, and only the
        # final failure (retries exhausted, or a permanent error) counts as a
        # breaker failure. The rate limiter is re-entered per attempt so
        # retries still respect it, and is NOT held during the backoff sleep.
        queue_started = time.monotonic()
        breaker = circuit_breaker.current_ollama_breaker("ollama")
        retries_done = 0
        timeout_retries_done = 0
        async with breaker:
            while True:
                attempt_queue_started = queue_started if retries_done == 0 else time.monotonic()
                try:
                    async with self.rate_limiter:
                        waited_ms = (time.monotonic() - attempt_queue_started) * 1000.0
                        measurement["queue_ms"] = (
                            waited_ms if measurement["queue_ms"] is None
                            else measurement["queue_ms"] + waited_ms)
                        parsed, data = await self._send_once(url, payload, model, measurement)
                except OllamaTransientError as exc:
                    retry_after = getattr(exc, "retry_after", None)
                    if not self._may_retry(retries_done) or (
                            getattr(exc, "timeout", False)
                            and timeout_retries_done >= MAX_TIMEOUT_RETRIES) or (
                            retry_after is not None and retry_after > _MAX_RETRY_AFTER_SECONDS):
                        if retries_done:
                            log.warning(
                                "Ollama call for model %s failed after %d transient retr%s (%s); giving up",
                                model, retries_done, "y" if retries_done == 1 else "ies", exc)
                        raise
                    retries_done += 1
                    timeout_retries_done += bool(getattr(exc, "timeout", False))
                    # A 429's Retry-After is the server's own floor on the wait.
                    delay = max(_backoff_delay(retries_done), retry_after or 0.0)
                    log.warning(
                        "Ollama transient failure for model %s (%s); retry %d/%d in %.1fs",
                        model, exc, retries_done, self.transient_retries, delay)
                    # A CancelledError raised while backing off propagates: no
                    # further attempt is made once the caller has cancelled.
                    await _backoff_sleep(delay)
                    # Counted only once the resend is really about to happen.
                    self.model_retry_count += 1
                    self._stage_row()["retried"] += 1
                    # Each resend is its own audited attempt.
                    self.audit_logger.log_llm_prompt(
                        model=model,
                        system_prompt=validated_system,
                        user_prompt=validated_user,
                    )
                    continue
                if retries_done:
                    self.model_retry_recovered_count += 1
                    log.info("Ollama call for model %s recovered after %d transient retr%s",
                             model, retries_done, "y" if retries_done == 1 else "ies")
                return parsed, data

    def _may_retry(self, retries_done: int) -> bool:
        """True while another transient retry is allowed: under the configured
        bound, and the calling task has not been cancelled."""
        return retries_done < self.transient_retries and not _cancellation_requested()

    async def _send_once(self, url: str, payload: dict, model: str, measurement: dict) -> tuple[dict, dict]:
        """One HTTP attempt against /api/chat. Transient faults (see
        _is_transient_status and the transport errors below) raise
        OllamaTransientError so the caller's retry loop can recognise them;
        everything else raises exactly what it always did and is never retried."""
        from harness.security import safe_error_summary
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.post(url, json=payload)
        except httpx.ConnectError as e:
            self.audit_logger.log_llm_error(
                model=model,
                error=OllamaError(safe_error_summary(e)),
            )
            raise OllamaTransientError(
                "Could not reach configured Ollama service"
            ) from e
        except httpx.TimeoutException as e:
            self.audit_logger.log_llm_error(
                model=model,
                error=e,
            )
            raise OllamaTransientError(f"Ollama request timed out after {self.timeout_seconds}s",
                                       timeout=True) from e
        except httpx.RemoteProtocolError as e:
            self.audit_logger.log_llm_error(
                model=model,
                error=OllamaError(safe_error_summary(e)),
            )
            raise OllamaTransientError("Ollama closed the connection unexpectedly") from e

        if resp.status_code != 200:
            if resp.status_code == 429:
                retry_after = _retry_after_seconds(resp.headers.get("retry-after"))
                err = OllamaRateLimitedError(
                    "Ollama returned HTTP 429 (rate limited"
                    + (f", Retry-After {retry_after:.0f}s)" if retry_after is not None else ")"),
                    retry_after=retry_after)
                self.audit_logger.log_llm_error(model=model, error=err)
                raise err
            if _is_transient_status(resp.status_code):
                self.audit_logger.log_llm_error(
                    model=model,
                    error=OllamaError(f"Ollama returned HTTP {resp.status_code}"),
                )
                raise OllamaTransientError(f"Ollama returned HTTP {resp.status_code}")

            if resp.status_code == 404:
                # Verified directly against a live Ollama instance: this
                # is specifically "model tag doesn't exist" -- see
                # OllamaModelNotFoundError's own docstring for why this
                # must not count as a circuit-breaker failure.
                err = OllamaModelNotFoundError(
                    f"Model '{model}' not found on this Ollama instance"
                )
                self.audit_logger.log_llm_error(model=model, error=err)
                raise err

            self.audit_logger.log_llm_error(
                model=model,
                error=OllamaError(f"Ollama returned HTTP {resp.status_code}"),
            )
            raise OllamaError(f"Ollama returned HTTP {resp.status_code}")

        data = resp.json()
        if not isinstance(data, dict):
            raise OllamaInvalidJSONError("Ollama returned an invalid response envelope")
        def count(key):
            value = data.get(key)
            return value if type(value) is int and value >= 0 else None
        prompt_tokens, completion_tokens = count("prompt_eval_count"), count("eval_count")
        measurement.update(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                           completed=True)
        duration = data.get("eval_duration")
        if type(duration) in (int, float) and duration >= 0:
            measurement["generation_ms"] = duration / 1_000_000.0
        data["_inference_measurement"] = measurement
        self.model_completed_count += 1
        self.model_prompt_tokens += prompt_tokens or 0
        self.model_completion_tokens += completion_tokens or 0
        stage = self._stage_row()
        stage["completed"] += 1
        stage["prompt_tokens"] += prompt_tokens or 0
        stage["completion_tokens"] += completion_tokens or 0
        if prompt_tokens is not None:
            stage["max_prompt_tokens"] = max(stage["max_prompt_tokens"], prompt_tokens)
            model_key = _model_key(model)
            self._max_prompt_tokens[model_key] = max(self._max_prompt_tokens.get(model_key, 0),
                                                     prompt_tokens)
        for field, key in (("prompt_eval_ms", "prompt_eval_duration"), ("eval_ms", "eval_duration"),
                           ("load_ms", "load_duration")):
            nanos = data.get(key)
            if type(nanos) in (int, float) and nanos >= 0:
                stage[field] += nanos / 1_000_000.0
        if prompt_tokens is None or completion_tokens is None:
            self.model_unknown_usage_count += 1
        self.rate_limiter.record_usage(prompt_tokens, completion_tokens)
        # AR-10 P2: a reasoning trace is never the answer and is never kept.
        # Ollama returns it as message.thinking (think on) or, for some models,
        # inline as a leading <think> block in content. Drop it from the raw
        # envelope handed back to callers and keep only its length.
        message = data.get("message")
        trace_chars = 0
        if isinstance(message, dict):
            thinking = message.pop("thinking", None)
            if isinstance(thinking, str):
                trace_chars += len(thinking)
            if isinstance(message.get("content"), str):
                message["content"], inline_chars = _strip_inline_thinking(message["content"])
                trace_chars += inline_chars
        if trace_chars:
            measurement["thinking_chars"] = trace_chars
            self.model_thinking_trace_count += 1
            self.model_thinking_trace_chars += trace_chars
        # Before the empty-body check: a reply that ran out of window often comes
        # back empty, and that is a context fault, not an Ollama one.
        await self._check_context(model, payload, prompt_tokens, completion_tokens,
                                  data.get("done_reason"), measurement)
        content = data.get("message", {}).get("content", "")
        if not content:
            err = OllamaEmptyResponseError("Ollama returned an empty message body")
            self.audit_logger.log_llm_error(model=model, error=err)
            raise err

        try:
            parsed = _loads_lenient(_strip_json_fence(content))
            if not isinstance(parsed, dict):
                raise OllamaInvalidJSONError("Model output must be a JSON object")

            # Log the response
            self.audit_logger.log_llm_response(
                model=model, response=content,
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            )

            return parsed, data
        except json.JSONDecodeError as e:
            self.audit_logger.log_llm_error(
                model=model,
                error=OllamaError(safe_error_summary(e)),
            )
            raise OllamaInvalidJSONError(
                f"Model '{model}' did not return valid JSON. "
                "Response content omitted."
            ) from e

    async def list_models(self) -> list[str]:
        """Model tags Ollama reports via GET /api/tags. Best-effort: returns []
        on any failure (unreachable, bad response) rather than raising -- this
        feeds a UI model picker, where "couldn't list" degrades to an empty
        local list, never a crash. NOTE cloud model tags (e.g. *-cloud) are
        reachable via /api/chat but do NOT appear here -- the server merges
        those in from config (models.cloud); see server.py /models."""
        url = f"{self.base_url}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout_seconds, 15.0)) as client:
                resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as e:
            log.warning("list_models: could not list Ollama models: %s", e)
            return []
        models = data.get("models", []) if isinstance(data, dict) else []
        names = [m.get("name") for m in models if isinstance(m, dict) and m.get("name")]
        return sorted(set(names))

    async def health_check(self, timeout: float = 3.0) -> dict:
        """Fast liveness probe for GET /health: is the Ollama backend reachable,
        and which model tags does it report? Best-effort and short-timeout (never
        the full inference timeout) so the health endpoint answers quickly even
        when Ollama is down. Returns {"reachable": bool, "models": [..],
        "error": str|None}. A refused connection (the common 'ollama not running'
        case) resolves near-instantly; `error` carries a short reason otherwise."""
        url = f"{self.base_url}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as e:
            return {"reachable": False, "models": [], "error": f"{type(e).__name__}: {e}"}
        models = data.get("models", []) if isinstance(data, dict) else []
        names = sorted({m.get("name") for m in models if isinstance(m, dict) and m.get("name")})
        return {"reachable": True, "models": names, "error": None}

    async def chat_json(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        seed: int | None = None,
    ) -> dict:
        """
        Calls the model and requires a JSON object back (Ollama's `format: json`
        mode). Returns the parsed dict. Raises OllamaError on failure --
        callers are responsible for turning that into a labeled, degraded
        result rather than pretending the call succeeded.

        `seed`, when supplied, is forwarded to Ollama's options.seed (a
        reproducibility control; `seed=0` is honored, not dropped).
        """
        parsed, _raw = await self._chat(model, system_prompt, user_prompt, temperature, seed=seed)
        return parsed

    async def chat_json_metered(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        seed: int | None = None,
    ) -> OllamaResult:
        """
        Same as chat_json, but also returns real token usage
        (prompt_eval_count / eval_count from Ollama's own response) so the
        caller can feed effort.EffortLedger with actual numbers instead of
        the unmeasured priors in effort._DEFAULT_TOKEN_ESTIMATE. Missing or
        invalid counts remain None; successful output can still be used.
        A sanitized measurement receipt accompanies errors as inference_usage,
        so returned counts survive output-parsing failures.

        `seed`, when supplied, is forwarded to Ollama's options.seed.
        """
        parsed, raw = await self._chat(model, system_prompt, user_prompt, temperature, seed=seed)
        measurement = raw["_inference_measurement"]
        return OllamaResult(data=parsed, prompt_tokens=measurement["prompt_tokens"],
                            completion_tokens=measurement["completion_tokens"], measurement=measurement)

