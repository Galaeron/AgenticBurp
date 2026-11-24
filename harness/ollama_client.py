from __future__ import annotations
import json
import logging
import math
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
from harness import model_activity

# ARC-9: parts of this module live in sibling modules; every name stays importable
# from here. The siblings read this module's names at call time (patches reach them).
from harness.ollama_client_errors import (  # noqa: E402
    OllamaError, OllamaModelNotFoundError, OllamaInvalidJSONError, OllamaOutputCappedError,
    OllamaTransientError, OllamaRateLimitedError, OllamaEmptyResponseError,
    OllamaContextTruncatedError, OllamaCloudModelRefusedError, OllamaPacerTimeoutError,
    BREAKER_EXCLUDED_ERRORS, _TRANSIENT_HTTP_STATUSES, DEFAULT_TRANSIENT_RETRIES,
    MAX_TIMEOUT_RETRIES, _MAX_TRANSIENT_RETRIES, _BACKOFF_BASE_SECONDS, _BACKOFF_CAP_SECONDS,
    _MAX_RETRY_AFTER_SECONDS, _DROPPED_CONNECTION_ERRORS, _retry_after_seconds,
    _is_transient_status, _backoff_delay, _backoff_sleep, _cancellation_requested,
)
from harness.ollama_client_context import (  # noqa: E402
    _WINDOW_SLACK_TOKENS, _MAX_CHARS_PER_TOKEN, _MIN_PLAUSIBLE_WINDOW,
    _CONTEXT_PROBE_RETRY_SECONDS, _CONTEXT_PROBE_TIMEOUT, ESTIMATED_LARGEST_PROMPT_TOKENS,
    _OPENAI_SERVER_KEY, _model_key, context_overflow, recommended_num_ctx, _announce_warning,
    run_context_preflight, context_truncated_count, context_window_error,
)
from harness.ollama_client_wire import (  # noqa: E402
    OllamaResult, _strip_json_fence, _VALID_JSON_ESCAPE, _repair_json_escapes, _loads_lenient,
    _INLINE_THINK, _strip_inline_thinking, parse_think_setting, think_setting, API_OLLAMA,
    API_OPENAI, REASONING_EFFORTS, _MAX_OUTPUT_TOKENS_CEILING, _CAPPED_RETRY_FACTOR,
    _payload_cap, _with_cap, parse_backend_settings, backend_options, backend_setting, _number,
    parse_rate_limit, _openai_envelope, _openai_context_error, _chat_options,
)

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


def is_cloud_model(model: str) -> bool:
    """True for an Ollama cloud model (`gemma4:31b-cloud`, `glm-4.6:cloud`). Those
    run off-host, ignore options.num_ctx and are not in /api/ps, so the context
    guard and the preflight leave them alone. SEC-1: OllamaClient refuses them
    unless `ollama.allow_cloud_models` is true (see parse_allow_cloud_models)."""
    name = str(model or "").strip().lower()
    return name.endswith("-cloud") or name.endswith(":cloud")


def parse_allow_cloud_models(value) -> bool:
    """`ollama.allow_cloud_models`, strictly: unset means false. Anything but an
    unquoted boolean raises at startup, so the string "false" cannot be read as
    an opt-in (the same rule as privacy.external_lookups)."""
    if value is None:
        return False
    if type(value) is not bool:
        raise ValueError("invalid ollama config: ollama.allow_cloud_models must be an unquoted "
                         f"true or false, got {value!r}")
    return value


def cloud_refusal_reason(models) -> str:
    """The operator-facing reason a cloud model was refused (SEC-1)."""
    names = ", ".join(sorted({str(m) for m in models if m}))
    return (f"cloud model(s) {names} refused: a -cloud/:cloud model runs off-host, so "
            "exchange content would leave this machine. Use a local model, or set "
            "ollama.allow_cloud_models: true in harness/config.local.yaml to accept that egress.")


class OllamaClient:
    """
    Minimal wrapper around Ollama's /api/chat endpoint.
    Docs: https://github.com/ollama/ollama/blob/main/docs/api.md
    """

    def __init__(self, base_url: str, timeout_seconds: float = 120.0,
                 num_ctx: int | None = None, seed: int | None = None,
                 transient_retries: int | None = DEFAULT_TRANSIENT_RETRIES,
                 think: bool | list[str] | None = None, *, api: str | None = None,
                 max_output_tokens: int | None = None, reasoning_effort: str | None = None,
                 allow_cloud_models: bool | None = None, rate_limit: dict | None = None):
        self.base_url = base_url.rstrip("/")
        # `ollama.rate_limit` (see parse_rate_limit), validated before anything else
        # so a bad value refuses the client; applied to the shared pacer below.
        pacer = parse_rate_limit(rate_limit)
        # `ollama.api` / `ollama.max_output_tokens` / `ollama.reasoning_effort`
        # (see parse_backend_settings). All unset => the Ollama payload is
        # byte-identical to the one sent before these keys existed.
        self.api, self.max_output_tokens, self.reasoning_effort = parse_backend_settings(
            api, max_output_tokens, reasoning_effort, think)
        # SEC-1: `ollama.allow_cloud_models` (default false). Every model call
        # goes through _chat, which refuses a cloud-suffixed model before any
        # request unless this is true, whichever slot (coordinator, routing,
        # agent override, critique, writeups) or live /settings toggle chose it.
        self.allow_cloud_models = parse_allow_cloud_models(allow_cloud_models)
        self.model_cloud_refused_count = 0
        self._cloud_refusal_warned: set[str] = set()
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
        # Replies discarded because they reached max_output_tokens unfinished; the
        # calls asked once more with a larger cap, and those that then answered.
        self.model_output_capped_count = 0
        self.model_output_capped_retry_count = 0
        self.model_output_capped_recovered_count = 0
        self._context_windows: dict[str, int] = {}
        self._context_probed_at: dict[str, float] = {}
        self._max_prompt_tokens: dict[str, int] = {}
        self._context_warned: set[tuple[str, str]] = set()
        # TOK-4: each model's trained maximum context from POST /api/show
        # (0 = the server answered without one, never asked again).
        self._show_windows: dict[str, int] = {}

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
        
        # The model-call pacer: ONE token limiter for every client in the process
        # (rate_limiter.PACER_NAME), entered before each attempt. With
        # `ollama.rate_limit` set, this client applies it to that shared limiter,
        # so the latest configured client sets the pace for all of them; without
        # it the limiter keeps what it has (the shipped 10-call burst, then one
        # call every 6 s, unless a client applied other values). The run manifest
        # records the values in force (rate_limiter.pacer_state).
        self.rate_limiter = (rate_limiter.configure_pacer(pacer) if pacer is not None
                             else rate_limiter.get_token_limiter(rate_limiter.PACER_NAME))
        
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
                           "context_truncated": self.model_context_truncated_count,
                           "output_capped": self.model_output_capped_count,
                           "output_capped_retried": self.model_output_capped_retry_count,
                           "output_capped_recovered": self.model_output_capped_recovered_count,
                           "cloud_refused": self.model_cloud_refused_count},
                # Which wire protocol served the run, and its output cap.
                "backend": {"api": self.api, "max_output_tokens": self.max_output_tokens,
                            "reasoning_effort": self.reasoning_effort,
                            "allow_cloud_models": self.allow_cloud_models},
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
        return [{"model": key, "context_length": length, "source": self._window_source()}
                for key, length in sorted(self._context_windows.items()) if length]

    async def _probe_context_windows(self) -> None:
        """One GET /api/ps: cache the context window of every model it lists.
        Best-effort and short-timeout; a failed lookup leaves the cache as it was
        and never fails the model call that asked for it. With api "openai" it is
        GET /props instead (llama-server: one model, one per-slot window)."""
        if self.api == API_OPENAI:
            await self._probe_openai_window()
            return
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

    async def _probe_openai_window(self) -> None:
        """llama-server's GET /props: default_generation_settings.n_ctx is the
        window of each slot, the most one request can use. Cached under one
        server key: the server answers for whatever model name a call carries."""
        try:
            async with httpx.AsyncClient(timeout=_CONTEXT_PROBE_TIMEOUT) as client:
                resp = await client.get(f"{self.base_url}/props")
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log.debug("context window lookup (GET /props) failed: %s", e)
            return
        settings = data.get("default_generation_settings") if isinstance(data, dict) else None
        length = settings.get("n_ctx") if isinstance(settings, dict) else None
        self._context_windows[_OPENAI_SERVER_KEY] = length if type(length) is int and length > 0 else 0

    async def _probe_show_window(self, model: str) -> None:
        """POST /api/show: the model's trained maximum context from model_info
        (`<architecture>.context_length`). Best-effort, short timeout; a failed
        lookup leaves the cache as it was."""
        try:
            async with httpx.AsyncClient(timeout=_CONTEXT_PROBE_TIMEOUT) as client:
                resp = await client.post(f"{self.base_url}/api/show", json={"model": model})
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log.debug("context window lookup (POST /api/show) failed: %s", e)
            return
        info = data.get("model_info") if isinstance(data, dict) else None
        info = info if isinstance(info, dict) else {}
        arch = info.get("general.architecture")
        length = info.get(f"{arch}.context_length") if isinstance(arch, str) else None
        if not (type(length) is int and length > 0):
            length = next((v for k, v in sorted(info.items()) if isinstance(k, str)
                           and k.endswith(".context_length") and type(v) is int and v > 0), 0)
        self._show_windows[_model_key(model)] = length

    async def _cached_lookup(self, key: str, cache: dict, probe, probe_key: str | None = None
                             ) -> int | None:
        """cache[key], looked up when absent at most once per
        _CONTEXT_PROBE_RETRY_SECONDS (0 cached = the server reports none)."""
        if key not in cache:
            probe_key = probe_key or key
            probed_at = self._context_probed_at.get(probe_key)
            if probed_at is None or time.monotonic() - probed_at >= _CONTEXT_PROBE_RETRY_SECONDS:
                self._context_probed_at[probe_key] = time.monotonic()
                await probe()
        return cache.get(key) or None

    async def discovered_context_window(self, model: str) -> dict:
        """TOK-4: the context window a prompt for `model` is budgeted against.

        {"window", "source", "model_max"}:
        - api "openai": llama-server's GET /props n_ctx, the per-slot window
          ("props"); with ollama.num_ctx also set, the smaller of the two;
        - else ollama.num_ctx when set ("num_ctx");
        - a local Ollama model: the window GET /api/ps reports it loaded with
          ("api_ps"). Not loaded, window is None: it loads at the server's
          default context, which no endpoint reports. model_max is then its
          trained maximum from POST /api/show, an upper bound;
        - a cloud model: POST /api/show's context_length ("api_show").

        Each lookup is cached per model on this client (one client, one
        endpoint); a failed one is retried at most once per
        _CONTEXT_PROBE_RETRY_SECONDS. Never raises."""
        try:
            if self.api == API_OPENAI:
                props = await self._cached_lookup(_OPENAI_SERVER_KEY, self._context_windows,
                                                  self._probe_openai_window)
                if self.num_ctx and (not props or self.num_ctx <= props):
                    return {"window": self.num_ctx, "source": "num_ctx", "model_max": None}
                return {"window": props, "source": "props" if props else None, "model_max": None}
            if self.num_ctx:
                return {"window": self.num_ctx, "source": "num_ctx", "model_max": None}
            key = _model_key(model)

            async def show():
                return await self._cached_lookup(key, self._show_windows,
                                                 lambda: self._probe_show_window(model),
                                                 probe_key=f"show:{key}")
            if is_cloud_model(model):
                length = await show()
                return {"window": length, "source": "api_show" if length else None,
                        "model_max": length}
            window = await self._cached_lookup(key, self._context_windows,
                                               self._probe_context_windows)
            if window:
                return {"window": window, "source": "api_ps", "model_max": None}
            return {"window": None, "source": None, "model_max": await show()}
        except Exception as e:  # discovery is advisory: the budget falls back
            log.debug("context window discovery failed: %s", type(e).__name__)
            return {"window": None, "source": None, "model_max": None}

    def _window_key(self, model: str) -> str:
        return _OPENAI_SERVER_KEY if self.api == API_OPENAI else _model_key(model)

    def _window_source(self) -> str:
        return "props" if self.api == API_OPENAI else "api_ps"

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
        key = self._window_key(model)
        source = self._window_source()
        cached = self._context_windows.get(key)
        if cached == 0:
            return None, None
        if cached and not (isinstance(prompt_tokens, int) and prompt_tokens > cached):
            return cached, source
        probed_at = self._context_probed_at.get(key)
        if probed_at is None or time.monotonic() - probed_at >= _CONTEXT_PROBE_RETRY_SECONDS:
            self._context_probed_at[key] = time.monotonic()
            await self._probe_context_windows()
            cached = self._context_windows.get(key)
        return (cached, source) if cached else (None, None)

    async def _check_context(self, model, payload, prompt_tokens, completion_tokens,
                             done_reason, measurement) -> None:
        """Raise OllamaContextTruncatedError when this call did not fit the model's
        context window (see context_overflow), or a local model's reply stopped
        for length while under ollama.max_output_tokens (so only the window can
        have stopped it); count and report it first. A reply that reached the
        configured output cap raises OllamaOutputCappedError instead. A call too small to fill any
        plausible window, and any cloud-model call, costs no lookup."""
        if is_cloud_model(model):
            return
        # The call's own cap: a capped reply's retry asks for more than the setting.
        cap = _payload_cap(payload) or self.max_output_tokens
        if (done_reason == "length" and cap
                and isinstance(completion_tokens, int)
                and completion_tokens >= cap):
            self.model_output_capped_count += 1
            measurement["outcome"] = "output_capped"
            err = OllamaOutputCappedError(
                f"Model '{model}': the reply reached its output cap "
                f"({cap} tokens) before it finished; reply discarded")
            self.audit_logger.log_llm_error(model=model, error=err)
            log.warning("%s", err)
            raise err
        window = source = kind = None
        prompt_chars = sum(len(m.get("content") or "") for m in payload.get("messages") or []
                           if isinstance(m, dict))
        if isinstance(prompt_tokens, int) and (
                self.num_ctx or prompt_tokens + (completion_tokens or 0)
                >= _MIN_PLAUSIBLE_WINDOW // 2 - _WINDOW_SLACK_TOKENS):
            window, source = await self._context_window(model, prompt_tokens)
            # An OpenAI-compatible server refuses an oversized prompt (HTTP 400,
            # see _send_once) instead of cutting it, so the characters-per-token
            # test for a silent cut does not apply: 0 characters disables it.
            kind = context_overflow(prompt_tokens, completion_tokens,
                                    0 if self.api == API_OPENAI else prompt_chars, window)
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
        larger = recommended_num_ctx(max(window or 0, ESTIMATED_LARGEST_PROMPT_TOKENS))
        advice = (f"start the server with -c {larger} (per slot) and set ollama.num_ctx: {larger}"
                  if self.api == API_OPENAI else
                  f"set ollama.num_ctx: {larger} in harness/config.local.yaml or use a cloud model")
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
                window = self._context_windows.get(self._window_key(name)) or None
                source = self._window_source() if window else None
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

    def _refuse_cloud_model(self, model) -> None:
        """SEC-1: raise OllamaCloudModelRefusedError, before anything is sent or
        counted as an attempt, for a cloud model this client may not use. The
        receipt marks the call as not attempted, so no tokens are settled."""
        if self.allow_cloud_models or not is_cloud_model(model):
            return
        self.model_cloud_refused_count += 1
        err = OllamaCloudModelRefusedError(cloud_refusal_reason([model]))
        err.inference_usage = {"prompt_tokens": None, "completion_tokens": None,
                               "attempted": False, "completed": False, "usable": False,
                               "outcome": "error", "refused": "cloud_model"}
        first = model not in self._cloud_refusal_warned
        self._cloud_refusal_warned.add(model)
        log.log(logging.WARNING if first else logging.DEBUG, "%s", err)
        if first:
            self.audit_logger.log_security_event(
                event_type="cloud_model_refused", message=str(err), severity="warning")
        raise err

    async def _chat(self, model, system_prompt, user_prompt, temperature=0.1, seed=None):
        """Keep consumption independent of successful JSON parsing."""
        self._refuse_cloud_model(model)
        started = time.monotonic()
        self.model_attempted_count += 1
        stage = self._stage_row()
        stage["calls"] += 1
        measurement = {"prompt_tokens": None, "completion_tokens": None,
                       "attempted": True, "completed": False, "usable": False,
                       "queue_ms": None, "connection_ms": None,
                       "generation_ms": None, "wall_ms": None, "outcome": "error"}
        # Who is using the model, and when it last worked (harness/model_activity.py):
        # a call waiting for the one local slot counts as in flight.
        activity_owner = model_activity.ACTIVITY.begin()
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
            model_activity.ACTIVITY.end(activity_owner)
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
        
        if self.api == API_OPENAI:
            payload = self._openai_payload(model, validated_system, validated_user, temperature,
                                           seed if seed is not None else self.seed)
            return await self._send_with_retries(f"{self.base_url}/v1/chat/completions", payload,
                                                 model, measurement, validated_system, validated_user)
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
                seed if seed is not None else self.seed,
                # ollama.max_output_tokens, opt-in like num_ctx: omitted unless set.
                self.max_output_tokens),
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
        return await self._send_with_retries(url, payload, model, measurement,
                                             validated_system, validated_user)

    def _openai_payload(self, model, system_prompt, user_prompt, temperature, seed) -> dict:
        """The /v1/chat/completions body. num_ctx is never sent (an OpenAI-compatible
        server's window is fixed when it starts, llama-server -c); the client still
        uses it as the window for the context guard and the prompt budget."""
        payload = {
            "model": model,
            "messages": [{"role": "system", "content": system_prompt},
                         {"role": "user", "content": user_prompt}],
            "stream": False,
            "temperature": temperature,
            # Constrains the final answer to one JSON object, as Ollama's
            # format: json does. Measured on gpt-oss-20b (llama.cpp b12084): 24/24
            # valid agent actions with it, 21/24 without (a stray closing brace).
            "response_format": {"type": "json_object"},
        }
        if seed is not None:
            payload["seed"] = seed
        if self.max_output_tokens:
            payload["max_tokens"] = self.max_output_tokens
        if self.reasoning_effort:
            payload["chat_template_kwargs"] = {"reasoning_effort": self.reasoning_effort}
        return payload

    async def _send_with_retries(self, url, payload, model, measurement,
                                 validated_system, validated_user) -> tuple[dict, dict]:
        """One logical call: breaker, rate limiter and bounded transient retry
        around _send_once, shared by both wire protocols."""
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
        capped_retried = False
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
                except rate_limiter.RateLimitWaitExceeded as exc:
                    # The pacer's bound (ollama.rate_limit.max_wait_seconds): the
                    # wait still counts as queue time; nothing was sent.
                    waited_ms = (time.monotonic() - attempt_queue_started) * 1000.0
                    measurement["queue_ms"] = (
                        waited_ms if measurement["queue_ms"] is None
                        else measurement["queue_ms"] + waited_ms)
                    log.warning("Model %s: call not admitted by the model-call pacer within "
                                "%gs (ollama.rate_limit); not sent", model, exc.max_wait_seconds)
                    raise OllamaPacerTimeoutError(
                        f"model call for {model} not admitted by the model-call pacer "
                        f"(ollama.rate_limit) within {exc.max_wait_seconds:g}s; nothing was sent",
                        max_wait_seconds=exc.max_wait_seconds) from exc
                except OllamaOutputCappedError:
                    larger = (None if capped_retried or _cancellation_requested()
                              else self._capped_retry_cap(model, payload, measurement))
                    if larger is None:
                        raise
                    capped_retried = True
                    log.warning("Model %s: reply reached its %d-token cap unfinished; asking once "
                                "more with %d", model, _payload_cap(payload), larger)
                    payload = _with_cap(payload, larger)
                    self.model_output_capped_retry_count += 1
                    self.audit_logger.log_llm_prompt(
                        model=model,
                        system_prompt=validated_system,
                        user_prompt=validated_user,
                    )
                    continue
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
                if capped_retried:
                    self.model_output_capped_recovered_count += 1
                return parsed, data

    def _capped_retry_cap(self, model: str, payload: dict, measurement: dict) -> int | None:
        """The cap a capped reply is asked again with: _CAPPED_RETRY_FACTOR times the
        call's cap, within what the context window leaves after the prompt. None when
        the cap cannot grow (no cap, or the window is already full)."""
        cap = _payload_cap(payload)
        if not cap:
            return None
        larger = min(cap * _CAPPED_RETRY_FACTOR, _MAX_OUTPUT_TOKENS_CEILING)
        window = self.num_ctx or self._context_windows.get(self._window_key(model)) or None
        prompt_tokens = measurement.get("prompt_tokens")
        if window and isinstance(prompt_tokens, int):
            larger = min(larger, window - prompt_tokens - _WINDOW_SLACK_TOKENS)
        return larger if larger > cap else None

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
        except _DROPPED_CONNECTION_ERRORS as e:
            self.audit_logger.log_llm_error(
                model=model,
                error=OllamaError(safe_error_summary(e)),
            )
            raise OllamaTransientError("Ollama connection dropped mid-request") from e

        if resp.status_code != 200:
            if self.api == API_OPENAI and resp.status_code == 400 and _openai_context_error(resp):
                self._raise_openai_prompt_too_large(model, measurement)
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
        if self.api == API_OPENAI:
            data = _openai_envelope(data)
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

    def _raise_openai_prompt_too_large(self, model, measurement):
        """llama-server refused the prompt as larger than its window: a context
        fault (counted and raised as one, kept out of the breaker), not an outage."""
        self.model_context_truncated_count += 1
        self.model_context_truncated_by_kind["prompt"] += 1
        self._stage_row()["context_truncated"] += 1
        measurement["outcome"] = "context_truncated"
        measurement["context_truncated"] = "prompt"
        window = self.num_ctx or self._context_windows.get(_OPENAI_SERVER_KEY) or None
        err = OllamaContextTruncatedError(
            f"Model '{model}': the prompt exceeds the server's context window; nothing was "
            "generated. Start llama-server with a larger -c (per slot) and set "
            "ollama.num_ctx to match",
            kind="prompt", window=window,
            window_source="num_ctx" if self.num_ctx else ("props" if window else None))
        self.audit_logger.log_llm_error(model=model, error=err)
        log.warning("%s", err)
        raise err

    async def list_models(self) -> list[str]:
        """Model tags Ollama reports via GET /api/tags. Best-effort: returns []
        on any failure (unreachable, bad response) rather than raising -- this
        feeds a UI model picker, where "couldn't list" degrades to an empty
        local list, never a crash. NOTE cloud model tags (e.g. *-cloud) are
        reachable via /api/chat but do NOT appear here -- the server merges
        those in from config (models.cloud); see server.py /models."""
        url = self._models_url()
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout_seconds, 15.0)) as client:
                resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as e:
            log.warning("list_models: could not list Ollama models: %s", e)
            return []
        return self._model_names(data)

    def _models_url(self) -> str:
        """GET /api/tags (Ollama) or GET /v1/models (OpenAI-compatible)."""
        return f"{self.base_url}/v1/models" if self.api == API_OPENAI else f"{self.base_url}/api/tags"

    def _model_names(self, data) -> list[str]:
        if self.api == API_OPENAI:
            rows, field = (data.get("data", []) if isinstance(data, dict) else []), "id"
        else:
            rows, field = (data.get("models", []) if isinstance(data, dict) else []), "name"
        return sorted({m.get(field) for m in rows if isinstance(m, dict) and m.get(field)})

    async def health_check(self, timeout: float = 3.0) -> dict:
        """Fast liveness probe for GET /health: is the Ollama backend reachable,
        and which model tags does it report? Best-effort and short-timeout (never
        the full inference timeout) so the health endpoint answers quickly even
        when Ollama is down. Returns {"reachable": bool, "models": [..],
        "error": str|None}. A refused connection (the common 'ollama not running'
        case) resolves near-instantly; `error` carries a short reason otherwise."""
        url = self._models_url()
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as e:
            return {"reachable": False, "models": [], "error": f"{type(e).__name__}: {e}"}
        return {"reachable": True, "models": self._model_names(data), "error": None}

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

