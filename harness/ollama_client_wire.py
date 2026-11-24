"""Wire-format helpers: the parsed result, lenient JSON, inline-thinking
strip, backend/think/rate-limit settings and the OpenAI-compatible
envelope, split from ollama_client.py (ARC-9). Import these names from
harness.ollama_client.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass

from harness import rate_limiter


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


# Wire protocol of the model server (`ollama.api`). "ollama", the default, speaks
# Ollama's /api/chat, /api/tags and /api/ps exactly as before this key existed.
# "openai" speaks the OpenAI-compatible API that llama.cpp's llama-server (and
# vLLM, LM Studio, ...) serve: POST /v1/chat/completions with response_format
# json_object, GET /v1/models, and llama-server's GET /props for the context
# window. Everything else -- prompt validation, sanitising, retries, the circuit
# breaker, rate limit, audit log, context guard, metrics -- is the same code for
# both, so callers get the same results and the same error types.
API_OLLAMA = "ollama"
API_OPENAI = "openai"
REASONING_EFFORTS = ("low", "medium", "high")
_MAX_OUTPUT_TOKENS_CEILING = 131072
# r9 (gpt-oss-20b, reasoning_effort low, cap 2048): 40 replies reached the cap and
# were discarded, most of them the injection agent's. A capped reply is asked once
# more with this many times the cap, within the context window.
_CAPPED_RETRY_FACTOR = 2


def _payload_cap(payload: dict) -> int | None:
    """The output cap a chat payload carries (max_tokens, or Ollama's num_predict)."""
    cap = payload.get("max_tokens") or (payload.get("options") or {}).get("num_predict")
    return cap if isinstance(cap, int) and cap > 0 else None


def _with_cap(payload: dict, cap: int) -> dict:
    """A copy of `payload` asking for at most `cap` output tokens."""
    if "max_tokens" in payload:
        return {**payload, "max_tokens": cap}
    return {**payload, "options": {**(payload.get("options") or {}), "num_predict": cap}}


def parse_backend_settings(api=None, max_output_tokens=None, reasoning_effort=None,
                           think=None) -> tuple[str, int | None, str | None]:
    """(`ollama.api`, `ollama.max_output_tokens`, `ollama.reasoning_effort`),
    validated. Strict like `ollama.think`: a wrong type, or a key that does not
    apply to the chosen api, raises at startup instead of being ignored.

    - api: unset/"ollama" or "openai".
    - max_output_tokens: unset (no cap, as before) or an int in 1..131072. Sent as
      options.num_predict (ollama) or max_tokens (openai). On a reasoning model
      the trace counts against it.
    - reasoning_effort: "low" | "medium" | "high", api "openai" only. Sent as
      chat_template_kwargs.reasoning_effort, which llama-server passes to the
      model's chat template (gpt-oss reads it).
    - think: must stay unset with api "openai"; such a server's model reasons per
      its template, steered by reasoning_effort."""
    api_value = API_OLLAMA if api is None else api
    if api_value not in (API_OLLAMA, API_OPENAI):
        raise ValueError('invalid ollama config: ollama.api must be "ollama" or "openai", '
                         f"got {api!r}")
    cap = max_output_tokens
    if cap is not None and (type(cap) is not int or not 1 <= cap <= _MAX_OUTPUT_TOKENS_CEILING):
        raise ValueError("invalid ollama config: ollama.max_output_tokens must be an unquoted "
                         f"integer from 1 to {_MAX_OUTPUT_TOKENS_CEILING}, got {cap!r}")
    if reasoning_effort is not None:
        if reasoning_effort not in REASONING_EFFORTS:
            raise ValueError("invalid ollama config: ollama.reasoning_effort must be one of "
                             f"{', '.join(REASONING_EFFORTS)}, got {reasoning_effort!r}")
        if api_value != API_OPENAI:
            raise ValueError('invalid ollama config: ollama.reasoning_effort applies only to '
                             'ollama.api: "openai"')
    if api_value == API_OPENAI and parse_think_setting(
            think if not isinstance(think, frozenset) else sorted(think)):
        raise ValueError('invalid ollama config: ollama.think applies only to ollama.api: '
                         '"ollama"; set ollama.reasoning_effort for an OpenAI-compatible server')
    return api_value, cap, reasoning_effort


def backend_options(ollama_config: dict | None) -> dict:
    """The backend keyword arguments for OllamaClient(...) from a config's `ollama`
    block, so every construction site passes the same keys (SEC-1 added
    allow_cloud_models: every client refuses cloud models unless it is true)."""
    cfg = ollama_config or {}
    return {"api": cfg.get("api"), "max_output_tokens": cfg.get("max_output_tokens"),
            "reasoning_effort": cfg.get("reasoning_effort"),
            "allow_cloud_models": cfg.get("allow_cloud_models"),
            "rate_limit": cfg.get("rate_limit")}


def backend_setting(ollama_config: dict | None) -> dict:
    """Plain-data description of the backend settings for run provenance:
    {"api", "max_output_tokens", "reasoning_effort"}, validated."""
    options = backend_options(ollama_config)
    api, cap, effort = parse_backend_settings(
        options["api"], options["max_output_tokens"], options["reasoning_effort"])
    return {"api": api, "max_output_tokens": cap, "reasoning_effort": effort}


def _number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def parse_rate_limit(section) -> rate_limiter.RateLimitConfig | None:
    """`ollama.rate_limit`, the model-call pacer every OllamaClient in the process
    shares, as its token-bucket config; None when the block is absent (the pacer
    keeps the values it has). Keys, each optional, defaulting to the pacer's
    shipped values (rate_limiter.PACER_DEFAULTS):
    - enabled: true | false (unquoted). false admits every call at once.
    - burst_calls: an integer from 1: calls that may start back to back.
    - calls_per_minute: a number above 0: the refill once the burst is spent.
    - max_wait_seconds: a number above 0: a call not admitted by then fails
      with OllamaPacerTimeoutError, unsent. It has no unbounded setting.
    Strict like the other ollama keys: an unknown key or a wrong type raises at
    startup instead of being ignored."""
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ValueError("invalid ollama config: ollama.rate_limit must be a mapping, "
                         f"got {type(section).__name__}")
    unknown = sorted(set(section) - set(rate_limiter.PACER_DEFAULTS))
    if unknown:
        raise ValueError(f"invalid ollama config: ollama.rate_limit has unknown key(s) {unknown}; "
                         f"allowed: {', '.join(rate_limiter.PACER_DEFAULTS)}")
    values = {**rate_limiter.PACER_DEFAULTS, **section}
    if type(values["enabled"]) is not bool:
        raise ValueError("invalid ollama config: ollama.rate_limit.enabled must be true or "
                         f"false (unquoted), got {values['enabled']!r}")
    if type(values["burst_calls"]) is not int or values["burst_calls"] < 1:
        raise ValueError("invalid ollama config: ollama.rate_limit.burst_calls must be an "
                         f"unquoted integer of at least 1, got {values['burst_calls']!r}")
    for key in ("calls_per_minute", "max_wait_seconds"):
        if not _number(values[key]) or values[key] <= 0:
            raise ValueError(f"invalid ollama config: ollama.rate_limit.{key} must be an "
                             f"unquoted finite number above 0, got {values[key]!r}")
    return rate_limiter.pacer_config(**values)


def _openai_envelope(data: dict) -> dict:
    """An OpenAI-compatible chat completion, rewritten as the Ollama /api/chat
    envelope the rest of this client reads: message.content, message.thinking
    (llama-server's reasoning_content; dropped later, only its length kept),
    prompt_eval_count / eval_count from usage, eval_duration / prompt_eval_duration
    from llama-server's timings, done_reason "length" when finish_reason is."""
    choices = data.get("choices")
    choice = choices[0] if isinstance(choices, list) and choices else None
    if not isinstance(choice, dict):
        raise _oc.OllamaInvalidJSONError("OpenAI-compatible server returned no choices")
    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
    content = message.get("content")
    out_message = {"role": "assistant", "content": content if isinstance(content, str) else ""}
    reasoning = message.get("reasoning_content")
    if isinstance(reasoning, str) and reasoning:
        out_message["thinking"] = reasoning
    envelope = {"model": data.get("model"), "message": out_message, "done": True,
                "done_reason": "length" if choice.get("finish_reason") == "length" else "stop"}
    usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
    for src, dst in (("prompt_tokens", "prompt_eval_count"), ("completion_tokens", "eval_count")):
        if type(usage.get(src)) is int and usage[src] >= 0:
            envelope[dst] = usage[src]
    timings = data.get("timings") if isinstance(data.get("timings"), dict) else {}
    for src, dst in (("prompt_ms", "prompt_eval_duration"), ("predicted_ms", "eval_duration")):
        value = timings.get(src)
        if type(value) in (int, float) and value >= 0:
            envelope[dst] = int(value * 1_000_000)
    return envelope


def _openai_context_error(resp) -> bool:
    """True for llama-server's HTTP 400 "the request exceeds the available context
    size" (error.type exceed_context_size_error): a prompt too large for the
    server's window, which llama-server refuses instead of cutting silently."""
    try:
        err = resp.json().get("error") or {}
    except Exception:
        return False
    return isinstance(err, dict) and (
        err.get("type") == "exceed_context_size_error"
        or "context size" in str(err.get("message") or "").lower())


def _chat_options(temperature, num_ctx, seed, num_predict=None) -> dict:
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
    if num_predict:
        options["num_predict"] = num_predict
    return options


# Bound last (ollama_client imports this module): read only at call time.
from harness import ollama_client as _oc  # noqa: E402
