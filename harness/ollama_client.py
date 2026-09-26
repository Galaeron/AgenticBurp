from __future__ import annotations
import json
import logging
import re
import httpx
from dataclasses import dataclass

from harness import prompt_validator
from harness import circuit_breaker
from harness import rate_limiter
from harness import audit_logger

log = logging.getLogger("harness.ollama_client")

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


@dataclass
class OllamaResult:
    """Parsed response body plus real token usage from the same call --
    verified against Ollama's actual /api/chat response shape (top-level
    prompt_eval_count / eval_count fields alongside "message" and "done"),
    not assumed. See effort.EffortLedger, which is what these numbers are
    for."""
    data: dict
    prompt_tokens: int
    completion_tokens: int


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


class OllamaClient:
    """
    Minimal wrapper around Ollama's /api/chat endpoint.
    Docs: https://github.com/ollama/ollama/blob/main/docs/api.md
    """

    def __init__(self, base_url: str, timeout_seconds: float = 120.0,
                 num_ctx: int | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        # Optional per-request Ollama context window (options.num_ctx). Default
        # None => the key is NOT sent, so Ollama keeps its own server/model
        # default and every existing call site is byte-for-byte unchanged. A
        # caller (e.g. a local/eval overlay via config.local.yaml's
        # `ollama.num_ctx`) can pin a smaller window when the harness's prompts
        # are far below the model's default context: on a VRAM-limited box, a
        # model loaded at a huge default context (e.g. qwen3:8b at 32768 = 10GB)
        # spills onto CPU and each call runs several times slower, whereas the
        # same model pinned to a context that actually covers the prompt
        # (measured p99 < 4k tokens here) stays fully GPU-resident. Never sent
        # unless set, so this cannot change behavior for a caller that leaves it
        # unset.
        self.num_ctx = int(num_ctx) if num_ctx else None

        # Pure instrumentation (added for the P2-2 ablation cost axis): count
        # model calls and accumulate the real prompt/completion token usage this
        # client already reads off each response for logging. Every model call in
        # the harness (agents, coordinator, critique) goes through one
        # OllamaClient, so these totals capture a whole run's model cost without
        # depending on the effort budget (whose agent-token wiring is currently
        # inert -- AgentManager._effort_budget is never set). Read-only counters;
        # they change no control flow, no gating, and no request payload.
        self.model_call_count = 0
        self.model_prompt_tokens = 0
        self.model_completion_tokens = 0

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
            # OllamaModelNotFoundError, see its own docstring for why.
            circuit_breaker.CircuitBreakerConfig(
                failure_threshold=3,
                success_threshold=2,
                timeout_seconds=60.0,
                half_open_max_requests=1,
                excluded_exceptions=(OllamaModelNotFoundError, OllamaInvalidJSONError),
                enabled=True,
            ),
        )
        
        # Initialize rate limiter
        self.rate_limiter = rate_limiter.get_token_limiter("ollama")
        
        # Initialize prompt validator
        self.prompt_validator = prompt_validator.PromptValidator()
        
        # Initialize audit logger
        self.audit_logger = audit_logger.get_audit_logger()

    async def _chat(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> tuple[dict, dict]:
        """Shared implementation. Returns (parsed_json_body, raw_response_dict)
        so callers needing usage fields don't have to make a second call.
        
        This method integrates:
        - Prompt validation (prevents injection attacks)
        - Circuit breaker (prevents cascading failures)
        - Rate limiting (prevents overloading)
        - Audit logging (tracks all LLM interactions)
        """
        # Validate prompts
        try:
            validated_system = self.prompt_validator.validate_system_prompt(system_prompt)
            validated_user = self.prompt_validator.validate_user_prompt(user_prompt)
        except prompt_validator.ValidationError as e:
            self.audit_logger.log_security_event(
                event_type="prompt_validation_failed",
                message=f"Prompt validation failed: {e}",
                severity="error",
            )
            raise OllamaError(f"Prompt validation failed: {e}") from e
        
        # Log the prompt
        self.audit_logger.log_llm_prompt(
            model=model,
            system_prompt=validated_system,
            user_prompt=validated_user,
        )
        
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
            # the payload is unchanged for every caller that never sets it.
            "options": (
                {"temperature": temperature, "num_ctx": self.num_ctx}
                if self.num_ctx else {"temperature": temperature}
            ),
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
            "think": False,
        }
        url = f"{self.base_url}/api/chat"
        
        # Use circuit breaker and rate limiter. Resolved AT CALL TIME (not
        # self.circuit_breaker, cached at __init__) via current_ollama_breaker
        # (AR-2, LOOP half): when a RunContext has pushed a per-run breaker,
        # this call is governed by THAT run's isolated breaker; otherwise it
        # falls back to self.circuit_breaker -- the same process-wide shared
        # singleton this always used, unchanged for every no-run caller.
        breaker = circuit_breaker.current_ollama_breaker("ollama")
        async with breaker:
            async with self.rate_limiter:
                try:
                    async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                        resp = await client.post(url, json=payload)
                except httpx.ConnectError as e:
                    self.audit_logger.log_llm_error(
                        model=model,
                        error=e,
                    )
                    raise OllamaError(
                        f"Could not reach Ollama at {self.base_url}. "
                        f"Is `ollama serve` running? ({e})"
                    ) from e
                except httpx.TimeoutException as e:
                    self.audit_logger.log_llm_error(
                        model=model,
                        error=e,
                    )
                    raise OllamaError(f"Ollama request timed out after {self.timeout_seconds}s") from e

                if resp.status_code == 404:
                    # Verified directly against a live Ollama instance: this
                    # is specifically "model tag doesn't exist" -- see
                    # OllamaModelNotFoundError's own docstring for why this
                    # must not count as a circuit-breaker failure.
                    err = OllamaModelNotFoundError(
                        f"Model '{model}' not found on this Ollama instance: {resp.text[:500]}"
                    )
                    self.audit_logger.log_llm_error(model=model, error=err)
                    raise err

                if resp.status_code != 200:
                    self.audit_logger.log_llm_error(
                        model=model,
                        error=OllamaError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:500]}"),
                    )
                    raise OllamaError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:500]}")

                data = resp.json()
                content = data.get("message", {}).get("content", "")
                if not content:
                    self.audit_logger.log_llm_error(
                        model=model,
                        error=OllamaError(f"Ollama returned an empty message body: {data}"),
                    )
                    raise OllamaError(f"Ollama returned an empty message body: {data}")

                try:
                    parsed = _loads_lenient(_strip_json_fence(content))

                    # Log the response
                    prompt_tokens = data.get("prompt_eval_count", 0) or 0
                    completion_tokens = data.get("eval_count", 0) or 0
                    self.audit_logger.log_llm_response(
                        model=model,
                        response=content,
                        prompt_tokens=prompt_tokens,
                        completion_tokens=completion_tokens,
                    )
                    
                    # Record token usage
                    self.rate_limiter.record_usage(prompt_tokens, completion_tokens)

                    # Instrumentation only (see __init__): a successful model
                    # call plus its real token usage. Counted here, after a
                    # parse, so it reflects calls that actually returned usable
                    # output; failures raise above and are not counted.
                    self.model_call_count += 1
                    self.model_prompt_tokens += prompt_tokens
                    self.model_completion_tokens += completion_tokens

                    return parsed, data
                except json.JSONDecodeError as e:
                    self.audit_logger.log_llm_error(
                        model=model,
                        error=e,
                    )
                    raise OllamaInvalidJSONError(
                        f"Model '{model}' did not return valid JSON. "
                        f"Raw content (truncated): {content[:500]}"
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

    async def chat_json(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> dict:
        """
        Calls the model and requires a JSON object back (Ollama's `format: json`
        mode). Returns the parsed dict. Raises OllamaError on failure --
        callers are responsible for turning that into a labeled, degraded
        result rather than pretending the call succeeded.
        """
        parsed, _raw = await self._chat(model, system_prompt, user_prompt, temperature)
        return parsed

    async def chat_json_metered(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> OllamaResult:
        """
        Same as chat_json, but also returns real token usage
        (prompt_eval_count / eval_count from Ollama's own response) so the
        caller can feed effort.EffortLedger with actual numbers instead of
        the unmeasured priors in effort._DEFAULT_TOKEN_ESTIMATE. Falls back
        to 0/0 if Ollama's response is missing these fields (older server
        versions, or a proxy that strips them) rather than raising --
        losing calibration data isn't worth failing an otherwise-successful
        call over.
        """
        parsed, raw = await self._chat(model, system_prompt, user_prompt, temperature)
        prompt_tokens = raw.get("prompt_eval_count", 0) or 0
        completion_tokens = raw.get("eval_count", 0) or 0
        return OllamaResult(data=parsed, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens)

