"""
Iterative (active) agent: bounded send -> observe -> adapt loop.

The specialist agents elsewhere in this harness are single-shot: one LLM call
over one captured exchange. This is the other mode -- an agent that actually
drives the target, adapting its payload to what it sees, the way a human tester
iterates. One "step" is a full send-a-request / read-the-response / decide
cycle. When it runs out of steps (or budget, or ideas) it HANDS BACK to the
orchestrator a structured result -- findings plus a handoff note of what it
tried and what still looks promising -- so another agent can pick up the thread
(the input the pivot/remember layer consumes).

Safety is the whole design, because an LLM in a loop against a live target is
exactly where blast radius gets away from you:

  - The model NEVER controls a raw URL or command. It emits a constrained
    action (mutate this param / set this header / stop) which the harness
    translates into a request DERIVED FROM THE CAPTURED EXCHANGE -- the same
    endpoint the tester already authorized analyzing. The model chooses payload
    *values* and *which bounded knob* to turn, not arbitrary destinations.
  - Every request is scope-checked against allowed_hosts, gated by safety_gate
    for mutating methods (inheriting the allow_mutating_replay opt-in), and
    paced by the global request throttle -- identical to the validator path.
  - Bounded three independent ways: step_budget (~250 cycles), the token
    effort_budget, and the global rate throttle.

Off by default; this is a fundamentally more active mode than the passive
pipeline and is opt-in per run.
"""
from __future__ import annotations
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

import httpx  # noqa: F401 -- HTTP transport site; sends now go via run_context.TargetTransport

from harness import global_throttle
from harness.models import Finding, HttpExchange, sanitize_agent_finding
from harness.safety_gate import get_default_gate
from harness.run_context import transport_for  # W-16: the single TargetTransport
# Reuse the exact, tested mutation helpers the sqlmap validator already uses --
# same bounded "change one param value on the captured request" envelope.
from harness.validators.sqlmap import (
    _mutate_query_param, _mutate_json_param, _mutate_form_param,
    _query_top_level_params, _json_top_level_params, _form_top_level_params,
    _looks_like_json, _content_type_of,
)

if TYPE_CHECKING:
    from harness.effort import EffortBudget

log = logging.getLogger("harness.iterative_agent")

_MAX_RESP_CHARS = 1200  # response summary fed back to the model, per step


def _request_signature(method: str, url: str, headers: dict | None, body: str | None) -> str:
    """P2.6: a stable fingerprint over (method, URL, sha256(body), relevant
    headers) -- relevant headers being every header this agent itself set
    (the whole dict; nothing here is agent-opaque boilerplate the way e.g.
    a browser's User-Agent would be), canonicalized so key order/case never
    changes the signature. Two calls that would send byte-identical requests
    produce the same signature; a different body, URL, method, or header
    value produces a different one."""
    body_hash = hashlib.sha256((body or "").encode("utf-8", "replace")).hexdigest()
    header_items = tuple(sorted((str(k).lower(), str(v)) for k, v in (headers or {}).items()))
    return hashlib.sha256(
        "\x1f".join([method.upper(), url, body_hash, repr(header_items)]).encode("utf-8")
    ).hexdigest()

# A path segment that is an OBJECT IDENTIFIER an IDOR swaps: all-digits
# (/tickets/1) or a long hex/uuid (/tickets/a1b2c3d4-...). Mirrors the
# cross-identity gate's notion of an object id, so the agent can ENUMERATE a
# path id (the case a query/body mutation can never reach) -- the gap that made
# every path-based IDOR probe return "no mutable parameters".
_PATH_ID_SEG = re.compile(r'^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{4,})$')


def _path_id_values(url: str) -> list[str]:
    """The id-like path segments of `url`, in order -- what the agent may swap."""
    segs = [s for s in urlsplit(url).path.split("/") if s]
    return [s for s in segs if _PATH_ID_SEG.match(s)]


def _mutate_path_segment(url: str, old_value: str, new_value: str) -> str | None:
    """Replace the first path segment equal to `old_value` with `new_value`.
    Returns the new URL, or None if no such segment (so the caller can tell the
    model its target id wasn't on the path)."""
    parts = urlsplit(url)
    segs = parts.path.split("/")
    for i, s in enumerate(segs):
        if s == old_value:
            segs[i] = new_value
            return urlunsplit((parts.scheme, parts.netloc, "/".join(segs), parts.query, parts.fragment))
    return None

# Target-distress signals: statuses that mean the service is struggling or
# actively shedding load. An iterative agent that keeps hammering a target
# returning these is both rude and useless -- it stops instead of piling on.
_DISTRESS_STATUSES = frozenset({429, 502, 503, 504})
# Consecutive distress responses / transport failures tolerated before aborting.
_MAX_CONSECUTIVE_TROUBLE = 3


@dataclass
class IterativeStep:
    n: int
    action: dict
    request_summary: str
    response_status: int | None
    response_summary: str
    blocked: str | None = None


@dataclass
class IterativeResult:
    agent: str
    findings: list[Finding] = field(default_factory=list)
    handoff_note: str = ""
    steps_used: int = 0
    stop_reason: str = ""            # found|exhausted_steps|gave_up|budget|error|target_distress
    transcript: list[IterativeStep] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "findings": [f.model_dump() for f in self.findings],
            "handoff_note": self.handoff_note,
            "steps_used": self.steps_used,
            "stop_reason": self.stop_reason,
            "transcript": [
                {"n": s.n, "action": s.action, "request": s.request_summary,
                 "status": s.response_status, "response": s.response_summary, "blocked": s.blocked}
                for s in self.transcript
            ],
        }


_SYSTEM_PROMPT = """You are an iterative security-testing agent specializing in {specialty}.
You probe ONE captured HTTP endpoint by adapting your payload to each response.

Each turn, respond with ONLY a JSON object choosing exactly one action:

  {{"action":"mutate","location":"query|body|path","param":"<name>","value":"<payload>","thought":"<one line>"}}
     -- resend the captured request with one value replaced by your payload. For location "path",
        `param` is the current id segment to swap (e.g. "1") and `value` the id to try (e.g. "2") --
        this is how you ENUMERATE an object id to test IDOR/BOLA on a path like /tickets/1.
  {{"action":"set_header","name":"<header>","value":"<value>","thought":"<one line>"}}
     -- resend with a request header set/overridden (persists for later steps).
  {{"action":"stop","verdict":"found|not_found","thought":"<one line>",
    "finding":{{"vulnerability_class":"...","confidence":0.0-1.0,"severity":"info|low|medium|high|critical",
               "summary":"...","evidence":"...","suggested_test":"...","basis":"derived"}}}}
     -- stop. Include "finding" ONLY when verdict is "found".

Rules:
- You cannot choose the URL, host, or method -- only payload values and which bounded knob to turn.
- Adapt: read each response (status, length, body markers) and change your next payload accordingly.
- Confirm before claiming: a finding needs response evidence the injection/bypass actually landed,
  not just that a payload was accepted. If the evidence is weak, keep probing or stop "not_found".
- Stop as soon as you have confirmed the issue, or when you've genuinely run out of ideas.
- Output ONLY the JSON object, no prose around it."""


class IterativeAgent:
    def __init__(self, ollama, model: str, allowed_hosts: list[str], *, temperature: float = 0.2,
                 max_steps: int = 250):
        self.ollama = ollama
        self.model = model
        self.allowed_hosts = allowed_hosts or []
        self.temperature = temperature
        self.max_steps = max_steps
        # P2.6: idempotency guard, scoped to THIS active-probe session -- one
        # IterativeAgent is constructed fresh per run_active_probe() call
        # (orchestrator_confirm.py), so this set's lifetime is exactly "this
        # session", never leaking across sessions or agents.
        self._sent_signatures: set[str] = set()

    @property
    def gate(self):
        # Resolved fresh on every access, never cached: this agent is built once
        # at Orchestrator startup, long before any particular run's RunContext
        # (and its ambient gate) exists. Caching get_default_gate() at __init__
        # time pinned every later _execute() to whatever gate was ambient (or
        # the safe fallback) at STARTUP, forever -- exactly the stale-gate defect
        # this property closes (2026-09-17 coverage-recovery plan, Step 1).
        return get_default_gate()

    def _build_request(self, exchange: HttpExchange, action: dict, headers_state: dict) -> tuple:
        """Translate a constrained action into (method, url, headers, body),
        derived from the captured exchange. Returns (None, reason) if invalid."""
        method = exchange.method.upper()
        url = exchange.url
        body = exchange.request_body or ""
        headers = dict(headers_state)

        if action.get("action") == "set_header":
            name, value = action.get("name"), action.get("value")
            if not isinstance(name, str) or not isinstance(value, str):
                return None, "set_header requires string name/value"
            headers[name] = value
            return (method, url, headers, body), None

        # mutate
        loc, param, value = action.get("location"), action.get("param"), action.get("value")
        if loc not in ("query", "body", "path") or not isinstance(param, str) or not isinstance(value, str):
            return None, "mutate requires location(query|body|path), param, value"
        if loc == "path":
            new_url = _mutate_path_segment(url, param, value)
            if new_url is None:
                return None, f"path segment {param!r} not present on the captured request path"
            return (method, new_url, headers, body), None
        if loc == "query":
            new_url = _mutate_query_param(url, param, value)
            if new_url is None:
                return None, f"query param {param!r} not present on the captured request"
            return (method, new_url, headers, body), None
        # body
        ct = _content_type_of(exchange)
        if _looks_like_json(body, ct):
            nb = _mutate_json_param(body, param, value)
        else:
            nb = _mutate_form_param(body, param, value)
        if nb is None:
            return None, f"body param {param!r} not present on the captured request"
        return (method, url, headers, nb), None

    def _mutable_params(self, exchange: HttpExchange) -> dict:
        ct = _content_type_of(exchange)
        body = exchange.request_body or ""
        body_params = (_json_top_level_params(body) if _looks_like_json(body, ct)
                       else _form_top_level_params(body))
        # `path` lists id-like segments the agent may ENUMERATE (IDOR) -- the case
        # an object-scoped endpoint (/tickets/1) exposes no query/body param for.
        return {"query": _query_top_level_params(exchange.url), "body": body_params,
                "path": _path_id_values(exchange.url)}

    async def _execute(self, method, url, headers, body) -> tuple:
        """Scope-check + safety-gate + throttle + send, all through the single
        TargetTransport (W-16). Returns (status, text) or (None, reason-blocked).

        Scope, gate, and budget are enforced ONCE inside the transport (no separate
        pre-check that could disagree or double-count a mutating send). A standalone
        context carries this agent's own SafetyGate so mutating-method decisions are
        unchanged, and its scope is is_host_allowed(self.allowed_hosts) -- a superset
        of the old host/subdomain check. send_creds forwards any captured credential
        headers; max_redirects=0 keeps the old follow_redirects=False behaviour.

        P2.6: before sending, skip (and log) a request whose (method, URL,
        sha256(body), headers) signature was already sent THIS session -- the
        model re-proposing an identical mutation it already tried wastes a
        step/request budget on a probe that can only repeat the same answer.
        A genuinely different request (any of those four differs) is never
        skipped."""
        sig = _request_signature(method, url, headers, body)
        if sig in self._sent_signatures:
            log.info(
                "iterative_agent: skipping duplicate request already sent this "
                "active-probe session: %s %s", method, url)
            return None, "skipped: identical request already sent this active-probe session"
        self._sent_signatures.add(sig)

        _tt, _ctx = transport_for(None, allowed_hosts=self.allowed_hosts, gate=self.gate)
        try:
            await global_throttle.acquire()
            out = await _tt.send_creds(method, url, capability="iterative_agent",
                                       headers=headers, body=body, max_redirects=0)
            if out.outcome == "out_of_scope":
                return None, f"blocked: {urlsplit(url).hostname} out of scope"
            if out.outcome == "blocked":
                return None, f"blocked by safety gate: {out.error}"
            if not out.ok:
                return None, f"request failed: {out.error or out.outcome}"
            return out.status, (out.body or "")[:_MAX_RESP_CHARS]
        finally:
            if _ctx is not None:
                await _ctx.aclose()

    async def run(self, exchange: HttpExchange, hypothesis: str, specialty: str,
                  step_budget: int = 250, effort_budget: "EffortBudget | None" = None,
                  on_step=None) -> IterativeResult:
        """`on_step`, if given, is called with each IterativeStep right after it
        is recorded -- the live activity feed a UI subscribes to, so the tester
        can watch what the agent is doing in real time."""
        budget = min(step_budget, self.max_steps)
        result = IterativeResult(agent=f"iterative:{specialty}")
        consecutive_trouble = 0

        def emit(step_obj: IterativeStep) -> None:
            result.transcript.append(step_obj)
            log.info("iterative:%s step %d: %s -> %s%s", specialty, step_obj.n,
                     step_obj.action.get("action", "?"),
                     step_obj.response_status if step_obj.response_status is not None else (step_obj.blocked or "-"),
                     "" if not step_obj.blocked else " [blocked]")
            if on_step is not None:
                try:
                    on_step(step_obj)
                except Exception as e:  # a broken UI callback must never kill the run
                    log.debug("on_step callback raised: %s", e)
        headers_state = {k: v for k, v in (exchange.request_headers or {}).items()
                         if k.lower() not in ("host", "content-length")}
        headers_state.setdefault("User-Agent", "harness-iterative-agent/1.0")

        system = _SYSTEM_PROMPT.format(specialty=specialty)
        history: list[str] = [
            f"HYPOTHESIS: {hypothesis}",
            f"ENDPOINT: {exchange.method} {exchange.url}",
            f"RESPONSE STATUS (captured baseline): {exchange.response_status}",
            f"MUTABLE PARAMETERS: {json.dumps(self._mutable_params(exchange))}",
        ]

        for step in range(1, budget + 1):
            if effort_budget is not None:
                allowed, reason = effort_budget.allow()
                if not allowed:
                    result.stop_reason = "budget"
                    result.handoff_note = f"Halted by effort budget at step {step}: {reason}"
                    break

            user = ("\n".join(history) +
                    "\n\nChoose your next action as a single JSON object.")
            try:
                if effort_budget is not None:
                    r = await self.ollama.chat_json_metered(
                        model=self.model, system_prompt=system, user_prompt=user, temperature=self.temperature)
                    from harness.effort import CallKind
                    effort_budget.record(CallKind.ESCALATION, self.model, r.prompt_tokens, r.completion_tokens)
                    action = r.data
                else:
                    action = await self.ollama.chat_json(
                        model=self.model, system_prompt=system, user_prompt=user, temperature=self.temperature)
            except Exception as e:
                result.stop_reason = "error"
                result.handoff_note = f"LLM call failed at step {step}: {e}"
                break

            if not isinstance(action, dict):
                history.append(f"[step {step}] invalid action (not an object); try again.")
                continue

            kind = action.get("action")
            if kind == "stop":
                result.stop_reason = "found" if action.get("verdict") == "found" else "gave_up"
                fd = action.get("finding")
                if result.stop_reason == "found" and isinstance(fd, dict):
                    try:
                        result.findings.append(Finding(**sanitize_agent_finding(fd)))
                    except Exception as e:
                        log.debug("iterative_agent: malformed finding on stop: %s", e)
                result.handoff_note = action.get("thought", "") or result.handoff_note
                result.steps_used = step - 1
                emit(IterativeStep(step, action, "(stop)", None, ""))
                return result

            built, err = self._build_request(exchange, action, headers_state)
            if err:
                history.append(f"[step {step}] action rejected: {err}")
                emit(IterativeStep(step, action, "(rejected)", None, err, blocked=err))
                continue
            method, url, headers, body = built
            if kind == "set_header":
                headers_state = headers  # persist

            status, text = await self._execute(method, url, headers, body)
            req_summary = f"{method} {url}" + (f" body={body[:80]}" if body else "")
            if status is None:
                history.append(f"[step {step}] {req_summary} -> {text}")
                emit(IterativeStep(step, action, req_summary, None, text, blocked=text))
                # A transport failure (or safety/scope block that returned None)
                # counts toward target-distress only when it is an actual send
                # failure, not a pre-send policy block.
                if text.startswith("request failed"):
                    consecutive_trouble += 1
                else:
                    consecutive_trouble = 0
            else:
                resp_summary = f"HTTP {status}, {len(text)} bytes: {text[:400]}"
                history.append(f"[step {step}] {req_summary} -> {resp_summary}")
                emit(IterativeStep(step, action, req_summary, status, text[:400]))
                consecutive_trouble = consecutive_trouble + 1 if status in _DISTRESS_STATUSES else 0

            # Abort if the target is clearly in trouble -- stop piling on a
            # service that is shedding load or failing, rather than exhausting
            # the whole step budget against it.
            if consecutive_trouble >= _MAX_CONSECUTIVE_TROUBLE:
                result.stop_reason = "target_distress"
                result.steps_used = step
                result.handoff_note = (
                    f"Aborted after {consecutive_trouble} consecutive distress responses "
                    f"(429/5xx or transport failures) at step {step}: the target appears "
                    f"unavailable or rate-limiting. Not a clean result -- retry later.")
                return result

        result.steps_used = min(budget, len(result.transcript))
        if not result.stop_reason:
            result.stop_reason = "exhausted_steps"
            if not result.handoff_note:
                result.handoff_note = (f"Ran {result.steps_used} steps on {exchange.method} "
                                       f"{exchange.url} without confirming {specialty}; last responses in transcript.")
        return result
