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
import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

import httpx  # noqa: F401 -- HTTP transport site; sends now go via run_context.TargetTransport

from harness import global_throttle
from harness.models import Finding, HttpExchange, sanitize_agent_finding
from harness.safety_gate import get_default_gate
from harness.security import SECRET_HEADER_NAMES  # the one classifier behind redact_headers
from harness.run_context import transport_for  # W-16: the single TargetTransport
# Reuse the exact, tested mutation helpers the sqlmap validator already uses --
# same bounded "change one param value on the captured request" envelope.
from harness.validators.sqlmap import (
    _mutate_query_param, _mutate_json_param, _mutate_form_param,
    _query_top_level_params, _json_top_level_params, _form_top_level_params,
    _looks_like_json, _content_type_of, _DB_ERROR_MARKERS,
)

if TYPE_CHECKING:
    from harness.effort import EffortBudget

log = logging.getLogger("harness.iterative_agent")


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


# Ticket D: the exact text a skipped duplicate carries, shared by _execute's
# backstop and the pre-transport rejection in _run_loop so both read the same.
_DUP_BLOCK = "skipped: identical request already sent this active-probe session"
# Back-to-back duplicate proposals of the SAME earlier attempt tolerated before
# the run is stopped as stuck (see _DuplicateStreak).
_MAX_CONSECUTIVE_DUPLICATES = 2
_PRIOR_ATTEMPTS_WINDOW = 25     # attempt lines carried in each prompt
_VALUE_EXCERPT_CHARS = 60       # payload value shown per attempt line
_TARGET_RENDER_CHARS = 160      # normalized target shown per attempt line
_OUTCOME_RENDER_CHARS = 100     # outcome (status+length, or block reason) per line


def _excerpt(text: object, limit: int = _VALUE_EXCERPT_CHARS) -> str:
    """One-line, whitespace-collapsed excerpt of at most `limit` characters."""
    flat = re.sub(r"\s+", " ", str(text)).strip()
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def _header_value_view(name: object, value: object) -> str:
    """How a header value the model set is shown in a prompt line: an excerpt,
    except for names security.SECRET_HEADER_NAMES treats as secret (Authorization,
    Cookie, X-API-Key, ...), which show only a fingerprint of the value so two
    different tokens still read as two different attempts."""
    if str(name).lower() in SECRET_HEADER_NAMES:
        return "<redacted #" + hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:8] + ">"
    return _excerpt(value)


# The body kept from each probe response, so an error or a reflection anywhere in a
# realistic page is still found; only _response_view's few hundred characters of it
# reach the model.
_MAX_RESP_CHARS = 262144
_RESP_HEAD_CHARS = 500          # start of the body shown for every response
_RESP_WINDOW_CHARS = 180        # context each side of an error, reflection or change
_RESP_MAX_WINDOWS = 3
_DETAILED_STEPS = 2             # latest responses shown in full; older ones as one line
_VIEW_HEADERS = ("content-type", "location", "www-authenticate", "x-powered-by", "server")
_SERVER_ERROR_RE = re.compile(
    "|".join(re.escape(m) for m in _DB_ERROR_MARKERS)
    + r"|exception|traceback|stack trace|syntax error|unexpected token|\berror:", re.I)
_COOKIE_NAME_RE = re.compile(r"(?:^|[,\n]\s*)([^=;,\s]+)=")


def _response_view(text: object, *, headers: dict | None = None, baseline: object = None,
                   probe: object = None) -> tuple[str, list[str]]:
    """What the model is shown of one probe response, and the signals found in it.

    The start of the body, then a window around each place that matters wherever it
    is: a database or server error, the value just sent coming back (reflection), and
    the first place the body departs from the captured baseline. A cut at a fixed
    length hides exactly these on a realistic page (an SQL error under 3 KB of HTML).
    A few response headers come first; cookie values are never shown."""
    body = re.sub(r"\s+", " ", str(text or ""))
    found: list[tuple[str, int]] = []
    error = _SERVER_ERROR_RE.search(body)
    if error:
        found.append(("error", error.start()))
    needle = re.sub(r"\s+", " ", str(probe or "")).strip()
    if len(needle) >= 3 and (at := body.find(needle)) >= 0:
        found.append(("reflected", at))
    if baseline is not None:
        base = re.sub(r"\s+", " ", str(baseline))
        if base != body:
            found.append(("differs from baseline", len(os.path.commonprefix([base, body]))))
    parts = [body[:_RESP_HEAD_CHARS] + ("..." if len(body) > _RESP_HEAD_CHARS else "")]
    shown_to = _RESP_HEAD_CHARS
    for name, at in sorted(found, key=lambda f: f[1])[:_RESP_MAX_WINDOWS]:
        if at + 60 <= shown_to:  # already readable in what is shown
            continue
        start, end = max(at - _RESP_WINDOW_CHARS, shown_to), min(len(body), at + _RESP_WINDOW_CHARS)
        parts.append(f"[{name} @{at}] ...{body[start:end]}...")
        shown_to = end
    lowered = {str(k).lower(): v for k, v in (headers or {}).items()}
    shown = [f"{k}={_excerpt(_header_value_view(k, lowered[k]), 80)}"
             for k in _VIEW_HEADERS if k in lowered]
    if "set-cookie" in lowered:
        shown.append("set-cookie names=" + ",".join(_COOKIE_NAME_RE.findall(str(lowered["set-cookie"]))))
    view = (f"headers: {'; '.join(shown)}\n" if shown else "") + "\n".join(parts)
    return view, [name for name, _ in found]


def _render_history(history: list) -> str:
    """The prompt's history. Plain lines as they are; of the (short, full) step responses
    the latest _DETAILED_STEPS in full and older ones as their short line, so the prompt
    stays inside the model's context window however many steps ran."""
    responses = [i for i, item in enumerate(history) if isinstance(item, tuple)]
    full = set(responses[-_DETAILED_STEPS:]) if _DETAILED_STEPS > 0 else set()
    return "\n".join(item if isinstance(item, str) else item[1] if i in full else item[0]
                     for i, item in enumerate(history))


def _sorted_query(query: str) -> str:
    # Only the order of DIFFERENT parameter names is normalized: segments are
    # neither decoded nor re-encoded, and the sort is stable on the name alone,
    # so repeated names keep their order (?id=1&id=2 != ?id=2&id=1) and two
    # requests that differ in any value byte stay distinct.
    return "&".join(sorted(query.split("&"), key=lambda seg: seg.split("=", 1)[0])) if query else ""


def _normalize_url(url: str) -> str:
    """URL with a canonical query-parameter order, lower-cased scheme/host and no
    fragment (never sent). Path and parameter values are left byte-exact."""
    parts = urlsplit(url)
    userinfo, at, hostport = parts.netloc.rpartition("@")
    return urlunsplit((parts.scheme.lower(), userinfo + at + hostport.lower(),
                       parts.path, _sorted_query(parts.query), ""))


def _attempt_key(method: str, url: str, headers: dict | None, body: str | None) -> str:
    """Ticket D: the per-run identity of a built request -- method, URL with
    sorted query, sha256(body) and the FULL header set (so a changed
    authorization header, object id or body field is a different attempt)."""
    return _request_signature(method, _normalize_url(url), headers, body)


def _normalized_target(url: str, body: str | None, changed_headers: dict | None) -> str:
    """Compact target for an attempt line: path + sorted query, a body hash and
    the header names/values the action changed."""
    parts = urlsplit(url)
    out = parts.path or "/"
    if parts.query:
        out += "?" + _sorted_query(parts.query)
    if body:
        out += " body#" + hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:10]
    for name, value in sorted((changed_headers or {}).items(), key=lambda kv: str(kv[0]).lower()):
        out += f" hdr[{name}={_header_value_view(name, value)}]"
    return out


class _DuplicateStreak:
    """`consecutive_duplicates`: back-to-back duplicate proposals that repeat the
    SAME earlier attempt. A duplicate of a different earlier attempt restarts the
    count at 1 (A,B,A,C,A,B,D has duplicate runs of one, so it is never stopped);
    a non-duplicate send resets it to 0. Mixed back-to-back duplicates (A,B,A,B)
    are still bounded by run()'s consecutive_no_progress >= 3 stop."""

    def __init__(self) -> None:
        self.count = 0
        self._of: int | None = None

    def duplicate(self, of: int) -> int:
        self.count = self.count + 1 if of == self._of else 1
        self._of = of
        return self.count

    def reset(self) -> None:
        self.count = 0
        self._of = None


@dataclass
class AttemptRecord:
    """One distinct request the agent tried (sent, or blocked/failed at transport)."""
    step: int
    kind: str          # action kind: mutate|set_header
    method: str
    target: str        # _normalized_target(...)
    location: str      # mutated location: query|body|path|header
    name: str          # param / path segment / header name
    value: str         # payload value excerpt, <= 60 chars
    outcome: str       # "HTTP <status>, <n> bytes" or the block reason
    key: str = ""

    def line(self) -> str:
        return (f"- step {self.step}: {self.kind} {self.location}:{_excerpt(self.name)}"
                f"={json.dumps(self.value)} | {self.method} "
                f"{_excerpt(self.target, _TARGET_RENDER_CHARS)}"
                f" | {_excerpt(self.outcome, _OUTCOME_RENDER_CHARS)}")


def _prior_attempts_block(attempts: list[AttemptRecord], duplicates: int) -> str:
    """The compact "PRIOR ATTEMPTS (do not repeat)" block each prompt carries:
    the last <=25 distinct attempts, one line each with its outcome, plus the
    count of distinct requests tried."""
    shown = attempts[-_PRIOR_ATTEMPTS_WINDOW:]
    head = (f"PRIOR ATTEMPTS (do not repeat) -- distinct requests tried: {len(attempts)}; "
            f"duplicate proposals rejected: {duplicates}")
    if not shown:
        return head + "\n(none yet)"
    if len(shown) < len(attempts):
        head += f"; showing the last {len(shown)}"
    return head + "\n" + "\n".join(a.line() for a in shown)

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
    stop_reason: str = ""            # found|exhausted_steps|gave_up|budget|error|target_distress|no_progress|repeated_duplicates
    transcript: list[IterativeStep] = field(default_factory=list)
    # Ticket D: proposals rejected before transport because the built request
    # was already attempted, and distinct requests actually tried (sent, or
    # blocked/failed at transport -- anything handed to _execute once).
    duplicate_proposals: int = 0
    distinct_requests: int = 0

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "findings": [f.model_dump() for f in self.findings],
            "handoff_note": self.handoff_note,
            "steps_used": self.steps_used,
            "stop_reason": self.stop_reason,
            "duplicate_proposals": self.duplicate_proposals,
            "distinct_requests": self.distinct_requests,
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
                 max_steps: int = 250, run_context=None):
        self.ollama = ollama
        self.model = model
        self.allowed_hosts = allowed_hosts or []
        self.temperature = temperature
        self.max_steps = max_steps
        # ARCH-1: the OWNING run's context when this probe runs inside an
        # engagement (threaded engagement -> run_active_probe -> here), else a
        # single standalone context the caller built for the whole probe. When
        # set, every send in _execute goes through THIS run's one TargetTransport,
        # so the probe draws on the run's request budget, cancel token, TLS and
        # evidence context instead of escaping into a throwaway per-send client
        # that no parent accounting ever covered. The agent BORROWS the context;
        # ownership (and aclose) stays with the caller (see run_active_probe).
        self._run_context = run_context
        # P2.6: idempotency guard, scoped to THIS active-probe session -- one
        # IterativeAgent is constructed fresh per run_active_probe() call
        # (orchestrator_confirm.py), so this set's lifetime is exactly "this
        # session", never leaking across sessions or agents.
        self._sent_signatures: set[str] = set()
        self._last_response_headers: dict = {}   # of the latest send, for _response_view

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
        skipped. Ticket D: `run` now rejects duplicates BEFORE calling this; the
        check here stays as the backstop for any other caller."""
        sig = _request_signature(method, url, headers, body)
        if sig in self._sent_signatures:
            log.info(
                "iterative_agent: skipping duplicate request already sent this "
                "active-probe session: %s %s", method, url)
            return None, _DUP_BLOCK
        self._sent_signatures.add(sig)

        # ARCH-1: route through the OWNING run's transport when present (owned
        # context is None, so the finally never closes a borrowed run); only a
        # directly-constructed agent with no run_context falls back to a
        # per-send standalone context (owned, closed below), preserving the old
        # behaviour for callers that build an IterativeAgent on their own.
        _tt, _ctx = transport_for(self._run_context, allowed_hosts=self.allowed_hosts, gate=self.gate)
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
            self._last_response_headers = dict(out.headers or {})
            return out.status, (out.body or "")[:_MAX_RESP_CHARS]
        finally:
            if _ctx is not None:
                await _ctx.aclose()

    def _find_duplicate(self, key: str, sig: str,
                        attempt_by_key: "dict[str, AttemptRecord]") -> tuple:
        """Ticket D: has this built request already been attempted? Returns
        (is_duplicate, earlier_attempt). The earlier attempt is None when only
        this agent instance's `_sent_signatures` remembers it (sent by an
        earlier run of the same instance, so there is no step to cite)."""
        prior = attempt_by_key.get(key)
        if prior is not None:
            return True, prior
        return (sig in self._sent_signatures), None

    async def run(self, exchange: HttpExchange, hypothesis: str, specialty: str,
                  step_budget: int = 250, effort_budget: "EffortBudget | None" = None,
                  on_step=None) -> IterativeResult:
        """`on_step`, if given, is called with each IterativeStep right after it
        is recorded -- the live activity feed a UI subscribes to, so the tester
        can watch what the agent is doing in real time.

        Ticket D: logs one summary line when the run ends, whichever way it ends
        (steps, distinct requests tried, duplicate proposals, stop reason)."""
        result = IterativeResult(agent=f"iterative:{specialty}")
        try:
            return await self._run_loop(result, exchange, hypothesis, specialty,
                                        step_budget, effort_budget, on_step)
        finally:
            log.info("iterative:%s summary steps=%d distinct=%d duplicates=%d stop=%s",
                     specialty, result.steps_used, result.distinct_requests,
                     result.duplicate_proposals, result.stop_reason)

    async def _run_loop(self, result: IterativeResult, exchange: HttpExchange,
                        hypothesis: str, specialty: str, step_budget: int,
                        effort_budget: "EffortBudget | None", on_step) -> IterativeResult:
        budget = min(step_budget, self.max_steps)
        consecutive_trouble = 0
        consecutive_no_progress = 0
        # Ticket D: structured prior attempts. `attempts` is the ordered list of
        # distinct requests tried; `attempt_by_key` finds the earlier attempt a
        # new proposal duplicates; `dup_streak` counts back-to-back duplicate
        # proposals of the SAME earlier attempt.
        attempts: list[AttemptRecord] = []
        attempt_by_key: dict[str, AttemptRecord] = {}
        dup_streak = _DuplicateStreak()

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
        history: list[str | tuple[str, str]] = [
            f"HYPOTHESIS: {hypothesis}",
            f"ENDPOINT: {exchange.method} {exchange.url}",
            f"RESPONSE STATUS (captured baseline): {exchange.response_status}",
            f"RESPONSE BODY (captured baseline, start): "
            f"{_excerpt(exchange.response_body or '', _RESP_HEAD_CHARS)}",
            f"MUTABLE PARAMETERS: {json.dumps(self._mutable_params(exchange))}",
        ]

        for step in range(1, budget + 1):
            if consecutive_no_progress >= 3:
                result.stop_reason = "no_progress"
                result.handoff_note = (
                    "Stopped after three consecutive actions produced no response "
                    "(duplicate, rejected, blocked, or failed requests). "
                    "Assessment remains inconclusive; see transcript.")
                break
            if effort_budget is not None:
                allowed, reason = effort_budget.allow()
                if not allowed:
                    result.stop_reason = "budget"
                    result.handoff_note = f"Halted by effort budget at step {step}: {reason}"
                    break

            user = (_render_history(history) +
                    "\n\n" + _prior_attempts_block(attempts, result.duplicate_proposals) +
                    "\n\nChoose your next action as a single JSON object.")
            try:
                from harness.ollama_client import model_stage
                if effort_budget is not None:
                    with model_stage("iterative"):
                        r = await self.ollama.chat_json_metered(
                            model=self.model, system_prompt=system, user_prompt=user, temperature=self.temperature)
                    from harness.effort import CallKind
                    effort_budget.record(CallKind.ESCALATION, self.model, r.prompt_tokens, r.completion_tokens)
                    action = r.data
                else:
                    with model_stage("iterative"):
                        action = await self.ollama.chat_json(
                            model=self.model, system_prompt=system, user_prompt=user, temperature=self.temperature)
            except Exception as e:
                result.stop_reason = "error"
                result.handoff_note = f"LLM call failed at step {step}: {e}"
                break

            if not isinstance(action, dict):
                history.append(f"[step {step}] invalid action (not an object); try again.")
                consecutive_no_progress += 1
                emit(IterativeStep(step, {}, "(rejected)", None, "invalid action", blocked="invalid action"))
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
                consecutive_no_progress += 1
                history.append(f"[step {step}] action rejected: {err}")
                emit(IterativeStep(step, action, "(rejected)", None, err, blocked=err))
                continue
            method, url, headers, body = built
            if kind == "set_header":
                headers_state = headers  # persist
            req_summary = f"{method} {url}" + (f" body={body[:80]}" if body else "")

            # Ticket D: reject a duplicate BEFORE transport. The key is built from
            # the request itself (method, URL with sorted query, body hash, full
            # header set), so the model's phrasing of the action cannot hide a repeat.
            key = _attempt_key(method, url, headers, body)
            is_dup, prior = self._find_duplicate(
                key, _request_signature(method, url, headers, body), attempt_by_key)
            if is_dup:
                result.duplicate_proposals += 1
                dup_of = prior.step if prior is not None else 0  # 0: sent by an earlier run
                consecutive_duplicates = dup_streak.duplicate(dup_of)
                consecutive_no_progress += 1
                ref = (f"step {prior.step} (outcome {_excerpt(prior.outcome, _OUTCOME_RENDER_CHARS)})"
                       if prior is not None
                       else "an earlier run's request on this agent (outcome unknown)")
                note = f"DUPLICATE of {ref}: choose a different supported action or stop"
                history.append(f"[step {step}] {note}")
                log.info(
                    "iterative_agent: skipping duplicate request already sent this "
                    "active-probe session: %s %s", method, url)
                blocked = f"{_DUP_BLOCK} ({note})"
                emit(IterativeStep(step, action, req_summary, None, blocked, blocked=blocked))
                if consecutive_duplicates >= _MAX_CONSECUTIVE_DUPLICATES:
                    result.stop_reason = "repeated_duplicates"
                    result.handoff_note = (
                        f"Stopped at step {step}: the model proposed {result.duplicate_proposals} "
                        f"duplicate request(s) ({consecutive_duplicates} back-to-back repeating the "
                        f"same earlier attempt) after {result.distinct_requests} distinct request(s) "
                        f"on {exchange.method} {exchange.url}. Assessment is inconclusive; "
                        f"see transcript.")
                    break
                continue
            dup_streak.reset()  # a non-duplicate send resets consecutive_duplicates
            result.distinct_requests += 1

            self._last_response_headers = {}
            status, text = await self._execute(method, url, headers, body)
            changed = {action["name"]: action["value"]} if kind == "set_header" else {}
            rec = AttemptRecord(
                step=step, kind="set_header" if kind == "set_header" else "mutate", method=method,
                target=_normalized_target(url, body, changed),
                location="header" if kind == "set_header" else str(action.get("location")),
                name=str(action.get("name") if kind == "set_header" else action.get("param")),
                value=(_header_value_view(action.get("name"), action.get("value"))
                       if kind == "set_header" else _excerpt(action.get("value"))),
                outcome=(f"HTTP {status}, {len(text)} bytes" if status is not None else text),
                key=key)
            attempts.append(rec)
            attempt_by_key[key] = rec
            if status is None:
                consecutive_no_progress += 1
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
                consecutive_no_progress = 0
                view, signals = _response_view(
                    text, headers=self._last_response_headers,
                    baseline=exchange.response_body or None,
                    probe=None if kind == "set_header" else action.get("value"))
                line = f"[step {step}] {req_summary} -> HTTP {status}, {len(text)} bytes"
                # Shown in full while among the latest _DETAILED_STEPS, then as the short line.
                history.append((line + (f" [{', '.join(signals)}]" if signals else ""),
                                f"{line}:\n{view}"))
                emit(IterativeStep(step, action, req_summary, status, view))
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
