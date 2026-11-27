"""How a harness refusal is shown to a model.

A model that drives requests (the iterative agent) reads every step's outcome
from one history. A refusal the harness itself made -- the host is out of
scope, the safety gate denied the request, the run's request budget is spent,
the proposal repeats an earlier one, the action was malformed -- used to sit in
that history as a bare line such as `blocked: <host> out of scope`, which a
model can mistake for the target's own defence (a WAF page, a 403) and then
spend steps re-encoding the same request to get past it.

`frame()` wraps such a reason in a fixed marker that says where it came from,
that nothing reached the target, and that a variant will be refused too. It is
for MODEL-FACING text only: logs, telemetry, transcripts, stop reasons,
counters and the evidence ledger keep the raw reason. A response the target
sent (any HTTP status, a WAF page, a rate limit) never goes through here.
"""
from __future__ import annotations

# The marker every framed refusal starts with; the system prompt names it.
MARKER = "HARNESS POLICY REFUSAL"

SCOPE = "scope"
SAFETY_GATE = "safety_gate"
BUDGET = "budget"
DUPLICATE = "duplicate"
REJECTED_PROPOSAL = "rejected_proposal"
SESSION = "session"
ROUTE_PAUSED = "route_paused"
CANCELLED = "cancelled"
MECHANISM = "mechanism"

# What the model should do instead, per category. Wording is this project's own.
_NEXT = {
    SCOPE: "that destination is outside this engagement; change approach or stop",
    SAFETY_GATE: "this kind of request is not permitted in this run; change approach or stop",
    BUDGET: "the run's request budget is spent and no further request will be sent; stop with your verdict",
    DUPLICATE: "the same request was already tried; choose a different supported action or stop",
    REJECTED_PROPOSAL: ("the action is malformed or not supported here; choose a different "
                        "supported action (see the action list and MUTABLE PARAMETERS) or stop"),
    SESSION: "the identity this probe uses is not usable right now; change approach or stop",
    ROUTE_PAUSED: "the harness paused requests to this route for now; change approach or stop",
    CANCELLED: "the run was cancelled and no further request will be sent; stop",
    MECHANISM: "the harness did not run this selection; choose a different supported action or stop",
}

# The transport's unsent outcomes (run_context.ExecutionOutcome.outcome) that the
# harness decides. "error" is not here: a connection failure is not a policy.
_OUTCOME_CATEGORY = {
    "out_of_scope": SCOPE,
    "blocked": SAFETY_GATE,
    "budget_exhausted": BUDGET,
    "session_expired": SESSION,
    "unknown_session": SESSION,
    "route_unavailable": ROUTE_PAUSED,
    "cancelled": CANCELLED,
}


def category_for_outcome(outcome: str | None) -> str | None:
    """The refusal category of a transport outcome, or None when the outcome is
    not a harness refusal (a send happened, or it failed in transit)."""
    return _OUTCOME_CATEGORY.get(outcome or "")


def frame(category: str, reason: str) -> str:
    """The model-facing text for one harness refusal: the marker, where it came
    from, that the target never saw it, that a variant is refused too, what to
    do next, and the raw reason last."""
    nxt = _NEXT.get(category, "choose a different supported action or stop")
    return (f"{MARKER} [{category}]: the testing harness refused this before anything was "
            "sent; it is not a response, error page, WAF block or rate limit from the target, "
            "so there is nothing to get around. Do not retry it or a re-encoded or otherwise "
            f"varied form of it: {nxt}. Harness reason: {reason}")


def short(category: str, reason: str) -> str:
    """The compact form: PRIOR ATTEMPTS lines, and every refusal after the first
    of its category in one probe (the system prompt explains the marker), so a
    probe full of refusals grows its prompt by this much per refusal, not by
    the full framing."""
    return f"{MARKER} [{category}], not sent: {reason}"
