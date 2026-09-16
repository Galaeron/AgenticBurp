"""
Wires retry_policy.py and payload_library.py into the one place they were
designed for but never connected to: a Burp-plane TestPlan (xss, ssrf,
business_logic -- the categories payload_library actually stocks) whose
first attempt comes back anything other than confirmed.

Before this module existed, /validation-results accepted a submission and
stopped -- a not_confirmed result on a real vulnerability that an LLM
correctly hypothesized but the FIRST payload happened not to trigger
(e.g. a canary landing in a JS string context when the curated library's
first guess assumed HTML text) was indistinguishable from "not a real
vulnerability." This module decides, using the same attempt history
retry_policy.py already knows how to reason about, whether another
attempt (a genuinely different payload, never a re-ask of the same
question) is warranted, and builds the TestPlan for it.

Deliberately scoped to execution_plane == "burp" and a category
payload_library actually has payloads for: sqlmap (the other retryable-
in-principle capability) already runs its own internal payload engine in
a single bounded invocation -- there is no per-payload "attempt" for this
module to slot a curated substitute into without redesigning that
validator's interface, which is out of scope here.
"""
from __future__ import annotations
import hashlib
import logging
from dataclasses import dataclass

from harness import payload_library
from harness import store
from harness.models import TestPlan, ValidationSubmission
from harness.ollama_client import OllamaClient, OllamaError
from harness.retry_policy import Action, Attempt, AttemptStatus, RetryPolicy

log = logging.getLogger("harness.active_verification")

_RETRYABLE_CATEGORIES = {"xss", "ssrf", "business_logic"}

_STATUS_MAP = {
    "confirmed": AttemptStatus.CONFIRMED,
    "supported": AttemptStatus.SUPPORTED,
    "not_confirmed": AttemptStatus.NOT_CONFIRMED,
    "inconclusive": AttemptStatus.INCONCLUSIVE,
    "error": AttemptStatus.ERROR,
    "blocked": AttemptStatus.ERROR,
    "skipped": AttemptStatus.ERROR,
}


@dataclass
class NextStep:
    next_plan: TestPlan | None = None
    handover_required: bool = False
    note: str = ""


def _to_attempt(row: dict) -> Attempt:
    payload = row["mutation"].get("payload")
    return Attempt(
        status=_STATUS_MAP.get(row["status"], AttemptStatus.NOT_CONFIRMED),
        model="default" if not row["escalated"] else "escalated",
        escalated=row["escalated"],
        payload=payload,
        confidence=row["result_confidence"] or 0.0,
    )


def is_retryable(plan: dict) -> bool:
    return plan.get("execution_plane") == "burp" and plan.get("category") in _RETRYABLE_CATEGORIES


def _build_plan(plan: dict, payload_value: str, note: str, escalated: bool) -> TestPlan:
    payload_digest = hashlib.sha256(payload_value.encode()).hexdigest()[:12]
    return TestPlan(
        id=f"{plan['plan_id']}:retry:{payload_digest}",
        capability=plan["capability"],
        finding_class=plan["finding_class"],
        category=plan["category"],
        source_exchange_url=plan["url"],
        mutation={"strategy": "payload-substitution", "payload": payload_value, "note": note},
        success_signals=["independent evidence supports the hypothesis"],
        requires_approval=True,
        execution_plane="burp",
        rationale=f"Retry of {plan['plan_id']}: previous attempt(s) did not confirm.",
        source_exchange_hash=plan["source_exchange_hash"],
        severity=plan["severity"],
        confidence=plan["confidence"],
        escalated=escalated,
    )


async def decide_next_step(
    plan: dict,
    submission: ValidationSubmission,
    ollama_client: OllamaClient | None = None,
    escalation_model: str = "",
) -> NextStep:
    """
    `plan` is the row for submission.plan_id (store.get_test_plan's
    output). Assumes the submission has ALREADY been persisted -- this
    only decides what, if anything, comes next.
    """
    if submission.confirmed or submission.status == "confirmed":
        return NextStep()
    if not is_retryable(plan):
        return NextStep()

    history = store.get_lineage_attempts(plan["category"], plan["source_exchange_hash"])
    attempts = [_to_attempt(r) for r in history]
    action = RetryPolicy().decide(attempts, plan["confidence"], plan["severity"] or "medium")

    tried = [a.payload for a in attempts if a.payload]

    if action == Action.RETRY_DEFAULT:
        candidate = payload_library.next_candidate(
            plan["category"], tried, tuple(submission.context_tags)
        )
        if candidate is not None:
            return NextStep(next_plan=_build_plan(plan, candidate.value, candidate.note, escalated=False))
        # Curated library exhausted sooner than max_default_attempts allowed
        # for -- fall through to the same LLM-fallback path ESCALATE uses,
        # since there is nothing left to retry with by default means.
        action = Action.ESCALATE

    if action == Action.ESCALATE:
        if ollama_client is None:
            log.warning(
                "active_verification: escalation needed for lineage (category=%s, exchange=%s) "
                "but no ollama_client was supplied -- stopping inconclusive instead of escalating.",
                plan["category"], plan["source_exchange_hash"],
            )
            return NextStep(note="escalation skipped: no LLM client available")
        failure_notes = [
            f"{r['status']}: {r['mutation'].get('note', '')}".strip(": ") for r in history
        ]
        prompt = payload_library.llm_fallback_prompt(
            plan["category"], tried,
            exchange_summary=f"{plan['url']} (finding_class={plan['finding_class']})",
            failure_notes=failure_notes,
        )
        try:
            result = await ollama_client.chat_json(
                model=escalation_model or "llama3.1:8b",
                system_prompt="You are a focused security payload assistant. Respond with ONLY the requested JSON.",
                user_prompt=prompt,
            )
            new_payload = str(result.get("payload", "")).strip()
            rationale = str(result.get("rationale", ""))
        except OllamaError as e:
            log.warning("active_verification: escalation LLM call failed: %s", e)
            return NextStep(note=f"escalation LLM call failed: {e}")
        if not new_payload:
            return NextStep(note="escalation LLM returned no payload")
        return NextStep(next_plan=_build_plan(plan, new_payload, rationale, escalated=True))

    if action == Action.HANDOVER_MANUAL:
        log.warning(
            "active_verification: HANDOVER_MANUAL -- unconfirmed high-suspicion finding "
            "(category=%s, exchange=%s, finding_class=%s) needs operator review.",
            plan["category"], plan["source_exchange_hash"], plan["finding_class"],
        )
        return NextStep(handover_required=True, note="unconfirmed after retries; needs operator review")

    return NextStep()
