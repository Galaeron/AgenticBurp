"""Run-owned accounting for existing passive specialist and family calls."""
from __future__ import annotations

import logging
import math
import time
import asyncio

from harness.effort import CallKind
from harness.ollama_client import OllamaError

log = logging.getLogger(__name__)


def settle_call(budget, kind, model, reserved, receipt, *, provider="", elapsed_ms=None):
    """One attempt receipt. Unknowns never become measured zero tokens."""
    receipt = receipt if isinstance(receipt, dict) else {}
    def count(value):
        return value if type(value) is int and value >= 0 else None
    return budget.commit(
        kind, model, count(receipt.get("prompt_tokens")), count(receipt.get("completion_tokens")),
        reserved=reserved, provider=provider,
        outcome=receipt.get("outcome", "error"), attempted=True,
        completed=bool(receipt.get("completed", False)), usable=bool(receipt.get("usable", False)),
        queue_ms=receipt.get("queue_ms"), connection_ms=receipt.get("connection_ms"),
        generation_ms=receipt.get("generation_ms"), wall_ms=receipt.get("wall_ms", elapsed_ms),
        latency_ms=receipt.get("wall_ms") or elapsed_ms or 0.0,
        retries=receipt.get("retries", 0),
    )


async def metered_passive_call(client, budget, *, kind=CallKind.AGENT_DISPATCH, **kwargs):
    """Reserve an admission estimate; settle only returned provider usage.

    The estimate limits concurrent admission, not the model's eventual output.
    No run state lives on a manager/client. Standalone callers can omit a budget
    but their calls are explicitly unmetered in the run ledger.
    """
    from harness.security import sanitize_for_inference
    kwargs["system_prompt"], kwargs["user_prompt"] = sanitize_for_inference(
        kwargs["system_prompt"], kwargs["user_prompt"])
    if budget is None:
        log.warning("Passive inference has no run-owned budget; run accounting is unmetered")
        return await client.chat_json_metered(**kwargs)

    reserved = math.ceil(budget.ledger.average_tokens(kind))
    allowed, reason = budget.reserve(reserved)
    if not allowed:
        raise OllamaError(reason)
    started = time.monotonic()
    try:
        result = await client.chat_json_metered(**kwargs)
        receipt = getattr(result, "measurement", None)
        if not isinstance(receipt, dict):
            receipt = {"prompt_tokens": result.prompt_tokens, "completion_tokens": result.completion_tokens,
                       "completed": True, "usable": True, "outcome": "ok"}
        settle_call(budget, kind, kwargs["model"], reserved, receipt,
                    provider="ollama", elapsed_ms=(time.monotonic() - started) * 1000.0)
        reserved = 0
        return result
    except BaseException as exc:
        receipt = getattr(exc, "inference_usage", None) or {
            "outcome": "cancelled" if isinstance(exc, asyncio.CancelledError) else "error"}
        settle_call(budget, kind, kwargs["model"], reserved, receipt,
                    provider="ollama", elapsed_ms=(time.monotonic() - started) * 1000.0)
        reserved = 0
        raise
    finally:
        # Includes cancellation (BaseException), provider errors and parsing
        # errors: failed transport never becomes invented measured tokens.
        if reserved:
            budget.release(reserved)


async def passive_chat_json(client, budget, **kwargs):
    if budget is None:
        from harness.security import sanitize_for_inference
        kwargs["system_prompt"], kwargs["user_prompt"] = sanitize_for_inference(
            kwargs["system_prompt"], kwargs["user_prompt"])
        log.warning("Passive inference has no run-owned budget; run accounting is unmetered")
        return await client.chat_json(**kwargs)
    return (await metered_passive_call(client, budget, **kwargs)).data
