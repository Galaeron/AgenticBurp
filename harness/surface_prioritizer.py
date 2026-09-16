"""
LLM-based prioritization pass over a BATCH of candidate endpoints (method,
URL, parameter names only -- no request/response bodies), used by the
Burp extension's "Attack Surface Map" tab (AttackSurfacePanel.java) to
rank pre-scanned rows beyond what the local, no-LLM PathScorer heuristic
alone can judge.

Deliberately batched into few LLM calls, not one per endpoint: the whole
point of PathScorer's own design (see AttackSurfacePanel.java's
docstring) is that running hundreds of endpoints through an LLM one at a
time would be slow and mostly redundant with cheap pattern matching.
Batching keeps this bounded even for a large site map, at the cost of
somewhat shallower per-endpoint reasoning than the full per-exchange
agent pipeline (/analyze) provides -- this is a triage/ranking pass over
STRUCTURE ALONE, not a vulnerability analysis; that's still /analyze's
job once the analyst picks a candidate off the ranked list.
"""
from __future__ import annotations
import logging

from harness.models import PrioritizeRequestItem, PrioritizeResultItem
from harness.ollama_client import OllamaClient, OllamaError

log = logging.getLogger("harness.surface_prioritizer")

_SYSTEM_PROMPT = """
You are triaging a list of HTTP endpoints (method, URL, and parameter
names only -- no request/response bodies, no live testing) for a security
assessment. For EACH endpoint in the input list, assign:
- "ai_priority": one of "critical", "high", "medium", "low"
- "ai_score": 0.0-1.0, how much this endpoint deserves early attention
- "reasoning": one short sentence, specific to what about THIS endpoint's
  method/URL/parameters makes it notable (or unremarkable) -- not a
  generic restatement of its priority level.

Judge purely from structure: mutating methods (POST/PUT/DELETE/PATCH),
parameter names that suggest identifiers/IDs (likely IDOR candidates),
auth/admin/config-shaped paths, search/filter/sort parameters (injection
candidates), file/upload/path-shaped parameters. You have NOT seen the
actual request or response bodies -- do not claim to know whether
something IS vulnerable, only how worth investigating it looks.

Respond with ONLY a JSON object of this exact shape, no prose outside it:
{"results": [
  {"index": 0, "ai_priority": "high", "ai_score": 0.8, "reasoning": "..."}
]}
"index" must match the 0-based position of that endpoint in the input
list below. Include exactly one result per input endpoint, no more, no
fewer.
"""


def _placeholder(item: PrioritizeRequestItem, reason: str) -> PrioritizeResultItem:
    return PrioritizeResultItem(
        method=item.method, url=item.url, ai_priority="unscored", ai_score=0.0, reasoning=reason,
    )


async def prioritize(
    items: list[PrioritizeRequestItem],
    ollama: OllamaClient,
    model: str,
    temperature: float = 0.1,
) -> list[PrioritizeResultItem]:
    """Batches `items` into ONE LLM call and returns a same-length list of
    results in the SAME order as `items`, matched by the model's own
    "index" field. Any index the model's response omits, duplicates, or
    gets wrong is left at a safe "unscored" placeholder -- a malformed or
    partial LLM response degrades individual rows to "no opinion," never
    a crash or a silently misaligned ranking.
    """
    if not items:
        return []

    lines = [
        f"{i}. {it.method} {it.url}" + (f" params={it.param_names}" if it.param_names else "")
        for i, it in enumerate(items)
    ]
    user_prompt = "Endpoints:\n" + "\n".join(lines)

    results = [_placeholder(it, "model did not return a result for this endpoint") for it in items]

    try:
        parsed = await ollama.chat_json(
            model=model, system_prompt=_SYSTEM_PROMPT, user_prompt=user_prompt, temperature=temperature,
        )
    except OllamaError as e:
        log.warning("surface prioritization call failed: %s", e)
        return [_placeholder(it, f"prioritization call failed: {e}") for it in items]

    raw_results = parsed.get("results", []) if isinstance(parsed, dict) else []
    for r in raw_results:
        if not isinstance(r, dict):
            continue
        idx = r.get("index")
        if not isinstance(idx, int) or not (0 <= idx < len(items)):
            continue
        item = items[idx]
        try:
            score = max(0.0, min(1.0, float(r.get("ai_score", 0.0))))
            results[idx] = PrioritizeResultItem(
                method=item.method, url=item.url,
                ai_priority=str(r.get("ai_priority", "unscored")),
                ai_score=score,
                reasoning=str(r.get("reasoning", ""))[:500],
            )
        except (TypeError, ValueError) as e:
            log.debug("surface prioritization: malformed result at index %d: %s", idx, e)

    return results
