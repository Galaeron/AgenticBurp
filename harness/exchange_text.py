"""
Single source of truth for turning an HttpExchange into a flat text blob.

This used to exist as two separate, hand-copied implementations --
`orchestrator.py`'s module-level `_exchange_text()` and
`analysis_pipeline.py`'s `AnalysisPipeline._exchange_text()` method. They
were meant to be identical but had silently diverged: orchestrator.py's
copy included `exchange.analyst_note` in the text used for
known-vulnerability component verification; analysis_pipeline.py's copy
did not. That means whether an analyst's own note (e.g. "this looks like
log4j 2.14 based on the stack trace") counted as evidence a component was
actually observed in the exchange depended on which code path handled a
given request -- not on anything either file's author intended, and not
visible from reading either copy alone.

Found during a from-scratch audit, not from a bug report -- exactly the
kind of thing `HANDOVER.md` warns this project has shipped before
(`categories.py`'s free-text-vs-exact-match bug, the `profileImage` SSRF
param-name miss). Collapsed into one function so a future edit to what
counts as "exchange text" can't silently diverge again.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness.models import HttpExchange


def exchange_text(exchange: "HttpExchange") -> str:
    """
    Flat, lowercased-by-caller text representation of everything in an
    exchange that a component name/version might plausibly appear in:
    URL, method, both bodies, the analyst's own note, and every request/
    response header (name and value). Used for verifying an LLM-claimed
    component is actually observed in the raw exchange, not to feed an
    LLM prompt -- callers that need redaction for a prompt should use
    `security.redact_headers()` on the exchange's headers separately;
    this function does not redact anything, by design, since local
    string-containment checks against raw values is exactly what this
    function's only two call sites need it for.
    """
    parts = [
        exchange.url,
        exchange.method,
        exchange.request_body,
        exchange.response_body,
        exchange.analyst_note,
    ]
    parts.extend(f"{k}: {v}" for k, v in exchange.request_headers.items())
    parts.extend(f"{k}: {v}" for k, v in exchange.response_headers.items())
    return "\n".join(parts)
