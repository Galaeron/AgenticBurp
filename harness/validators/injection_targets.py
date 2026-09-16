"""
Shared injection-point enumeration for the parameter-mutating confirmation legs
(command injection, SSTI, path traversal).

Each of these legs needs the same two primitives the SSRF leg spells out inline:
enumerate every settable parameter (query + JSON body + form body), and produce a
copy of the exchange with ONE of them replaced by a payload. Factored here so the
legs share one tested implementation instead of drifting copies -- the sqlmap
mutators (`_mutate_query_param` / `_mutate_json_param` / `_mutate_form_param`) are
the low-level primitives; this wraps them with enumeration and a body/URL rebuild.
"""
from __future__ import annotations

from harness.models import HttpExchange
from harness.validators.sqlmap import (
    _query_top_level_params, _json_top_level_params, _form_top_level_params,
    _mutate_query_param, _mutate_json_param, _mutate_form_param,
    _looks_like_json, _content_type_of,
)

QUERY = "query"
BODY = "body"


def param_targets(exchange: HttpExchange) -> list[tuple[str, str]]:
    """Every (location, param) worth injecting into -- query params first, then
    JSON/form body params. Order is stable so a leg that stops at the first
    confirmation is deterministic."""
    out: list[tuple[str, str]] = []
    for k in _query_top_level_params(exchange.url):
        out.append((QUERY, k))
    body = exchange.request_body or ""
    if body:
        if _looks_like_json(body, _content_type_of(exchange)):
            for k in _json_top_level_params(body):
                out.append((BODY, k))
        else:
            for k in _form_top_level_params(body):
                out.append((BODY, k))
    return out


def mutate(exchange: HttpExchange, loc: str, param: str, value: str) -> tuple[str, str]:
    """(url, body) with `param` at `loc` replaced by `value`; the other of the
    pair is returned unchanged. Falls back to the original on a mutator miss so a
    caller always gets a sendable pair."""
    url, body = exchange.url, (exchange.request_body or "")
    if loc == QUERY:
        url = _mutate_query_param(url, param, value) or url
    elif _looks_like_json(body, _content_type_of(exchange)):
        body = _mutate_json_param(body, param, value) or body
    else:
        body = _mutate_form_param(body, param, value) or body
    return url, body


def replay_headers(exchange: HttpExchange) -> dict[str, str]:
    """The captured request headers minus the two that must be recomputed for a
    replayed send (Host is set by the client from the URL; Content-Length by the
    body)."""
    return {k: v for k, v in (exchange.request_headers or {}).items()
            if k.lower() not in ("host", "content-length")}
