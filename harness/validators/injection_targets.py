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


# control_outcome markers for a not_confirmed that is NOT a controlled negative for
# the finding's own case. The confirmation gate only counts "" / "control_held" as
# refuting, so either marker lands the finding as inconclusive, never refuted.
NAMED_PARAMETER_UNTESTED = "named_parameter_untested"
PARTIAL_COVERAGE = "partial_coverage"

_LOCATION_ALIASES = {"query": QUERY, "url": QUERY, "body": BODY, "json": BODY, "form": BODY}
# Named locations these legs never inject into: a same-named query/body parameter
# is a different input, so it must not stand in for the one the finding names.
_UNREACHABLE_LOCATIONS = {"header", "cookie", "path"}


def select_targets(finding, candidates: list[tuple[str, str]], limit: int,
                   *, available: list[tuple[str, str]] | None = None
                   ) -> tuple[list[tuple[str, str]], str]:
    """Bound a leg's injection points without dropping the one the agent named.

    `candidates` is the leg's own ordered choice (e.g. file-shaped params first);
    `available` is every point the leg could inject into (defaults to candidates),
    so a named parameter outside the leg's shape heuristic is still tested.
    Returns (targets, coverage): coverage is "" when a negative over `targets` is a
    controlled negative for this finding's case, else a marker for control_outcome.
    """
    available = list(candidates if available is None else available)
    named = (getattr(finding, "parameter_name", "") or "").strip()
    if named:
        raw_loc = (getattr(finding, "parameter_location", "") or "").strip().lower()
        loc = _LOCATION_ALIASES.get(raw_loc)
        hit = None
        if raw_loc not in _UNREACHABLE_LOCATIONS:
            hit = next((t for t in available if t[1] == named and (loc is None or t[0] == loc)), None)
        if hit is None:
            return list(candidates[:limit]), NAMED_PARAMETER_UNTESTED
        rest = [t for t in candidates if t != hit]
        return [hit] + rest[:max(limit - 1, 0)], ""
    return list(candidates[:limit]), ("" if len(candidates) <= limit else PARTIAL_COVERAGE)


def coverage_note(coverage: str, finding) -> str:
    """One evidence sentence saying why a negative does not refute this finding."""
    if coverage == NAMED_PARAMETER_UNTESTED:
        return (f" The parameter the finding names ({finding.parameter_name!r}) is not an "
                f"injectable point this leg can reach, so this is not a negative for it.")
    if coverage == PARTIAL_COVERAGE:
        return " Not every parameter was tested, so this is not a negative for the endpoint."
    return ""


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
