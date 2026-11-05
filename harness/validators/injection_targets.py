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

_LOCATION_ALIASES = {"query": QUERY, "url": QUERY, "body": BODY, "json": BODY, "form": BODY,
                     "body_json": BODY, "body_form": BODY}
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
        if getattr(finding, "parameter_only", False):
            # Per-parameter dispatch: test that point alone, so the verdict is
            # bound to it; a point the request lacks is not tested at all.
            return ([hit], "") if hit is not None else ([], NAMED_PARAMETER_UNTESTED)
        if hit is None:
            return list(candidates[:limit]), NAMED_PARAMETER_UNTESTED
        rest = [t for t in candidates if t != hit]
        return [hit] + rest[:max(limit - 1, 0)], ""
    return list(candidates[:limit]), ("" if len(candidates) <= limit else PARTIAL_COVERAGE)


def tested_inputs(finding, targets) -> tuple[tuple[str, str], ...]:
    """What a leg reports in ValidationResult.tested_parameters: under a
    per-parameter dispatch, the one input it was bound to once that input is its
    only target; otherwise nothing, so the case driver keeps the R01 rule."""
    if getattr(finding, "parameter_only", False) and len(targets) == 1:
        return (((finding.parameter_location or "").strip().lower(),
                 (finding.parameter_name or "").strip()),)
    return ()


# Coverage case driving: legs that can test ONE input per dispatch, by the case
# locations each can address on its own. sqlmap's `-p` naming of JSON body keys
# is unverified, so its JSON keys stay request-level.
PER_PARAMETER_LOCATIONS = {
    "ssti": frozenset({"query", "body_form", "body_json"}),
    "command_injection": frozenset({"query", "body_form", "body_json"}),
    "sqlmap": frozenset({"query", "body_form"}),
}
# At most this many parameter cases of one cell are dispatched one by one (the
# legs' own six-parameter cap); the rest stay inconclusive.
PER_PARAMETER_FIELD_CAP = 6


def case_target(confirmation: str, case_key) -> tuple[str, str] | None:
    """The (parameter_location, parameter_name) a per-parameter dispatch of
    `confirmation` names for a coverage `case_key`, or None when that leg cannot
    test the input on its own (header, path, nested JSON, a repeated name)."""
    loc = getattr(case_key, "parameter_location", "") or ""
    name = getattr(case_key, "parameter_name", "") or ""
    if (not name or getattr(case_key, "occurrence", 0)
            or loc not in PER_PARAMETER_LOCATIONS.get(confirmation, ())):
        return None
    if loc == "body_json":
        # A top-level key only: "/name" (RFC 6901 escapes undone).
        if not name.startswith("/") or "/" in name[1:]:
            return None
        name = name[1:].replace("~1", "/").replace("~0", "~")
    return loc, name


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
