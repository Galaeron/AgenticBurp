"""Response and tool-output classifiers for the sqlmap validator (proxy stop reasons, connection
blips, database error markers): moved verbatim out of sqlmap.py (ARC-9)."""

from __future__ import annotations

import httpx
import re

from .base import ValidationResult


# General-purpose parameter enumeration/mutation for the boolean-probe
# fallback below (see _boolean_probe_fallback's own docstring for why it
# exists at all). Deliberately NOT limited to credential fields: SQL
# injection is not an auth-only bug class -- an id/sort/filter/search
# parameter in the query string or body is at least as common a real-world
# injection point (see agents/sqli_agent.py's own prompt, which lists
# exactly this set of parameter shapes). Proper JSON/form/query-string
# parsing is used here rather than regex specifically so this generalizes
# to arbitrary field names correctly (a regex approach that hardcodes
# field names, as an earlier version of this module did for password/
# email specifically, cannot generalize to "whatever parameters this
# exchange happens to have").
# Why the run stopped the tool's proxied traffic (ToolProxy.stop_reason), for summaries.
_PROXY_STOP_WHY = {"budget_exhausted": "the run's request budget ran out",
                   "session_expired": "the identity's session expired during the scan",
                   "route_unavailable": "the route answered 5xx to every request and was paused",
                   "tool_cap": "the per-scan request cap was reached",
                   "mutating_ceiling": "the case's mutating-request ceiling was reached"}

# Stops whose cause may clear by itself, so a later retry can finish the scan.
_TRANSIENT_STOPS = frozenset({"session_expired", "route_unavailable"})


def _transient(proxy) -> bool:
    return getattr(proxy, "stop_reason", "") in _TRANSIENT_STOPS


# sqlmap's own "could not reach the target" verdicts. Only [CRITICAL] lines (and the
# OS's "network is unreachable") count: a single "[WARNING] connection timed out ...
# sqlmap is going to retry" during an otherwise answered scan is not a failure.
_CONNECTION_WORDS = (r"unable to connect|connection refused|connection reset|connection timed out|"
                     r"can't establish|cannot connect|failed to establish a new connection|"
                     r"host .* does not exist|name or service not known")
_CONNECTION_FAILURE_RE = re.compile(
    rf"network is unreachable|\[CRITICAL\][^\n]*(?:{_CONNECTION_WORDS})", re.I)
# One connection line per request. "... sqlmap is going to retry the request(s)" is a
# retry; the same line without it is a request sqlmap gave up on. Inside a test it
# then moves on to the next payload, so the scan still ends in a verdict.
_CONNECTION_LINE_RE = re.compile(rf"\[CRITICAL\][^\n]*(?:{_CONNECTION_WORDS})[^\n]*", re.I)
# sqlmap's negative conclusion on the parameters it tested: it reached the end of
# its tests, which a scan that never got an answer does not.
_PARAMETER_VERDICT_RE = re.compile(
    r"all tested parameters do not appear to be injectable|does not seem to be injectable", re.I)
# A scan that reached its verdict but gave up on more requests than this is not
# trusted as answered. In r9 the container's network dropped single requests
# ("Network is unreachable") in 16 scans that each lost at most one.
_MAX_LOST_REQUESTS = 2


def _connection_blips(output: str) -> tuple[int, int]:
    """(retried, lost): sqlmap's connection failures it retried, and the requests it
    gave up on after its retries."""
    retried = lost = 0
    for line in _CONNECTION_LINE_RE.findall(output or ""):
        if "going to retry" in line.lower():
            retried += 1
        else:
            lost += 1
    return retried, lost


def _answered_through_blips(output: str, proxy) -> bool:
    """sqlmap's connection failures were blips inside a scan the target answered:
    it reached its verdict on the parameters, lost at most _MAX_LOST_REQUESTS
    requests, and inside a run the proxy answered at least one of its requests."""
    if not _PARAMETER_VERDICT_RE.search(output or ""):
        return False
    if proxy is not None and proxy.forwarded - proxy.refused.get("error", 0) <= 0:
        return False
    return _connection_blips(output)[1] <= _MAX_LOST_REQUESTS


def _blip_note(output: str) -> str:
    """The limitation for an answered scan that had connection blips, or ""."""
    retried, lost = _connection_blips(output)
    if not (retried or lost):
        return ""
    return (f"sqlmap retried {retried} request(s) after a transport failure"
            + (f" and gave up on {lost}; a lost request may hide a finding" if lost else ""))


def _connection_failure(output: str, proxy) -> str:
    """Why sqlmap never got an answer from the target, or "". Either sqlmap said so,
    or inside a run every request it sent through the tool proxy failed at the
    transport (the proxy answers those 502, which sqlmap reads as a page, not as a
    connection failure). Connection lines inside a scan the target answered
    (_answered_through_blips) are not a failure: r9 marked 16 finished scans as
    "could not reach the target" this way, and the retry rounds ran them again."""
    found = _CONNECTION_FAILURE_RE.search(output or "")
    if found and not _answered_through_blips(output, proxy):
        return found.group(0).replace("[CRITICAL]", "").strip()[:160]
    if proxy is not None and proxy.forwarded and proxy.refused.get("error", 0) >= proxy.forwarded:
        return f"all {proxy.forwarded} request(s) sqlmap sent failed at the transport"
    return ""


def _with_light_note(result: ValidationResult, note: str) -> ValidationResult:
    """The light-coverage note leads the limitation (the proof reason) and the
    evidence, so the report says why coverage was light."""
    result.limitation = (note + ("; " + result.limitation if result.limitation else ""))[:1000]
    if result.confirmed:
        # sqlmap's injection points keep leading a confirmed result's evidence.
        result.evidence = (result.evidence + "\n" if result.evidence else "") + note
    else:
        result.evidence = note + ("\n" + result.evidence if result.evidence else "")
    return result


# Error-based signal, complementary to the boolean-blind differential
# above -- found necessary live, against a real target: Juice Shop's
# product search (`GET /rest/products/search?q=`) wraps the parameter in
# a LIKE '%...%' clause, where an unprefixed OR-based tautology/contradiction
# pair was not a true/false differential at all (the unconditional
# `LIKE '%'` half of the OR already matches everything, so both the
# "true" and "false" injected predicates return identical results -- a
# real, confirmed injection point that the boolean-blind check alone
# would have reported as not_confirmed). An unclosed quote or broken
# UNION reliably surfaces as a raw DB error message regardless of how the
# value is wrapped (exact match, LIKE, or otherwise), which is exactly
# why agents/sqli_agent.py's own prompt lists this as its first-choice
# signal. Markers are deliberately generic engine/error strings, not
# tied to one database.
_DB_ERROR_MARKERS = (
    "sql syntax", "sqlite_error", "sqlite3.", "you have an error in your sql syntax",
    "unclosed quotation mark", "ora-01756", "ora-00933", "pg::syntaxerror",
    "sqlstate", "odbc sql server driver", "npgsql", "sequelize",
)


def _text_has_db_error_markers(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _DB_ERROR_MARKERS)


def _looks_like_db_error(resp: httpx.Response) -> bool:
    try:
        text = resp.text
    except Exception:
        return False
    return _text_has_db_error_markers(text)


# A DB *parser* rejecting the statement, as opposed to the generic driver/ORM or
# type-conversion text in _DB_ERROR_MARKERS ("sequelize", "sqlstate", "npgsql",
# Postgres's "invalid input syntax for type integer"): a parameterized query that
# rejects a non-numeric value answers those too. Only these confirm an error-based
# point, so the breaking value must have reached SQL text.
_DB_SYNTAX_ERROR_MARKERS = (
    "syntax error", "sql syntax", "incorrect syntax near", "unclosed quotation mark",
    "unrecognized token", "unterminated quoted string", "unterminated string",
    "quoted string not properly terminated", "ora-01756", "ora-00933", "ora-00907",
    "pg::syntaxerror",
)


def _looks_like_db_syntax_error(resp: httpx.Response) -> bool:
    try:
        lowered = resp.text.lower()
    except Exception:
        return False
    return any(marker in lowered for marker in _DB_SYNTAX_ERROR_MARKERS)
