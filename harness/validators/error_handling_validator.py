"""
Error Handling Validator -- the WSTG-ERRH-01 coverage adapter.

Passive: judges the captured error response it is handed and sends nothing. The
coverage drive hands it each replayable capture of an endpoint, so the verdict
is per endpoint, per identity, per observed response. It does not provoke
errors; an endpoint whose captures are all successful is skipped, not clean.

A capture is judged only when it is an error response (status >= 400) whose
body was kept and is a document (HTML, JSON, XML, plain text, or no media
type). It is confirmed when the body holds a stack trace or a framework error
page -- the signatures below name a runtime's own trace format or a framework's
default error page, never a word that ordinary page text uses. A judged error
response without one is not_confirmed. Anything else is skipped, never a
negative: no captured response, a non-error status (a 2xx page may quote a trace
as content), a body that was not kept (an access-matrix probe keeps only its
digest), or a static asset (a script bundle may carry the strings as code).

verbose_error_validator keeps its wider lead set (internal paths, environment
variable names, debug flags) for agent findings; those are leads, so this
adapter does not decide on them. It routes no agent finding (empty
finding_classes).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

_QUOTE = r"(?:\"|&quot;|&#34;|&#x22;)"
# (name, pattern, severity). A body may be HTML-escaped, so quotes match either way.
_SIGNATURES: tuple[tuple[str, re.Pattern, str], ...] = (
    ("python_traceback", re.compile(r"Traceback \(most recent call last\)"), "medium"),
    ("python_frame", re.compile(rf"\bFile {_QUOTE}[^\"&\r\n]+{_QUOTE}, line \d+, in \S+"), "medium"),
    ("java_stacktrace", re.compile(
        r"\bat [\w$]+(?:\.[\w$<>]+)+\([\w$]+\.(?:java|kt|scala|groovy):\d+\)"), "medium"),
    ("dotnet_stacktrace", re.compile(r"\bat [\w.`<>\[\],]+\([^)\r\n]*\) in [^\r\n]+?:line \d+"), "medium"),
    ("node_stacktrace", re.compile(
        r"\bat (?:[^\r\n()]{1,200}? \()?(?:node:[\w/]+|(?:file:///?)?(?:/|[A-Za-z]:[\\/])"
        r"[^\s()]*?\.(?:js|mjs|cjs|ts)):\d+:\d+"), "medium"),
    ("php_error", re.compile(
        r"(?:Fatal error|Parse error|Warning|Notice|Deprecated)(?:</b>)?:\s.{0,400}? in (?:<b>)?"
        r"\S+\.php(?:</b>)? on line (?:<b>)?\d+"), "medium"),
    ("werkzeug_debugger", re.compile(r"Werkzeug Debugger|<div class=\"debugger\">"), "high"),
    ("django_debug", re.compile(r"You(?:'|&#39;|&#x27;)re seeing this error because you have"), "high"),
    ("rails_debug", re.compile(r"Action Controller: Exception caught"), "medium"),
    ("aspnet_error_page", re.compile(r"Server Error in '[^'\r\n]*' Application"), "medium"),
    ("spring_whitelabel", re.compile(r"Whitelabel Error Page"), "low"),
    ("sql_error", re.compile(
        r"SQLSTATE\[\w+\]|\bORA-\d{5}:|\bPG::\w*Error|sqlite3\.OperationalError|SQLITE_ERROR:"
        r"|You have an error in your SQL syntax|Unclosed quotation mark after the character string"
        r"|org\.postgresql\.util\.PSQLException|SequelizeDatabaseError|ActiveRecord::StatementInvalid"),
     "medium"),
)
_RANK = {"low": 0, "medium": 1, "high": 2}
# Media types whose body is a document this oracle reads.
_DOCUMENT_TYPES = ("html", "json", "xml", "text/plain")


def _header(headers: dict, name: str) -> str | None:
    """A response header's value by case-insensitive name; None when absent."""
    for key, value in (headers or {}).items():
        if str(key).lower() == name:
            return "" if value is None else str(value)
    return None


def _snippet(body: str, match: re.Match) -> str:
    start = max(0, match.start() - 40)
    return " ".join(body[start:match.end() + 80].split())[:200]


def audit_error_response(exchange: "HttpExchange") -> dict:
    """Decide WSTG-ERRH-01 on one captured response.

    Returns {"verdict": "fail" | "pass" | "skip", "reason": str, "matches":
    [(name, severity, snippet)], "severity": str}. "fail" names each signature
    found; "pass" means a judged error response held none; "skip" says why the
    response cannot decide."""
    status = getattr(exchange, "response_status", None)
    headers = getattr(exchange, "response_headers", None) or {}
    body = getattr(exchange, "response_body", "") or ""
    def skip(reason):
        return {"verdict": "skip", "reason": reason, "matches": [], "severity": ""}
    if not isinstance(status, int):
        return skip("no captured response for this request")
    if status < 400:
        return skip(f"captured response is {status}; no error response was captured")
    if (getattr(exchange, "method", "") or "").upper() == "HEAD":
        return skip("a HEAD response carries no body")
    media = (_header(headers, "content-type") or "").split(";")[0].strip().lower()
    if media and not any(kind in media for kind in _DOCUMENT_TYPES):
        return skip(f"{media} is not a document this oracle reads")
    if not body:
        length = (_header(headers, "content-length") or "").strip()
        if length != "0":
            return skip("the response body was not kept with this capture")
    matches = []
    for name, pattern, severity in _SIGNATURES:
        found = pattern.search(body)
        if found:
            matches.append((name, severity, _snippet(body, found)))
    if not matches:
        return {"verdict": "pass", "severity": "", "matches": [],
                "reason": f"error response {status} discloses no stack trace or framework error page"}
    worst = max((m[1] for m in matches), key=_RANK.__getitem__)
    return {"verdict": "fail", "severity": worst, "matches": matches,
            "reason": f"error response {status} discloses " + ", ".join(m[0] for m in matches)}


class ErrorHandlingValidator(Validator):
    """Passive WSTG-ERRH-01 oracle over a captured error response."""

    name = "error_handling_validator"
    finding_classes: set[str] = set()   # coverage dispatch only; see the module docstring
    active = False

    def get_name(self) -> str:
        return self.name

    def get_capability(self) -> str:
        return "error_disclosure"

    def get_execution_plane(self) -> str:
        return "local_analysis"

    async def validate(self, finding: "Finding", exchange: "HttpExchange") -> ValidationResult:
        audit = audit_error_response(exchange)
        target = f"{(exchange.method or 'GET').upper()} {exchange.url}"
        if audit["verdict"] == "skip":
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary=f"WSTG-ERRH-01 not judged: {audit['reason']}")
        if audit["verdict"] == "pass":
            return ValidationResult(self.name, "not_confirmed", finding.vulnerability_class,
                                    confidence=0.9, summary=f"WSTG-ERRH-01 held: {audit['reason']}")
        return ValidationResult(self.name, "confirmed", finding.vulnerability_class,
                                confidence=0.95, confirmed=True, severity=audit["severity"],
                                summary=f"WSTG-ERRH-01 fails on {target}: {audit['reason']}",
                                evidence="; ".join(f"{name}: {snippet}" for name, _, snippet in audit["matches"]))
