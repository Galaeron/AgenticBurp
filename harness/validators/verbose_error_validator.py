"""
Verbose Error / Stack Trace / Debug Info Validator

Passive validator: scans captured response bodies for stack traces, debug
information, internal path disclosure, and framework debug pages. No network
traffic -- pure pattern matching on the already-captured exchange.

Findings from this validator are informational (info-disclosure) but can
feed re-discovery: a stack trace often reveals internal file paths and
framework versions; a debug page may list routes or configuration.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

log = logging.getLogger("harness.validators.verbose_error")

# Patterns that indicate verbose error / stack trace exposure.
# Each tuple: (name, compiled regex, severity, requires body match).
_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("python_traceback",
     re.compile(r"Traceback \(most recent call last\)", re.I), "medium"),
    ("python_exception_line",
     re.compile(r"^\s*File \"[^\"]+\", line \d+, in \w+", re.M), "medium"),
    ("java_stacktrace",
     re.compile(r"(?:at |Caused by: )\S+\.\S+\([\w.]+:\d+\)"), "medium"),
    ("dotnet_stacktrace",
     re.compile(r"at \S+\.\S+\([^)]*\) in [A-Z]:\\[^\r\n]+:\s*line \d+"), "medium"),
    ("php_error",
     re.compile(r"(?:Fatal error|Parse error|Warning|Notice):\s.*?in /\S+\.php on line \d+"), "medium"),
    ("node_error",
     re.compile(r"at (Object\.|Module\.|Function\.)?\S+ \([^)]+\.js:\d+:\d+\)"), "medium"),
    ("flask_debug",
     re.compile(r"<div class=\"(?:debugger|traceback)\">|Werkzeug Debugger", re.I), "high"),
    ("django_debug",
     re.compile(r"(?:Django Version:|You're seeing this error because you have|"
                r"DEBUG\s*=\s*True)", re.I), "high"),
    ("rails_debug",
     re.compile(r"(?:ActionController::RoutingError|ActiveRecord::\w+Error|"
                r"ExceptionNotifier)"), "medium"),
    ("spring_whitelabel",
     re.compile(r"Whitelabel Error Page|There was an unexpected error"), "low"),
    ("sql_error_detail",
     re.compile(r"(?:ORA-\d{5}|PG::Error|MySQL.*?Error|"
                r"SQLSTATE\[\w+\]|sqlite3\.OperationalError)"), "medium"),
    ("internal_path_disclosure",
     re.compile(r"(?:/home/\w+/|/var/www/|/opt/\w+/|/srv/\w+/|"
                r"C:\\(?:Users|inetpub|Program Files)\\)", re.I), "low"),
    ("environment_variable_leak",
     re.compile(r"(?:SECRET_KEY|DATABASE_URL|AWS_SECRET|API_KEY|PRIVATE_KEY)\s*[:=]", re.I), "high"),
    ("debug_mode_indicator",
     re.compile(r"(?:FLASK_DEBUG|DEBUG\s*=\s*True|debug_mode.*?(?:true|on|1)|"
                r"\"debug\":\s*true)", re.I), "medium"),
]

# Headers that indicate debug/verbose-error mode.
_DEBUG_HEADERS = {
    "x-debug-token": "Symfony debug toolbar token",
    "x-debug-token-link": "Symfony debug profiler link",
    "x-powered-by": None,  # check value for version detail
}


class VerboseErrorValidator(Validator):
    """Passive validator: detects verbose errors, stack traces, and debug info
    in captured HTTP responses."""

    name = "verbose_error_validator"
    finding_classes = {
        "verbose_error", "stack_trace", "debug_info", "information_disclosure",
        "error_disclosure", "debug_mode",
    }
    active = False  # pure passive -- no network requests

    def get_name(self) -> str:
        return "verbose_error_validator"

    def get_capability(self) -> str:
        return "verbose_error_detection"

    def get_execution_plane(self) -> str:
        return "local_analysis"

    def plan(self, finding: "Finding", exchange: "HttpExchange") -> Any:
        from harness.models import TestPlan
        from harness.categories import canonicalize
        import hashlib
        import json

        exchange_hash = hashlib.sha256(
            json.dumps(exchange.model_dump(), sort_keys=True).encode()
        ).hexdigest()[:16]
        plan_id = f"verbose_error_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale="Verbose error / stack trace / debug info detection",
            success_signals=["Confirm verbose error or debug information exposure"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: "Finding", exchange: "HttpExchange") -> ValidationResult:
        matches = scan_exchange(exchange)
        if not matches:
            return ValidationResult(
                validator=self.get_name(),
                status="not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.1,
                confirmed=False,
                summary="No verbose error patterns detected in response",
                evidence="",
                raw_output="",
            )

        worst_severity = "low"
        for _, sev, _ in matches:
            if sev == "high":
                worst_severity = "high"
            elif sev == "medium" and worst_severity != "high":
                worst_severity = "medium"

        evidence_parts = [f"{name}: {snippet[:200]}" for name, _, snippet in matches]
        return ValidationResult(
            validator=self.get_name(),
            status="confirmed",
            finding_class=finding.vulnerability_class,
            confidence=0.95,
            confirmed=True,
            summary=f"Verbose error/debug info confirmed: {len(matches)} pattern(s) matched",
            evidence=" | ".join(evidence_parts),
            raw_output="\n".join(evidence_parts),
        )


def scan_exchange(exchange: "HttpExchange") -> list[tuple[str, str, str]]:
    """Scan an exchange for verbose-error patterns. Returns [(name, severity, snippet)]."""
    body = getattr(exchange, "response_body", "") or ""
    headers = getattr(exchange, "response_headers", {}) or {}
    status = getattr(exchange, "response_status", None)
    matches: list[tuple[str, str, str]] = []

    # Only scan error-like responses and responses that are large enough to contain
    # a stack trace (but also 200s that leak debug info).
    if not body:
        return matches

    for name, pattern, severity in _PATTERNS:
        m = pattern.search(body)
        if m:
            start = max(0, m.start() - 50)
            end = min(len(body), m.end() + 100)
            snippet = body[start:end].strip()
            matches.append((name, severity, snippet))

    # Header-based debug detection
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for hdr, desc in _DEBUG_HEADERS.items():
        val = headers_lower.get(hdr, "")
        if val:
            if hdr == "x-powered-by" and not any(c.isdigit() for c in val):
                continue
            detail = desc or f"version info: {val}"
            matches.append((f"header_{hdr}", "low", f"{hdr}: {val} ({detail})"))

    return matches


def findings_from_exchange(exchange: "HttpExchange") -> list:
    """Produce Finding objects for any verbose-error patterns in the exchange.
    Called from the orchestrator's deterministic-detector pass."""
    from harness.models import Finding

    matches = scan_exchange(exchange)
    if not matches:
        return []

    worst_severity = "low"
    for _, sev, _ in matches:
        if sev == "high":
            worst_severity = "high"
        elif sev == "medium" and worst_severity != "high":
            worst_severity = "medium"

    evidence_parts = [f"{name}: {snippet[:150]}" for name, _, snippet in matches]
    return [Finding(
        vulnerability_class="verbose_error_disclosure",
        severity=worst_severity,
        confidence=0.9,
        summary=f"Verbose error/debug info: {', '.join(name for name, _, _ in matches)}",
        evidence="; ".join(evidence_parts),
        suggested_test="Review the error response for leaked secrets, internal paths, or debug endpoints",
        basis="derived",
        confirmed=True,
        confirmation_method="verbose_error_validator",
    )]


def extract_disclosed_paths(exchange: "HttpExchange") -> list[str]:
    """Extract internal paths, routes, and endpoints mentioned in error
    responses. Useful for feeding back into discovery."""
    body = getattr(exchange, "response_body", "") or ""
    if not body:
        return []

    paths: list[str] = []
    # URL-like paths in stack traces / debug output
    for m in re.finditer(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/[a-zA-Z0-9_/\-{}.<>]+)', body):
        paths.append(m.group(1))
    # Route definitions
    for m in re.finditer(r'["\'](/(?:api|web|app|admin|v\d+)/[a-zA-Z0-9_/\-{}.<>]+)["\']', body):
        paths.append(m.group(1))
    # Flask/Django route patterns
    for m in re.finditer(r'@\w+\.route\(["\'](/[^"\']+)["\']', body):
        paths.append(m.group(1))
    # Deduplicate
    return sorted(set(paths))
