"""
Security Headers Validator -- the WSTG-CONF-02 coverage adapter.

Passive: judges the response headers of the captured exchange it is handed and
sends nothing. The coverage drive hands it each replayable capture of an
endpoint, so the verdict is per endpoint, per identity, per observed response.

The anomaly detector's header audit flags six headers missing on every
response, which is a lead, not a verdict: CSP and framing belong to
WSTG-CONF-05 (csp validator), HSTS to WSTG-CONF-07 and means nothing over plain
HTTP, and X-XSS-Protection is deprecated, so its absence is no weakness. This
adapter decides only the headers no other catalog check owns:

1. X-Content-Type-Options must be `nosniff` (the first value, as the Fetch
   standard reads it) on every 2xx response with content. Without it a browser
   may MIME-sniff the body into an active type.
2. Referrer-Policy, when sent, must not resolve to `unsafe-url` (the last
   recognised token wins), which sends the full URL, path and query, to every
   origin, including over plain HTTP. An absent policy is the browser default
   (strict-origin-when-cross-origin), not a finding.

A response the headers cannot speak for is skipped, never a negative: no
captured response, a non-2xx status (redirects and error pages often come from
another layer), or no content to sniff (204, 205, 304, HEAD).

It routes no agent finding (empty finding_classes): a free-text "missing
security header" claim may be about CSP or HSTS, which this oracle cannot decide.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Validator, ValidationResult, header_fingerprint

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

# Referrer-Policy tokens a browser recognises (W3C Referrer Policy, section 3).
_REFERRER_TOKENS = frozenset({
    "no-referrer", "no-referrer-when-downgrade", "same-origin", "origin",
    "strict-origin", "origin-when-cross-origin", "strict-origin-when-cross-origin",
    "unsafe-url",
})
# Statuses whose response carries no content to sniff.
_NO_CONTENT = frozenset({204, 205, 304})


def _header(headers: dict, name: str) -> str | None:
    """A response header's value by case-insensitive name; None when absent."""
    for key, value in (headers or {}).items():
        if str(key).lower() == name:
            return "" if value is None else str(value)
    return None


def _referrer_policy(value: str) -> str:
    """The policy a browser applies: the last recognised token, else ""."""
    tokens = [t.strip().lower() for t in value.split(",")]
    return next((t for t in reversed(tokens) if t in _REFERRER_TOKENS), "")


def audit_security_headers(exchange: "HttpExchange") -> dict:
    """Decide WSTG-CONF-02 on one captured response.

    Returns {"verdict": "fail" | "pass" | "skip", "reason": str, "failures":
    [str], "fingerprint": str}. "fail" names each header that fails; "pass"
    means every owned header was judged and held; "skip" says why the response
    cannot decide."""
    status = getattr(exchange, "response_status", None)
    headers = getattr(exchange, "response_headers", None) or {}
    nosniff = _header(headers, "x-content-type-options")
    referrer = _header(headers, "referrer-policy")
    fingerprint = header_fingerprint(nosniff, referrer)
    def skip(reason):
        return {"verdict": "skip", "reason": reason, "failures": [], "fingerprint": ""}
    if not isinstance(status, int):
        return skip("no captured response for this request")
    if not 200 <= status < 300:
        return skip(f"captured response is {status}; headers are judged on a 2xx response")
    if status in _NO_CONTENT or (getattr(exchange, "method", "") or "").upper() == "HEAD":
        return skip(f"{status} response to {(exchange.method or 'GET').upper()} carries no content to sniff")
    failures = []
    if nosniff is None:
        failures.append("X-Content-Type-Options is missing")
    elif nosniff.split(",")[0].strip().lower() != "nosniff":
        failures.append(f"X-Content-Type-Options is {nosniff.strip()[:60]!r}, not 'nosniff'")
    policy = _referrer_policy(referrer) if referrer is not None else ""
    if policy == "unsafe-url":
        failures.append("Referrer-Policy resolves to 'unsafe-url' (full URL sent to every origin)")
    if failures:
        return {"verdict": "fail", "reason": "; ".join(failures), "failures": failures,
                "fingerprint": fingerprint}
    held = ("X-Content-Type-Options: nosniff; Referrer-Policy: "
            + (policy or ("browser default" if referrer is None else "no recognised token, browser default")))
    return {"verdict": "pass", "reason": held, "failures": [], "fingerprint": fingerprint}


class SecurityHeadersValidator(Validator):
    """Passive WSTG-CONF-02 oracle over a captured response's headers."""

    name = "security_headers_validator"
    finding_classes: set[str] = set()   # coverage dispatch only; see the module docstring
    active = False

    def get_name(self) -> str:
        return self.name

    def get_capability(self) -> str:
        return "security_header_policy"

    def get_execution_plane(self) -> str:
        return "local_analysis"

    async def validate(self, finding: "Finding", exchange: "HttpExchange") -> ValidationResult:
        audit = audit_security_headers(exchange)
        target = f"{(exchange.method or 'GET').upper()} {exchange.url}"
        if audit["verdict"] == "skip":
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary=f"WSTG-CONF-02 not judged: {audit['reason']}")
        if audit["verdict"] == "pass":
            return ValidationResult(self.name, "not_confirmed", finding.vulnerability_class,
                                    confidence=0.9,
                                    summary=f"WSTG-CONF-02 held on {exchange.response_status}: {audit['reason']}",
                                    header_fingerprint=audit["fingerprint"])
        return ValidationResult(self.name, "confirmed", finding.vulnerability_class,
                                confidence=0.95, confirmed=True, severity="low",
                                summary=f"WSTG-CONF-02 header policy fails on {target}: {audit['reason']}",
                                evidence=f"response {exchange.response_status}: {audit['reason']}",
                                header_fingerprint=audit["fingerprint"])
