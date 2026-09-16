"""
Deterministic, non-LLM detection of credential-submission ("login-shaped")
endpoints.

Rule-based for the same reason chaining.py's chain-rule matcher is
rule-based, not LLM-based: this is a purely structural, auditable signal
(a specific field-name/path pattern was present), not something that
benefits from an LLM's judgment call, and relying on an LLM to notice it
reliably every time has already been shown, live against a real target,
to fail: a genuinely ordinary login attempt (real-looking credentials, no
injection syntax anywhere in the request) produced zero sqli-agent
findings, because that agent's prompt (see agents/sqli_agent.py) is
reactive -- it looks for injection markers already present in the
exchange -- with nothing that reasons "this is a canonical SQL injection
auth-bypass target regardless of what the captured credentials look
like." Since no finding means no TestPlan (planner.plans_for_findings
only ever sees agent output) and no TestPlan means the harness's own
active SQL injection validator (validators/sqlmap.py) never gets
dispatched at all, an ordinary login exchange was silently never
tested -- not "tested, found nothing," but never tried in the first
place.

This module's only job is to guarantee that never happens: it feeds a
low/moderate-confidence Finding into the SAME existing planner/validator
pipeline every other finding already goes through, exactly the way
chaining.detect() feeds its own rule-based findings into that pipeline as
a "chain_detector"-style synthetic AgentReport. It never claims a
vulnerability exists (basis="derived", confidence deliberately capped
well below what an agent-observed injection marker would earn) -- the
point is only to make sure the endpoint gets a real chance to be
actively confirmed or rejected, not to assert it already is one.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

from harness.models import Finding, HttpExchange

_PASSWORD_FIELD_RE = re.compile(r'["\']?(password|passwd|pwd)["\']?\s*[:=]', re.IGNORECASE)
_IDENTIFIER_FIELD_RE = re.compile(r'["\']?(email|username|user|login|identifier)["\']?\s*[:=]', re.IGNORECASE)
_AUTH_PATH_RE = re.compile(r'/(login|signin|sign-in|log-in|authenticate|auth)(?:[/?]|$)', re.IGNORECASE)


def detect_credential_submission(exchange: HttpExchange) -> Finding | None:
    """Return a moderate-confidence sqli Finding when this exchange looks
    like a credential-submission (login-shaped) request -- a password-
    shaped field is present in the body, together with either an
    identifier-shaped field (email/username) or a URL path matching a
    common auth pattern. Returns None otherwise, including for GET
    requests (credentials submitted via GET are a separate, already-
    covered concern -- info disclosure/logging, not this heuristic).
    """
    if exchange.method.upper() not in ("POST", "PUT", "PATCH"):
        return None

    body = exchange.request_body or ""
    if not _PASSWORD_FIELD_RE.search(body):
        return None

    has_identifier_field = bool(_IDENTIFIER_FIELD_RE.search(body))
    path = urlparse(exchange.url).path or ""
    looks_like_auth_path = bool(_AUTH_PATH_RE.search(path))

    if not (has_identifier_field or looks_like_auth_path):
        return None

    matched_on = []
    if has_identifier_field:
        matched_on.append("an identifier-shaped field (email/username)")
    if looks_like_auth_path:
        matched_on.append("a URL path matching a common auth pattern")

    return Finding(
        vulnerability_class="sqli",
        confidence=0.5,
        severity="medium",
        summary=(
            "Structurally a login/authentication endpoint (a password-shaped "
            "field plus " + " and ".join(matched_on) + "). Login endpoints are "
            "one of the most common SQL injection auth-bypass targets; this is "
            "flagged independent of whether the captured credentials themselves "
            "contain any injection syntax, specifically so the harness's own "
            "active SQL injection validator gets a chance to test it."
        ),
        evidence=f"{exchange.method.upper()} {path}: password-shaped field present, "
                  + ", ".join(matched_on),
        suggested_test=(
            "Try a standard boolean-based auth-bypass payload in the credential "
            "field (e.g. \"' OR '1'='1' -- \" in place of a normal email/username) "
            "and compare the response against this exchange's baseline: a "
            "response that looks like a successful authentication despite the "
            "payload not being a real credential confirms the injection."
        ),
        basis="derived",
    )
