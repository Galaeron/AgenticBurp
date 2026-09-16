"""
Deterministic precision gate for access-control findings.

Motivation (found live via the blind-target-2 eval, a target with no public
write-up): the idor / auth / api_security agents flag broken access control
from the *shape* of a request (a cross-user id, a foreign resource) without
weighting the *response outcome*. On that target they flagged IDOR at
confidence 0.90 on a request the server answered with 403 (control enforced)
and function-level-authz at 0.80 on a 405 (method blocked) -- both HIGHER than
their 0.85 on the one genuine IDOR, which returned 200 with another user's
data. An analyst sorting by confidence could not tell the real finding from
the false ones.

The discriminator the agents miss is deterministic and lives in the exchange
itself: an access-control bug is only demonstrated when the unauthorized
request actually SUCCEEDS. A 401/403/405 on that same request is direct
evidence the control WORKED on this exchange. This gate encodes exactly that
one rule -- it does not try to judge whether a 200 is a real IDOR (that stays
the agent's/validator's job), it only caps the confidence of an
access-control claim that the response itself contradicts.

Deterministic, no LLM, no network. Runs after the agents and before the
critique pass, so the LLM critique never spends budget re-litigating a finding
the status code already refutes, and the capped confidence is what everything
downstream (reporting gate, chaining, persistence) sees.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness.models import HttpExchange, AgentReport

# Response statuses that constitute a denial -- direct evidence the access
# control under test actually blocked this request. 404 is deliberately
# EXCLUDED: it is ambiguous (a missing resource, or an object-level control
# that hides existence) and does not by itself prove a control fired.
_DENIAL_STATUSES = frozenset({401, 403, 405})

# Vulnerability-class markers for the access-control family this gate governs.
# Matched case-insensitively as substrings, since agents emit both snake_case
# machine classes ("insecure_direct_object_reference") and prose ones
# ("Insecure Direct Object Reference", "function-level authorization at the
# api layer").
_ACCESS_CONTROL_MARKERS = (
    "idor",
    "insecure_direct_object",
    "insecure direct object",
    "object-level",
    "object level authorization",
    "function-level authorization",
    "function level authorization",
    "broken_access_control",
    "broken access control",
    "bola",
    "bfla",
    "missing authorization",
    "missing_authorization",
    "privilege escalation",
    "privilege_escalation",
    "unauthorized access",
    "broken_authentication",
    "broken authentication",
)

# Confidence a denial-contradicted access-control finding is capped to. Low
# enough to fall below the default reporting/critique gate (0.5) and the
# chaining thresholds, but non-zero: the observation ("agent suspected
# access-control on a request that was denied") is retained for audit rather
# than deleted, so a reviewer can still see what the agent reasoned.
_CAPPED_CONFIDENCE = 0.15


def _is_access_control_class(vuln_class: str) -> bool:
    lowered = (vuln_class or "").lower()
    return any(marker in lowered for marker in _ACCESS_CONTROL_MARKERS)


def apply_access_control_response_gate(
    exchange: "HttpExchange", reports: list["AgentReport"]
) -> int:
    """Cap the confidence of access-control findings the response contradicts.

    For every finding in `reports` whose class is in the access-control family,
    if the exchange's response status is a denial (401/403/405) and the
    finding's confidence currently exceeds the cap, lower it to
    `_CAPPED_CONFIDENCE` and annotate it (original_confidence / review_verdict
    "downgraded" / review_note) exactly the way the critique pass annotates,
    so the provenance of the change is visible downstream.

    Returns the number of findings adjusted. Mutates findings in place.
    """
    status = exchange.response_status
    if status not in _DENIAL_STATUSES:
        return 0

    adjusted = 0
    for report in reports:
        for finding in report.findings:
            if not _is_access_control_class(finding.vulnerability_class):
                continue
            if finding.confidence <= _CAPPED_CONFIDENCE:
                continue
            finding.original_confidence = finding.confidence
            finding.confidence = _CAPPED_CONFIDENCE
            # Cap severity too, not just confidence. A denial-contradicted
            # access-control claim is not a medium+ issue on this exchange, and
            # leaving severity high let it survive severity-based operating-point
            # views even after the confidence cap (found via the blind-target-2
            # re-score: 8 such FPs sat at confidence 0.15 but severity medium+).
            if finding.severity not in ("info", "low"):
                finding.severity = "low"
            finding.review_verdict = "downgraded"
            finding.review_note = (
                f"Access-control claim capped by deterministic response gate: the "
                f"request was denied with HTTP {status}, so the control was enforced "
                f"on this exchange. A real broken-access-control finding requires the "
                f"unauthorized request to succeed (typically 2xx returning another "
                f"identity's data), not to be blocked."
            )
            adjusted += 1
    return adjusted
