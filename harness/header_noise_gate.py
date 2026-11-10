"""
Header/config noise gate -- deterministic precision control (critique rec #4).

A live run's raw data made the problem undeniable: of 73 "confirmed" findings on
Juice Shop, 56 were the CORS validator re-reading a wildcard
Access-Control-Allow-Origin header, and on a blind target every one of 6 secure
control endpoints still drew a medium+ finding. The header/config observer classes
(CORS, CSP, clickjacking, missing security headers, HSTS) will ALWAYS find
something to say about any HTTP response, so as per-exchange medium+ findings they
manufacture false positives by construction on exactly the endpoints that are
actually secure.

These are legitimately DETECTABLE and legitimately LOW-VALUE. So we keep the
observation but cap its severity to at most `low` -- below the sev>=medium
operating point the scorer and report key on -- turning a pile of per-exchange
"medium CORS" findings into one honest informational note per host (the report
layer already de-dupes per (endpoint-family, class)). This is the severity knob
score.py itself names as the biggest FP lever; it changes precision, not recall
(no true-positive class is touched), and it never deletes a finding, only demotes
its severity so it stops competing with real, exploitable results.

Deliberately NARROW: only the header/transport observer classes are matched.
`information_disclosure`, `security_misconfiguration`, and crypto findings are NOT
capped here -- they span genuinely high-value cases (leaked source/secrets, a real
broken misconfig) that a blanket demotion would wrongly bury.
"""
from __future__ import annotations

import logging

log = logging.getLogger("harness.header_noise_gate")

# Severity this gate caps a matched finding DOWN to (never up). `low` keeps the
# observation visible while dropping it below the sev>=medium operating point.
_CAP_SEVERITY = "low"
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Substrings (matched against the lowercased vulnerability_class) that identify a
# header/transport observer finding. Kept explicit and narrow; each is a class the
# model or a passive validator emits for a property visible on ANY response.
_HEADER_NOISE_MARKERS = (
    "cors", "cross-origin resource sharing",
    "csp", "content security policy", "content-security-policy",
    "clickjack", "x-frame", "frame options", "frame-options",
    "hsts", "strict-transport", "strict transport",
    "missing security header", "missing header", "security headers",
    "referrer-policy", "referrer policy",
    "permissions-policy", "permissions policy", "feature-policy",
    "x-content-type-options", "content-type-options", "nosniff",
)


def is_header_noise_class(vuln_class: str) -> bool:
    low = (vuln_class or "").lower()
    return any(marker in low for marker in _HEADER_NOISE_MARKERS)


def apply_header_noise_gate(exchange, reports) -> int:
    """Cap every header/config-observer finding to at most `low` severity, in
    place. Returns how many findings were demoted. Recall-safe by construction:
    the matched classes are informational, never a scored true-positive class."""
    cap = _SEV_RANK[_CAP_SEVERITY]
    n = 0
    for report in reports:
        for finding in getattr(report, "findings", []) or []:
            if not is_header_noise_class(getattr(finding, "vulnerability_class", "")):
                continue
            sev = (getattr(finding, "severity", "info") or "info").lower()
            if _SEV_RANK.get(sev, 0) > cap:
                # Record the pre-cap severity for audit, mirroring the
                # access-control gate's original_confidence bookkeeping.
                if finding.original_severity is None:
                    finding.original_severity = sev
                finding.severity = _CAP_SEVERITY
                n += 1
    if n:
        log.debug("Header-noise gate capped %d header/config finding(s) to %s", n, _CAP_SEVERITY)
    return n


# r7: a plain-HTTP target on a loopback or private address drew "Insecure
# Transmission of Credentials/Data", "Insecure Transport" and "Token Transmission
# over HTTP" findings on every route. On such a target the scheme is a fact of the
# test deployment (a local container, a lab VM), not of the application: it is a
# hardening item for production, not a vulnerability of this engagement. The same
# classes on a public host keep their severity and stay vulnerabilities.
ENVIRONMENT_VERDICT = "environment_observation"
_CLEARTEXT_MARKERS = (
    "insecure transport", "insecure_transport", "insecure transmission",
    "cleartext", "clear text", "plaintext transmission", "unencrypted transport",
    "unencrypted communication", "over http", "over plain http",
)


def is_cleartext_transport_class(vuln_class: str) -> bool:
    from harness.categories import canonicalize
    if canonicalize(vuln_class) == "insecure_transport":
        return True
    low = (vuln_class or "").lower().replace("_", " ")
    return any(marker.replace("_", " ") in low for marker in _CLEARTEXT_MARKERS)


def local_plain_http_host(url: str) -> str:
    """The host of a plain-HTTP URL on a loopback or private address (localhost,
    *.localhost, 127.0.0.0/8, ::1, RFC 1918 / ULA), else ""."""
    import ipaddress
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url or "")
        host = (parts.hostname or "").lower()
    except ValueError:
        return ""
    if parts.scheme.lower() != "http" or not host:
        return ""
    if host == "localhost" or host.endswith(".localhost"):
        return host
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return ""
    return host if (ip.is_loopback or ip.is_private) and not ip.is_unspecified else ""


def apply_local_cleartext_gate(exchange, reports) -> int:
    """Classify cleartext-transport findings on a plain-HTTP loopback/private
    target as environment (hardening) observations, in place: severity capped to
    `info` (pre-cap severity kept), review_verdict ENVIRONMENT_VERDICT and the
    reason in review_note. Never deletes a finding; a finding the critique
    rejected, or any finding on an HTTPS or public target, is left alone.
    Returns how many findings were classified."""
    host = local_plain_http_host(getattr(exchange, "url", "") or "")
    if not host:
        return 0
    note = (f"Environment observation (hardening), not a vulnerability: the target is "
            f"served over plain HTTP on the loopback/private address {host}, so cleartext "
            f"transport describes this test deployment, not the application. Serve the "
            f"production deployment over HTTPS.")
    n = 0
    for report in reports:
        for finding in getattr(report, "findings", []) or []:
            if not is_cleartext_transport_class(getattr(finding, "vulnerability_class", "")):
                continue
            if (finding.review_verdict or "") in ("rejected", ENVIRONMENT_VERDICT):
                continue
            sev = (finding.severity or "info").lower()
            if sev != "info":
                if finding.original_severity is None:
                    finding.original_severity = sev
                finding.severity = "info"
            finding.review_verdict = ENVIRONMENT_VERDICT
            finding.review_note = (finding.review_note + " " if finding.review_note else "") + note
            n += 1
    if n:
        log.debug("Local cleartext gate classified %d transport finding(s) as environment", n)
    return n
