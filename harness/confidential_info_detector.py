"""
Confidential-information response detector -- A4.

A deterministic, stateless pass over a single response looking for things that
should never be in it: live secrets (cloud keys, private keys, tokens), internal
infrastructure leakage (private IPs, internal hostnames, absolute filesystem or
cloud-storage paths), and regulated PII (credit-card / national-ID shapes). It
complements, not duplicates, the two things already here:

  - anomaly_detector.py is a STATEFUL behavioral profiler (needs a baseline of
    ~10 exchanges, reasons about deviations). This is stateless and per-response.
  - the info_disclosure agent is an LLM. This is regex -- fast, free, and exact,
    so a real AWS key or a `-----BEGIN PRIVATE KEY-----` block is caught with
    certainty and a citable match, not a probabilistic judgment.

Two rules the whole module is built around:

  1. NEVER echo a secret back. Every match is REDACTED before it appears in a
     finding's evidence -- you get the pattern name and a masked sample (a few
     leading/trailing chars), never the live value. The detector's own output
     must not become a second copy of the leak.
  2. Prefer precision. The patterns are high-signal shapes (structured key
     prefixes, key blocks, Luhn-valid card numbers), not broad guesses, because
     a confidential-info finding that cries wolf is worse than useless. Lower-
     signal categories (emails, private IPs) are still reported but at low
     severity, clearly separated from the high-severity secret matches.

Runs on the RESPONSE (body + headers): this is about what the application
GAVE BACK, not what the tester sent.
"""
from __future__ import annotations
import re
from dataclasses import dataclass

from harness.models import Finding, HttpExchange


@dataclass(frozen=True)
class _Pattern:
    name: str
    category: str        # secret | private_key | pii | internal_host | internal_path
    severity: str        # info | low | medium | high | critical
    rx: re.Pattern
    luhn: bool = False   # validate the match with the Luhn checksum (card numbers)


def _p(name, category, severity, pattern, flags=0, luhn=False) -> _Pattern:
    return _Pattern(name, category, severity, re.compile(pattern, flags), luhn)


# High-signal secret shapes. Ordered roughly most- to least-severe; the scan
# reports every distinct match, not just the first.
_PATTERNS: tuple[_Pattern, ...] = (
    _p("Private key block", "private_key", "critical",
       r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    _p("AWS access key id", "secret", "high", r"\bAKIA[0-9A-Z]{16}\b"),
    _p("AWS secret access key", "secret", "high",
       r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    _p("Google API key", "secret", "high", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _p("Slack token", "secret", "high", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    _p("GitHub token", "secret", "high", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    _p("Stripe live key", "secret", "high", r"\b[sr]k_live_[0-9A-Za-z]{16,}\b"),
    _p("Google OAuth client secret", "secret", "high", r"\bGOCSPX-[0-9A-Za-z_\-]{20,}\b"),
    _p("JWT", "secret", "medium", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    _p("Credential in connection string", "secret", "high",
       r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^:\s/]+:[^@\s/]+@"),
    _p("Basic-auth credentials in URL", "secret", "high",
       r"(?i)\bhttps?://[^:\s/]+:[^@\s/]+@"),
    _p("Password field in body", "secret", "medium",
       r"(?i)[\"']?passw(?:or)?d[\"']?\s*[:=]\s*[\"'][^\"'\s]{3,}[\"']"),
    # PII
    _p("Credit-card number", "pii", "high", r"\b(?:\d[ -]?){13,19}\b", luhn=True),
    _p("US SSN", "pii", "high", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    # Internal infrastructure leakage
    _p("Private IP address", "internal_host", "low",
       r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
    _p("Internal hostname", "internal_host", "low",
       r"\b[a-z0-9][a-z0-9\-]*\.(?:internal|local|corp|intranet|lan)\b", re.IGNORECASE),
    _p("Cloud storage path", "internal_path", "medium",
       r"\b(?:s3://[a-z0-9.\-]+|gs://[a-z0-9.\-]+|https?://[a-z0-9.\-]*\.blob\.core\.windows\.net)\S*"),
    _p("Absolute filesystem path", "internal_path", "low",
       r"(?:/(?:var|etc|home|root|opt|usr)/[\w./\-]+|[A-Za-z]:\\\\?(?:Users|Windows|inetpub)\\[\w.\\\-]+)"),
)

_MAX_MATCHES_PER_PATTERN = 5
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _luhn_ok(digits: str) -> bool:
    ds = [int(c) for c in re.sub(r"\D", "", digits)]
    if not (13 <= len(ds) <= 19):
        return False
    total, alt = 0, False
    for d in reversed(ds):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _redact(value: str) -> str:
    """Mask the middle of a matched value: keep a few chars at each end so the
    finding is recognizable/greppable without reproducing the secret."""
    v = value.strip()
    if len(v) <= 8:
        return v[0] + "*" * (len(v) - 1) if v else ""
    return f"{v[:4]}…{v[-4:]} ({len(v)} chars)"


@dataclass
class ConfidentialMatch:
    pattern: str
    category: str
    severity: str
    location: str        # "response_body" | "header:<name>"
    redacted: str

    def to_dict(self) -> dict:
        return {"pattern": self.pattern, "category": self.category, "severity": self.severity,
                "location": self.location, "redacted": self.redacted}


def _scan_text(text: str, location: str) -> list[ConfidentialMatch]:
    matches: list[ConfidentialMatch] = []
    if not text:
        return matches
    for pat in _PATTERNS:
        found = 0
        for m in pat.rx.finditer(text):
            raw = m.group(0)
            if pat.luhn and not _luhn_ok(raw):
                continue
            matches.append(ConfidentialMatch(pat.name, pat.category, pat.severity,
                                             location, _redact(raw)))
            found += 1
            if found >= _MAX_MATCHES_PER_PATTERN:
                break
    return matches


def scan_response(exchange: HttpExchange) -> list[ConfidentialMatch]:
    """Every confidential-info match in the exchange's RESPONSE (body + header
    values), deduplicated by (pattern, redacted sample, location)."""
    out: list[ConfidentialMatch] = []
    out.extend(_scan_text(exchange.response_body or "", "response_body"))
    for name, value in (exchange.response_headers or {}).items():
        # Skip the header whose whole job is to carry a token to the client on
        # request; a Set-Cookie value isn't a server-side leak the way a key in
        # a JSON body is. Still scan other headers (e.g. a debug header echoing
        # an internal path).
        if name.lower() in ("set-cookie", "authorization"):
            continue
        out.extend(_scan_text(value or "", f"header:{name}"))

    seen: set[tuple] = set()
    deduped: list[ConfidentialMatch] = []
    for m in out:
        key = (m.pattern, m.redacted, m.location)
        if key not in seen:
            seen.add(key)
            deduped.append(m)
    return deduped


def findings_from_exchange(exchange: HttpExchange) -> list[Finding]:
    """Group the matches into Findings -- one per category, at that category's
    highest matched severity, with REDACTED evidence. Empty when nothing
    matched."""
    matches = scan_response(exchange)
    if not matches:
        return []
    by_cat: dict[str, list[ConfidentialMatch]] = {}
    for m in matches:
        by_cat.setdefault(m.category, []).append(m)

    findings: list[Finding] = []
    for category, ms in by_cat.items():
        severity = max((m.severity for m in ms), key=lambda s: _SEV_RANK[s])
        patterns = sorted({m.pattern for m in ms})
        samples = "; ".join(f"{m.pattern}[{m.location}]={m.redacted}" for m in ms[:6])
        findings.append(Finding(
            vulnerability_class="info_disclosure",
            confidence=0.9,
            summary=f"Confidential information in response ({category}): {', '.join(patterns)}",
            evidence=f"Deterministic response scan matched {len(ms)} item(s) (values redacted): {samples}",
            suggested_test="Confirm the value is real (not example/placeholder data) and remove it from "
                           "the response; rotate any exposed credential.",
            basis="derived",
            severity=severity,
            owasp_category="A01:2021-Broken Access Control" if category in ("internal_path", "internal_host")
                           else "A02:2021-Cryptographic Failures" if category in ("secret", "private_key")
                           else "A04:2021-Insecure Design",
            confirmed=False,
            validation_hints=[f"confidential_info:{category}"],
        ))
    return findings
