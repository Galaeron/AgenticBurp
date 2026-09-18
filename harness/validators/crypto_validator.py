"""
Cryptography / Transport Security Validator

Unlike most validators in this harness, this one CAN do something the
agent explicitly said it couldn't: open a real TLS connection and
inspect the negotiated protocol version, cipher suite, and certificate
validity. That's a genuinely independent check (a different route
entirely -- a raw socket-level TLS handshake, not another HTTP
request) rather than a rephrasing of what the agent already saw.

Checks performed:
1. TLS protocol version negotiated (flags TLS 1.0/1.1, SSLv3)
2. Certificate validity (expiry, hostname match)
3. HSTS header presence (from the original captured exchange)
4. Secure cookie attribute audit (from the original captured exchange)
"""

from __future__ import annotations
import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

log = logging.getLogger("harness.validators.crypto")

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class CryptoTestResult:
    test_name: str
    passed: bool
    severity: str
    detail: str
    evidence: str
    vulnerable: bool = False
    checked: bool = True

    def to_dict(self) -> dict:
        return {
            "test": self.test_name, "passed": self.passed, "severity": self.severity,
            "detail": self.detail, "evidence": self.evidence,
            "vulnerable": self.vulnerable, "checked": self.checked,
        }


class CryptoValidator(Validator):
    """
    Validator for transport-layer and cryptographic weaknesses.

    Opens a real TLS connection to the target host (independent of
    the HTTP-level checks every other validator in this harness does)
    and separately audits HSTS/cookie attributes from the already
    -captured exchange.
    """

    name = "crypto_validator"
    finding_classes = {"crypto", "cryptography", "weak crypto", "weak_crypto", "tls", "ssl"}
    active = True

    def __init__(self, timeout: float = 10.0, max_redirects: int = 0,
                 allowed_hosts: list[str] | None = None):
        # Safety item #12: crypto opens a RAW TLS socket to the host (not httpx),
        # so it is neither covered by the safety gate nor an httpx-level guard --
        # it must enforce scope itself before connecting.
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.max_redirects = max_redirects

    def get_name(self) -> str:
        return "crypto_validator"

    def get_capability(self) -> str:
        return "crypto_transport_validation"

    def get_execution_plane(self) -> str:
        return "local_tool"

    def plan(self, finding: Finding, exchange: HttpExchange) -> Any:
        from harness.models import TestPlan
        from harness.categories import canonicalize
        import hashlib
        import json

        # Plan ID must incorporate the FULL exchange, not just the URL --
        # see cors_validator.py's plan() for the real, live-reproduced
        # collision this fixes (two different real requests to the same
        # URL producing the same plan_id and clobbering each other).
        exchange_hash = hashlib.sha256(
            json.dumps(exchange.model_dump(), sort_keys=True).encode()
        ).hexdigest()[:16]
        plan_id = f"crypto_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"Cryptography/transport validation for {finding.vulnerability_class}",
            success_signals=["Confirm weak TLS configuration, missing HSTS, or insecure cookie attributes"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        from harness import scope_lock
        if not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return ValidationResult(
                validator=self.get_name(), status="skipped",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=scope_lock.out_of_scope_reason(exchange.url, self.allowed_hosts),
                evidence="", raw_output="")
        tests: list[CryptoTestResult] = []
        try:
            parsed = urlparse(exchange.url)
            if parsed.scheme == "https":
                tests.append(self._check_tls(parsed.hostname, parsed.port or 443))
            else:
                tests.append(CryptoTestResult(
                    "TLS Configuration", False, "high",
                    "This exchange used plain HTTP, not HTTPS -- transport is unencrypted by definition",
                    f"URL scheme: {parsed.scheme}", vulnerable=True,
                ))
            tests.append(self._check_hsts(exchange))
            tests.append(self._check_cookie_attributes(exchange))

            checked = [t for t in tests if t.checked]
            vulnerable = any(t.vulnerable for t in checked)
            severities = [t.severity for t in checked if t.vulnerable]
            severity = "critical" if "critical" in severities else ("high" if "high" in severities else "medium")

            vulnerable_tests = [t for t in checked if t.vulnerable]
            summary_parts = []
            if vulnerable_tests:
                summary_parts.append(f"Cryptography/transport issue(s) confirmed: {len(vulnerable_tests)}")
                for t in vulnerable_tests:
                    summary_parts.append(f"  - {t.test_name}: {t.detail}")
            else:
                summary_parts.append("No transport/crypto issue confirmed by these checks")

            return ValidationResult(
                validator=self.get_name(),
                status="confirmed" if vulnerable else "not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.9 if vulnerable else 0.2,
                confirmed=vulnerable,
                summary=" ".join(summary_parts),
                evidence=self._build_evidence(checked),
                raw_output=self._build_raw_output(tests),
            )
        except Exception as e:
            log.error(f"Crypto validation error: {e}")
            return ValidationResult(
                validator=self.get_name(), status="error",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=f"Crypto validation failed: {e}", evidence="", raw_output=str(e),
            )

    def _check_tls(self, hostname: str | None, port: int) -> CryptoTestResult:
        if not hostname:
            return CryptoTestResult("TLS Configuration", True, "low", "No hostname to test", "", checked=False)

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    version = tls_sock.version()
                    cipher = tls_sock.cipher()
                    cert = tls_sock.getpeercert()
        except ssl.SSLCertVerificationError as e:
            return CryptoTestResult(
                "TLS Configuration", False, "high",
                f"Certificate verification failed: {e}",
                str(e), vulnerable=True,
            )
        except Exception as e:
            log.debug(f"TLS check failed for {hostname}:{port}: {e}")
            return CryptoTestResult("TLS Configuration", True, "low",
                                     f"Could not establish TLS connection to verify: {e}", "", checked=False)

        issues = []
        if version in _WEAK_PROTOCOLS:
            issues.append(f"negotiated protocol {version} is deprecated/weak")

        not_after = cert.get("notAfter") if cert else None
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                if expiry < datetime.now(timezone.utc):
                    issues.append(f"certificate expired on {not_after}")
            except ValueError:
                pass

        if issues:
            return CryptoTestResult(
                "TLS Configuration", False, "high",
                "; ".join(issues),
                f"Protocol: {version}, Cipher: {cipher[0] if cipher else 'unknown'}, notAfter: {not_after}",
                vulnerable=True,
            )
        return CryptoTestResult(
            "TLS Configuration", True, "low",
            f"TLS looks reasonable: protocol {version}, cipher {cipher[0] if cipher else 'unknown'}",
            f"Protocol: {version}", vulnerable=False,
        )

    def _check_hsts(self, exchange: HttpExchange) -> CryptoTestResult:
        parsed = urlparse(exchange.url)
        if parsed.scheme != "https":
            return CryptoTestResult("HSTS Header", True, "low", "Not an HTTPS exchange", "", checked=False)

        headers_lower = {k.lower(): v for k, v in (exchange.response_headers or {}).items()}
        if "strict-transport-security" not in headers_lower:
            return CryptoTestResult(
                "HSTS Header", False, "medium",
                "No Strict-Transport-Security header on this HTTPS response -- a user who is ever "
                "downgraded to http:// (or clicks an old http:// link/bookmark) is not protected "
                "from SSL-stripping on that first request",
                "Strict-Transport-Security header absent", vulnerable=True,
            )
        return CryptoTestResult("HSTS Header", True, "low",
                                 f"HSTS present: {headers_lower['strict-transport-security']}", "", vulnerable=False)

    def _check_cookie_attributes(self, exchange: HttpExchange) -> CryptoTestResult:
        headers_lower = {k.lower(): v for k, v in (exchange.response_headers or {}).items()}
        set_cookie = headers_lower.get("set-cookie", "")
        if not set_cookie:
            return CryptoTestResult("Cookie Attributes", True, "low", "No Set-Cookie header in this exchange", "", checked=False)

        missing = []
        if "secure" not in set_cookie.lower():
            missing.append("Secure")
        if "httponly" not in set_cookie.lower():
            missing.append("HttpOnly")
        if "samesite" not in set_cookie.lower():
            missing.append("SameSite")

        if missing:
            return CryptoTestResult(
                "Cookie Attributes", False, "medium",
                f"Set-Cookie is missing: {', '.join(missing)}",
                f"Set-Cookie: {set_cookie[:200]}", vulnerable=True,
            )
        return CryptoTestResult("Cookie Attributes", True, "low", "Cookie carries Secure/HttpOnly/SameSite", "", vulnerable=False)

    def _build_evidence(self, tests: list[CryptoTestResult]) -> str:
        vulnerable = [t for t in tests if t.vulnerable]
        if not vulnerable:
            return "No transport/crypto issue confirmed"
        return " | ".join(f"{t.test_name}: {t.detail} ({t.severity})" for t in vulnerable)

    def _build_raw_output(self, tests: list[CryptoTestResult]) -> str:
        import json
        return json.dumps([t.to_dict() for t in tests], indent=2)
