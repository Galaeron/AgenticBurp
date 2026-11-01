"""
CSP / Clickjacking Validator

Active validator: re-fetches the target URL fresh (rather than trusting
only the captured exchange, in case CSP is applied inconsistently
across requests) and parses the actual CSP directive list and framing
headers. Inside a run the fresh GET replays the captured request's identity
(cookie, authorization, ...) under the run's registered session, so an
authenticated route is judged on the response its own caller received, not on
an anonymous 401 or error page. Standalone (no run) it sends only User-Agent,
Accept and Accept-Language from the captured request, so no credential of any
name, and follows no redirect. A fetch that ends on another route (a login
page, a foreign host) is inconclusive, never a verdict on the route.

Checks performed:
1. CSP presence and directive analysis (unsafe-inline, unsafe-eval,
   wildcard sources, object-src)
2. Report-only-without-enforcing-policy detection
3. Clickjacking / framing protection (X-Frame-Options, frame-ancestors)

Each claim is decided only by its own check (a framing claim by 3, a CSP claim
by 1 and 2), and only on a 2xx HTML document: CSP and framing headers protect
documents, so a JSON API response or an error page says nothing about them.
Response headers cannot confirm any other class (XSS, generic misconfiguration).
"""

from __future__ import annotations
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from harness import security

from .base import Validator, ValidationResult, header_fingerprint

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

log = logging.getLogger("harness.validators.csp")

# Content types whose headers CSP / framing protection apply to.
_DOCUMENT_TYPES = ("text/html", "application/xhtml+xml")

# Captured request headers the fresh GET must not replay: connection-scoped
# (hop-by-hop) headers, headers describing a body the GET does not carry, and
# conditional / range / encoding headers that would make the server answer 304,
# 206 or an encoding the client does not decode instead of the document.
_NOT_REPLAYED = frozenset({
    "host", "content-length", "content-type", "content-encoding", "transfer-encoding",
    "connection", "keep-alive", "proxy-connection", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "upgrade", "expect", "http2-settings",
    "accept-encoding", "range", "if-range", "if-match", "if-none-match",
    "if-modified-since", "if-unmodified-since",
})

# The only captured request headers a standalone fresh GET sends (no run, so no
# session registry decides where a credential may go). An allowlist, so a
# credential header under any name (X-Functions-Key, X-JWT-Assertion, ...) is
# dropped with every other header.
_STANDALONE_HEADERS = frozenset({"user-agent", "accept", "accept-language"})

_FRAMING_CLAIM = re.compile(r"clickjack|framing|frame ancestors|x frame options|ui redress")
_CSP_CLAIM = re.compile(r"\bcsp\b|content security policy")

# Longest header value written into evidence.
_VALUE_LIMIT = 300


class FetchedHeaders(dict):
    """Response headers of one fetch, plus the status and URL that produced them."""
    status: int | None = None
    final_url: str = ""


def _claim_kinds(vulnerability_class: str) -> set[str]:
    """Which header checks decide this class: {"csp"}, {"framing"} or both.
    Empty for any class response headers cannot confirm (XSS, generic
    misconfiguration, ...). The universal header audit evaluates every class in
    CspValidator.audit_classes (CspValidator.audit), each by its own check."""
    from harness.categories import canonicalize, distinctive_token
    if canonicalize(vulnerability_class) not in (None, "csp") \
            or distinctive_token(vulnerability_class) not in (None, "csp"):
        return set()
    text = re.sub(r"[\s_\-]+", " ", (vulnerability_class or "").lower()).strip()
    kinds = set()
    if _FRAMING_CLAIM.search(text):
        kinds.add("framing")
    if _CSP_CLAIM.search(text):
        kinds.add("csp")
    return kinds


def _same_route(url: str, final_url: str) -> bool:
    """Whether a fetch ended on the route it asked for: same scheme, host, port
    and path (query and fragment aside); False after any redirect elsewhere."""
    def route(value: str):
        parts = urlsplit(value)
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme.lower())
        return parts.scheme.lower(), (parts.hostname or "").lower(), port, parts.path or "/"

    try:
        return route(url) == route(final_url)
    except ValueError:
        return False


def _content_type(headers_lower: dict) -> str:
    return (headers_lower.get("content-type") or "").split(";")[0].strip().lower()


def _bounded(value: str) -> str:
    return value if len(value) <= _VALUE_LIMIT else value[:_VALUE_LIMIT] + "..."


@dataclass
class CspTestResult:
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


def _parse_csp(csp: str) -> dict[str, list[str]]:
    """Parse a CSP header value into {directive: [sources]}."""
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


class CspValidator(Validator):
    """Validator for CSP weaknesses and clickjacking exposure."""

    name = "csp_validator"
    finding_classes = {"csp", "content security policy", "content_security_policy", "clickjacking"}
    # The universal header audit evaluates each class listed here from one fetch
    # (CspValidator.audit), not whichever finding class a set iteration yields first,
    # so a CSP claim and a framing claim are each decided by their own check.
    audit_classes = ("csp", "clickjacking")
    active = True

    def __init__(self, timeout: float = 10.0, max_redirects: int = 5,
                 run_context=None, allowed_hosts: list[str] | None = None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.run_context = run_context
        self.allowed_hosts = allowed_hosts or []  # safety item #12: scope lock
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def get_name(self) -> str:
        return "csp_validator"

    def get_capability(self) -> str:
        return "csp_clickjacking_validation"

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
        plan_id = f"csp_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"CSP/clickjacking validation for {finding.vulnerability_class}",
            success_signals=["Confirm missing/weak CSP or missing framing protection"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        finding_class = finding.vulnerability_class
        return (await self.audit(exchange, (finding_class,)))[finding_class]

    async def audit(self, exchange: HttpExchange,
                    classes: tuple[str, ...] | None = None) -> dict[str, ValidationResult]:
        """One verdict per class (default: audit_classes) from ONE fresh fetch of
        the exchange's URL, each class decided by its own check. validate() is
        the single-class case; the universal header audit calls this so a page
        is fetched once, not once per class."""
        from harness import scope_lock
        classes = tuple(dict.fromkeys(classes or self.audit_classes))
        if not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            reason = scope_lock.out_of_scope_reason(exchange.url, self.allowed_hosts)
            return {c: ValidationResult(validator=self.get_name(), status="skipped",
                                        finding_class=c, summary=reason) for c in classes}
        kinds = {c: _claim_kinds(c) for c in classes}
        results = {c: ValidationResult(
            validator=self.get_name(), status="skipped", finding_class=c,
            summary=f"not supported: response headers cannot confirm {c}")
            for c in classes if not kinds[c]}
        supported = [c for c in classes if kinds[c]]
        if not supported:
            return results
        try:
            fetched = await self._fetch_fresh_headers(exchange)
            source = "fresh"
            if fetched is None:
                source = "captured"
                fetched = FetchedHeaders(exchange.response_headers or {})
                fetched.status = exchange.response_status
                fetched.final_url = exchange.url
            for c in supported:
                results[c] = self._verdict(c, kinds[c], exchange, fetched, source)
        except Exception as e:
            log.error(f"CSP validation error: {e}")
            for c in supported:
                results.setdefault(c, ValidationResult(
                    validator=self.get_name(), status="error",
                    finding_class=c, confidence=0.0, confirmed=False,
                    summary=f"CSP validation failed: {e}", evidence="", raw_output=str(e)))
        return {c: results[c] for c in classes}

    def _verdict(self, finding_class: str, kinds: set[str], exchange: HttpExchange,
                 fetched: FetchedHeaders, source: str) -> ValidationResult:
        """The verdict of one class on one fetched response."""
        tests: list[CspTestResult] = []
        if source == "captured":
            tests.append(CspTestResult("Fresh Fetch", True, "low",
                                        "Could not re-fetch; using headers from the captured exchange", "",
                                        checked=False))
        headers_lower = {k.lower(): v for k, v in fetched.items()}
        content_type = _content_type(headers_lower)
        observed = self._observed(exchange.url, fetched, content_type, headers_lower, source)

        status = fetched.status
        if status is None or status >= 500:
            return self._skipped(
                finding_class, observed, tests,
                "inconclusive: " + ("no HTTP status for the evaluated response" if status is None
                                    else f"HTTP {status}; an error page does not describe the route"))
        if not _same_route(exchange.url, fetched.final_url or exchange.url):
            # A login page or a foreign page answering for the route says
            # nothing about the route's own headers.
            return self._skipped(
                finding_class, observed, tests,
                f"inconclusive: redirected to {security.redact_secrets_in_url(fetched.final_url)}")
        if not 200 <= status < 300 or content_type not in _DOCUMENT_TYPES:
            return self._skipped(
                finding_class, observed, tests,
                f"not applicable: HTTP {status} {content_type or 'no content type'}; "
                "CSP/framing protect HTML documents")

        if "csp" in kinds:
            tests.append(self._check_csp(headers_lower))
        if "framing" in kinds:
            tests.append(self._check_framing(headers_lower))

        checked = [t for t in tests if t.checked]
        vulnerable = any(t.vulnerable for t in checked)
        severities = [t.severity for t in checked if t.vulnerable]
        severity = "high" if "high" in severities else ("medium" if "medium" in severities else "low")

        vulnerable_tests = [t for t in checked if t.vulnerable]
        summary_parts = []
        if vulnerable_tests:
            summary_parts.append(f"CSP/clickjacking issue(s) confirmed: {len(vulnerable_tests)}")
            for t in vulnerable_tests:
                summary_parts.append(f"  - {t.test_name}: {t.detail}")
        else:
            subject = {"csp": "CSP", "framing": "Framing protection"}
            summary_parts.append(
                "CSP and framing protection look adequate on this fetch" if len(kinds) == 2
                else f"{subject[next(iter(kinds))]} looks adequate on this fetch")

        return ValidationResult(
            validator=self.get_name(),
            status="confirmed" if vulnerable else "not_confirmed",
            finding_class=finding_class,
            confidence=0.85 if vulnerable else 0.2,
            confirmed=vulnerable,
            summary=" ".join(summary_parts),
            evidence=f"{observed} | {self._build_evidence(checked)}",
            raw_output=self._build_raw_output(tests),
            header_fingerprint=header_fingerprint(
                headers_lower.get("content-security-policy"),
                headers_lower.get("content-security-policy-report-only"),
                headers_lower.get("x-frame-options")),
        )

    def _skipped(self, finding_class: str, observed: str, tests: list[CspTestResult],
                 summary: str) -> ValidationResult:
        return ValidationResult(
            validator=self.get_name(), status="skipped",
            finding_class=finding_class, confidence=0.0, confirmed=False,
            summary=summary, evidence=observed, raw_output=self._build_raw_output(tests))

    def _observed(self, url: str, fetched: FetchedHeaders, content_type: str,
                  headers_lower: dict, source: str) -> str:
        """The values the verdict rests on, stated whatever the verdict is."""
        def value(name: str) -> str:
            present = headers_lower.get(name)
            return "absent" if present is None else (_bounded(present) or "(empty)")
        shown_url = security.redact_secrets_in_url(url)
        if fetched.final_url not in ("", url):
            shown_url += f" (final: {security.redact_secrets_in_url(fetched.final_url)})"
        return (f"URL: {shown_url} | HTTP {fetched.status} {content_type or 'no content type'} "
                f"| source: {source} "
                f"| Content-Security-Policy: {value('content-security-policy')} "
                f"| Content-Security-Policy-Report-Only: {value('content-security-policy-report-only')} "
                f"| X-Frame-Options: {value('x-frame-options')}")

    def _replay_headers(self, exchange: HttpExchange) -> dict:
        """The captured request's identity for the fresh GET: its headers minus
        the connection / body / conditional ones in _NOT_REPLAYED."""
        headers = {"User-Agent": self.user_agent}
        for name, value in (exchange.request_headers or {}).items():
            lowered = name.lower()
            if lowered in _NOT_REPLAYED or lowered.startswith(":") or not str(value).strip():
                continue
            if lowered == "user-agent":
                headers.pop("User-Agent", None)
            headers[name] = value
        return headers

    async def _fetch_fresh_headers(self, exchange: HttpExchange) -> FetchedHeaders | None:
        """GET the URL again as the captured request's identity. None when the
        fetch could not be made (denied, errored, redirect limit): the caller
        then falls back to the captured response headers."""
        try:
            from harness.run_context import TypedRequest, current_run_context
            replay = self._replay_headers(exchange)
            run = self.run_context or current_run_context()  # I03: enclosing run if unbound
            if run is not None:
                # Authorization / Cookie / Proxy-Authorization only travel under a
                # session registered for them (and this origin); otherwise the
                # executor refuses the send and the captured headers are used.
                # Every other captured header goes to this URL only: the executor
                # sends none of them on a redirect hop.
                session_ref, request_headers = run.sessions.bind_headers(replay)
                outcome = await run.executor().execute(
                    TypedRequest("GET", exchange.url, headers=request_headers),
                    capability=self.get_name(), session_ref=session_ref,
                    max_redirects=self.max_redirects)
                if not outcome.ok or outcome.status is None:
                    return None
                fetched = FetchedHeaders(outcome.headers)
                fetched.status, fetched.final_url = outcome.status, outcome.final_url
                return fetched
            # Standalone: no session registry decides where a credential may go, so
            # only the _STANDALONE_HEADERS allowlist is sent (no credential of any
            # name), and a redirect is reported rather than followed (the next hop
            # is unchecked scope and would answer for the route).
            allowed = {k: v for k, v in replay.items() if k.lower() in _STANDALONE_HEADERS}
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                from harness import global_throttle
                await global_throttle.acquire()
                response = await client.get(exchange.url, headers=allowed)
                location = response.headers.get("location")
                target = response.url.join(location) if response.is_redirect and location else response.url
                fetched = FetchedHeaders(response.headers)
                fetched.status, fetched.final_url = response.status_code, str(target)
                return fetched
        except Exception as e:
            log.debug(f"Fresh fetch failed: {e}")
            return None

    def _check_csp(self, headers_lower: dict) -> CspTestResult:
        csp = headers_lower.get("content-security-policy", "")
        csp_report_only = headers_lower.get("content-security-policy-report-only", "")

        if not csp and csp_report_only:
            return CspTestResult(
                "CSP Presence", False, "medium",
                "Only Content-Security-Policy-Report-Only is set, with no enforcing "
                "Content-Security-Policy -- violations are logged but nothing is blocked",
                f"CSP-Report-Only: {csp_report_only[:150]}", vulnerable=True,
            )
        if not csp and "content-security-policy" in headers_lower:
            return CspTestResult(
                "CSP Presence", False, "medium",
                "Content-Security-Policy header is present but empty -- no policy is enforced",
                "Content-Security-Policy header empty", vulnerable=True,
            )
        if not csp:
            return CspTestResult(
                "CSP Presence", False, "medium",
                "No Content-Security-Policy header present -- no defense-in-depth against XSS "
                "from this layer",
                "Content-Security-Policy header absent", vulnerable=True,
            )

        directives = _parse_csp(csp)
        script_src = directives.get("script-src") or directives.get("default-src") or []
        issues = []
        if "'unsafe-inline'" in script_src:
            issues.append("script-src allows 'unsafe-inline'")
        if "'unsafe-eval'" in script_src:
            issues.append("script-src allows 'unsafe-eval'")
        if "*" in script_src or "https:" in script_src or "http:" in script_src:
            issues.append(f"script-src has an overly broad source: {[s for s in script_src if s in ('*','https:','http:')]}")
        object_src = directives.get("object-src")
        if object_src is None and "default-src" not in directives:
            issues.append("no object-src (and no default-src fallback) restricting plugin content")
        elif object_src and "'none'" not in object_src:
            issues.append(f"object-src is not restricted to 'none': {object_src}")

        if issues:
            return CspTestResult(
                "CSP Directive Analysis", False, "medium",
                "; ".join(issues),
                f"CSP: {csp[:200]}", vulnerable=True,
            )
        return CspTestResult("CSP Directive Analysis", True, "low", "CSP directives look reasonably restrictive",
                              f"CSP: {csp[:200]}", vulnerable=False)

    def _check_framing(self, headers_lower: dict) -> CspTestResult:
        csp = headers_lower.get("content-security-policy", "")
        directives = _parse_csp(csp) if csp else {}
        has_frame_ancestors = "frame-ancestors" in directives
        xfo = headers_lower.get("x-frame-options", "")

        if has_frame_ancestors:
            fa = directives["frame-ancestors"]
            if "*" in fa:
                return CspTestResult(
                    "Framing Protection", False, "medium",
                    f"frame-ancestors allows any origin: {fa}",
                    f"frame-ancestors: {fa}", vulnerable=True,
                )
            return CspTestResult("Framing Protection", True, "low",
                                  f"frame-ancestors restricts framing: {fa}", "", vulnerable=False)

        if xfo:
            if xfo.upper() not in ("DENY", "SAMEORIGIN"):
                return CspTestResult(
                    "Framing Protection", False, "medium",
                    f"X-Frame-Options has a non-standard value: {xfo}",
                    f"X-Frame-Options: {xfo}", vulnerable=True,
                )
            return CspTestResult("Framing Protection", True, "low",
                                  f"X-Frame-Options: {xfo}", "", vulnerable=False)

        return CspTestResult(
            "Framing Protection", False, "medium",
            "No frame-ancestors CSP directive and no X-Frame-Options header -- "
            "this page can be framed by any site (clickjacking exposure)",
            "Both frame-ancestors and X-Frame-Options absent", vulnerable=True,
        )

    def _build_evidence(self, tests: list[CspTestResult]) -> str:
        vulnerable = [t for t in tests if t.vulnerable]
        if not vulnerable:
            return "No CSP/clickjacking issue confirmed"
        return " | ".join(f"{t.test_name}: {t.detail} ({t.severity})" for t in vulnerable)

    def _build_raw_output(self, tests: list[CspTestResult]) -> str:
        import json
        return json.dumps([t.to_dict() for t in tests], indent=2)
