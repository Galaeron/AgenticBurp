"""
Subdomain Takeover Validator

Active validator: extracts candidate third-party-service hostnames
from the exchange (or uses the exchange's own hostname if it already
looks like one), fetches them, and compares the response against a
curated set of known "unclaimed resource" fingerprints published by
major cloud/SaaS providers.

This is a SUBSET of the fingerprint databases maintained by dedicated
tools (e.g. the community-maintained "can-i-take-over-xyz" list, which
tracks 100+ providers) -- this validator covers roughly a dozen of the
highest-prevalence ones rather than reimplementing the full list.
Absence of a match here is NOT proof the target is safe; it only means
none of these specific fingerprints matched.

This validator does not attempt to actually claim/register the
resource on the third-party provider -- that would have real
side effects on infrastructure this harness doesn't own, and stays
strictly an analyst-approved, out-of-band step.
"""

from __future__ import annotations
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from models import Finding, HttpExchange

log = logging.getLogger("harness.validators.subdomain_takeover")

# (provider label, hostname suffix pattern, body fingerprint regex)
# Deliberately a small, high-confidence subset -- see module docstring.
_FINGERPRINTS: list[tuple[str, str, re.Pattern]] = [
    ("GitHub Pages", "github.io", re.compile(r"There isn't a GitHub Pages site here", re.IGNORECASE)),
    ("Amazon S3", "s3.amazonaws.com", re.compile(r"NoSuchBucket|The specified bucket does not exist", re.IGNORECASE)),
    ("Heroku", "herokuapp.com", re.compile(r"No such app|herokucdn\.com/error-pages/no-such-app", re.IGNORECASE)),
    ("Heroku (DNS)", "herokudns.com", re.compile(r"No such app|herokucdn\.com/error-pages/no-such-app", re.IGNORECASE)),
    ("Fastly", "fastly.net", re.compile(r"Fastly error: unknown domain|do not know of this page", re.IGNORECASE)),
    ("Bitbucket", "bitbucket.io", re.compile(r"Repository not found", re.IGNORECASE)),
    ("Surge.sh", "surge.sh", re.compile(r"project not found", re.IGNORECASE)),
    ("Shopify", "myshopify.com", re.compile(r"Sorry, this shop is currently unavailable", re.IGNORECASE)),
    ("Ghost(Pro)", "ghost.io", re.compile(r"The thing you were looking for is no longer here", re.IGNORECASE)),
    ("WP Engine", "wpengine.com", re.compile(r"The site you were looking for couldn't be found", re.IGNORECASE)),
    ("Webflow", "webflow.io", re.compile(r"The page you are looking for doesn't exist or has been moved", re.IGNORECASE)),
    ("Tilda", "tilda.ws", re.compile(r"Please renew your subscription", re.IGNORECASE)),
    ("Statuspage", "statuspage.io", re.compile(r"You are being <a href=\"https://www\.statuspage\.io\">redirected", re.IGNORECASE)),
]

# Third-party hostname suffixes worth flagging as "dangling reference"
# even without a body fingerprint match on THIS response, since the
# agent may have spotted them in a link rather than the response
# actually coming from that host.
_WATCHED_SUFFIXES = tuple(sorted({p[1] for p in _FINGERPRINTS}))


@dataclass
class TakeoverTestResult:
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


class SubdomainTakeoverValidator(Validator):
    """
    Validator for subdomain takeover findings.

    Fetches candidate third-party hostnames referenced in the exchange
    (or the exchange's own URL, if it already targets one of the
    watched suffixes) and checks the response against a curated set of
    provider "unclaimed resource" fingerprints.
    """

    name = "subdomain_takeover_validator"
    finding_classes = {"subdomain_takeover", "subdomain takeover", "dangling dns", "dangling_dns"}
    active = True

    def __init__(self, timeout: float = 15.0, max_redirects: int = 3,
                 run_context=None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.run_context = run_context
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def get_name(self) -> str:
        return "subdomain_takeover_validator"

    def get_capability(self) -> str:
        return "subdomain_takeover_detection"

    def get_execution_plane(self) -> str:
        return "local_tool"

    def plan(self, finding: Finding, exchange: HttpExchange) -> Any:
        from models import TestPlan
        from categories import canonicalize
        import hashlib
        import json

        # Plan ID must incorporate the FULL exchange, not just the URL --
        # see cors_validator.py's plan() for the real, live-reproduced
        # collision this fixes (two different real requests to the same
        # URL producing the same plan_id and clobbering each other).
        exchange_hash = hashlib.sha256(
            json.dumps(exchange.model_dump(), sort_keys=True).encode()
        ).hexdigest()[:16]
        plan_id = f"takeover_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"Subdomain takeover validation for {finding.vulnerability_class}",
            success_signals=["Confirm an unclaimed third-party resource fingerprint"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        tests: list[TakeoverTestResult] = []
        try:
            candidates = self._extract_candidate_hostnames(exchange)
            if not candidates:
                return ValidationResult(
                    validator=self.get_name(), status="skipped",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary="No hostname in this exchange (its own URL, or referenced links) matches "
                            "any of this validator's watched third-party-service suffixes",
                    evidence="", raw_output="[]",
                )

            for host in candidates:
                tests.append(await self._check_fingerprint(host))

            vulnerable_tests = [t for t in tests if t.vulnerable]
            vulnerable = bool(vulnerable_tests)

            summary_parts = []
            if vulnerable_tests:
                summary_parts.append(f"Subdomain takeover CONFIRMED for {len(vulnerable_tests)} host(s)")
                for t in vulnerable_tests:
                    summary_parts.append(f"  - {t.test_name}: {t.detail}")
            else:
                summary_parts.append(
                    f"Checked {len(candidates)} candidate host(s), no unclaimed-resource fingerprint "
                    "matched -- note this validator covers ~13 providers, not the full universe of "
                    "CNAME-able services, so a negative result here is not a clean bill of health"
                )

            return ValidationResult(
                validator=self.get_name(),
                status="confirmed" if vulnerable else "not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.9 if vulnerable else 0.2,
                confirmed=vulnerable,
                summary=" ".join(summary_parts),
                evidence=self._build_evidence(tests),
                raw_output=self._build_raw_output(tests),
            )
        except Exception as e:
            log.error(f"Subdomain takeover validation error: {e}")
            return ValidationResult(
                validator=self.get_name(), status="error",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=f"Subdomain takeover validation failed: {e}", evidence="", raw_output=str(e),
            )

    def _extract_candidate_hostnames(self, exchange: HttpExchange) -> list[str]:
        """Own URL's host, plus any watched-suffix hostname found in the response body."""
        candidates: set[str] = set()

        own_host = urlparse(exchange.url).netloc
        if any(own_host.endswith(suf) for suf in _WATCHED_SUFFIXES):
            candidates.add(own_host)

        body = exchange.response_body or ""
        # Cheap hostname-shaped token scan restricted to the watched suffixes,
        # not a general-purpose URL parser -- good enough to catch links/CNAMEs
        # mentioned in HTML/JSON without pulling in a full HTML parser here.
        for suf in _WATCHED_SUFFIXES:
            for m in re.finditer(r"[a-zA-Z0-9][a-zA-Z0-9\-\.]*\." + re.escape(suf), body):
                candidates.add(m.group(0))

        return sorted(candidates)[:5]  # bounded: don't fan out unboundedly on a busy page

    def _fingerprint_url(self, host: str) -> str:
        return f"https://{host}/"

    async def _check_fingerprint(self, host: str) -> TakeoverTestResult:
        url = self._fingerprint_url(host)
        try:
            if self.run_context is not None:
                from types import SimpleNamespace
                from run_context import TypedRequest
                outcome = await self.run_context.executor().execute(
                    TypedRequest("GET", url, headers={"User-Agent": self.user_agent}),
                    capability=self.get_name(), max_redirects=self.max_redirects)
                if not outcome.ok:
                    raise httpx.TransportError(outcome.error or outcome.outcome)
                response = SimpleNamespace(status_code=outcome.status,
                                           text=outcome.body, headers=outcome.headers)
            else:
                async with httpx.AsyncClient(
                    timeout=self.timeout, follow_redirects=True,
                    max_redirects=self.max_redirects,
                ) as client:
                    import global_throttle
                    await global_throttle.acquire()
                    response = await client.get(url, headers={"User-Agent": self.user_agent})
        except Exception as e:
            log.debug(f"Fingerprint fetch failed for {host}: {e}")
            return TakeoverTestResult(
                f"Fingerprint: {host}", True, "low",
                f"Could not fetch {url} ({e}) -- inconclusive, not a negative result", "",
                vulnerable=False, checked=False,
            )

        body = response.text or ""
        for provider, suffix, pattern in _FINGERPRINTS:
            if host.endswith(suffix) and pattern.search(body):
                return TakeoverTestResult(
                    f"Fingerprint: {host}", False, "high",
                    f"{host} responds with {provider}'s unclaimed-resource page -- if any DNS record "
                    "under the organization's domain still CNAMEs to this host, an attacker who "
                    f"registers this name on {provider} takes control of that subdomain",
                    f"HTTP {response.status_code}, matched {provider} fingerprint pattern",
                    vulnerable=True,
                )

        return TakeoverTestResult(
            f"Fingerprint: {host}", True, "low",
            f"{host} returned HTTP {response.status_code}, no watched fingerprint matched "
            "(resource may be actively claimed, or unclaimed in a way this validator's "
            "fingerprint list doesn't cover)",
            f"HTTP {response.status_code}", vulnerable=False,
        )

    def _build_evidence(self, tests: list[TakeoverTestResult]) -> str:
        vulnerable = [t for t in tests if t.vulnerable]
        if not vulnerable:
            return "No unclaimed-resource fingerprint matched"
        return " | ".join(f"{t.test_name}: {t.detail} ({t.severity})" for t in vulnerable)

    def _build_raw_output(self, tests: list[TakeoverTestResult]) -> str:
        import json
        return json.dumps([t.to_dict() for t in tests], indent=2)
