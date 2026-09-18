"""
Web Cache Poisoning Validator

Active validator for web cache poisoning findings. Tests whether
unkeyed inputs (headers/params not part of the cache key) can change
a cacheable response, and whether a static-looking path suffix causes
a dynamic/authenticated response to be served as if it were a shared
static asset (web cache deception).

Tests performed:
1. Unkeyed header reflection (X-Forwarded-Host / X-Forwarded-Scheme)
2. Cache persistence -- does the poisoned value survive a follow-up
   request that no longer sends the injected header?
3. Cacheability signals on the original response
4. Web cache deception via a static-looking path suffix
"""

from __future__ import annotations
import asyncio
import logging
import random
import string
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

log = logging.getLogger("harness.validators.web_cache_poisoning")

_CACHE_INDICATOR_HEADERS = (
    "age", "x-cache", "x-cache-status", "cf-cache-status",
    "x-varnish", "x-served-by", "surrogate-control",
)


@dataclass
class CacheTestResult:
    test_name: str
    passed: bool
    severity: str
    detail: str
    evidence: str
    vulnerable: bool = False

    def to_dict(self) -> dict:
        return {
            "test": self.test_name, "passed": self.passed, "severity": self.severity,
            "detail": self.detail, "evidence": self.evidence, "vulnerable": self.vulnerable,
        }


class WebCachePoisoningValidator(Validator):
    """
    Validator for web cache poisoning and web cache deception.

    Performs active testing by sending requests with unkeyed inputs
    and checking whether they change a cacheable response, and whether
    the poisoned response persists for a follow-up request that no
    longer sends the injected value.
    """

    name = "web_cache_poisoning_validator"
    finding_classes = {"web_cache_poisoning", "cache poisoning", "web cache poisoning", "cache_poisoning"}
    active = True

    def __init__(self, timeout: float = 15.0, max_redirects: int = 5,
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
        return "web_cache_poisoning_validator"

    def get_capability(self) -> str:
        return "web_cache_poisoning_detection"

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
        plan_id = f"cache_poison_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"Web cache poisoning validation for {finding.vulnerability_class}",
            success_signals=["Confirm unkeyed-input cache poisoning or web cache deception"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        from harness import scope_lock
        if not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return ValidationResult(
                validator=self.get_name(), status="skipped",
                finding_class=finding.vulnerability_class,
                summary=scope_lock.out_of_scope_reason(exchange.url, self.allowed_hosts))
        tests: list[CacheTestResult] = []

        try:
            tests.append(await self._test_cacheability_signals(exchange))
            tests.append(await self._test_unkeyed_host_header(exchange))
            tests.append(await self._test_cache_deception(exchange))

            vulnerable = any(t.vulnerable for t in tests)
            if vulnerable:
                severities = [t.severity for t in tests if t.vulnerable]
                severity = "critical" if "critical" in severities else ("high" if "high" in severities else "medium")
            else:
                severity = "low"

            vulnerable_tests = [t for t in tests if t.vulnerable]
            # RETIRED (review 2026-09-09): reflection of an unkeyed input or a
            # cache-friendly response is NOT a confirmed poisoning -- it does not
            # show the attacker's influence (or private data) is CACHED and served
            # to a DIFFERENT client under the controlled cache key. This no longer
            # emits a confirmed verdict; a match is a CANDIDATE. Re-qualify: a clean
            # SECOND-CLIENT retrieval that returns the attacker's influence/private
            # data under the controlled cache key; only then confirmed=True.
            summary_parts = []
            if vulnerable_tests:
                summary_parts.append(
                    f"Web cache poisoning CANDIDATE (not confirmed): {len(vulnerable_tests)} "
                    f"unkeyed-input reflection primitive(s) -- no second-client cached-retrieval proof")
                for t in vulnerable_tests:
                    summary_parts.append(f"  - {t.test_name}: {t.detail}")
            else:
                summary_parts.append("No unkeyed-input cache poisoning primitive observed with these probes")

            return ValidationResult(
                validator=self.get_name(),
                status="not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.4 if vulnerable_tests else 0.1,
                confirmed=False,
                summary=" ".join(summary_parts),
                evidence=self._build_evidence(tests),
                raw_output=self._build_raw_output(tests),
            )
        except Exception as e:
            log.error(f"Web cache poisoning validation error: {e}")
            return ValidationResult(
                validator=self.get_name(),
                status="error",
                finding_class=finding.vulnerability_class,
                confidence=0.0,
                confirmed=False,
                summary=f"Web cache poisoning validation failed: {e}",
                evidence="",
                raw_output=str(e),
            )

    async def _send(self, url: str, method: str = "GET", headers: dict | None = None) -> httpx.Response | None:
        headers = dict(headers or {})
        headers.setdefault("User-Agent", self.user_agent)
        try:
            if self.run_context is not None:
                from harness.run_context import TypedRequest
                outcome = await self.run_context.executor().execute(
                    TypedRequest(method, url, headers=headers),
                    capability=self.get_name(), max_redirects=self.max_redirects)
                if not outcome.ok:
                    return None
                return httpx.Response(
                    outcome.status or 0, content=(outcome.body or "").encode(),
                    headers=outcome.headers, request=httpx.Request(method, url))
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=False, max_redirects=self.max_redirects,
            ) as client:
                from harness import global_throttle
                await global_throttle.acquire()
                return await client.request(method, url, headers=headers)
        except Exception as e:
            log.debug(f"Request failed: {e}")
            return None

    async def _test_cacheability_signals(self, exchange: HttpExchange) -> CacheTestResult:
        """Passive-ish check on a fresh fetch of the original URL: is this endpoint cached at all?"""
        response = await self._send(exchange.url, method="GET")  # cacheability testing is GET-based; never replay the captured method
        if response is None:
            return CacheTestResult("Cacheability Signals", True, "low", "Could not fetch original URL", "", False)

        cc = response.headers.get("Cache-Control", "")
        found = [h for h in _CACHE_INDICATOR_HEADERS if h in {k.lower() for k in response.headers.keys()}]
        publicly_cacheable = "public" in cc.lower() or "s-maxage" in cc.lower()

        if publicly_cacheable or found:
            detail = f"Endpoint is cacheable (Cache-Control: {cc!r}, indicators: {found})"
            return CacheTestResult("Cacheability Signals", True, "info", detail,
                                    f"Cache-Control: {cc}; headers present: {found}", vulnerable=False)
        return CacheTestResult("Cacheability Signals", True, "low",
                                "No shared-cache indicators observed on this response", "", vulnerable=False)

    async def _test_unkeyed_host_header(self, exchange: HttpExchange) -> CacheTestResult:
        """Classic unkeyed-input probe: inject X-Forwarded-Host, check reflection, then re-request clean."""
        marker = "cache-poison-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + ".example"

        poisoned = await self._send(exchange.url, method="GET", headers={  # never replay the captured method
            "X-Forwarded-Host": marker,
            "X-Forwarded-Scheme": "https",
        })
        if poisoned is None:
            return CacheTestResult("Unkeyed Host Header", True, "low", "Could not send poisoning probe", "", False)

        reflected = marker in (poisoned.text or "") or marker in poisoned.headers.get("Location", "")
        if not reflected:
            return CacheTestResult("Unkeyed Host Header", True, "low",
                                    "X-Forwarded-Host not reflected in body or redirect Location", "", vulnerable=False)

        # Reflected -- now check persistence: re-request WITHOUT the injected header.
        # If the marker still comes back, this specific response is actually cached
        # and poisoned, not just reflected per-request.
        await asyncio.sleep(0.5)
        followup = await self._send(exchange.url, method="GET")  # never replay the captured method
        if followup is not None and marker in (followup.text or ""):
            return CacheTestResult(
                "Unkeyed Host Header", False, "critical",
                "X-Forwarded-Host was reflected AND persisted on a follow-up request that did not send it "
                "-- the poisoned response is being served from cache to other requests",
                f"Marker {marker} present in follow-up response without re-sending the header",
                vulnerable=True,
            )

        return CacheTestResult(
            "Unkeyed Host Header", False, "medium",
            "X-Forwarded-Host is reflected into the response (confirmed unkeyed-input influence), "
            "but did not persist on this follow-up -- either not cached, cached briefly, or this "
            "cache layer doesn't store single-request probes. Still worth checking with real traffic "
            "in front, since Age/Cache-Control indicate whether caching happens here at all.",
            f"Marker {marker} reflected in initial response but not in follow-up",
            vulnerable=True,
        )

    async def _test_cache_deception(self, exchange: HttpExchange) -> CacheTestResult:
        """Append a static-looking suffix to the path and compare to the original response."""
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(exchange.url)
        if not parsed.path or parsed.path == "/":
            return CacheTestResult("Web Cache Deception", True, "low", "No path segment to test", "", False)

        deceptive_path = parsed.path.rstrip("/") + "/nonexistent-cache-deception-probe.css"
        deceptive_url = urlunparse(parsed._replace(path=deceptive_path))

        response = await self._send(deceptive_url, method="GET")
        if response is None:
            return CacheTestResult("Web Cache Deception", True, "low", "Could not fetch deceptive path", "", False)

        cc = response.headers.get("Cache-Control", "")
        looks_cacheable = "public" in cc.lower() or "s-maxage" in cc.lower() or "age" in {k.lower() for k in response.headers}
        # A real deception bug requires the ORIGIN to still serve dynamic/real content
        # under the fake-static path, not a generic 404. A 200 with a non-trivial body
        # and cache-friendly headers is the signal; this can't fully confirm the body
        # is the *authenticated* page without a logged-in session, so this stays a
        # lower-confidence structural signal rather than a hard confirm.
        if response.status_code == 200 and looks_cacheable and len(response.text or "") > 200:
            return CacheTestResult(
                "Web Cache Deception", False, "medium",
                "Static-looking suffix appended to a dynamic path returns 200 with cache-friendly headers "
                "-- worth checking manually whether this actually served the real per-user content "
                "(this probe was unauthenticated, so it cannot confirm that part)",
                f"{deceptive_url} -> {response.status_code}, Cache-Control: {cc}",
                vulnerable=True,
            )
        return CacheTestResult(
            "Web Cache Deception", True, "low",
            f"Deceptive path returned {response.status_code}, not a deception pattern", "", vulnerable=False,
        )

    def _build_evidence(self, tests: list[CacheTestResult]) -> str:
        vulnerable = [t for t in tests if t.vulnerable]
        if not vulnerable:
            return "No web cache poisoning primitive confirmed"
        return " | ".join(f"{t.test_name}: {t.detail} ({t.severity})" for t in vulnerable)

    def _build_raw_output(self, tests: list[CacheTestResult]) -> str:
        import json
        return json.dumps([t.to_dict() for t in tests], indent=2)
