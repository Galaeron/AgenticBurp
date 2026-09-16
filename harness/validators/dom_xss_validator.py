"""
DOM-based XSS confirmation leg (V29, WSTG-CLNT-01).

browser_xss confirms SERVER-reflected execution: a payload in a query parameter
is echoed into the HTML the server returns and runs. It structurally cannot
confirm DOM-based XSS, where a client-side SOURCE (location.hash / .search /
document.referrer) flows to a dangerous SINK (innerHTML, document.write, eval,
jQuery .html()) entirely in the browser -- the server may never see the payload
at all.

This leg confirms exactly that, and unambiguously: it places the execution
payload in the URL FRAGMENT (after `#`). Browsers never transmit the fragment to
the server, so if the per-run nonce fires when navigating `url#<payload>`, the
payload could only have reached a sink via CLIENT-SIDE code reading
`location.hash` -- proof of a DOM source->sink taint, not server reflection.

Same real-browser driver seam as browser_xss (Playwright/CDP, injectable fake in
tests), same nonce-in-an-execution-sink oracle, same safe posture: GET navigation
only, scope-gated, throttled, degrades to skipped when no browser is installed.
"""
from __future__ import annotations

import logging
import secrets
from urllib.parse import urlsplit, urlunsplit

from harness import global_throttle
from harness.models import Finding, HttpExchange
from .base import Validator, ValidationResult

log = logging.getLogger("harness.dom_xss_validator")


def _fragment_payloads(nonce: str) -> list[str]:
    """Payloads that, if a client-side sink reads location.hash and writes it to
    an HTML/JS context, surface `nonce` via a console/dialog/error sink. Placed in
    the fragment, so they never reach the server."""
    js = f"console.log('{nonce}')"
    return [
        f"<img src=x onerror={js}>",
        f"<svg onload={js}>",
        f"<script>{js}</script>",
        f"javascript:{js}",
        f"';{js};//",
        f"\"><img src=x onerror={js}>",
    ]


class DomXssValidator(Validator):
    name = "dom_xss"
    finding_classes = {"dom_xss", "dom xss", "dom-based xss", "dom based xss",
                       "dom-based cross-site scripting", "client-side xss",
                       "client side xss", "client-side cross-site scripting"}
    active = True  # drives a real browser -- gated by active_enabled

    def __init__(self, *, timeout: float = 15.0, allowed_hosts: list[str] | None = None,
                 wait_ms: int = 1200, max_visits: int = 8, driver=None,
                 cdp_endpoint: str | None = None):
        self.timeout = timeout
        self.allowed_hosts = allowed_hosts or []
        self.wait_ms = wait_ms
        self.max_visits = max_visits
        self.cdp_endpoint = cdp_endpoint or None
        self._driver = driver

    def _host_allowed(self, url: str) -> bool:
        if not self.allowed_hosts:
            return True
        host = (urlsplit(url).hostname or "").lower()
        return any(host == h.lower() or host.endswith("." + h.lower()) for h in self.allowed_hosts)

    def _candidate_urls(self, exchange: HttpExchange, nonce: str) -> list[str]:
        """One URL per payload: the captured URL (query preserved) with the
        payload placed in the FRAGMENT. The fragment is never sent to the server,
        so execution can only be client-side (DOM XSS)."""
        parts = urlsplit(exchange.url)
        urls: list[str] = []
        for pl in _fragment_payloads(nonce):
            urls.append(urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, pl)))
        return urls[: self.max_visits]

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        driver = self._driver
        if driver is None:
            from harness import browser_driver
            driver = browser_driver.default_driver(cdp_endpoint=self.cdp_endpoint)
            if driver is None:
                _, reason = browser_driver.available(self.cdp_endpoint)
                return ValidationResult(
                    validator=self.name, status="skipped", finding_class="dom_xss",
                    summary="DOM XSS validation unavailable (no headless browser)", evidence=reason)

        if not exchange.url.startswith(("http://", "https://")):
            return ValidationResult(validator=self.name, status="skipped", finding_class="dom_xss",
                                    summary="unsupported URL scheme", evidence=exchange.url[:200])
        if not self._host_allowed(exchange.url):
            return ValidationResult(validator=self.name, status="skipped", finding_class="dom_xss",
                                    summary="target out of scope", evidence=urlsplit(exchange.url).hostname or "")

        nonce = "HARNESSDOM" + secrets.token_hex(8)
        urls = self._candidate_urls(exchange, nonce)
        errors: list[str] = []
        for url in urls:
            await global_throttle.acquire()
            try:
                # R25: drive the browser AS the captured identity, not anonymously.
                obs = await driver.visit(url, wait_ms=self.wait_ms,
                                         headers=exchange.request_headers)
            except Exception as e:
                errors.append(f"{url[:120]}: {e.__class__.__name__}")
                continue
            if getattr(obs, "load_error", None):
                errors.append(f"{url[:120]}: {obs.load_error}")
                continue
            if nonce in obs.all_text():
                sink = ("dialog" if any(nonce in d for d in obs.dialogs)
                        else "console" if any(nonce in c for c in obs.console)
                        else "page-error")
                return ValidationResult(
                    validator=self.name, status="confirmed", finding_class="dom_xss",
                    confidence=0.95, confirmed=True,
                    summary=f"DOM-based XSS executed in a real browser at {url.split('#')[0]}",
                    evidence=(f"Payload placed in the URL FRAGMENT (never sent to the server) fired the "
                              f"per-run nonce via the {sink} sink -- a client-side source (location.hash) "
                              f"flowed to a DOM sink. This is DOM-based XSS, not server reflection. "
                              f"URL: {url[:300]}"),
                    raw_output=obs.all_text()[:800])

        status = "not_confirmed" if not errors or len(errors) < len(urls) else "error"
        return ValidationResult(
            validator=self.name, status=status, finding_class="dom_xss",
            confidence=0.0, confirmed=False,
            summary="No DOM-based script execution observed in a headless browser",
            evidence=(f"Tried {len(urls)} fragment payload(s); the nonce never reached a "
                      f"dialog/console/error sink." + (f" Errors: {'; '.join(errors[:3])}" if errors else "")))
