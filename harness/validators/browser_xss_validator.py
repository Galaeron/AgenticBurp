"""
Browser-driven XSS validation -- A2.

Every other XSS signal in this harness is inferential: an agent sees a payload
reflected in a response and reasons that it *would* execute. This validator is
the one that actually checks, by loading candidate URLs in a real headless
browser and watching for the injected script to fire -- a dialog, a console
message, or a page error carrying a per-run nonce. Only the nonce actually
appearing in one of those execution sinks confirms; reflection in the HTML body
does not (that's what the inferential agents already do).

Bounded and safe:
  - GET navigation only, scope-gated to allowed_hosts (URLs are derived from the
    captured exchange's own parameters -- never a model-chosen destination), and
    each visit passes through the global request throttle.
  - The nonce is fresh per validate() call, so a page that happens to contain
    the literal word "alert" can't produce a false confirm.
  - Degrades cleanly: with no headless browser installed it returns
    status="skipped" naming what to install, never an error or a crash. The
    whole validator is exercised in tests via an injected fake driver.
"""
from __future__ import annotations
import logging
import secrets
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from harness import global_throttle
from harness.models import Finding, HttpExchange
from .base import Validator, ValidationResult

log = logging.getLogger("harness.browser_xss_validator")


def _payloads(nonce: str) -> list[str]:
    """Execution payloads across the common reflection contexts. Each, if it
    runs, surfaces `nonce` in a console message, dialog, or page error."""
    js = f"console.log('{nonce}')"
    return [
        f"<script>{js}</script>",
        f"\"><script>{js}</script>",
        f"\"><img src=x onerror={js}>",
        f"<svg onload={js}>",
        f"';{js};//",
        f"\"><script>alert('{nonce}')</script>",
    ]


class BrowserXssValidator(Validator):
    name = "browser_xss"
    finding_classes = {"xss"}
    active = True  # executes payloads in a real browser -- gated by active_enabled

    def __init__(self, *, timeout: float = 15.0, allowed_hosts: list[str] | None = None,
                 wait_ms: int = 1200, max_visits: int = 8, driver=None,
                 cdp_endpoint: str | None = None):
        self.timeout = timeout
        self.allowed_hosts = allowed_hosts or []
        self.wait_ms = wait_ms
        self.max_visits = max_visits
        # When set (e.g. ws://127.0.0.1:3000 from a browser container), the
        # engine is driven over CDP instead of launched on the host -- host
        # cleanliness, mirroring sqlmap-in-container. Default: local launch.
        self.cdp_endpoint = cdp_endpoint or None
        # An injected driver (tests / a custom engine) wins; otherwise the best
        # available real driver is resolved lazily at validate() time.
        self._driver = driver

    def _host_allowed(self, url: str) -> bool:
        if not self.allowed_hosts:
            return True
        host = (urlsplit(url).hostname or "").lower()
        return any(host == h.lower() or host.endswith("." + h.lower()) for h in self.allowed_hosts)

    def _candidate_urls(self, exchange: HttpExchange, nonce: str) -> list[str]:
        """One URL per (query param, payload): the captured URL with a single
        parameter's value replaced by an execution payload. Bounded by
        max_visits. When the URL has no query params, the payloads are tried as
        a single synthetic `q` parameter so a bare reflected endpoint is still
        probed."""
        parts = urlsplit(exchange.url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        payloads = _payloads(nonce)
        urls: list[str] = []
        if not params:
            for pl in payloads:
                q = urlencode([("q", pl)])
                urls.append(urlunsplit((parts.scheme, parts.netloc, parts.path, q, "")))
        else:
            for i in range(len(params)):
                for pl in payloads:
                    mutated = list(params)
                    mutated[i] = (params[i][0], pl)
                    q = urlencode(mutated)
                    urls.append(urlunsplit((parts.scheme, parts.netloc, parts.path, q, "")))
        return urls[: self.max_visits]

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        driver = self._driver
        if driver is None:
            from harness import browser_driver
            driver = browser_driver.default_driver(cdp_endpoint=self.cdp_endpoint)
            if driver is None:
                _, reason = browser_driver.available(self.cdp_endpoint)
                return ValidationResult(
                    validator=self.name, status="skipped", finding_class="xss",
                    summary="browser XSS validation unavailable", evidence=reason)

        if not exchange.url.startswith(("http://", "https://")):
            return ValidationResult(validator=self.name, status="skipped", finding_class="xss",
                                    summary="unsupported URL scheme", evidence=exchange.url[:200])
        if not self._host_allowed(exchange.url):
            return ValidationResult(validator=self.name, status="skipped", finding_class="xss",
                                    summary="target out of scope", evidence=urlsplit(exchange.url).hostname or "")

        nonce = "HARNESSXSS" + secrets.token_hex(8)
        urls = self._candidate_urls(exchange, nonce)
        errors: list[str] = []
        for url in urls:
            await global_throttle.acquire()
            try:
                # R25: drive the browser AS the captured identity (auth headers +
                # cookies), so an AUTHENTICATED reflected-XSS sink is reachable.
                obs = await driver.visit(url, wait_ms=self.wait_ms,
                                         headers=exchange.request_headers)
            except Exception as e:  # a driver blowing up must not kill the whole pass
                errors.append(f"{url[:120]}: {e.__class__.__name__}")
                continue
            if obs.load_error:
                errors.append(f"{url[:120]}: {obs.load_error}")
                continue
            if nonce in obs.all_text():
                sink = ("dialog" if any(nonce in d for d in obs.dialogs)
                        else "console" if any(nonce in c for c in obs.console)
                        else "page-error")
                return ValidationResult(
                    validator=self.name, status="confirmed", finding_class="xss",
                    confidence=0.95, confirmed=True,
                    summary=f"Reflected XSS executed in a real browser at {url.split('?')[0]}",
                    evidence=(f"Injected payload executed: the per-run nonce fired via the {sink} "
                              f"sink when loading {url[:300]}"),
                    raw_output=obs.all_text()[:800])

        status = "not_confirmed" if not errors or len(errors) < len(urls) else "error"
        return ValidationResult(
            validator=self.name, status=status, finding_class="xss",
            confidence=0.0, confirmed=False,
            summary="No script execution observed in a headless browser",
            evidence=(f"Tried {len(urls)} candidate URL(s); the injected nonce never reached a "
                      f"dialog/console/error sink." + (f" Errors: {'; '.join(errors[:3])}" if errors else "")),
            raw_output="")
