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
the server, so if the payload's computed value shows when navigating `url#<payload>`, the
payload could only have reached a sink via CLIENT-SIDE code reading
`location.hash` -- proof of a DOM source->sink taint, not server reflection.

Same real-browser driver seam as browser_xss (Playwright/CDP, injectable fake in
tests), same computed-challenge oracle (RV-L L7: the payload alerts and logs
a*b, and only a console message or an alert/confirm/prompt dialog exactly equal
to the product confirms -- the dialog is RV-O O8, an owner decision of
2026-10-21; an echo or log of the fragment text cannot produce it, and any
other dialog or a page error is a candidate to check by hand, never a
negative), same safe posture: GET navigation only, scope-gated, throttled,
degrades to skipped when no browser is installed.
"""
from __future__ import annotations

import logging
import secrets
from urllib.parse import urlsplit, urlunsplit

from harness import global_throttle
from harness.models import Finding, HttpExchange
from .base import Validator, ValidationResult

log = logging.getLogger("harness.dom_xss_validator")


def _challenge() -> tuple[int, int, str]:
    """Two random six-digit operands and the text of their product. The payload
    carries `a*b`, never the product, so only evaluating it yields the product."""
    a, b = (100000 + secrets.randbelow(900000) for _ in range(2))
    return a, b, str(a * b)


def _fragment_payloads(a: int, b: int) -> list[str]:
    """Payloads that, if a client-side sink reads location.hash and writes it to
    an HTML/JS context, show the product a*b in an alert and then log it to the
    console (RV-O O8: a sink that lets only alert() run still shows it). Placed
    in the fragment, so they never reach the server."""
    js = f"alert({a}*{b});console.log({a}*{b})"
    return [
        f"<img src=x onerror={js}>",
        f"<svg onload={js}>",
        f"<script>{js}</script>",
        f"javascript:{js}",
        f"';{js};//",
        f"\"><img src=x onerror={js}>",
    ]


_DIALOG_TYPES = ("alert", "confirm", "prompt")


def _dialog_messages(obs) -> list[str]:
    """The message of each alert/confirm/prompt dialog the page raised (the
    driver records one as "type:message")."""
    out = []
    for entry in getattr(obs, "dialogs", None) or []:
        kind, sep, message = str(entry).partition(":")
        if sep and kind in _DIALOG_TYPES:
            out.append(message.strip())
    return out


def _unmatched_signal(obs) -> tuple[str, str]:
    """(note, detail) for a page that raised a dialog or a page error without
    the computed product -- a candidate to check by hand, never a negative
    (RV-O O8) -- or ("", "") when it raised neither."""
    if getattr(obs, "dialogs", None):
        return ("a dialog fired, but not with the computed value; check manually",
                f"dialog {str(obs.dialogs[0])[:120]!r}")
    if getattr(obs, "page_errors", None):
        return ("a page error was raised, but no computed value was shown; check manually",
                f"error {str(obs.page_errors[0])[:120]!r}")
    return "", ""


class DomXssValidator(Validator):
    name = "dom_xss"
    finding_classes = {"dom_xss", "dom xss", "dom-based xss", "dom based xss",
                       "dom-based cross-site scripting", "client-side xss",
                       "client side xss", "client-side cross-site scripting"}
    active = True  # drives a real browser -- gated by active_enabled

    def __init__(self, *, timeout: float = 15.0, allowed_hosts: list[str] | None = None,
                 wait_ms: int = 1200, max_visits: int = 8, driver=None,
                 cdp_endpoint: str | None = None, run_context=None):
        self.timeout = timeout
        self.allowed_hosts = allowed_hosts or []
        self.wait_ms = wait_ms
        self.max_visits = max_visits
        self.cdp_endpoint = cdp_endpoint or None
        self._driver = driver
        # R7: see browser_xss_validator's identical field -- bound per-dispatch
        # by ValidatorRegistry.bind_run_context, threaded into the browser's
        # request interception below so mid-visit redirects/subresources are
        # policed by this run's actual scope/gate/budget.
        self.run_context = run_context

    def _host_allowed(self, url: str) -> bool:
        if not self.allowed_hosts:
            return True
        host = (urlsplit(url).hostname or "").lower()
        return any(host == h.lower() or host.endswith("." + h.lower()) for h in self.allowed_hosts)

    def _candidate_urls(self, exchange: HttpExchange, a: int, b: int) -> list[str]:
        """One URL per payload: the captured URL (query preserved) with the
        payload placed in the FRAGMENT. The fragment is never sent to the server,
        so execution can only be client-side (DOM XSS)."""
        parts = urlsplit(exchange.url)
        urls: list[str] = []
        for pl in _fragment_payloads(a, b):
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

        a, b, expected = _challenge()
        urls = self._candidate_urls(exchange, a, b)
        errors: list[str] = []
        signal: tuple[str, str, str] | None = None  # (url, note, detail) of the first candidate
        # R7: only forwarded when a RunContext is bound -- see
        # browser_xss_validator's identical comment.
        from harness.run_context import current_run_context
        rc = self.run_context or current_run_context()  # I03: enclosing run if unbound
        visit_kw = (dict(scope=rc.scope, gate=rc.gate, budget=rc.budget, cancel=rc.cancel)
                    if rc is not None else {})
        for url in urls:
            await global_throttle.acquire()
            try:
                # R25: drive the browser AS the captured identity, not anonymously.
                obs = await driver.visit(url, wait_ms=self.wait_ms,
                                         headers=exchange.request_headers, **visit_kw)
            except Exception as e:
                errors.append(f"{url[:120]}: {e.__class__.__name__}")
                continue
            if getattr(obs, "load_error", None):
                errors.append(f"{url[:120]}: {obs.load_error}")
                continue
            # RV-L L7 / RV-O O8: an exact console message, or dialog message,
            # equal to the computed product. A page that logs or shows the
            # fragment text carries a*b, not the product, so it never confirms.
            if any(str(m).strip() == expected for m in obs.console):
                return ValidationResult(
                    validator=self.name, status="confirmed", finding_class="dom_xss",
                    confidence=0.95, confirmed=True,
                    summary=f"DOM-based XSS executed in a real browser at {url.split('#')[0]}",
                    evidence=(f"Payload placed in the URL FRAGMENT (never sent to the server) ran: the "
                              f"console logged {expected}, the product of {a}*{b}, which the payload "
                              f"computes but does not contain -- a client-side source (location.hash) "
                              f"flowed to a DOM sink. This is DOM-based XSS, not server reflection. "
                              f"URL: {url[:300]}"),
                    raw_output=obs.all_text()[:800])
            if expected in _dialog_messages(obs):
                return ValidationResult(
                    validator=self.name, status="confirmed", finding_class="dom_xss",
                    confidence=0.95, confirmed=True,
                    summary=(f"DOM-based XSS executed in a real browser at {url.split('#')[0]} "
                             f"(shown by a dialog only)"),
                    evidence=(f"Payload placed in the URL FRAGMENT (never sent to the server) ran: a "
                              f"browser dialog showed {expected}, the product of {a}*{b}, which the "
                              f"payload computes but does not contain -- a client-side source "
                              f"(location.hash) flowed to a DOM sink. Execution was shown by the "
                              f"dialog only, not by the console. URL: {url[:300]}"),
                    raw_output=obs.all_text()[:800])
            note, detail = _unmatched_signal(obs)
            if note and signal is None:
                signal = (url, note, detail)
        if signal is not None:
            url, note, detail = signal
            return ValidationResult(
                validator=self.name, status="inconclusive", finding_class="dom_xss",
                confidence=0.0, confirmed=False,
                summary=f"DOM-based XSS candidate, not confirmed: {note}",
                evidence=(f"Tried {len(urls)} fragment payload(s); neither the console nor a dialog "
                          f"showed the computed product {expected}. Loading {url[:300]}: {note} "
                          f"({detail})." + (f" Errors: {'; '.join(errors[:3])}" if errors else "")))
        status = "not_confirmed" if not errors or len(errors) < len(urls) else "error"
        return ValidationResult(
            validator=self.name, status=status, finding_class="dom_xss",
            confidence=0.0, confirmed=False,
            summary="No DOM-based script execution observed in a headless browser",
            evidence=(f"Tried {len(urls)} fragment payload(s); neither the console nor a dialog "
                      f"showed the computed product {expected}."
                      + (f" Errors: {'; '.join(errors[:3])}" if errors else "")))
