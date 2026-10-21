"""
Browser-driven XSS validation -- A2.

Every other XSS signal in this harness is inferential: an agent sees a payload
reflected in a response and reasons that it *would* execute. This validator is
the one that actually checks, by loading candidate URLs in a real headless
browser and watching for the injected script to run. The payload alerts and
logs a*b for two random operands; only a console message, or an alert/confirm/
prompt dialog, exactly equal to the product confirms (RV-L L7; the dialog is
RV-O O8, an owner decision of 2026-10-21, so a sink that lets only alert() run
is not missed). The product appears nowhere in the payload, so a page that
echoes or logs the payload text, shows it in a dialog, or quotes it in an error
cannot produce it -- only evaluating the script can. Any other dialog, or a page
error, is a candidate to check by hand, never a negative. Reflection in the HTML
body does not confirm (that's what the inferential agents already do).

Bounded and safe:
  - GET navigation only, scope-gated to allowed_hosts (URLs are derived from the
    captured exchange's own parameters -- never a model-chosen destination), and
    each visit passes through the global request throttle.
  - The operands are fresh per validate() call (from `secrets`), so a page that
    happens to contain some number can't produce a false confirm.
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


def _challenge() -> tuple[int, int, str]:
    """Two random six-digit operands and the text of their product. The payload
    carries `a*b`, never the product, so only evaluating it yields the product."""
    a, b = (100000 + secrets.randbelow(900000) for _ in range(2))
    return a, b, str(a * b)


def _payloads(a: int, b: int) -> list[str]:
    """Execution payloads across the common reflection contexts. Each, if it
    runs, shows the product a*b in an alert and then logs it to the console."""
    # Every payload leads with a dialog: a dialog is the completion oracle used
    # by common XSS benchmark labs, and a sink that lets only alert() run (a
    # filter that strips the console call) still shows the product (RV-O O8).
    js = f"alert({a}*{b});console.log({a}*{b})"
    return [
        f"<script>{js}</script>",
        f"\"><script>{js}</script>",
        f"\"><img src=x onerror={js}>",
        f"<svg onload={js}>",
        f"';{js};//",
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


class BrowserXssValidator(Validator):
    name = "browser_xss"
    finding_classes = {"xss"}
    active = True  # executes payloads in a real browser -- gated by active_enabled

    def __init__(self, *, timeout: float = 15.0, allowed_hosts: list[str] | None = None,
                 wait_ms: int = 1200, max_visits: int = 8, driver=None,
                 cdp_endpoint: str | None = None, run_context=None):
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
        # R7: optional RunContext, bound per-dispatch by
        # ValidatorRegistry.bind_run_context (same seam every other active
        # validator uses -- see orchestrator_confirm.py's for_finding/
        # bind_run_context call). When present, its scope/gate/budget/cancel
        # are threaded into the browser's own request interception (SC-7), so
        # a redirect or subresource the payload triggers mid-visit is policed
        # by the SAME capability policy as every other outbound send in this
        # run, instead of falling back to the driver's same-origin-only
        # default with no gate/budget coverage at all.
        self.run_context = run_context

    def _host_allowed(self, url: str) -> bool:
        if not self.allowed_hosts:
            return True
        host = (urlsplit(url).hostname or "").lower()
        return any(host == h.lower() or host.endswith("." + h.lower()) for h in self.allowed_hosts)

    def _candidate_urls(self, exchange: HttpExchange, a: int, b: int) -> list[str]:
        """One URL per (query param, payload): the captured URL with a single
        parameter's value replaced by an execution payload. Bounded by
        max_visits. When the URL has no query params, the payloads are tried as
        a single synthetic `q` parameter so a bare reflected endpoint is still
        probed."""
        parts = urlsplit(exchange.url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        payloads = _payloads(a, b)
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

        a, b, expected = _challenge()
        urls = self._candidate_urls(exchange, a, b)
        errors: list[str] = []
        signal: tuple[str, str, str] | None = None  # (url, note, detail) of the first candidate
        # R7: forwarded only when a RunContext is actually bound -- omitted
        # entirely otherwise, so a standalone/no-context caller (and every
        # fake driver in the test suite, which doesn't accept these kwargs)
        # sees byte-identical behavior to before this wiring existed.
        # I03: fall back to the enclosing run when this instance was not bound.
        from harness.run_context import current_run_context
        rc = self.run_context or current_run_context()
        visit_kw = (dict(scope=rc.scope, gate=rc.gate, budget=rc.budget, cancel=rc.cancel)
                    if rc is not None else {})
        for url in urls:
            await global_throttle.acquire()
            try:
                # R25: drive the browser AS the captured identity (auth headers +
                # cookies), so an AUTHENTICATED reflected-XSS sink is reachable.
                obs = await driver.visit(url, wait_ms=self.wait_ms,
                                         headers=exchange.request_headers, **visit_kw)
            except Exception as e:  # a driver blowing up must not kill the whole pass
                errors.append(f"{url[:120]}: {e.__class__.__name__}")
                continue
            if obs.load_error:
                errors.append(f"{url[:120]}: {obs.load_error}")
                continue
            # RV-L L7 / RV-O O8: an exact console message, or dialog message,
            # equal to the computed product. A page that shows the payload's own
            # text carries a*b, never the product, so it cannot match.
            if any(str(m).strip() == expected for m in obs.console):
                return ValidationResult(
                    validator=self.name, status="confirmed", finding_class="xss",
                    confidence=0.95, confirmed=True,
                    summary=f"Reflected XSS executed in a real browser at {url.split('?')[0]}",
                    evidence=(f"Injected payload executed: the browser console logged {expected}, "
                              f"the product of {a}*{b}, which the payload computes but does not "
                              f"contain, when loading {url[:300]}"),
                    raw_output=obs.all_text()[:800])
            if expected in _dialog_messages(obs):
                return ValidationResult(
                    validator=self.name, status="confirmed", finding_class="xss",
                    confidence=0.95, confirmed=True,
                    summary=(f"Reflected XSS executed in a real browser at {url.split('?')[0]} "
                             f"(shown by a dialog only)"),
                    evidence=(f"Injected payload executed: a browser dialog showed {expected}, the "
                              f"product of {a}*{b}, which the payload computes but does not "
                              f"contain, when loading {url[:300]}. Execution was shown by the "
                              f"dialog only, not by the console."),
                    raw_output=obs.all_text()[:800])
            note, detail = _unmatched_signal(obs)
            if note and signal is None:
                signal = (url, note, detail)

        if signal is not None:
            url, note, detail = signal
            return ValidationResult(
                validator=self.name, status="inconclusive", finding_class="xss",
                confidence=0.0, confirmed=False,
                summary=f"Reflected XSS candidate, not confirmed: {note}",
                evidence=(f"Tried {len(urls)} candidate URL(s); neither the console nor a dialog "
                          f"showed the computed product {expected}. Loading {url[:300]}: {note} "
                          f"({detail})." + (f" Errors: {'; '.join(errors[:3])}" if errors else "")),
                raw_output="")
        status = "not_confirmed" if not errors or len(errors) < len(urls) else "error"
        return ValidationResult(
            validator=self.name, status=status, finding_class="xss",
            confidence=0.0, confirmed=False,
            summary="No script execution observed in a headless browser",
            evidence=(f"Tried {len(urls)} candidate URL(s); neither the console nor a dialog showed "
                      f"the computed product {expected}."
                      + (f" Errors: {'; '.join(errors[:3])}" if errors else "")),
            raw_output="")
