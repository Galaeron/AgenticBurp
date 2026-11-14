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

A hash-routed single-page app reads its input from a parameter INSIDE the
fragment route (`/#/route?term=`), so a payload that replaces the whole
fragment never reaches that code. The leg also places the payload in each
parameter of the URL's own fragment route and of each page route a crawled view
showed issuing the captured request (client_routes.py); for a history-routed
page it places the payload in the page's own query, and confirms DOM-based XSS
there only when the HTML document the server returned did not carry the
payload (otherwise it is server reflection, browser_xss's verdict). A captured
HTML page's own query parameters are location.search sources too: each one gets
the payload alone, under the same served-document rule.
"""
from __future__ import annotations
from harness import scope_lock

import logging
import secrets
from urllib.parse import urlsplit, urlunsplit

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.client_routes import PAGE, QUERY, ROUTE, SEGMENT, fragment_route
from .base import Validator, ValidationResult
from . import route_candidates
from .injection_targets import NAMED_PARAMETER_UNTESTED, tested_inputs
from .route_candidates import Candidate

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
        return scope_lock.host_in_scope(url, self.allowed_hosts)

    def _fragment_candidates(self, exchange: HttpExchange, a: int, b: int) -> list[Candidate]:
        """One candidate per payload: the captured URL (query preserved) with the
        payload as the whole FRAGMENT. The fragment is never sent to the server, so
        execution can only be client-side (DOM XSS). The fragment is encoded as the
        browser would encode it (route_candidates.browser_fragment), so the page
        sees the same location.hash and the driver can tell the URL's origin."""
        parts = urlsplit(exchange.url)
        return [Candidate(urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query,
                                      route_candidates.browser_fragment(pl))),
                          route_candidates.FRAGMENT, "", pl)
                for pl in _fragment_payloads(a, b)]

    def _candidate_urls(self, exchange: HttpExchange, a: int, b: int) -> list[str]:
        """The raw-fragment candidates' URLs, bounded by max_visits."""
        return [c.url for c in self._fragment_candidates(exchange, a, b)][: self.max_visits]

    def _candidates(self, exchange: HttpExchange, a: int, b: int, only: str | None,
                    location: str, run_context) -> list[Candidate]:
        """Every URL this validation loads, bounded by max_visits.

        A per-parameter dispatch tests its one input: a parameter in the fragment
        route (`route`), of the page's own query (`page`), or of the captured
        URL's query (`query`). The coverage driver's request-level remainder
        (`fragment`, every parameter case of the cell already tested alone) tests
        what no parameter case names: the raw fragment, and each page route a
        crawled view showed issuing this request. Otherwise the raw-fragment
        candidates are kept and taken in turn with the parameters of the URL's own
        fragment route, of its own query when the captured response is an HTML
        page, and of each mapped page route (client_routes.py). A hash-routed app
        reads its input from inside the route, so a payload that replaces the
        whole fragment only reaches a sink that reads the raw hash."""
        dom = route_candidates.dom_payloads(a, b)
        if only is not None and location == route_candidates.FRAGMENT:
            groups = [self._fragment_candidates(exchange, a, b)]
            groups += route_candidates.mapped_routes(exchange, dom, run_context)
            return route_candidates.interleave(groups, self.max_visits)
        if only is not None:
            return route_candidates.per_parameter(exchange.url, location, only, dom)[: self.max_visits]
        groups = [self._fragment_candidates(exchange, a, b)]
        groups += route_candidates.own_route(exchange.url, dom)
        if route_candidates.renders_script(exchange):
            groups += route_candidates.own_query(exchange.url, dom)
        groups += route_candidates.mapped_routes(exchange, dom, run_context)
        return route_candidates.interleave(groups, self.max_visits)

    @staticmethod
    def _executed(c: Candidate, how: str, expected: str, a: int, b: int) -> tuple[str, str]:
        """(summary, evidence) for a DOM-based execution `how` showed."""
        dialog_only = how == "dialog"
        shown = (f"a browser dialog showed {expected}" if dialog_only
                 else f"the console logged {expected}")
        tail = " (shown by a dialog only)" if dialog_only else ""
        dialog_note = (" Execution was shown by the dialog only, not by the console."
                       if dialog_only else "")
        product = (f"the product of {a}*{b}, which the payload computes but does not contain")
        if c.location == route_candidates.FRAGMENT:
            return (f"DOM-based XSS executed in a real browser at {c.url.split('#')[0]}{tail}",
                    f"Payload placed in the URL FRAGMENT (never sent to the server) ran: {shown}, "
                    f"{product} -- a client-side source (location.hash) flowed to a DOM sink. "
                    f"This is DOM-based XSS, not server reflection.{dialog_note} URL: {c.url[:300]}")
        if c.location == ROUTE:
            parts = urlsplit(c.url)
            page = (f"{parts.scheme}://{parts.netloc}{parts.path}"
                    f"#{parts.fragment.split('?', 1)[0]}")
            return (f"DOM-based XSS executed in a real browser via the fragment route parameter "
                    f"{c.parameter!r} at {page}{tail}",
                    f"Payload placed in {route_candidates.describe(c)} ran: {shown}, {product} -- "
                    f"page script read the route parameter from location.hash and wrote it to a "
                    f"DOM sink. This is DOM-based XSS, not server reflection.{dialog_note} "
                    f"URL: {c.url[:300]}")
        if c.location == SEGMENT:
            sent = route_candidates.segment_sent(c.url)
            source = "location.pathname" if sent else "location.hash"
            served = (" The HTML document the server returned did not carry the payload "
                      "verbatim." if sent else "")
            return (f"DOM-based XSS executed in a real browser via the route path segment "
                    f":{c.parameter} at {c.url[:200]}{tail}",
                    f"Payload placed in {route_candidates.describe(c)} ran: {shown}, {product} -- "
                    f"page script read the segment from {source} and wrote it to a DOM sink."
                    f"{served} This is DOM-based XSS, not server reflection.{dialog_note} "
                    f"URL: {c.url[:300]}")
        kind = "page query parameter" if c.location == PAGE else "query parameter"
        return (f"DOM-based XSS executed in a real browser via the {kind} "
                f"{c.parameter!r} at {c.url.split('?')[0]}{tail}",
                f"Payload placed in {route_candidates.describe(c)} ran: {shown}, {product}. The "
                f"HTML document the server returned did not carry the payload verbatim, so page "
                f"script read it from location.search and wrote it to a DOM sink: DOM-based XSS, "
                f"not server reflection.{dialog_note} URL: {c.url[:300]}")

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

        only, location = None, ""
        if getattr(finding, "parameter_only", False):
            # Per-parameter dispatch: test the named client-side route input alone,
            # so the verdict is bound to it. Any other input is not tested at all.
            only = (finding.parameter_name or "").strip()
            location = (finding.parameter_location or "").strip().lower()
            why = "is not a client-side route input of the replayed URL"
            if location == route_candidates.FRAGMENT:
                # The request-level remainder: the raw fragment names no parameter.
                reachable = True
            elif location == QUERY:
                reachable = bool(only) and only in route_candidates.query_names(exchange.url)
                if not reachable:
                    why = "is not a query parameter of the replayed URL"
                elif route_candidates.renders_script(exchange) is False:
                    # A JSON or plain-text answer runs no page script: nothing
                    # there reads location.search. The page that issued the
                    # call is tested through its route.
                    reachable = False
                    why = ("is answered with a document no page script runs in (not HTML), "
                           "so nothing there reads location.search")
            elif location == SEGMENT:
                reachable = bool(only) and only in route_candidates.segment_names(exchange.url)
                if not reachable:
                    why = "is not a path segment of the replayed URL's route"
            else:
                reachable = bool(only) and (
                    location == PAGE
                    or (location == ROUTE
                        and fragment_route(urlsplit(exchange.url).fragment) is not None))
            if not reachable:
                return ValidationResult(
                    validator=self.name, status="skipped", finding_class="dom_xss",
                    summary=(f"the {finding.parameter_location or 'unnamed'} parameter {only!r} "
                             f"{why}, so it was not tested"),
                    control_outcome=NAMED_PARAMETER_UNTESTED)
        tested = tested_inputs(finding, [only] if only is not None else [])

        a, b, expected = _challenge()
        # R7: only forwarded when a RunContext is bound -- see
        # browser_xss_validator's identical comment.
        from harness.run_context import current_run_context
        rc = self.run_context or current_run_context()  # I03: enclosing run if unbound
        candidates = self._candidates(exchange, a, b, only, location, rc)
        if not candidates:
            return ValidationResult(
                validator=self.name, status="skipped", finding_class="dom_xss",
                summary=f"no candidate URL places a payload in {location or 'an'} input {only!r}",
                control_outcome=NAMED_PARAMETER_UNTESTED)
        errors: list[str] = []
        signal: tuple[str, str, str] | None = None  # (url, note, detail) of the first candidate
        visit_kw = (dict(scope=rc.scope, gate=rc.gate, budget=rc.budget, cancel=rc.cancel)
                    if rc is not None else {})
        for c in candidates:
            url = c.url
            if not self._host_allowed(route_candidates.origin_of(url)):
                errors.append(f"{url[:120]}: out of scope")
                continue
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
            how = ("console" if any(str(m).strip() == expected for m in obs.console) else
                   "dialog" if expected in _dialog_messages(obs) else "")
            if how and (c.location in (PAGE, QUERY) or (
                    c.location == SEGMENT and route_candidates.segment_sent(c.url))):
                # The query (or a history route's path) reaches the server.
                # Execution is DOM-based only when the document the server
                # returned did not carry the payload.
                served = route_candidates.served_payload(obs, c.payload)
                if served is not False:
                    which = {PAGE: "page query", QUERY: "query"}.get(c.location, "page path")
                    if signal is None:
                        signal = (url, (f"the payload executed from the {which}, but the server "
                                        "returned it in the document (reflected XSS, browser_xss's "
                                        "verdict)" if served else
                                        f"the payload executed from the {which}, but the document "
                                        "the server returned was not kept, so a server reflection "
                                        "cannot be ruled out"),
                                  f"computed product {expected}")
                    continue
            if how:
                summary, evidence = self._executed(c, how, expected, a, b)
                return ValidationResult(
                    validator=self.name, status="confirmed", finding_class="dom_xss",
                    confidence=0.95, confirmed=True, summary=summary, evidence=evidence,
                    raw_output=obs.all_text()[:800], tested_parameters=tested)
            note, detail = _unmatched_signal(obs)
            if note and signal is None:
                signal = (url, note, detail)
        n = len(candidates)
        what = ("fragment payload(s)" if {c.location for c in candidates} == {route_candidates.FRAGMENT}
                else f"candidate URL(s){route_candidates.kinds(candidates)}")
        if signal is not None:
            url, note, detail = signal
            return ValidationResult(
                validator=self.name, status="inconclusive", finding_class="dom_xss",
                confidence=0.0, confirmed=False,
                summary=f"DOM-based XSS candidate, not confirmed: {note}",
                evidence=(f"Tried {n} {what}; neither the console nor a dialog showed the computed "
                          f"product {expected} from a client-side source. Loading {url[:300]}: "
                          f"{note} ({detail})."
                          + (f" Errors: {'; '.join(errors[:3])}" if errors else "")))
        status = "not_confirmed" if not errors or len(errors) < n else "error"
        return ValidationResult(
            validator=self.name, status=status, finding_class="dom_xss",
            confidence=0.0, confirmed=False,
            summary="No DOM-based script execution observed in a headless browser",
            evidence=(f"Tried {n} {what}; neither the console nor a dialog showed the computed "
                      f"product {expected}."
                      + (f" Errors: {'; '.join(errors[:3])}" if errors else "")),
            tested_parameters=tested if status == "not_confirmed" else ())
