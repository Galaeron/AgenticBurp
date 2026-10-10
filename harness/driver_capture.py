"""
Driver-based request capture (LB-2) -- a discovery mode that loads a page in a
real headless browser and records the actual HTTP requests the page's own
JavaScript issues (XHR/fetch), not just the request the harness itself sent.

Why: every other discovery path in this harness only ever sees a request
*the harness constructed* -- a GET to a discovered URL, or a synthesized body
built from a guessed shape (role_crawl's `_synthesize_body`, a parsed HTML
<form>). A page whose JS assembles the real request at runtime -- e.g.
serializing a form into an XML document and POSTing it via `fetch()` with
`Content-Type: application/xml` -- has a shape no synthesizer invents and no
passive/HTML-only crawl observes. This module loads the page, lets its JS
run, and captures every XHR/fetch request the page actually issued (method,
URL, content-type, body, headers, and the response), turning each into the
same `HttpExchange` shape the rest of the harness already consumes -- so the
existing confirmation legs (xxe, file_upload, ssrf, ...) can fire against a
real JS-built request they would otherwise never see.

This module is a THIN wrapper, not a second browser engine: it imports only
`harness.browser_driver` (for the engine/driver -- `PlaywrightDriver.
capture_requests`, `default_driver`, `playwright_available`) and
`harness.models` is reached only indirectly via that driver. It deliberately
touches NEITHER `playwright.async_api` NOR `harness.role_crawl` itself:

  - Browser/context creation is NC-2's single-context-site invariant
    (test_browser_interception_gate.py): exactly one file -- browser_driver.py
    -- may call the Playwright engine/context-creation entrypoints (async
    playwright, chromium launch, connect-over-CDP, new-context). This module
    calls INTO `PlaywrightDriver.capture_requests` for that, never creates a
    context itself.
  - `RoleCrawlResult` is a plain dataclass with a public `.captured: list`
    field, so `discover()` below populates it by attribute, keeping this
    module free of a role_crawl dependency and role_crawl itself unmodified.

OFF by default. Gated by the `driver_capture.enabled` config flag
(harness/config.yaml), which also means "no caller in this codebase invokes
this module's entrypoints yet" -- today it is exercised only by its own
tests and the leg-verification fixture integration test. Wiring it into the
autonomous crawl loop is explicitly out of scope for LB-2.
"""
from __future__ import annotations

from typing import Any

from harness.browser_driver import CaptureObservation, default_driver, playwright_available

__all__ = ["CaptureObservation", "capture_requests", "discover", "playwright_available"]


async def capture_requests(url: str, *, wait_ms: int = 1500,
                            headers: dict | None = None,
                            scope: Any = None,
                            cancel: Any = None,
                            gate: Any = None,
                            budget: Any = None,
                            cdp_endpoint: str | None = None,
                            launch_timeout_ms: int = 10000,
                            max_captured: int = 50) -> CaptureObservation:
    """Load `url` in headless Chromium and capture the JS-issued XHR/fetch
    requests it makes, as `HttpExchange.model_dump()` dicts on the returned
    `CaptureObservation.exchanges`.

    A thin wrapper around `browser_driver.PlaywrightDriver.capture_requests`
    -- see that method's docstring for the full policy (scope/credentials/
    gate/budget, identical to `visit()`'s) and the single-context-site
    rationale for why the actual browser/context creation lives there, not
    here. When no Playwright engine is installed, returns a
    `CaptureObservation` with `load_error` set and an empty `exchanges` list
    (mirrors `browser_driver.ExecutionObservation`'s degrade-gracefully
    contract; check `playwright_available()` first to distinguish "no
    engine" from "navigation failed" if that matters to the caller).
    """
    driver = default_driver(cdp_endpoint=cdp_endpoint)
    if driver is None:
        obs = CaptureObservation(url=url)
        obs.load_error = "no headless browser engine available (playwright not installed)"
        return obs
    driver.launch_timeout_ms = launch_timeout_ms
    return await driver.capture_requests(
        url, wait_ms=wait_ms, headers=headers, scope=scope, cancel=cancel,
        gate=gate, budget=budget, max_captured=max_captured)


def _dedup_key(exchange: dict) -> tuple:
    return (exchange.get("method"), exchange.get("url"), exchange.get("request_body"))


async def discover(rc: Any, url: str, **kwargs) -> CaptureObservation:
    """Capture JS-issued requests from `url` and append each (deduped against
    what `rc.captured` already holds) to `rc.captured` -- the SAME list
    `RoleCrawlResult.captured` exposes, populated by attribute rather than by
    importing `harness.role_crawl` (see module docstring). `rc` only needs a
    `.captured: list` attribute; `**kwargs` forwards to `capture_requests`
    (wait_ms, headers, scope, cancel, gate, budget, cdp_endpoint,
    launch_timeout_ms, max_captured).

    This is the single landing point LB-2's acceptance criteria describe:
    "discovery captures the real shape ... feeds them into
    RoleCrawlResult.captured so the existing legs fire." Nothing beyond this
    (no orchestrator/crawl-loop wiring) is in scope for LB-2.
    """
    obs = await capture_requests(url, **kwargs)
    existing = {_dedup_key(e) for e in rc.captured}
    for ex in obs.exchanges:
        key = _dedup_key(ex)
        if key in existing:
            continue
        existing.add(key)
        rc.captured.append(ex)
    return obs
