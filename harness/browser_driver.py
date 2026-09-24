"""
Headless-browser execution surface -- the dependency-guarded engine behind the
browser-driven XSS validator (A2).

Reflected-XSS confirmation from HTTP responses alone is a guess: you see your
payload echoed in the body and *infer* it would run. The only way to know it
actually executes is to load the page in a real browser and watch for the
script firing -- an alert dialog, a console message, a thrown error from your
injected handler. That's what Aikido's Selenium step did, and what this provides.

A real browser is a heavy, optional dependency, so this module is written so the
rest of the harness never hard-depends on it:

  - The engine (Playwright) is imported lazily, inside the methods that use it,
    never at module import. Importing this module is always safe.
  - `available()` reports whether an engine is actually usable, so callers
    (the validator) degrade to "skipped: no browser" instead of crashing when
    nothing is installed.
  - Everything is expressed against the small BrowserDriver protocol below, so
    tests inject a fake driver and the validator's whole decision logic is
    exercised with no browser present.

Navigation is GET-only. That used to be where policy stopped: only the initial
URL was scope-checked, and the captured identity's Authorization was handed to
the browser context wholesale (`extra_http_headers`), so it rode along on
*every* request the page went on to make -- a redirect, a cross-origin
subresource, a fetch the page's own JS fired -- none of which were re-checked
(R01). `PlaywrightDriver.visit` now intercepts EVERY request the browser makes
(navigation, redirects, subresources) through `evaluate_browser_request` below
and attaches credentials only to requests that land on the exact origin the
run navigated to. `evaluate_browser_request` and the cancel-signal helper are
pure stdlib code with no Playwright import, so the policy itself is fully
unit-tested with Playwright ABSENT; only `PlaywrightDriver.visit` touches the
real `playwright.async_api` module, and only inside its existing
try/except-guarded lazy import.
"""
from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable
from urllib.parse import urlsplit

from harness.run_context import ScopePolicy

log = logging.getLogger("harness.browser_driver")


# ---------------------------------------------------------------------------
# Per-request interception policy (PR-10 / R01) -- pure, no Playwright import.
# ---------------------------------------------------------------------------

# Schemes a browser-driven request may use. Fail closed: ws/wss, blob:,
# file:, data: (and anything else) are blocked outright, as a navigation or
# as a subresource.
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Playwright's `request.resource_type` values this driver forwards. Everything
# else -- "websocket", "eventsource", "media", "manifest", "texttrack",
# Playwright's "other" catch-all (what a download-style response typically
# surfaces as through routing, since there is no distinct "download"
# resource_type), and any resource_type this driver has never seen -- is
# blocked by NOT being in this allow-list. Fail-closed by construction.
_ALLOWED_RESOURCE_TYPES = frozenset({
    "document", "script", "xhr", "fetch", "image", "stylesheet", "font",
})


@dataclass(frozen=True)
class BrowserRequestDecision:
    """The outcome for one intercepted browser request."""
    allow: bool
    attach_credentials: bool
    reason: str


def evaluate_browser_request(*, url: str, method: str, resource_type: str,
                              is_navigation: bool, run_origin: str,
                              scope: ScopePolicy) -> "BrowserRequestDecision":
    """Decide whether one browser-driven request may proceed, and whether the
    captured identity's credentials (Authorization) may be attached to it.

    Pure and synchronous -- no Playwright, no I/O -- so it is exercised
    directly by unit tests and reused unchanged by the real interception
    handler in `PlaywrightDriver.visit`. FAIL CLOSED throughout: an
    unrecognised scheme, an unrecognised resource_type, or an out-of-scope
    origin blocks the request; credentials attach only when the request's
    origin is the exact origin the run navigated to (`run_origin`) -- never
    forwarded cross-origin, even to another in-scope host.
    """
    method_u = (method or "GET").upper()
    resource_type_l = (resource_type or "").lower()
    scheme = (urlsplit(url).scheme or "").lower()
    request_origin = ScopePolicy.origin_of(url)
    same_origin_as_run = request_origin == ScopePolicy.origin_of(run_origin)

    def blocked(reason: str) -> "BrowserRequestDecision":
        return BrowserRequestDecision(allow=False, attach_credentials=False, reason=reason)

    if scheme not in _ALLOWED_SCHEMES:
        return blocked(f"scheme '{scheme or url[:32]}' is not http/https")

    if resource_type_l not in _ALLOWED_RESOURCE_TYPES:
        return blocked(
            f"resource_type '{resource_type_l or '(unknown)'}' is not permitted "
            "(service worker / websocket / download-like / unrecognised types "
            "are conservatively blocked)")

    if not scope.in_scope(url):
        return blocked(f"origin '{request_origin}' is not in scope")

    if is_navigation:
        if method_u != "GET":
            return blocked(f"navigation method '{method_u}' is not GET")
    else:
        if method_u != "GET" and not same_origin_as_run:
            return blocked(
                f"non-GET subrequest to '{request_origin}' is not same-origin as "
                f"run origin '{run_origin}'")

    return BrowserRequestDecision(
        allow=True,
        attach_credentials=same_origin_as_run,
        reason=("in scope, same-origin -- credentials attached" if same_origin_as_run
                else "in scope, cross-origin -- no credentials attached"))


def is_cancelled(cancel) -> bool:
    """Normalises the two accepted cancel-signal shapes -- an `asyncio.Event`,
    or a zero-arg callable returning truthy -- into a plain bool. `None` means
    never cancelled. Stdlib-only, so the cancellation seam the route handler
    checks on every request is directly unit-testable without a browser."""
    if cancel is None:
        return False
    if isinstance(cancel, asyncio.Event):
        return cancel.is_set()
    if callable(cancel):
        return bool(cancel())
    return False


@dataclass
class ExecutionObservation:
    """What a page did when loaded: the signals that prove script execution."""
    url: str
    dialogs: list[str] = field(default_factory=list)     # alert/confirm/prompt messages
    console: list[str] = field(default_factory=list)     # console.log/info/... text
    page_errors: list[str] = field(default_factory=list)  # uncaught JS errors
    load_error: str = ""                                 # navigation itself failed

    def all_text(self) -> str:
        return "\n".join(self.dialogs + self.console + self.page_errors)


@runtime_checkable
class BrowserDriver(Protocol):
    async def visit(self, url: str, *, wait_ms: int = 1500,
                    headers: dict | None = None) -> ExecutionObservation:
        ...


def _extra_headers_and_cookies(headers: dict | None, url: str):
    """Split an identity's request headers into Playwright's two channels (R25):
    non-cookie headers go to extra_http_headers (carries Authorization), and the
    Cookie header is parsed into add_cookies() entries scoped to the URL host, so
    an AUTHENTICATED XSS sink is tested as that identity, not anonymously."""
    headers = headers or {}
    extra: dict = {}
    cookie_val = ""
    for k, v in headers.items():
        if (k or "").lower() == "cookie":
            cookie_val = v or ""
        elif k:
            extra[k] = v
    cookies: list[dict] = []
    if cookie_val:
        from urllib.parse import urlsplit
        host = urlsplit(url).hostname or ""
        for part in cookie_val.split(";"):
            if "=" in part:
                name, _, value = part.strip().partition("=")
                if name and host:
                    cookies.append({"name": name, "value": value, "domain": host, "path": "/"})
    return (extra or None), cookies


def playwright_available() -> bool:
    try:
        import playwright.async_api  # noqa: F401
        return True
    except Exception:
        return False


def available(cdp_endpoint: str | None = None) -> tuple[bool, str]:
    """(usable, reason). Reason names the missing piece so the operator knows
    exactly what to install. With a `cdp_endpoint` set the browser runs in a
    container and only the Playwright *client* library is needed on the host
    (no local browser binary) -- the host-cleanliness win, mirroring
    sqlmap-in-container."""
    if playwright_available():
        return True, ("playwright (over CDP -> containerised browser)"
                      if cdp_endpoint else "playwright")
    hint = ("`pip install playwright` (a browser container serves the engine over CDP)"
            if cdp_endpoint else "`pip install playwright && playwright install chromium`")
    return False, f"no headless browser engine available -- install one, e.g. {hint}"


def default_driver(cdp_endpoint: str | None = None) -> "BrowserDriver | None":
    """The best available real driver, or None when the Playwright client is not
    installed. Pass `cdp_endpoint` (e.g. ws://127.0.0.1:3000 from a browser
    container) to drive a containerised Chromium instead of launching one on the
    host."""
    if playwright_available():
        return PlaywrightDriver(cdp_endpoint=cdp_endpoint)
    return None


class PlaywrightDriver:
    """Playwright-backed driver. Navigates to the URL and records dialogs /
    console messages / page errors -- the observable evidence that injected
    script ran. Auto-dismisses dialogs so a blocking alert() can't hang the run.
    Everything Playwright is imported lazily.

    Two engine modes:
      - **local launch** (default): starts a headless Chromium on the host.
        Needs `playwright install chromium`.
      - **container over CDP** (`cdp_endpoint` set): connects to a Chromium
        already running in a container (e.g. the `browserless/chrome` image
        exposing CDP on ws://host:3000). Nothing but the Playwright client lib
        lands on the host -- the same host-cleanliness rationale as
        sqlmap-in-container. We own only the context/session we open, never the
        shared remote browser, so cleanup closes the context, not the browser."""

    def __init__(self, *, launch_timeout_ms: int = 10000, cdp_endpoint: str | None = None):
        self.launch_timeout_ms = launch_timeout_ms
        self.cdp_endpoint = cdp_endpoint or None

    async def visit(self, url: str, *, wait_ms: int = 1500,
                    headers: dict | None = None,
                    scope: "ScopePolicy | None" = None,
                    cancel: "asyncio.Event | Callable[[], bool] | None" = None,
                    ) -> ExecutionObservation:
        """Navigate to `url` and report what executed.

        `scope` is the run's approved-origin policy (PR-10 / R01): every
        request the browser makes -- navigation, redirects, subresources,
        fetch/XHR -- is checked against it via `evaluate_browser_request`
        through Playwright request interception, and credentials (the
        captured identity's Authorization, split out by
        `_extra_headers_and_cookies`) are attached only to requests on the
        exact origin `url` itself is on. When `scope` is omitted, the visit is
        conservatively restricted to that same origin -- a caller that does
        not pass a scope gets "same-origin only", never "everywhere".

        `cancel` (an `asyncio.Event` or a zero-arg callable) lets an in-flight
        visit be stopped cooperatively: once it reads cancelled, no further
        request is dispatched (each is aborted at the interception point) and
        navigation is skipped if it hasn't started yet.
        """
        obs = ExecutionObservation(url=url)
        if is_cancelled(cancel):
            obs.load_error = "cancelled before navigation"
            return obs
        run_origin = ScopePolicy.origin_of(url)
        effective_scope = scope if scope is not None else ScopePolicy(
            allowed_hosts=frozenset({ScopePolicy.host_of(url)}))
        try:
            from playwright.async_api import async_playwright
        except Exception as e:  # pragma: no cover - guarded by available()
            obs.load_error = f"playwright import failed: {e}"
            return obs
        try:
            async with async_playwright() as p:
                # Connect to a containerised browser over CDP, or launch locally.
                # We only ever close what we opened: for a connected (shared)
                # browser that means the context, never the remote process.
                connected = bool(self.cdp_endpoint)
                if connected:
                    browser = await p.chromium.connect_over_cdp(
                        self.cdp_endpoint, timeout=self.launch_timeout_ms)
                else:
                    browser = await p.chromium.launch(headless=True)
                context = None
                try:
                    # R25: load the page AS the supplied identity (auth headers +
                    # cookies), not anonymously, so authenticated XSS sinks are
                    # reachable. None -> anonymous, as before. R01: credentials
                    # are NO LONGER handed to the context wholesale via
                    # extra_http_headers (that projected Authorization onto
                    # every request the page went on to make, any origin). The
                    # context starts with none; the route handler below adds
                    # `_extra` back in per-request, only when
                    # evaluate_browser_request says the request is on the
                    # run's own origin.
                    _extra, _cookies = _extra_headers_and_cookies(headers, url)
                    context = await browser.new_context()

                    async def _handle_route(route, request):
                        if is_cancelled(cancel):
                            try:
                                await route.abort()
                            except Exception:
                                pass
                            return
                        decision = evaluate_browser_request(
                            url=request.url,
                            method=request.method,
                            resource_type=request.resource_type,
                            is_navigation=request.is_navigation_request(),
                            run_origin=run_origin,
                            scope=effective_scope)
                        if not decision.allow:
                            log.info("browser_driver: blocked %s %s (%s)",
                                     request.method, request.url, decision.reason)
                            try:
                                await route.abort()
                            except Exception:
                                pass
                            return
                        try:
                            if decision.attach_credentials and _extra:
                                merged_headers = dict(request.headers)
                                merged_headers.update(_extra)
                                await route.continue_(headers=merged_headers)
                            else:
                                await route.continue_()
                        except Exception:
                            pass

                    await context.route("**/*", _handle_route)

                    if _cookies:
                        try:
                            await context.add_cookies(_cookies)
                        except Exception:
                            pass
                    page = await context.new_page()

                    async def _on_dialog(dialog):
                        obs.dialogs.append(f"{dialog.type}:{dialog.message}")
                        try:
                            await dialog.dismiss()
                        except Exception:
                            pass

                    page.on("dialog", lambda d: __import__("asyncio").create_task(_on_dialog(d)))
                    page.on("console", lambda msg: obs.console.append(msg.text))
                    page.on("pageerror", lambda err: obs.page_errors.append(str(err)))

                    if is_cancelled(cancel):
                        obs.load_error = "cancelled before navigation"
                    else:
                        await page.goto(url, timeout=self.launch_timeout_ms, wait_until="load")
                        await page.wait_for_timeout(wait_ms)
                finally:
                    if context is not None:
                        try:
                            await context.close()
                        except Exception:
                            pass
                    # A locally-launched browser is ours to terminate; a
                    # connected one is only disconnected (never kill a shared
                    # container browser out from under other sessions).
                    try:
                        await browser.close()
                    except Exception:
                        pass
        except Exception as e:
            obs.load_error = f"{e.__class__.__name__}: {e}"
        return obs
