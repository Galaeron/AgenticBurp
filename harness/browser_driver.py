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
unit-tested with Playwright ABSENT; only `PlaywrightDriver.visit`, its LB-2
sibling `PlaywrightDriver.capture_requests` (request capture for discovery --
see harness/driver_capture.py), and its LB-5 sibling
`PlaywrightDriver.cross_site_submit` (a self-contained cross-site CSRF
browser PoC, with its own narrow `evaluate_cross_site_submit_request` policy
-- see harness/validators/csrf_validator.py) touch the real
`playwright.async_api` module, each only inside its own
try/except-guarded lazy import, and all three stay the ONLY browser/context
creation sites in this codebase (test_browser_interception_gate.py enforces
this: every other module, including driver_capture.py and csrf_validator.py,
must obtain a driver via this module's factory/methods rather than creating
its own).
"""
from __future__ import annotations
import asyncio
import html
import json
import logging
from dataclasses import dataclass, field
from typing import Callable, Protocol, TYPE_CHECKING, runtime_checkable
from urllib.parse import urljoin, urlsplit

from harness.run_context import ScopePolicy

if TYPE_CHECKING:  # pragma: no cover - type-checking only, no runtime import cost
    from harness.run_context import RequestBudget
    from harness.safety_gate import SafetyGate

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
                              scope: ScopePolicy,
                              gate: "SafetyGate | None" = None,
                              budget: "RequestBudget | None" = None,
                              ) -> "BrowserRequestDecision":
    """Decide whether one browser-driven request may proceed, and whether the
    captured identity's credentials (Authorization) may be attached to it.

    Pure and synchronous when `gate` and `budget` are both omitted (the
    default, and the case for every caller/test that predates SC-7) -- no
    Playwright, no I/O -- so it is exercised directly by unit tests and reused
    unchanged by the real interception handler in `PlaywrightDriver.visit`.
    FAIL CLOSED throughout: an unrecognised scheme, an unrecognised
    resource_type, or an out-of-scope origin blocks the request; credentials
    attach only when the request's origin is the exact origin the run
    navigated to (`run_origin`) -- never forwarded cross-origin, even to
    another in-scope host.

    `gate`/`budget` (SC-7, opt-in): when a `gate` is supplied, a same-origin
    MUTATING (non-GET) subrequest is additionally routed through it, mirroring
    the scope -> gate -> budget order `TargetTransport.execute` enforces for
    every other outbound send -- so browser-originated mutating traffic no
    longer bypasses the run's single RunContext capability policy. A GET
    request never consults the gate: the `scope` ScopePolicy above remains the
    single scope authority for the browser plane, and the gate only adds the
    mutation decision on top of it. When a `budget` is supplied, it is
    reserved (1 unit) as the LAST step, only for a request that is otherwise
    allowed -- a request blocked by scheme/resource_type/scope/method/gate
    NEVER reserves budget. This makes the function SIDE-EFFECTFUL (it reserves
    budget) ONLY when `budget` is passed; with `gate=None, budget=None` (every
    call site before SC-7) it stays pure and is BYTE-FOR-BYTE
    behavior-identical to before these two parameters existed.
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

    # SC-7: mirror TargetTransport.execute's scope -> gate -> budget order.
    # Everything above is a scope/method/shape check; from here on the request
    # is otherwise allowed, so the gate (mutating methods only) and then the
    # budget (any allowed request) get the final say -- in that order, so a
    # gate-denied request never reserves budget.
    if gate is not None and method_u != "GET":
        gate_decision = gate.authorize(validator_name="browser", method=method_u, url=url)
        if not gate_decision.allowed:
            return blocked(f"gate denied browser {method_u}: {gate_decision.reason}")

    if budget is not None and not budget.reserve(1):
        return blocked("browser request budget exhausted")

    return BrowserRequestDecision(
        allow=True,
        attach_credentials=same_origin_as_run,
        reason=("in scope, same-origin -- credentials attached" if same_origin_as_run
                else "in scope, cross-origin -- no credentials attached"))


# ---------------------------------------------------------------------------
# Cross-site browser PoC primitive (LB-5) -- pure route-policy half, no
# Playwright import. A SEPARATE, narrower policy from evaluate_browser_request
# above: that one governs an entire run's approved-origin browsing (any
# number of same-/cross-origin requests over the run's lifetime, credentials
# attached by origin match). This one governs exactly ONE
# PlaywrightDriver.cross_site_submit() call, which by construction permits
# exactly THREE requests and nothing else:
#   1. the synthesized "attacker" page -- never dispatched to the network at
#      all; FULFILLED locally by cross_site_submit with no real DNS/connect,
#      so `attacker_url` can be any placeholder hostname (on a different SITE
#      than the victim) without needing a second real HTTP host.
#   2. the one declared cross-origin state-changing request to `victim_url` --
#      allowed through to the real network UNCHANGED (no header added or
#      removed). The browser's OWN cookie jar + SameSite logic -- not this
#      policy -- decides whether the ambient session cookie rides along; the
#      whole point of the primitive is to observe what a real browser does
#      with real credentials, not to simulate or control that decision.
#   3. the GET-only independent readback at `readback_url`.
# Anything else -- a different URL, a subresource, a non-matching method, a
# non-navigation request, a redirect to an undeclared target -- fails closed
# (aborted). Authorization is never attached by this policy or by
# cross_site_submit at any point: the only identity channel an attacker-
# controlled cross-site page actually has is whatever the browser's cookie
# jar decides to send on its own, so that is the only channel this primitive
# exercises.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrossSitePlan:
    """The exact, single-use set of requests ONE cross_site_submit() call
    permits. Built fresh per call from the caller's declared URLs -- never
    shared across calls, never widened after construction."""
    attacker_url: str
    victim_url: str
    victim_method: str
    readback_url: str


@dataclass(frozen=True)
class CrossSiteRequestDecision:
    """The outcome for one request the cross-site-submit route handler sees."""
    allow: bool
    fulfill_locally: bool
    reason: str


def evaluate_cross_site_submit_request(*, url: str, method: str, resource_type: str,
                                        is_navigation: bool, plan: CrossSitePlan,
                                        ) -> CrossSiteRequestDecision:
    """Pure, synchronous, no Playwright/I/O -- decide one request against a
    CrossSitePlan. FAIL CLOSED: only the plan's three EXACT (method, url)
    pairs are permitted, and only as top-level navigations
    (`is_navigation=True`) of a "document" resource_type -- never a
    subresource, a redirect-chain hop to a different URL, or any other
    method. `fulfill_locally=True` only for the attacker page: the caller
    MUST answer it with `route.fulfill(...)` (synthesized content), never
    `route.continue_()` (which would attempt a real network fetch this
    primitive neither needs nor controls)."""
    method_u = (method or "GET").upper()
    resource_type_l = (resource_type or "").lower()
    scheme = (urlsplit(url).scheme or "").lower()

    def blocked(reason: str) -> CrossSiteRequestDecision:
        return CrossSiteRequestDecision(allow=False, fulfill_locally=False, reason=reason)

    if scheme not in _ALLOWED_SCHEMES:
        return blocked(f"scheme '{scheme or url[:32]}' is not http/https")
    if not is_navigation:
        return blocked("only this call's declared top-level navigations are permitted (no subresources)")
    if resource_type_l != "document":
        return blocked(f"resource_type '{resource_type_l or '(unknown)'}' is not a navigation document")

    if url == plan.attacker_url and method_u == "GET":
        return CrossSiteRequestDecision(
            allow=True, fulfill_locally=True,
            reason="the synthesized attacker page -- fulfilled locally, never sent to the network")

    if url == plan.victim_url and method_u == plan.victim_method.upper():
        return CrossSiteRequestDecision(
            allow=True, fulfill_locally=False,
            reason="the one declared cross-site submission -- allowed through unchanged; the "
                   "browser's own cookie jar/SameSite logic decides credential delivery")

    if url == plan.readback_url and method_u == "GET":
        return CrossSiteRequestDecision(
            allow=True, fulfill_locally=False, reason="GET-only independent readback")

    return blocked(f"{method_u} {url} is not one of this call's three declared requests")


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
    # I03: run_context.CancelToken (what validators and engagement discovery
    # pass) is neither an Event nor callable; it used to read as never cancelled.
    if hasattr(cancel, "cancelled"):
        return bool(cancel.cancelled)
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


@dataclass
class CrossSiteSubmitObservation:
    """What one PlaywrightDriver.cross_site_submit() call observed. `submitted`
    is True once the declared cross-site request was allowed through this
    call's OWN CrossSitePlan policy and the browser actually navigated to
    it -- it says nothing about whether the victim server accepted it (see
    `submit_status`) or whether the ambient cookie was actually delivered
    (that is exactly what the independent GET-only readback below exists to
    show, rather than trusting the POST's own response)."""
    attacker_url: str
    victim_url: str
    readback_url: str
    submitted: bool = False
    submit_status: int | None = None
    readback_status: int | None = None
    readback_body: str = ""
    load_error: str = ""


@dataclass
class CaptureObservation:
    """What one driver-backed request-CAPTURE visit produced (LB-2) -- distinct
    from ExecutionObservation (visit()'s dialog/console/error evidence that
    script EXECUTED). This instead records the actual XHR/fetch requests the
    page's own JS issued -- method, URL, headers, body, and response -- as
    `HttpExchange(...).model_dump()` dicts, for discovery (harness.driver_capture
    consumes this)."""
    url: str
    exchanges: list = field(default_factory=list)
    load_error: str = ""


# Playwright resource_type values that represent a request the PAGE's own JS
# issued (fetch()/XMLHttpRequest) -- as opposed to the navigation document
# itself or a passive subresource (image/stylesheet/font/script). These are
# exactly the requests a passive/HTML-only crawl can never see the real shape
# of, which is what `PlaywrightDriver.capture_requests` below exists to capture.
_JS_ISSUED_RESOURCE_TYPES = frozenset({"xhr", "fetch"})


@runtime_checkable
class BrowserDriver(Protocol):
    async def visit(self, url: str, *, wait_ms: int = 1500,
                    headers: dict | None = None) -> ExecutionObservation:
        ...


def _extra_headers_and_cookies(headers: dict | None, url: str):
    """Split an identity's request headers into its non-cookie headers (carries
    Authorization) and its cookies, parsed into add_cookies()-shaped entries for
    the URL host (R25), so an AUTHENTICATED XSS sink is tested as that identity,
    not anonymously. I05-D: neither goes to the browser any more; _IdentityRouter
    adds both to the requests it sends to the exact run origin."""
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


# ---------------------------------------------------------------------------
# I05-D: the captured identity never enters the browser.
#
# Playwright's route is not a complete boundary. It never sees a redirect hop
# (Playwright continues each hop itself and re-applies the route's header
# overrides to it), a speculation-rules prefetch, or service-worker traffic;
# and a Cookie override is silently dropped, so identity cookies could only
# travel in the context's jar, which scopes a cookie to the host (any port,
# either scheme). Reproduced with owned servers: one redirect carried the
# run's Authorization to an out-of-scope host, and the run's cookie reached
# another port of the same host through a subresource, frame, popup or
# prefetch.
#
# `_IdentityRouter` therefore sends every request the policy allows ITSELF,
# through the run's pinned client (AddressPins and the run's TLS policy, as
# every other send in the run), and fulfills the browser with the answer. The
# identity's headers and cookies are added there, only for the exact run
# origin; the browser holds none. A redirect answer comes back to the router
# instead of being followed out of sight: each hop is checked by
# evaluate_browser_request, a navigation hop is re-issued as a fresh routed
# navigation, and a subresource hop is followed and accounted here. (Sending
# everything also keeps Chromium's private-network checks out of the way: a
# fulfilled document has no address space of its own, so Chromium refused its
# native requests to a loopback or private target.) A locally launched
# Chromium also resolves only in-scope names, each to the run's pinned address
# (--host-resolver-rules), which bounds what the browser still sends on its own
# (prefetches the route never sees) and refuses special-purpose answers. A
# browser connected over CDP cannot take launch flags, so it has the routed
# boundary only.
# ---------------------------------------------------------------------------

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECT_HOPS = 10
# Request headers the router does not copy from the browser's request when it
# sends that request itself (connection-level, or rebuilt by the router).
_UNFORWARDED_REQUEST_HEADERS = frozenset({
    "host", "connection", "keep-alive", "proxy-connection", "upgrade", "te", "trailer",
    "transfer-encoding", "content-length", "accept-encoding", "cookie"})
# Response headers that no longer describe the decoded body handed to fulfill().
_UNFORWARDED_RESPONSE_HEADERS = frozenset({
    "content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"})


def _redirect_method(status: int, method: str) -> str:
    return "GET" if status == 303 or (status in (301, 302) and method == "POST") else method


def _scope_hosts(scope) -> list[str]:
    """The exact hosts a scope admits (wildcard/network entries grant the browser
    nothing: it cannot pin a name it does not know)."""
    from harness.scope_lock import configured_entries, parse_scope_entry
    raw = getattr(scope, "hosts", None) or getattr(scope, "allowed_hosts", None) or ()
    hosts = []
    for value in configured_entries(raw):
        entry = parse_scope_entry(value) if isinstance(value, str) else None
        if entry is not None and entry.host and entry.network is None and not entry.subdomains:
            hosts.append(entry.host)
    return hosts


def _cookie_pair(set_cookie: str) -> tuple[str, str, bool]:
    """(name, value, deletes) for one Set-Cookie header value."""
    pair, _, attrs = set_cookie.partition(";")
    name, _, value = pair.partition("=")
    attrs_l = attrs.lower().replace(" ", "")
    return name.strip(), value.strip(), not value.strip() or "max-age=0" in attrs_l


def _same_cookie_host(url: str, other: str) -> bool:
    """Cookies are filed by host (any port), so fulfill() may hand the browser a
    Set-Cookie only from the requested URL's own host."""
    return ScopePolicy.host_of(url) == ScopePolicy.host_of(other)


async def _quietly(awaitable) -> None:
    try:
        await awaitable
    except Exception:
        pass


class _IdentityRouter:
    """The route handler, browser launch flags and main-frame navigation shared
    by `visit` and `capture_requests` (I05-D; see the block comment above)."""

    def __init__(self, *, url: str, headers: dict | None, scope: ScopePolicy,
                 cancel, gate, budget, timeout_s: float, label: str):
        from harness.run_context import AddressPins, current_run_context
        from harness.tls_policy import TLSPolicy
        self.run_origin = ScopePolicy.origin_of(url)
        self.scope, self.cancel, self.gate, self.budget = scope, cancel, gate, budget
        self.timeout_s = timeout_s
        self.label = label
        extra, cookies = _extra_headers_and_cookies(headers, url)
        self.identity_headers = {k.lower(): v for k, v in (extra or {}).items()}
        self.identity_cookies = {c["name"]: c["value"] for c in cookies}
        # Inside a run: the run's pins (None when the run opted out) and trust.
        # Standalone: pins of its own, so special-purpose answers are refused.
        rc = current_run_context()
        self.pins = rc.address_pins if rc is not None else AddressPins()
        self.tls = rc.tls_policy if rc is not None else TLSPolicy.from_config()
        self._clients: dict = {}
        self.context = None
        self.page = None
        self._driving = False
        self._main_hop: str | None = None

    async def launch_args(self) -> list[str]:
        """Chromium resolves only in-scope names, each to its run-pinned address."""
        from harness.run_context import _is_ip_literal
        maps, excluded = [], []
        for host in sorted({ScopePolicy.host_of(self.run_origin), *_scope_hosts(self.scope)} - {""}):
            if _is_ip_literal(host) or self.pins is None:
                excluded.append(f"[{host}]" if ":" in host else host)
                continue
            try:
                ip = await self.pins.address_for(host)
            except Exception as e:   # unresolvable or refused: unreachable here too
                log.info("%s: %s not mapped for the browser (%s)", self.label, host, e)
                continue
            maps.append(f"MAP {host} {f'[{ip}]' if ':' in ip else ip}")
        rules = maps + ["MAP * ~NOTFOUND"] + [f"EXCLUDE {h}" for h in excluded]
        return [f"--host-resolver-rules={', '.join(rules)}"]

    async def install(self, context) -> None:
        self.context = context
        await context.route("**/*", self.handle)

    async def goto(self, page, url: str, timeout_ms: int) -> None:
        """Navigate the main frame; a redirect hop is re-issued here as a fresh
        (routed) navigation instead of being followed by the browser."""
        self.page = page
        target = url
        self._driving = True
        try:
            for _ in range(_MAX_REDIRECT_HOPS + 1):
                self._main_hop = None
                await page.goto(target, timeout=timeout_ms, wait_until="load")
                if self._main_hop is None:
                    return
                target = self._main_hop
            raise RuntimeError(f"more than {_MAX_REDIRECT_HOPS} redirects")
        finally:
            self._driving = False

    async def aclose(self) -> None:
        for client in self._clients.values():
            await _quietly(client.aclose())
        self._clients.clear()

    def _decide(self, url: str, method: str, resource_type: str, is_navigation: bool,
                *, account: bool) -> BrowserRequestDecision:
        return evaluate_browser_request(
            url=url, method=method, resource_type=resource_type, is_navigation=is_navigation,
            run_origin=self.run_origin, scope=self.scope,
            gate=self.gate if account else None, budget=self.budget if account else None)

    async def handle(self, route, request) -> None:
        if is_cancelled(self.cancel):
            await _quietly(route.abort())
            return
        is_navigation = request.is_navigation_request()
        decision = self._decide(request.url, request.method, request.resource_type,
                                is_navigation, account=True)
        if not decision.allow:
            log.info("%s: blocked %s %s (%s)", self.label, request.method, request.url,
                     decision.reason)
            await _quietly(route.abort())
            return
        try:
            await self._send_and_fulfill(route, request, is_navigation)
        except Exception as e:
            log.info("%s: %s %s not sent (%s: %s)", self.label, request.method, request.url,
                     e.__class__.__name__, e)
            await _quietly(route.abort())

    async def _send_and_fulfill(self, route, request, is_navigation: bool) -> None:
        url, method = request.url, request.method.upper()
        resource_type = request.resource_type
        headers = dict(request.headers)
        body = request.post_data_buffer
        # Cookies set along a subresource redirect this router follows: sent on
        # later hops to the same host, and handed to the browser only when set
        # by the requested URL's own host, the final answer's included
        # (fulfill() files every Set-Cookie under that host).
        hop_cookies: dict = {}
        hop_set_cookies: list = []
        for _ in range(_MAX_REDIRECT_HOPS + 1):
            response = await self._send(url, method, headers, body, hop_cookies)
            fulfilled = self._response_headers(response, url)
            location = response.headers.get("location")
            if response.status_code not in _REDIRECT_STATUSES or not location:
                final = fulfilled.pop("set-cookie", "")
                if not _same_cookie_host(url, request.url):
                    final = ""
                if hop_set_cookies or final:
                    fulfilled["set-cookie"] = "\n".join(hop_set_cookies + ([final] if final else []))
                await route.fulfill(status=response.status_code, headers=fulfilled,
                                    body=response.content)
                return
            next_url, next_method = urljoin(url, location), _redirect_method(response.status_code, method)
            if is_navigation:
                # Checked here; accounted when the browser re-issues it as a navigation.
                hop = self._decide(next_url, next_method, resource_type, True, account=False)
                if not hop.allow:
                    log.info("%s: blocked redirect %s -> %s (%s)", self.label, url, next_url,
                             hop.reason)
                    await route.abort()
                    return
                await self._fulfill_navigation_hop(route, request, fulfilled, next_url)
                return
            hop = self._decide(next_url, next_method, resource_type, False, account=True)
            if is_cancelled(self.cancel) or not hop.allow:
                log.info("%s: blocked redirect %s -> %s (%s)", self.label, url, next_url,
                         hop.reason)
                await route.abort()
                return
            host = ScopePolicy.host_of(url)
            for value in fulfilled.get("set-cookie", "").split("\n"):
                if not value:
                    continue
                name, cookie_value, deletes = _cookie_pair(value)
                jar = hop_cookies.setdefault(host, {})
                jar.pop(name, None) if deletes else jar.__setitem__(name, cookie_value)
                if _same_cookie_host(url, request.url):
                    hop_set_cookies.append(value)
            if next_method != method:
                body = None
                headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
            url, method = next_url, next_method
        await route.abort()

    async def _send(self, url: str, method: str, request_headers: dict, body, hop_cookies: dict):
        """One request the browser asked for, sent through the run's pinned
        client. The identity's headers and cookies go only to the exact run origin."""
        from harness.run_context import _target_client
        exact = ScopePolicy.origin_of(url) == self.run_origin
        headers = {k: v for k, v in request_headers.items()
                   if k.lower() not in _UNFORWARDED_REQUEST_HEADERS and not k.startswith(":")}
        headers["accept-encoding"] = "gzip, deflate"   # a body the client always decodes
        cookies = dict(self.identity_cookies) if exact else {}
        try:
            jar = await self.context.cookies([url])
        except Exception:
            jar = []
        cookies.update({c["name"]: c["value"] for c in jar})
        cookies.update(hop_cookies.get(ScopePolicy.host_of(url), {}))
        if cookies:
            headers["cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if exact:
            headers.update(self.identity_headers)
        profile = self.tls.profile_for(url)
        client = self._clients.get(profile.pool_key)
        if client is None:
            client = self._clients[profile.pool_key] = _target_client(
                verify=profile.context, timeout=self.timeout_s, http2=False, pins=self.pins)
        client.cookies.clear()   # the browser's jar is the only cookie store
        return await client.send(client.build_request(method, url, headers=headers,
                                                      content=body or None))

    def _response_headers(self, response, url: str) -> dict:
        """Response headers for fulfill(). The identity's own cookie, re-issued by
        the run origin, updates the identity and stays out of the browser's jar."""
        exact = ScopePolicy.origin_of(url) == self.run_origin
        out: dict = {}
        for key, value in response.headers.multi_items():
            k = key.lower()
            if k in _UNFORWARDED_RESPONSE_HEADERS:
                continue
            if k == "set-cookie" and exact:
                name, cookie_value, deletes = _cookie_pair(value)
                if name in self.identity_cookies:
                    if deletes:
                        self.identity_cookies.pop(name)
                    else:
                        self.identity_cookies[name] = cookie_value
                    continue
            out[k] = f"{out[k]}{chr(10) if k == 'set-cookie' else ', '}{value}" if k in out else value
        return out

    async def _fulfill_navigation_hop(self, route, request, fulfilled: dict, next_url: str) -> None:
        """Answer a redirected navigation with a page that leads to `next_url` as a
        new navigation, so the hop is routed (checked, accounted, credentialed only
        on the run origin). The driver's own main-frame load follows it in goto()."""
        headers = {"content-type": "text/html; charset=utf-8", "cache-control": "no-store"}
        if "set-cookie" in fulfilled:
            headers["set-cookie"] = fulfilled["set-cookie"]
        main_frame = False
        try:
            main_frame = (self._driving and self.page is not None
                          and request.frame == self.page.main_frame)
        except Exception:
            pass
        if main_frame:
            self._main_hop = next_url
            body = "<!doctype html><title>redirect</title>"
        else:
            target = json.dumps(next_url).replace("<", "\\u003c")
            body = f"<!doctype html><script>location.replace({target})</script>"
        await route.fulfill(status=200, headers=headers, body=body)


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
                    gate: "SafetyGate | None" = None,
                    budget: "RequestBudget | None" = None,
                    ) -> ExecutionObservation:
        """Navigate to `url` and report what executed.

        `scope` is the run's approved-origin policy (PR-10 / R01): every
        request the browser makes -- navigation, redirects, subresources,
        fetch/XHR -- is checked against it via `evaluate_browser_request`
        through Playwright request interception, and credentials (the
        captured identity's Authorization and cookies, split out by
        `_extra_headers_and_cookies`) are attached only to requests on the
        exact origin `url` itself is on -- by `_IdentityRouter`, which sends
        every allowed request itself (I05-D). When `scope` is omitted, the visit is
        conservatively restricted to that same origin -- a caller that does
        not pass a scope gets "same-origin only", never "everywhere".

        `cancel` (an `asyncio.Event` or a zero-arg callable) lets an in-flight
        visit be stopped cooperatively: once it reads cancelled, no further
        request is dispatched (each is aborted at the interception point) and
        navigation is skipped if it hasn't started yet.

        `gate`/`budget` (SC-7, opt-in, default None): threaded straight
        through to `evaluate_browser_request` for every intercepted request,
        unchanged otherwise. Omitting both (every caller today) keeps this
        method's behavior exactly as before they existed.
        """
        obs = ExecutionObservation(url=url)
        if is_cancelled(cancel):
            obs.load_error = "cancelled before navigation"
            return obs
        effective_scope = scope if scope is not None else ScopePolicy(
            allowed_hosts=frozenset({ScopePolicy.host_of(url)}))
        try:
            from playwright.async_api import async_playwright
        except Exception as e:  # pragma: no cover - guarded by available()
            obs.load_error = f"playwright import failed: {e}"
            return obs
        # R25: load the page AS the supplied identity (auth headers + cookies),
        # not anonymously, so authenticated XSS sinks are reachable. None ->
        # anonymous, as before. R01: credentials are never handed to the context
        # wholesale (extra_http_headers projected Authorization onto every
        # request the page went on to make, any origin). I05-D: nor are they
        # put in its cookie jar, which scopes a cookie to the host on any port.
        # The browser holds no identity at all; _IdentityRouter adds it to the
        # requests it sends itself, only on the exact origin `url` is on.
        router = _IdentityRouter(url=url, headers=headers, scope=effective_scope,
                                 cancel=cancel, gate=gate, budget=budget,
                                 timeout_s=self.launch_timeout_ms / 1000,
                                 label="browser_driver")
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
                    browser = await p.chromium.launch(headless=True,
                                                      args=await router.launch_args())
                context = None
                try:
                    # Service-worker fetches bypass Playwright route interception.
                    context = await browser.new_context(service_workers="block")
                    await router.install(context)
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
                        await router.goto(page, url, self.launch_timeout_ms)
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
        finally:
            await router.aclose()
        return obs

    async def capture_requests(self, url: str, *, wait_ms: int = 1500,
                               headers: dict | None = None,
                               scope: "ScopePolicy | None" = None,
                               cancel: "asyncio.Event | Callable[[], bool] | None" = None,
                               gate: "SafetyGate | None" = None,
                               budget: "RequestBudget | None" = None,
                               max_captured: int = 50) -> "CaptureObservation":
        """LB-2: load `url` and record every XHR/fetch request the page's own
        JS issues while it loads, as `HttpExchange(...).model_dump()` dicts
        (harness.models, imported lazily here to keep this module's only
        hard import at module scope limited to harness.run_context, as today).

        A SIBLING entrypoint to `visit()`, not a fork of its policy: the SAME
        `evaluate_browser_request` route handler decides every request
        (identical scope/credential-attach/gate/budget decision `visit()`
        would make for the same request), and the SAME cancellation seam
        (`is_cancelled`) applies. It does NOT share `visit()`'s dialog/
        console/pageerror evidence collection -- that is a different kind of
        observation (did script EXECUTE) from this one (what requests did the
        page's JS ISSUE).

        Per NC-2 (test_browser_interception_gate.py's single-context-site
        guard): browser/context creation for this capture lives HERE, inside
        PlaywrightDriver, the one file that guard allows it in -- not in
        harness.driver_capture, which only calls this method and never
        touches `playwright.async_api` itself. Capture is an ADDITIONAL
        passive listener (`page.on("requestfinished")`) layered on top of the
        same route interceptor; it never changes whether a request is
        allowed, only whether an already-allowed xhr/fetch request is
        recorded.
        """
        from harness.models import HttpExchange
        obs = CaptureObservation(url=url)
        if is_cancelled(cancel):
            obs.load_error = "cancelled before navigation"
            return obs
        effective_scope = scope if scope is not None else ScopePolicy(
            allowed_hosts=frozenset({ScopePolicy.host_of(url)}))
        try:
            from playwright.async_api import async_playwright
        except Exception as e:  # pragma: no cover - guarded by available()
            obs.load_error = f"playwright import failed: {e}"
            return obs
        # The same identity router as visit(): one boundary for both (I05-D).
        router = _IdentityRouter(url=url, headers=headers, scope=effective_scope,
                                 cancel=cancel, gate=gate, budget=budget,
                                 timeout_s=self.launch_timeout_ms / 1000,
                                 label="browser_driver.capture_requests")
        try:
            async with async_playwright() as p:
                connected = bool(self.cdp_endpoint)
                if connected:
                    browser = await p.chromium.connect_over_cdp(
                        self.cdp_endpoint, timeout=self.launch_timeout_ms)
                else:
                    browser = await p.chromium.launch(headless=True,
                                                      args=await router.launch_args())
                context = None
                try:
                    # Service-worker fetches bypass Playwright route interception.
                    context = await browser.new_context(service_workers="block")
                    await router.install(context)
                    page = await context.new_page()

                    async def _record(request) -> None:
                        if len(obs.exchanges) >= max_captured:
                            return
                        if (request.resource_type or "").lower() not in _JS_ISSUED_RESOURCE_TYPES:
                            return
                        try:
                            body = request.post_data or ""
                        except Exception:
                            body = ""
                        resp_status = None
                        resp_headers: dict = {}
                        resp_body = ""
                        try:
                            response = await request.response()
                        except Exception:
                            response = None
                        if response is not None:
                            try:
                                resp_status = response.status
                                resp_headers = dict(response.headers)
                            except Exception:
                                pass
                            try:
                                resp_body = await response.text()
                            except Exception:
                                resp_body = ""
                        try:
                            req_headers = dict(request.headers)
                        except Exception:
                            req_headers = {}
                        obs.exchanges.append(HttpExchange(
                            url=request.url, method=request.method,
                            request_headers=req_headers, request_body=body,
                            response_status=resp_status, response_headers=resp_headers,
                            response_body=resp_body,
                            analyst_note="driver_capture: JS-issued request observed while "
                                         f"loading {url}",
                        ).model_dump())

                    page.on("requestfinished",
                            lambda req: __import__("asyncio").create_task(_record(req)))

                    if is_cancelled(cancel):
                        obs.load_error = "cancelled before navigation"
                    else:
                        await router.goto(page, url, self.launch_timeout_ms)
                        await page.wait_for_timeout(wait_ms)
                finally:
                    if context is not None:
                        try:
                            await context.close()
                        except Exception:
                            pass
                    try:
                        await browser.close()
                    except Exception:
                        pass
        except Exception as e:
            obs.load_error = f"{e.__class__.__name__}: {e}"
        finally:
            await router.aclose()
        return obs

    async def cross_site_submit(self, *, attacker_url: str, victim_url: str,
                                readback_url: str, victim_method: str = "POST",
                                form_fields: dict | None = None,
                                cookie_name: str, cookie_value: str, cookie_domain: str,
                                same_site: str | None = None, secure: bool = False,
                                cancel: "asyncio.Event | Callable[[], bool] | None" = None,
                                ) -> CrossSiteSubmitObservation:
        """LB-5: a cross-site CSRF browser PoC, SELF-CONTAINED (NC-2: context
        creation stays here -- the one place browser_driver.py allows it --
        never in a validator).

        Loads a SYNTHESIZED attacker-origin page -- never dispatched to the
        real network at all, FULFILLED locally by this method's own route
        handler via `evaluate_cross_site_submit_request`, so `attacker_url`
        can be any placeholder host on a different SITE than `victim_url`
        without this needing a second real HTTP server. That page
        auto-submits a hidden form carrying `form_fields` to `victim_url`.
        Before navigating, the victim's session cookie is seeded via
        `context.add_cookies([...])` WITH an EXPLICIT `sameSite` value when
        `same_site` is given (the browser's OWN enforcement of that
        attribute -- not anything this method checks -- is what then blocks
        or allows the cross-site delivery); when `same_site` is None (no
        declared defense), the `sameSite` key is OMITTED entirely so Chromium
        applies its own default-Lax-with-grace-period policy to a freshly-set
        cookie, which is what lets a real "no SameSite attribute at all"
        ambient cookie ride along on a fresh cross-site top-level POST --
        exactly the no-defense case this exists to confirm.

        After the declared POST completes, performs an INDEPENDENT GET-only
        readback at `readback_url` in the SAME browser context, so the proof
        of a state change never relies on trusting the POST's own response
        body.

        NEVER attaches an Authorization header or any other identity header:
        the only credential channel exercised is the browser's own cookie
        jar -- exactly the one an attacker-controlled page actually has
        access to. A bearer/non-ambient-only victim therefore cannot be
        confirmed by this method, by construction, not by a special case.

        Fails closed throughout: `evaluate_cross_site_submit_request` permits
        EXACTLY the three requests declared by this call's own CrossSitePlan
        and aborts everything else -- a redirect to an undeclared URL, a
        subresource, a second form submission -- never `continue_()`s a
        request this call did not explicitly plan for."""
        obs = CrossSiteSubmitObservation(attacker_url=attacker_url, victim_url=victim_url,
                                         readback_url=readback_url)
        if is_cancelled(cancel):
            obs.load_error = "cancelled before navigation"
            return obs
        plan = CrossSitePlan(attacker_url=attacker_url, victim_url=victim_url,
                             victim_method=(victim_method or "POST").upper(),
                             readback_url=readback_url)
        try:
            from playwright.async_api import async_playwright
        except Exception as e:  # pragma: no cover - guarded by available()
            obs.load_error = f"playwright import failed: {e}"
            return obs

        fields = form_fields or {}
        inputs_html = "".join(
            f'<input type="hidden" name="{html.escape(str(k), quote=True)}" '
            f'value="{html.escape(str(v), quote=True)}">'
            for k, v in fields.items())
        attacker_html = (
            "<!doctype html><html><body>"
            f'<form id="csrf-poc-form" action="{html.escape(victim_url, quote=True)}" '
            f'method="{plan.victim_method}">{inputs_html}</form>'
            '<script>document.getElementById("csrf-poc-form").submit();</script>'
            "</body></html>")

        try:
            async with async_playwright() as p:
                connected = bool(self.cdp_endpoint)
                if connected:
                    browser = await p.chromium.connect_over_cdp(
                        self.cdp_endpoint, timeout=self.launch_timeout_ms)
                else:
                    browser = await p.chromium.launch(headless=True)
                context = None
                try:
                    context = await browser.new_context()

                    cookie: dict = {"name": cookie_name, "value": cookie_value,
                                    "domain": cookie_domain, "path": "/",
                                    "secure": bool(secure)}
                    if same_site is not None:
                        cookie["sameSite"] = same_site
                    try:
                        await context.add_cookies([cookie])
                    except Exception as e:
                        obs.load_error = f"failed to seed victim cookie: {e}"
                        return obs

                    responses: dict[str, int] = {}

                    async def _record_response(resp) -> None:
                        try:
                            if resp.url in (plan.victim_url, plan.readback_url):
                                responses[resp.url] = resp.status
                        except Exception:
                            pass

                    async def _handle_route(route, request):
                        if is_cancelled(cancel):
                            try:
                                await route.abort()
                            except Exception:
                                pass
                            return
                        decision = evaluate_cross_site_submit_request(
                            url=request.url, method=request.method,
                            resource_type=request.resource_type,
                            is_navigation=request.is_navigation_request(), plan=plan)
                        if decision.fulfill_locally:
                            try:
                                await route.fulfill(status=200, content_type="text/html",
                                                    body=attacker_html)
                            except Exception:
                                pass
                            return
                        if not decision.allow:
                            log.info("browser_driver.cross_site_submit: blocked %s %s (%s)",
                                     request.method, request.url, decision.reason)
                            try:
                                await route.abort()
                            except Exception:
                                pass
                            return
                        # Allowed to the real network -- continue UNCHANGED.
                        # No header is ever added or removed here: the
                        # browser's own cookie jar + SameSite logic is the
                        # entire credential-delivery mechanism this primitive
                        # exists to observe, never to control.
                        try:
                            await route.continue_()
                        except Exception:
                            pass

                    await context.route("**/*", _handle_route)
                    page = await context.new_page()
                    page.on("response",
                            lambda r: __import__("asyncio").create_task(_record_response(r)))

                    if is_cancelled(cancel):
                        obs.load_error = "cancelled before navigation"
                        return obs

                    await page.goto(attacker_url, timeout=self.launch_timeout_ms,
                                    wait_until="commit")
                    try:
                        await page.wait_for_url(victim_url, timeout=self.launch_timeout_ms)
                    except Exception as e:
                        obs.load_error = f"cross-site submission did not reach the victim: {e}"
                        return obs
                    await page.wait_for_load_state("load")
                    obs.submitted = True
                    obs.submit_status = responses.get(victim_url)

                    if is_cancelled(cancel):
                        obs.load_error = "cancelled before readback"
                        return obs
                    try:
                        readback_resp = await page.goto(
                            readback_url, timeout=self.launch_timeout_ms, wait_until="load")
                    except Exception as e:
                        obs.load_error = f"independent readback navigation failed: {e}"
                        return obs
                    if readback_resp is not None:
                        obs.readback_status = readback_resp.status
                        try:
                            obs.readback_body = await readback_resp.text()
                        except Exception:
                            obs.readback_body = ""
                finally:
                    if context is not None:
                        try:
                            await context.close()
                        except Exception:
                            pass
                    try:
                        await browser.close()
                    except Exception:
                        pass
        except Exception as e:
            obs.load_error = f"{e.__class__.__name__}: {e}"
        return obs
