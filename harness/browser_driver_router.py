"""I05-D identity router: every request the browser makes is checked and sent
through the run, split from browser_driver.py (ARC-9). Import these names
from harness.browser_driver; this module reads browser_driver's names at
call time, so the scope and egress policy stays single-sourced there.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from harness.run_context import ScopePolicy

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from harness.browser_driver import BrowserRequestDecision


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
# ExecutionObservation.navigation_bodies: at most this many documents, each cut here.
_MAX_NAVIGATION_BODIES = 4
_NAVIGATION_BODY_BYTES = 262_144
# crawl_spa's route probes read a view back as its title, its visible text and the
# values of its form fields (a password field's value never), capped.
_VIEW_TEXT_JS = """() => {
  const parts = [document.title || "", document.body ? (document.body.innerText || "") : ""];
  for (const el of document.querySelectorAll("input, textarea, select")) {
    if ((el.type || "").toLowerCase() !== "password") parts.push(el.value || "");
  }
  return parts.join("\\n").slice(0, 200000);
}"""


# _IdentityRouter.script_bodies (crawl_spa with declared_views): the same-origin
# scripts of one crawl, each cut at _SCRIPT_BODY_BYTES (client_routes reads no
# more), kept while their total stays within _SCRIPT_BYTES_TOTAL. The bound is in
# bytes, not a count of six: a bundler's runtime, polyfills and small chunks load
# (and finish) before the large script that holds the router config, and a count
# spent on them dropped that config, so no declared view was ever visited.
_MAX_SCRIPT_BODIES = 64
_SCRIPT_BODY_BYTES = 5_000_000
_SCRIPT_BYTES_TOTAL = 30_000_000
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


class _IdentityRouter:
    """The route handler, browser launch flags and main-frame navigation shared
    by `visit` and `capture_requests` (I05-D; see the block comment above)."""

    def __init__(self, *, url: str, headers: dict | None, scope: ScopePolicy,
                 cancel, gate, budget, timeout_s: float, label: str, obs=None):
        from harness.run_context import AddressPins, current_run_context
        from harness.tls_policy import TLSPolicy
        self.run_origin = ScopePolicy.origin_of(url)
        self.scope, self.cancel, self.gate, self.budget = scope, cancel, gate, budget
        self.timeout_s = timeout_s
        self.label = label
        # visit()'s ExecutionObservation: what was sent, blocked or cancelled.
        self.obs = obs
        # Main-frame redirects refused by scope/policy (target origin and reason,
        # never the query): a crawl reports such a view as refused, not failed.
        self.refused_redirects: list[str] = []
        # crawl_spa(declared_views=...): the run origin's script bodies, for the
        # router config they declare. None (the default) keeps none.
        self.script_bodies: list[str] | None = None
        self._scripts_kept = 0
        self._script_bytes_kept = 0
        # Each script URL is kept once: a probe loads the app as a new document,
        # and its bundles again (route probes, crawl_views).
        self._script_urls: set = set()
        # crawl_spa(file_uploads=True) while one file input's upload is tried: every
        # write the page issues is HELD and aborted, never sent (see _hold_write).
        self.hold: dict | None = None
        extra, cookies = _bd._extra_headers_and_cookies(headers, url)
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
                _bd.log.info("%s: %s not mapped for the browser (%s)", self.label, host, e)
                continue
            maps.append(f"MAP {host} {f'[{ip}]' if ':' in ip else ip}")
        rules = maps + ["MAP * ~NOTFOUND"] + [f"EXCLUDE {h}" for h in excluded]
        return [f"--host-resolver-rules={', '.join(rules)}"]

    async def install(self, context) -> None:
        self.context = context
        await context.route("**/*", self.handle)

    async def goto(self, page, url: str, timeout_ms: int):
        """Navigate the main frame; a redirect hop is re-issued here as a fresh
        (routed) navigation instead of being followed by the browser. Returns
        the final hop's response (None when the browser reports none)."""
        self.page = page
        target = url
        self._driving = True
        try:
            for _ in range(_MAX_REDIRECT_HOPS + 1):
                self._main_hop = None
                response = await page.goto(target, timeout=timeout_ms, wait_until="load")
                if self._main_hop is None:
                    return response
                target = self._main_hop
            raise RuntimeError(f"more than {_MAX_REDIRECT_HOPS} redirects")
        finally:
            self._driving = False

    async def aclose(self) -> None:
        for client in self._clients.values():
            await _bd._quietly(client.aclose())
        self._clients.clear()

    def _decide(self, url: str, method: str, resource_type: str, is_navigation: bool,
                *, account: bool) -> BrowserRequestDecision:
        return _bd.evaluate_browser_request(
            url=url, method=method, resource_type=resource_type, is_navigation=is_navigation,
            run_origin=self.run_origin, scope=self.scope,
            gate=self.gate if account else None, budget=self.budget if account else None)

    def _blocked(self, reason: str) -> None:
        if self.obs is not None:
            self.obs.blocked_requests.append(reason)

    async def handle(self, route, request) -> None:
        if _bd.is_cancelled(self.cancel):
            if self.obs is not None:
                self.obs.cancelled = True
            await _bd._quietly(route.abort())
            return
        if self.hold is not None and (request.method or "GET").upper() not in _bd._HELD_READS:
            await self._hold_write(route, request, self.hold)
            return
        is_navigation = request.is_navigation_request()
        decision = self._decide(request.url, request.method, request.resource_type,
                                is_navigation, account=True)
        if not decision.allow:
            _bd.log.info("%s: blocked %s %s (%s)", self.label, request.method, request.url,
                     decision.reason)
            self._blocked(decision.reason)
            await _bd._quietly(route.abort())
            return
        if self.obs is not None:
            self.obs.requests_sent += 1
        try:
            await self._send_and_fulfill(route, request, is_navigation)
        except Exception as e:
            _bd.log.info("%s: %s %s not sent (%s: %s)", self.label, request.method, request.url,
                     e.__class__.__name__, e)
            await _bd._quietly(route.abort())

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
                if not _bd._same_cookie_host(url, request.url):
                    final = ""
                if hop_set_cookies or final:
                    fulfilled["set-cookie"] = "\n".join(hop_set_cookies + ([final] if final else []))
                if (resource_type or "").lower() in _bd._JS_ISSUED_RESOURCE_TYPES:
                    self._offer_route(url, method, body, response)
                if (is_navigation and self.obs is not None
                        and len(self.obs.navigation_bodies) < _MAX_NAVIGATION_BODIES):
                    self.obs.navigation_bodies.append(
                        bytes(response.content[:_NAVIGATION_BODY_BYTES]).decode("utf-8", "replace"))
                if (self.script_bodies is not None and (resource_type or "").lower() == "script"
                        and 200 <= response.status_code < 300
                        and self._scripts_kept < _bd._MAX_SCRIPT_BODIES
                        and url not in self._script_urls
                        and ScopePolicy.origin_of(url) == self.run_origin):
                    kept = bytes(response.content[:_SCRIPT_BODY_BYTES])
                    if self._script_bytes_kept + len(kept) <= _bd._SCRIPT_BYTES_TOTAL:
                        self._script_urls.add(url)
                        self._scripts_kept += 1
                        self._script_bytes_kept += len(kept)
                        self.script_bodies.append(kept.decode("utf-8", "replace"))
                await route.fulfill(status=response.status_code, headers=fulfilled,
                                    body=response.content)
                return
            next_url, next_method = urljoin(url, location), _redirect_method(response.status_code, method)
            if is_navigation:
                # Checked here; accounted when the browser re-issues it as a navigation.
                hop = self._decide(next_url, next_method, resource_type, True, account=False)
                if not hop.allow:
                    _bd.log.info("%s: blocked redirect %s -> %s (%s)", self.label, url, next_url,
                             hop.reason)
                    self._blocked(hop.reason)
                    self.refused_redirects.append(
                        f"redirect to {ScopePolicy.origin_of(next_url)} refused ({hop.reason})")
                    await route.abort()
                    return
                await self._fulfill_navigation_hop(route, request, fulfilled, next_url)
                return
            hop = self._decide(next_url, next_method, resource_type, False, account=True)
            if _bd.is_cancelled(self.cancel) or not hop.allow:
                _bd.log.info("%s: blocked redirect %s -> %s (%s)", self.label, url, next_url,
                         hop.reason)
                if not hop.allow:
                    self._blocked(hop.reason)
                elif self.obs is not None:
                    self.obs.cancelled = True
                await route.abort()
                return
            host = ScopePolicy.host_of(url)
            for value in fulfilled.get("set-cookie", "").split("\n"):
                if not value:
                    continue
                name, cookie_value, deletes = _cookie_pair(value)
                jar = hop_cookies.setdefault(host, {})
                jar.pop(name, None) if deletes else jar.__setitem__(name, cookie_value)
                if _bd._same_cookie_host(url, request.url):
                    hop_set_cookies.append(value)
            if next_method != method:
                body = None
                headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
            url, method = next_url, next_method
        await route.abort()

    async def _hold_write(self, route, request, hold: dict) -> None:
        """A write the page issued while a file input's upload is tried. Nothing
        is forwarded: an uploaded file cannot be removed generically, so the
        request is captured as a template and dropped (_drop_held). The first one
        carrying the attached file is the upload: checked against scope and
        same-origin, then authorized as a write (active + mutating replay, the
        input's ceiling case) before it is recorded. Any other write is dropped
        and counted."""
        from harness.models import HttpExchange
        method, url = (request.method or "POST").upper(), request.url
        try:
            body = request.post_data_buffer or b""
        except Exception:
            body = b""
        if hold.get("exchange") is not None or not any(m and m in body for m in hold["markers"]):
            hold["aborted"].append(f"{method} {urlsplit(url).path or '/'}")
            _bd.log.info("%s: held write %s %s aborted (not the upload)", self.label, method,
                     urlsplit(url).path or "/")
            await self._drop_held(route, request)
            return
        decision = _bd.evaluate_browser_request(
            url=url, method=method, resource_type="fetch", is_navigation=False,
            run_origin=self.run_origin, scope=self.scope)
        if not decision.allow:
            hold["reason"] = f"upload request refused: {decision.reason}"
        elif self.gate is None:
            hold["reason"] = "upload capture not authorized: no gate"
        else:
            verdict = self.gate.authorize(validator_name=hold["capability"], method=method,
                                          url=url, finding_id=hold["case_ref"])
            if not verdict.allowed:
                hold["reason"] = f"upload capture not authorized: {verdict.reason}"
            else:
                try:
                    headers = dict(request.headers)
                except Exception:
                    headers = {}
                hold["exchange"] = HttpExchange(
                    url=url, method=method, request_headers=headers,
                    request_body=body.decode("utf-8", "replace"),
                    analyst_note=hold["note"][:2000], capture_source=hold["capability"],
                ).model_dump()
        await self._drop_held(route, request)

    @staticmethod
    async def _drop_held(route, request) -> None:
        """End a held request without sending it. A held form submit (a navigation)
        is answered locally with 204 No Content, so the page stays on its document
        instead of committing an error page; anything else is aborted."""
        try:
            navigation = request.is_navigation_request()
        except Exception:
            navigation = False
        if navigation:
            try:
                await route.fulfill(status=204, headers={"cache-control": "no-store"}, body="")
                return
            except Exception:
                pass
        await _bd._quietly(route.abort())

    def _offer_route(self, url: str, method: str, body, response) -> None:
        """route_feed (engagement.recrawl): an XHR/fetch call a page fired is offered
        back to the engagement, so a route a later browser visit reveals reaches
        the worklist. No feed installed: nothing happens."""
        from harness.run_context import current_run_context
        rc = current_run_context()
        feed = getattr(rc, "route_feed", None) if rc is not None else None
        if feed is None:
            return
        try:
            if isinstance(body, (bytes, bytearray)):
                body = bytes(body).decode("utf-8", "replace")
            feed.observe_response(
                capability=f"browser:{self.label}", method=method, url=url,
                status=response.status_code, request_headers={}, request_body=body,
                response_headers=dict(response.headers),
                response_body=lambda: response.text)
        except Exception:   # feedback is additive; never break the page
            pass

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


# Bound last (browser_driver imports this module): read only at call time.
from harness import browser_driver as _bd  # noqa: E402
