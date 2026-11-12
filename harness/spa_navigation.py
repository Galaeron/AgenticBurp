"""
SPA navigation for the browser crawl -- visit a single-page app's client-side views.

The 8-hour Juice Shop run (2026-11-03) loaded the home page once in the browser and
never followed a single in-app link: the SPA's own XHRs fired for `/` only, so every
API call a later view makes (basket, address, order history, administration, ...)
stayed invisible to discovery. "It can't process what it doesn't see."

This module is the engine-free half of the fix. `crawl_views` walks an app breadth-
first through a small adapter (open a view, list the link targets the RENDERED DOM
exposes, drain the XHR/fetch requests the view fired), so it is testable with a fake
SPA. `harness.browser_driver.PlaywrightDriver.crawl_spa` supplies the real adapter;
browser/context creation stays in browser_driver.py (NC-2's single-context-site rule).

What counts as a view: `<a href>`, Angular `routerLink` (and its dev-mode
`ng-reflect-router-link` mirror), `data-href`/`data-route`, React-router style
`to` attributes and hash routes (`#/basket`, `#!/basket`). Every target is resolved
against the current view, kept only when it is on the start origin AND in the run's
scope, and dropped when it looks destructive (logout, delete, reset, ...) or is a
download. With `declared_views` it also visits, under a cap of its own, the
parameter-less routes the app's router config declares and nothing links to;
one the app does not stay on (a guard, a redirect to login) is `guarded`, not a
view. The walk stops at `max_views`, at `max_depth`, on cancellation, at the
deadline and when the request budget is spent; the browser's own route handler still
decides every request (scope, gate, credentials, budget), exactly as for one page.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

from harness.browser_driver import is_cancelled

__all__ = ["LINK_TARGETS_JS", "SpaCrawlResult", "ViewAdapter", "ViewRefused", "crawl_views",
           "describe_error", "resolve_view", "view_key"]


class ViewRefused(Exception):
    """A view the run refused to enter (e.g. its navigation redirected out of
    scope): recorded as refused, not as a crawl error."""


# A URL's query/fragment inside an error message (it may carry a token): dropped.
_URL_TAIL = re.compile(r"([a-z][a-z0-9+.-]*://[^\s?#]*)[?#][^\s]*", re.IGNORECASE)


def describe_error(exc: BaseException) -> str:
    """`Type: first line of the message` -- a browser error's message runs to a
    multi-line call log, and some (Playwright's own `Error`) are useless by type
    alone. URL queries are cut; an empty message falls back to its cause."""
    name = type(exc).__name__
    text = next((line.strip() for line in str(exc).splitlines() if line.strip()), "")
    text = _URL_TAIL.sub(r"\1?...", text)[:200]
    if text:
        return f"{name}: {text}"
    cause = exc.__cause__ or exc.__context__
    return f"{name} ({describe_error(cause)})" if cause is not None else name

# Read by page.evaluate(): every link target the rendered DOM exposes, raw.
LINK_TARGETS_JS = """() => {
  const out = new Set();
  const add = v => { if (typeof v === 'string' && v.trim()) out.add(v.trim()); };
  document.querySelectorAll('a[href]').forEach(a => add(a.getAttribute('href')));
  document.querySelectorAll('[routerlink],[ng-reflect-router-link],[data-href],[data-route],[to]')
    .forEach(e => ['routerlink', 'ng-reflect-router-link', 'data-href', 'data-route', 'to']
      .forEach(n => add(e.getAttribute(n))));
  return Array.from(out).slice(0, 500);
}"""

_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "blob:", "about:", "file:")
_DESTRUCTIVE = re.compile(
    r"(?:^|[-_/#!])(delete|remove|destroy|disable|revoke|logout|log-out|signout|sign-out|"
    r"reset|terminate|deactivate|unsubscribe)(?:[-_/?]|$)", re.IGNORECASE)
_DOWNLOAD = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?|ttf|eot|pdf|zip|gz|tar|7z|rar|exe|"
    r"msi|dmg|mp[34]|avi|mov|webm|docx?|xlsx?|pptx?|md|txt|kdbx|bak|yml|yaml)$", re.IGNORECASE)


def _hash_routed(url: str) -> bool:
    frag = urlsplit(url).fragment
    return frag.startswith("/") or frag.startswith("!/")


def resolve_view(current: str, raw: str) -> str | None:
    """`raw` link target -> absolute view URL, or None when it is not a view.

    A fragment survives only when it is a route (`#/x`, `#!/x`); an in-page anchor
    is dropped. In a hash-routed app (the current view's fragment is a route), a
    bare router path (`/basket`, `basket`) is a hash route, not a server path."""
    raw = (raw or "").strip()
    if not raw or raw.lower().startswith(_SKIP_SCHEMES) or raw in ("#", "#!"):
        return None
    if raw.startswith("#"):
        frag = raw[1:]
        if not (frag.startswith("/") or frag.startswith("!/")):
            return None
        base = urlsplit(current)
        return urlunsplit((base.scheme, base.netloc, base.path or "/", base.query, frag))
    if _hash_routed(current) and "://" not in raw and not raw.startswith("//"):
        base = urlsplit(current)
        frag = urlsplit(current).fragment
        prefix = "!" if frag.startswith("!") else ""
        route_path, _, route_query = raw.partition("?")
        if not route_path.startswith("/"):
            route_path = "/" + route_path
        route = prefix + route_path + (f"?{route_query}" if route_query else "")
        return urlunsplit((base.scheme, base.netloc, base.path or "/", base.query, route))
    absolute = urljoin(current, raw)
    parts = urlsplit(absolute)
    if parts.scheme not in ("http", "https"):
        return None
    frag = parts.fragment if (parts.fragment.startswith("/") or parts.fragment.startswith("!/")) else ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, frag))


def view_key(url: str) -> str:
    """Dedup key: path + route fragment, query values ignored (one view per shape)."""
    parts = urlsplit(url)
    frag_path = parts.fragment.split("?", 1)[0]
    return f"{parts.path or '/'}#{frag_path}" if frag_path else (parts.path or "/")


class ViewAdapter(Protocol):
    async def open(self, url: str) -> None: ...
    async def links(self) -> list[str]: ...
    async def drain(self) -> list[dict]: ...
    def current_url(self) -> str: ...


@dataclass
class SpaCrawlResult:
    start_url: str
    views: list[str] = field(default_factory=list)          # visited, in order
    exchanges: list[dict] = field(default_factory=list)     # XHR/fetch request templates
    skipped: dict = field(default_factory=dict)             # reason -> count
    errors: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)        # views the run refused to enter
    stopped_by: str = ""                                    # "" | max_views | budget | ...
    # Every in-scope link target the rendered views exposed, resolved, query and
    # route fragment kept (a link to a known view shape is still a route input),
    # and every request each view fired as (view URL as loaded, method, url, body):
    # client_routes.py maps an API call back to the route that issued it.
    links: list[str] = field(default_factory=list)
    view_calls: list[tuple] = field(default_factory=list)
    # Router-declared views nothing linked to (declared_views > 0): the ones the
    # app stayed on, and the ones it did not ("requested -> landed" or the status).
    declared: list[str] = field(default_factory=list)
    guarded: list[str] = field(default_factory=list)

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


def _budget_spent(budget: Any) -> bool:
    remaining = getattr(budget, "remaining", None)
    try:
        value = remaining() if callable(remaining) else remaining
    except Exception:
        return False
    return value is not None and value <= 0


def _same_view(a: str, b: str) -> bool:
    """Whether two URLs are the same view, a trailing slash aside."""
    def norm(url: str) -> str:
        path, _, frag = view_key(url).partition("#")
        return (path.rstrip("/") or "/") + "#" + ((frag.rstrip("/") or "/") if frag else "")
    return norm(a) == norm(b)


def _declared_url(current: str, path: str, hash_hint: bool) -> str | None:
    """A router-declared path as a view of the app at `current`: a hash route in a
    hash-routed app (the current view's fragment is a route, or the bundle says
    so), a history route otherwise."""
    if not _hash_routed(current) and hash_hint:
        return resolve_view(current, "#" + path)
    return resolve_view(current, path)


async def crawl_views(adapter: ViewAdapter, start_url: str, *, in_scope, max_views: int = 30,
                      max_depth: int = 4, max_captured: int = 200, extra_views=(),
                      declared_views: int = 0,
                      cancel: Any = None, budget: Any = None,
                      deadline: float | None = None) -> SpaCrawlResult:
    """Breadth-first walk of the app's client-side views from `start_url`.

    `in_scope(url) -> bool` is the run's scope check. `extra_views` seeds the
    queue with routes learned elsewhere (route feedback), resolved like links.
    Each exchange the adapter drains is tagged with the view that fired it.

    `declared_views` > 0 also visits up to that many routes the app's router
    config declares without a parameter and nothing links to (an adapter with
    `scripts()` hands over the same-origin script bodies the views loaded). They
    count against this cap, not `max_views`; the links they expose are followed
    like any view's, under `max_views`, so a route that is both declared and
    linked loses nothing. One the app does not stay on (a guard cancels it, it
    redirects, to login or elsewhere, or the document answers an error status)
    is recorded in `guarded`, never as a view, and its links are not followed;
    the calls fired meanwhile are still captured, tagged with the view the app
    landed on."""
    result = SpaCrawlResult(start_url=start_url)
    origin = urlsplit(start_url)[:2]
    queue: list[tuple[str, int, bool]] = [(start_url, 0, False)]
    seen = {view_key(start_url)}
    captured_keys: set = set()
    seen_links: set = set()
    declared_room = max(0, int(declared_views or 0))
    declared_paths: list[str] = []
    hash_hint = False
    linked_views = 0
    landed: set = set()      # where each opened view ended up (a redirect's target)

    def admit(url: str | None, depth: int, declared: bool = False) -> None:
        if url is None:
            result.skip("not_a_view")
            return
        if urlsplit(url)[:2] != origin or not in_scope(url):
            result.skip("out_of_scope")
            return
        parts = urlsplit(url)
        if _DESTRUCTIVE.search(parts.path) or _DESTRUCTIVE.search(parts.fragment):
            result.skip("destructive")
            return
        if _DOWNLOAD.search(parts.path) or _DOWNLOAD.search(parts.fragment.split("?", 1)[0]):
            result.skip("download")
            return
        if not declared and url not in seen_links and len(result.links) < 500:
            seen_links.add(url)
            result.links.append(url)
        key = view_key(url)
        if key in seen:
            return
        seen.add(key)
        queue.append((url, depth, declared))

    async def mine_declared(current: str) -> None:
        nonlocal declared_room, hash_hint
        from harness.client_routes import declared_views as declared_of
        try:
            bodies = await adapter.scripts()
        except Exception as exc:
            result.errors.append(f"scripts {view_key(current)}: {describe_error(exc)}")
            return
        for body in bodies or ():
            paths, hinted = declared_of(body)
            hash_hint = hash_hint or hinted
            declared_paths.extend(p for p in paths if p not in declared_paths)
        while declared_paths and declared_room > 0:
            url = _declared_url(current, declared_paths.pop(0), hash_hint)
            if url is None or view_key(url) in seen or view_key(url) in landed:
                continue
            before = len(queue)
            admit(url, 1, declared=True)
            if len(queue) > before:
                declared_room -= 1

    for extra in extra_views or ():
        admit(resolve_view(start_url, extra), 1)

    while queue:
        if is_cancelled(cancel):
            result.stopped_by = "cancelled"
            break
        if deadline is not None and time.monotonic() >= deadline:
            result.stopped_by = "deadline"
            break
        if _budget_spent(budget):
            result.stopped_by = "budget"
            break
        if linked_views >= max_views:
            # A declared view has a cap of its own: only those still queued go on.
            result.stopped_by = "max_views"
            queue = [entry for entry in queue if entry[2]]
            if not queue:
                break
        url, depth, declared = queue.pop(0)
        try:
            await adapter.open(url)
        except ViewRefused as exc:
            result.skip("refused_redirect")
            result.refused.append(f"view {view_key(url)}: {exc}")
            continue
        except Exception as exc:
            result.errors.append(f"view {view_key(url)}: {describe_error(exc)}")
            continue
        current = adapter.current_url() or url
        landed.add(view_key(current))
        guarded = ""
        if declared:
            status_of = getattr(adapter, "status", None)
            status = status_of() if callable(status_of) else None
            if isinstance(status, int) and status >= 400:
                guarded = f"{view_key(url)} -> status {status}"
            elif not _same_view(current, url):
                guarded = f"{view_key(url)} -> {view_key(current)}"
        if guarded:
            result.guarded.append(guarded)
        else:
            result.views.append(url)
            if declared:
                result.declared.append(view_key(url))
            else:
                linked_views += 1
        try:
            fired = await adapter.drain()
        except Exception as exc:
            fired = []
            result.errors.append(f"capture {view_key(url)}: {describe_error(exc)}")
        for exchange in fired:
            if len(result.view_calls) < 2000:
                result.view_calls.append((current, exchange.get("method") or "GET",
                                          exchange.get("url") or "", exchange.get("request_body") or ""))
            key = (exchange.get("method"), exchange.get("url"), exchange.get("request_body"))
            if key in captured_keys or len(result.exchanges) >= max_captured:
                continue
            captured_keys.add(key)
            exchange = dict(exchange)
            exchange["analyst_note"] = ("driver_capture: JS-issued request observed on view "
                                        f"{view_key(current if guarded else url)} (spa navigation)")
            result.exchanges.append(exchange)
        if depth < max_depth and not guarded:
            try:
                targets = await adapter.links()
            except Exception as exc:
                targets = []
                result.errors.append(f"links {view_key(url)}: {describe_error(exc)}")
            for raw in targets:
                admit(resolve_view(current, raw), depth + 1)
        if declared_room > 0 and callable(getattr(adapter, "scripts", None)):
            await mine_declared(current)
    else:
        result.stopped_by = result.stopped_by or "exhausted"
    return result
