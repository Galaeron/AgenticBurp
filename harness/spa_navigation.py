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
download. The walk stops at `max_views`, at `max_depth`, on cancellation, at the
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

__all__ = ["LINK_TARGETS_JS", "SpaCrawlResult", "ViewAdapter", "crawl_views", "resolve_view",
           "view_key"]

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
    stopped_by: str = ""                                    # "" | max_views | budget | ...

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


def _budget_spent(budget: Any) -> bool:
    remaining = getattr(budget, "remaining", None)
    try:
        value = remaining() if callable(remaining) else remaining
    except Exception:
        return False
    return value is not None and value <= 0


async def crawl_views(adapter: ViewAdapter, start_url: str, *, in_scope, max_views: int = 30,
                      max_depth: int = 4, max_captured: int = 200, extra_views=(),
                      cancel: Any = None, budget: Any = None,
                      deadline: float | None = None) -> SpaCrawlResult:
    """Breadth-first walk of the app's client-side views from `start_url`.

    `in_scope(url) -> bool` is the run's scope check. `extra_views` seeds the
    queue with routes learned elsewhere (route feedback), resolved like links.
    Each exchange the adapter drains is tagged with the view that fired it."""
    result = SpaCrawlResult(start_url=start_url)
    origin = urlsplit(start_url)[:2]
    queue: list[tuple[str, int]] = [(start_url, 0)]
    seen = {view_key(start_url)}
    captured_keys: set = set()

    def admit(url: str | None, depth: int) -> None:
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
        key = view_key(url)
        if key in seen:
            return
        seen.add(key)
        queue.append((url, depth))

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
        if len(result.views) >= max_views:
            result.stopped_by = "max_views"
            break
        url, depth = queue.pop(0)
        try:
            await adapter.open(url)
        except Exception as exc:
            result.errors.append(f"view {view_key(url)}: {type(exc).__name__}")
            continue
        result.views.append(url)
        current = adapter.current_url() or url
        try:
            fired = await adapter.drain()
        except Exception as exc:
            fired = []
            result.errors.append(f"capture {view_key(url)}: {type(exc).__name__}")
        for exchange in fired:
            key = (exchange.get("method"), exchange.get("url"), exchange.get("request_body"))
            if key in captured_keys or len(result.exchanges) >= max_captured:
                continue
            captured_keys.add(key)
            exchange = dict(exchange)
            exchange["analyst_note"] = ("driver_capture: JS-issued request observed on view "
                                        f"{view_key(url)} (spa navigation)")
            result.exchanges.append(exchange)
        if depth >= max_depth:
            continue
        try:
            targets = await adapter.links()
        except Exception as exc:
            result.errors.append(f"links {view_key(url)}: {type(exc).__name__}")
            continue
        for raw in targets:
            admit(resolve_view(current, raw), depth + 1)
    else:
        result.stopped_by = result.stopped_by or "exhausted"
    return result
