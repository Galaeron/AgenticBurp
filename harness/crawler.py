"""
Site-map crawler: discover an application's real endpoint surface.

Drives the "Crawl" feature (Burp button -> POST /crawl). Unlike a link-only
spider, this deliberately fetches and mines the JavaScript bundles a page
loads -- that is where a single-page app hides its whole API surface (see
js_endpoint_extractor.py). The output is the set of endpoints the application
actually references, ready to seed the site map / attack surface.

Bounded and safe by construction:
  - Scope-gated: only fetches URLs whose host is in `allowed_hosts` (reuses the
    engagement scope; never wanders off the target).
  - Throttled: every fetch goes through the global request throttle, so a
    crawl obeys the same aggregate rate ceiling as everything else.
  - Bounded: hard caps on pages fetched and crawl depth; no unbounded spider.
  - Session-aware: optional headers (Authorization / Cookie the tester's Burp
    session already holds) are sent, so authenticated surface is reachable.

Deterministic aside from network I/O; the extraction it relies on is pure.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from harness import global_throttle
from harness.js_endpoint_extractor import extract_endpoints

# <script src="..."> and bare .js references in HTML, to know which bundles to
# fetch and mine.
_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
# same-origin anchor targets, to follow a little HTML too (not just JS).
_HREF = re.compile(r"""<a[^>]+href\s*=\s*['"]([^'"#?]+)""", re.IGNORECASE)


@dataclass
class CrawlResult:
    base_url: str
    pages_fetched: int = 0
    scripts_mined: int = 0
    endpoints: set[str] = field(default_factory=set)          # normalized same-origin paths
    external_urls: set[str] = field(default_factory=set)
    from_request_calls: set[str] = field(default_factory=set)  # endpoints seen in fetch/axios/xhr
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "pages_fetched": self.pages_fetched,
            "scripts_mined": self.scripts_mined,
            "endpoint_count": len(self.endpoints),
            "endpoints": sorted(self.endpoints),
            "from_request_calls": sorted(self.from_request_calls),
            "external_urls": sorted(self.external_urls),
            "errors": self.errors,
        }


def _host_allowed(url: str, allowed_hosts: list[str] | None) -> bool:
    if not allowed_hosts:
        return True
    host = (urlsplit(url).hostname or "").lower()
    return any(host == h.lower() or host.endswith("." + h.lower()) for h in allowed_hosts)


async def crawl(
    base_url: str,
    headers: dict[str, str] | None = None,
    allowed_hosts: list[str] | None = None,
    max_pages: int = 40,
    max_depth: int = 2,
    timeout: float = 15.0,
    run_context=None,
    session_ref: str | None = None,
) -> CrawlResult:
    """BFS from `base_url`, fetching same-origin HTML pages (to depth) and every
    JavaScript bundle they load, mining each for endpoint references. Returns a
    CrawlResult; never raises for per-URL fetch failures (recorded in errors)."""
    result = CrawlResult(base_url=base_url)
    if not base_url.startswith(("http://", "https://")):
        result.errors.append(f"unsupported scheme: {base_url}")
        return result
    if not _host_allowed(base_url, allowed_hosts):
        result.errors.append(f"base_url host out of scope: {base_url}")
        return result

    headers = dict(headers or {})
    headers.setdefault("User-Agent", "harness-crawler/1.0")
    base_origin = urlsplit(base_url)
    origin_prefix = f"{base_origin.scheme}://{base_origin.netloc}"

    seen: set[str] = set()
    # queue of (url, depth, is_script)
    queue: list[tuple[str, int, bool]] = [(base_url, 0, False)]

    client = None if run_context is not None else httpx.AsyncClient(
        timeout=timeout, follow_redirects=True)
    try:
        while queue and result.pages_fetched + result.scripts_mined < max_pages:
            url, depth, is_script = queue.pop(0)
            norm_url = url.split("#", 1)[0]
            if norm_url in seen:
                continue
            seen.add(norm_url)
            if not _host_allowed(norm_url, allowed_hosts):
                continue

            try:
                if run_context is not None:
                    from harness.run_context import TypedRequest
                    request_headers = {k: v for k, v in headers.items()
                                       if k.lower() not in ("authorization", "cookie", "proxy-authorization")}
                    outcome = await run_context.executor().execute(
                        TypedRequest("GET", norm_url, headers=request_headers),
                        capability="crawler", session_ref=session_ref)
                    if not outcome.ok:
                        result.errors.append(f"{norm_url}: {outcome.outcome}")
                        continue
                    body = outcome.body or ""
                else:
                    await global_throttle.acquire()
                    resp = await client.get(norm_url, headers=headers)
                    body = resp.text or ""
            except httpx.HTTPError as e:
                result.errors.append(f"{norm_url}: {e.__class__.__name__}")
                continue

            found = extract_endpoints(body, norm_url)
            result.endpoints |= found.same_origin_paths
            result.external_urls |= found.external_urls
            result.from_request_calls |= found.from_request_calls

            if is_script:
                result.scripts_mined += 1
                continue
            result.pages_fetched += 1

            # From an HTML page: enqueue its script bundles (always mined) and,
            # up to depth, its same-origin anchor links.
            for m in _SCRIPT_SRC.finditer(body):
                src = urljoin(norm_url, m.group(1))
                if src.startswith(origin_prefix) and src.split("#", 1)[0] not in seen:
                    queue.append((src, depth, True))
            if depth < max_depth:
                for m in _HREF.finditer(body):
                    link = urljoin(norm_url, m.group(1))
                    if link.startswith(origin_prefix) and link.split("#", 1)[0] not in seen:
                        queue.append((link, depth + 1, False))

    finally:
        if client is not None:
            await client.aclose()
    return result
