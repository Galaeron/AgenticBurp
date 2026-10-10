"""
Site-map crawler: discover an application's real endpoint surface.

Drives the "Crawl" feature (Burp button -> POST /crawl). Unlike a link-only
spider, this deliberately fetches and mines the JavaScript bundles a page
loads -- that is where a single-page app hides its whole API surface (see
js_endpoint_extractor.py). The output is the set of endpoints the application
actually references, ready to seed the site map / attack surface.

Bounded and safe by construction:
  - Scope-gated, fail-closed: only fetches URLs whose host is in `allowed_hosts`
    (reuses the engagement scope; never wanders off the target). An empty/unset
    scope fetches NOTHING -- active crawling requires an explicit scope.
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
from harness.feature_workflow import FormAction, extract_forms
from harness.js_endpoint_extractor import extract_endpoints

# <script src="..."> and bare .js references in HTML, to know which bundles to
# fetch and mine.
_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
# same-origin anchor targets, to follow a little HTML too (not just JS).
_HREF = re.compile(r"""<a[^>]+href\s*=\s*['"]([^'"#]+)""", re.IGNORECASE)
# Query-bearing resource URLs are also executable application surface. Product
# image handlers are the canonical example: /image?filename=25.jpg is a dynamic
# file-read endpoint, while the filename's extension previously made the generic
# endpoint extractor mistake the whole URL for a static image asset.
_RESOURCE_SRC = re.compile(
    r"""<(?:img|source|video|audio)[^>]+src\s*=\s*['"]([^'"#]+)""",
    re.IGNORECASE,
)
# Standard robots directives often disclose intentionally hidden application
# routes. Treat same-origin absolute paths as discovery seeds; comments,
# wildcards and external URLs are not executable crawl targets.
_ROBOTS_PATH = re.compile(r"^\s*(?:allow|disallow)\s*:\s*([^\s#]+)", re.IGNORECASE)
# HTTP GET is not proof that navigation is read-only. Server-rendered apps still
# expose state changes as links (delete/logout/reset are common). Passive crawl
# records these links separately but never fetches or promotes them into the
# role-crawl probe list; an explicitly declared objective stage must execute one.
_DESTRUCTIVE_NAVIGATION = re.compile(
    r"(?:^|[-_/])(delete|remove|destroy|disable|revoke|logout|signout|reset|terminate|deactivate)(?:[-_/]|$)",
    re.IGNORECASE,
)


@dataclass
class CrawlResult:
    base_url: str
    pages_fetched: int = 0
    scripts_mined: int = 0
    discovery_files_fetched: int = 0
    endpoints: set[str] = field(default_factory=set)          # normalized same-origin paths
    external_urls: set[str] = field(default_factory=set)
    from_request_calls: set[str] = field(default_factory=set)  # endpoints seen in fetch/axios/xhr
    forms: list[FormAction] = field(default_factory=list)       # observed request shapes; never submitted here
    suppressed_navigation: set[str] = field(default_factory=set)  # observed state-changing-looking links
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "pages_fetched": self.pages_fetched,
            "scripts_mined": self.scripts_mined,
            "discovery_files_fetched": self.discovery_files_fetched,
            "endpoint_count": len(self.endpoints),
            "endpoints": sorted(self.endpoints),
            "from_request_calls": sorted(self.from_request_calls),
            "forms": [
                {"method": f.method, "action": f.action, "body": f.body(),
                 "enctype": f.enctype}
                for f in self.forms
            ],
            "suppressed_navigation": sorted(self.suppressed_navigation),
            "external_urls": sorted(self.external_urls),
            "errors": self.errors,
        }


def _host_allowed(url: str, allowed_hosts: list[str] | None) -> bool:
    # Every crawl fetch is ACTIVE outbound traffic, so this fails CLOSED when no
    # scope is configured -- the same W-17 active_mode contract scope_lock and
    # scope_discovery already enforce. An empty/unset `allowed_hosts` used to
    # return True here, which let a default-config crawl reach ANY host (e.g.
    # localhost:3000) with nothing in scope -- a real safety bug, not a
    # convenience. Callers that genuinely want to crawl must set
    # server.allowed_hosts first.
    if not allowed_hosts:
        return False
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
        if not allowed_hosts:
            result.errors.append(
                "crawl refused: no server.allowed_hosts configured. Crawling sends "
                "active traffic, so it fails closed without an explicit scope -- set "
                "server.allowed_hosts (e.g. in config.local.yaml) to the target host.")
        else:
            result.errors.append(f"base_url host out of scope: {base_url}")
        return result

    headers = dict(headers or {})
    headers.setdefault("User-Agent", "harness-crawler/1.0")
    base_origin = urlsplit(base_url)
    origin_prefix = f"{base_origin.scheme}://{base_origin.netloc}"

    seen: set[str] = set()
    # queue of (url, depth, is_script)
    queue: list[tuple[str, int, bool]] = [(base_url, 0, False)]
    robots_url = origin_prefix + "/robots.txt"
    if robots_url != base_url.split("#", 1)[0]:
        queue.append((robots_url, 0, False))

    client = None if run_context is not None else httpx.AsyncClient(
        timeout=timeout, follow_redirects=True)
    try:
        while (queue and result.pages_fetched + result.scripts_mined
               + result.discovery_files_fetched < max_pages):
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
                    final_url = outcome.final_url or norm_url
                else:
                    await global_throttle.acquire()
                    resp = await client.get(norm_url, headers=headers)
                    body = resp.text or ""
                    final_url = str(getattr(resp, "url", norm_url) or norm_url)
            except httpx.HTTPError as e:
                result.errors.append(f"{norm_url}: {e.__class__.__name__}")
                continue

            found = extract_endpoints(body, norm_url)
            # The generic extractor sees href values before the anchor-specific
            # suppression below. Filter them here too, otherwise `/logout` is
            # still promoted into role_crawl's probe list and destroys the very
            # authenticated session the later form probes depend on.
            safe_paths = set()
            for found_path in found.same_origin_paths:
                candidate_path = urlsplit(found_path).path or "/"
                if _DESTRUCTIVE_NAVIGATION.search(candidate_path):
                    result.suppressed_navigation.add(found_path)
                else:
                    safe_paths.add(found_path)
            result.endpoints |= safe_paths
            result.external_urls |= found.external_urls
            result.from_request_calls |= {
                p for p in found.from_request_calls
                if not _DESTRUCTIVE_NAVIGATION.search(urlsplit(p).path or "/")
            }

            if is_script:
                result.scripts_mined += 1
                continue
            # robots.txt is a standard, bounded discovery source rather than an
            # HTML page. Seed its same-origin path directives into the normal
            # crawl so their forms and links are observed under the same scope,
            # depth and request-budget controls as every other page.
            if urlsplit(norm_url).path == "/robots.txt":
                result.discovery_files_fetched += 1
                for line in body.splitlines():
                    match = _ROBOTS_PATH.match(line)
                    if not match:
                        continue
                    path = match.group(1)
                    if not path.startswith("/") or path == "/" or "*" in path:
                        continue
                    target = urljoin(origin_prefix + "/", path)
                    if not target.startswith(origin_prefix):
                        continue
                    parts = urlsplit(target)
                    rendered = parts.path or "/"
                    if parts.query:
                        rendered += "?" + parts.query
                    result.endpoints.add(rendered)
                    if target.split("#", 1)[0] not in seen and max_depth >= 1:
                        queue.append((target, 0, False))
                continue

            result.pages_fetched += 1

            # Forms are executable request surface. Record their exact method,
            # action and benign field values, but never submit them in this
            # passive crawler. role_crawl owns the gated, budgeted replay.
            # A form whose ACTION is destructive (delete/remove/reset/...) is
            # recorded as suppressed navigation but never captured for replay:
            # the same guard applied to GET links above, so an authorized run
            # cannot attempt a state-destroying submit (e.g. POST /admin/delete)
            # while probing. An explicitly declared objective stage would be the
            # only path allowed to execute one.
            known_forms = {f.signature() for f in result.forms}
            for form in extract_forms(body, final_url):
                if not (_host_allowed(form.action, allowed_hosts)
                        and form.signature() not in known_forms):
                    continue
                if _DESTRUCTIVE_NAVIGATION.search(urlsplit(form.action).path or ""):
                    result.suppressed_navigation.add(form.action)
                    continue
                result.forms.append(form)
                known_forms.add(form.signature())

            # A redirect target can introduce the only input shape in a flow
            # (for example /product?id=1 -> /?message=...). Preserve the final
            # same-origin query as surface even though the HTTP client followed
            # it while fetching the page.
            final_parts = urlsplit(final_url)
            if final_url.startswith(origin_prefix) and final_parts.query:
                result.endpoints.add(f"{final_parts.path or '/'}?{final_parts.query}")

            # Record dynamic resource handlers with their observed query. Do not
            # enqueue/fetch them as crawl pages; role_crawl owns the one bounded
            # access-matrix request. A static path such as /logo.png?rev=1 is
            # rejected by extract_endpoints, while /image?filename=25.jpg keeps
            # /image because the asset extension belongs to the parameter value.
            for m in _RESOURCE_SRC.finditer(body):
                resource = urljoin(norm_url, m.group(1))
                parts = urlsplit(resource)
                if (resource.startswith(origin_prefix) and parts.query):
                    mined = extract_endpoints(f'"{parts.path or "/"}"', norm_url)
                    result.endpoints |= {
                        f"{path}?{parts.query}"
                        for path in mined.same_origin_paths
                    }

            # From an HTML page: enqueue its script bundles (always mined) and,
            # up to depth, its same-origin anchor links.
            for m in _SCRIPT_SRC.finditer(body):
                src = urljoin(norm_url, m.group(1))
                if src.startswith(origin_prefix) and src.split("#", 1)[0] not in seen:
                    queue.append((src, depth, True))
            if depth < max_depth:
                for m in _HREF.finditer(body):
                    link = urljoin(norm_url, m.group(1))
                    if link.startswith(origin_prefix):
                        # Navigation links are application surface too. Previously
                        # they were followed but never recorded, so a conventional
                        # server-rendered app with no fetch()/API strings produced
                        # an empty worklist. Preserve the query while crawling, and
                        # record the normalized path for role/access probing.
                        linked_parts = urlsplit(link)
                        linked_path = linked_parts.path or "/"
                        rendered_link = linked_path
                        if linked_parts.query:
                            rendered_link += "?" + linked_parts.query
                        if _DESTRUCTIVE_NAVIGATION.search(linked_path):
                            result.suppressed_navigation.add(rendered_link)
                            continue
                        mined = extract_endpoints(f'"{linked_path}"', norm_url)
                        if linked_parts.query:
                            # Keep the observed input shape with the sitemap
                            # endpoint. The role crawl separates the query back
                            # out before building its access-matrix key, while
                            # retaining it as the concrete replay template.
                            result.endpoints |= {
                                f"{path}?{linked_parts.query}"
                                for path in mined.same_origin_paths
                            }
                        else:
                            result.endpoints |= mined.same_origin_paths
                        if link.split("#", 1)[0] not in seen:
                            queue.append((link, depth + 1, False))

    finally:
        if client is not None:
            await client.aclose()
    return result
