"""
client_routes.py -- a single-page app's client-side routes and their parameters, as inputs.

r9 (2026-11-11): 318 XSS-family proofs ran against a hash-routed single-page app with
known client-side XSS, and none confirmed. The DOM XSS leg replaced the WHOLE fragment
with its payload, and the reflected leg mutated the query of captures that were mostly
JSON API calls, so no page script ever read the payload. A hash-routed app reads its
input from a parameter INSIDE the fragment route (`/#/<route>?<param>=`), which the
browser never sends to the server. A history-routed app reads it from the HTML
document's own query (`/<route>?<param>=`). Neither shape was an input.

This module models both shapes generically:

- `ClientRoute`: one route, hash or history, with the NAMES of the parameters it reads.
  Values are never kept, because a link may carry a token. A hash route's coverage key
  is `GET <document path>#<route>`. No server endpoint can have that key, because a
  server path never carries a fragment. A history route's key is `GET <path>`, which
  merges into the server endpoint of the same path when there is one.
- `ClientRouteMap`: what discovery learned, bounded. It has four sources:
    * links: `href`, `routerLink`, `ng-reflect-router-link`, `data-href`, `data-route`
      and `to` attributes in HTML the crawl fetched, resolved the way the SPA crawl
      resolves them;
    * views: every URL the browser crawl navigated to, fragment included;
    * bundles: route-shaped strings in same-origin JavaScript. These are `"#/r?p="`
      literals, router navigation calls that name query parameters, `"/r?p="`
      strings whose path the router config declares, and router config paths with
      a `:name` segment (`/item/:id`), whose segment is an input of its own;
    * api_map: an API call a view fired, mapped back to that view's route where the
      crawl shows it. The call either carries the value of one of the route's
      parameters, or names a parameter the bundles read from the router.
- `payload_url`: the page URL with one route, page or segment input set to a payload.

Nothing here is specific to an application: there are no route or field names.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

__all__ = ["CLIENT_ROUTE_LEGS", "CLIENT_ROUTE_LOCATIONS", "ClientRoute", "ClientRouteMap",
           "HASH", "HISTORY", "PAGE", "QUERY", "ROUTE", "SEGMENT", "declared_views",
           "fragment_route", "payload_url", "probe_url", "read_names_of",
           "route_params_of_template", "route_segments", "route_segments_of_template"]

HASH, HISTORY = "hash", "history"
# Coverage case locations: a parameter of the fragment route, a parameter of the page query.
ROUTE, PAGE = "route", "page"
# A parameter of a captured URL's own query, which a page script may also read
# from location.search (dom_xss). It is the coverage model's own "query" input.
QUERY = "query"
# A `:name` segment of a route path the router config declares (`/item/:id`). The
# route's URL keeps the `:name` placeholder, and a payload replaces that segment.
SEGMENT = "segment"
CLIENT_ROUTE_LOCATIONS = frozenset({ROUTE, PAGE})
# The legs that load the page in a browser and so can test a client-side route input.
CLIENT_ROUTE_LEGS = frozenset({"browser_xss", "dom_xss"})

MAX_ROUTES = 200
MAX_PARAMS = 8
MAX_API_LINKS = 400
MAX_API_VIEWS = 200
MAX_READ_NAMES = 64
MAX_PENDING_CALLS = 2000
MAX_API_CLICKS = 200
MAX_SELECTOR = 300

_PARAM_NAME = re.compile(r"^[A-Za-z_$][\w$.\-\[\]]{0,63}$")
_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-f]{16,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
                         re.IGNORECASE)
_ROUTE_PATH = re.compile(r"^/[\w\-./~%]*$")


def _ok_name(name: str) -> bool:
    return bool(_PARAM_NAME.match(name or ""))


def _volatile(name: str, value: str) -> bool:
    from harness.volatile_params import is_volatile_value
    return is_volatile_value(name, value)


def _route_template(path: str) -> str:
    """Route path with object-id segments collapsed, for dedup only."""
    return "/".join("{id}" if _ID_SEGMENT.match(seg) else seg for seg in path.split("/"))


def _clean_route_path(path: str) -> str | None:
    path = (path or "").strip()
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    if not _ROUTE_PATH.match(path) or len(path) > 200:
        return None
    return path


def _excluded(path: str) -> bool:
    """A route that looks destructive (logout, delete, ...) or is a file download."""
    from harness.spa_navigation import _DESTRUCTIVE, _DOWNLOAD
    return bool(_DESTRUCTIVE.search(path) or _DOWNLOAD.search(path))


# A router config's `path:` entries, a child route joined to its parents' paths.
# The scan skips string, comment and regular-expression literals, so a bracket in
# one never shifts the nesting. `path` and `open`/`close` are the tokens it acts on.
_ROUTER_ANY_PATH = re.compile(r"\bpath\s*:\s*[\"'`]([\w\-./:?$*]*)[\"'`]")
_ROUTE_SCAN = re.compile(
    r"\bpath\s*:\s*([\"'`])(?P<path>[\w\-./:?$*]*)\1"
    r"|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`"
    r"|(?<=[(,=:\[!&|?{};])/(?![*/])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/"
    r"|/\*[\s\S]*?\*/|//[^\n]*"
    r"|(?P<open>[{\[])|(?P<close>[}\]])")
_CHILDREN_KEY = re.compile(r"[\"']?\bchildren[\"']?\s*:\s*$")
_MAX_NESTING = 2000


def _flat_router_entries(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(m.group(1) for m in _ROUTER_ANY_PATH.finditer(text)))


@lru_cache(maxsize=2)
def _router_entries(text: str) -> tuple[str, ...]:
    """Every `path: '...'` value of a script's router config, raw and in order,
    each child route (an object in another's `children: [...]`) prefixed with its
    parents' paths: `{path: 'admin', children: [{path: 'users'}]}` declares `admin`
    and `admin/users`. A child path starting with `/` is absolute and kept as is;
    a parent with no path (a layout route) adds nothing. A script with no
    `children` key, or nesting too deep to be a config, is read flat."""
    if "children" not in text:
        return _flat_router_entries(text)
    stack: list[dict] = []
    entries: list[tuple] = []
    for m in _ROUTE_SCAN.finditer(text):
        raw, opener, closer = m.group("path"), m.group("open"), m.group("close")
        if raw is not None:
            frame = stack[-1] if stack and stack[-1]["t"] == "{" else None
            if frame is not None and frame["path"] is None:
                frame["path"] = raw
            entries.append((frame, raw))
        elif opener == "{":
            top = stack[-1] if stack else None
            stack.append({"t": "{", "path": None,
                          "parent": top["of"] if top is not None and top["t"] == "[" else None})
        elif opener == "[":
            top = stack[-1] if stack else None
            of = top if (top is not None and top["t"] == "{"
                         and _CHILDREN_KEY.search(text, max(0, m.start() - 40), m.start())) else None
            stack.append({"t": "[", "of": of})
        elif closer:
            want = "{" if closer == "}" else "["
            for i in range(len(stack) - 1, -1, -1):
                if stack[i]["t"] == want:
                    del stack[i:]
                    break
        if len(stack) > _MAX_NESTING:
            return _flat_router_entries(text)
    out: dict[str, None] = {}
    for frame, raw in entries:
        parts = [raw]
        parent = frame["parent"] if frame is not None else None
        hops = 0
        while parent is not None and hops < 12 and not parts[0].startswith("/"):
            if parent["path"]:
                parts.insert(0, parent["path"])
            parent = parent["parent"]
            hops += 1
        joined = "/".join(p.strip("/") for p in parts if p.strip("/"))
        out[("/" if parts[0].startswith("/") else "") + joined] = None
    return tuple(out)


def _router_config_paths(text: str) -> list[str]:
    """`path: '...'` entries of a router config (child routes under their parents'
    paths), cleaned, in order: no path parameter (`:id`), wildcard, file name or
    absolute URL."""
    out: list[str] = []
    for raw in _router_entries(text):
        if (":" in raw or "*" in raw or "." in raw.rsplit("/", 1)[-1]
                or raw.startswith(("http", "//"))):
            continue
        path = _clean_route_path(raw)
        if path is not None and path not in out:
            out.append(path)
    return out


_SEGMENT_NAME = re.compile(r"^:([A-Za-z_$][\w$]*)\??$")
_PLAIN_SEGMENT = re.compile(r"^[\w\-.~%]+$")


def route_segments(path: str) -> list[str]:
    """The names of a route path's `:name` segments, in order (`/item/:id` -> ["id"])."""
    out: list[str] = []
    for seg in (path or "").split("/"):
        m = _SEGMENT_NAME.match(seg)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def _segment_route_path(raw: str) -> str | None:
    """A router-config path with at least one `:name` segment, cleaned (`item/:id?`
    -> `/item/:id`), or None for a wildcard, a file, an absolute URL, a malformed
    segment or a destructive-looking route."""
    raw = (raw or "").strip()
    if not raw or "*" in raw or raw.startswith(("http", "//")):
        return None
    out = []
    for seg in [s for s in raw.split("/") if s]:
        m = _SEGMENT_NAME.match(seg)
        if m:
            out.append(":" + m.group(1))
        elif _PLAIN_SEGMENT.match(seg):
            out.append(seg)
        else:
            return None
    if not any(s.startswith(":") for s in out) or len(out) > 12:
        return None
    if not out[-1].startswith(":") and "." in out[-1]:
        return None
    path = "/" + "/".join(out)
    return path if len(path) <= 200 and not _excluded(path) else None


def _router_segment_paths(text: str) -> list[str]:
    """`path: '...'` entries of a router config that have a `:name` segment (child
    routes under their parents' paths), cleaned, in order."""
    out: list[str] = []
    for raw in _router_entries(text):
        if ":" not in raw:
            continue
        path = _segment_route_path(raw)
        if path is not None and path not in out and len(out) < MAX_ROUTES:
            out.append(path)
    return out


def declared_views(body: str, limit: int = MAX_ROUTES) -> tuple[list[str], bool]:
    """The client routes a script's router config declares that take no
    parameter, as `(paths, hash_hint)`. The paths are in order and none is the
    root or looks destructive or like a download. `hash_hint` says whether the
    script configures hash routing. The SPA crawl visits these paths as views
    when nothing links to them (driver_capture.declared_views)."""
    text = (body or "")[:5_000_000]
    paths = [p for p in _router_config_paths(text) if p != "/" and not _excluded(p)]
    return paths[:max(0, limit)], bool(_HASH_HINTS.search(text))


def fragment_route(fragment: str) -> tuple[str, str, str] | None:
    """`(prefix, route path, route query)` when a URL fragment is a client route
    (`/r?q`, `!/r?q`), else None. The prefix is "!" for a hashbang route."""
    frag = fragment or ""
    prefix = ""
    if frag.startswith("!/"):
        prefix, frag = "!", frag[1:]
    if not frag.startswith("/"):
        return None
    path, _, query = frag.partition("?")
    return prefix, path, query


def _fill_segment(path: str, token: str, payload: str) -> str:
    """`path` with its `token` segment set to `payload`, percent-encoded with no safe
    character, so a `/` in the payload stays inside that one segment."""
    return "/".join(quote(payload, safe="") if s == token else s for s in path.split("/"))


def _set_param(query: str, name: str, value: str) -> str:
    """`query` with `name` set to `value`: the first occurrence is replaced and later
    ones are dropped; a name the query lacks is appended. The value is
    percent-encoded with no safe characters, so the payload survives a router's
    decode as the same text."""
    pairs = parse_qsl(query or "", keep_blank_values=True)
    out, placed = [], False
    for k, v in pairs:
        if k == name:
            if not placed:
                out.append((k, value))
                placed = True
            continue
        out.append((k, v))
    if not placed:
        out.append((name, value))
    return urlencode(out, quote_via=quote, safe="")


def probe_url(url: str, values: dict[str, str]) -> str | None:
    """The view URL with each of `values` set as a route input: in the fragment
    route's query for a hash route (`/#/r?name=value`), in the page's own query
    otherwise (a fragment that is no route is dropped). None for no values."""
    if not values:
        return None
    parts = urlsplit(url)
    fr = fragment_route(parts.fragment)
    if fr is not None:
        prefix, path, query = fr
        for name, value in values.items():
            query = _set_param(query, name, value)
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query,
                           f"{prefix}{path}?{query}"))
    query = parts.query
    for name, value in values.items():
        query = _set_param(query, name, value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))


def payload_url(url: str, location: str, name: str, payload: str) -> str | None:
    """The page URL with one client-side input set to `payload`.

    `route`: a parameter of the fragment route (`/#/r?name=<payload>`), which is never
    sent to the server. `page`: a parameter of the page's own query
    (`/r?name=<payload>`). `query`: a parameter of the captured URL's own query,
    with its fragment kept. `segment`: the route path's `:name` segment (the fragment
    route's for a hash route, the page path's otherwise). Returns None when `url`
    has no fragment route for a `route` input, or no `:name` segment for a
    `segment` input."""
    parts = urlsplit(url)
    if location == ROUTE:
        fr = fragment_route(parts.fragment)
        if fr is None:
            return None
        prefix, path, query = fr
        frag = f"{prefix}{path}?{_set_param(query, name, payload)}"
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, frag))
    if location == PAGE:
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/",
                           _set_param(parts.query, name, payload), ""))
    if location == QUERY:
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/",
                           _set_param(parts.query, name, payload), parts.fragment))
    if location == SEGMENT:
        token = ":" + (name or "")
        fr = fragment_route(parts.fragment)
        if fr is not None:
            prefix, path, query = fr
            if token not in path.split("/"):
                return None
            frag = prefix + _fill_segment(path, token, payload) + (f"?{query}" if query else "")
            return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, frag))
        path = parts.path or "/"
        if token not in path.split("/"):
            return None
        return urlunsplit((parts.scheme, parts.netloc, _fill_segment(path, token, payload),
                           parts.query, ""))
    return None


def route_params_of_template(template: dict | None) -> tuple[str, list[str]]:
    """`(location, parameter names)` of the client route a coverage template carries,
    or ("", [])."""
    cr = (template or {}).get("client_route") if isinstance(template, dict) else None
    if not isinstance(cr, dict):
        return "", []
    location = cr.get("location") or ""
    if location not in CLIENT_ROUTE_LOCATIONS:
        return "", []
    return location, [p for p in (cr.get("params") or []) if isinstance(p, str) and p]


def route_segments_of_template(template: dict | None) -> list[str]:
    """The `:name` segment names of the client route a coverage template carries."""
    cr = (template or {}).get("client_route") if isinstance(template, dict) else None
    if not isinstance(cr, dict) or (cr.get("location") or "") not in CLIENT_ROUTE_LOCATIONS:
        return []
    return [s for s in (cr.get("segments") or []) if isinstance(s, str) and _ok_name(s)]


@dataclass
class ClientRoute:
    """One client-side route. `document` is the path of the HTML document the
    router runs in, and for a history route it is also the route itself. `route`
    is the route path inside the fragment for a hash route, with a "!" prefix for
    a hashbang route."""
    kind: str
    document: str
    route: str = ""
    params: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def path(self) -> str:
        return f"{self.document}#{self.route}" if self.kind == HASH else self.document

    @property
    def location(self) -> str:
        return ROUTE if self.kind == HASH else PAGE

    @property
    def segments(self) -> list[str]:
        """The names of the route path's `:name` segments (router-declared path
        parameters), in order."""
        return route_segments(self.route if self.kind == HASH else self.document)

    @property
    def endpoint_key(self) -> str:
        return f"GET {self.path}"

    def dedup_key(self) -> tuple:
        if self.kind == HASH:
            return (HASH, self.document, _route_template(self.route))
        return (HISTORY, _route_template(self.document), "")

    def add_params(self, names, source: str) -> None:
        for name in names:
            if name not in self.params and _ok_name(name) and len(self.params) < MAX_PARAMS:
                self.params.append(name)
        if source and source not in self.sources:
            self.sources.append(source)

    def seed_url(self, base_url: str) -> str:
        """The route's page URL on `base_url`'s origin, each parameter blank."""
        parts = urlsplit(base_url)
        query = "&".join(f"{quote(p, safe='')}=" for p in self.params)
        if self.kind == HASH:
            frag = self.route + (f"?{query}" if query else "")
            return urlunsplit((parts.scheme, parts.netloc, self.document, "", frag))
        return urlunsplit((parts.scheme, parts.netloc, self.document, query, ""))

    def template(self) -> dict:
        """A coverage template: no server inputs, the route's parameters as client inputs."""
        return {"method": "GET", "query": "", "body": "", "content_type": "", "object_id": None,
                "path_ids": [],
                "client_route": {"kind": self.kind, "location": self.location,
                                 "params": list(self.params), "segments": self.segments,
                                 "sources": list(self.sources)}}

    def to_dict(self) -> dict:
        return {"kind": self.kind, "document": self.document, "route": self.route,
                "params": list(self.params), "sources": list(self.sources)}

    @classmethod
    def from_dict(cls, d: dict) -> "ClientRoute":
        return cls(kind=d.get("kind", HASH), document=d.get("document", "/") or "/",
                   route=d.get("route", "") or "", params=list(d.get("params") or []),
                   sources=list(d.get("sources") or []))


# --- JavaScript bundle patterns (generic router idioms, no application names) ---
_Q = r"[\"'`]"
_HASH_LITERAL = re.compile(_Q + r"#(!?/[\w\-./~%]*)(?:\?([^\"'`\s<>]*))?" + _Q)
_PATH_QUERY_LITERAL = re.compile(_Q + r"(/[\w\-./~%]*)\?((?:[\w\-$.\[\]]+=[^\"'`&\s<>]*&?)+)")
_NAVIGATE_QP = re.compile(
    r"navigate\(\s*\[\s*" + _Q + r"(/?[\w\-./]*)" + _Q + r"[^\]]{0,200}\]\s*,\s*\{[^{}]{0,200}?"
    r"queryParams\s*:\s*\{([^{}]{0,400})\}")
_PUSH_QUERY = re.compile(
    r"\{\s*path\s*:\s*" + _Q + r"(/[\w\-./]*)" + _Q + r"\s*,\s*query\s*:\s*\{([^{}]{0,400})\}")
_READS = [
    re.compile(r"queryParamMap\.get\(\s*" + _Q + r"([\w\-$]+)" + _Q),
    re.compile(r"queryParams\s*\[\s*" + _Q + r"([\w\-$]+)" + _Q + r"\s*\]"),
    # `snapshot.queryParams.q`, `location.query.q`: a property read, not a call.
    re.compile(r"\b(?:queryParams|location\.query)\.([A-Za-z_$][\w$]*)\b(?!\s*\()"),
    re.compile(r"searchParams\.get\(\s*" + _Q + r"([\w\-$]+)" + _Q),
    re.compile(r"URLSearchParams\([^()]{0,120}\)\.get\(\s*" + _Q + r"([\w\-$]+)" + _Q),
    re.compile(r"\broute\.query\.([A-Za-z_$][\w$]*)"),
    re.compile(r"\broute\.query\[\s*" + _Q + r"([\w\-$]+)" + _Q),
]
# Property names of the router objects themselves, never a parameter name.
_READ_STOPWORDS = frozenset({"get", "getAll", "has", "keys", "pipe", "subscribe", "value",
                             "length", "forEach", "toString", "then", "map", "params"})


def read_names_of(body: str, limit: int = 64) -> list[str]:
    """The route-parameter names a JavaScript bundle reads from the router or from
    location.search, in order (`URLSearchParams(...).get("q")`,
    `queryParamMap.get("q")`, `queryParams.q`, `route.query.q`, ...). A name read
    is not yet a route input: nothing says which route reads it."""
    text = (body or "")[:5_000_000]
    out: list[str] = []
    for pattern in _READS:
        for m in pattern.finditer(text):
            name = m.group(1)
            if (_ok_name(name) and name not in _READ_STOPWORDS and name not in out
                    and len(out) < limit):
                out.append(name)
    return out


_HASH_HINTS = re.compile(r"useHash\s*:\s*(?:!0|true)\b|createWebHashHistory|HashLocationStrategy|"
                         r"\bHashRouter\b|\bmode\s*:\s*[\"']hash[\"']")
_HTML_ROUTE_ATTR = re.compile(
    r"\s(href|routerlink|ng-reflect-router-link|data-href|data-route|to)\s*=\s*([\"'])(.*?)\2",
    re.IGNORECASE | re.DOTALL)


def _object_keys(body: str) -> list[str]:
    """The top-level keys of a small object literal's inner text (`q:t,page:1`)."""
    depth, cur, parts = 0, "", []
    for ch in body:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    out = []
    for part in parts:
        m = re.match(r"\s*[\"']?([A-Za-z_$][\w$\-]*)[\"']?\s*(?::|$)", part)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def _view_route(view_url: str) -> "ClientRoute | None":
    """The route of a view URL as loaded (a hash route, else a history route),
    its parameters dropped; None when its path is no route."""
    parts = urlsplit(view_url)
    fr = fragment_route(parts.fragment)
    if fr is not None:
        prefix, path, _query = fr
        clean = _clean_route_path(path)
        return None if clean is None else ClientRoute(HASH, parts.path or "/", prefix + clean)
    clean = _clean_route_path(parts.path or "/")
    return None if clean is None else ClientRoute(HISTORY, clean)


class ClientRouteMap:
    """The client-side routes one engagement learned, bounded and value-free once
    finalized."""

    def __init__(self):
        self._routes: dict[tuple, ClientRoute] = {}
        # Router paths whose kind (hash or history) depends on the app's routing
        # mode: templated path -> ClientRoute (kind left to `routes()`).
        self._router: dict[str, ClientRoute] = {}
        self.router_paths: set[str] = set()
        self.read_names: list[str] = []
        self.hash_hint = False
        # "METHOD path" -> [{"route": dedup key as list, "route_param", "api_param"}]
        self.api_links: dict[str, list[dict]] = {}
        # "GET path" -> [[kind, document, route]]: the views a crawl saw read that
        # API, the route only (never a value). A value the API returns may be
        # rendered by any of them (views_for_api; stored_xss loads them).
        self.api_views: dict[str, list[list[str]]] = {}
        # "GET path" -> [[kind, document, route, selector]]: click recipes. A crawl
        # (driver_capture.click_explore) saw that API read only after clicking the
        # control `selector` names on that view, e.g. a dialog that fetches and
        # renders its content (clicks_for_api; stored_xss replays the recipe).
        self.api_clicks: dict[str, list[list[str]]] = {}
        # In memory only, never persisted: (view url, method, api url, body).
        self._pending: list[tuple[str, str, str, str]] = []
        # Query-bearing path literals from bundles, kept until the router config
        # (which may be mined later) says whether the path is a route.
        self._literals: list[tuple[str, list[str]]] = []
        self.origin: tuple[str, str] | None = None

    # --- bookkeeping ---

    def __len__(self) -> int:
        return len(self.routes())

    def _same_origin(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return False
        if self.origin is None:
            self.origin = (parts.scheme, parts.netloc)
            return True
        return (parts.scheme, parts.netloc) == self.origin

    def _put(self, route: ClientRoute, names, source: str) -> ClientRoute | None:
        key = route.dedup_key()
        known = self._routes.get(key)
        if known is None:
            if len(self._routes) >= MAX_ROUTES:
                return None
            self._routes[key] = known = route
        known.add_params(names, source)
        return known

    def _put_router(self, path: str, names, source: str) -> None:
        path = _clean_route_path(path)
        if path is None or _excluded(path):
            return
        key = _route_template(path)
        known = self._router.get(key)
        if known is None:
            if len(self._router) >= MAX_ROUTES:
                return
            self._router[key] = known = ClientRoute(kind="", document="/", route=path)
        known.add_params(names, source)

    def _put_segment_route(self, path: str, names, source: str) -> None:
        """A router path with a `:name` segment (already cleaned by
        _segment_route_path, which _clean_route_path would reject)."""
        key = _route_template(path)
        if key not in self._router and len(self._router) < MAX_ROUTES:
            self._router[key] = ClientRoute(kind="", document="/", route=path)
        if key in self._router:
            self._router[key].add_params(names, source)

    # --- sources ---

    def add_url(self, url: str, source: str) -> ClientRoute | None:
        """A page URL seen as a link or a crawled view. A fragment route is a hash
        route; any other URL is a history route (its page query is its input).
        Parameter values are read for the volatile check only, never kept."""
        if not self._same_origin(url):
            return None
        parts = urlsplit(url)
        fr = fragment_route(parts.fragment)
        if fr is not None:
            prefix, path, query = fr
            path = _clean_route_path(path)
            if path is None or _excluded(path):
                return None
            pairs = parse_qsl(query, keep_blank_values=True)
            names = [k for k, v in pairs if not _volatile(k, v)]
            return self._put(ClientRoute(HASH, parts.path or "/", prefix + path), names, source)
        path = _clean_route_path(parts.path or "/")
        if path is None or _excluded(path):
            return None
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        names = [k for k, v in pairs if not _volatile(k, v)]
        return self._put(ClientRoute(HISTORY, path), names, source)

    def mine_html(self, body: str, page_url: str) -> None:
        """Route links in an HTML document: an `href` is resolved against the page
        (a fragment route is a hash route; a same-origin link with a query is a page
        input); a router attribute value is a router path."""
        from harness.spa_navigation import resolve_view
        if not body or not self._same_origin(page_url):
            return
        for m in _HTML_ROUTE_ATTR.finditer(body[:2_000_000]):
            attr, raw = m.group(1).lower(), (m.group(3) or "").strip()
            if not raw or len(raw) > 500 or "{{" in raw:
                continue
            if attr == "href" or raw.startswith("#") or "://" in raw:
                resolved = resolve_view(page_url, raw)
                if resolved is None:
                    continue
                parts = urlsplit(resolved)
                if fragment_route(parts.fragment) is not None or parts.query:
                    self.add_url(resolved, "link")
                continue
            path, _, query = raw.partition("?")
            names = [k for k, v in parse_qsl(query, keep_blank_values=True) if not _volatile(k, v)]
            self._put_router(path, names, "link")

    def mine_script(self, body: str) -> None:
        """Route-shaped strings in a same-origin JavaScript bundle."""
        if not body:
            return
        text = body[:5_000_000]
        if _HASH_HINTS.search(text):
            self.hash_hint = True
        for path in _router_config_paths(text):
            if len(self.router_paths) < MAX_ROUTES:
                self.router_paths.add(path)
        for path in _router_segment_paths(text):
            # A path parameter: the route's `:name` segment is its input.
            self._put_segment_route(path, (), "router")
        for m in _HASH_LITERAL.finditer(text):
            if self.origin is None:
                continue
            path, query = m.group(1), m.group(2) or ""
            names = [k for k, v in parse_qsl(query, keep_blank_values=True) if not _volatile(k, v)]
            prefix = "!" if path.startswith("!") else ""
            clean = _clean_route_path(path.lstrip("!"))
            if clean is None or _excluded(clean):
                continue
            self.hash_hint = True
            self._put(ClientRoute(HASH, "/", prefix + clean), names, "bundle")
        for m in _NAVIGATE_QP.finditer(text):
            self._put_router(m.group(1), _object_keys(m.group(2)), "bundle")
        for m in _PUSH_QUERY.finditer(text):
            self._put_router(m.group(1), _object_keys(m.group(2)), "bundle")
        for m in _PATH_QUERY_LITERAL.finditer(text):
            path = _clean_route_path(m.group(1))
            if path is None:
                continue
            names = [k for k, v in parse_qsl(m.group(2), keep_blank_values=True)
                     if not _volatile(k, v)]
            # Only a path the router declares: any other query-bearing string is a
            # server URL, which the crawler already records as an endpoint.
            if path in self.router_paths:
                self._put_router(path, names, "bundle")
            elif len(self._literals) < MAX_ROUTES and (path, names) not in self._literals:
                self._literals.append((path, names))
        for name in read_names_of(text, MAX_READ_NAMES):
            if name not in self.read_names and len(self.read_names) < MAX_READ_NAMES:
                self.read_names.append(name)

    def add_view_calls(self, view_url: str, calls) -> None:
        """The API calls (method, url, body) a crawled view fired, kept in memory
        until `finalize` maps them back to the view's route."""
        if not self._same_origin(view_url):
            return
        self.add_url(view_url, "crawl")
        for method, url, body in calls or ():
            if len(self._pending) >= MAX_PENDING_CALLS:
                return
            self._pending.append((view_url, (method or "GET").upper(), url or "", body or ""))

    def add_probe(self, probe_url: str, names, calls) -> None:
        """A route probe (spa_navigation's `route_probes`): the crawl loaded a view
        with a marker value in each parameter name the bundles read. `names` are
        the ones the view showed or sent, which become the route's inputs. The calls
        fired then are mapped back like any view's: finalize matches a call's
        values to the markers in `probe_url`. The probe URL itself is no view, so a
        name in it that the view neither showed nor sent is no input."""
        if not self._same_origin(probe_url):
            return
        parts = urlsplit(probe_url)
        fr = fragment_route(parts.fragment)
        if fr is not None:
            prefix, path, _query = fr
            clean = _clean_route_path(path)
            route = None if clean is None else ClientRoute(HASH, parts.path or "/", prefix + clean)
        else:
            clean = _clean_route_path(parts.path or "/")
            route = None if clean is None else ClientRoute(HISTORY, clean)
        if route is None or _excluded(clean):
            return
        if names:
            self._put(route, [n for n in names if _ok_name(n)], "probe")
        for method, url, body in calls or ():
            if len(self._pending) >= MAX_PENDING_CALLS:
                return
            self._pending.append((probe_url, (method or "GET").upper(), url or "", body or ""))

    def add_click(self, view_url: str, selector: str, calls) -> None:
        """A click recipe (spa_navigation click exploration): on the view loaded as
        `view_url`, clicking the control `selector` names fired `calls` (method,
        url, body). Each same-origin GET is kept by route, the route only (never a
        value), so a read-back can reproduce "open the view, click the control"."""
        from harness.engagement import normalize_path
        selector = str(selector or "").strip()
        if not selector or len(selector) > MAX_SELECTOR or not self._same_origin(view_url):
            return
        route = _view_route(view_url)
        if route is None or _excluded(route.route.lstrip("!") if route.kind == HASH
                                      else route.document):
            return
        recipe = [route.kind, route.document, route.route, selector]
        netloc = urlsplit(view_url).netloc
        for method, url, _body in calls or ():
            if (method or "GET").upper() != "GET" or urlsplit(url or "").netloc not in ("", netloc):
                continue
            key = f"GET {normalize_path(url)}"
            recipes = self.api_clicks.get(key) or []
            if recipe in recipes or sum(len(v) for v in self.api_clicks.values()) >= MAX_API_CLICKS:
                continue
            self.api_clicks[key] = recipes + [recipe]

    def clicks_for_api(self, method: str, url: str) -> list[tuple[str, str]]:
        """(page URL, selector) for each click recipe that read this API path
        (object ids collapsed): the view on `url`'s origin with no parameter set,
        and the control to click there, in the order seen."""
        from harness.engagement import normalize_path
        out: list[tuple[str, str]] = []
        for entry in self.api_clicks.get(
                f"{(method or 'GET').upper()} {normalize_path(url)}") or []:
            if not (isinstance(entry, (list, tuple)) and len(entry) == 4):
                continue
            kind, document, route, selector = entry
            pair = (ClientRoute(kind, document, route).seed_url(url), selector)
            if pair not in out:
                out.append(pair)
        return out

    def merge(self, other: "ClientRouteMap | None") -> None:
        if other is None:
            return
        if self.origin is None:
            self.origin = other.origin
        for route in other._routes.values():
            self._put(ClientRoute(route.kind, route.document, route.route), route.params,
                      route.sources[0] if route.sources else "")
            for s in route.sources[1:]:
                self._put(ClientRoute(route.kind, route.document, route.route), (), s)
        for route in other._router.values():
            for s in route.sources or [""]:
                if route_segments(route.route):
                    self._put_segment_route(route.route, route.params, s)
                else:
                    self._put_router(route.route, route.params, s)
        self.router_paths |= set(list(other.router_paths)[:MAX_ROUTES])
        for name in other.read_names:
            if name not in self.read_names and len(self.read_names) < MAX_READ_NAMES:
                self.read_names.append(name)
        self.hash_hint = self.hash_hint or other.hash_hint
        for key, links in other.api_links.items():
            for link in links:
                self._link(key, link)
        for key, views in other.api_views.items():
            for kind, document, route in views:
                self._view_link(key, ClientRoute(kind, document, route))
        for key, recipes in other.api_clicks.items():
            for recipe in recipes:
                known = self.api_clicks.get(key) or []
                if (list(recipe) not in known
                        and sum(len(v) for v in self.api_clicks.values()) < MAX_API_CLICKS):
                    self.api_clicks[key] = known + [list(recipe)]
        self._pending.extend(other._pending[:max(0, MAX_PENDING_CALLS - len(self._pending))])
        for literal in other._literals:
            if len(self._literals) < MAX_ROUTES and literal not in self._literals:
                self._literals.append(literal)

    # --- materialised view ---

    def hash_routed(self) -> bool:
        return self.hash_hint or any(r.kind == HASH for r in self._routes.values())

    def _hash_document(self) -> str:
        docs = [r.document for r in self._routes.values() if r.kind == HASH]
        return min(docs, key=lambda d: (docs.count(d) * -1, len(d))) if docs else "/"

    def routes(self) -> list[ClientRoute]:
        """Every route, router paths resolved to the app's routing mode."""
        out: dict[tuple, ClientRoute] = {
            k: ClientRoute(r.kind, r.document, r.route, list(r.params), list(r.sources))
            for k, r in self._routes.items()}
        hashed = self.hash_routed()
        doc = self._hash_document()
        router = {k: ClientRoute("", "/", r.route, list(r.params), list(r.sources))
                  for k, r in self._router.items()}
        for path, names in self._literals:
            if path in self.router_paths and not _excluded(path):
                known = router.setdefault(_route_template(path), ClientRoute("", "/", path))
                known.add_params(names, "bundle")
        for r in router.values():
            route = (ClientRoute(HASH, doc, r.route) if hashed
                     else ClientRoute(HISTORY, r.route))
            key = route.dedup_key()
            known = out.get(key)
            if known is None:
                if len(out) >= MAX_ROUTES:
                    continue
                out[key] = known = route
            for s in r.sources or [""]:
                known.add_params(r.params, s)
        return list(out.values())

    def inputs(self) -> list[ClientRoute]:
        """The routes that read at least one parameter or have a `:name` segment."""
        return [r for r in self.routes() if r.params or r.segments]

    def route_for_key(self, endpoint_key: str) -> ClientRoute | None:
        return next((r for r in self.inputs() if r.endpoint_key == endpoint_key), None)

    def _link(self, api_key: str, link: dict) -> None:
        links = self.api_links.setdefault(api_key, [])
        if link not in links and sum(len(v) for v in self.api_links.values()) < MAX_API_LINKS:
            links.append(link)

    def finalize(self) -> None:
        """Map each pending API call back to the route of the view that fired it,
        then drop the pending calls (they carry values). A link needs evidence: the
        call carries the value one of the view's route parameters had, or names a
        parameter the bundles read from the router."""
        from harness.engagement import normalize_path
        pending, self._pending = self._pending, []
        for view_url, method, api_url, body in pending:
            parts = urlsplit(view_url)
            fr = fragment_route(parts.fragment)
            if fr is not None:
                prefix, path, query = fr
                clean = _clean_route_path(path)
                if clean is None:
                    continue
                route = ClientRoute(HASH, parts.path or "/", prefix + clean)
            else:
                clean = _clean_route_path(parts.path or "/")
                if clean is None:
                    continue
                route, query = ClientRoute(HISTORY, clean), parts.query
            values = {k: v for k, v in parse_qsl(query, keep_blank_values=True)
                      if len(v) >= 2 and not _volatile(k, v)}
            api_parts = urlsplit(api_url)
            api_params = [(k, v) for k, v in parse_qsl(api_parts.query, keep_blank_values=True)
                          if _ok_name(k)]
            api_params += _body_params(body)
            api_key = f"{method} {normalize_path(api_url)}"
            if (method == "GET" and api_parts.netloc in ("", parts.netloc)
                    and not _excluded(clean)):
                # The view read this API: what the API returns, the view may render.
                self._view_link(api_key, route)
            for api_name, api_value in api_params:
                route_param = next((k for k, v in values.items() if v == api_value), None)
                if (route_param is None and api_name in self.read_names
                        and not (route.kind == HISTORY and self.hash_routed())):
                    # The bundles read this name from the router, and the view
                    # sent it: the view's route reads it. A non-route view of a
                    # hash-routed app has no router query to read it from.
                    route_param = api_name
                if route_param is None:
                    continue
                known = self._put(ClientRoute(route.kind, route.document, route.route),
                                  [route_param], "api_map")
                if known is None:
                    continue
                self._link(api_key, {"route": list(known.dedup_key()), "route_param": route_param,
                                     "api_param": api_name})

    def routes_for_api(self, method: str, url: str) -> list[tuple[ClientRoute, str, str]]:
        """`(route, route parameter, API parameter)` for each route a crawled view
        showed issuing this API call."""
        from harness.engagement import normalize_path
        links = self.api_links.get(f"{(method or 'GET').upper()} {normalize_path(url)}") or []
        if not links:
            return []
        by_key = {r.dedup_key(): r for r in self.routes()}
        out = []
        for link in links:
            route = by_key.get(tuple(link.get("route") or ()))
            if route is not None:
                out.append((route, link.get("route_param", ""), link.get("api_param", "")))
        return out

    def _view_link(self, api_key: str, route: ClientRoute) -> None:
        view = [route.kind, route.document, route.route]
        views = self.api_views.get(api_key) or []
        if view in views or sum(len(v) for v in self.api_views.values()) >= MAX_API_VIEWS:
            return
        self.api_views[api_key] = views + [view]

    def views_for_api(self, method: str, url: str) -> list[str]:
        """The page URLs, on `url`'s origin with no parameter set, of the views a
        crawl saw read this API path (object ids collapsed), in the order seen."""
        from harness.engagement import normalize_path
        out: list[str] = []
        for kind, document, route in self.api_views.get(
                f"{(method or 'GET').upper()} {normalize_path(url)}") or []:
            view = ClientRoute(kind, document, route).seed_url(url)
            if view not in out:
                out.append(view)
        return out

    # --- persistence (names only, never values) ---

    def to_dict(self) -> dict:
        return {"routes": [r.to_dict() for r in self._routes.values()],
                "router": [r.to_dict() for r in self._router.values()],
                "router_paths": sorted(self.router_paths),
                "read_names": list(self.read_names),
                "hash_hint": self.hash_hint,
                "api_links": {k: list(v) for k, v in self.api_links.items()},
                "api_views": {k: [list(v) for v in vs] for k, vs in self.api_views.items()},
                **({"api_clicks": {k: [list(v) for v in vs] for k, vs in self.api_clicks.items()}}
                   if self.api_clicks else {}),
                "literals": [[p, list(n)] for p, n in self._literals],
                "origin": list(self.origin) if self.origin else None}

    @classmethod
    def from_dict(cls, d: dict | None) -> "ClientRouteMap":
        m = cls()
        d = d or {}
        if d.get("origin"):
            m.origin = tuple(d["origin"])[:2]
        for rd in d.get("routes") or []:
            r = ClientRoute.from_dict(rd)
            m._routes[r.dedup_key()] = r
        for rd in d.get("router") or []:
            r = ClientRoute.from_dict(rd)
            m._router[_route_template(r.route)] = r
        m.router_paths = set(d.get("router_paths") or [])
        m.read_names = list(d.get("read_names") or [])
        m.hash_hint = bool(d.get("hash_hint"))
        m.api_links = {k: list(v) for k, v in (d.get("api_links") or {}).items()}
        m.api_views = {k: [list(v) for v in vs if isinstance(v, (list, tuple)) and len(v) == 3]
                       for k, vs in (d.get("api_views") or {}).items()}
        m.api_clicks = {k: [list(v) for v in vs if isinstance(v, (list, tuple)) and len(v) == 4]
                        for k, vs in (d.get("api_clicks") or {}).items()}
        m._literals = [(p, list(n)) for p, n in (d.get("literals") or [])][:MAX_ROUTES]
        return m

    def summary(self) -> dict:
        inputs = self.inputs()
        return {"routes": len(self.routes()), "routes_with_params": len(inputs),
                "hash_routed": self.hash_routed(),
                "api_links": sum(len(v) for v in self.api_links.values())}


def _body_params(body: str) -> list[tuple[str, str]]:
    """Top-level string or number fields of a JSON or form body (for value matching)."""
    body = (body or "").strip()
    if not body:
        return []
    if body[:1] == "{":
        try:
            data = json.loads(body)
        except ValueError:
            return []
        return [(k, str(v)) for k, v in data.items()
                if isinstance(k, str) and _ok_name(k) and isinstance(v, (str, int, float))
                and not isinstance(v, bool)][:MAX_PARAMS * 2]
    if "=" in body and "\n" not in body:
        return [(k, v) for k, v in parse_qsl(body, keep_blank_values=True) if _ok_name(k)][:MAX_PARAMS * 2]
    return []
