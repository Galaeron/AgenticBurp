"""
Client-side route candidates for the two browser XSS legs (browser_xss, dom_xss).

client_routes.py models a single-page app's route inputs: a parameter inside the
fragment route (`/#/r?p=`, location "route") and a parameter of the page's own query
(`/r?p=`, location "page"). This module turns them into URLs to load in the browser:

- `per_parameter`: a coverage case names one route or page input, so each payload
  goes into that input alone.
- `own_route`: the captured URL is itself a route page, so each of its route
  parameters is tried.
- `mapped_routes`: the captured request is an API call that a crawled view was seen
  issuing (ClientRouteMap.routes_for_api), so the view's route parameter is tried.
  An API call answers JSON, and no page script runs on JSON, so the page that issued
  the call is the place where the payload can run.
- `own_query`: the captured URL is an HTML page, so a page script may read each
  of its own query parameters from location.search (dom_xss).

`interleave` takes the candidate groups in turn, so each kind of input gets a visit
before `max_visits` cuts the list. Every URL keeps the captured URL's origin. The
validator still checks scope, and the browser still polices every request through
the run's scope, gate and budget.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from harness.client_routes import PAGE, QUERY, ROUTE, fragment_route, payload_url

FRAGMENT = "fragment"


@dataclass(frozen=True)
class Candidate:
    url: str
    location: str        # query | route | page | fragment
    parameter: str = ""
    payload: str = ""


def dom_payloads(a: int, b: int) -> list[str]:
    """Payloads for a value a page script writes into the DOM. An `innerHTML` sink
    never runs a `<script>` element, so event-handler payloads come first. Each one,
    if it runs, shows the product a*b in an alert and then logs it."""
    js = f"alert({a}*{b});console.log({a}*{b})"
    return [
        f"<img src=x onerror={js}>",
        f"<svg onload={js}>",
        f"\"><img src=x onerror={js}>",
        f"';{js};//",
        f"javascript:{js}",
        f"<script>{js}</script>",
    ]


def per_parameter(url: str, location: str, name: str, payloads: list[str]) -> list[Candidate]:
    out = []
    for pl in payloads:
        target = payload_url(url, location, name, pl)
        if target is not None:
            out.append(Candidate(target, location, name, pl))
    return out


def route_names(url: str) -> list[str]:
    """The parameter names in a URL's fragment route, in order."""
    fr = fragment_route(urlsplit(url).fragment)
    if fr is None:
        return []
    names = []
    for k, _v in parse_qsl(fr[2], keep_blank_values=True):
        if k and k not in names:
            names.append(k)
    return names


def own_route(url: str, payloads: list[str]) -> list[list[Candidate]]:
    """One group per parameter of the URL's own fragment route."""
    return [per_parameter(url, ROUTE, name, payloads) for name in route_names(url)]


def query_names(url: str) -> list[str]:
    """The parameter names in a URL's own query, in order."""
    names = []
    for k, _v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if k and k not in names:
            names.append(k)
    return names


def own_query(url: str, payloads: list[str]) -> list[list[Candidate]]:
    """One group per parameter of the URL's own query (fragment kept)."""
    return [per_parameter(url, QUERY, name, payloads) for name in query_names(url)]


# Content types of a document a browser runs page script in.
_SCRIPTED_TYPES = ("html", "xml", "svg")


def renders_script(exchange) -> bool | None:
    """Whether the captured response is a document the browser runs page script in:
    True for an HTML, XHTML, XML or SVG content type, False for any other declared
    type (JSON, plain text, an image), None when the capture declares none."""
    ctype = ""
    for k, v in (getattr(exchange, "response_headers", None) or {}).items():
        if str(k).lower() == "content-type":
            ctype = str(v or "").lower()
            break
    if not ctype:
        return None
    return any(t in ctype for t in _SCRIPTED_TYPES)


def mapped_routes(exchange, payloads: list[str], run_context) -> list[list[Candidate]]:
    """One group per (route, route parameter) a crawled view showed issuing this
    request."""
    routes = getattr(run_context, "client_routes", None) if run_context is not None else None
    if routes is None:
        return []
    try:
        links = routes.routes_for_api(exchange.method, exchange.url)
    except Exception:
        return []
    groups, seen = [], set()
    for route, route_param, _api_param in links:
        key = (route.endpoint_key, route_param)
        if not route_param or key in seen:
            continue
        seen.add(key)
        groups.append(per_parameter(route.seed_url(exchange.url), route.location,
                                    route_param, payloads))
    return groups


def interleave(groups: list[list[Candidate]], limit: int) -> list[Candidate]:
    """Take the groups in turn, one candidate each, up to `limit` distinct URLs."""
    out: list[Candidate] = []
    seen: set[str] = set()
    groups = [list(g) for g in groups if g]
    while groups and len(out) < limit:
        nxt = []
        for g in groups:
            c = g.pop(0)
            if c.url not in seen:
                seen.add(c.url)
                out.append(c)
                if len(out) >= limit:
                    break
            if g:
                nxt.append(g)
        groups = nxt
    return out


# The URL standard's fragment percent-encode set: what a browser itself encodes in
# a fragment it navigates to (C0 controls, space, `"`, `<`, `>`, backtick).
_FRAGMENT_ENCODE = {c: f"%{ord(c):02X}" for c in ' "<>`'} | {chr(i): f"%{i:02X}" for i in range(32)}


def browser_fragment(fragment: str) -> str:
    """`fragment` as the browser sends it to location.hash: the characters the
    browser would encode on navigation are encoded here, everything else is kept.
    The page sees the same location.hash either way, but a URL with a raw space in
    it is not a URL the run's scope policy parses, so the browser driver would know
    no origin for it: it would refuse the page without a run scope, and send it
    without the captured identity's cookies and headers with one."""
    return "".join(_FRAGMENT_ENCODE.get(c, c) for c in fragment)


def origin_of(url: str) -> str:
    """`scheme://host[:port]/` of a candidate URL, for the scope check: a payload's
    raw characters in the fragment or query must not decide where it is sent."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}/"


def served_payload(obs, payload: str) -> bool | None:
    """Whether the HTML document the server returned for the visit carried
    `payload` verbatim: True when it did (the server reflected it), False when it
    did not, None when the driver kept no document."""
    bodies = getattr(obs, "navigation_bodies", None)
    if not bodies:
        return None
    return any(payload in (b or "") for b in bodies)


def kinds(candidates: list[Candidate]) -> str:
    """` (2 query, 2 route)`: how many candidates placed their payload where, or ""
    when they are all of one kind."""
    counts: dict[str, int] = {}
    for c in candidates:
        counts[c.location] = counts.get(c.location, 0) + 1
    if len(counts) < 2:
        return ""
    return " (" + ", ".join(f"{n} {k}" for k, n in counts.items()) + ")"


def describe(c: Candidate) -> str:
    """Where the candidate placed its payload, for a summary."""
    if c.location == ROUTE:
        return f"the fragment route parameter {c.parameter!r} (never sent to the server)"
    if c.location == PAGE:
        return f"the page query parameter {c.parameter!r}"
    if c.location == FRAGMENT:
        return "the URL fragment (never sent to the server)"
    return f"the query parameter {c.parameter!r}" if c.parameter else "the query string"
