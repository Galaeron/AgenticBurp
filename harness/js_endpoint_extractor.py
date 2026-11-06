"""
Endpoint / URL extraction from JavaScript and HTML response bodies.

Single-page apps ship their whole API surface inside their JS bundles -- the
paths the front end calls (fetch/axios/XHR string arguments, route tables,
bare string literals) are all sitting in the served JavaScript, even
when no HTML page ever links to them. Crawling only rendered links misses that
surface entirely. This module mines a JS/HTML body for the endpoints it
references, so the harness's site map reflects what the application actually
talks to, not just what a link-follower would reach.

Deterministic, regex-based, no network and no execution of the script (never
eval untrusted JS). Returns normalized path/URL candidates plus light
classification, for scope_discovery / the Burp crawl feature to act on.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

# A path segment charset conservative enough to avoid swallowing code, but
# permissive enough for real routes incl. template-literal placeholders
# (`/user/${id}` -> normalized to `/user/{id}` below).
_PATH = r"/[A-Za-z0-9_\-./~%${}:]+"

# Quoted string literals that look like a site-relative path: "/api/x",
# '/rest/user', `/v2/orders/${id}`. Requires a leading slash and at least one
# more char, and rejects `//` (protocol-relative handled separately) and bare
# `/`.
_QUOTED_PATH = re.compile(r"""['"`](/(?!/)[A-Za-z0-9_\-./~%${}:]*[A-Za-z0-9_\-}%])['"`]""")

# Slash-less API literals a bundle joins onto a host variable itself
# (`this.host + "api/Users"`, `"rest/products/search"`): the leading slash is
# missing, so _QUOTED_PATH skips them, yet they name same-origin routes.
_RELATIVE_API_PATH = re.compile(
    r"""['"`]((?:api|rest)/[A-Za-z0-9_\-./~%${}:]*[A-Za-z0-9_\-}%])['"`]""")

# Absolute URLs anywhere in the body.
_ABS_URL = re.compile(r"""['"`]?(https?://[A-Za-z0-9._\-]+(?::\d+)?(/[^'"`\s<>()]*)?)""")

# Explicit request-call forms: fetch / axios.get|post|... / $.ajax({url:}) /
# XMLHttpRequest.open("GET", "..."). The path is captured from the first
# string argument.
_CALL_FORMS = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|\.open|\.ajax|\.get|\.post|\.put|\.patch|\.delete)\s*\(\s*"""
    r"""(?:['"`](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"`]\s*,\s*)?"""
    r"""['"`](/(?!/)[A-Za-z0-9_\-./~%${}:]*)['"`]""",
    re.IGNORECASE,
)

# Static-asset / noise extensions to drop -- these are not API surface.
_ASSET_EXT = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|avif|mp4|webm|pdf)(?:$|[?#])",
    re.IGNORECASE,
)
# Obvious non-endpoints often caught by the path regex.
_NOISE_PREFIX = ("//", "/node_modules/", "/@", "/assets/", "/static/", "/fonts/")


def _looks_like_endpoint(path: str) -> bool:
    if not path or not path.startswith("/") or path == "/":
        return False
    if path.startswith(_NOISE_PREFIX):
        return False
    if _ASSET_EXT.search(path):
        return False
    # Reject things that are clearly code fragments / regex, not routes.
    if any(c in path for c in ("<", ">", "(", ")", " ", "\\")):
        return False
    return True


def _normalize(path: str) -> str:
    # Collapse template-literal / :param placeholders to a single {id} token
    # so /user/${userId} and /user/:id and /user/42 map together.
    path = re.sub(r"\$\{[^}]*\}", "{id}", path)
    path = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "{id}", path)
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    # strip trailing query/hash for the sitemap key
    path = path.split("?", 1)[0].split("#", 1)[0]
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


# Call-shape forms that also reveal the HTTP METHOD (not just the path), so a
# request can be RECONSTRUCTED from the JS and replayed -- e.g. to test a
# supposedly-authenticated endpoint without credentials (missing_auth_probe).
#   axios.post("/x") / $.post("/x") / http.put("/x")  -> method from the call
#   xhr.open("POST", "/x") / .open("PUT", "/x")        -> method as first arg
#   fetch("/x", { method: "POST" })                    -> method from options
_VERB_CALL = re.compile(
    r"""\.(get|post|put|patch|delete)\s*\(\s*['"`](/(?!/)[A-Za-z0-9_\-./~%${}:]*)['"`]""",
    re.IGNORECASE,
)
_OPEN_CALL = re.compile(
    r"""\.open\s*\(\s*['"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"`]\s*,\s*"""
    r"""['"`](/(?!/)[A-Za-z0-9_\-./~%${}:]*)['"`]""",
    re.IGNORECASE,
)
_FETCH_METHOD = re.compile(
    r"""fetch\s*\(\s*['"`](/(?!/)[A-Za-z0-9_\-./~%${}:]*)['"`]\s*,\s*\{[^}]*?"""
    r"""method\s*:\s*['"`](GET|POST|PUT|PATCH|DELETE)['"`]""",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class CallShape:
    method: str
    path: str  # normalized

    def to_dict(self) -> dict:
        return {"method": self.method, "path": self.path}


def extract_call_shapes(body: str) -> list[CallShape]:
    """Recover (method, path) call shapes from JS so a request can be
    reconstructed and replayed. Deduplicated; methods uppercased. A plain
    `fetch("/x")` with no options object is intentionally NOT emitted here (it
    lands in extract_endpoints as a GET-shaped path already) -- this focuses on
    the forms that pin down a specific, replayable method."""
    if not body:
        return []
    shapes: set[CallShape] = set()
    for rx, method_first in ((_VERB_CALL, True), (_OPEN_CALL, "arg"), (_FETCH_METHOD, False)):
        for m in rx.finditer(body):
            if method_first is True:
                method, path = m.group(1), m.group(2)
            elif method_first == "arg":
                method, path = m.group(1), m.group(2)
            else:  # fetch: path first, method second
                path, method = m.group(1), m.group(2)
            if _looks_like_endpoint(path):
                shapes.add(CallShape(method=method.upper(), path=_normalize(path)))
    return sorted(shapes, key=lambda s: (s.path, s.method))


@dataclass
class ExtractedEndpoints:
    same_origin_paths: set[str] = field(default_factory=set)   # normalized paths on the target
    external_urls: set[str] = field(default_factory=set)       # absolute URLs to other hosts
    from_request_calls: set[str] = field(default_factory=set)  # subset seen in fetch/axios/xhr

    def to_dict(self) -> dict:
        return {
            "same_origin_paths": sorted(self.same_origin_paths),
            "external_urls": sorted(self.external_urls),
            "from_request_calls": sorted(self.from_request_calls),
        }


def extract_endpoints(body: str, base_url: str = "") -> ExtractedEndpoints:
    """Mine a JS/HTML body for endpoint/URL references.

    `base_url` (the URL the body was served from) classifies absolute URLs as
    same-origin vs external and resolves them; when empty, absolute URLs are
    all treated as external and same-origin extraction still works on the
    relative paths.
    """
    out = ExtractedEndpoints()
    if not body:
        return out

    base_host = urlsplit(base_url).netloc if base_url else ""

    # 1. request-call forms first (highest-signal), so we can tag them.
    for m in _CALL_FORMS.finditer(body):
        p = m.group(1)
        if _looks_like_endpoint(p):
            norm = _normalize(p)
            out.same_origin_paths.add(norm)
            out.from_request_calls.add(norm)

    # 2. every quoted path-shaped literal.
    for m in _QUOTED_PATH.finditer(body):
        p = m.group(1)
        if _looks_like_endpoint(p):
            out.same_origin_paths.add(_normalize(p))

    # 2b. slash-less api/... and rest/... literals.
    for m in _RELATIVE_API_PATH.finditer(body):
        p = "/" + m.group(1)
        if _looks_like_endpoint(p):
            out.same_origin_paths.add(_normalize(p))

    # 3. absolute URLs -> same-origin path (if host matches) or external.
    for m in _ABS_URL.finditer(body):
        url = m.group(1)
        host = urlsplit(url).netloc
        if base_host and host == base_host:
            path = urlsplit(url).path or "/"
            if _looks_like_endpoint(path):
                out.same_origin_paths.add(_normalize(path))
        else:
            if not _ASSET_EXT.search(url):
                out.external_urls.add(url)

    return out
