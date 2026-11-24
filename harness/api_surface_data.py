"""Data and pure helpers of the API surface discovery: the probe wordlists and thresholds, the
Route and SurfaceResult records, the scope and not-found helpers, and the HTML / OpenAPI
spec parsing helpers.

Part of the ARC-9 split of harness.api_surface_discovery. Import these names from
harness.api_surface_discovery, the facade, not from this module.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from harness import scope_lock


# Framework "route does not exist" markers some apps leak in the body (Flask/
# Werkzeug wraps 404s this way; others return a bare 404 status, handled too).
_NOT_FOUND_MARKERS = (
    "werkzeug.exceptions.NotFound",
    "404 Not Found: The requested URL was not found",
)

# Well-known machine-readable API contracts. If any is served, it is the surface.
SPEC_PATHS = (
    "/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json",
    "/api-docs", "/api/docs", "/v3/api-docs", "/swagger/v1/swagger.json",
    "/.well-known/openapi.json", "/api/schema", "/api/spec",
)
# A spec path that answers an API documentation PAGE (Swagger UI, ReDoc) instead of
# the document: the page's own scripts embed the spec (swagger-ui-express writes it
# into its init script as `"swaggerDoc": {...}`) or name the document's URL
# (`SwaggerUIBundle({url: ...})`, `<redoc spec-url=...>`). _spec_behind_ui reads at
# most _MAX_UI_SCRIPTS of the page's same-origin scripts (the UI library's own
# bundles skipped) and follows at most _MAX_UI_SPEC_URLS same-origin references.
_UI_PAGE_MARKERS = ("swagger-ui", "swaggeruibundle", "redoc")
_UI_SCRIPT_SRC = re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_UI_LIBRARY_SCRIPT = re.compile(r"(?:bundle|standalone|preset|polyfill|vendor)[^/]*\.js$", re.I)
_EMBEDDED_SPEC = re.compile(r"""["']?\b(?:swaggerDoc|spec)["']?\s*:\s*(?=\{)""")
_SPEC_URL_REF = re.compile(r"""["']?\b(?:url|spec-url)["']?\s*[:=]\s*["']([^"'\s<>]+)["']""")
_MAX_UI_SCRIPTS = 3
_MAX_UI_SPEC_URLS = 4

# A compact, generic REST + support-app vocabulary. Callers can extend with terms
# mined from the app (response bodies, JS) for better hit rates.
DEFAULT_NOUNS = (
    "login logout register token refresh session sessions password reset verify mfa "
    "users user me whoami profile account accounts admin roles permissions "
    "tickets ticket comments attachments replies assign escalate close reopen import export search mine "
    "kb articles faq categories tags labels "
    "integrations webhook webhooks connect oauth callback fetch proxy notify "
    # injection-prone feature surface: SSTI (templates/render/preview/email),
    # open-redirect (redirect/url/next/return/continue), command-injection
    # (ping/exec/run/convert/process). These are the agent-role features the
    # session-13 frontier legs never reached.
    "templates template render preview email emails message messages send "
    "redirect url link next return continue goto forward "
    "ping exec run execute convert process transform generate command "
    "refunds reports invoices payments billing credits approve reject "
    "diagnostics debug logs audit config settings backup system health status metrics maintenance "
    "files upload uploads download media avatar "
    "notifications feed activity orgs organizations teams groups version info stats "
    # workflow actions often reachable only at compound paths
    "signature invite redeem filtered change-email change-password change-username "
    "webhook-test export-csv import-csv two-factor enable-2fa disable-2fa "
    "api-keys api-key rotate-key revoke-token "
    # server-rendered page nouns (the /web/ prefix surface)
    "home index about contact help support faq terms privacy "
    "signup sign-up sign-in forgot-password reset-password "
    "profile edit preferences notifications-settings "
    # admin sub-features
    "overview analytics dashboard panel console tools utilities "
    "queue jobs workers cron scheduled tasks"
).split()

# Path segments that plausibly parent a nested resource (/api/<collection>/<noun>).
DEFAULT_COLLECTIONS = (
    "account users admin tickets kb integrations reports system auth org orgs "
    "billing config me files "
    "attachments comments notifications settings diagnostics"
).split()

# Object-scoped ACTION verbs (state changes / workflow transitions), distinct
# from the resource NOUNS above. These live as suffixes on an object
# (/tickets/1/lock), not as bare collections. Deliberately excludes verbs already
# in DEFAULT_NOUNS (assign/escalate/close/reopen/approve/reject/verify/refresh)
# so the two lists don't re-probe the same paths.
DEFAULT_ACTIONS = (
    "activate deactivate enable disable lock unlock ban unban suspend unsuspend "
    "restore archive unarchive publish unpublish submit cancel confirm retry "
    "resend duplicate clone promote demote grant revoke invite accept decline "
    "start stop pause resume rotate impersonate"
).split()

DEFAULT_PREFIXES = (
    "/api/", "/api/v1/", "/api/v2/", "/", "/admin/", "/internal/",
    "/web/", "/app/", "/portal/", "/dashboard/", "/console/",
    "/v1/", "/v2/",
)

# Generically-sensitive artifacts that live at FIXED conventional paths, not as
# REST resource nouns -- a flat noun sweep never names them. Relative (no leading
# slash); probed at the origin root. Kept high-signal (things that should never
# be web-served), not an exhaustive fuzz list.
DEFAULT_SENSITIVE_FILES = (
    ".env .env.local .env.production .env.dev config.json config.yaml config.yml "
    "settings.py application.properties appsettings.json web.config .htaccess .htpasswd "
    ".git/config .git/HEAD .gitignore .svn/entries "
    "backup.sql dump.sql database.sql db.sqlite db.sqlite3 backup.zip backup.tar.gz "
    "backup/ backups/ backup/database.sql "
    "id_rsa .ssh/id_rsa .aws/credentials credentials.json secrets.json .npmrc .pypirc "
    "package.json composer.json composer.lock requirements.txt Dockerfile docker-compose.yml "
    ".DS_Store phpinfo.php info.php server-status .well-known/security.txt "
    "error.log access.log debug.log app.log"
).split()

# Method mining runs last. Reserve probes for a safe OPTIONS request per
# discovered path, even when the earlier combinatorial wordlists are larger
# than max_probes.
_ALLOW_MINING_RESERVE = 200
_LATE_DISCOVERY_FRACTION = 0.25

# Backup/editor-swap suffixes, and the common source/config basenames worth
# trying them on even before any file is discovered.
_BACKUP_SUFFIXES = (".bak", "~", ".old", ".orig", ".save", ".swp")
_COMMON_BACKUP_BASES = (
    "index.php config.php database.php wp-config.php settings.php config.js app.js "
    ".env web.config config.json"
).split()
# Discovered file-like routes per directory that get backup variants. The cap is
# reported in SurfaceResult.backup_capped_prefixes, never applied silently.
_BACKUP_BASES_PER_DIR = 8
# Recursive discovery never goes deeper than this many levels below the
# directories discovery found, whatever the configured depth.
_MAX_RECURSION_DEPTH = 5


def _non_negative_int(value) -> int:
    """An operator count; a bool, a non-number or a negative value is 0 (off)."""
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _has_backup_suffix(segment: str) -> bool:
    return any(segment.endswith(suffix) for suffix in _BACKUP_SUFFIXES)


def _first_segment_prefix(path: str) -> str:
    """The leading '/<segment>/' of a path with >=2 segments, else '/'.
    /portal/users -> /portal/ ; /a/b/c -> /a/ ; /dashboard -> / (a leaf, no
    namespace to derive). Used to learn the namespaces an app actually exposes."""
    p = (path or "").split("?", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    segs = [s for s in p.split("/") if s]
    if len(segs) < 2:
        return "/"
    return "/" + segs[0] + "/"


@dataclass(frozen=True)
class Route:
    """One discovered route. `methods` are the real HTTP verbs it accepts
    (from an Allow header when the probe method was rejected, else the probe
    method that succeeded)."""
    path: str
    status: int = 0
    methods: tuple[str, ...] = ()
    length: int = 0
    source: str = "wordlist"  # spec | wordlist | nested | allow | response


@dataclass
class SurfaceResult:
    base_url: str
    routes: list[Route] = field(default_factory=list)
    spec_found: str | None = None
    probes_sent: int = 0
    errors: list[str] = field(default_factory=list)
    # Paths of the sensitive-file wordlist that answered 2xx/3xx (existence only).
    sensitive_file_hits: list[str] = field(default_factory=list)
    wildcard_prefixes: list[str] = field(default_factory=list)
    wildcard_candidates_suppressed: int = 0
    # Namespaces whose guessed descendants kept matching the soft-404 signature
    # with no live route under them; their remaining wordlist branch was dropped.
    soft404_pruned_prefixes: list[str] = field(default_factory=list)
    soft404_candidates_pruned: int = 0
    # ffuf inside a run: requests it sent through the run (each one charged to the
    # run budget), and its hits the harness's own soft-404 fingerprint rejected.
    ffuf_requests: int = 0
    ffuf_soft404_disagreements: int = 0
    # WL-05: one record per sensitive_file_hits entry -- the real status, content
    # type, body length and fingerprint, and whether the body carries the
    # artifact's content signature (see sensitive_file_verdict). Never the body.
    sensitive_file_evidence: list[dict] = field(default_factory=list)
    # Backup-suffix bounds: variants that mirrored their base file (dropped, and
    # the base's remaining suffixes not sent), and directories whose discovered
    # file-like routes exceeded _BACKUP_BASES_PER_DIR -> bases left unexpanded.
    backup_variants_mirrored: int = 0
    backup_capped_prefixes: dict[str, int] = field(default_factory=dict)

    def paths(self) -> list[str]:
        return sorted({r.path for r in self.routes})

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "spec_found": self.spec_found,
            "probes_sent": self.probes_sent,
            "routes": [
                {"path": r.path, "status": r.status, "methods": list(r.methods),
                 "length": r.length, "source": r.source}
                for r in sorted(self.routes, key=lambda x: x.path)
            ],
            "errors": self.errors,
            "wildcard_prefixes": self.wildcard_prefixes,
            "wildcard_candidates_suppressed": self.wildcard_candidates_suppressed,
            "soft404_pruned_prefixes": self.soft404_pruned_prefixes,
            "soft404_candidates_pruned": self.soft404_candidates_pruned,
            "ffuf_requests": self.ffuf_requests,
            "ffuf_soft404_disagreements": self.ffuf_soft404_disagreements,
            "backup_variants_mirrored": self.backup_variants_mirrored,
            "backup_capped_prefixes": dict(self.backup_capped_prefixes),
        }


def _is_not_found(status: int, body: str) -> bool:
    if status == 404:
        return True
    return any(m in body for m in _NOT_FOUND_MARKERS)


def _header_value(headers, name: str) -> str:
    """A response header by name, whatever its capitalisation. The run executor
    hands back a plain dict keyed by LOWERCASE names, so an exact-case lookup
    (``headers.get("Allow")``) never matched there and dropped every method the
    route listed (code review 02 R13)."""
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == wanted:
            return value or ""
    return ""


def _host_in_scope(url: str, allowed_hosts) -> bool:
    # Guards every probe, which is a live send: an empty or unset scope admits no host.
    if not allowed_hosts:
        return False
    return scope_lock.host_in_scope(url, allowed_hosts)


def _looks_html_body(body: str) -> bool:
    b = (body or "")[:2000].lower()
    return "<html" in b or "<a " in b or "<form" in b or "<!doctype" in b


def _extract_html_links(html: str, base_url: str) -> list[str]:
    """Extract href values from <a>, <form action>, and <link> tags."""
    from html.parser import HTMLParser
    from urllib.parse import urljoin

    links: list[str] = []

    class _P(HTMLParser):
        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "a":
                href = a.get("href", "")
                if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    links.append(urljoin(base_url, href))
            elif tag == "form":
                action = a.get("action", "")
                if action:
                    links.append(urljoin(base_url, action))
            elif tag == "link":
                href = a.get("href", "")
                if href and not href.startswith(("#", "javascript:")):
                    links.append(urljoin(base_url, href))

    try:
        _P().feed(html or "")
    except Exception:
        pass
    return links


# Common query parameter names worth probing on discovered GET endpoints.
# A hit (distinct response vs. no-param) means the endpoint accepts user input
# through that parameter -- critical for injection testing downstream.
_COMMON_PARAMS = (
    "id", "name", "file", "path", "url", "uri", "redirect", "next", "return",
    "callback", "continue", "goto", "forward", "dest", "destination",
    "query", "q", "search", "filter", "sort", "order", "page", "limit", "offset",
    "user_id", "org_id", "account_id", "role", "type", "category", "status",
    "format", "output", "template", "view", "action", "cmd", "command",
    "email", "username", "token", "key", "ref", "source", "target",
    "download", "export", "include", "lang", "locale", "debug", "verbose",
)


def _looks_like_spec(body: str) -> bool:
    return ('"openapi"' in body or '"swagger"' in body) and '"paths"' in body


def _paths_from_spec(body: str) -> list[str]:
    try:
        doc = json.loads(body)
        paths = doc.get("paths", {})
        # OpenAPI templates ids as {id}; keep them as-is (the graph normalises).
        return [p for p in paths.keys() if isinstance(p, str) and p.startswith("/")]
    except (ValueError, TypeError, AttributeError):
        return []


def _embedded_spec(text: str) -> str | None:
    """An OpenAPI 3 / Swagger 2 document a page or script embeds as a JSON object
    value (`"swaggerDoc": {...}`, `spec: {...}`), re-serialised; else None."""
    decoder = json.JSONDecoder()
    head = (text or "")[:5_000_000]
    for m in _EMBEDDED_SPEC.finditer(head):
        try:
            doc, _end = decoder.raw_decode(head, m.end())
        except ValueError:
            continue
        if isinstance(doc, dict) and isinstance(doc.get("paths"), dict) \
                and ("openapi" in doc or "swagger" in doc):
            return json.dumps(doc)
    return None


def _spec_base_path(spec: str, base_url: str) -> str:
    """The path a spec's paths are relative to on base_url's origin: the first
    OpenAPI 3 `servers[].url` that is relative or on this origin, else a Swagger 2
    `basePath` (when its `host`, if any, is this one). A templated server URL
    (`{variable}`) is skipped. "" when the spec names none or names only other
    origins, so its paths are used as they are."""
    try:
        doc = json.loads(spec)
    except (ValueError, TypeError):
        return ""
    if not isinstance(doc, dict):
        return ""
    here = urlsplit(base_url)
    candidates = []
    for server in doc.get("servers") or ():
        url = server.get("url") if isinstance(server, dict) else None
        if isinstance(url, str) and url.strip():
            candidates.append(url.strip())
    base_path, host = doc.get("basePath"), doc.get("host")
    if isinstance(base_path, str) and base_path.strip() and (not host or host == here.netloc):
        candidates.append(base_path.strip())
    for url in candidates:
        if "{" in url:
            continue
        try:
            target = urlsplit(urljoin(base_url.rstrip("/") + "/", url))
        except ValueError:
            continue
        if (target.scheme, target.netloc) != (here.scheme, here.netloc):
            continue
        path, own = target.path.rstrip("/"), here.path.rstrip("/")
        if own and (path == own or path.startswith(own + "/")):
            path = path[len(own):]
        return path
    return ""


def _under_base(base: str, path: str) -> str:
    """A spec path under its base path (see _spec_base_path): OpenAPI appends each
    path to the server URL, and Swagger 2 to basePath."""
    return base + path if base else path
