"""
Active black-box API surface discovery.

crawler.py mines an app's JS/HTML for endpoints -- which finds nothing on a
headless JSON API (no bundle, no links). Real coverage on an API needs active
probing, the way a human reaches for ffuf/gobuster once they realise the app is
API-only. This module is that layer: it discovers routes the tester's proxied
browsing never touched -- the "generateReport unauthenticated" class -- so the
engagement graph is built on the real surface, not the fraction that happened to
be exercised.

Four techniques, cheapest-signal first:
  1. SPEC probe   -- GET the well-known OpenAPI/Swagger locations; if the app
                     serves its own contract, that IS the surface (jackpot).
  2. WORDLIST     -- REST + domain nouns across prefixes, bare / id-scoped, and
                     NESTED two-segment (/api/<collection>/<noun>). Single-segment
                     lists miss most of a real API (/api/admin/users lives two
                     deep); nesting is what makes this find the majority.
  3. ALLOW mining -- a route that exists but rejects GET answers 405 with an
                     `Allow` header -> learn its real methods (POST-only routes,
                     otherwise invisible to a GET sweep).
  4. RESPONSE-driven -- mine 2xx JSON bodies for object ids and enumerate their
                     siblings (a list of tickets reveals ids 4,5,6...).

The existence oracle is deliberately app-agnostic: a route is REAL unless the
response is a not-found (a plain 404, or a framework "NotFound" marker some apps
wrap as a 500). Everything else -- 200/401/403/405/400/3xx -- means the route
is there, only the auth/method/shape differs.

Scope-gated to allowed_hosts and paced by the global throttle, exactly like the
validators. Discovery is READ-ONLY: every probe is a GET (plus a bounded method
sweep for Allow mining); it never sends a mutating body.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, urlsplit, urlunsplit, urlencode

import httpx

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

# Backup/editor-swap suffixes, and the common source/config basenames worth
# trying them on even before any file is discovered.
_BACKUP_SUFFIXES = (".bak", "~", ".old", ".orig", ".save", ".swp")
_COMMON_BACKUP_BASES = (
    "index.php config.php database.php wp-config.php settings.php config.js app.js "
    ".env web.config config.json"
).split()


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
    sensitive_file_hits: list[str] = field(default_factory=list)

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
        }


def _is_not_found(status: int, body: str) -> bool:
    if status == 404:
        return True
    return any(m in body for m in _NOT_FOUND_MARKERS)


def _host_in_scope(url: str, allowed_hosts) -> bool:
    if not allowed_hosts:
        return True
    return (urlparse(url).hostname or "") in set(allowed_hosts)


class SurfaceDiscovery:
    def __init__(self, base_url: str, *, headers: dict | None = None,
                 allowed_hosts: list[str] | None = None,
                 nouns=None, collections=None, prefixes=None, seed_paths=None,
                 actions=None, sensitive_files=None, timeout: float = 8.0, max_probes: int = 6000,
                 use_ffuf: bool = True, ffuf_image: str = "harness/ffuf:2.1.0",
                 run_context=None, session_ref: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.allowed_hosts = allowed_hosts or []
        self.nouns = list(nouns) if nouns is not None else list(DEFAULT_NOUNS)
        self.collections = list(collections) if collections is not None else list(DEFAULT_COLLECTIONS)
        self.actions = list(actions) if actions is not None else list(DEFAULT_ACTIONS)
        self.sensitive_files = (list(sensitive_files) if sensitive_files is not None
                                else list(DEFAULT_SENSITIVE_FILES))
        self.prefixes = list(prefixes) if prefixes is not None else list(DEFAULT_PREFIXES)
        # Paths the caller already knows exist (e.g. the crawler's HTML/JS-mined
        # links). Used to DERIVE namespaces the app actually exposes -- see
        # _derive_prefixes -- so a server-rendered surface under a non-default
        # prefix is reached, not only the built-in /api|/admin guesses.
        self.seed_paths = [s for s in (seed_paths or []) if isinstance(s, str) and s.startswith("/")]
        self.timeout = timeout
        self.max_probes = max_probes
        self.use_ffuf = use_ffuf
        self.ffuf_image = ffuf_image
        self.run_context = run_context
        self.session_ref = session_ref
        self._seen: dict[str, Route] = {}
        self._probes = 0
        self._phase_limit = max_probes
        self._attempted: set[tuple[str, str]] = set()
        self._bodies: dict[str, str] = {}
        self._mined: set[str] = set()
        self._sensitive_hits: list[str] = []
        # Soft-404 signature (Phase 5): (status, normalized-body-hash) that a
        # KNOWN-BOGUS path returns, so a catch-all that answers non-404 for
        # everything (404->500, a 200 "not found" page, an SPA index) is
        # recognised as "not found" by SHAPE, not mistaken for a real route.
        # None until calibrated, or when the app returns honest 404s.
        self._soft404: tuple[int, str] | None = None

    async def _probe(self, method: str, path: str):
        """One live request. A method seam so tests inject a canned responder and
        never touch the network. Returns (status, body, allow) or None on error.
        Throttled and scope-gated identically to the validator path."""
        url = self.base_url + path
        if not _host_in_scope(url, self.allowed_hosts):
            return None
        if self.run_context is not None:
            from harness.run_context import TypedRequest
            request_headers = {k: v for k, v in self.headers.items()
                               if k.lower() not in ("authorization", "cookie", "proxy-authorization")}
            outcome = await self.run_context.executor().execute(
                TypedRequest(method, url, headers=request_headers),
                capability="surface_discovery", session_ref=self.session_ref)
            if not outcome.ok:
                return None
            return outcome.status or 0, outcome.body or "", outcome.headers.get("Allow", "")
        from harness import global_throttle
        await global_throttle.acquire()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=False) as client:
                resp = await client.request(method, url, headers=self.headers or None)
        except Exception:
            return None
        return resp.status_code, (resp.text or ""), resp.headers.get("Allow", "")

    def _budget_left(self) -> bool:
        return self._probes < min(self.max_probes, self._phase_limit)

    async def _raw(self, method: str, path: str):
        """Budget-guarded, counted single probe -- every phase goes through this
        so max_probes bounds the whole run (spec + wordlist + allow + response),
        not just the wordlist. Returns None when the budget is spent."""
        if not self._budget_left():
            return None
        self._probes += 1
        return await self._probe(method, path)

    def _norm_body_hash(self, body: str, path: str) -> str:
        """A body fingerprint stable across the ECHOED PATH and numeric ids -- so
        two bogus paths that only differ by the path they echo hash the same, and
        a soft-404 is recognised whatever path it was probed with."""
        b = (body or "").replace(path, "PATH")
        b = re.sub(r"\d+", "N", b)
        return hashlib.sha1(b[:2000].encode("utf-8", "ignore")).hexdigest()[:16]

    def _not_found(self, status: int, body: str, path: str) -> bool:
        """Existence oracle: a hard 404/framework marker, OR a match to the
        calibrated soft-404 signature (Phase 5 -- content/shape, not status)."""
        if _is_not_found(status, body):
            return True
        if self._soft404 is not None and (status, self._norm_body_hash(body, path)) == self._soft404:
            return True
        return False

    async def _calibrate_not_found(self) -> None:
        """Fingerprint the app's answer to KNOWN-BOGUS paths. A soft-404 signature
        is recorded ONLY if two independent random paths return the SAME non-404
        (status, normalized-body) -- otherwise responses genuinely vary and
        suppressing by shape would hide real routes. If the app returns honest
        404s (or a framework marker), nothing is recorded and behavior is
        unchanged."""
        sigs = []
        for _ in range(2):
            bogus = "/" + secrets.token_hex(12)
            r = await self._raw("GET", bogus)
            if r is None:
                return
            status, body, _allow = r
            if _is_not_found(status, body):
                continue  # honest not-found already handled by the oracle
            sigs.append((status, self._norm_body_hash(body, bogus)))
        if len(sigs) == 2 and sigs[0] == sigs[1]:
            self._soft404 = sigs[0]

    async def _check(self, path: str, source: str, method: str = "GET") -> Route | None:
        if path in self._seen:
            return self._seen[path]
        if (method, path) in self._attempted or not self._budget_left():
            return None
        self._attempted.add((method, path))
        r = await self._raw(method, path)
        if r is None:
            return None
        status, body, allow = r
        if self._not_found(status, body, path):
            return None
        methods = tuple(m.strip().upper() for m in allow.split(",") if m.strip()) or (method,)
        route = Route(path=path, status=status, methods=methods, length=len(body), source=source)
        self._seen[path] = route
        if 200 <= status < 300:
            self._bodies[path] = body
        return route

    async def discover(self) -> SurfaceResult:
        result = SurfaceResult(base_url=self.base_url)

        # 0. Calibrate the soft-404 signature FIRST (Phase 5): if the target has a
        #    catch-all that answers non-404 for unknown paths, learn its shape now
        #    so the whole sweep below keys off content, not just "not a 404".
        await self._calibrate_not_found()
        if self._soft404 is not None:
            result.errors.append(f"soft-404 calibrated: status {self._soft404[0]} treated as "
                                 f"not-found by body shape")

        # 0b. ffuf fast-path: when Docker + the ffuf image are available, run
        #     the container-based content discovery first. Its routes seed _seen
        #     so the Python sweep below skips paths ffuf already found (the
        #     _check dedup in _seen handles this). Falls back silently when
        #     Docker/image is absent.
        ffuf_count = 0
        if self.use_ffuf:
            ffuf_count = await self._ffuf_fast_path(result)

        # 1. spec probe -- if the app hands us its contract, use it verbatim.
        for sp in SPEC_PATHS:
            r = await self._raw("GET", sp)
            if r and not _is_not_found(r[0], r[1]) and r[0] == 200 and _looks_like_spec(r[1]):
                result.spec_found = sp
                # W-21: keep the METHODS the spec documents for each path (a spec
                # route used to be recorded with methods=(), throwing away the
                # verbs a validator needs to know). The full operation surface
                # (paths x methods x parameters) is available via
                # openapi_ingest.operations_from_spec for callers that target
                # parameters -- the reach win over a bare path list.
                from harness import openapi_ingest
                methods_by_path = openapi_ingest.methods_by_path(r[1])
                for path in _paths_from_spec(r[1]):
                    self._seen.setdefault(path, Route(
                        path=path, status=0,
                        methods=methods_by_path.get(path, ()), source="spec"))
                break

        # 2. wordlist: single-segment, bare and id-scoped, across prefixes.
        for pre in self.prefixes:
            for n in self.nouns:
                for suffix in ("", "/1"):
                    await self._check(pre + n + suffix, "wordlist")
        # 2b. NESTED two-segment: /prefix/<collection>/<noun>. Bare only -- id
        #     depth is reached far more cheaply by response mining + sub-resources
        #     below than by blindly appending /1 to every combination. Uses ALL
        #     prefixes that end with /api*/ or look like API mounts, not just the
        #     hardcoded two.
        _nest_prefixes = sorted({p for p in self.prefixes
                                 if "api" in p.lower() or p in ("/admin/", "/internal/", "/v1/", "/v2/")})
        for pre in _nest_prefixes:
            for coll in self.collections:
                for n in self.nouns:
                    await self._check(f"{pre}{coll}/{n}", "nested")

        # 2c. Phase 0.2(a): don't assume the surface lives under the built-in
        #     prefixes. Sweep the noun list under the namespaces the app actually
        #     exposes -- derived from caller seed paths and from hits so far.
        await self._derive_prefixes()

        # 3. response-driven: mine 2xx bodies for object ids (enumerate siblings)
        #    AND for path-like strings / same-host URLs fed back as candidates
        #    (Phase 0.2(d)).
        await self._mine_responses()

        # 3b. re-derive prefixes now that body mining may have revealed a namespace
        #     the app references but the built-in guesses never named (0.2(a)+(d)).
        await self._derive_prefixes()

        # 4. SUB-RESOURCES: nest nouns under one representative object per
        #    collection (/api/tickets/1/comments, /assign, /attachments...). One id
        #    per collection is enough -- the sub-resource SHAPE repeats across ids,
        #    so this finds the pattern without re-probing it for every object.
        await self._mine_subresources()

        # 4b. Phase 0.2(b): object-scoped action suffixes (built-in workflow verbs
        #     + verbs generated from actions the app already exposes). Before Allow
        #     mining so a POST-only action route gets its real verbs learned.
        await self._mine_actions()

        # 4c. Phase 0.2(c): a sensitive-artifact wordlist (dotfiles/configs/backups/
        #     VCS/key-material) at fixed conventional paths, distinct from the REST
        #     nouns, plus generated backup-suffix (.bak/~/.old) variants. A hit here
        #     enters role_crawl's probe set and gets Phase-0.1 content review.
        await self._probe_sensitive_files()

        # 4d. Deep nesting: three-segment paths under live 2-segment prefixes
        #     (e.g. /api/admin/diagnostics/ping). Only fans out under namespaces
        #     that already proved live, so the cost is adaptive.
        await self._mine_deep_nested()

        # 4e. Query-parameter discovery: probe common param names on discovered
        #     GET endpoints. A distinct response means the endpoint accepts that
        #     parameter -- surfaces hidden input vectors the path wordlist misses.
        await self._probe_query_params()

        # 5. Allow mining (LAST, over the FULL route set incl. sub-resources): a
        #    route that rejects GET answers 405 with an `Allow` header -> learn its
        #    real verbs so POST-only routes aren't mislabelled GET-only.
        for path, route in list(self._seen.items()):
            if route.methods == ("GET",) and route.status in (405, 500):
                for m in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                    r = await self._raw(m, path)
                    if r and r[2]:
                        methods = tuple(x.strip().upper() for x in r[2].split(",") if x.strip())
                        if methods:
                            self._seen[path] = Route(path=path, status=route.status,
                                                     methods=methods, length=route.length, source=route.source)
                        break

        result.routes = list(self._seen.values())
        result.probes_sent = self._probes
        result.sensitive_file_hits = list(self._sensitive_hits)
        return result

    async def _ffuf_fast_path(self, result: SurfaceResult) -> int:
        """Run ffuf in a container and seed its discovered routes into _seen.
        Returns the number of routes found. Fails silently (returns 0) when
        Docker or the image is absent."""
        from harness import ffuf_runner
        ok, reason = ffuf_runner.ffuf_available(self.ffuf_image)
        if not ok:
            result.errors.append(f"ffuf skipped: {reason}")
            return 0
        ffuf_result = await ffuf_runner.ffuf_discover(
            self.base_url, image=self.ffuf_image, headers=self.headers or None)
        if ffuf_result.error:
            result.errors.append(f"ffuf error: {ffuf_result.error}")
            return 0
        count = 0
        for route in ffuf_result.routes:
            if route.path not in self._seen:
                self._seen[route.path] = route
                count += 1
        if count:
            result.errors.append(f"ffuf seeded {count} routes")
        return count

    async def _derive_prefixes(self, max_new: int = 8) -> None:
        """Phase 0.2(a): sweep the namespaces the app actually exposes, not only
        the built-in prefix guesses. Collect the '/<segment>/' prefixes present
        across caller-supplied seed paths (the crawler's server-rendered links)
        and routes already found, and sweep the noun list (bare + id-scoped)
        under any prefix outside the built-in set. This reaches a non-API /
        server-rendered surface living under a different prefix as soon as
        anything reveals it -- a headless-API run with no seeds simply derives
        nothing and this is a no-op. Bounded by max_new prefixes and the probe
        budget so it can't fan out unboundedly."""
        known = set(self.prefixes)
        derived: list[str] = []
        seen_new: set[str] = set()
        for path in list(self.seed_paths) + list(self._seen.keys()):
            pre = _first_segment_prefix(path)
            if pre == "/" or pre in known or pre in seen_new:
                continue
            seen_new.add(pre)
            derived.append(pre)
            if len(derived) >= max_new:
                break
        # Record swept prefixes so a later call (e.g. after body mining reveals a
        # new namespace) doesn't re-sweep them -- makes this safe to call twice.
        self.prefixes.extend(derived)
        for pre in derived:
            for n in self.nouns:
                if not self._budget_left():
                    return
                for suffix in ("", "/1"):
                    await self._check(pre + n + suffix, "derived")

    async def _probe_sensitive_files(self) -> None:
        """Phase 0.2(c): probe generically-sensitive artifacts at their fixed
        conventional paths (a wordlist distinct from the REST nouns), then
        generate backup-suffix variants (.bak/~/.old/...) of common source files
        and of any discovered file-like route (a route whose last segment has an
        extension). The existence oracle is unchanged: only non-404s are kept.
        Hits are tracked in _sensitive_hits for downstream finding emission."""
        for f in self.sensitive_files:
            if not self._budget_left():
                return
            path = "/" + f.lstrip("/")
            route = await self._check(path, "sensitive_file")
            if route is not None and 200 <= route.status < 400:
                self._sensitive_hits.append(path)

        file_like = set(_COMMON_BACKUP_BASES)
        for p in list(self._seen):
            seg = p.rsplit("/", 1)[-1]
            if "." in seg and not seg.startswith("."):   # looks like <name>.<ext>
                file_like.add(p.lstrip("/"))
        for base in sorted(file_like):
            for suf in _BACKUP_SUFFIXES:
                if not self._budget_left():
                    return
                await self._check("/" + base.lstrip("/") + suf, "sensitive_file")

    async def _mine_responses(self) -> None:
        """Mine each 2xx body once for three candidate sources:
          - Phase 0.2(d): path-like strings and same-host URLs anywhere in the
            body (JSON payloads, HTML, help/error text), via js_endpoint_extractor
            generalized off the JS-crawl -- fed back as candidate routes so an
            internal path the app merely NAMES becomes probed surface.
          - HTML link/form mining: <a href>, <form action>, <link href> tags
            in HTML responses -- so the server-rendered navigation graph feeds
            discovery even when the surface isn't a JSON API.
          - id enumeration: a JSON list/object's `id` fields -> id-scoped siblings.
        All work off the SAME fetch, so this is one GET per seed."""
        import harness.js_endpoint_extractor as jse
        seeds = [p for p, r in list(self._seen.items()) if 200 <= r.status < 300]
        for p in seeds:
            if not self._budget_left():
                return
            r = await self._raw("GET", p)
            if not r or _is_not_found(r[0], r[1]):
                continue
            body = r[1]
            # (d) body path/URL mining -- runs on ANY body, not just parseable JSON.
            for path in sorted(jse.extract_endpoints(body, self.base_url).same_origin_paths):
                if not self._budget_left():
                    return
                await self._check(path.replace("{id}", "1"), "body")
            # HTML link/form mining: extract navigable hrefs and form actions from
            # HTML responses. The js_endpoint_extractor catches path-like strings
            # but misses proper HTML anchors that use relative hrefs or query params.
            if _looks_html_body(body):
                for href in _extract_html_links(body, self.base_url):
                    if not self._budget_left():
                        return
                    parsed = urlparse(href)
                    if _host_in_scope(href, self.allowed_hosts) or not parsed.netloc:
                        path_only = parsed.path or "/"
                        if path_only.startswith("/"):
                            await self._check(path_only, "html")
            # id enumeration (JSON only).
            try:
                data = json.loads(body)
            except (ValueError, TypeError):
                continue
            items = data if isinstance(data, list) else [data]
            base_coll = re.sub(r"/\d+$", "", p)
            for it in items[:20]:
                if isinstance(it, dict) and "id" in it and self._budget_left():
                    await self._check(f"{base_coll}/{it['id']}", "response")

    def _representative_ids(self) -> dict[str, str]:
        """One representative (lowest) object id per collection, from routes of
        the shape /<collection>/<digits>. Shared by sub-resource and action
        mining: the SHAPE repeats across ids, so one id per collection is enough."""
        reps: dict[str, str] = {}
        for p in list(self._seen):
            m = re.match(r"^(.*)/(\d+)$", p)
            if m and (m.group(1) not in reps or int(m.group(2)) < int(reps[m.group(1)])):
                reps[m.group(1)] = m.group(2)
        return reps

    async def _mine_subresources(self) -> None:
        # Nest nouns under one representative id per collection.
        for coll, idv in self._representative_ids().items():
            for n in self.nouns:
                if not self._budget_left():
                    return
                await self._check(f"{coll}/{idv}/{n}", "subresource")

    async def _mine_deep_nested(self) -> None:
        """Three-segment nesting under collections that returned 2xx: if
        /api/admin/ has live routes, try /api/admin/<coll>/<noun> for each
        collection+noun pair. Adaptive: only fans out under namespaces that
        proved live, so a wordlist with 5 dead admin paths wastes nothing."""
        live_prefixes: set[str] = set()
        for p in list(self._seen):
            parts = [s for s in p.split("/") if s]
            if len(parts) >= 2:
                live_prefixes.add("/" + "/".join(parts[:2]) + "/")
        for pre in sorted(live_prefixes):
            for coll in self.collections:
                for n in self.nouns:
                    if not self._budget_left():
                        return
                    path = f"{pre}{coll}/{n}"
                    if path not in self._seen:
                        await self._check(path, "deep_nested")

    async def _probe_query_params(self) -> None:
        """Probe common query parameters on discovered GET endpoints. An endpoint
        that returns a distinct response with ?param=value vs. without means it
        accepts that parameter -- surfaces hidden input vectors (file=, path=,
        redirect=, org_id=) that the path-only wordlist never tests."""
        candidates = [p for p, r in list(self._seen.items())
                      if 200 <= r.status < 300 and "?" not in p]
        for p in candidates:
            if not self._budget_left():
                return
            base_r = await self._raw("GET", p)
            if not base_r or _is_not_found(base_r[0], base_r[1]):
                continue
            base_len = len(base_r[1])
            base_hash = self._norm_body_hash(base_r[1], p)
            for param in _COMMON_PARAMS:
                if not self._budget_left():
                    return
                qpath = f"{p}?{param}=1"
                r = await self._raw("GET", qpath)
                if r is None or _is_not_found(r[0], r[1]):
                    continue
                r_hash = self._norm_body_hash(r[1], qpath)
                if r_hash != base_hash or abs(len(r[1]) - base_len) > 50:
                    if qpath not in self._seen:
                        self._seen[qpath] = Route(path=qpath, status=r[0],
                                                   methods=("GET",), length=len(r[1]),
                                                   source="param_probe")
                    break

    async def _mine_actions(self) -> None:
        """Phase 0.2(b): probe object-scoped ACTION suffixes (/tickets/1/lock),
        beyond the fixed noun list. Two sources: the built-in workflow-verb
        vocabulary, and verbs GENERATED from actions the app already exposes --
        an /api/tickets/{id}/escalate seen in a spec (or found on any object)
        makes `escalate` worth trying on every other object, catching actions
        specific to this app that no built-in list would name. Verbs already in
        the noun list are skipped -- sub-resource mining tried those already."""
        reps = self._representative_ids()
        if not reps:
            return
        harvested: set[str] = set()
        for p in list(self._seen):
            m = re.search(r"/(?:\d+|\{[^/]+\})/([A-Za-z][A-Za-z0-9_-]{1,29})$", p)
            if m:
                harvested.add(m.group(1).lower())
        noun_set = set(self.nouns)
        actions = [a for a in dict.fromkeys(list(self.actions) + sorted(harvested))
                   if a not in noun_set]
        for coll, idv in reps.items():
            for act in actions:
                if not self._budget_left():
                    return
                await self._check(f"{coll}/{idv}/{act}", "action")


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
