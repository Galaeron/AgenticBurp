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

The module is split by seam (ARC-9). This module stays the import path and holds
SurfaceDiscovery's state, `__init__`, `discover` and the spec-behind-UI probe (they read the
wordlists and thresholds that tests patch here); it re-exports every name below, and
SurfaceDiscovery is composed of three mixins whose code reads the patched names it needs
(`_host_in_scope`, `sensitive_file_verdict`) back through this module at call time:

    api_surface_data       wordlists, thresholds, Route, SurfaceResult, spec / HTML helpers
    api_surface_sensitive  sensitive-file signatures, verdict, finding
    api_surface_probe      probing and not-found calibration
    api_surface_walk       ffuf fast paths, directory scan and recursion
    api_surface_mining     sensitive-file probes, response / subresource / action mining
"""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from harness.api_surface_data import (  # noqa: F401
    DEFAULT_ACTIONS, DEFAULT_COLLECTIONS, DEFAULT_NOUNS, DEFAULT_PREFIXES,
    DEFAULT_SENSITIVE_FILES, Route, SPEC_PATHS, SurfaceResult, _ALLOW_MINING_RESERVE,
    _BACKUP_BASES_PER_DIR, _BACKUP_SUFFIXES, _COMMON_BACKUP_BASES, _COMMON_PARAMS, _EMBEDDED_SPEC,
    _LATE_DISCOVERY_FRACTION, _MAX_RECURSION_DEPTH, _MAX_UI_SCRIPTS, _MAX_UI_SPEC_URLS,
    _NOT_FOUND_MARKERS, _SPEC_URL_REF, _UI_LIBRARY_SCRIPT, _UI_PAGE_MARKERS, _UI_SCRIPT_SRC,
    _embedded_spec, _extract_html_links, _first_segment_prefix, _has_backup_suffix, _header_value,
    _host_in_scope, _is_not_found, _looks_html_body, _looks_like_spec, _non_negative_int,
    _paths_from_spec, _spec_base_path, _under_base,
)
from harness.api_surface_mining import _MiningMixin  # noqa: F401
from harness.api_surface_probe import _ProbeMixin  # noqa: F401
from harness.api_surface_sensitive import (  # noqa: F401
    SensitiveFileVerdict, _DJANGO_SETTING, _DOTENV_LINE, _GIT_HEAD, _HTACCESS_DIRECTIVES,
    _HTML_ARTIFACT_CLASSES, _HTPASSWD_LINE, _INI_SECTION, _LOG_LINE, _NPMRC_KEYS, _NPMRC_LINE,
    _PRIVATE_KEY, _PROPERTIES_LINE, _REQ_LINE, _REQ_PIN, _SENSITIVE_CLASS_BY_NAME,
    _SENSITIVE_CLASS_BY_PATH, _SENSITIVE_CLASS_BY_SUFFIX, _SENSITIVE_SIGNATURES, _SIG_SCAN,
    _SQL_DUMP_HEADER, _SQL_STATEMENT, _content_lines, _dotenv_has_credentials, _is_html_document,
    _json_object, _matching_lines, _sig_aws_credentials, _sig_cloud_credentials_json,
    _sig_compose_file, _sig_composer_lock, _sig_composer_manifest, _sig_directory_listing,
    _sig_django_settings, _sig_dockerfile, _sig_dotenv, _sig_dotnet_appsettings, _sig_ds_store,
    _sig_git_config, _sig_git_head, _sig_gzip_archive, _sig_htaccess, _sig_htpasswd,
    _sig_java_properties, _sig_log_file, _sig_npm_manifest, _sig_npmrc, _sig_phpinfo,
    _sig_pip_requirements, _sig_private_key, _sig_pypirc, _sig_server_status, _sig_sql_dump,
    _sig_sqlite_db, _sig_svn_entries, _sig_web_config, _sig_zip_archive, sensitive_artifact_class,
    sensitive_file_finding, sensitive_file_verdict,
)
from harness.api_surface_walk import _WalkMixin  # noqa: F401


class SurfaceDiscovery(_ProbeMixin, _WalkMixin, _MiningMixin):
    def __init__(self, base_url: str, *, headers: dict | None = None,
                 allowed_hosts: list[str] | None = None,
                 nouns=None, collections=None, prefixes=None, seed_paths=None,
                 actions=None, sensitive_files=None, timeout: float = 8.0, max_probes: int = 6000,
                 use_ffuf: bool = True, ffuf_image: str = "harness/ffuf:2.1.0",
                 run_context=None, session_ref: str | None = None,
                 soft404_prune_after: int = 16, ffuf_in_runs: bool = False,
                 ffuf_wordlist: str = "harness", recursion_depth: int = 0,
                 recursion_max_requests: int = 0):
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
        # Inside a run ffuf is launched only when the operator enables it
        # (engagement.discovery_ffuf); its traffic then goes through a ToolProxy
        # that charges every request to the run's budget, scope and gate.
        self.ffuf_in_runs = ffuf_in_runs
        # Named in-image wordlist (ffuf_runner.WORDLISTS); refused early if unknown.
        from harness import ffuf_runner
        self.ffuf_wordlist = ffuf_runner.wordlist_path(ffuf_wordlist)
        self.run_context = run_context
        self.session_ref = session_ref
        self._seen: dict[str, Route] = {}
        self._probes = 0
        self._phase_limit = max_probes
        self._attempted: set[tuple[str, str]] = set()
        self._bodies: dict[str, str] = {}
        self._mined: set[str] = set()
        self._sensitive_hits: list[str] = []
        self._sensitive_evidence: list[dict] = []
        # GET response Content-Type per path, and the target path of a redirect the
        # run transport followed (evidence only; both filled by _probe).
        self._content_types: dict[str, str] = {}
        self._redirected_to: dict[str, str] = {}
        # The run transport follows redirects; the sensitive-file phase turns this
        # off so it sees each file's own status, as the raw-client path always did.
        self._follow_redirects = True
        # Soft-404 signature (Phase 5): (status, normalized-body-hash) that a
        # KNOWN-BOGUS path returns, so a catch-all that answers non-404 for
        # everything (404->500, a 200 "not found" page, an SPA index) is
        # recognised as "not found" by SHAPE, not mistaken for a real route.
        # None until calibrated, or when the app returns honest 404s.
        # (status, content type, normalized-body hash, normalized length, hash
        # stable?) -- see _calibrate_not_found and _soft404_match.
        self._soft404: tuple[int, str, str, int, bool] | None = None
        # The soft-404 answer's raw byte length when both calibration controls had
        # the same one: handed to ffuf as -fs so both filters drop one baseline.
        self._soft404_bytes: int | None = None
        self._soft404_matches = 0
        # Paths a proxied ffuf run already sent through the run: the Python sweep
        # does not guess them again.
        self._ffuf_covered: set[str] = set()
        self._ffuf_covered_skips = 0
        # Soft-404 branch pruning: once `soft404_prune_after` guessed paths under
        # one namespace match the soft-404 signature and none of its paths is a
        # live route, the rest of that wordlist branch is not sent. A juice-shop
        # SPA run spent ~19k probes enumerating /admin/, /v1/, /internal/ ...
        # descendants that all answered the index page.
        self.soft404_prune_after = max(1, int(soft404_prune_after))
        self._soft404_counts: dict[str, int] = {}
        self._live_prefixes: set[str] = set()
        self._soft404_dead: set[str] = set()
        self._soft404_pruned = 0
        self._prefix_controls: dict[tuple[str, str], tuple[int, str] | None] = {}
        self._wildcard_prefixes: set[str] = set()
        self._wildcard_suppressed = 0
        self._backup_mirrored = 0
        self._backup_capped: dict[str, int] = {}
        # Bounded recursion into the directories discovery found (see
        # _recurse_directories). 0 levels or 0 requests: off, today's behaviour.
        self.recursion_depth = min(_MAX_RECURSION_DEPTH, _non_negative_int(recursion_depth))
        self.recursion_max_requests = _non_negative_int(recursion_max_requests)
        # Paths whose GET redirected to the same path plus "/" on this origin: a
        # directory (filled by _probe).
        self._dir_redirects: set[str] = set()
        # The in-run ffuf launch that worked (pinned image, its pin note): reused to
        # scan each directory the recursion expands. None: the Python sweep does it.
        self._ffuf_in_run_image: tuple[str, str] | None = None

    def _note_dir_redirect(self, path: str, location_url: str) -> None:
        """A GET of /x answered with a redirect to /x/ on this origin names a
        directory. A redirect anywhere else is not followed or recorded here."""
        if not location_url or path.endswith("/") or "?" in path:
            return
        try:
            url = self.base_url + path
            target, here = urlsplit(urljoin(url, location_url)), urlsplit(url)
        except ValueError:
            return
        if (target.scheme, target.netloc) == (here.scheme, here.netloc) \
                and target.path == here.path + "/":
            self._dir_redirects.add(path + "/")

    def _origin_path(self, url: str) -> str | None:
        """`url` as a path _probe can send (relative to base_url), or None when it is
        on another origin or outside base_url's own path."""
        try:
            target, here = urlsplit(url), urlsplit(self.base_url)
        except ValueError:
            return None
        if (target.scheme, target.netloc) != (here.scheme, here.netloc):
            return None
        own = here.path.rstrip("/")
        path = target.path or "/"
        if own:
            if path != own and not path.startswith(own + "/"):
                return None
            path = path[len(own):] or "/"
        return path + ("?" + target.query if target.query else "")

    async def _spec_behind_ui(self, path: str, status: int, body: str) -> str | None:
        """The spec behind an API documentation page served at a spec path (see
        _UI_PAGE_MARKERS): embedded in the page or one of its same-origin scripts,
        or the same-origin document a script or the page names. A directory
        redirect the client did not follow (`/api-docs` -> `/api-docs/`) is read
        at its target. None when the answer is no such page or names no spec."""
        page = self._redirected_to.get(path) or path
        if 300 <= status < 400 and f"{path}/" in self._dir_redirects:
            page = path + "/"
            r = await self._raw("GET", page)
            if not r:
                return None
            status, body = r[0], r[1]
        if status != 200 or not body or not any(m in body.lower() for m in _UI_PAGE_MARKERS):
            return None
        found = _embedded_spec(body)
        if found is not None:
            return found
        page_url = self.base_url + page
        texts, scripts = [body], []
        for src in _UI_SCRIPT_SRC.findall(body):
            target = self._origin_path(urljoin(page_url, src))
            if target and not _UI_LIBRARY_SCRIPT.search(target.split("?", 1)[0]) \
                    and target not in scripts:
                scripts.append(target)
        for script in scripts[:_MAX_UI_SCRIPTS]:
            r = await self._raw("GET", script)
            if not r or r[0] != 200:
                continue
            found = _embedded_spec(r[1])
            if found is not None:
                return found
            texts.append(r[1])
        tried: set[str] = set()
        for text in texts:
            for ref in _SPEC_URL_REF.findall(text[:2_000_000]):
                target = self._origin_path(urljoin(page_url, ref))
                if not target or target in tried or target == page:
                    continue
                if len(tried) >= _MAX_UI_SPEC_URLS:
                    return None
                tried.add(target)
                r = await self._raw("GET", target)
                if r and r[0] == 200 and _looks_like_spec(r[1]):
                    return r[1]
        return None

    async def discover(self) -> SurfaceResult:
        result = SurfaceResult(base_url=self.base_url)

        # Keep part of the probe budget for response/subresource and query
        # mining. The nested wordlist can otherwise consume all 6,000 probes
        # before any input-bearing routes are examined.
        mining_reserve = min(_ALLOW_MINING_RESERVE, max(0, self.max_probes // 10))
        # Tiny test/operator budgets need the calibration and spec probes plus
        # at least one wordlist candidate; phase quotas only help at useful
        # discovery sizes.
        late_reserve = (min(int(self.max_probes * _LATE_DISCOVERY_FRACTION),
                            max(0, self.max_probes - mining_reserve))
                        if self.max_probes >= 24 else 0)
        query_reserve = late_reserve // 2
        self._phase_limit = max(0, self.max_probes - mining_reserve - late_reserve)

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
            # Leave room for a candidate plus its two sibling controls, even
            # when the operator supplies a very small discovery budget.
            if self._phase_limit - self._probes <= 3:
                break
            r = await self._raw("GET", sp)
            if not r or _is_not_found(r[0], r[1]):
                continue
            spec = r[1] if r[0] == 200 and _looks_like_spec(r[1]) else None
            if spec is None:
                # A documentation page in the document's place: its spec.
                spec = await self._spec_behind_ui(sp, r[0], r[1])
            if spec is not None:
                result.spec_found = sp
                # W-21: keep the METHODS the spec documents for each path (a spec
                # route used to be recorded with methods=(), throwing away the
                # verbs a validator needs to know). The full operation surface
                # (paths x methods x parameters) is available via
                # openapi_ingest.operations_from_spec for callers that target
                # parameters -- the reach win over a bare path list.
                from harness import openapi_ingest
                methods_by_path = openapi_ingest.methods_by_path(spec)
                base = _spec_base_path(spec, self.base_url)
                for path in _paths_from_spec(spec):
                    self._seen.setdefault(_under_base(base, path), Route(
                        path=_under_base(base, path), status=0,
                        methods=methods_by_path.get(path, ()), source="spec"))
                break

        # 2. wordlist: single-segment, bare and id-scoped, across prefixes.
        # Spend on observed app references before speculative combinations.
        for path in self.seed_paths:
            await self._check(path.replace("{id}", "1"), "seed")
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

        # Wordlist quota ends here; let adaptive discovery spend its share.
        self._phase_limit = max(0, self.max_probes - mining_reserve - query_reserve)

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

        # 4c'. Bounded recursion (engagement.discovery_recursion_depth, default off):
        #     the wordlist (or, inside a run with ffuf on, ffuf) under each
        #     directory found so far, then under the directories that turns up, to
        #     the configured depth and within its own request cap.
        await self._recurse_directories(result)

        # 4d. Deep nesting: three-segment paths under live 2-segment prefixes
        #     (e.g. /api/admin/diagnostics/ping). Only fans out under namespaces
        #     that already proved live, so the cost is adaptive.
        await self._mine_deep_nested()

        # Query mining has its own reserve, separate from response and deep
        # route discovery. An endpoint with an undiscovered input must not be
        # labelled inapplicable just because a path wordlist used the budget.
        self._phase_limit = max(0, self.max_probes - mining_reserve)

        # 4e. Query-parameter discovery: probe common param names on discovered
        #     GET endpoints. A distinct response means the endpoint accepts that
        #     parameter -- surfaces hidden input vectors the path wordlist misses.
        await self._probe_query_params()

        # 5. Learn accepted methods without executing a write. OPTIONS can
        # reveal POST-only routes as well as a PUT operation on a readable GET
        # route. Check ambiguous routes first while the reserve is available.
        self._phase_limit = self.max_probes
        method_candidates = sorted(
            list(self._seen.items()),
            key=lambda item: (item[1].methods not in ((), ("GET",)),
                              item[1].status not in (405, 500), item[0]))
        for path, route in method_candidates:
            if route.methods not in ((), ("GET",)) or "?" in path:
                continue
            r = await self._raw("OPTIONS", path)
            if r and r[2]:
                methods = tuple(x.strip().upper() for x in r[2].split(",") if x.strip())
                if methods:
                    self._seen[path] = Route(path=path, status=route.status,
                                             methods=methods, length=route.length,
                                             source=route.source)

        result.routes = list(self._seen.values())
        result.probes_sent = self._probes
        result.sensitive_file_hits = list(self._sensitive_hits)
        result.sensitive_file_evidence = [dict(r) for r in self._sensitive_evidence]
        result.wildcard_prefixes = sorted(self._wildcard_prefixes)
        result.wildcard_candidates_suppressed = self._wildcard_suppressed
        result.soft404_pruned_prefixes = sorted(self._soft404_dead)
        result.soft404_candidates_pruned = self._soft404_pruned
        if self._ffuf_covered_skips:
            result.errors.append(f"ffuf covered {self._ffuf_covered_skips} wordlist candidate(s); "
                                 "the Python sweep did not resend them")
        if self._soft404_dead:
            result.errors.append(f"soft-404 branches pruned: {len(self._soft404_dead)} namespace(s), "
                                 f"{self._soft404_pruned} guessed candidate(s) not sent")
        if self._wildcard_prefixes:
            result.errors.append("wildcard responses suppressed; guessed descendants were not expanded")
        result.backup_variants_mirrored = self._backup_mirrored
        result.backup_capped_prefixes = dict(self._backup_capped)
        if self._backup_mirrored:
            result.errors.append(f"backup suffixes: {self._backup_mirrored} file(s) served their original "
                                 "body for a suffixed name; their remaining suffixes were not sent")
        if self._backup_capped:
            result.errors.append(
                f"backup suffixes capped at {_BACKUP_BASES_PER_DIR} discovered file(s) per directory: "
                + ", ".join(f"{d} ({n} not expanded)" for d, n in sorted(self._backup_capped.items())))
        return result
