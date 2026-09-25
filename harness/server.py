from __future__ import annotations
import asyncio
import logging
import os
import secrets
import yaml
from harness import store
from harness import active_verification
from harness import surface_prioritizer
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from harness.models import (AnalysisRequest, AnalysisResponse, ValidationSubmission, EstimateRequest, EffortStatus,
                     IdentityCreateRequest, SessionCreateRequest, SuppressFindingRequest,
                     PrioritizeRequest, PrioritizeResponse, PrioritizeResultItem, HttpExchange)
import harness.identity as identity_mod
from harness.orchestrator import Orchestrator

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("harness.server")

CONFIG_PATH = Path(__file__).parent / "config.yaml"
LOCAL_CONFIG_PATH = Path(__file__).parent / "config.local.yaml"


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge overlay into base (overlay wins); returns base."""
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config() -> tuple[dict, set[str]]:
    """Load config.yaml, then merge an optional git-ignored config.local.yaml
    over it (local wins). This keeps active-mode toggles on for a live local
    server without ever committing them -- a `git add config.yaml` can no longer
    leak them (SESSION_4_PLAN.md T0.1).

    Returns `(cfg, explicit_keys)`. P0-5: `explicit_keys` is the set of
    dotted paths the operator explicitly set via config.local.yaml -- the
    provenance seam resolve_operating_profile's `explicit_keys` param
    consumes, threaded through Orchestrator.__init__. This is the one place
    in the loader that still has the pre-merge overlay dict, so it's the
    cleanest place to capture "the operator touched this" before that
    information is lost in the deep-merge. Deliberately returned SEPARATELY
    from `cfg` rather than stashed inside it: `cfg` feeds
    config_fingerprint()/redacted_effective_config(), and a set of strings
    isn't stable/JSON-clean through those. Empty when there is no
    config.local.yaml (or it's empty) -- callers get an accurate "nothing
    was explicitly overridden" rather than a stale/missing value."""
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f) or {}
    explicit_keys: set[str] = set()
    if LOCAL_CONFIG_PATH.exists():
        with open(LOCAL_CONFIG_PATH) as f:
            local = yaml.safe_load(f) or {}
        if local:
            from harness import config_schema
            explicit_keys = config_schema.flatten_explicit_keys(local)
            _deep_merge(cfg, local)
            log.info("load_config: merged local overrides from config.local.yaml")
    # W-20: validate the MERGED config and record its fingerprint at startup.
    # Non-fatal (errors are logged, not raised) so a running server is never taken
    # down by config linting, but a typo'd knob or an incoherent safety
    # combination (allow_mutating_replay without active_enabled) is surfaced
    # loudly instead of failing silently, and the fingerprint ties a run to
    # exactly which configuration produced it.
    try:
        from harness import config_schema
        result = config_schema.validate_config(cfg)
        for err in result.errors:
            log.error("config validation: %s", err)
        for warn in result.warnings:
            log.warning("config validation: %s", warn)
        log.info("load_config: effective config fingerprint %s",
                 config_schema.config_fingerprint(cfg))
    except Exception as e:
        log.warning("load_config: config validation skipped (%s)", e)
    return cfg, explicit_keys


config, _explicit_config_keys = load_config()
orchestrator = Orchestrator(config, explicit_keys=_explicit_config_keys)
app = FastAPI(title="Burp LLM Harness", version="0.1.0")


def _live_validators_gate_config() -> dict:
    """The validators config for a NEW invocation started RIGHT NOW: the
    static startup config as a base, with the live `active_enabled` toggle
    (POST /settings -> ValidatorRegistry.set_active_enabled, in-memory only,
    never written back to `config`) always taking precedence.

    Without this, every RunContext built here read `config.get("validators")`
    directly -- the frozen startup snapshot -- so a run started AFTER an
    operator armed active mode via /settings still got a safe-default gate
    (the actual defect behind SQLMap/CSRF mutating sends being BLOCKED with
    "active testing... which is off" while the registry had already armed
    dispatch for them). 2026-09-17 coverage-recovery plan, Step 1.
    """
    live = dict(config.get("validators", {}) or {})
    live["active_enabled"] = orchestrator.validator_registry.active_enabled
    return live


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


_BEARER_TOKEN = config.get("server", {}).get("auth_token") or os.environ.get("HARNESS_BEARER_TOKEN")
_SERVER_HOST = config.get("server", {}).get("host", "127.0.0.1")
# FR-8 (F12 offline half): ships false -- see the config.yaml comment on
# server.require_read_auth for why. Read as a plain module global (not
# wrapped in a function) so a test can flip it directly via
# `server._READ_AUTH_ENABLED = True`/`False` without a config reload;
# _require_read_auth below re-reads this name from the module each call
# (never captures it in a closure/default arg) so that monkeypatch works.
_READ_AUTH_ENABLED = bool(config.get("server", {}).get("require_read_auth", False))
if not _is_loopback(_SERVER_HOST) and not _BEARER_TOKEN:
    raise RuntimeError(
        "Refusing non-loopback harness.server.host without authentication. "
        "Set server.auth_token or HARNESS_BEARER_TOKEN, or bind to 127.0.0.1."
    )


# W-4: DNS-rebinding / Host-header defense. On the default loopback deploy the
# JSON endpoints are otherwise protected only by accidental CORS-preflight, and
# GET endpoints (/report, /settings, ...) are simple cross-origin requests any
# visited web page can trigger; DNS rebinding defeats the loopback assumption
# for everything. TrustedHostMiddleware rejects (400) any request whose Host
# header is not in this allowlist -- a rebound attacker.com no longer matches.
# NOTE: this is the set of hostnames the HARNESS SERVER itself answers to, a
# different thing from server.allowed_hosts (which is the TARGET scope the
# harness may probe). Override with server.trusted_hosts (e.g. ["*"] behind a
# trusted reverse proxy).
_TRUSTED_HOSTS = list(
    config.get("server", {}).get("trusted_hosts")
    or ["127.0.0.1", "localhost", "::1"]
)
if _SERVER_HOST not in _TRUSTED_HOSTS and "*" not in _TRUSTED_HOSTS:
    _TRUSTED_HOSTS.append(_SERVER_HOST)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_TRUSTED_HOSTS)


def _require_auth(authorization: str | None) -> None:
    # Loopback remains convenient for the Burp extension by default. Any
    # remotely reachable deployment must prove possession of a bearer token.
    if _is_loopback(_SERVER_HOST) and not _BEARER_TOKEN:
        return
    expected = f"Bearer {_BEARER_TOKEN}"
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="missing or invalid bearer token")


# RB-1: local-API origin/CSRF defense. -------------------------------------
#
# Problem this closes: any web page the tester's browser visits (a malicious
# site, or a compromised ad on an otherwise legitimate one) can silently
# fetch() this loopback server. TrustedHostMiddleware above only checks the
# Host header a same-origin OR cross-origin request equally carries, and
# "simple" cross-origin requests (GET, and a POST with a CORS-simple
# Content-Type such as text/plain) never trigger a preflight the browser
# would otherwise block -- they just go out. Before this, on the default
# deploy (loopback, no server.auth_token/HARNESS_BEARER_TOKEN configured),
# _require_auth's loopback bypass above meant EVERY route, including every
# state-changing one, was reachable by such a request with no proof the
# caller is the tester's own Burp extension or curl session.
#
# Two independent controls, per the RB-1 backlog item:
#   1. PRIMARY -- an ephemeral bearer token, generated at startup whenever no
#      operator token is configured, required on every state-changing
#      (POST/PUT/PATCH/DELETE) route EVEN FROM LOOPBACK. This is enforced in
#      the middleware below, independently of _require_auth (left completely
#      unchanged above, including its loopback bypass for GET/other safe
#      routes -- see the docstring on _csrf_defense_middleware for why GET is
#      intentionally NOT gated behind this token).
#   2. DEFENSE-IN-DEPTH -- an Origin/Sec-Fetch-Site check that rejects any
#      request a browser has labeled cross-site, on every route (GET
#      included), since GET is exactly the "simple request" class the
#      primary control above does not cover.
#
# RB-1b (separate, OWNER/JDK item, out of this change's scope) is the Burp
# extension reading this token from the lockfile and sending it. Until that
# lands, the packaged extension will not authenticate its mutating calls --
# expected and accepted, per the backlog item.
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Where the ephemeral token is published for a local operator/extension to
# read. Never committed (see .gitignore) -- regenerated fresh every process
# start, so a stale lockfile from a prior run is always overwritten.
TOKEN_LOCKFILE_PATH = Path(__file__).parent / ".harness_token.lock"


def _write_token_lockfile(token: str) -> None:
    """Best-effort: publish the ephemeral token to TOKEN_LOCKFILE_PATH with
    owner-only (0600) permissions where the OS supports it. A failure to
    write or chmod the file must never crash startup -- the token still
    works for any caller that already has it (e.g. this same process's
    tests); an operator who needs the file can always regenerate it by
    restarting. NOTE (Windows caveat): os.chmod on Windows does not map onto
    POSIX owner/group/other permission bits -- it can only toggle the
    read-only attribute, not actually restrict the file to the current
    user's account. On Windows this call is therefore a no-op with respect
    to the "0600, other local accounts cannot read it" guarantee POSIX gets;
    the real security boundary on any platform is still the token itself
    (an attacker who can already read arbitrary files on the host has far
    worse problems than this lockfile).
    """
    try:
        TOKEN_LOCKFILE_PATH.write_text(token, encoding="utf-8")
    except OSError as e:
        log.warning("RB-1: could not write ephemeral token lockfile %s: %s", TOKEN_LOCKFILE_PATH, e)
        return
    try:
        os.chmod(TOKEN_LOCKFILE_PATH, 0o600)
    except OSError as e:
        # Expected/benign on Windows (see docstring above) and on any
        # filesystem that doesn't support POSIX permission bits.
        log.debug("RB-1: chmod 0600 on token lockfile not applied (%s): %s", TOKEN_LOCKFILE_PATH, e)


_EPHEMERAL_TOKEN: str | None = None
if not _BEARER_TOKEN:
    _EPHEMERAL_TOKEN = secrets.token_urlsafe(32)
    _write_token_lockfile(_EPHEMERAL_TOKEN)
    log.info("RB-1: no operator server.auth_token/HARNESS_BEARER_TOKEN configured -- generated an "
             "ephemeral bearer token for state-changing routes and wrote it to %s", TOKEN_LOCKFILE_PATH)


def _mutation_token() -> str | None:
    """The token a state-changing request must present. The operator-
    configured token if one was set (mirrors _require_auth's own precedence
    -- an explicitly configured token always wins), else the ephemeral one
    generated above. Never None in a running process: exactly one of
    _BEARER_TOKEN / _EPHEMERAL_TOKEN is always set by the startup block
    above."""
    return _BEARER_TOKEN or _EPHEMERAL_TOKEN


def _require_read_auth(authorization: str | None) -> None:
    """FR-8 (F12 offline half): opt-in gate for sensitive GET reads
    (/report, /telemetry, /test-plans/{plan_id}, GET /settings) -- routes
    that expose captured client traffic, discovered secrets and diagnostics,
    which _require_auth's loopback bypass otherwise leaves open to any local
    process/user with no token at all. Deliberately a SEPARATE function from
    _require_auth (which stays exactly as it was: unchanged, still gates
    only on the configured _BEARER_TOKEN, still bypassed on loopback with no
    configured token) -- this one is opt-in via server.require_read_auth
    (ships false) and, when armed, requires the SAME effective token already
    required on mutations (_mutation_token(): the configured token if set,
    else the RB-1 ephemeral one), not just a configured operator token. That
    lets an operator arm this on the default no-token-configured loopback
    deploy and still have it mean something (today's ephemeral mutation
    token), rather than requiring them to additionally set server.auth_token.

    Reads the _READ_AUTH_ENABLED module global fresh on every call (never
    caches it in a default arg or closure) so a test can flip
    `server._READ_AUTH_ENABLED` directly without reloading the module or
    re-reading config.yaml. /health calls neither this nor _require_auth and
    must stay that way -- it is the one route pairing/liveness needs open
    unconditionally.
    """
    if not _READ_AUTH_ENABLED:
        return
    expected = f"Bearer {_mutation_token()}"
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="missing or invalid bearer token")


@app.middleware("http")
async def _csrf_defense_middleware(request, call_next):
    """Runs on every request, after TrustedHostMiddleware's Host check and
    before any route handler (including before that route's own
    _require_auth call). See the module comment above _MUTATING_METHODS for
    the two controls this implements.

    GET/HEAD/other safe methods are deliberately NOT required to present
    _mutation_token() here -- only _require_auth's existing (unchanged)
    logic gates them, which still allows a loopback caller through when no
    operator token is configured. That preserves the Burp extension's and
    curl's existing read-only calls exactly as before RB-1; the Origin/
    Sec-Fetch-Site check below is what defends those routes instead, since
    they are the "simple request" class a browser lets through un-preflighted.
    """
    # --- Control 2 (checked first so a genuinely cross-site request is
    # rejected before we even look for a token): reject anything a browser
    # itself has labeled cross-site, or whose Origin's host disagrees with
    # the Host this request actually arrived on. CRUCIAL: curl and the Burp
    # extension send NO Origin header and NO Sec-Fetch-Site header at all --
    # neither condition below can ever fire for them, so a missing Origin is
    # always allowed through to control 1.
    if request.headers.get("sec-fetch-site") == "cross-site":
        return JSONResponse(status_code=403, content={"detail": "cross-site request rejected"})
    origin = request.headers.get("origin")
    if origin:
        origin_host = urlparse(origin).hostname
        request_host = request.url.hostname
        if not origin_host or not request_host or origin_host.lower() != request_host.lower():
            return JSONResponse(status_code=403, content={"detail": "cross-origin request rejected"})

    # --- Control 1 (primary): state-changing routes need the bearer token,
    # even from loopback, even with no Origin header at all.
    if request.method in _MUTATING_METHODS:
        expected = _mutation_token()
        if expected:
            authorization = request.headers.get("authorization")
            if not authorization or not secrets.compare_digest(authorization, f"Bearer {expected}"):
                return JSONResponse(status_code=401, content={"detail": "missing or invalid bearer token"})

    return await call_next(request)


@app.get("/health")
async def health():
    from harness import coordinator
    return {
        "status": "ok",
        "coordinator_model": orchestrator.coordinator_model,
        "agents": list(orchestrator.agent_manager.get_enabled_agents()),
        "coordinator_fail_opens": coordinator.fail_open_stats(),
    }


@app.get("/telemetry")
async def telemetry(run_id: str | None = None, authorization: str | None = Header(default=None)):
    _require_read_auth(authorization)
    from harness import coordinator
    import harness.telemetry as _telemetry
    # W-11: the diagnostics snapshot answers "why did this target produce
    # zero/few findings?" -- swallowed-exception counts (a validator crashing on
    # every exchange, a header audit that failed), scope-denial events, and the
    # coordinator fail-open counters -- without reading server logs.
    # Pass ?run_id=<Orchestrator.analyze's run_context.run_id> for one
    # invocation's own diagnostics; omitted, this is a process-wide aggregate
    # across every bound invocation (see telemetry.snapshot's docstring) --
    # never presented as one run's explanation.
    return {
        "coordinator_fail_open": coordinator.fail_open_stats(),
        "effort_budget": orchestrator.effort_status().model_dump() if hasattr(orchestrator, "effort_status") else {},
        "diagnostics": _telemetry.snapshot(run_id),
    }


@app.get("/report")
async def report(url: str, authorization: str | None = Header(default=None)):
    """
    Analyst-facing Markdown writeup of everything found for `url`'s host
    so far -- report_generator.py, wired here for the first time. The
    module was fully built and tested (test_report_generator.py) but had
    no caller anywhere: no endpoint, no CLI hook, nothing -- found during
    a dead-code audit prompted by the same pattern already found and
    fixed once this session for retry_policy.py/payload_library.py.
    Passing the live orchestrator's effort ledger (not omitted, unlike
    the module's own standalone-script default) gets cost-aware ordering
    of unconfirmed findings for real, in-session token-spend data.
    """
    _require_auth(authorization)
    _require_read_auth(authorization)
    from harness import report_generator
    markdown = await __import__("asyncio").to_thread(
        report_generator.generate_report_for_host, url, orchestrator.effort_budget.ledger,
    )
    return PlainTextResponse(markdown, media_type="text/markdown")


@app.get("/test-plans/{plan_id}")
async def test_plan(plan_id: str, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    _require_read_auth(authorization)
    plan = await __import__("asyncio").to_thread(store.get_test_plan, plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="unknown test plan")
    return plan


@app.post("/validation-results")
async def validation_result(submission: ValidationSubmission, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    # The execution plane (normally Burp) posts only the observed result.
    # It cannot change a plan's target or turn a model assertion into a
    # confirmation; the server accepts the result as evidence for the plan.
    accepted, reason = await __import__("asyncio").to_thread(store.persist_validation_submission, submission)
    if not accepted:
        raise HTTPException(status_code=400 if reason == "binding_mismatch" else 404, detail=reason)
    log.info("Validation result received plan=%s status=%s confirmed=%s",
             submission.plan_id, submission.status, submission.confirmed)

    # Not confirmed on a retryable (xss/ssrf/business_logic, Burp-plane)
    # capability: decide whether another attempt with a genuinely
    # different payload is warranted -- see active_verification.py for
    # why this exists (retry_policy.py and payload_library.py were fully
    # built but never wired to any caller before this).
    response: dict = {"accepted": True, "plan_id": submission.plan_id}
    plan = await __import__("asyncio").to_thread(store.get_test_plan, submission.plan_id)
    if plan is not None:
        step = await active_verification.decide_next_step(
            plan, submission, ollama_client=orchestrator.ollama,
        )
        if step.next_plan is not None:
            await __import__("asyncio").to_thread(store.persist_retry_plan, step.next_plan)
            response["next_plan"] = step.next_plan.model_dump()
        if step.handover_required:
            response["handover_required"] = True
        if step.note:
            response["note"] = step.note
    return response


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(req: AnalysisRequest, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    try:
        return await orchestrator.analyze(req.exchange, req.force_agents, req.attempt_rediscovery)
    except Exception as e:
        log.exception("Unhandled error during analysis")
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/estimate")
async def estimate(req: EstimateRequest, authorization: str | None = Header(default=None)):
    """
    Projects total token cost for running the full assessment across the
    given URLs. Intended to be called once the analyst has spidered the
    target in Burp and sent at least one real exchange through /analyze
    (so the projection is calibrated against real per-call-kind token
    averages -- see `calibrated_from_real_calls` in the response; before
    that it still works, using the unmeasured priors in effort.py, and
    says so). Each URL can optionally carry a risk_score (e.g. Burp's
    PathScorer tier, normalized to 0-1) if the analyst's first walkthrough
    has already scored it -- unscored URLs are still counted, just at the
    lower "rest" retry-round assumption rather than "high risk".
    """
    _require_auth(authorization)
    if not req.urls:
        raise HTTPException(status_code=400, detail="urls must be non-empty")
    return orchestrator.estimate_for_urls(req.urls)


@app.post("/prioritize", response_model=PrioritizeResponse)
async def prioritize(req: PrioritizeRequest, authorization: str | None = Header(default=None)):
    """
    Structure-only (method/URL/param names, no bodies) LLM triage pass for
    the Attack Surface Map tab's "Scan Site Map" -- see
    surface_prioritizer.py's own docstring. Batches req.items into chunks
    of surface_prioritization.max_items_per_call, one LLM call per chunk,
    run concurrently -- bounded even for a large site map, not one call
    per endpoint.
    """
    _require_auth(authorization)
    cfg = config.get("surface_prioritization", {})
    if not cfg.get("enabled", True):
        raise HTTPException(status_code=403, detail="surface_prioritization is disabled in config.yaml")
    if not req.items:
        return PrioritizeResponse(results=[])

    chunk_size = max(1, cfg.get("max_items_per_call", 40))
    chunks = [req.items[i:i + chunk_size] for i in range(0, len(req.items), chunk_size)]
    model = cfg.get("model") or orchestrator.coordinator_model
    chunk_results = await asyncio.gather(*[
        surface_prioritizer.prioritize(chunk, orchestrator.ollama, model, cfg.get("temperature", 0.1))
        for chunk in chunks
    ])
    results: list[PrioritizeResultItem] = [r for chunk in chunk_results for r in chunk]

    # Fold the LLM ratings into the engagement model, grouped by host, so the
    # fused worklist reflects them alongside crawl/findings signals.
    by_host: dict[str, list[dict]] = {}
    for r in results:
        by_host.setdefault(store.host_of(r.url), []).append(
            {"method": r.method, "url": r.url, "ai_priority": r.ai_priority, "ai_score": r.ai_score})
    for host, items in by_host.items():
        await asyncio.to_thread(_update_engagement, host, lambda st, it=items: st.ingest_prioritization(it))

    return PrioritizeResponse(results=results)


from pydantic import BaseModel as _BaseModel


class CrawlRequest(_BaseModel):
    base_url: str
    # Optional session the tester's Burp already holds (Authorization / Cookie),
    # so the crawl reaches authenticated surface. Never populated by the server.
    headers: dict[str, str] = {}
    max_pages: int = 40
    max_depth: int = 2


@app.post("/crawl")
async def crawl_endpoint(req: CrawlRequest, authorization: str | None = Header(default=None)):
    """Discover the application's real endpoint surface by fetching its pages
    AND mining the JavaScript bundles they load (js_endpoint_extractor.py) --
    the API surface a link-only spider misses. Scope-gated to the engagement's
    server.allowed_hosts, paced by the global request throttle, and bounded by
    max_pages/max_depth. Drives the Burp "Crawl" button; returns the discovered
    endpoints for the site map / attack-surface tab."""
    _require_auth(authorization)
    from harness import crawler
    result = await crawler.crawl(
        req.base_url,
        headers=req.headers or {},
        allowed_hosts=orchestrator.allowed_hosts,
        max_pages=max(1, min(req.max_pages, 200)),
        max_depth=max(0, min(req.max_depth, 4)),
    )
    out = result.to_dict()
    await __import__("asyncio").to_thread(
        _update_engagement, store.host_of(req.base_url),
        lambda st: st.ingest_endpoints(out.get("endpoints", [])))
    return out


class MissingAuthRequest(_BaseModel):
    base_url: str
    # Endpoints to probe, as call shapes recovered from the app's JS
    # (js_endpoint_extractor.extract_call_shapes) or supplied by the tester.
    call_shapes: list[dict[str, str]] = []   # [{"method": "...", "path": "..."}]
    # Extra bare paths with no known method are probed as GET.
    paths: list[str] = []
    # The tester's Burp session headers, if any -- the probe STRIPS the auth
    # ones and keeps the rest; the point is to fire with credentials removed.
    headers: dict[str, str] = {}
    # If true and no call_shapes given, crawl base_url first and probe every
    # discovered endpoint as a GET shape.
    discover: bool = False
    max_pages: int = 40
    send_garbage_token: bool = True
    # Off by default: probing mutating methods (POST/PUT/PATCH/DELETE) is gated
    # by the safety gate and only fires when active testing + mutating replay
    # are enabled in config.yaml. Left off, mutating shapes are skipped.
    include_mutating: bool = False
    # The caller knows these endpoints are meant to be authenticated (e.g. they
    # were only referenced in authenticated JS) -- nudges confidence up.
    expected_protected: bool = False


class RoleCrawlRequest(_BaseModel):
    base_url: str
    # Each role's real captured session headers (Authorization/Cookie) from Burp.
    # Include an anonymous role (empty headers) to detect auth bypass. Credentials
    # are used for this call only, never stored.
    roles: list[dict]   # [{"role": "admin", "headers": {...}}, {"role": "anonymous", "headers": {}}]
    max_pages: int = 40
    max_endpoints: int = 150
    id_fill: str = "1"
    # Auto-register a named test identity per role, so the reachable identities
    # persist and the cross-identity compare can reuse them (deduped by name).
    register_identities: bool = True
    # Augment the JS-mined surface with active black-box API discovery
    # (api_surface_discovery) -- essential on a headless API where JS crawling
    # finds nothing. Read-only, scope-gated, throttled; bounded by max_probes.
    active_discovery: bool = False
    discovery_max_probes: int = 6000


def _register_role_identities(roles) -> list[dict]:
    """Register an Identity per distinct role (idempotent by name), so a role
    crawl's reachable identities feed the existing identity/cross-identity-compare
    system. Never stores credentials -- only the label + role."""
    existing = {i["name"] for i in store.list_identities()}
    registered: list[dict] = []
    for r in roles:
        name = f"rolecrawl:{r.role}"
        if name in existing:
            continue
        existing.add(name)
        try:
            role_enum = identity_mod.IdentityRole(r.role)
        except ValueError:
            role_enum = identity_mod.IdentityRole.USER
        ident = identity_mod.Identity(name=name, role=role_enum,
                                      notes="auto-registered by /crawl-roles")
        store.save_identity(ident)
        registered.append({"id": ident.id, "name": ident.name, "role": ident.role.value})
    return registered


class SessionHeadersRequest(_BaseModel):
    host: str
    name: str
    headers: dict          # another identity's real session headers (Authorization/Cookie)
    role: str = "user"


@app.post("/identities/session-headers")
async def set_identity_session_headers(req: SessionHeadersRequest, authorization: str | None = Header(default=None)):
    """Supply ANOTHER identity's real session headers for cross-identity
    (Autorize-style) access-control testing. Held IN MEMORY ONLY for this process
    -- never persisted, logged, or cached (see identity_headers.py) -- exactly
    like configuring Autorize's low-privilege cookie. The cross_identity validator
    replays object-scoped GETs as these identities to tell a real IDOR from a
    properly-restricted 200. Requires validators.cross_identity.enabled +
    validators.active_enabled."""
    _require_auth(authorization)
    from harness import identity_headers
    identity_headers.set_identity(req.host, req.name, req.headers, req.role)
    return {"ok": True, "host": req.host,
            "identities": [i["name"] for i in identity_headers.identities_for_host(req.host)]}


@app.post("/crawl-roles")
async def crawl_roles_endpoint(req: RoleCrawlRequest, authorization: str | None = Header(default=None)):
    """Role-aware crawl: discover the surface per role, probe every endpoint with
    every role, and return the access matrix plus derived auth-bypass and IDOR/
    BOLA candidates (role linked to URL). Also runs the same-object cross-identity
    comparison (idor_findings) and, unless disabled, auto-registers a named
    identity per role so the reachable identities feed the cross-identity-compare
    flow. Scope-gated to server.allowed_hosts, throttled, bounded by
    max_endpoints. Credentials arrive per call and are never persisted."""
    _require_auth(authorization)
    from harness import role_crawl
    roles = [role_crawl.RoleSession(role=str(r.get("role", "user")),
                                    headers=r.get("headers") or {})
             for r in req.roles]
    if not roles:
        raise HTTPException(status_code=400, detail="roles must be non-empty")
    result = await role_crawl.crawl_roles(
        req.base_url, roles,
        allowed_hosts=orchestrator.allowed_hosts,
        max_pages=max(1, min(req.max_pages, 200)),
        max_endpoints=max(1, min(req.max_endpoints, 500)),
        id_fill=req.id_fill or "1",
        active_discovery=bool(req.active_discovery),
        discovery_max_probes=max(1, min(req.discovery_max_probes, 20000)),
    )
    out = result.to_dict()
    registered: list[dict] = []
    if req.register_identities:
        try:
            registered = await __import__("asyncio").to_thread(_register_role_identities, roles)
            out["registered_identities"] = registered
        except Exception as e:
            # Identity registration is a convenience layered on top of the crawl;
            # a store hiccup must never sink the (already-completed) crawl result.
            log.warning("crawl-roles: identity registration failed: %s", e)
            out["registered_identities"] = []
            out["identity_registration_error"] = str(e)

    def _ingest(st):
        st.ingest_role_crawl(out)
        for r in roles:
            st.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")
        for ri in registered:
            st.ingest_identity(ri["name"], ri["role"], source="seed")
    await __import__("asyncio").to_thread(_update_engagement, store.host_of(req.base_url), _ingest)
    return out


@app.post("/probe-missing-auth")
async def probe_missing_auth_endpoint(req: MissingAuthRequest, authorization: str | None = Header(default=None)):
    """Fire discovered endpoints with authentication stripped and flag the ones
    that still return data -- the "generateReport unauthenticated" class an
    always-authenticated capture never reveals (missing_auth_probe.py).

    Scope-gated to server.allowed_hosts, paced by the global request throttle,
    and read-only unless include_mutating AND the safety gate allow it. Provide
    call_shapes (method+path) mined from the app's JS, bare `paths` (probed as
    GET), or set `discover` to crawl base_url first. Returns per-endpoint
    outcomes plus the missing_authentication findings."""
    _require_auth(authorization)
    from harness import missing_auth_probe
    from harness.js_endpoint_extractor import CallShape

    shapes: list[CallShape] = []
    for cs in req.call_shapes:
        method, path = cs.get("method"), cs.get("path")
        if method and path:
            shapes.append(CallShape(method=str(method).upper(), path=str(path)))
    shapes.extend(CallShape("GET", p) for p in req.paths if p)

    if not shapes and req.discover:
        from harness import crawler
        from harness.run_context import RunContext, ScopePolicy
        async with RunContext.create(
                allowed_hosts=orchestrator.allowed_hosts,
                gate_config=_live_validators_gate_config(),
                max_requests=max(1, min(req.max_pages, 200))) as crawl_context:
            session_ref = None
            if req.headers:
                session_ref = "probe-missing-auth:source"
                crawl_context.sessions.register(
                    session_ref, session_ref, dict(req.headers),
                    allowed_origins=[ScopePolicy.origin_of(req.base_url)])
            crawl = await crawler.crawl(
                req.base_url, headers=req.headers or {}, allowed_hosts=orchestrator.allowed_hosts,
                max_pages=max(1, min(req.max_pages, 200)), run_context=crawl_context,
                session_ref=session_ref)
        shapes.extend(CallShape("GET", p) for p in sorted(crawl.endpoints))

    if not shapes:
        raise HTTPException(status_code=400, detail="no call_shapes, paths, or discoverable endpoints to probe")

    from harness.run_context import RunContext
    sends_per_shape = 2 if req.send_garbage_token else 1
    async with RunContext.create(
            allowed_hosts=orchestrator.allowed_hosts,
            gate_config=_live_validators_gate_config(),
            max_requests=max(1, len(shapes) * sends_per_shape)) as probe_context:
        outcomes = await missing_auth_probe.probe_call_shapes(
            req.base_url, shapes,
            allowed_hosts=orchestrator.allowed_hosts,
            baseline_headers=req.headers or None,
            send_garbage_token=req.send_garbage_token,
            include_mutating=req.include_mutating,
            expected_protected=req.expected_protected,
            run_context=probe_context,
        )
    findings = missing_auth_probe.findings_from(outcomes)
    return {
        "base_url": req.base_url,
        "probed": len(outcomes),
        "findings_count": len(findings),
        "outcomes": [o.to_dict() for o in outcomes],
        "findings": [f.model_dump() for f in findings],
    }


class ActiveProbeRequest(_BaseModel):
    exchange: HttpExchange
    # What the agent is testing for, in the target's own terms, and which
    # specialty prompt to load (e.g. "sqli", "idor", "xss").
    hypothesis: str
    specialty: str
    model: str = ""
    step_budget: int = 0  # 0 -> the configured iterative_agent.max_steps


@app.post("/active-probe")
async def active_probe(req: ActiveProbeRequest, authorization: str | None = Header(default=None)):
    """Run the iterative (active) agent against one captured exchange, then
    integrate its result through F2 (pause->validate->remember; pivot/combine).

    Off unless iterative_agent.enabled is set in config.yaml -- this drives real
    adaptive traffic at the target. Every step is scope-gated to allowed_hosts,
    throttled, and (for mutating methods) safety-gated. Returns the agent's
    transcript + findings and the integration outcome (held findings, validation
    plans, detected chains, and forward pivot hints)."""
    _require_auth(authorization)
    if not orchestrator.iterative_agent_enabled:
        raise HTTPException(status_code=403, detail="iterative_agent is disabled in config.yaml")
    try:
        return await orchestrator.run_active_probe(
            req.exchange, req.hypothesis, req.specialty,
            model=req.model or "", step_budget=req.step_budget or None,
        )
    except Exception as e:
        log.exception("Unhandled error during active probe")
        return JSONResponse(status_code=500, content={"error": str(e)})


class RetryAgentsRequest(_BaseModel):
    exchange: HttpExchange
    agent_class: str
    # Per-request policy overrides (any omitted -> the configured retry_budget
    # default). granted_tokens is an allocator-assigned sub-cap for this vuln.
    policy_overrides: dict = {}
    granted_tokens: int | None = None


@app.post("/retry-agents")
async def retry_agents(req: RetryAgentsRequest, authorization: str | None = Header(default=None)):
    """F5 retry loop: re-run one specialist agent on one exchange up to the
    per-vulnerability policy's cap, stopping on an actionable finding. Bounded by
    max_retries / max_agents / max_tokens_per_vuln AND the global effort budget.
    Returns per-round token spend and the best finding."""
    _require_auth(authorization)
    try:
        return await orchestrator.run_retry_agents(
            req.exchange, req.agent_class,
            policy_overrides=req.policy_overrides or None,
            granted_tokens=req.granted_tokens,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.exception("Unhandled error during retry-agents")
        return JSONResponse(status_code=500, content={"error": str(e)})


class PlanAllocationRequest(_BaseModel):
    # Competing vulnerabilities: {id?, vulnerability_class, url, severity, confidence?, priority?}
    candidates: list[dict]
    policy_overrides: dict = {}
    avg_agents_per_round: float = 1.0
    # When true, a large model (the cloud coordinator by default) ranks the
    # candidates for this app first; its scores become each candidate's priority
    # before the deterministic governor allocates. Fails safe to the static
    # severity ranking. `ranking_model` overrides which model does the ranking.
    use_llm_priority: bool = False
    ranking_model: str = ""


@app.post("/plan-allocation")
async def plan_allocation_endpoint(req: PlanAllocationRequest, authorization: str | None = Header(default=None)):
    """F5 prioritizer: given competing vulnerabilities and the REMAINING global
    token budget, return which get full retry policy, which are reduced, which
    are deferred, and written guidance. With no budget cap set, everyone gets
    full policy. Calibrated against the real token ledger, like /estimate.

    With use_llm_priority, a large model ranks the candidates for this app
    first (the model ranks, the deterministic governor still allocates and
    enforces)."""
    _require_auth(authorization)
    if not req.candidates:
        raise HTTPException(status_code=400, detail="candidates must be non-empty")
    if req.use_llm_priority:
        return await orchestrator.plan_allocation_ranked(
            req.candidates, policy_overrides=req.policy_overrides or None,
            avg_agents_per_round=req.avg_agents_per_round, model=req.ranking_model or "")
    return orchestrator.plan_allocation(
        req.candidates, policy_overrides=req.policy_overrides or None,
        avg_agents_per_round=req.avg_agents_per_round)


@app.get("/settings")
async def get_settings(authorization: str | None = Header(default=None)):
    """Runtime-tunable settings the UI exposes: the global request throttle and
    the default per-vulnerability retry budget. Reflects the live values, which
    a request may have changed since startup."""
    _require_auth(authorization)
    _require_read_auth(authorization)
    from harness import global_throttle
    from harness import llm_provider as _llm_provider
    p = orchestrator.retry_budget_policy
    return {
        "throttle": global_throttle.throttle.stats(),
        "retry_budget": {
            "max_retries": p.max_retries, "max_agents": p.max_agents,
            "max_tokens_per_vuln": p.max_tokens_per_vuln, "stop_on_found": p.stop_on_found,
            "min_actionable_confidence": p.min_actionable_confidence,
        },
        # Live validator gating -- lets the UI reflect (and, via POST, flip) the
        # active-validator gate and the cross-identity arm at run time.
        "validators": orchestrator.validator_registry.state(),
        # Cloud-coordinator reasoning seam (Phase 4): whether the iterative agent
        # + critique run on the cloud model (sends real content off-host).
        "coordinator": orchestrator.cloud_reasoning_state(),
        # P2.2: redacted per-role provider diagnostics -- provider name, model,
        # whether a remote provider is configured, and whether its API-key env
        # var is PRESENT (never its value). Lets an operator confirm which
        # provider is actually active without exposing a secret.
        "llm_providers": {
            "coordinator": _llm_provider.provider_diagnostics(
                orchestrator.config.get("coordinator", {}) or {}),
            "critique": _llm_provider.provider_diagnostics(
                orchestrator.config.get("critique", {}) or {}),
        },
    }


class SettingsRequest(_BaseModel):
    # Global outbound throttle ceiling (requests/sec; 0 = unlimited). None -> leave as-is.
    throttle_rps: float | None = None
    # Default retry-budget policy overrides (any omitted -> unchanged).
    retry_budget: dict | None = None
    # Runtime validator toggles (in-memory only, never persisted): recognized keys
    # are `active_enabled` and `cross_identity` (both bool). Any omitted -> unchanged.
    validators: dict | None = None
    # Cloud-coordinator seam toggle (in-memory): recognized key `cloud_reasoning`
    # (bool). Enabling sends real exchange content to the cloud model -- see the
    # config.yaml note. Any omitted -> unchanged.
    coordinator: dict | None = None


@app.post("/settings")
async def update_settings(req: SettingsRequest, authorization: str | None = Header(default=None)):
    """Apply runtime settings from the UI: retune the global throttle and/or the
    default retry-budget policy. Takes effect immediately for subsequent work."""
    _require_auth(authorization)
    changed: dict = {}
    if req.throttle_rps is not None:
        from harness import global_throttle
        global_throttle.configure(max(0.0, float(req.throttle_rps)))
        changed["throttle"] = global_throttle.throttle.stats()
    if req.retry_budget:
        orchestrator.retry_budget_policy = orchestrator.retry_budget_policy.merged_with(req.retry_budget)
        p = orchestrator.retry_budget_policy
        changed["retry_budget"] = {"max_retries": p.max_retries, "max_agents": p.max_agents,
                                   "max_tokens_per_vuln": p.max_tokens_per_vuln}
    if req.validators:
        # Runtime, in-memory validator toggles (Burp "Cross-Identity" panel).
        # Never persisted -- gone on restart, by design. Unknown keys are ignored.
        vr = orchestrator.validator_registry
        v = req.validators
        if "active_enabled" in v:
            vr.set_active_enabled(bool(v["active_enabled"]))
        if "cross_identity" in v:
            vr.set_cross_identity_enabled(bool(v["cross_identity"]))
        changed["validators"] = vr.state()
    if req.coordinator and "cloud_reasoning" in req.coordinator:
        # Cloud-coordinator reasoning seam (Phase 4). In-memory, not persisted.
        changed["coordinator"] = orchestrator.set_cloud_reasoning(
            bool(req.coordinator["cloud_reasoning"]))
    if not changed:
        raise HTTPException(status_code=400,
                            detail="nothing to set: provide throttle_rps, retry_budget, "
                                   "validators, and/or coordinator")
    return changed


@app.get("/models")
async def list_models(authorization: str | None = Header(default=None)):
    """Model choices for the tester's dropdowns: local Ollama tags + the cloud
    models config declares (not in /api/tags), plus the currently-selected
    coordinator and agent models."""
    _require_auth(authorization)
    return await orchestrator.list_models()


class SelectModelRequest(_BaseModel):
    # Two independent dropdowns: the coordinator/governor model, and the agent
    # model. Either may be omitted. `agent` scopes the agent change to one agent
    # (omit to flip every agent -- e.g. all to gemma 31b for debugging).
    coordinator: str = ""
    agent_model: str = ""
    agent: str = ""


@app.post("/models/select")
async def select_model(req: SelectModelRequest, authorization: str | None = Header(default=None)):
    """Set the coordinator model and/or the agent model from the UI dropdowns.
    Takes effect on the next call. A bad tag isn't rejected here -- it surfaces
    as a model-not-found error when actually used."""
    _require_auth(authorization)
    result: dict = {}
    try:
        if req.coordinator:
            result.update(orchestrator.set_coordinator_model(req.coordinator))
        if req.agent_model:
            result["agents"] = orchestrator.set_agents_model(req.agent_model, req.agent or None)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not result:
        raise HTTPException(status_code=400, detail="nothing to set: provide coordinator and/or agent_model")
    return result


@app.post("/scan/confidential")
async def scan_confidential(exchange: HttpExchange, authorization: str | None = Header(default=None)):
    """Deterministic confidential-info scan (A4) of one response: secrets, PII,
    and internal-infra leakage, with every value REDACTED. Regex, no model."""
    _require_auth(authorization)
    from harness import confidential_info_detector
    matches = confidential_info_detector.scan_response(exchange)
    findings = confidential_info_detector.findings_from_exchange(exchange)
    return {
        "match_count": len(matches),
        "matches": [m.to_dict() for m in matches],
        "findings": [f.model_dump() for f in findings],
    }


class KnowledgeNoteRequest(_BaseModel):
    note: str
    tags: list[str] = []


@app.post("/knowledge")
async def add_knowledge(req: KnowledgeNoteRequest, authorization: str | None = Header(default=None)):
    """Add a retrievable knowledge note (a methodology writeup / house rule) that
    the agents' Memory Retriever surfaces at decision time (knowledge.py). Tags
    help it match; the note text is matched too."""
    _require_auth(authorization)
    if not req.note.strip():
        raise HTTPException(status_code=400, detail="note must be non-empty")
    added = await __import__("asyncio").to_thread(store.save_knowledge_note, req.tags, req.note, "manual")
    return {"added": added, "note": req.note.strip(), "tags": req.tags}


@app.get("/knowledge")
async def list_knowledge(authorization: str | None = Header(default=None)):
    """All stored knowledge notes (tester-authored + auto-remembered findings)."""
    _require_auth(authorization)
    return {"notes": await __import__("asyncio").to_thread(store.list_knowledge_notes)}


@app.get("/tools")
async def tools_catalog(category: str = "", vulnerability_class: str = "",
                        authorization: str | None = Header(default=None)):
    """The web-app tool catalog (A3). No filter -> everything grouped by
    category. `vulnerability_class` -> the tools relevant to that class;
    `category` -> just that category's tools."""
    _require_auth(authorization)
    from harness import tool_catalog
    if vulnerability_class:
        return {"tools": [t.to_dict() for t in tool_catalog.recommend_for(vulnerability_class, limit=20)]}
    grouped = tool_catalog.by_category()
    if category:
        return {"tools": [t.to_dict() for t in grouped.get(category, [])]}
    return {"by_category": {c: [t.to_dict() for t in ts] for c, ts in grouped.items()}}


class ToolRecommendRequest(_BaseModel):
    # Either a single class+url, or a batch of findings.
    vulnerability_class: str = ""
    url: str = ""
    situations: list[str] = []
    findings: list[dict] = []   # [{vulnerability_class, url|source_exchange_url}]


@app.post("/tools/recommend")
async def tools_recommend(req: ToolRecommendRequest, authorization: str | None = Header(default=None)):
    """Recommend tools for a finding (or batch): which external tool to reach
    for, why, and a command templated to the target -- the 'agent needs a tool,
    return it to the user' path."""
    _require_auth(authorization)
    from harness import tool_catalog
    if req.findings:
        recs = tool_catalog.recommendations_for_findings(req.findings)
    elif req.vulnerability_class:
        recs = tool_catalog.recommend_for_finding(
            req.vulnerability_class, req.url, situations=req.situations or None)
    else:
        raise HTTPException(status_code=400, detail="provide vulnerability_class (+url) or findings")
    return {"recommendations": [r.to_dict() for r in recs]}


def _update_engagement(host: str, apply_fn) -> None:
    """Load the host's engagement snapshot, apply an ingest function, save it.
    Defensive: engagement is a convenience layer over the primary result, so a
    store hiccup here must never fail the endpoint that called it."""
    from harness import engagement
    try:
        st = engagement.EngagementState.from_dict(store.load_engagement(host) or {"host": host})
        apply_fn(st)
        store.save_engagement(host, st.to_dict())
    except Exception as e:
        log.warning("engagement update failed for %s: %s", host, e)


@app.get("/engagement/{host}")
async def engagement_view(host: str, limit: int = 25, authorization: str | None = Header(default=None)):
    """The fused, per-host worklist (engagement.py): every known endpoint ranked
    by a transparent combination of PathScorer tier, LLM rating, the role-access
    matrix, and findings so far -- the one picture the discrete capabilities feed.
    Empty until a crawl / analysis has populated it."""
    _require_auth(authorization)
    from harness import engagement
    snap = await __import__("asyncio").to_thread(store.load_engagement, host)
    if not snap:
        return {"host": host, "endpoint_count": 0, "worklist": [], "summary": {"host": host, "endpoint_count": 0}}
    st = engagement.EngagementState.from_dict(snap)
    return {"host": host, "worklist": st.worklist(limit=max(1, min(limit, 200))),
            "ready_tasks": st.pending(), "blocked_tasks": st.blocked(), "summary": st.summary()}


class RunEngagementRequest(_BaseModel):
    base_url: str = ""
    max_targets: int = 10
    max_rounds: int = 3   # the re-planning loop: plan->execute->summarize->re-plan, up to N rounds
    # Default false -> plan only. Executing ALSO requires engagement.driver_execute
    # in config, so the driver never tests automatically.
    execute: bool = False


@app.post("/engagement/{host}/run")
async def engagement_run(host: str, req: RunEngagementRequest, authorization: str | None = Header(default=None)):
    """The engagement driver: read the fused worklist back out and produce a
    ranked, budget-allocated 'test next' plan (F5 governor). Plan-only by default
    -- it does NOT test anything. With execute=true AND engagement.driver_execute
    enabled, it fetches + analyzes the funded GET targets, bounded by the
    allocation, and returns the updated worklist."""
    _require_auth(authorization)
    max_targets = max(1, min(req.max_targets, 50))
    if req.execute:
        if not req.base_url:
            raise HTTPException(status_code=400, detail="execute requires base_url")
        return await orchestrator.run_engagement(
            host, req.base_url, max_targets=max_targets,
            max_rounds=max(1, min(req.max_rounds, 10)), execute=True)
    return await orchestrator.plan_engagement(host, max_targets=max_targets, base_url=req.base_url)


class AdvanceRequest(_BaseModel):
    base_url: str
    # Re-crawl as these roles (the tester supplies creds for any new identity,
    # e.g. one a finding revealed). Folds the new surface + access matrix back
    # into the engagement worklist -- the closed loop, tester-driven.
    roles: list[dict]
    max_pages: int = 30
    max_endpoints: int = 100


@app.post("/engagement/{host}/advance")
async def engagement_advance(host: str, req: AdvanceRequest, authorization: str | None = Header(default=None)):
    """Advance the engagement: re-crawl `base_url` as the given roles and fold the
    result (surface + access matrix + IDOR findings) back into the fused
    worklist. This is the closed loop the tester drives -- run it as a newly
    obtained identity and the new surface it can reach re-enters the ranking."""
    _require_auth(authorization)
    from harness import role_crawl, engagement
    roles = [role_crawl.RoleSession(role=str(r.get("role", "user")), headers=r.get("headers") or {})
             for r in req.roles]
    if not roles:
        raise HTTPException(status_code=400, detail="roles must be non-empty")
    result = await role_crawl.crawl_roles(
        req.base_url, roles, allowed_hosts=orchestrator.allowed_hosts,
        max_pages=max(1, min(req.max_pages, 200)), max_endpoints=max(1, min(req.max_endpoints, 500)))
    out = result.to_dict()

    await __import__("asyncio").to_thread(
        _update_engagement, host, lambda st: st.ingest_role_crawl(out))

    snap = await __import__("asyncio").to_thread(store.load_engagement, host)
    st = engagement.EngagementState.from_dict(snap or {"host": host})
    return {"host": host, "crawl": out, "worklist": st.worklist(),
            "ready_tasks": st.pending(), "blocked_tasks": st.blocked(), "summary": st.summary()}


# --- Flagship graph investigation as a tracked, cancellable job (R18) ----------
# Before this, server.py exposed run/advance/crawl but NEVER invoked
# investigate_engagement, so the Burp UI could not reach the flagship path at all.
# This runs it as a background asyncio job with status/result/cancel. NOTE: a
# persisted mid-run RESUME cursor (SHOULD-tier) is not implemented -- investigate_
# engagement is not internally checkpointed; that needs the execution ledger
# (roadmap Phase 2) and is an explicit follow-up. Jobs live in-process.
import uuid as _uuid
import time as _time
import harness.run_manifest as _run_manifest

_INVESTIGATE_JOBS: dict[str, dict] = {}

# P1-8: bounded admission + terminal-job retention. _INVESTIGATE_JOBS
# accumulated without bound before this (every job dict, including its Task
# and RunContext, lived forever), and engagement_investigate started an
# asyncio task per request with no cap on concurrent RUNNING jobs. These
# constants add both bounds. They are plain module constants, not
# harness/config.yaml keys -- P1-8 must not add a SafeDefaultGuard-checked
# config key or touch a committed default.
_MAX_RUNNING_JOBS = 4            # admission cap on concurrent running/cancelling jobs
_JOB_RETENTION_SECONDS = 900.0   # how long a terminal job's result stays readable/pollable
_MAX_RETAINED_TERMINAL_JOBS = 50 # cap on retained terminal jobs; oldest-finished evicted first
_RUNNING_STATUSES = {"running", "cancelling"}
_TERMINAL_STATUSES = {"done", "error", "cancelled"}


def _evict_expired_jobs(now: float | None = None) -> None:
    """Release terminal (done/error/cancelled) jobs so their Task/RunContext
    references (and eventually the job dict itself) can be GC'd. A terminal
    job is evicted once it is older than _JOB_RETENTION_SECONDS past
    finished_at, and/or once the number of retained terminal jobs exceeds
    _MAX_RETAINED_TERMINAL_JOBS (oldest-finished evicted first). A RUNNING or
    CANCELLING job is never touched here -- eviction is purely a terminal-job
    memory bound, never a way to reclaim capacity from active work. After
    eviction, GET status/cancel for that job_id returns 404 ("unknown job"),
    the same response as a job_id that never existed -- this keeps the
    lifecycle to one documented not-found path instead of adding a second
    "410 Gone" state to distinguish, and leaks no information about
    evicted job history."""
    now = _time.time() if now is None else now
    for job_id in [jid for jid, j in _INVESTIGATE_JOBS.items() if j["status"] in _TERMINAL_STATUSES]:
        job = _INVESTIGATE_JOBS.get(job_id)
        finished_at = job.get("finished_at") if job else None
        if finished_at is not None and (now - finished_at) > _JOB_RETENTION_SECONDS:
            del _INVESTIGATE_JOBS[job_id]
    terminal_ids = [jid for jid, j in _INVESTIGATE_JOBS.items() if j["status"] in _TERMINAL_STATUSES]
    excess = len(terminal_ids) - _MAX_RETAINED_TERMINAL_JOBS
    if excess > 0:
        terminal_ids.sort(key=lambda jid: _INVESTIGATE_JOBS[jid].get("finished_at") or 0)
        for job_id in terminal_ids[:excess]:
            del _INVESTIGATE_JOBS[job_id]


def _job_public(job: dict) -> dict:
    """The JSON-safe view of a job (never leaks the asyncio Task)."""
    return {k: job.get(k) for k in ("job_id", "host", "base_url", "status",
                                    "started_at", "finished_at", "error", "manifest_path")}


class InvestigateRequest(_BaseModel):
    base_url: str
    roles: list[dict] = []
    max_nodes: int = 8
    step_budget: int = 16
    max_chain_rounds: int = 2


@app.post("/engagement/{host}/investigate")
async def engagement_investigate(host: str, req: InvestigateRequest,
                                 authorization: str | None = Header(default=None)):
    """Start the flagship graph-driven investigation as a background JOB and return
    a job_id to poll. The job is cancellable. This is the single API entry to
    investigate_engagement (R18)."""
    _require_auth(authorization)
    if not req.base_url:
        raise HTTPException(status_code=400, detail="base_url is required")
    from harness import role_crawl
    from harness.run_context import RunContext
    from urllib.parse import urlsplit

    # P1-7 pre-admission check -- runs BEFORE any job/task is created or any
    # target request is made. An investigation start request must use scope
    # that is ALREADY pre-authorized (orchestrator.allowed_hosts, sourced from
    # config.yaml server.allowed_hosts); it may never grant new scope by the
    # mere act of naming a base_url (that was the prior bug this closes: the
    # target host used to be auto-added to allowed_hosts here). Host
    # normalization: lowercase, host-only (no port, no scheme) -- the same
    # normalization ScopePolicy.host_of/in_scope use elsewhere, so a request
    # to "shop.test:8080" and "SHOP.TEST" both normalize to "shop.test".
    def _norm_host(raw: str) -> str:
        # Accept either a bare hostname (the route {host} path param) or a
        # full URL (base_url); urlsplit on a bare host with no scheme puts it
        # in .path, not .hostname, so fall back to stripping a port manually.
        parsed = urlsplit(raw if "//" in raw else f"//{raw}")
        host = parsed.hostname
        if host is None:
            host = raw.split(":", 1)[0].split("/", 1)[0]
        return host.lower()

    target_host = _norm_host(req.base_url)
    route_host = _norm_host(host)
    if not target_host:
        raise HTTPException(status_code=400, detail="base_url has no resolvable host")
    if route_host != target_host:
        raise HTTPException(
            status_code=400,
            detail=f"route host {host!r} does not match base_url host {target_host!r}")
    allowed_hosts = {(h or "").lower() for h in (orchestrator.allowed_hosts or [])}
    if target_host not in allowed_hosts:
        raise HTTPException(
            status_code=403,
            detail=f"host {target_host!r} is not in pre-authorized scope "
                   f"(server.allowed_hosts); investigate cannot grant new scope")

    # P1-8 admission bound -- an ADDITIONAL gate that runs strictly AFTER
    # P1-7's route/base_url-consistency and pre-authorized-scope checks
    # above, never before or in place of them. First release any terminal
    # jobs past their retention window (frees capacity room), then reject if
    # concurrent running/cancelling jobs are already at the cap. This is a
    # simple hard rejection (no queue): a 503 with Retry-After, since the
    # server has finite job capacity and the caller can just retry later.
    _evict_expired_jobs()
    running_count = sum(1 for j in _INVESTIGATE_JOBS.values() if j["status"] in _RUNNING_STATUSES)
    if running_count >= _MAX_RUNNING_JOBS:
        raise HTTPException(
            status_code=503,
            detail=f"investigation job capacity reached ({running_count}/{_MAX_RUNNING_JOBS} "
                   f"running); retry later",
            headers={"Retry-After": "5"})

    roles = [role_crawl.RoleSession(role=str(r.get("role", "user")),
                                    headers=r.get("headers") or {}, name=r.get("name"),
                                    tenant=r.get("tenant"),
                                    expected_permissions=frozenset(
                                        r.get("expected_permissions") or []))
             for r in (req.roles or [])] or [role_crawl.RoleSession(role="anonymous", headers={})]
    job_id = _uuid.uuid4().hex[:12]
    runs_cfg = (config.get("runs", {}) or {})
    run_context = RunContext.create(
        run_id=job_id, allowed_hosts=allowed_hosts,
        gate_config=_live_validators_gate_config(),
        max_requests=runs_cfg.get("max_requests"), config=config,
        timeout=float(runs_cfg.get("request_timeout_seconds", 15.0)))
    manifest = _run_manifest.RunManifest.start(
        run_id=job_id, target_identifier=host, config=config,
        cache_namespace=run_context.cache_namespace, output_dir=runs_cfg.get("output_dir"),
        model_versions={"coordinator": orchestrator.coordinator_model,
                        "agents": sorted({getattr(a, "model", "")
                                          for a in orchestrator.agent_manager.agents.values()
                                          if getattr(a, "model", "")}),
                        # P1.1: which provider actually served each role this run --
                        # "ollama" unless config explicitly opted a role into a
                        # remote provider. Read from config, not from a live
                        # provider object, so this never touches an API key.
                        "coordinator_provider": (config.get("coordinator") or {}).get("provider", "ollama"),
                        "critique_provider": (config.get("critique") or {}).get("provider", "ollama")})
    job: dict = {"job_id": job_id, "host": host, "base_url": req.base_url,
                 "status": "running", "task": None, "result": None, "error": None,
                 "started_at": _time.time(), "finished_at": None,
                 "manifest_path": str(manifest.path), "run_context": run_context}

    async def _run():
        try:
            async with run_context:
                job["result"] = await orchestrator.investigate_engagement(
                    req.base_url, roles,
                    max_nodes=max(1, min(req.max_nodes, 100)),
                    step_budget=max(1, min(req.step_budget, 64)),
                    max_chain_rounds=max(0, min(req.max_chain_rounds, 10)),
                    run_context=run_context)
            job["result"].setdefault("run_id", run_context.run_id)
            job["result"].setdefault("cache_namespace", run_context.cache_namespace)
            job["result"].setdefault("request_count", run_context.budget.used)
            job["status"] = "done"
            manifest.finish("done", result=job["result"])
        except asyncio.CancelledError:
            job["status"] = "cancelled"
            manifest.finish("cancelled")
            raise
        except Exception as e:  # a failed job must report, never crash the server
            job["status"] = "error"
            job["error"] = f"{type(e).__name__}: {e}"
            manifest.finish("error", error=job["error"])
            log.warning("investigate job %s failed: %s", job_id, e)
        finally:
            job["finished_at"] = _time.time()
            # P1-8: the job just reached a terminal state -- release the
            # Task and RunContext references (the run_context's "async with"
            # above already closed its transport) so they're eligible for
            # GC. The job dict itself, including its result/error/
            # manifest_path, stays in _INVESTIGATE_JOBS and readable for
            # _JOB_RETENTION_SECONDS; _evict_expired_jobs() drops the whole
            # dict once that window (or the retained-terminal-job cap) is
            # exceeded.
            job["task"] = None
            job["run_context"] = None

    job["task"] = asyncio.create_task(_run())
    _INVESTIGATE_JOBS[job_id] = job
    return _job_public(job)


@app.get("/engagement/{host}/investigate")
async def engagement_investigate_list(host: str, authorization: str | None = Header(default=None)):
    """List investigation jobs for a host (newest-first status only)."""
    _require_auth(authorization)
    _evict_expired_jobs()
    jobs = [j for j in _INVESTIGATE_JOBS.values() if j["host"] == host]
    jobs.sort(key=lambda j: j.get("started_at") or 0, reverse=True)
    return {"host": host, "jobs": [_job_public(j) for j in jobs]}


@app.get("/engagement/{host}/investigate/{job_id}")
async def engagement_investigate_status(host: str, job_id: str,
                                        authorization: str | None = Header(default=None)):
    """Poll a job; the full investigate_engagement result is included once done."""
    _require_auth(authorization)
    _evict_expired_jobs()
    job = _INVESTIGATE_JOBS.get(job_id)
    if not job or job["host"] != host:
        # P1-8: an evicted/expired job_id lands here too (its dict was
        # dropped by _evict_expired_jobs), same as a job_id that never
        # existed -- see _evict_expired_jobs's docstring for why this is a
        # single documented 404 rather than a distinct "410 Gone".
        raise HTTPException(status_code=404, detail="unknown job")
    out = _job_public(job)
    if job["status"] == "done":
        out["result"] = job["result"]
    return out


@app.post("/engagement/{host}/investigate/{job_id}/cancel")
async def engagement_investigate_cancel(host: str, job_id: str,
                                        authorization: str | None = Header(default=None)):
    """Request cancellation of a running job (asyncio task cancellation)."""
    _require_auth(authorization)
    _evict_expired_jobs()
    job = _INVESTIGATE_JOBS.get(job_id)
    if not job or job["host"] != host:
        raise HTTPException(status_code=404, detail="unknown job")
    task = job.get("task")
    if task is not None and not task.done():
        context = job.get("run_context")
        if context is not None:
            context.cancel.cancel()
        task.cancel()
        if job["status"] == "running":
            job["status"] = "cancelling"
    return _job_public(job)


@app.get("/activity")
async def activity(since: int = 0, limit: int = 100, authorization: str | None = Header(default=None)):
    """Live agent-activity feed (V1). Poll with the last seq you saw
    (`?since=N`) to get everything after it, plus the current latest_seq and a
    `dropped` count if you fell behind the buffer. `since=0` (default) returns a
    recent snapshot to prime the view."""
    _require_auth(authorization)
    from harness import activity_feed
    if since <= 0:
        return activity_feed.snapshot(limit=limit)
    return activity_feed.since(since)


@app.get("/effort", response_model=EffortStatus)
async def effort_status(authorization: str | None = Header(default=None)):
    """Current cumulative spend against the configured budget (see
    config.yaml's effort_budget section) -- real numbers, not a projection."""
    _require_auth(authorization)
    return orchestrator.effort_status()


@app.post("/effort/confirm-overspend")
async def confirm_overspend(authorization: str | None = Header(default=None)):
    """
    Soft-mode only in practice: unblocks further dispatch after the budget
    is spent. Has no effect in hard mode -- see effort.EffortBudget.allow,
    which never checks this flag when mode is hard, by design (hard mode
    cannot be talked past by this endpoint or anything else).
    """
    _require_auth(authorization)
    orchestrator.effort_budget.confirm_overspend()
    return orchestrator.effort_status()


@app.post("/identities")
async def create_identity(req: IdentityCreateRequest, authorization: str | None = Header(default=None)):
    """Registers a named test identity (see identity.py) -- replaces
    picking a captured exchange out of an unlabeled list at
    cross-identity-compare time with a persistent, named identity."""
    _require_auth(authorization)
    try:
        role = identity_mod.IdentityRole(req.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"unknown role {req.role!r}")
    ident = identity_mod.Identity(name=req.name, role=role, notes=req.notes)
    await __import__("asyncio").to_thread(store.save_identity, ident)
    return {"id": ident.id, "name": ident.name, "role": ident.role.value, "notes": ident.notes}


@app.get("/identities")
async def get_identities(authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    return await __import__("asyncio").to_thread(store.list_identities)


@app.post("/sessions")
async def create_session(req: SessionCreateRequest, authorization: str | None = Header(default=None)):
    """Links an identity to a captured exchange's fingerprint (never the
    credential itself -- see identity.Session's docstring)."""
    _require_auth(authorization)
    if not await __import__("asyncio").to_thread(store.get_identity, req.identity_id):
        raise HTTPException(status_code=404, detail="unknown identity_id")
    sess = identity_mod.Session(identity_id=req.identity_id, host=req.host,
                                 exchange_hash=req.exchange_hash, label=req.label)
    await __import__("asyncio").to_thread(store.save_session, sess)
    return {"id": sess.id, "identity_id": sess.identity_id, "host": sess.host,
            "exchange_hash": sess.exchange_hash, "label": sess.label}


@app.get("/hosts/{host}/sessions")
async def sessions_for_host(host: str, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    return await __import__("asyncio").to_thread(store.sessions_for_host, host)


@app.post("/findings/suppress")
async def suppress_finding(req: SuppressFindingRequest, authorization: str | None = Header(default=None)):
    """
    Marks a finding fingerprint as suppressed so it doesn't resurface on
    a future scan of the same host -- see store.suppress_finding's
    docstring for the workflow gap this closes and its known limitation
    (fingerprint includes summary text, so a re-run with a differently-
    worded summary for the same underlying issue won't match).
    """
    _require_auth(authorization)
    await __import__("asyncio").to_thread(store.suppress_finding, req.fingerprint, req.reason)
    return {"fingerprint": req.fingerprint, "reason": req.reason, "suppressed": True}


@app.delete("/findings/suppress/{fingerprint}")
async def unsuppress_finding(fingerprint: str, authorization: str | None = Header(default=None)):
    """Reverses a suppression. 404s if the fingerprint wasn't suppressed,
    so a caller can tell "nothing happened" from "it worked"."""
    _require_auth(authorization)
    removed = await __import__("asyncio").to_thread(store.unsuppress_finding, fingerprint)
    if not removed:
        raise HTTPException(status_code=404, detail="fingerprint was not suppressed")
    return {"fingerprint": fingerprint, "suppressed": False}


@app.get("/findings/suppressions")
async def list_suppressions(authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    return await __import__("asyncio").to_thread(store.list_suppressions)


@app.get("/findings/{finding_ref}/evidence")
async def finding_evidence(finding_ref: str, authorization: str | None = Header(default=None)):
    """P0-1: the EvidenceLedger's audit-grade reconstruction of one finding --
    why it was tested, what was sent, what came back, why it was concluded
    (vulnerable or not), and what was never tested -- plus the minimal recipe
    to reproduce it. Read-only: this exposes what the pipeline already
    recorded, never a live re-test. Reads the durable store (not the
    in-memory ledger) so it works even after a server restart."""
    _require_auth(authorization)
    from harness import evidence_ledger
    reconstruction = await __import__("asyncio").to_thread(
        evidence_ledger.reconstruct_persisted, finding_ref)
    recipe = await __import__("asyncio").to_thread(
        evidence_ledger.reproduction_recipe_persisted, finding_ref)
    if not reconstruction.get("event_count"):
        raise HTTPException(status_code=404, detail="no evidence-ledger events for this finding_ref")
    return {"reconstruction": reconstruction, "reproduction_recipe": recipe}


class MergeIssuesRequest(_BaseModel):
    source_id: str
    target_id: str


@app.post("/issues/{host}/merge")
async def merge_issues(host: str, req: MergeIssuesRequest,
                       authorization: str | None = Header(default=None)):
    """Operator override (P1.8): declare that issue `source_id` is actually
    the same underlying bug as `target_id` on `host`, folding them together
    in every subsequent export_issues_for_host() call. Reversible via DELETE
    /issues/{host}/merge/{source_id} -- see issues.apply_merge_overrides
    and store.record_issue_merge for why this never mutates the underlying
    findings or the automatic grouping."""
    _require_auth(authorization)
    try:
        await __import__("asyncio").to_thread(
            store.record_issue_merge, host, req.source_id, req.target_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"host": host, "source_id": req.source_id, "target_id": req.target_id, "merged": True}


@app.delete("/issues/{host}/merge/{source_id}")
async def unmerge_issue(host: str, source_id: str, authorization: str | None = Header(default=None)):
    """Reverses a prior merge. 404s if no such override existed, so a caller
    can tell "nothing happened" from "it worked"."""
    _require_auth(authorization)
    removed = await __import__("asyncio").to_thread(store.remove_issue_merge, host, source_id)
    if not removed:
        raise HTTPException(status_code=404, detail="no such merge override")
    return {"host": host, "source_id": source_id, "merged": False}


@app.get("/issues/{host}/merges")
async def list_issue_merges(host: str, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    return await __import__("asyncio").to_thread(store.all_issue_merges, host)


@app.get("/cache/stats")
async def cache_stats(authorization: str | None = Header(default=None)):
    """Get cache statistics (hits, misses, hit rate, etc.)."""
    _require_auth(authorization)
    from harness import cache
    stats = cache.get_cache().stats()
    return {
        "cache_enabled": cache.get_cache().is_enabled(),
        "size": cache.get_cache().size(),
        "stats": stats.to_dict(),
    }


@app.post("/cache/clear")
async def cache_clear(authorization: str | None = Header(default=None)):
    """Clear all cached analysis results."""
    _require_auth(authorization)
    from harness import cache
    cache.get_cache().clear()
    return {"status": "ok", "message": "Cache cleared"}


@app.post("/cache/enable")
async def cache_enable(authorization: str | None = Header(default=None)):
    """Enable caching."""
    _require_auth(authorization)
    from harness import cache
    cache.get_cache().set_enabled(True)
    return {"status": "ok", "cache_enabled": True}


@app.post("/cache/disable")
async def cache_disable(authorization: str | None = Header(default=None)):
    """Disable caching."""
    _require_auth(authorization)
    from harness import cache
    cache.get_cache().set_enabled(False)
    return {"status": "ok", "cache_enabled": False}


if __name__ == "__main__":
    import uvicorn
    # W-18: harness is now a package -- run as `python -m harness.server` (or
    # `uvicorn harness.server:app`) from the repository root.
    uvicorn.run(
        "harness.server:app",
        host=config["server"]["host"],
        port=config["server"]["port"],
        reload=False,
    )
