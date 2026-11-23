from __future__ import annotations
import logging
import os
import secrets
import sys
import yaml
from harness import store
from harness import security
# The ingest router reaches the prioritizer as srv.surface_prioritizer, so a test
# patches it here.
from harness import surface_prioritizer  # noqa: F401
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.middleware.trustedhost import TrustedHostMiddleware

# The /prioritize result model, which harness.server imported before ARC-9.
from harness.models import PrioritizeResultItem  # noqa: F401
from harness.orchestrator import Orchestrator
from harness.ollama_client import OllamaCloudModelRefusedError
# ARC-1 admission is single-sourced in harness.server_admission (ARC-9). The
# registry and the dependency stay readable here for callers and tests.
from harness.server_admission import (ACTIVE_TRAFFIC_ROUTES, ACTIVE_TRAFFIC_WHEN,  # noqa: F401
                                      PASSIVE_RUN_ROUTES, _ACTIVE_TRAFFIC,
                                      require_active_traffic)

logging.basicConfig(level=logging.INFO)
security.install_privacy_log_filters()
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
from harness.source_identity import capture_source_snapshot
_startup_source = capture_source_snapshot()
# OPS-3: warn at startup when installed packages differ from harness/requirements.lock
# (advisory: never blocks startup); the same report is served by the authenticated
# GET /health/details as `dependency_lock`.
try:
    from harness import lock_preflight
    _dependency_lock = lock_preflight.log_report(lock_preflight.check_lock(), log).to_dict()
except Exception as _lock_check_error:
    log.warning("dependency lock check skipped (%s)", _lock_check_error)
    _dependency_lock = {"lock_found": False, "ok": True, "error": str(_lock_check_error)}
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
    from harness.target_request_policy import TargetRequestPolicy
    live['target_policy'] = TargetRequestPolicy.from_config(orchestrator.config)
    return live


def _require_target_fetch(url: str, *, bulk: bool = False) -> None:
    """Admission for API operations that fetch rather than analyze supplied data."""
    from harness.target_request_policy import TargetRequestPolicy
    policy = TargetRequestPolicy.from_config(orchestrator.config)
    reason = policy.denial_reason(url)
    if not reason and bulk and policy.excluded_path_prefixes:
        # Legacy raw crawl/browser adapters cannot enforce exclusions per hop.
        # Reject the entire operation rather than promising partial containment.
        reason = 'target operation blocked: this adapter cannot enforce endpoint exclusions per hop'
    if reason:
        raise HTTPException(status_code=403, detail=reason)


def _require_active_scope(url: str, *, action: str = "crawl") -> None:
    """Active-mode scope admission: an explicit scope that covers `url`.

    Empty server.allowed_hosts is fail-CLOSED for active traffic (W-17
    active_mode): a default-config crawl or probe must not reach an arbitrary
    host. Returns a clear 403, never a silent empty result. The master switch is
    the separate require_active_traffic dependency."""
    from harness.scope_lock import host_in_scope, out_of_scope_reason
    allowed = orchestrator.allowed_hosts
    if not host_in_scope(url, allowed, active_mode=True):
        if not allowed:
            raise HTTPException(
                status_code=403,
                detail=f"{action} refused: no server.allowed_hosts configured. This route "
                       "sends active traffic, so it fails closed without an explicit "
                       "scope. Set server.allowed_hosts (e.g. in config.local.yaml) to "
                       "the target host, then retry.")
        raise HTTPException(status_code=403, detail=f"{action} refused: {out_of_scope_reason(url, allowed)}")


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


_BEARER_TOKEN = config.get("server", {}).get("auth_token") or os.environ.get("HARNESS_BEARER_TOKEN")
_SERVER_HOST = config.get("server", {}).get("host", "127.0.0.1")
# Compatibility name for legacy diagnostics/tests. Sensitive reads always
# authenticate; server.require_read_auth=false no longer disables the policy.
_READ_AUTH_ENABLED = True
# P3-1 (partial): ships false -- see the config.yaml comment on
# server.enable_wipe_endpoint for why. Same pattern as _READ_AUTH_ENABLED
# above: a plain module global (not wrapped in a function) so a test can
# flip it directly via `server._WIPE_ENDPOINT_ENABLED = True`/`False`
# without a config reload; wipe_engagement_evidence below re-reads this
# name from the module each call (never captures it in a closure/default
# arg) so that monkeypatch works.
_WIPE_ENDPOINT_ENABLED = bool(config.get("server", {}).get("enable_wipe_endpoint", False))
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
# The extension accepts an explicitly supplied token (or environment bearer).
# /pairing/check proves authentication separately from public liveness.
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Where the ephemeral token is published for a local operator/extension to
# read. Never committed (see .gitignore) -- regenerated fresh every process
# start, so a stale lockfile from a prior run is always overwritten.
TOKEN_LOCKFILE_PATH = Path(__file__).parent / ".harness_token.lock"


def _write_token_lockfile(token: str) -> bool:
    """Publish privately or report failure; no credential bytes in diagnostics.

    Windows uses a protected explicit user DACL before writing, POSIX uses 0600.
    Failure leaves the prior file unchanged; it may be stale, so do not report
    successful publication. Startup retains the generated in-memory token.
    """
    try:
        security.write_private_credential_file(TOKEN_LOCKFILE_PATH, token)
    except OSError as e:
        log.warning("Could not privately publish ephemeral pairing token (%s); "
                    "prior lockfile may be stale. Configure an explicit bearer token to pair.", type(e).__name__)
        return False
    return True


_EPHEMERAL_TOKEN: str | None = None
if not _BEARER_TOKEN:
    _EPHEMERAL_TOKEN = secrets.token_urlsafe(32)
    _token_published = _write_token_lockfile(_EPHEMERAL_TOKEN)
    if _token_published:
        log.info("Generated an ephemeral bearer token for authenticated routes and privately published it to %s",
                 TOKEN_LOCKFILE_PATH)


def _mutation_token() -> str | None:
    """The token a state-changing request must present. The operator-
    configured token if one was set (mirrors _require_auth's own precedence
    -- an explicitly configured token always wins), else the ephemeral one
    generated above. Never None in a running process: exactly one of
    _BEARER_TOKEN / _EPHEMERAL_TOKEN is always set by the startup block
    above."""
    return _BEARER_TOKEN or _EPHEMERAL_TOKEN


def _require_read_auth(authorization: str | None) -> None:
    """Require the effective credential for sensitive reads, including loopback.

    Legacy require_read_auth=false and the compatibility module flag cannot
    disable this policy. Public health/schema documentation remain readable;
    pairing requires the effective token independently. See docs/PRIVACY.md.
    """
    token = _mutation_token()
    if not token or not authorization or not secrets.compare_digest(
            authorization, f"Bearer {token}"):
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

    # Central route coverage also protects newly added diagnostic/sensitive
    # GET routes; public liveness and API schema documentation are explicit.
    if request.method in {"GET", "HEAD"} and request.url.path not in {
            "/health", "/pairing/check", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}:
        try:
            _require_read_auth(request.headers.get("authorization"))
        except HTTPException:
            return JSONResponse(status_code=401, content={"detail": "missing or invalid bearer token"})

    return await call_next(request)


# ARC-8: how long GET /health/details reuses its model-server probe, so a
# client polling it does not send a request to the model server per call.
_HEALTH_PROBE_TTL_SECONDS = 10.0
_health_probe_cache: dict = {}


async def _cached_backend_probe() -> tuple[dict, float]:
    """(orchestrator.ollama.health_check() result, its age in seconds), probed
    again when older than _HEALTH_PROBE_TTL_SECONDS or the client changed."""
    import time
    client = orchestrator.ollama
    cached = _health_probe_cache.get("probe")
    now = time.monotonic()
    if cached and cached[2] is client and now - cached[1] < _HEALTH_PROBE_TTL_SECONDS:
        return cached[0], round(now - cached[1], 3)
    probe = await client.health_check()
    # Only a reachable probe is reused: an operator who just started the model
    # server sees it on the next call, not after the TTL.
    if probe.get("reachable"):
        _health_probe_cache["probe"] = (probe, time.monotonic(), client)
    else:
        _health_probe_cache.pop("probe", None)
    return probe, 0.0


# ARC-4/ARC-12: the HTTP status and wording of each Burp-plane refusal code
# (store.PLANE_REFUSAL_REASONS). 404 is an unknown plan and nothing else; a
# refusal by the plan's state is 409, and a result or dispatch that does not
# fit the plan is 422. The body is {"detail": {"reason": <code>, "message": ...}}.
_PLANE_REFUSALS = {
    "unknown_plan": (404, "unknown test plan"),
    "not_dispatched": (409, "the plan was not dispatched to the Burp plane"),
    "dispatch_nonce_mismatch": (409, "the dispatch nonce is not the plan's current one"),
    "duplicate_submission": (409, "this dispatch already has a result"),
    "plan_terminal": (409, "the plan already holds a verdict"),
    "dispatch_nonce_required": (422, "the result carries no dispatch nonce"),
    "wrong_execution_plane": (422, "the plan does not run on the Burp plane"),
    "binding_mismatch": (422, "the source exchange does not match the plan"),
    "executor_mismatch": (422, "executor does not match the registered capability"),
    "capability_cannot_confirm": (422, "this capability may provide evidence but cannot mark the vulnerability confirmed"),
    "confirmed_status_invalid": (422, "confirmed result has invalid status"),
}


def _plane_refusal(reason: str) -> HTTPException:
    # A code without an entry is a refusal all the same: 409, never a 404
    # that reads as "unknown plan".
    status, message = _PLANE_REFUSALS.get(reason, (409, "refused"))
    return HTTPException(status_code=status, detail={"reason": reason, "message": message})


def _cloud_run_refused(e: OllamaCloudModelRefusedError) -> HTTPException:
    """SEC-1: a run refused for a cloud model without ollama.allow_cloud_models
    is a config conflict the operator fixes, not a server fault: 409 carrying
    the refusal reason (config slot and model names, never exchange content)."""
    return HTTPException(status_code=409, detail=str(e))


def _update_engagement(host: str, apply_fn, *, engagement_id: str = "") -> dict | None:
    """Atomically apply an ingest function in the requested host partition.
    Defensive: engagement is a convenience layer over the primary result, so a
    store hiccup here must never fail the endpoint that called it."""
    from harness import engagement
    try:
        def mutate(snapshot):
            st = engagement.EngagementState.from_dict(snapshot)
            apply_fn(st)
            return st.to_dict()
        return store.mutate_engagement(host, mutate, engagement_id=engagement_id)
    except Exception as e:
        log.warning("engagement update failed for %s: %s", host, e)


# --- Flagship graph investigation as a tracked, cancellable job (R18) ----------
# Before this, server.py exposed run/advance/crawl but NEVER invoked
# investigate_engagement, so the Burp UI could not reach the flagship path at all.
# This runs it as a background asyncio job with status/result/cancel. With
# runs.journal on (default off), the run also writes each finished unit (discovery,
# worklist nodes, capture reviews, coverage checkpoints) to a run journal
# (run_journal.py), so an interrupted job -- which has no result -- can be resumed with
# resume_job_id without repeating them. Job status lives in-process and in the job store.
import uuid as _uuid
import time as _time
# The investigate router starts the run manifest; tests patch it as server._run_manifest.
import harness.run_manifest as _run_manifest  # noqa: F401

_INVESTIGATE_JOBS: dict[str, dict] = {}
_JOB_OWNER = _uuid.uuid4().hex

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
_TERMINAL_STATUSES = {"done", "error", "cancelled", "interrupted"}


def _job_store():
    from harness.job_status import JobStatusStore
    return JobStatusStore(Path(store._DB_PATH).with_name('harness_jobs.db'), _JOB_OWNER,
                          retention=_JOB_RETENTION_SECONDS,
                          max_terminal=_MAX_RETAINED_TERMINAL_JOBS,
                          max_running=_MAX_RUNNING_JOBS)


def _run_journal_path():
    return Path(store._DB_PATH).with_name('harness_run_journal.db')


def _save_job_status(job):
    try:
        _job_store().update(job)
        job['persistence_error'] = None
    except Exception as exc:
        job['persistence_error'] = 'durable job status unavailable; polling after restart may be incomplete'
        job['delivery_error'] = 'complete result could not be durably stored'
        log.warning('job status persistence failed (%s)', type(exc).__name__)


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
    try:
        journal = _job_store()
        journal.recover_interrupted(now=now)
        journal.prune(now=now)
    except Exception:
        raise HTTPException(status_code=503, detail='durable job status unavailable') from None


def _attempt_findings(base_url: str, attempts) -> list[dict]:
    """Stored findings of every attempt of this assessment, oldest attempt first."""
    return [row for run_id in attempts for row in store.all_host_findings(base_url, run_id=run_id)]


def _attempt_accounting(attempts, findings) -> tuple[list, dict]:
    """(proof-bound case refs, issue accounting) over every attempt of this
    assessment: a resumed job's own run and the runs it resumed (r9). One attempt
    is the single-run accounting, unchanged."""
    from harness.assessment_health import (confirmed_issue_inventory, confirmed_issue_accounting,
                                           stored_proof_artifacts_resolve)
    scope = attempts[0] if len(attempts) == 1 else list(attempts)
    proven = confirmed_issue_inventory(findings, scope, store.proofs_for_case)
    accounting = confirmed_issue_accounting(
        findings, scope, store.proofs_for_case,
        run_proofs=[p for run_id in attempts for p in store.proofs_for_run(run_id)],
        artifact_resolver=stored_proof_artifacts_resolve)
    return proven, accounting


def _job_public(job: dict, *, include_result: bool = False) -> dict:
    """The JSON-safe view of a job (never leaks the asyncio Task)."""
    from harness.job_status import JobStatusStore
    snapshot = JobStatusStore.public_snapshot(job)
    out = {k: snapshot.get(k) for k in ("job_id", "host", "base_url", "status",
                                    "started_at", "finished_at", "error", "manifest_path",
                                    "recovered", "result_available", "result_ref", "result_size_bytes",
                                    "result_sha256", "result_summary", "delivery_error")}
    out['persistence_error'] = job.get('persistence_error')
    if out.get('result_ref'):
        try:
            _job_store().read_result(job['job_id'])
        except (ValueError, OSError, __import__('sqlite3').Error):
            out.update(result_available=False, delivery_error='result artifact missing or corrupt')
    if include_result and snapshot['status'] in _TERMINAL_STATUSES:
        out['result'] = snapshot['result']
    return out


def _journal_context_key(config, req) -> str:
    """E7: the run journal's context key. Source and configuration
    (resume_context_key) plus the request inputs that shape what a run discovers
    and investigates: the target URL, each role's identity (role, name, tenant,
    expected permissions, credential header NAMES), the seed requests and the
    limits. Credential VALUES are left out on purpose: a resumed run logs in again
    and the journal fills each `$role:` placeholder from the new run's roles."""
    import hashlib
    import json
    from harness.coverage_tracker import resume_context_key
    roles = sorted(
        (str(r.get("role", "user")), str(r.get("name") or ""), str(r.get("tenant") or ""),
         sorted(str(p) for p in (r.get("expected_permissions") or [])),
         sorted(str(k).lower() for k in (r.get("headers") or {})))
        for r in (req.roles or []))
    seeds = [(s.method, s.url, hashlib.sha256((s.request_body or "").encode()).hexdigest())
             for s in (req.seed_exchanges or [])]
    limits = req.model_dump(exclude={"base_url", "roles", "seed_exchanges", "resume_job_id",
                                     "protected_paths", "owners", "use_saved_declarations"})
    key_inputs = [req.base_url, roles, seeds, limits]
    # I16: declarations change what confirms, so a declared list is part of the key;
    # none declared leaves the key exactly as it was before these fields existed.
    declared = {name: value for name, value in (("protected_paths", req.protected_paths),
                                                ("owners", req.owners)) if value}
    if declared:
        key_inputs.append(declared)
    inputs = json.dumps(key_inputs, sort_keys=True, default=str)
    return f"{resume_context_key(config)}:{hashlib.sha256(inputs.encode()).hexdigest()[:16]}"


# --- ARC-9: the routes live in harness/server_routes_*.py ----------------------
# Each router module exposes build_router(srv, router). Its handlers read this
# module's state and helpers as srv.<name> at request time, so patching
# harness.server.<name>, or loading a fresh copy of this module, reaches them. The
# shared admission dependency finds this module through app.state.harness_server.
#
# The routes are added to app.router itself, not through app.include_router: from
# FastAPI 0.141 an included router is one lazy _IncludedRouter entry, which hides
# its APIRoutes from app.routes, and the ARC-1 admission scan and the route audits
# read app.routes. Added this way, app.routes holds the same APIRoute objects
# (dependency overrides, operation ids) as when the routes were defined here.
app.state.harness_server = sys.modules[__name__]

from harness import (server_routes_active, server_routes_admin,  # noqa: E402
                     server_routes_data, server_routes_engagement,
                     server_routes_ingest, server_routes_investigate,
                     server_routes_reports)

ROUTER_MODULES = (server_routes_admin, server_routes_ingest, server_routes_active,
                  server_routes_engagement, server_routes_reports,
                  server_routes_investigate, server_routes_data)
for _router_module in ROUTER_MODULES:
    _router_module.build_router(sys.modules[__name__], app.router)


def _router_names() -> dict:
    """The route endpoints and the request models of the router modules by name:
    names harness.server defined before ARC-9, kept readable here (tests call
    server.<endpoint>(...) and build server.<Model>(...)). A name that would
    shadow one of this module's own, or that two routers share, is an error."""
    found: dict = {}

    def add(name, obj):
        if found.get(name, obj) is not obj or name in globals():
            raise RuntimeError(f"router name {name!r} is not unique in harness.server")
        found[name] = obj

    for route in app.routes:
        if isinstance(route, APIRoute) and route.endpoint.__module__.startswith(
                "harness.server_routes_"):
            add(route.endpoint.__name__, route.endpoint)
    for module in ROUTER_MODULES:
        for name, obj in vars(module).items():
            if (isinstance(obj, type) and issubclass(obj, BaseModel)
                    and obj.__module__ == module.__name__):
                add(name, obj)
    return found


# importlib.reload runs this module again in its old namespace, which still holds
# the names the last load exported (tests reload it); those are not collisions.
for _name in globals().pop("_ROUTER_EXPORTS", ()):
    globals().pop(_name, None)
_router_exports = _router_names()
globals().update(_router_exports)
_ROUTER_EXPORTS = tuple(_router_exports)
del _router_exports, _router_module
globals().pop("_name", None)


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
