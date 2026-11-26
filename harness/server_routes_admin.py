"""Administration routes: health, pairing, telemetry, provenance, settings, models,
activity, effort budget and the analysis cache.

ARC-9: split out of harness/server.py. build_router(srv, router) adds these
routes to `router` (harness.server passes app.router) and reads per-process
state and the helpers tests patch through server module `srv`
(srv.orchestrator, srv._require_auth, ...) at request time, so each server
module gets its own state."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel as _BaseModel, ConfigDict, Field, model_validator as _model_validator, StrictBool

from harness import security
from harness.models import EffortStatus


class _ValidatorToggles(_BaseModel):
    # RV-G R01: JSON booleans only. A plain `bool(value)` turned the string
    # "false" into True, so a caller disabling active testing armed it. StrictBool
    # rejects strings, numbers and null with a 422. Unknown keys are ignored.
    model_config = ConfigDict(extra="allow")
    active_enabled: StrictBool = False
    cross_identity: StrictBool = False


class _CoordinatorToggles(_BaseModel):
    # Same strict rule: "false" must not start sending exchanges to the cloud.
    model_config = ConfigDict(extra="allow")
    cloud_reasoning: StrictBool = False


def _non_finite_marked(value):
    """ARC-15: NaN/Infinity (which the JSON parser accepts) become a marker string,
    so the field fails validation with a 422 that can itself be serialized: the
    default 422 body echoes the input, and a raw NaN there was a 500."""
    if isinstance(value, float) and (value != value or abs(value) == float("inf")):
        return "<non-finite number>"
    if isinstance(value, dict):
        return {k: _non_finite_marked(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_non_finite_marked(v) for v in value]
    return value


class _RetryBudgetSettings(_BaseModel):
    # ARC-15: a typed, bounded schema; a malformed policy is a 422, never applied.
    # Unknown keys are refused. Bounds are owner values (see the b1 HANDOFF).
    model_config = ConfigDict(extra="forbid")
    max_retries: int | None = Field(None, ge=0, le=10, strict=True)
    max_agents: int | None = Field(None, ge=1, le=10, strict=True)
    # 0 = no per-vulnerability token cap, as in config.yaml and the Burp field.
    max_tokens_per_vuln: int | None = Field(None, ge=0, le=2_000_000, strict=True)
    stop_on_found: StrictBool | None = None
    min_actionable_confidence: float | None = Field(None, ge=0.0, le=1.0, strict=True,
                                                    allow_inf_nan=False)


class SettingsRequest(_BaseModel):
    # Global outbound throttle ceiling (requests/sec; 0 = unlimited). None -> leave as-is.
    # ARC-15: finite and >= 0 (a negative or NaN rate used to become "unlimited").
    throttle_rps: float | None = Field(None, ge=0.0, allow_inf_nan=False)
    # Removing a throttle that is on (throttle_rps 0) must be confirmed explicitly.
    confirm_unlimited: StrictBool = False
    # Default retry-budget policy overrides (any omitted -> unchanged).
    retry_budget: _RetryBudgetSettings | None = None

    @_model_validator(mode="before")
    @classmethod
    def _mark_non_finite(cls, data):
        return _non_finite_marked(data)
    # Runtime validator toggles (in-memory only, never persisted): recognized keys
    # are `active_enabled` and `cross_identity` (both bool). Any omitted -> unchanged.
    validators: _ValidatorToggles | None = None
    # Cloud-coordinator seam toggle (in-memory): recognized key `cloud_reasoning`
    # (bool). Enabling sends real exchange content to the cloud model -- see the
    # config.yaml note. Any omitted -> unchanged.
    coordinator: _CoordinatorToggles | None = None


class SelectModelRequest(_BaseModel):
    # Two independent dropdowns: the coordinator/governor model, and the agent
    # model. Either may be omitted. `agent` scopes the agent change to one agent
    # (omit to flip every agent -- e.g. all to gemma 31b for debugging).
    coordinator: str = ""
    agent_model: str = ""
    agent: str = ""


def build_router(srv, router: APIRouter | None = None) -> APIRouter:
    """The admin routes, bound to server module `srv`, added to `router`
    (a new APIRouter when none is given)."""
    router = APIRouter() if router is None else router

    @router.get("/run-provenance")
    async def run_provenance(authorization: str | None = Header(default=None)):
        srv._require_read_auth(authorization)
        from harness.runtime_provenance import describe
        return describe(srv.config, srv.orchestrator, srv._startup_source)

    @router.get("/health")
    async def health():
        """ARC-8: liveness only. Unauthenticated, so it makes no outbound request
        (no model-server probe) and names no model or agent: {"status": "ok"}
        whenever this process serves requests. Readiness (model server reachable,
        configured local models pulled), the agent and model names and the model
        egress state are at the authenticated GET /health/details."""
        return {"status": "ok"}

    @router.get("/health/details")
    async def health_details(authorization: str | None = Header(default=None)):
        """Readiness, authenticated (ARC-8). `status` is "ok" only when the LLM
        backend is usable: reachable, with every configured LOCAL model pulled
        (cloud model tags are not pulled locally and are excluded); "degraded"
        otherwise, with `ollama` carrying the detail. The backend probe is cached
        for _HEALTH_PROBE_TTL_SECONDS (`probe_age_seconds`). `model_egress` is
        SEC-1's record: which slots hold cloud models and whether
        ollama.allow_cloud_models opted in."""
        srv._require_read_auth(authorization)
        from harness import coordinator, model_egress
        from harness.ollama_client import is_cloud_model
        probe, probe_age = await srv._cached_backend_probe()
        present = set(probe.get("models") or [])

        def _is_present(model: str) -> bool:
            if model in present:
                return True
            base = model.split(":")[0]
            return any(tag == model or tag.split(":")[0] == base for tag in present)

        configured = {srv.orchestrator.coordinator_model}
        configured.update(a.model for a in srv.orchestrator.agent_manager.agents.values())
        crit = (srv.config.get("critique") or {}).get("model")
        if crit:
            configured.add(crit)
        local_models = sorted(m for m in configured if m and not is_cloud_model(m))
        missing = [m for m in local_models if not _is_present(m)]

        reachable = bool(probe.get("reachable"))
        status = "ok" if (reachable and not missing) else "degraded"
        ollama_detail = {
            "base_url": srv.orchestrator.ollama.base_url,
            "reachable": reachable,
            "models_present": sorted(present),
            "configured_local_models": local_models,
            "missing_models": missing,
        }
        if not reachable:
            ollama_detail["error"] = probe.get("error")
            ollama_detail["hint"] = "start Ollama (`ollama serve`) and confirm ollama.base_url in config.yaml"
        elif missing:
            ollama_detail["hint"] = ("pull the configured model(s), e.g. "
                                     + "; ".join(f"`ollama pull {m}`" for m in missing))
        return {
            "status": status,
            "coordinator_model": srv.orchestrator.coordinator_model,
            "agents": list(srv.orchestrator.agent_manager.get_enabled_agents()),
            # Per-agent model, so an operator can VERIFY which model each agent
            # actually runs (a per-agent override can silently shadow the default --
            # see the config.yaml agents note) instead of assuming they all moved
            # when agent_defaults.model changed.
            "agent_models": {name: a.model
                             for name, a in sorted(srv.orchestrator.agent_manager.agents.items())},
            "ollama": ollama_detail,
            "probe_age_seconds": probe_age,
            "coordinator_fail_opens": coordinator.fail_open_stats(),
            "model_egress": model_egress.egress_state(
                srv.config, model_egress.agent_models_of(srv.orchestrator.agent_manager)),
            # OPS-3: installed-versus-lock mismatches found at startup (advisory).
            "dependency_lock": srv._dependency_lock,
        }

    @router.get("/pairing/check")
    async def pairing_check(authorization: str | None = Header(default=None)):
        """Authenticate a configured client without inference or state changes.

        No credential is returned. Unlike /health, this always requires the
        effective mutation token, including the ephemeral loopback credential.
        """
        expected = srv._mutation_token()
        if not expected or not authorization or not secrets.compare_digest(
                authorization, f"Bearer {expected}"):
            raise HTTPException(status_code=401, detail="pairing credential missing or stale; reconnect")
        return {"status": "authenticated"}

    @router.get("/telemetry")
    async def telemetry(run_id: str | None = None, authorization: str | None = Header(default=None)):
        srv._require_read_auth(authorization)
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
            "effort_budget": srv.orchestrator.effort_status().model_dump() if hasattr(srv.orchestrator, "effort_status") else {},
            "diagnostics": _telemetry.snapshot(run_id),
        }

    @router.get("/settings")
    async def get_settings(authorization: str | None = Header(default=None)):
        """Runtime-tunable settings the UI exposes: the global request throttle and
        the default per-vulnerability retry budget. Reflects the live values, which
        a request may have changed since startup."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import global_throttle
        from harness.target_request_policy import TargetRequestPolicy
        from harness import llm_provider as _llm_provider
        p = srv.orchestrator.retry_budget_policy
        return {
            'target_policy': TargetRequestPolicy.from_config(srv.orchestrator.config).status(),
            "throttle": global_throttle.throttle.stats(),
            "retry_budget": {
                "max_retries": p.max_retries, "max_agents": p.max_agents,
                "max_tokens_per_vuln": p.max_tokens_per_vuln, "stop_on_found": p.stop_on_found,
                "min_actionable_confidence": p.min_actionable_confidence,
            },
            # Live validator gating -- lets the UI reflect (and, via POST, flip) the
            # active-validator gate and the cross-identity arm at run time.
            "validators": srv.orchestrator.validator_registry.state(),
            # Cloud-coordinator reasoning seam (Phase 4): whether the iterative agent
            # + critique run on the cloud model (sends real content off-host).
            "coordinator": srv.orchestrator.cloud_reasoning_state(),
            # P2.2: redacted per-role provider diagnostics -- provider name, model,
            # whether a remote provider is configured, and whether its API-key env
            # var is PRESENT (never its value). Lets an operator confirm which
            # provider is actually active without exposing a secret.
            "llm_providers": {
                "coordinator": _llm_provider.provider_diagnostics(
                    srv.orchestrator.config.get("coordinator", {}) or {}),
                "critique": _llm_provider.provider_diagnostics(
                    srv.orchestrator.config.get("critique", {}) or {}),
            },
        }

    @router.post("/settings")
    async def update_settings(req: SettingsRequest, authorization: str | None = Header(default=None)):
        """Apply runtime settings from the UI: retune the global throttle and/or the
        default retry-budget policy. Takes effect immediately for subsequent work."""
        srv._require_auth(authorization)
        from harness import global_throttle
        changed: dict = {}
        # ARC-15: turning a live throttle OFF needs confirm_unlimited; refused before
        # anything in the request is applied. Every change is logged (source
        # "settings") and copied into the manifest of each run live at the time.
        removing = (req.throttle_rps is not None and req.throttle_rps == 0
                    and global_throttle.throttle.enabled)
        if removing and not req.confirm_unlimited:
            raise HTTPException(status_code=422,
                                detail="throttle_rps 0 removes the outbound throttle "
                                       f"({global_throttle.throttle.stats()['rate_per_second']} req/s); "
                                       "resend with confirm_unlimited: true to remove it")
        if req.throttle_rps is not None:
            global_throttle.configure(float(req.throttle_rps), source="settings",
                                      detail={"confirmed_unlimited": True} if removing else None)
            changed["throttle"] = global_throttle.throttle.stats()
        retry = req.retry_budget.model_dump(exclude_unset=True) if req.retry_budget else {}
        if retry:
            no_cap = retry.get("max_tokens_per_vuln") == 0
            policy = srv.orchestrator.retry_budget_policy.merged_with(
                {k: v for k, v in retry.items() if not (no_cap and k == "max_tokens_per_vuln")})
            if no_cap:
                import dataclasses as _dataclasses
                policy = _dataclasses.replace(policy, max_tokens_per_vuln=None)
            srv.orchestrator.retry_budget_policy = policy
            p = srv.orchestrator.retry_budget_policy
            changed["retry_budget"] = {"max_retries": p.max_retries, "max_agents": p.max_agents,
                                       "max_tokens_per_vuln": p.max_tokens_per_vuln}
        v = req.validators
        if v is not None and (v.model_fields_set or v.model_extra):
            # Runtime, in-memory validator toggles (Burp "Cross-Identity" panel).
            # Never persisted -- gone on restart, by design. Unknown keys are ignored.
            # Only keys the caller sent are applied (an omitted toggle is unchanged).
            vr = srv.orchestrator.validator_registry
            if "active_enabled" in v.model_fields_set:
                vr.set_active_enabled(v.active_enabled)
            if "cross_identity" in v.model_fields_set:
                vr.set_cross_identity_enabled(v.cross_identity)
            changed["validators"] = vr.state()
        if req.coordinator is not None and "cloud_reasoning" in req.coordinator.model_fields_set:
            # Cloud-coordinator reasoning seam (Phase 4). In-memory, not persisted.
            changed["coordinator"] = srv.orchestrator.set_cloud_reasoning(req.coordinator.cloud_reasoning)
        if not changed:
            raise HTTPException(status_code=400,
                                detail="nothing to set: provide throttle_rps, retry_budget, "
                                       "validators, and/or coordinator")
        return changed

    @router.get("/models")
    async def list_models(authorization: str | None = Header(default=None)):
        """Model choices for the tester's dropdowns: local Ollama tags + the cloud
        models config declares (not in /api/tags), plus the currently-selected
        coordinator and agent models."""
        srv._require_auth(authorization)
        return await srv.orchestrator.list_models()

    @router.post("/models/select")
    async def select_model(req: SelectModelRequest, authorization: str | None = Header(default=None)):
        """Set the coordinator model and/or the agent model from the UI dropdowns.
        Takes effect on the next call. A bad tag isn't rejected here -- it surfaces
        as a model-not-found error when actually used."""
        srv._require_auth(authorization)
        result: dict = {}
        try:
            if req.coordinator:
                result.update(srv.orchestrator.set_coordinator_model(req.coordinator))
            if req.agent_model:
                result["agents"] = srv.orchestrator.set_agents_model(req.agent_model, req.agent or None)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=security.safe_error_summary(e))
        if not result:
            raise HTTPException(status_code=400, detail="nothing to set: provide coordinator and/or agent_model")
        return result

    @router.get("/activity")
    async def activity(since: int = 0, limit: int = 100, authorization: str | None = Header(default=None)):
        """Live agent-activity feed (V1). Poll with the last seq you saw
        (`?since=N`) to get everything after it, plus the current latest_seq and a
        `dropped` count if you fell behind the buffer. `since=0` (default) returns a
        recent snapshot to prime the view."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import activity_feed
        if since <= 0:
            return activity_feed.snapshot(limit=limit)
        return activity_feed.since(since)

    @router.get("/effort", response_model=EffortStatus)
    async def effort_status(authorization: str | None = Header(default=None)):
        """Current cumulative spend against the configured budget (see
        config.yaml's effort_budget section) -- real numbers, not a projection."""
        srv._require_auth(authorization)
        return srv.orchestrator.effort_status()

    @router.post("/effort/confirm-overspend")
    async def confirm_overspend(authorization: str | None = Header(default=None)):
        """
        Soft-mode only in practice: unblocks further dispatch after the budget
        is spent. Has no effect in hard mode -- see effort.EffortBudget.allow,
        which never checks this flag when mode is hard, by design (hard mode
        cannot be talked past by this endpoint or anything else).
        """
        srv._require_auth(authorization)
        srv.orchestrator.effort_budget.confirm_overspend()
        return srv.orchestrator.effort_status()

    @router.get("/cache/stats")
    async def cache_stats(authorization: str | None = Header(default=None)):
        """Get cache statistics (hits, misses, hit rate, etc.)."""
        srv._require_auth(authorization)
        from harness import cache
        stats = cache.get_cache().stats()
        return {
            "cache_enabled": cache.get_cache().is_enabled(),
            "size": cache.get_cache().size(),
            "stats": stats.to_dict(),
        }

    @router.post("/cache/clear")
    async def cache_clear(authorization: str | None = Header(default=None)):
        """Clear all cached analysis results."""
        srv._require_auth(authorization)
        from harness import cache
        cache.get_cache().clear()
        return {"status": "ok", "message": "Cache cleared"}

    @router.post("/cache/enable")
    async def cache_enable(authorization: str | None = Header(default=None)):
        """Enable caching."""
        srv._require_auth(authorization)
        from harness import cache
        cache.get_cache().set_enabled(True)
        return {"status": "ok", "cache_enabled": True}

    @router.post("/cache/disable")
    async def cache_disable(authorization: str | None = Header(default=None)):
        """Disable caching."""
        srv._require_auth(authorization)
        from harness import cache
        cache.get_cache().set_enabled(False)
        return {"status": "ok", "cache_enabled": False}

    return router
