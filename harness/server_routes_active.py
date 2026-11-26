"""Active-traffic routes (ARC-1): crawl, role crawl, the missing-auth probe, the
active probe and the engagement driver's run and advance.

Each route carries the shared server_admission dependency, except
/engagement/{host}/run, which calls the same master switch before the branch that
sends (ACTIVE_TRAFFIC_WHEN).

ARC-9: split out of harness/server.py. build_router(srv, router) adds these
routes to `router` (harness.server passes app.router) and reads per-process
state and the helpers tests patch through server module `srv`
(srv.orchestrator, srv._require_auth, ...) at request time, so each server
module gets its own state."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel as _BaseModel

import harness.identity as identity_mod
from harness import security, server_admission, store
from harness.models import HttpExchange
from harness.orchestrator_confirm import ProbeScopeRefused
from harness.server_admission import _ACTIVE_TRAFFIC

log = logging.getLogger("harness.server")


def _route_session(run_context, session_id: str, headers: dict | None, base_url: str,
                   role: str = "user") -> str:
    """Register the caller's headers as a run session bound to base_url's origin."""
    from harness.run_context import ScopePolicy
    run_context.sessions.register(session_id, session_id, dict(headers or {}),
                                  allowed_origins=[ScopePolicy.origin_of(base_url)], role=role)
    return session_id


def _role_route_sessions(run_context, prefix: str, roles, base_url: str) -> list[str]:
    """One session per role, aligned with `roles` (role_crawl's run contract)."""
    return [_route_session(run_context, f"{prefix}:{index}:{role.role}", role.headers,
                           base_url, role=role.role)
            for index, role in enumerate(roles)]


class CrawlRequest(_BaseModel):
    base_url: str
    # Optional session the tester's Burp already holds (Authorization / Cookie),
    # so the crawl reaches authenticated surface. Never populated by the server.
    headers: dict[str, str] = {}
    max_pages: int = 40
    max_depth: int = 2


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
    # were only referenced in authenticated JS). Required for a CONFIRMED
    # missing-auth finding, together with an authenticated baseline from
    # `headers` that returns the same payload (RV-G R15). Without both, data
    # served anonymously is reported as an unconfirmed candidate.
    expected_protected: bool = False


class RoleCrawlRequest(_BaseModel):
    base_url: str
    # Each role's real captured session headers (Authorization/Cookie) from Burp.
    # Include an anonymous role (empty headers) to detect auth bypass. Credentials
    # are used for this call only, never stored.
    # [{"role": "admin", "headers": {...}, "name": "ops"}, {"role": "anonymous", "headers": {}}]
    # Optional per role: name (principal), tenant, expected_permissions -- see _role_sessions.
    roles: list[dict]
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


def _role_sessions(raw_roles) -> list:
    """API role dicts -> role_crawl.RoleSession, keeping the operator-declared
    principal metadata (X03): `name` identifies the principal (two credentials
    with one name are one principal, renewed), `tenant` and
    `expected_permissions` are declared, never inferred. Credentials arrive
    per call and are never persisted."""
    from harness import role_crawl
    return [role_crawl.RoleSession(
                role=str(r.get("role", "user")), headers=r.get("headers") or {},
                name=(str(r["name"]) if r.get("name") else None),
                tenant=(str(r["tenant"]) if r.get("tenant") else None),
                expected_permissions=frozenset(r.get("expected_permissions") or []),
                login=(dict(r["login"]) if isinstance(r.get("login"), dict) else None))
            for r in (raw_roles or [])]


def _register_role_identities(roles) -> list[dict]:
    """Register an Identity per distinct principal label (idempotent by name), so
    a role crawl's reachable identities feed the existing identity/cross-identity-
    compare system. The label is the principal's declared name, else its role, so
    two named same-role principals stay two identities. Never stores credentials
    -- only the label + role."""
    existing = {i["name"] for i in store.list_identities()}
    registered: list[dict] = []
    for r in roles:
        name = f"rolecrawl:{r.name or r.role}"
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


class ActiveProbeRequest(_BaseModel):
    exchange: HttpExchange
    # What the agent is testing for, in the target's own terms, and which
    # specialty prompt to load (e.g. "sqli", "idor", "xss").
    hypothesis: str
    specialty: str
    model: str = ""
    step_budget: int = 0  # 0 -> the configured iterative_agent.max_steps


class RunEngagementRequest(_BaseModel):
    base_url: str = ""
    max_targets: int = 10
    max_rounds: int = 3   # the re-planning loop: plan->execute->summarize->re-plan, up to N rounds
    # Default false -> plan only. Executing ALSO requires engagement.driver_execute
    # in config, so the driver never tests automatically.
    execute: bool = False


class AdvanceRequest(_BaseModel):
    base_url: str
    # Re-crawl as these roles (the tester supplies creds for any new identity,
    # e.g. one a finding revealed). Folds the new surface + access matrix back
    # into the engagement worklist -- the closed loop, tester-driven.
    roles: list[dict]
    max_pages: int = 30
    max_endpoints: int = 100


def build_router(srv, router: APIRouter | None = None) -> APIRouter:
    """The active routes, bound to server module `srv`, added to `router`
    (a new APIRouter when none is given)."""
    router = APIRouter() if router is None else router

    def _crawl_route_run():
        """The run a /crawl, /crawl-roles or /engagement/{host}/advance call owns
        (RV-G, I05's no-run routes), as a standalone analyze() owns one (I05-A2).

        Their raw clients followed redirects internally, so only the starting URL
        was scope-checked and the caller's headers went to every hop. Inside this
        run each hop goes through TargetTransport: scope and endpoint exclusions are
        checked before every redirect hop (an out-of-scope Location is never
        contacted), the caller's headers are a session only its own origin
        receives, and the clients use the configured connect-time pin and TLS policy.

        The routes stay read-only, as they were: mutating replay is forced off for
        this run whatever the operator configured. The request ceiling is
        runs.max_requests (unset = none beyond the route's own page/endpoint caps),
        the knob the investigate job uses; a dedicated default is an owner decision
        (RV-G handoff)."""
        from harness.run_context import RunContext
        runs_cfg = srv.orchestrator.config.get("runs", {}) or {}
        gate_config = {**srv._live_validators_gate_config(), "allow_mutating_replay": False}
        return RunContext.create(
            allowed_hosts=srv.orchestrator.allowed_hosts, gate_config=gate_config,
            config=srv.orchestrator.config, max_requests=runs_cfg.get("max_requests"),
            timeout=float(runs_cfg.get("request_timeout_seconds", 15.0)))

    @router.post("/crawl", dependencies=_ACTIVE_TRAFFIC)
    async def crawl_endpoint(req: CrawlRequest, authorization: str | None = Header(default=None)):
        """Discover the application's real endpoint surface by fetching its pages
        AND mining the JavaScript bundles they load (js_endpoint_extractor.py) --
        the API surface a link-only spider misses. Scope-gated to the engagement's
        server.allowed_hosts, paced by the global request throttle, and bounded by
        max_pages/max_depth. Drives the Burp "Crawl" button; returns the discovered
        endpoints for the site map / attack-surface tab."""
        srv._require_auth(authorization)
        srv._require_target_fetch(req.base_url, bulk=True)
        srv._require_active_scope(req.base_url, action="crawl")
        from harness import crawler
        async with _crawl_route_run() as run_context:
            session_ref = (_route_session(run_context, "crawl:source", req.headers, req.base_url)
                           if req.headers else None)
            result = await crawler.crawl(
                req.base_url,
                headers=req.headers or {},
                allowed_hosts=srv.orchestrator.allowed_hosts,
                max_pages=max(1, min(req.max_pages, 200)),
                max_depth=max(0, min(req.max_depth, 4)),
                run_context=run_context, session_ref=session_ref,
            )
        out = result.to_dict()
        await __import__("asyncio").to_thread(
            srv._update_engagement, store.host_of(req.base_url),
            lambda st: st.ingest_endpoints(out.get("endpoints", [])))
        return out

    @router.post("/identities/session-headers")
    async def set_identity_session_headers(req: SessionHeadersRequest, authorization: str | None = Header(default=None)):
        """Supply ANOTHER identity's real session headers for cross-identity
        (Autorize-style) access-control testing. Held IN MEMORY ONLY for this process
        -- never persisted, logged, or cached (see identity_headers.py) -- exactly
        like configuring Autorize's low-privilege cookie. The cross_identity validator
        replays object-scoped GETs as these identities to tell a real IDOR from a
        properly-restricted 200. Requires validators.cross_identity.enabled +
        validators.active_enabled."""
        srv._require_auth(authorization)
        from harness import identity_headers
        identity_headers.set_identity(req.host, req.name, req.headers, req.role)
        return {"ok": True, "host": req.host,
                "identities": [i["name"] for i in identity_headers.identities_for_host(req.host)]}

    @router.post("/crawl-roles", dependencies=_ACTIVE_TRAFFIC)
    async def crawl_roles_endpoint(req: RoleCrawlRequest, authorization: str | None = Header(default=None)):
        """Role-aware crawl: discover the surface per role, probe every endpoint with
        every role, and return the access matrix plus derived auth-bypass and IDOR/
        BOLA candidates (role linked to URL). Also runs the same-object cross-identity
        comparison (idor_findings) and, unless disabled, auto-registers a named
        identity per role so the reachable identities feed the cross-identity-compare
        flow. Scope-gated to server.allowed_hosts, throttled, bounded by
        max_endpoints. Credentials arrive per call and are never persisted."""
        srv._require_auth(authorization)
        srv._require_target_fetch(req.base_url, bulk=True)
        srv._require_active_scope(req.base_url, action="crawl")
        from harness import role_crawl
        roles = _role_sessions(req.roles)
        if not roles:
            raise HTTPException(status_code=400, detail="roles must be non-empty")
        async with _crawl_route_run() as run_context:
            result = await role_crawl.crawl_roles(
                req.base_url, roles,
                allowed_hosts=srv.orchestrator.allowed_hosts,
                max_pages=max(1, min(req.max_pages, 200)),
                max_endpoints=max(1, min(req.max_endpoints, 500)),
                id_fill=req.id_fill or "1",
                active_discovery=bool(req.active_discovery),
                discovery_max_probes=max(1, min(req.discovery_max_probes, 20000)),
                run_context=run_context,
                session_refs=_role_route_sessions(run_context, "crawl-roles", roles, req.base_url),
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
                out["identity_registration_error"] = security.safe_error_summary(e)

        def _ingest(st):
            st.ingest_role_crawl(out)
            for r in roles:
                st.ingest_identity(f"rolecrawl:{r.name or r.role}", r.role, source="seed")
            for ri in registered:
                st.ingest_identity(ri["name"], ri["role"], source="seed")
        await __import__("asyncio").to_thread(srv._update_engagement, store.host_of(req.base_url), _ingest)
        return out

    @router.post("/probe-missing-auth", dependencies=_ACTIVE_TRAFFIC)
    async def probe_missing_auth_endpoint(req: MissingAuthRequest, authorization: str | None = Header(default=None)):
        """Fire discovered endpoints with authentication stripped and flag the ones
        that still return data -- the "generateReport unauthenticated" class an
        always-authenticated capture never reveals (missing_auth_probe.py).

        Scope-gated to server.allowed_hosts, paced by the global request throttle,
        and read-only unless include_mutating AND the safety gate allow it. Provide
        call_shapes (method+path) mined from the app's JS, bare `paths` (probed as
        GET), or set `discover` to crawl base_url first. Returns per-endpoint
        outcomes plus the missing_authentication findings."""
        srv._require_auth(authorization)
        srv._require_target_fetch(req.base_url, bulk=bool(req.discover))
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
                    allowed_hosts=srv.orchestrator.allowed_hosts,
                    gate_config=srv._live_validators_gate_config(),
                    max_requests=max(1, min(req.max_pages, 200))) as crawl_context:
                session_ref = None
                if req.headers:
                    session_ref = "probe-missing-auth:source"
                    crawl_context.sessions.register(
                        session_ref, session_ref, dict(req.headers),
                        allowed_origins=[ScopePolicy.origin_of(req.base_url)])
                crawl = await crawler.crawl(
                    req.base_url, headers=req.headers or {}, allowed_hosts=srv.orchestrator.allowed_hosts,
                    max_pages=max(1, min(req.max_pages, 200)), run_context=crawl_context,
                    session_ref=session_ref)
            shapes.extend(CallShape("GET", p) for p in sorted(crawl.endpoints))

        if not shapes:
            raise HTTPException(status_code=400, detail="no call_shapes, paths, or discoverable endpoints to probe")

        from harness.run_context import RunContext
        # One anonymous send per shape, then at most one more: the garbage token
        # (after a denial) or the authenticated baseline (after an anonymous payload).
        sends_per_shape = 2 if (req.send_garbage_token or req.expected_protected) else 1
        async with RunContext.create(
                allowed_hosts=srv.orchestrator.allowed_hosts,
                gate_config=srv._live_validators_gate_config(),
                max_requests=max(1, len(shapes) * sends_per_shape)) as probe_context:
            # RV-G R15: a missing-auth finding is confirmed only for an endpoint the
            # caller declared protected AND whose payload the caller's own
            # credentials also fetch; otherwise it stays an unconfirmed candidate.
            outcomes = await missing_auth_probe.probe_call_shapes(
                req.base_url, shapes,
                allowed_hosts=srv.orchestrator.allowed_hosts,
                baseline_headers=req.headers or None,
                send_garbage_token=req.send_garbage_token,
                include_mutating=req.include_mutating,
                expected_protected=req.expected_protected,
                protected_baseline=True,
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

    @router.post("/active-probe", dependencies=_ACTIVE_TRAFFIC)
    async def active_probe(req: ActiveProbeRequest, authorization: str | None = Header(default=None)):
        """Run the iterative (active) agent against one captured exchange, then
        integrate its result through F2 (pause->validate->remember; pivot/combine).

        Off unless iterative_agent.enabled is set in config.yaml -- this drives real
        adaptive traffic at the target. Every step is scope-gated to allowed_hosts,
        throttled, and (for mutating methods) safety-gated. Returns the agent's
        transcript + findings and the integration outcome (held findings, validation
        plans, detected chains, and forward pivot hints)."""
        srv._require_auth(authorization)
        srv._require_target_fetch(req.exchange.url, bulk=True)
        if not srv.orchestrator.iterative_agent_enabled:
            raise HTTPException(status_code=403, detail="iterative_agent is disabled in config.yaml")
        # ARC-2: the model chooses these requests, so they need an explicit scope that
        # covers the exchange; an empty server.allowed_hosts refuses instead of
        # admitting whatever host the submitted exchange names.
        srv._require_active_scope(req.exchange.url, action="active probe")
        try:
            return await srv.orchestrator.run_active_probe(
                req.exchange, req.hypothesis, req.specialty,
                model=req.model or "", step_budget=req.step_budget or None,
            )
        except ProbeScopeRefused as e:
            raise HTTPException(status_code=403, detail=str(e)) from None
        except Exception as e:
            log.error("Unhandled error during active probe: %s", security.safe_error_summary(e))
            return JSONResponse(status_code=500, content={"error": security.safe_error_summary(e)})

    @router.post("/engagement/{host}/run")
    async def engagement_run(host: str, req: RunEngagementRequest, authorization: str | None = Header(default=None)):
        """The engagement driver: read the fused worklist back out and produce a
        ranked, budget-allocated 'test next' plan (F5 governor). Plan-only by default
        -- it does NOT test anything. With execute=true AND engagement.driver_execute
        enabled, it fetches + analyzes the funded GET targets, bounded by the
        allocation, and returns the updated worklist."""
        srv._require_auth(authorization)
        max_targets = max(1, min(req.max_targets, 50))
        if req.execute:
            # ARC-1: executing fetches and analyzes target pages (ACTIVE_TRAFFIC_WHEN);
            # a plan-only call sends nothing and stays available while passive.
            # The operating-profile denial (e.g. passive-only "captured-only") is
            # checked first: it names the real reason, and arming active mode
            # cannot lift it.
            srv._require_target_fetch(req.base_url or '', bulk=True)
            server_admission._admit_active_traffic(srv.orchestrator)
            if not req.base_url:
                raise HTTPException(status_code=400, detail="execute requires base_url")
            return await srv.orchestrator.run_engagement(
                host, req.base_url, max_targets=max_targets,
                max_rounds=max(1, min(req.max_rounds, 10)), execute=True)
        return await srv.orchestrator.plan_engagement(host, max_targets=max_targets, base_url=req.base_url)

    @router.post("/engagement/{host}/advance", dependencies=_ACTIVE_TRAFFIC)
    async def engagement_advance(host: str, req: AdvanceRequest, authorization: str | None = Header(default=None)):
        """Advance the engagement: re-crawl `base_url` as the given roles and fold the
        result (surface + access matrix + IDOR findings) back into the fused
        worklist. This is the closed loop the tester drives -- run it as a newly
        obtained identity and the new surface it can reach re-enters the ranking."""
        srv._require_auth(authorization)
        srv._require_target_fetch(req.base_url, bulk=True)
        # RV-G R03: a re-crawl is active traffic, so it obeys the same scope and
        # active-mode admission as /crawl-roles, before any discovery or probing.
        srv._require_active_scope(req.base_url, action="crawl")
        from harness import role_crawl, engagement
        roles = _role_sessions(req.roles)
        if not roles:
            raise HTTPException(status_code=400, detail="roles must be non-empty")
        async with _crawl_route_run() as run_context:
            result = await role_crawl.crawl_roles(
                req.base_url, roles, allowed_hosts=srv.orchestrator.allowed_hosts,
                max_pages=max(1, min(req.max_pages, 200)), max_endpoints=max(1, min(req.max_endpoints, 500)),
                run_context=run_context,
                session_refs=_role_route_sessions(run_context, "advance", roles, req.base_url))
        out = result.to_dict()

        await __import__("asyncio").to_thread(
            srv._update_engagement, host, lambda st: st.ingest_role_crawl(out))

        snap = await __import__("asyncio").to_thread(store.load_engagement, host)
        st = engagement.EngagementState.from_dict(snap or {"host": host})
        return {"host": host, "crawl": out, "worklist": st.worklist(),
                "ready_tasks": st.pending(), "blocked_tasks": st.blocked(), "summary": st.summary()}

    return router
