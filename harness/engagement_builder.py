"""
Engagement builder -- the harness-owned assembly of the app model.

This is the spine of the graph-driven engagement (Milestone A). It runs the
capabilities in the right order and fuses their output into ONE EngagementState
the harness then prioritises from, instead of firing every agent at every
captured request:

  1. DISCOVER the real surface (api_surface_discovery, via role_crawl's
     active_discovery) -- the full route set, not the fraction JS-mining finds.
  2. Build the per-role ACCESS MATRIX (role_crawl) -- who can reach what, plus
     the deterministic auth-bypass / IDOR candidates that fall out of it.
  3. INGEST both into EngagementState -- surface (endpoint x role x findings) and
     identities -- so a single fused, auditable "test-next" ranking exists.

The result is a prioritised worklist: privileged-looking endpoints reachable by a
low-trust role rank above a bare high-tier path, already-validated endpoints sink.
That worklist is the object the next milestones (iterative per-node investigation,
the task-graph driver) consume -- coverage and prioritisation first, in one place.

Pure orchestration: no new network or LLM logic of its own, only the ordering and
the fusion. Deterministic given the same live responses.
"""
from __future__ import annotations

import logging
from urllib.parse import urlsplit

from harness import engagement
from harness import role_crawl
from harness.role_crawl import RoleSession

log = logging.getLogger("harness.engagement_builder")


def _host_of(base_url: str) -> str:
    return urlsplit(base_url).netloc or base_url


def register_role_sessions(run_context, base_url: str, roles) -> list[str] | None:
    """Register each role's credentials with the run, for `base_url`'s origin only, and
    return their session refs (None without a run). build_engagement does this first,
    and a run that restores its discovery from a journal does it instead."""
    if run_context is None:
        return None
    from harness.run_context import ScopePolicy
    permitted_origin = ScopePolicy.origin_of(base_url)
    session_refs = []
    for index, role in enumerate(roles):
        principal_id = role.principal_id()
        session_id = ("anonymous" if not role.headers and principal_id == "anonymous"
                      else f"principal:{index}:{principal_id}")
        run_context.sessions.register(
            session_id, principal_id, dict(role.headers or {}),
            allowed_origins=[permitted_origin], role=role.role,
            name=role.name or principal_id, principal=role.to_principal())
        if getattr(role, "login", None):
            from harness.session_freshness import login_refresher
            run_context.sessions.set_refresh(
                session_id, login_refresher(run_context, role.login, base_url))
        session_refs.append(session_id)
    return session_refs


async def build_engagement(
    base_url: str,
    roles: list[RoleSession],
    *,
    allowed_hosts: list[str] | None = None,
    host: str | None = None,
    crawl_max_pages: int = 40,
    max_endpoints: int = 150,
    active_discovery: bool = True,
    discovery_max_probes: int = 6000,
    id_fill: str = "1",
    run_context=None,
    seed_exchanges=None,
    driver_capture_config=None,
    per_principal: bool = False,
    extra_views=(),
) -> tuple[engagement.EngagementState, role_crawl.RoleCrawlResult]:
    """Discover + build the access matrix + fuse into an EngagementState.

    Returns (state, raw_role_crawl_result). `state.worklist()` is the prioritised
    ranking; the raw result carries the endpoints, candidates and IDOR findings."""
    session_refs = register_role_sessions(run_context, base_url, roles)
    # Browser/Burp captures are observations, not guessed endpoints. Keep their
    # original method/body/query and identity; never relabel authenticated traffic
    # as anonymous or import another origin's traffic into this engagement.
    from harness.models import HttpExchange
    from harness.run_context import ScopePolicy
    seeds = []
    seed_errors = []
    spa_views: list[dict] = []
    capture_config = driver_capture_config or {}
    supplied = list(seed_exchanges or [])[:200]
    if capture_config.get("enabled", False):
        if run_context is None:
            seed_errors.append("browser capture skipped: owning RunContext required")
        else:
            from harness import driver_capture
            spa = bool(capture_config.get("spa_navigation", False))
            for role in role_crawl.crawl_roles_for(roles, per_principal):
                if run_context.cancel.cancelled or len(supplied) >= 200:
                    break
                try:
                    wait_ms = min(10000, max(0, int(capture_config.get("wait_ms", 1500))))
                    room = min(200 - len(supplied),
                               max(0, int(capture_config.get("max_captured", 50))))
                    if spa:
                        # Follow the app's client-side routes, recording each view's
                        # XHR/fetch calls (spa_navigation; off by default).
                        crawl = await driver_capture.crawl_spa(
                            base_url, headers=role.norm_headers(), scope=run_context.scope,
                            gate=run_context.gate, budget=run_context.budget,
                            cancel=run_context.cancel, wait_ms=wait_ms, max_captured=room,
                            max_views=max(1, int(capture_config.get("max_views", 30))),
                            max_depth=max(0, int(capture_config.get("max_depth", 4))),
                            extra_views=extra_views)
                        supplied.extend(crawl.exchanges[:200 - len(supplied)])
                        spa_views.append({"principal": role.principal_id(),
                                          "views": len(crawl.views),
                                          "exchanges": len(crawl.exchanges),
                                          "stopped_by": crawl.stopped_by})
                        seed_errors.extend("browser spa crawl: " + e for e in crawl.errors)
                        continue
                    observation = await driver_capture.capture_requests(
                        base_url, headers=role.norm_headers(), scope=run_context.scope,
                        gate=run_context.gate, budget=run_context.budget,
                        cancel=run_context.cancel, wait_ms=wait_ms, max_captured=room)
                    supplied.extend(observation.exchanges[:200 - len(supplied)])
                    if observation.load_error:
                        seed_errors.append("browser capture incomplete: " + observation.load_error)
                except Exception as exc:
                    seed_errors.append("browser capture failed: " + type(exc).__name__)
    origin = ScopePolicy.origin_of(base_url)
    scope = ScopePolicy(allowed_hosts=allowed_hosts or [])
    identity_header_names = {"authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token"}
    identity_header_names.update(k.lower() for role in roles for k in (role.headers or {}))
    def credentials(headers):
        return {k.lower(): v for k, v in (headers or {}).items()
                if k.lower() in identity_header_names}
    def cookie_pairs(value):
        pairs = set()
        for part in str(value or "").split(";"):
            name, sep, val = part.strip().partition("=")
            if sep and name.strip():
                pairs.add((name.strip(), val.strip()))
        return pairs
    def owns(role_headers, capture_headers):
        # AR-ID: a browser sends the declared session cookie next to cookies it or
        # the server set, in any order. A role that declares cookies owns a capture
        # carrying all of them; a role that declares none (anonymous, bearer-only)
        # still needs a cookie-free capture, so an undeclared session is never
        # relabelled. Every other identity header must match exactly.
        declared, seen = credentials(role_headers), credentials(capture_headers)
        declared_cookies = cookie_pairs(declared.pop("cookie", ""))
        seen_cookies = cookie_pairs(seen.pop("cookie", ""))
        if declared != seen:
            return False
        return declared_cookies <= seen_cookies if declared_cookies else not seen_cookies
    for item in supplied:
        try:
            ex = item if isinstance(item, HttpExchange) else HttpExchange(**item)
            if ScopePolicy.origin_of(ex.url) != origin or not scope.in_scope(ex.url):
                seed_errors.append("capture ignored: outside engagement origin/scope")
                continue
            owners = [(index, r) for index, r in enumerate(roles)
                      if owns(r.headers, ex.request_headers)]
            if owners:
                # The most specific declaration wins when one role's cookies are a
                # subset of another's (e.g. session-only vs session+csrf).
                most = max(len(cookie_pairs(credentials(r.headers).get("cookie"))) for _, r in owners)
                owners = [(i, r) for i, r in owners
                          if len(cookie_pairs(credentials(r.headers).get("cookie"))) == most]
            if not owners:
                # Header NAMES only: never a cookie or token value.
                names = sorted(credentials(ex.request_headers)) or ["none"]
                seed_errors.append("capture unbound: identity headers (" + ", ".join(names)
                                   + ") match no supplied identity")
                continue
            seeds.append((ex, owners))
        except (TypeError, ValueError):
            seed_errors.append("capture ignored: invalid exchange")
    if len(seed_exchanges or []) > 200:
        seed_errors.append("supplied captures truncated to 200")
    result = await role_crawl.crawl_roles(
        base_url, roles,
        allowed_hosts=allowed_hosts,
        max_pages=crawl_max_pages,
        max_endpoints=max_endpoints,
        id_fill=id_fill,
        active_discovery=active_discovery,
        discovery_max_probes=discovery_max_probes,
        run_context=run_context,
        session_refs=session_refs,
        **({"per_principal": True} if per_principal else {}),
        **({"seed_paths": [urlsplit(ex.url).path for ex, _ in seeds]} if seeds else {}),
    )

    state = engagement.EngagementState(host=host or _host_of(base_url))
    state.ingest_role_crawl(result.to_dict())
    result.errors.extend(seed_errors)
    for ex, owners in seeds:
        result.captured.append(ex.model_dump())
        ep = state._ep(ex.method, engagement.normalize_path(ex.url))
        access = next((entry for entry in result.endpoints
                       if entry.method == ex.method and entry.path == ep.path), None)
        if access is None:
            access = role_crawl.EndpointAccess(method=ex.method, path=ep.path)
            result.endpoints.append(access)
        # The matrix row's template decides object-scoping, as ingest_role_crawl does.
        ep.object_scoped = ep.object_scoped or access.object_scoped
        # WL-02: a supplied capture is ONE principal's observation of this
        # operation. Record it per principal and MERGE it with the crawl's cells
        # (another principal's cell is never overwritten); the role view is
        # re-derived. Its time is the capture's own `captured_at` (unknown stays
        # None, never fabricated).
        reached = ex.response_status is not None and 200 <= ex.response_status < 300
        for index, owner in owners:
            observation = dict(
                role=owner.role, status=ex.response_status, reachable=reached,
                session_ref=session_refs[index] if session_refs is not None else None,
                observed_at=ex.captured_at, source="seed_capture")
            principal_id = role_crawl._matrix_principal_id(owner)
            ep.record_principal_observation(principal_id, **observation)
            access.record(principal_id, **observation)
        state.record_template(ex.url, ex.method, ex)
    # E5b: every probe the crawl sent is a replayable request AS the identity that
    # sent it, so a check on an identity whose body (or 401) was not kept as a
    # capture still has its own request to replay.
    for probe in getattr(result, "identity_probes", None) or []:
        state.record_identity_probe(probe["url"], probe["method"], probe)
    for r in roles:
        state.ingest_identity(f"rolecrawl:{r.name or r.role}", r.role, source="seed")
    if spa_views:
        log.info("build_engagement: spa navigation %s", spa_views)
        result.spa_views = spa_views

    log.info("build_engagement: %s -- %d endpoints, %d idor candidates, %d idor findings",
             base_url, len(result.endpoints), len(result.idor_candidates), len(result.idor_findings))
    return state, result


async def recrawl_state(base_url: str, roles: list[RoleSession], observations, *,
                        run_context=None, host: str | None = None,
                        deadline: float | None = None) -> tuple:
    """engagement.recrawl: turn routes seen after discovery (route_feed) into a
    separate EngagementState to investigate and merge, like a chain round's.

    Each route gets its observed request as its template and, when the request
    carried a session, that principal's observation. A GET route is then re-crawled
    once AS every registered principal (one GET each, through the run's transport,
    so scope, gate, budget and cancellation apply) and each answer is recorded per
    principal -- an authenticated-only route enters the worklist with the
    principal(s) that reached it. Returns (state, captured exchange dicts)."""
    import time
    from harness.models import HttpExchange
    from harness.run_context import TypedRequest
    state = engagement.EngagementState(host=host or _host_of(base_url))
    captured: list[dict] = []
    principals = role_crawl.crawl_roles_for(roles, per_principal=True)
    for obs in observations:
        ep = state._ep(obs.method, obs.path)
        try:
            ex = HttpExchange(**obs.exchange)
            state.record_template(ex.url, ex.method, ex)
            captured.append(ex.model_dump())
        except (TypeError, ValueError):
            pass
        if obs.principal_id and obs.status is not None:
            ep.record_principal_observation(
                obs.principal_id, role=obs.role or "user", status=obs.status,
                reachable=200 <= obs.status < 300, session_ref=obs.session_ref,
                observed_at=time.time(), source="route_feed")
        if obs.method != "GET" or run_context is None:
            continue
        for role in principals:
            if run_context.cancel.cancelled or (deadline is not None and time.monotonic() >= deadline):
                break
            session_ref, extra = run_context.sessions.bind_headers(role.norm_headers())
            if role.norm_headers() and session_ref is None:
                continue          # credentials with no registered session: never sent
            out = await run_context.target_transport().execute(
                TypedRequest("GET", obs.url, headers=extra), capability="recrawl",
                session_ref=session_ref)
            if out.status is None:
                continue
            ep.record_principal_observation(
                role_crawl._matrix_principal_id(role), role=role.role, status=out.status,
                reachable=200 <= out.status < 300, session_ref=session_ref,
                observed_at=time.time(), source="recrawl")
    log.info("recrawl_state: %s -- %d new route(s) re-crawled as %d principal(s)",
             base_url, len(observations), len(principals))
    return state, captured


async def feature_crawl_captures(
    base_url: str,
    roles: list[RoleSession],
    *,
    fetch_fn=None,
    allowed_hosts: list[str] | None = None,
    submit_forms: bool = True,
    max_steps: int = 40,
    max_depth: int = 3,
    max_captured: int = 200,
    seed_paths: list[str] | None = None,
    run_context=None,
    errors=None,
    per_principal: bool = False,
) -> list:
    """Run the stateful feature-workflow crawl (feature_workflow.crawl_features) as
    each DISTINCT-feature role and union the captured exchanges.

    This reaches the surface route-guessing can't: a workflow's own requests,
    carrying the authenticated session, which the confirmation legs then consume.
    Deduped across roles by (method, url, request body, credential-bearing headers,
    response body): a public page returning identical content to several roles
    with the same session context collapses to one review candidate, but a
    response that DIFFERS per identity, or a request carrying a DISTINCT session
    (e.g. a pickle cookie only one role holds -- V26), is always kept. `fetch_fn`
    defaults to the scope-gated, throttled production client (mutating submits are
    gated by allow_mutating_replay inside it).

    `seed_paths` cross-seeds the crawl with routes discovered by API surface
    discovery, so the feature crawl starts from EVERY known page (not just /)
    and reaches workflow surfaces that live behind discovered routes.

    Returns a list of `HttpExchange` (model objects, ready for
    review_captured_exchanges)."""
    import hashlib
    from harness import feature_workflow
    from urllib.parse import urlsplit

    def _h(*parts: str) -> str:
        return hashlib.sha1("\x00".join(parts).encode("utf-8", "ignore")).hexdigest()[:12]

    sweep_roles = role_crawl.crawl_roles_for(roles, per_principal) if roles else []
    seen: set[tuple] = set()
    out: list = []
    for r in sweep_roles:
        try:
            if fetch_fn is not None:
                fx = fetch_fn
            elif run_context is not None:
                session_ref, _ = run_context.sessions.bind_headers(r.norm_headers())
                fx = feature_workflow.run_context_fetch_fn(run_context, session_ref)
            else:
                fx = feature_workflow.default_fetch_fn(allowed_hosts)
            res = await feature_workflow.crawl_features(
                base_url, r.role, r.norm_headers(), fetch_fn=fx,
                allowed_hosts=allowed_hosts, submit_forms=submit_forms,
                seed_paths=seed_paths,
                max_steps=max_steps, max_depth=max_depth, max_captured=max_captured)
        except Exception as e:  # a role's feature crawl must not sink the build
            if errors is not None:
                errors.append({"phase": "feature_crawl", "error": f"{r.role}: {type(e).__name__}"})
            log.debug("feature_crawl_captures: role %r failed: %s", r.role, e)
            continue
        if errors is not None:
            errors.extend({"phase": "feature_crawl", "error": e} for e in res.errors)
        for ex in res.captured:
            sp = urlsplit(ex.url)
            hdrs = ex.request_headers or {}
            cred = " ".join(v for k, v in hdrs.items() if k.lower() in ("cookie", "authorization"))
            key = (ex.method, sp.path, sp.query,
                   _h(ex.request_body or ""), _h(cred), _h((ex.response_body or "")[:4000]))
            if key in seen or len(out) >= max_captured:
                continue
            seen.add(key)
            out.append(ex)
    log.info("feature_crawl_captures: %s -- %d unique exchange(s) across %d role sweep(s), "
             "%d seed path(s)",
             base_url, len(out), len(sweep_roles), len(seed_paths or []))
    return out


async def execute_declared_workflows(workflows, run_context) -> list:
    """Production adapter for T07 declarations used by investigate_engagement.

    Accepts config-shaped dictionaries or already-validated Workflow records and
    executes each through the invocation's existing RunContext.
    """
    from harness import workflow_engine
    results = []
    for declaration in workflows or []:
        workflow = (declaration if isinstance(declaration, workflow_engine.Workflow)
                    else workflow_engine.workflow_from_dict(declaration))
        results.append(await workflow_engine.execute_workflow(workflow, run_context))
    return results
