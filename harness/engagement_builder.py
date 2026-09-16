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


async def build_engagement(
    base_url: str,
    roles: list[RoleSession],
    *,
    allowed_hosts: list[str] | None = None,
    host: str | None = None,
    max_endpoints: int = 150,
    discovery_max_probes: int = 6000,
    id_fill: str = "1",
    run_context=None,
) -> tuple[engagement.EngagementState, role_crawl.RoleCrawlResult]:
    """Discover + build the access matrix + fuse into an EngagementState.

    Returns (state, raw_role_crawl_result). `state.worklist()` is the prioritised
    ranking; the raw result carries the endpoints, candidates and IDOR findings."""
    session_refs = None
    if run_context is not None:
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
            session_refs.append(session_id)
    result = await role_crawl.crawl_roles(
        base_url, roles,
        allowed_hosts=allowed_hosts,
        max_endpoints=max_endpoints,
        id_fill=id_fill,
        active_discovery=True,
        discovery_max_probes=discovery_max_probes,
        run_context=run_context,
        session_refs=session_refs,
    )

    state = engagement.EngagementState(host=host or _host_of(base_url))
    state.ingest_role_crawl(result.to_dict())
    for r in roles:
        state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")

    log.info("build_engagement: %s -- %d endpoints, %d idor candidates, %d idor findings",
             base_url, len(result.endpoints), len(result.idor_candidates), len(result.idor_findings))
    return state, result


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

    sweep_roles = role_crawl._distinct_discovery_roles(roles) if roles else []
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
            log.debug("feature_crawl_captures: role %r failed: %s", r.role, e)
            continue
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
