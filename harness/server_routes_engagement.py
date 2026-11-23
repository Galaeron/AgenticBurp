"""Engagement state routes: the engagement view, the I16 declarations (protected paths,
owners) and the access-matrix questions.

ARC-9: split out of harness/server.py. build_router(srv, router) adds these
routes to `router` (harness.server passes app.router) and reads per-process
state and the helpers tests patch through server module `srv`
(srv.orchestrator, srv._require_auth, ...) at request time, so each server
module gets its own state."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel as _BaseModel, Field

from harness import store


class DeclarationsRequest(_BaseModel):
    base_url: str
    protected_paths: list[str] = Field(default_factory=list, max_length=1000)
    owners: list[dict] = Field(default_factory=list, max_length=1000)


def _declarations_target(host: str, base_url: str) -> tuple[str, int]:
    """(host, effective port) the saved declarations are keyed on, from base_url,
    after checking the route host names the same host."""
    from urllib.parse import urlsplit
    from harness.protected_routes import _target_of
    target = _target_of(base_url or "")
    if target is None:
        raise HTTPException(status_code=400, detail="base_url has no resolvable host and port")
    route = urlsplit(host if "//" in host else f"//{host}").hostname or host.split(":", 1)[0]
    if route.lower() != target[0]:
        raise HTTPException(status_code=400,
                            detail=f"route host {host!r} does not match base_url host {target[0]!r}")
    return target


def _validated_declarations(protected_paths: list, owners: list) -> None:
    """422 unless every entry parses under the RV-S / RV-T grammars, so only route
    patterns and identity labels are ever saved."""
    from harness.protected_routes import parse_pattern
    from harness.ownership_declarations import _entry
    problems = []
    for index, entry in enumerate(protected_paths):
        try:
            parse_pattern(entry)
        except ValueError as exc:
            problems.append(f"protected_paths[{index}]: {exc}")
    for index, entry in enumerate(owners):
        try:
            _entry(entry)
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            problems.append(f"owners[{index}]: {exc}")
    if problems:
        raise HTTPException(status_code=422, detail=problems[:20])


# --- HU-1: the operator access matrix (logic in harness/access_matrix.py) ---------
class AccessMatrixAnswersRequest(_BaseModel):
    operator: str = Field(min_length=1, max_length=64)
    answers: list[dict] = Field(default_factory=list, max_length=500)
    engagement_id: str = Field(default="", max_length=128)


def build_router(srv, router: APIRouter | None = None) -> APIRouter:
    """The engagement routes, bound to server module `srv`, added to `router`
    (a new APIRouter when none is given)."""
    router = APIRouter() if router is None else router

    @router.get("/engagement/{host}")
    async def engagement_view(host: str, limit: int = 25, authorization: str | None = Header(default=None),
                              engagement_id: str = Query(default="", max_length=128)):
        """The fused, per-host worklist (engagement.py): every known endpoint ranked
        by a transparent combination of PathScorer tier, LLM rating, the role-access
        matrix, and findings so far -- the one picture the discrete capabilities feed.
        Empty until a crawl / analysis has populated it."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import engagement
        snap = await __import__("asyncio").to_thread(store.load_engagement, host, engagement_id=engagement_id)
        partition_meta = {"engagement_id": engagement_id,
                          "state_partition": "explicit-engagement" if engagement_id else "shared-site-history"}
        if not snap:
            return {**partition_meta, "host": host, "endpoint_count": 0, "worklist": [], "summary": {"host": host, "endpoint_count": 0}}
        st = engagement.EngagementState.from_dict(snap)
        return {**partition_meta, "host": host, "worklist": st.worklist(limit=max(1, min(limit, 200))),
                "ready_tasks": st.pending(), "blocked_tasks": st.blocked(), "summary": st.summary()}

    @router.put("/engagement/{host}/declarations")
    async def engagement_declarations_save(host: str, req: DeclarationsRequest,
                                           authorization: str | None = Header(default=None)):
        """Explicitly save (replace) the operator's protected_paths and owners for one
        target (I16). Saving applies them to nothing: an investigation uses them only
        with use_saved_declarations. Empty lists for both clear the saved entry."""
        srv._require_auth(authorization)
        target = _declarations_target(host, req.base_url)
        from harness.scope_lock import host_in_scope
        allowed_hosts = {(h or "").lower() for h in (srv.orchestrator.allowed_hosts or [])}
        if not host_in_scope(req.base_url, allowed_hosts, active_mode=True):
            raise HTTPException(status_code=403,
                                detail=f"target {req.base_url!r} is not in pre-authorized scope")
        _validated_declarations(req.protected_paths, req.owners)
        await asyncio.to_thread(store.save_engagement_declarations, *target,
                                protected_paths=req.protected_paths, owners=req.owners)
        return {"host": target[0], "port": target[1], "saved": bool(req.protected_paths or req.owners),
                "protected_paths": len(req.protected_paths), "owners": len(req.owners)}

    @router.get("/engagement/{host}/declarations")
    async def engagement_declarations_view(host: str, base_url: str = Query(max_length=2048),
                                           authorization: str | None = Header(default=None)):
        """The declarations saved for this target, or empty lists when none are."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        target = _declarations_target(host, base_url)
        saved = await asyncio.to_thread(store.load_engagement_declarations, *target)
        return {"host": target[0], "port": target[1], "saved": saved is not None,
                "protected_paths": (saved or {}).get("protected_paths", []),
                "owners": (saved or {}).get("owners", [])}

    def _access_matrix_max_questions() -> int:
        cfg = (srv.orchestrator.config or {}).get("access_matrix") or {}
        try:
            return max(1, int(cfg.get("max_questions_per_round", 20)))
        except (TypeError, ValueError):
            return 20

    @router.get("/engagement/{host}/access-matrix")
    async def engagement_access_matrix_view(host: str,
                                            engagement_id: str = Query(default="", max_length=128),
                                            authorization: str | None = Header(default=None)):
        """The draft access matrix for this engagement with the saved operator answers
        and this round's ranked questions. Sends nothing; proposals are never truth."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import access_matrix
        return await asyncio.to_thread(access_matrix.build_draft, host.lower(),
                                       engagement_id=engagement_id,
                                       max_questions=_access_matrix_max_questions())

    @router.put("/engagement/{host}/access-matrix")
    async def engagement_access_matrix_answer(host: str, req: AccessMatrixAnswersRequest,
                                              authorization: str | None = Header(default=None)):
        """Save operator answers (allowed / denied / owner_only / admin_only / unknown, or
        null to clear) per cell, with provenance (operator, time, source=operator).
        All-or-nothing: 422 names every invalid entry and saves none."""
        srv._require_auth(authorization)
        from harness import access_matrix
        problems = []
        for index, entry in enumerate(req.answers):
            try:
                access_matrix.clean_answer(entry)
            except ValueError as exc:
                problems.append(f"answers[{index}]: {exc}")
        if problems:
            raise HTTPException(status_code=422, detail=problems[:20])
        saved = await asyncio.to_thread(access_matrix.save_answers, host.lower(), req.answers,
                                        operator=req.operator, engagement_id=req.engagement_id)
        return {"host": host.lower(), "engagement_id": req.engagement_id, "saved": len(saved),
                "answers": await asyncio.to_thread(access_matrix.load_answers, host.lower(),
                                                   engagement_id=req.engagement_id)}

    return router
