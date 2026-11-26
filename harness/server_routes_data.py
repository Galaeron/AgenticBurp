"""Data-maintenance routes: the opt-in wipe and close (server.enable_wipe_endpoint, off
by default), identities and sessions, finding suppressions, retained observations and
issue merges. Nothing here sends target traffic.

ARC-9: split out of harness/server.py. build_router(srv, router) adds these
routes to `router` (harness.server passes app.router) and reads per-process
state and the helpers tests patch through server module `srv`
(srv.orchestrator, srv._require_auth, ...) at request time, so each server
module gets its own state."""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel as _BaseModel, ConfigDict, Field

import harness.identity as identity_mod
from harness import security, store
from harness.models import (IdentityCreateRequest, ObservationAttributionCorrection, SessionCreateRequest, SuppressFindingRequest)

log = logging.getLogger("harness.server")


class CloseEngagementRequest(_BaseModel):
    model_config = ConfigDict(extra="forbid")
    engagement_id: str = Field(min_length=1, max_length=128)
    # The engagement ID typed again: a destructive close must be confirmed explicitly.
    confirm: str = Field(default="", max_length=128)


class MergeIssuesRequest(_BaseModel):
    source_id: str
    target_id: str


def build_router(srv, router: APIRouter | None = None) -> APIRouter:
    """The data routes, bound to server module `srv`, added to `router`
    (a new APIRouter when none is given)."""
    router = APIRouter() if router is None else router

    @router.delete("/engagement/{host}/evidence")
    async def wipe_engagement_evidence(host: str, authorization: str | None = Header(default=None)):
        """P3-1 (partial): opt-in, auth-gated wipe of everything this store
        persisted for `host`, via the already-landed callable-only
        store.wipe_engagement(host) -- see that function's docstring for the
        table-by-table scope and the blob-sharing guard. Ships OFF
        (server.enable_wipe_endpoint: false); an operator must deliberately
        flip it (git-ignored config.local.yaml overlay) to arm this endpoint.
        No scheduler/retention-apply wiring here -- those are separate
        follow-ons; this is a single explicit, destructive, auth-gated action.

        Auth: gated the same as every other mutating route by
        _csrf_defense_middleware's Control 1 (the _mutation_token() bearer,
        required on every POST/PUT/PATCH/DELETE even from loopback) before this
        handler ever runs, plus _require_auth here. Not scope-gated by
        server.allowed_hosts -- deleting one's own stored data for a host is not
        a probe of that host, so the scope check that governs live target
        traffic does not apply here.
        """
        srv._require_auth(authorization)
        if not srv._WIPE_ENDPOINT_ENABLED:
            raise HTTPException(status_code=403, detail="wipe endpoint disabled (set server.enable_wipe_endpoint)")
        counts = await __import__("asyncio").to_thread(store.wipe_engagement, host)
        # OPS-5: the wipe acts on the store this process uses ('' = legacy single store).
        return {"host": host, "wiped": counts, "engagement_store": store.active_engagement()}

    @router.post("/engagements/close")
    async def close_engagement_store(req: CloseEngagementRequest, authorization: str | None = Header(default=None)):
        """OPS-5: export, then remove, one engagement's data -- its own store
        (engagements/<key>/) and the rows the legacy single store attributes to it.
        Gated like the wipe route: the CSRF middleware's mutation token and
        _require_auth, the same server.enable_wipe_endpoint opt-in (ships false),
        plus `confirm` repeating the engagement ID. The export lands in a new
        directory under engagement_exports/ beside the legacy store, never at a
        request-supplied path. The engagement this process stores into is refused
        (409): restart the server for another engagement (or none) first. The
        offline equivalent is `python -m harness.data_maintenance close-engagement`."""
        srv._require_auth(authorization)
        if not srv._WIPE_ENDPOINT_ENABLED:
            raise HTTPException(status_code=403, detail="close endpoint disabled (set server.enable_wipe_endpoint)")
        if req.confirm != req.engagement_id:
            raise HTTPException(status_code=422, detail="closing removes the engagement's stored data after export; "
                                                        "resend with confirm set to the engagement_id")
        try:
            return await asyncio.to_thread(store.close_engagement, req.engagement_id)
        except store.EngagementStoreActive as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except LookupError:
            raise HTTPException(status_code=404, detail="nothing is stored for this engagement") from None
        except ValueError:
            raise HTTPException(status_code=422, detail="engagement ID or store layout refused; nothing was removed") from None
        except (OSError, __import__("sqlite3").Error) as exc:
            log.warning("close engagement failed: %s", type(exc).__name__)
            raise HTTPException(status_code=500, detail="close failed before removal; nothing was removed") from None

    @router.post("/identities")
    async def create_identity(req: IdentityCreateRequest, authorization: str | None = Header(default=None)):
        """Registers a named test identity (see identity.py) -- replaces
        picking a captured exchange out of an unlabeled list at
        cross-identity-compare time with a persistent, named identity."""
        srv._require_auth(authorization)
        try:
            role = identity_mod.IdentityRole(req.role)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"unknown role {req.role!r}")
        ident = identity_mod.Identity(name=req.name, role=role, notes=req.notes)
        await __import__("asyncio").to_thread(store.save_identity, ident)
        return {"id": ident.id, "name": ident.name, "role": ident.role.value, "notes": ident.notes}

    @router.get("/identities")
    async def get_identities(authorization: str | None = Header(default=None)):
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        return await __import__("asyncio").to_thread(store.list_identities)

    @router.post("/sessions")
    async def create_session(req: SessionCreateRequest, authorization: str | None = Header(default=None)):
        """Links an identity to a captured exchange's fingerprint (never the
        credential itself -- see identity.Session's docstring)."""
        srv._require_auth(authorization)
        if not await __import__("asyncio").to_thread(store.get_identity, req.identity_id):
            raise HTTPException(status_code=404, detail="unknown identity_id")
        sess = identity_mod.Session(identity_id=req.identity_id, host=req.host,
                                     exchange_hash=req.exchange_hash, label=req.label)
        await __import__("asyncio").to_thread(store.save_session, sess)
        return {"id": sess.id, "identity_id": sess.identity_id, "host": sess.host,
                "exchange_hash": sess.exchange_hash, "label": sess.label}

    @router.get("/hosts/{host}/sessions")
    async def sessions_for_host(host: str, authorization: str | None = Header(default=None)):
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        return await __import__("asyncio").to_thread(store.sessions_for_host, host)

    @router.post("/findings/suppress")
    async def suppress_finding(req: SuppressFindingRequest, authorization: str | None = Header(default=None)):
        """
        Marks a finding fingerprint as suppressed so it doesn't resurface on
        a future scan of the same host -- see store.suppress_finding's
        docstring for the workflow gap this closes and its known limitation
        (fingerprint includes summary text, so a re-run with a differently-
        worded summary for the same underlying issue won't match).
        """
        srv._require_auth(authorization)
        await __import__("asyncio").to_thread(store.suppress_finding, req.fingerprint, req.reason)
        return {"fingerprint": req.fingerprint, "reason": req.reason, "suppressed": True}

    @router.delete("/findings/suppress/{fingerprint}")
    async def unsuppress_finding(fingerprint: str, authorization: str | None = Header(default=None)):
        """Reverses a suppression. 404s if the fingerprint wasn't suppressed,
        so a caller can tell "nothing happened" from "it worked"."""
        srv._require_auth(authorization)
        removed = await __import__("asyncio").to_thread(store.unsuppress_finding, fingerprint)
        if not removed:
            raise HTTPException(status_code=404, detail="fingerprint was not suppressed")
        return {"fingerprint": fingerprint, "suppressed": False}

    @router.get("/findings/suppressions")
    async def list_suppressions(authorization: str | None = Header(default=None)):
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        return await __import__("asyncio").to_thread(store.list_suppressions)

    # I02-C: analyst actions on retained observations (supplied captures that later
    # analyses of the same endpoint are given). Each acts within one pile:
    # engagement_id '' is the site's shared pile. Nothing here sends traffic.
    @router.get("/observations/{observation_id}")
    async def get_observation(observation_id: str, authorization: str | None = Header(default=None),
                              engagement_id: str = Query(default="", max_length=128)):
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        found = await __import__("asyncio").to_thread(store.get_observation, observation_id,
                                                      engagement_id=engagement_id)
        if found is None:
            raise HTTPException(status_code=404, detail="no such observation in this pile")
        return found

    @router.post("/observations/{observation_id}/attribution")
    async def correct_observation_attribution(observation_id: str, req: ObservationAttributionCorrection,
                                              authorization: str | None = Header(default=None)):
        """Append a complete new attribution revision. `expected_revision` must be
        the current one (409 otherwise); later analyses use the new revision."""
        srv._require_auth(authorization)
        attribution = {name: getattr(req, name) for name in ("principal_ref", "role", "tenant", "session_ref")}
        try:
            return await __import__("asyncio").to_thread(
                store.correct_observation_attribution, observation_id, engagement_id=req.engagement_id,
                expected_revision=req.expected_revision, attribution=attribution, reason=req.reason)
        except store.ObservationRevisionConflict as e:
            raise HTTPException(status_code=409, detail=str(e))
        except store.ObservationDeleted as e:
            raise HTTPException(status_code=410, detail=str(e))
        except LookupError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.delete("/observations/{observation_id}")
    async def delete_observation(observation_id: str, authorization: str | None = Header(default=None),
                                 engagement_id: str = Query(default="", max_length=128)):
        """Delete one observation: a tombstone stays, its content and evidence go,
        and later analyses see it as unavailable rather than as evidence."""
        srv._require_auth(authorization)
        try:
            return await __import__("asyncio").to_thread(store.delete_observation, observation_id,
                                                         engagement_id=engagement_id)
        except LookupError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @router.post("/issues/{host}/merge")
    async def merge_issues(host: str, req: MergeIssuesRequest,
                           authorization: str | None = Header(default=None)):
        """Operator override (P1.8): declare that issue `source_id` is actually
        the same underlying bug as `target_id` on `host`, folding them together
        in every subsequent export_issues_for_host() call. Reversible via DELETE
        /issues/{host}/merge/{source_id} -- see issues.apply_merge_overrides
        and store.record_issue_merge for why this never mutates the underlying
        findings or the automatic grouping."""
        srv._require_auth(authorization)
        try:
            await __import__("asyncio").to_thread(
                store.record_issue_merge, host, req.source_id, req.target_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=security.safe_error_summary(e))
        return {"host": host, "source_id": req.source_id, "target_id": req.target_id, "merged": True}

    @router.delete("/issues/{host}/merge/{source_id}")
    async def unmerge_issue(host: str, source_id: str, authorization: str | None = Header(default=None)):
        """Reverses a prior merge. 404s if no such override existed, so a caller
        can tell "nothing happened" from "it worked"."""
        srv._require_auth(authorization)
        removed = await __import__("asyncio").to_thread(store.remove_issue_merge, host, source_id)
        if not removed:
            raise HTTPException(status_code=404, detail="no such merge override")
        return {"host": host, "source_id": source_id, "merged": False}

    @router.get("/issues/{host}/merges")
    async def list_issue_merges(host: str, authorization: str | None = Header(default=None)):
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        return await __import__("asyncio").to_thread(store.all_issue_merges, host)

    return router
