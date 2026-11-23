"""Burp capture ingest and analysis routes: /analyze, /estimate, /prioritize (site-map
prioritisation), confidential-data scan, Burp-plane test plans and validation results,
agent retries, plan allocation, knowledge notes and the tool catalog. None is an ARC-1
active-traffic route; /analyze owns a run that stays passive (PASSIVE_RUN_ROUTES).

ARC-9: split out of harness/server.py. build_router(srv, router) adds these
routes to `router` (harness.server passes app.router) and reads per-process
state and the helpers tests patch through server module `srv`
(srv.orchestrator, srv._require_auth, ...) at request time, so each server
module gets its own state."""
from __future__ import annotations

import asyncio
import logging
import uuid as _uuid

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel as _BaseModel

from harness import active_verification, security, store
from harness.models import (AnalysisRequest, AnalysisResponse, EstimateRequest, HttpExchange, PlanDispatchRequest, PlaneValidationSubmission, PrioritizeRequest, PrioritizeResponse, PrioritizeResultItem)
from harness.ollama_client import OllamaCloudModelRefusedError

log = logging.getLogger("harness.server")


async def _plane_ledger(event_type, plan_id: str, summary: str, data: dict) -> None:
    """One evidence-ledger event for the Burp plane's dispatch protocol, keyed
    "plan:<plan_id>" (wiped with the plan's host). Best effort, like emit()."""
    from harness import evidence_ledger
    await asyncio.to_thread(evidence_ledger.emit, event_type, f"plan:{plan_id}", summary, data=data)


class RetryAgentsRequest(_BaseModel):
    exchange: HttpExchange
    agent_class: str
    # Per-request policy overrides (any omitted -> the configured retry_budget
    # default). granted_tokens is an allocator-assigned sub-cap for this vuln.
    policy_overrides: dict = {}
    granted_tokens: int | None = None


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


class KnowledgeNoteRequest(_BaseModel):
    note: str
    tags: list[str] = []


class ToolRecommendRequest(_BaseModel):
    # Either a single class+url, or a batch of findings.
    vulnerability_class: str = ""
    url: str = ""
    situations: list[str] = []
    findings: list[dict] = []   # [{vulnerability_class, url|source_exchange_url}]


def build_router(srv, router: APIRouter | None = None) -> APIRouter:
    """The ingest routes, bound to server module `srv`, added to `router`
    (a new APIRouter when none is given)."""
    router = APIRouter() if router is None else router

    @router.get("/test-plans/{plan_id}")
    async def test_plan(plan_id: str, authorization: str | None = Header(default=None)):
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        plan = await __import__("asyncio").to_thread(store.get_test_plan, plan_id)
        if not plan:
            raise HTTPException(status_code=404, detail="unknown test plan")
        return plan

    def _plane_policy() -> tuple[dict, int | None]:
        """The live policy the Burp plane executes a dispatched plan under: the
        same two flags the Python SafetyGate reads for a run started now (live
        active toggle over config, parsed strictly), and the run request ceiling
        (runs.max_requests; None = no ceiling, as for RunContext)."""
        from harness.config_schema import parse_validators_flags
        flags = parse_validators_flags(srv._live_validators_gate_config())
        runs = srv.orchestrator.config.get("runs", {})
        runs = {} if runs is None else runs
        budget = runs.get("max_requests") if isinstance(runs, dict) else 0
        if budget is not None and (isinstance(budget, bool) or not isinstance(budget, int) or budget < 0):
            budget = 0  # a malformed ceiling refuses every send rather than lifting the limit
        return ({"active_enabled": bool(flags["active_enabled"]),
                 "allow_mutating_replay": bool(flags["allow_mutating_replay"])}, budget)

    @router.post("/test-plans/{plan_id}/dispatch")
    async def dispatch_test_plan(plan_id: str, req: PlanDispatchRequest,
                                 authorization: str | None = Header(default=None)):
        """Issue the single-use nonce and live policy for one Burp-plane run (ARC-4).

        The plane reads the policy here rather than trusting its own copy: a
        mutating arm runs only when active_enabled and allow_mutating_replay are
        both on, and the plane stops at request_budget sends."""
        srv._require_auth(authorization)
        from harness.evidence_ledger import EventType
        policy, budget = _plane_policy()
        issued, reason, nonce = await asyncio.to_thread(
            store.issue_plane_dispatch, plan_id, req.source_exchange_hash,
            {**policy, "request_budget": budget})
        if not issued:
            if reason != "unknown_plan":  # an unknown id has no plan to attach an event to
                await _plane_ledger(EventType.AUTHORIZATION_DECISION, plan_id,
                                    f"Burp dispatch refused: {reason}",
                                    {"stage": "dispatch", "decision": "refused", "reason": reason})
            raise srv._plane_refusal(reason)
        await _plane_ledger(EventType.AUTHORIZATION_DECISION, plan_id, "Burp dispatch issued",
                            {"stage": "dispatch", "decision": "dispatched", "policy": policy,
                             "request_budget": budget})
        log.info("Burp dispatch issued plan=%s policy=%s budget=%s", plan_id, policy, budget)
        return {"plan_id": plan_id, "dispatch_nonce": nonce, "policy": policy, "request_budget": budget}

    @router.post("/validation-results")
    async def validation_result(submission: PlaneValidationSubmission, authorization: str | None = Header(default=None)):
        srv._require_auth(authorization)
        # The execution plane (normally Burp) posts only the observed result.
        # It cannot change a plan's target or turn a model assertion into a
        # confirmation; the server accepts the result as evidence for the plan,
        # once, under the nonce POST /test-plans/{plan_id}/dispatch issued (ARC-4).
        from harness.evidence_ledger import EventType
        accepted, reason = await asyncio.to_thread(store.persist_plane_submission, submission)
        if not accepted:
            if reason != "unknown_plan":
                await _plane_ledger(EventType.AUTHORIZATION_DECISION, submission.plan_id,
                                    f"Burp result refused: {reason}",
                                    {"stage": "submission", "decision": "refused", "reason": reason,
                                     "status": submission.status})
            raise srv._plane_refusal(reason)
        await _plane_ledger(EventType.VALIDATION_DECISION, submission.plan_id,
                            f"Burp result accepted: {submission.status}",
                            {"stage": "submission", "decision": "accepted", "status": submission.status,
                             "confirmed": submission.confirmed, "confidence": submission.confidence,
                             "executor": submission.executor})
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
                plan, submission, ollama_client=srv.orchestrator.ollama,
                config=srv.orchestrator.config,
            )
            if step.next_plan is not None:
                await __import__("asyncio").to_thread(store.persist_retry_plan, step.next_plan)
                response["next_plan"] = step.next_plan.model_dump()
            if step.handover_required:
                response["handover_required"] = True
            if step.note:
                response["note"] = step.note
        return response

    @router.post("/analyze", response_model=AnalysisResponse)
    async def analyze(req: AnalysisRequest, authorization: str | None = Header(default=None)):
        srv._require_auth(authorization)
        attribution = req.observation_attribution.model_dump() if req.observation_attribution else None
        try:
            attribution = store.clean_observation_attribution(attribution) if attribution else None
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        try:
            # An omitted name selects the site's shared history. Generating a new
            # partition per request makes prior observations impossible to retrieve.
            partition = {"engagement_id": req.engagement_id or ""}
            if attribution:
                partition["observation_attribution"] = attribution
            return await srv.orchestrator.analyze(req.exchange, req.force_agents, req.attempt_rediscovery,
                                              **partition)
        except OllamaCloudModelRefusedError as e:
            raise srv._cloud_run_refused(e)
        except Exception as e:
            log.error("Unhandled error during analysis: %s", security.safe_error_summary(e))
            return JSONResponse(status_code=500, content={"error": security.safe_error_summary(e)})

    @router.post("/estimate")
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
        srv._require_auth(authorization)
        if not req.urls:
            raise HTTPException(status_code=400, detail="urls must be non-empty")
        return srv.orchestrator.estimate_for_urls(req.urls)

    @router.post("/prioritize", response_model=PrioritizeResponse)
    async def prioritize(req: PrioritizeRequest, authorization: str | None = Header(default=None)):
        """
        Structure-only (method/URL/param names, no bodies) LLM triage pass for
        the Attack Surface Map tab's "Scan Site Map" -- see
        surface_prioritizer.py's own docstring. Batches req.items into chunks
        of surface_prioritization.max_items_per_call, one LLM call per chunk,
        run concurrently -- bounded even for a large site map, not one call
        per endpoint.
        """
        srv._require_auth(authorization)
        cfg = srv.config.get("surface_prioritization", {})
        if not cfg.get("enabled", True):
            raise HTTPException(status_code=403, detail="surface_prioritization is disabled in config.yaml")
        engagement_partition = req.engagement_id or f"prioritize:{_uuid.uuid4().hex}"
        if not req.items:
            return PrioritizeResponse(results=[], engagement_id=engagement_partition)

        chunk_size = max(1, cfg.get("max_items_per_call", 40))
        chunks = [req.items[i:i + chunk_size] for i in range(0, len(req.items), chunk_size)]
        model = cfg.get("model") or srv.orchestrator.coordinator_model
        chunk_results = await asyncio.gather(*[
            srv.surface_prioritizer.prioritize(chunk, srv.orchestrator.ollama, model, cfg.get("temperature", 0.1))
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
            await asyncio.to_thread(srv._update_engagement, host, lambda st, it=items: st.ingest_prioritization(it),
                                    engagement_id=engagement_partition)

        return PrioritizeResponse(results=results, engagement_id=engagement_partition)

    @router.post("/retry-agents")
    async def retry_agents(req: RetryAgentsRequest, authorization: str | None = Header(default=None)):
        """F5 retry loop: re-run one specialist agent on one exchange up to the
        per-vulnerability policy's cap, stopping on an actionable finding. Bounded by
        max_retries / max_agents / max_tokens_per_vuln AND the global effort budget.
        Returns per-round token spend and the best finding."""
        srv._require_auth(authorization)
        try:
            return await srv.orchestrator.run_retry_agents(
                req.exchange, req.agent_class,
                policy_overrides=req.policy_overrides or None,
                granted_tokens=req.granted_tokens,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=security.safe_error_summary(e))
        except Exception as e:
            log.error("Unhandled error during retry-agents: %s", security.safe_error_summary(e))
            return JSONResponse(status_code=500, content={"error": security.safe_error_summary(e)})

    @router.post("/plan-allocation")
    async def plan_allocation_endpoint(req: PlanAllocationRequest, authorization: str | None = Header(default=None)):
        """F5 prioritizer: given competing vulnerabilities and the REMAINING global
        token budget, return which get full retry policy, which are reduced, which
        are deferred, and written guidance. With no budget cap set, everyone gets
        full policy. Calibrated against the real token ledger, like /estimate.

        With use_llm_priority, a large model ranks the candidates for this app
        first (the model ranks, the deterministic governor still allocates and
        enforces)."""
        srv._require_auth(authorization)
        if not req.candidates:
            raise HTTPException(status_code=400, detail="candidates must be non-empty")
        if req.use_llm_priority:
            return await srv.orchestrator.plan_allocation_ranked(
                req.candidates, policy_overrides=req.policy_overrides or None,
                avg_agents_per_round=req.avg_agents_per_round, model=req.ranking_model or "")
        return srv.orchestrator.plan_allocation(
            req.candidates, policy_overrides=req.policy_overrides or None,
            avg_agents_per_round=req.avg_agents_per_round)

    @router.post("/scan/confidential")
    async def scan_confidential(exchange: HttpExchange, authorization: str | None = Header(default=None)):
        """Deterministic confidential-info scan (A4) of one response: secrets, PII,
        and internal-infra leakage, with every value REDACTED. Regex, no model."""
        srv._require_auth(authorization)
        from harness import confidential_info_detector
        matches = confidential_info_detector.scan_response(exchange)
        findings = confidential_info_detector.findings_from_exchange(exchange)
        return {
            "match_count": len(matches),
            "matches": [m.to_dict() for m in matches],
            "findings": [f.model_dump() for f in findings],
        }

    @router.post("/knowledge")
    async def add_knowledge(req: KnowledgeNoteRequest, authorization: str | None = Header(default=None)):
        """Add a retrievable knowledge note (a methodology writeup / house rule) that
        the agents' Memory Retriever surfaces at decision time (knowledge.py). Tags
        help it match; the note text is matched too."""
        srv._require_auth(authorization)
        if not req.note.strip():
            raise HTTPException(status_code=400, detail="note must be non-empty")
        added = await __import__("asyncio").to_thread(store.save_knowledge_note, req.tags, req.note, "manual")
        return {"added": added, "note": req.note.strip(), "tags": req.tags}

    @router.get("/knowledge")
    async def list_knowledge(authorization: str | None = Header(default=None)):
        """All stored knowledge notes (tester-authored + auto-remembered findings)."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        return {"notes": await __import__("asyncio").to_thread(store.list_knowledge_notes)}

    @router.get("/tools")
    async def tools_catalog(category: str = "", vulnerability_class: str = "",
                            authorization: str | None = Header(default=None)):
        """The web-app tool catalog (A3). No filter -> everything grouped by
        category. `vulnerability_class` -> the tools relevant to that class;
        `category` -> just that category's tools."""
        srv._require_auth(authorization)
        from harness import tool_catalog
        if vulnerability_class:
            return {"tools": [t.to_dict() for t in tool_catalog.recommend_for(vulnerability_class, limit=20)]}
        grouped = tool_catalog.by_category()
        if category:
            return {"tools": [t.to_dict() for t in grouped.get(category, [])]}
        return {"by_category": {c: [t.to_dict() for t in ts] for c, ts in grouped.items()}}

    @router.post("/tools/recommend")
    async def tools_recommend(req: ToolRecommendRequest, authorization: str | None = Header(default=None)):
        """Recommend tools for a finding (or batch): which external tool to reach
        for, why, and a command templated to the target -- the 'agent needs a tool,
        return it to the user' path."""
        srv._require_auth(authorization)
        from harness import tool_catalog
        if req.findings:
            recs = tool_catalog.recommendations_for_findings(req.findings)
        elif req.vulnerability_class:
            recs = tool_catalog.recommend_for_finding(
                req.vulnerability_class, req.url, situations=req.situations or None)
        else:
            raise HTTPException(status_code=400, detail="provide vulnerability_class (+url) or findings")
        return {"recommendations": [r.to_dict() for r in recs]}

    return router
