"""orchestrator_detect.py -- DetectMixin mixin for Orchestrator (W-15 decomposition).

Detection half of the captured-exchange pipeline: analyze() and _analyze_inner(). The steps
they compose (agent selection, the adaptive re-spin, known-vulnerability resolution /
rediscovery, identity seeding) live in orchestrator_detect_steps.py (ARC-9).

Split out of orchestrator.py verbatim; `self` state is initialised in
Orchestrator.__init__ and resolved across mixins via the MRO.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time as _time
from urllib.parse import urlparse

from harness import (
    cache,
    chaining,
    coordinator,
    credential_endpoint_detector,
    planner,
    run_inference,
    scope_discovery,
    store,
)
from harness.circuit_breaker import current_ollama_breaker
from harness.models import AgentReport, AnalysisResponse, HttpExchange
from harness.orchestrator_detect_steps import DetectStepsMixin
from harness.orchestrator_helpers import (
    _REFLECTION_AGENT,
    _SHAPE_LEG_AGENT,
    log,
    per_run_gate_config,
    reflected_parameter_findings,
    shape_precondition_findings,
)


class DetectMixin(DetectStepsMixin):
    @run_inference.isolate_inference
    @store.isolate_engagement_context
    async def analyze(
        self,
        exchange: HttpExchange,
        force_agents: list[str] = None,
        attempt_rediscovery: bool = False,
        bypass_cache: bool = False,
        _from_discovery: bool = False,
        run_context=None,
        engagement_id: str = "",
        observation_attribution: dict | None = None,
        retain_observation: bool = True,
    ) -> AnalysisResponse:
        """Public entry point. ARCH-3: owns the run-context LIFECYCLE for a
        STANDALONE analyze (no engagement passed a context in). It creates ONE
        context with an explicit request ceiling and GUARANTEES that context is
        closed on every exit -- success, early return (cache hit / budget block)
        and error -- via the try/finally below, closing the resource leak where
        the owned context was never closed. A context BORROWED from an engagement
        is created and closed by that engagement, never here. The analysis itself
        is unchanged in _analyze_inner."""
        owns_run = run_context is None
        if owns_run:
            # SEC-1: a standalone analysis is a run of its own: a cloud-suffixed
            # model in any slot, without ollama.allow_cloud_models, refuses it
            # before any model call. A borrowed context was checked by its run.
            from harness import model_egress
            model_egress.refuse_cloud_models(
                self.config, model_egress.agent_models_of(getattr(self, "agent_manager", None)))
        # I02-C: only a supplied capture is retained as an observation -- this call
        # owns its run AND no other run encloses it. Engagement, discovery and
        # harness-fetched work passes or runs inside an existing run. Read before
        # this call publishes its own run (I05-A2), which would always be found.
        from harness.run_context import current_run_context
        retain_observation = retain_observation and owns_run and current_run_context() is None
        if owns_run:
            from harness.run_context import RunContext
            # The per-run gate carries the operator's active/mutating POLICY (not
            # just a fresh budget), so a mutating send the validators are allowed
            # to make is not blocked by a default-safe gate (see per_run_gate_config).
            # max_requests is an EXPLICIT per-run ceiling so a standalone active
            # analysis cannot issue unbounded target traffic; generous by default,
            # overridable via config analyze.max_requests.
            _acfg = self.config.get("analyze", {}) if isinstance(self.config, dict) else {}
            _ceiling = (_acfg or {}).get("max_requests")
            _ceiling = 1000 if _ceiling is None else _ceiling
            if isinstance(_ceiling, bool) or not isinstance(_ceiling, int) or _ceiling < 0:
                raise ValueError("analyze.max_requests must be a nonnegative integer")
            run_context = RunContext.create(
                allowed_hosts=self.allowed_hosts, config=self.config,
                gate_config=per_run_gate_config(self.config, getattr(self, "validator_registry", None)),
                max_requests=int(_ceiling))
        try:
            if owns_run:
                # I05 (owner decision 2026-10-19): a standalone analysis publishes its
                # run, so sends without explicit run wiring (GatedAsyncClient
                # validators, get_default_gate() callers) spend this run's ceiling
                # under its scope and TLS policy. The model plane (shared Ollama
                # breaker, fail-open stats) stays shared. aclose() below undoes it.
                run_context.publish()
                self._seed_identities_from_store(run_context, exchange)
                await self._bind_captured_session(run_context, exchange)
            if getattr(run_context, "self_ownership", None) is not None:
                await self._observe_self_ownership(run_context, exchange)
            return await self._analyze_inner(
                exchange, force_agents=force_agents,
                attempt_rediscovery=attempt_rediscovery, bypass_cache=bypass_cache,
                _from_discovery=_from_discovery, run_context=run_context,
                engagement_id=engagement_id, _owns_run=owns_run,
                observation_attribution=observation_attribution,
                retain_observation=retain_observation)
        finally:
            # Close ONLY a context this call created; a borrowed engagement context
            # outlives this call and is closed by its owner.
            if owns_run:
                await run_context.aclose()

    async def _analyze_inner(
        self,
        exchange: HttpExchange,
        force_agents: list[str] = None,
        attempt_rediscovery: bool = False,
        bypass_cache: bool = False,
        _from_discovery: bool = False,
        run_context=None,
        engagement_id: str = "",
        _owns_run: bool = False,
        observation_attribution: dict | None = None,
        retain_observation: bool = True,
    ) -> AnalysisResponse:
        """
        Analyze an HTTP exchange.

        This is the main entry point for analyzing HTTP exchanges.
        It coordinates all aspects of the analysis workflow.

        Args:
            exchange: HTTP exchange to analyze
            force_agents: Optional list of agents to force dispatch
            attempt_rediscovery: Whether to attempt rediscovery of known vulnerabilities
            bypass_cache: Whether to bypass the cache
            _from_discovery: internal only -- True when this call is itself
                one of scope_discovery's own recursive re-analysis calls.
                Guards against infinite recursion: a discovery pass's own
                results must never themselves trigger another discovery
                pass (see the end of this method).

        Returns:
            AnalysisResponse with all findings and metadata
        """
        # ER-2: elapsed wall-clock for the run-summary emitted at teardown.
        # Taken at the very top of the method, before the cache lookup, so it
        # spans the whole call (a cache-hit early-return never reaches
        # teardown and never emits a summary -- see the cache-hit branch below).
        _run_start = _time.monotonic()
        # Hoisted above the hypothesis-cache hit/miss branch below (FR-7): a
        # hypothesis-cache HIT skips the "Live activity feed (V1)" dispatch
        # publish inside that branch, but this name is still read later, in
        # the always-run tail's "analysis_done" publish -- must be bound on
        # both paths, not just the miss path that historically imported it.
        from harness import activity_feed

        # A top-level captured exchange is its own invocation unless its caller
        # explicitly groups it into an engagement run. This must happen before
        # cache lookup: cached responses contain case/proof references and may not
        # cross run namespaces.
        # ER-2: whether THIS call owns (created) the run, vs. joining a
        # run_context an engagement passed in -- decides whether this call is
        # the one that should emit the run-summary (see teardown below).
        # ARCH-3: context ownership (create + explicit request ceiling + close on
        # every exit) is handled by the public `analyze` wrapper above; this inner
        # body only RECORDS whether this call owns the run, to decide run-summary
        # emission at teardown. A borrowed engagement context is passed straight in.
        owns_run = _owns_run
        run_inference.attach(self, run_context)
        # Findings, evidence and ledger events are partitioned by engagement so
        # distinct engagements stay isolated. A STANDALONE analyze (no explicit
        # engagement_id) MUST persist host-only (empty partition): every operator
        # surface -- /report, the findings API, the Burp panel -- reads back
        # through store.all_host_findings(url) with no engagement, so a non-empty
        # partition files findings where no operator read can ever see them.
        # Deriving the partition from the ephemeral run_id did exactly that and
        # made an ordinary scan's findings invisible (regression vs main; caught
        # by test_finding_is_persisted_with_api_shape). An explicit engagement_id
        # still partitions, keeping concurrent engagements isolated.
        engagement_partition = store._engagement_partition(engagement_id or "")
        store.bind_engagement_context(engagement_partition)
        captured_principal = await asyncio.to_thread(store.captured_principal_id, exchange)
        store.bind_captured_principal_context(captured_principal)
        prior_context_snapshot = await asyncio.to_thread(store.prior_findings_summary,
            exchange.url, exclude_url=exchange.url, engagement_id=engagement_partition,
            captured_principal=captured_principal)
        # I02-C: a standalone analysis of a supplied capture is retained as an
        # observation (below, once the host is in scope) and is given the earlier
        # observations of the same endpoint. Engagement- and discovery-driven
        # analyses, and callers analysing traffic the harness fetched itself
        # (retain_observation=False), neither retain nor read them. The rendered
        # selection joins the prior context BEFORE its digest, so the response
        # and hypothesis caches change with every correction, deletion or
        # evidence expiry; an endpoint with no history leaves the prompt as before.
        retains_observation = owns_run and not _from_discovery and retain_observation
        observation_context: dict = {}
        if retains_observation:
            observation_attribution = store.clean_observation_attribution(observation_attribution)
            try:
                selection = await asyncio.to_thread(
                    store.select_observations, exchange.url, engagement_id=engagement_partition,
                    captured_principal=captured_principal, attribution=observation_attribution,
                    exclude_exchange_id=store.exchange_identity(exchange)[0])
            except Exception as exc:
                log.warning("observation retrieval failed (%s); earlier observations unavailable",
                            type(exc).__name__)
                selection = {"status": "unavailable", "selected": [], "unavailable": [],
                             "excluded_counts": {}, "order_basis": "none", "digest": ""}
            observation_block = store.observation_context_block(selection)
            if observation_block:
                prior_context_snapshot = "\n\n".join(
                    part for part in (prior_context_snapshot, observation_block) if part)
            observation_context = {
                "status": selection["status"],
                "write": {"status": "not_attempted"},
                "selected": [{"observation_id": o["observation_id"], "reason": o["reason"],
                              "order_basis": o["order_basis"], "evidence_status": o["evidence_status"]}
                             for o in selection["selected"]],
                "unavailable": selection["unavailable"],
                "excluded_counts": selection["excluded_counts"],
                "order_basis": selection["order_basis"],
                "digest": selection["digest"],
            }
        context_digest = hashlib.sha256(prior_context_snapshot.encode()).hexdigest()
        from harness import config_schema
        analysis_config_identity = config_schema.config_fingerprint(self.config)
        response_cache_namespace = json.dumps([run_context.cache_namespace, engagement_partition,
                                              context_digest, analysis_config_identity])
        hypothesis_namespace = json.dumps([engagement_partition, context_digest])

        # W-11: bind diagnostics recorded during this call to this invocation's
        # run_id. A contextvar, not a shared/global assignment -- concurrent
        # asyncio Tasks (e.g. two overlapping analyze() calls) each hold their
        # own copy, so they cannot contaminate each other's saved explanation.
        from harness import telemetry
        telemetry.bind_current_run(run_context.run_id)

        # Check cache first (unless bypassed or force_agents specified)
        cache_hit = False
        if not bypass_cache and not force_agents:
            current_prompt_versions = {
                agent.name: json.dumps([agent._prompt_version(), agent._guide_version()])
                for agent in self.agent_manager.agents.values()
            }
            cached_result = cache.get_cache().get(
                exchange, self.coordinator_model, current_prompt_versions,
                namespace=response_cache_namespace
            )
            if cached_result is not None and (cached_result.degraded or any(
                    report.raw_error for report in cached_result.agent_reports) or any(
                    outcome.status == "failed" for outcome in cached_result.stage_outcomes)):
                cached_result = None
            if cached_result is not None:
                log.info(
                    "Cache hit for exchange %s",
                    cache.ExchangeCache.compute_exchange_hash(exchange)[:16]
                )
                cache_hit = True
                return AnalysisResponse(
                    **cached_result.model_dump(
                        exclude={
                            "effort_spent_tokens", "effort_usage_complete",
                            "effort_budget_remaining",
                            "effort_budget_warning",
                            "summary",
                            "engagement_id",
                            "captured_principal_id",
                            "observation_context",
                        }
                    ),
                    summary=f"{cached_result.summary} (cached)",
                    engagement_id=engagement_partition,
                    captured_principal_id=captured_principal,
                    # Recomputed above for this call, never replayed from the cache.
                    observation_context=({**observation_context,
                                          "write": {"status": "not_attempted", "reason": "cached response"}}
                                         if observation_context else {}),
                    effort_spent_tokens=self.effort_budget.spent,
                    effort_usage_complete=self.effort_budget.ledger.usage_complete,
                    effort_budget_remaining=self.effort_budget.remaining,
                    effort_budget_warning="",
                )
        
        # Check allowed hosts. Shared with scope_discovery.py's own per-URL
        # re-check (extracted so there is exactly one implementation of
        # this hostname-match logic, not a second copy that could silently
        # drift -- see that module's is_host_allowed docstring for why a
        # SECOND check, beyond this single entry-point one, matters once a
        # feature can construct URLs of its own after this point).
        if not scope_discovery.is_host_allowed(exchange.url, self.allowed_hosts):
            hostname = (urlparse(exchange.url).hostname or "")
            raise ValueError(
                f"target host {hostname!r} is outside configured server.allowed_hosts scope"
            )

        # I02-C: retain the supplied capture whether or not it yields a finding,
        # and before the effort budget can stop the analysis. Out-of-scope hosts
        # never get here. A storage failure is reported, not hidden: the analysis
        # continues and observation_context.write says the capture was not kept.
        if retains_observation:
            try:
                observation_context["write"] = await asyncio.to_thread(
                    store.record_observation, exchange, engagement_id=engagement_partition,
                    captured_principal=captured_principal, attribution=observation_attribution,
                    run_id=run_context.run_id)
            except Exception as exc:
                log.warning("observation not retained (%s)", type(exc).__name__)
                observation_context["write"] = {"status": "error"}

        # Check effort budget
        budget_allowed, budget_reason = self.effort_budget.allow()
        if not budget_allowed:
            log.warning("Effort budget blocked this analysis: %s", budget_reason)
            return AnalysisResponse(
                engagement_id=engagement_partition,
                captured_principal_id=captured_principal,
                observation_context=observation_context,
                coordinator_model=self.coordinator_model,
                dispatched_agents=[],
                agent_reports=[],
                summary=f"Not analyzed: {budget_reason}",
                effort_spent_tokens=self.effort_budget.spent,
                effort_usage_complete=self.effort_budget.ledger.usage_complete,
                effort_budget_remaining=self.effort_budget.remaining,
                effort_budget_warning=budget_reason,
            )

        # FR-7 (F11): run-INDEPENDENT hypothesis cache -- reuses the
        # pre-proof half of a prior analysis (model-inference-derived
        # `reports` plus the tail metadata below) across DIFFERENT runs'
        # cache_namespaces on identical traffic, unlike the run-namespaced
        # full-response cache checked above (which can never cross-run-hit
        # by design -- see that cache-get's own comment). Gated behind
        # runs.hypothesis_cache.enabled (config.yaml default: false), so
        # with the flag off this whole feature is inert and behavior below
        # is unchanged. On a HIT, this reconstitutes dispatch/reason/reports/
        # stage_outcomes/n_reviewed/n_rejected and falls through to the
        # SAME tail every other path uses -- in particular _validate_findings
        # below still runs and mints FRESH proof/case identifiers for THIS
        # run; nothing proof-shaped is ever read from or written to this
        # cache (see cache.HypothesisCacheEntry/get_hypothesis/put_hypothesis).
        _hyp_cfg = (self.config.get("runs", {}) or {}).get("hypothesis_cache", {}) or {}
        _hyp_enabled = bool(_hyp_cfg.get("enabled", False)) and not bypass_cache and not force_agents
        _hyp_hit = None
        if _hyp_enabled:
            from harness import config_schema
            _hyp_prompt_versions = {
                agent.name: json.dumps([agent._prompt_version(), agent._guide_version()])
                for agent in self.agent_manager.agents.values()
            }
            _hyp_config_fingerprint = config_schema.config_fingerprint(self.config)
            # Inference contains prior context owned by this engagement.
            _hyp_config_fingerprint = hashlib.sha256(json.dumps([
                _hyp_config_fingerprint, engagement_partition, context_digest]).encode()).hexdigest()
            _hyp_hit = cache.get_cache().get_hypothesis(
                exchange, self.coordinator_model, _hyp_prompt_versions,
                config_fingerprint=_hyp_config_fingerprint,
                namespace=hypothesis_namespace,
            )
            if _hyp_hit is not None and (any(report.raw_error for report in _hyp_hit.reports) or any(
                    outcome.status == "failed" for outcome in _hyp_hit.stage_outcomes)):
                _hyp_hit = None

        if _hyp_hit is not None:
            dispatch = _hyp_hit.dispatch
            reason = _hyp_hit.reason
            reports = _hyp_hit.reports
            stage_outcomes = _hyp_hit.stage_outcomes
            n_reviewed = _hyp_hit.findings_reviewed
            n_rejected = _hyp_hit.findings_rejected
        else:
            # Choose agents
            if force_agents:
                dispatch = [
                    a for a in force_agents
                    if a in self.agent_manager.agents
                ]
                reason = "explicit override from caller"
            else:
                # All routing (fast-path-primary or cloud-coordinator-primary)
                # is centralized in _choose_agents so the two modes can't drift.
                dispatch, reason = await self._choose_agents(exchange)

                # P2.5: cross-host pattern memory is checked FIRST for its
                # candidates, then ADDITIVELY unioned into whatever the normal
                # routing already chose -- it can only ADD a specialist worth
                # trying on a familiar-shaped endpoint, never subtract or
                # override a routing decision. Default off (pattern_memory.enabled)
                # so no test/deployment writes or reads harness/pattern_memory.jsonl
                # unless explicitly opted in.
                pm_cfg = (self.config.get("pattern_memory", {}) or {})
                if pm_cfg.get("enabled", False):
                    from harness import pattern_memory
                    pm_path = pm_cfg.get("path", pattern_memory.DEFAULT_PATH)
                    suggested_classes = pattern_memory.suggest_classes_for_exchange(exchange, path=pm_path)
                    if suggested_classes:
                        from harness.categories import canonicalize
                        candidate_names = {canonicalize(c) or c for c in suggested_classes}
                        pattern_agents = sorted(
                            a for a in candidate_names
                            if a in self.agent_manager.agents and a not in dispatch)
                        if pattern_agents:
                            dispatch = sorted(set(dispatch) | set(pattern_agents))
                            reason = f"{reason}; pattern_memory added {pattern_agents} for a familiar shape"

            # E1: leave out a hardening agent whose host-wide header facts this run
            # already has (or csp on a non-HTML response). A forced dispatch is exact.
            _agent_skips: list = []
            _hardening_keys: dict = {}
            if not force_agents:
                dispatch, _agent_skips, _hardening_keys = self._apply_hardening_reuse(
                    exchange, dispatch, run_context, engagement_partition)

            # Live activity feed (V1): announce what this analysis is about to do so
            # a UI can render it in real time. Never fails into the analysis.
            activity_feed.publish("dispatch", f"{exchange.method} {exchange.url}: dispatching {len(dispatch)} agent(s)",
                                  detail={"agents": dispatch, "reason": reason, "url": exchange.url,
                                          "method": exchange.method})

            # Get prior context (findings from same host)
            prior_context = prior_context_snapshot

            # Run agents via analysis pipeline with early termination
            # R08/PR-7: one typed StageOutcome per run_full_analysis call this
            # exchange makes (first batch, and the early-termination remainder if
            # it runs) -- feeds AnalysisResponse.stage_outcomes/.degraded below.
            stage_outcomes: list[StageOutcome] = []
            if len(dispatch) > 1:
                # Run first batch (size from config, W-13 -- was a hardcoded 3).
                first_batch_size = min(getattr(self, "early_termination_batch_size", 3), len(dispatch))
                first_batch = dispatch[:first_batch_size]
                remaining = dispatch[first_batch_size:]

                # Run first batch
                reports, n_reviewed, n_rejected, critique_outcome = await self.analysis_pipeline.run_full_analysis(
                    exchange, first_batch, prior_context, self.max_body_chars
                )
                stage_outcomes.append(critique_outcome)

                # Check for early termination
                if remaining:
                    should_stop, stop_reason = self.fast_path_selector.check_early_termination(
                        reports, remaining
                    )

                    if should_stop:
                        # Review pt 3: a cancelled batch means other agents were
                        # NOT run on this exchange -- that is a coverage decision
                        # an operator should be able to see, not an INFO-level
                        # detail. Name the agents that were skipped.
                        log.warning(
                            "Early termination skipped %d remaining agent(s) on this "
                            "exchange (%s): %s",
                            len(remaining), ", ".join(remaining), stop_reason,
                        )
                    else:
                        # Run remaining agents
                        remaining_reports, rem_reviewed, rem_rejected, rem_outcome = await self.analysis_pipeline.run_full_analysis(
                            exchange, remaining, prior_context, self.max_body_chars
                        )
                        reports.extend(remaining_reports)
                        n_reviewed += rem_reviewed
                        n_rejected += rem_rejected
                        stage_outcomes.append(rem_outcome)
            else:
                reports, n_reviewed, n_rejected, critique_outcome = await self.analysis_pipeline.run_full_analysis(
                    exchange, dispatch, prior_context, self.max_body_chars
                )
                stage_outcomes.append(critique_outcome)

            self._note_hardening_runs(run_context, _hardening_keys, reports)
            stage_outcomes.extend(_agent_skips)

            # Adaptive re-spin (handover §7): if the pass above found nothing
            # actionable, let the cloud coordinator challenge that result and
            # suggest a different specialist for a second look. No-op unless both
            # adaptive_respin.enabled and coordinator.cloud_primary are set;
            # bounded by max_rounds and the effort budget. Runs before the
            # deterministic detectors and validation below so any re-spin
            # findings get the same credential-detection/validation treatment.
            respin_reports = await self._maybe_adaptive_respin(
                exchange, reports, dispatch, prior_context
            )
            if respin_reports:
                reports.extend(respin_reports)

            # R6: a failed inference stage is an outage, not a reusable
            # hypothesis -- caching it would replay the failure on identical
            # traffic until TTL and skip recovery. Only complete inference is stored.
            # A dispatch cut short by this run's own reuse record is not a reusable
            # hypothesis for another run (it would replay the missing agents).
            if _hyp_enabled and not any(
                    getattr(o, "status", "") == "failed" for o in stage_outcomes) and not any(
                    report.raw_error for report in reports) and not any(
                    (o.reason or "").startswith("already analysed") for o in _agent_skips):
                # MISS: persist the pre-proof half (never anything proof-
                # shaped -- see put_hypothesis's own defensive check) so a
                # LATER run under a different cache_namespace can reuse this
                # model inference instead of re-paying for it.
                cache.get_cache().put_hypothesis(
                    exchange,
                    dispatch=dispatch, reason=reason, reports=reports,
                    stage_outcomes=stage_outcomes,
                    findings_reviewed=n_reviewed, findings_rejected=n_rejected,
                    model=self.coordinator_model, prompt_versions=_hyp_prompt_versions,
                    config_fingerprint=_hyp_config_fingerprint,
                    namespace=hypothesis_namespace,
                )

        # X08: inference health is judged over the model agents' reports only,
        # captured before the deterministic/rule-based reports below are
        # appended -- a deterministic hit must not mask a model outage.
        model_reports = list(reports)

        # Deterministic, non-LLM login-shape detection (see
        # credential_endpoint_detector.py's own docstring for why this
        # exists: a real, live test against this exchange's own kind --
        # an ordinary login submission with no injection syntax -- showed
        # the sqli agent produces zero findings for it, since its prompt
        # is reactive to observed injection markers, not proactive about
        # canonical attack-surface shape. This closes that gap the same
        # way chain_detector below closes its own: a rule-based synthetic
        # AgentReport feeding the same planner/validator pipeline. MUST run
        # before _validate_findings() below, not after -- found live,
        # this session, that appending it after validation already ran
        # meant the active sqlmap validator never got a chance to see it
        # at all (validation_reports had already been computed from the
        # OLD reports list), silently defeating the entire point of this
        # detector: it produced a persisted finding but never triggered
        # the active test it exists to guarantee.
        credential_finding = credential_endpoint_detector.detect_credential_submission(exchange)
        if credential_finding is not None:
            reports.append(AgentReport(
                agent="credential_endpoint_detector",
                model="rule-based",
                findings=[credential_finding],
            ))

        # Proactive, shape-driven confirmation legs on the CAPTURED exchange --
        # the analyze() analogue of investigate_engagement's _precondition. An
        # XML-accepting body or a URL-shaped param warrants trying XXE/SSRF
        # regardless of whether an agent flagged that class, closing the
        # detection->confirmation coupling on the captured-exchange path the way
        # shape_precondition_legs did for the graph path. These legs need a real
        # captured body/param, which only this stream carries. MUST be appended
        # before _validate_findings (like credential_endpoint_detector above),
        # or the active validator never sees them. Kept only if confirmed -- see
        # the prune below -- so shape never leaves an unconfirmed guess standing.
        shape_findings = shape_precondition_findings(exchange)
        if any(r.findings for r in reports):
            # Any finding on this exchange already reaches the exposure oracle by
            # response evidence (api_security applies()); the sweep leg is for a
            # capture nothing else flagged, so it would only repeat the replays.
            shape_findings = [f for f in shape_findings
                              if f.vulnerability_class != "excessive data exposure"]
        # A reflected query parameter is an observed fact, so it is kept as its
        # own (unconfirmed) hypothesis and planned; its parameter-scoped XSS
        # check replaces the generic shape XSS leg on the same request.
        reflected = reflected_parameter_findings(exchange)
        if reflected:
            shape_findings = [f for f in shape_findings if f.vulnerability_class != "xss"]
            reports.append(AgentReport(
                agent=_REFLECTION_AGENT, model="deterministic", findings=reflected))
        if shape_findings:
            reports.append(AgentReport(
                agent=_SHAPE_LEG_AGENT, model="rule-based", findings=shape_findings,
            ))

        # Validate findings
        validation_reports, proof_records = await self._validate_findings(
            exchange, reports, run_context=run_context)

        # Drop shape-precondition legs that no validator confirmed: they are
        # hypotheses justified only by endpoint shape, so an XML endpoint with
        # entities disabled must not leave a standing "XXE" finding. (Agent-
        # produced XXE/SSRF findings live on their own reports and are untouched.)
        # I04: a shape candidate the check could not confirm but marked for a
        # manual check (CSRF on a cookie-authenticated write) stays visible as a
        # low-severity "needs manual check" item, never as a confirmed finding.
        for _r in reports:
            if _r.agent == _SHAPE_LEG_AGENT:
                for f in _r.findings:
                    if not f.confirmed and f.manual_verification:
                        f.severity = "low"
                        f.confidence = min(f.confidence, 0.3)
                        f.summary = ("NEEDS MANUAL CHECK - " + f.vulnerability_class.upper()
                                     + " candidate, not automatically verified: " + f.summary)
                _r.findings = [f for f in _r.findings if f.confirmed or f.manual_verification]
        reports[:] = [r for r in reports if r.agent != _SHAPE_LEG_AGENT or r.findings]

        # NOTE (review R12/oracle-audit + the "finding vs observation" MUST): a
        # prior revision auto-CONFIRMED config/header classes (CORS, CSP,
        # clickjacking, missing headers, version/plaintext-password disclosure)
        # purely from an LLM label. That is a false confirmation -- a configuration
        # FACT is a structural observation, not a proven exploitable vulnerability,
        # and "confirmed" must mean a leg proved an effect. That block is removed:
        # these classes have no confirmation leg, so the suppression gate leaves
        # them untouched and they ship as unconfirmed observations at their own
        # severity -- honestly labelled, never fake-confirmed. (An ACTIVE cors/csp
        # validator that actually tested the endpoint may still set confirmed via
        # the normal validation path; that is a real check, not a label.)

        # Confirmation-suppression gate: unconfirmed hypotheses in confirmable
        # classes (IDOR, SQLi, XSS, SSRF, XXE, CMDi, SSTI, Traversal, Redirect, JWT)
        # must never ship at actionable severity (medium/high/critical).
        from harness import confirmation_gate
        # P0-2: run-derived trust tiers -- None (default/offline) keeps the
        # static LIVE_VERIFIED_MARKERS table exactly as before; when
        # leg_self_test.enabled is set, this is the frozenset of classes this
        # run's leg self-test actually confirmed-true-and-refuted-false on
        # the loopback fixture, which OVERRIDES the static table (demotion
        # only -- see get_run_derived_live_markers docstring).
        _live_markers = await self.get_run_derived_live_markers()
        confirmation_gate.apply_confirmation_suppression(
            reports, validation_reports, live_verified_markers=_live_markers,
            config=getattr(self, "config", {}))

        # Category-attribution reliability (Phase 3.5): a confirmed finding's
        # class is authoritative from the leg that proved it (relabel over a wrong
        # agent label); an UNCONFIRMED finding whose class contradicts the
        # endpoint shape is flagged so a mislabel doesn't stand unchallenged.
        from harness import attribution
        for _r in reports:
            attribution.relabel_confirmed_findings(_r.findings)
            attribution.annotate_shape_inconsistent(_r.findings, exchange)

        # Known-vulnerability resolution happens AFTER critique and is
        # never itself critiqued -- these findings come from an
        # authoritative external source (GitHub's Advisory Database), not
        # LLM reasoning, so the adversarial-review step that exists to
        # catch bad LLM reasoning doesn't apply to them.
        known_vuln_report = await self._resolve_known_vulnerabilities(exchange, reports)
        if known_vuln_report is not None:
            reports.append(known_vuln_report)

        registry_age_report = await self._check_registry_ages(exchange, reports)
        if registry_age_report is not None:
            reports.append(registry_age_report)

        # Opt-in only: see AnalysisRequest.attempt_rediscovery. Default
        # behavior trusts the known-vulnerability match and stops there.
        if attempt_rediscovery and known_vuln_report is not None and known_vuln_report.findings:
            rediscovery_report = await self._attempt_rediscovery(exchange, known_vuln_report.findings)
            if rediscovery_report is not None:
                reports.append(rediscovery_report)

        # Deterministic confidential-info response scan (A4) -- secrets/PII/
        # internal-infra leakage present in THIS response, with redacted
        # evidence. Regex, no model, not critiqued (an AKIA key or a private-key
        # block is an exact match, not an LLM judgment); added as its own report
        # so it persists, chains, and surfaces like any other.
        from harness import confidential_info_detector
        conf_findings = confidential_info_detector.findings_from_exchange(exchange)
        if conf_findings:
            reports.append(AgentReport(agent="confidential_info", model="deterministic",
                                       findings=conf_findings))

        # Deterministic verbose-error / stack-trace / debug-info detector.
        # Passive (no network), scans every response for patterns like
        # Python tracebacks, Java stack traces, Flask/Django debug pages,
        # leaked environment variables. Already-confirmed on detection.
        from harness.validators.verbose_error_validator import findings_from_exchange as _ve_findings
        ve_findings = _ve_findings(exchange)
        if ve_findings:
            reports.append(AgentReport(agent="verbose_error_detector", model="deterministic",
                                       findings=ve_findings))

        # Secret-disclosure CONFIRMATION (Phase 3.1): if a string in this response
        # cryptographically verifies the signature of the JWT the client presents,
        # that string IS the signing key -- a confirmed, exploitable leak (forge
        # any token). Deterministic + offline (no send), so it runs here like the
        # confidential-info scan; it emits an already-confirmed finding.
        from harness import secret_disclosure
        sd_findings = secret_disclosure.findings_from_exchange(exchange)
        if sd_findings:
            reports.append(AgentReport(agent="secret_disclosure", model="deterministic",
                                       findings=sd_findings))

        # Persist what survived review -- this is what makes prior_context
        # non-empty on the *next* call for this host.
        for report in reports:
            await asyncio.to_thread(
                store.persist_findings,
                exchange,
                report.agent,
                report.findings,
                report.model,
                report.prompt_version,
                engagement_id=engagement_partition,
            )

        # Chain detection runs over the host's FULL accumulated finding
        # history (not just this exchange), rule-based, after persistence
        # so it can see what was just added.
        host_findings = await asyncio.to_thread(store.all_host_findings, exchange.url,
                                              engagement_id=engagement_partition)
        # Exclude previously-detected chain findings from re-triggering
        # detection against themselves
        host_findings = [
            f for f in host_findings
            if not f["vulnerability_class"].startswith("potential-attack-chain:")
        ]
        chain_findings = [
            f for f in chaining.detect(host_findings)
            if not await asyncio.to_thread(
                store.is_chain_already_detected,
                exchange.url,
                f.vulnerability_class.split(":", 1)[-1],
                engagement_id=engagement_partition
            )
        ]
        if chain_findings:
            for f in chain_findings:
                await asyncio.to_thread(
                    store.mark_chain_detected,
                    exchange.url,
                    f.vulnerability_class.split(":", 1)[-1],
                    engagement_id=engagement_partition,
                )
            chain_report = AgentReport(
                agent="chain_detector",
                model="rule-based",
                findings=chain_findings,
            )
            reports.append(chain_report)
            await asyncio.to_thread(
                store.persist_findings,
                exchange,
                "chain_detector",
                chain_findings,
                engagement_id=engagement_partition,
            )

        all_findings: list[Finding] = [f for r in reports for f in r.findings]

        # P2.5: remember a CONFIRMED finding's structural shape (never its
        # host, values, or evidence) for future cross-host recognition.
        # Default off, same flag as the read side above.
        pm_cfg = (self.config.get("pattern_memory", {}) or {})
        if pm_cfg.get("enabled", False):
            from harness import pattern_memory
            pm_path = pm_cfg.get("path", pattern_memory.DEFAULT_PATH)
            for f in all_findings:
                if f.confirmed:
                    sig = pattern_memory.signature_for_finding(f.model_dump(), exchange)
                    pattern_memory.record_pattern(f.vulnerability_class, sig, path=pm_path)

        test_plans = planner.plans_for_findings(exchange, all_findings)
        # A plan another capture of this request (differing only in a
        # cache-buster parameter) already stored is that capture's: it is not
        # dispatched or bound again from here.
        own_plans = await asyncio.to_thread(store.persist_test_plans, exchange, test_plans)
        # Bind each plan to the validator run that already covered it here, or
        # record why none could; nothing is re-sent (validated=True).
        if own_plans:
            from harness import plan_dispatch
            try:
                await plan_dispatch.dispatch_plans(
                    self, exchange, own_plans, reports, validation_reports,
                    run_context=run_context, validated=True)
            except Exception as e:  # plan bookkeeping must never break analysis
                log.warning("plan dispatch failed for %s: %s", exchange.url.split("?", 1)[0], e)
        top = max(all_findings, key=lambda f: f.confidence, default=None)

        # Autonomous scope-discovery (harness/scope_discovery.py) -- off by
        # default (autonomous_discovery.enabled), see that module's own
        # docstring. Guarded by `not _from_discovery` so a discovery pass's
        # own results can never themselves trigger another discovery pass.
        # Fire-and-persist, not merged into THIS exchange's own response:
        # each discovered exchange gets its own full, independent
        # self.analyze() call (its findings/test_plans persist normally,
        # visible via all_host_findings/the Burp panel on a later query),
        # the same way any other exchange's analysis works.
        if not _from_discovery:
            discovered_exchanges = await scope_discovery.discover_from_scope_change(
                exchange, all_findings, self.config, self.allowed_hosts,
                run_context=run_context
            )
            for discovered in discovered_exchanges:
                await self.analyze(
                    discovered, _from_discovery=True, run_context=run_context,
                    engagement_id=engagement_partition)

        errors = [f"{r.agent}: {r.raw_error}" for r in reports if r.raw_error]
        # Every dispatched LLM agent failed -- almost always the model backend
        # being unreachable or the configured model not pulled. This used to be
        # invisible at the response level (only per-agent raw_error), so the run
        # looked normal while every agent had actually errored. Fold it into
        # `degraded` (below) and lead the summary with an unmistakable warning.
        # X08: counted over model agents only, and SOME agents failing is a
        # partial result, not a clean miss -- also degraded and warned.
        model_failures = [r for r in model_reports if r.raw_error]
        all_agents_failed = bool(model_reports) and len(model_failures) == len(model_reports)
        partial_inference = bool(model_failures) and not all_agents_failed
        summary_parts = []
        if all_agents_failed:
            summary_parts.append(
                f"WARNING: all {len(model_reports)} LLM agent(s) failed -- results below are from "
                "deterministic checks only, NOT model analysis. Check that Ollama is running "
                "and the configured model is pulled (GET /health/details).")
        elif partial_inference:
            summary_parts.append(
                f"WARNING: {len(model_failures)} of {len(model_reports)} LLM agent(s) failed "
                f"({', '.join(r.agent for r in model_failures)}) -- results below are incomplete; "
                "an absent finding from a failed agent is not a clean miss.")
        if _from_discovery:
            summary_parts.append(f"[Autonomous discovery] {exchange.analyst_note}.")
        summary_parts.append(f"Dispatched: {', '.join(dispatch) or 'none'} ({reason}).")
        summary_parts.append(f"{len(all_findings)} finding(s) across {len(reports)} agent(s).")
        if known_vuln_report is not None and known_vuln_report.findings:
            summary_parts.append(
                f"{len(known_vuln_report.findings)} matched a known GitHub advisory."
            )
        if n_reviewed:
            summary_parts.append(
                f"Critique pass reviewed {n_reviewed}; rejected {n_rejected}."
            )
        if errors:
            summary_parts.append(f"{len(errors)} agent(s) failed: {'; '.join(errors)}")

        _, current_budget_reason = self.effort_budget.allow()

        # Tool recommendations (A3): map the findings to external tools the
        # tester should reach for, each with a command templated to this URL --
        # the harness handing back what it can't run itself.
        from harness import tool_catalog
        tool_recs: list[dict] = []
        seen_recs: set[tuple[str, str]] = set()
        for f in all_findings:
            for rec in tool_catalog.recommend_for_finding(f.vulnerability_class, exchange.url, limit=2):
                key = (rec.tool, rec.for_finding)
                if key not in seen_recs:
                    seen_recs.add(key)
                    tool_recs.append(rec.to_dict())

        # Engagement spine (engagement.py): fold this exchange's findings into the
        # per-host shared surface model so the fused worklist reflects them.
        # Defensive -- observability must never break the analysis it observes.
        try:
            from harness import engagement
            host = store.host_of(exchange.url)
            # Slice 2 -- the closed loop: detect capabilities each finding grants
            # (a learned credential, a newly-reachable area) and fold them into
            # the work queue. Credential capabilities carry ephemeral headers used
            # ONLY for an in-process re-crawl below; they are never persisted.
            detected_caps = [engagement.detect_capabilities(
                f.model_dump(), exchange.response_headers, exchange.response_body, exchange.url)
                for f in all_findings]
            credential_caps: list = []
            def fold(snapshot):
                st = engagement.EngagementState.from_dict(snapshot)
                st.ingest_findings(exchange.url, exchange.method, all_findings)
                for f, caps in zip(all_findings, detected_caps):
                    credential_caps.extend(st.apply_capabilities(caps, exchange.url))
                    st.flag_business_logic(f.vulnerability_class, exchange.url)
                return st.to_dict()
            snapshot = await asyncio.to_thread(store.mutate_engagement, host, fold,
                                               engagement_id=engagement_partition)
            for f in all_findings:
                # Memory Retriever (gap 3): remember a CONFIRMED finding as a
                # retrievable note, so similar surface later gets grounded in it.
                if f.confirmed:
                    from harness import knowledge
                    await asyncio.to_thread(knowledge.remember_finding,
                                            f.vulnerability_class, exchange.url,
                                            engagement_id=engagement_partition)

            # Opt-in auto-escalation: when a credential was learned AND
            # engagement.auto_escalate is on, re-crawl the origin as that new
            # identity right now and fold the new surface back in -- the loop
            # closes automatically. Off by default (it sends active traffic).
            if credential_caps and self.engagement_auto_escalate:
                st = engagement.EngagementState.from_dict(snapshot)
                await self._auto_escalate(host, exchange.url, credential_caps, st,
                                          run_context=run_context)
                # Network work stays outside the transaction. A stale follow-up
                # cannot silently replace intervening passive observations.
                await asyncio.to_thread(store.save_engagement, host, st.to_dict(),
                    engagement_id=engagement_partition,
                    expected_revision=snapshot["_snapshot_revision"])
        except Exception as e:
            log.debug("engagement update skipped: %s", e)

        # Build the response
        # B2-1: surface the shared ollama circuit breaker's OPEN state on the
        # response itself, so a breaker-starved run is distinguishable from a
        # healthy clean one. Read-only -- never mutates the breaker.
        _circuit_open = current_ollama_breaker("ollama").is_open
        # R08/PR-7: `degraded` is the single OR of every known health signal a
        # reader would otherwise have to check separately -- any stage (today:
        # critique) that FAILED and shipped its input unreviewed, OR the shared
        # circuit breaker being open (a breaker-starved run is degraded even if
        # no stage individually raised, since agent calls may have short-
        # circuited without reaching the model). Findings are never dropped for
        # this: `reports`/`all_findings` above are unaffected either way, this
        # only adds a flag. False (the default) when every stage completed
        # cleanly and the breaker was closed -- i.e. unchanged for a healthy run.
        # X08: any dispatched model agent failing (all or some) is degraded.
        _degraded = (_circuit_open or bool(model_failures)
                     or any(o.status == "failed" for o in stage_outcomes))
        response = AnalysisResponse(
            engagement_id=engagement_partition,
            captured_principal_id=captured_principal,
            coordinator_model=self.coordinator_model,
            dispatched_agents=dispatch,
            agent_reports=reports,
            summary=" ".join(summary_parts),
            highest_confidence_finding=top,
            findings_reviewed=n_reviewed,
            findings_rejected=n_rejected,
            validation_reports=validation_reports,
            proof_records=proof_records,
            test_plans=test_plans,
            effort_spent_tokens=self.effort_budget.spent,
            effort_usage_complete=self.effort_budget.ledger.usage_complete,
            effort_budget_remaining=self.effort_budget.remaining,
            effort_budget_warning=current_budget_reason,
            tool_recommendations=tool_recs,
            telemetry=coordinator.fail_open_stats() if hasattr(coordinator, "fail_open_stats") else {},
            # P0.9: surface THIS exchange's routing outcome as a structured flag,
            # not just the process-wide `telemetry` counters above. `in` (not
            # `startswith`) so a cloud-primary reason like "cloud-coordinator
            # (fallback (...): ...)" -- the fallback nested inside the composed
            # string -- is still caught, not just a bare local-coordinator fallback.
            coordinator_fallback=coordinator.is_fallback_reason(reason),
            agents_circuit_open=_circuit_open,
            # R08/PR-7: typed per-stage health (currently critique) and the
            # single degraded flag derived from it -- see StageOutcome/
            # AnalysisResponse.degraded in models.py for the full contract.
            stage_outcomes=stage_outcomes,
            degraded=_degraded,
            partial_inference=partial_inference,
            agent_errors=errors,
            observation_context=observation_context,
        )

        activity_feed.publish(
            "analysis_done",
            f"{exchange.method} {exchange.url}: {len(all_findings)} finding(s), "
            f"{len(validation_reports)} validation(s)",
            detail={"url": exchange.url, "findings": len(all_findings),
                    "agents": [r.agent for r in reports],
                    "top": top.vulnerability_class if top else None})

        # Cache the result if this was a normal analysis
        if (not bypass_cache and not force_agents and not cache_hit and not response.degraded
                and not any(report.raw_error for report in reports)):
            current_prompt_versions = {
                agent.name: json.dumps([agent._prompt_version(), agent._guide_version()])
                for agent in self.agent_manager.agents.values()
            }
            cache.get_cache().put(
                exchange, response, self.coordinator_model, current_prompt_versions,
                namespace=response_cache_namespace
            )
            log.debug(
                "Cached analysis result for exchange %s",
                cache.ExchangeCache.compute_exchange_hash(exchange)[:16],
            )

        # ER-2: one canonical per-run trace summary onto the EvidenceLedger,
        # emitted ONLY by the call that owns this run (owns_run) so a
        # nested/engagement-shared analyze() call never multiplies summaries
        # per-exchange. Instrumentation only, best-effort: any failure here
        # must never raise into analyze() or affect the response already
        # built above.
        if owns_run:
            try:
                from harness import evidence_ledger
                effort_ledger = self.effort_budget.ledger
                accounting = self.effort_budget.accounting()
                degraded = current_ollama_breaker("ollama").is_open
                evidence_ledger.emit(
                    evidence_ledger.EventType.RUN_SUMMARY,
                    run_context.run_id,
                    f"run summary: {len(dispatch)} agent(s) dispatched, "
                    f"{len(validation_reports)} validation(s), "
                    f"{accounting['known_tokens']} known token(s)"
                    f"{' (lower bound; usage incomplete)' if not accounting['usage_complete'] else ''}"[:500],
                    data={
                        **accounting,
                        "tokens_total": accounting["known_tokens"],
                        "tokens_lower_bound": not accounting["usage_complete"],
                        "tokens_breakdown": effort_ledger.breakdown(),
                        "elapsed_s": _time.monotonic() - _run_start,
                        "degraded": degraded,
                        "validator_count": len(validation_reports),
                        "leg_count": len(dispatch),
                    },
                    provenance=evidence_ledger.Provenance.capture(
                        config=self.config, model=self.coordinator_model),
                    case_ref=run_context.run_id,
                )
            except Exception as e:  # best-effort: must never sink a run
                log.debug("ER-2: run-summary emit failed: %s", e)

        return response
