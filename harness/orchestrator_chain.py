"""orchestrator_chain.py -- ChainMixin mixin for Orchestrator (W-15 decomposition).

The graph-driven engagement loop: plan/run_engagement, auto-escalation,
credential-grant checks, and the investigate_engagement driver.

ARC-9: investigate_engagement's body is six stage methods in the five
orchestrator_chain_{discovery,legs,worklist,coverage,finish}.py mixins, sharing one
`EngagementRun`; the helpers they use are in orchestrator_chain_support.py. `self` state is
initialised in Orchestrator.__init__ and resolved across mixins via the MRO.
"""
from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from urllib.parse import urlsplit

# FR-6: need the module too (the driver scope reads its ambient run) -- aliased because
# investigate_engagement and several methods have a `run_context` parameter that would shadow it.
from harness import run_context as _run_context_mod
from harness import global_throttle, identity_headers, review_overlap, scope_discovery, store
from harness.models import HttpExchange
from harness.orchestrator_chain_coverage import ChainCoverageMixin
from harness.orchestrator_chain_discovery import ChainDiscoveryMixin
from harness.orchestrator_chain_finish import ChainFinishMixin
from harness.orchestrator_chain_legs import ChainLegsMixin
from harness.orchestrator_chain_support import (
    EngagementRun,
    _driver_scope,
    _invalidated_headers,
    _responses_materially_same,
)
from harness.orchestrator_chain_worklist import ChainWorklistMixin
from harness.orchestrator_helpers import log, per_run_gate_config
# W-16: the single TargetTransport. Imported by name (not as the module) because
# investigate_engagement has a `run_context` parameter that would shadow the module;
# `transport_for(run_context, ...)` then reads as "use this run's transport, or a
# standalone one when it is None".
from harness.run_context import transport_for


class ChainMixin(
    ChainDiscoveryMixin,
    ChainLegsMixin,
    ChainWorklistMixin,
    ChainCoverageMixin,
    ChainFinishMixin,
):
    async def plan_engagement(self, host: str, *, max_targets: int = 10,
                              base_url: str = "") -> dict:
        """The engagement driver, planning mode (no side effects): read the fused
        worklist back out, take the top untested endpoints, and run them through
        the F5 budget governor -- returning a ranked, budgeted 'test next' queue
        with the governor's full/reduced/deferred decisions and guidance. The
        endpoint's fused score IS its allocation priority, so the whole
        signal-fusion pipeline drives what gets budget. Pure planning: nothing is
        fetched or analyzed here."""
        from harness import engagement, resource_governor
        snap = await asyncio.to_thread(store.load_engagement, host)
        if not snap:
            return {"host": host, "targets": [], "guidance": ["no engagement state for this host yet -- "
                                                              "crawl or analyze it first"], "executed": False}
        st = engagement.EngagementState.from_dict(snap)
        # "Test next" = not already validated; ranked by the fused score.
        ranked = [e for e in st.worklist(limit=max(1, min(max_targets * 3, 200)))
                  if e.get("status") != "validated"][:max_targets]

        origin = ""
        if base_url:
            p = urlsplit(base_url)
            origin = f"{p.scheme}://{p.netloc}"

        candidates: list[dict] = []
        for e in ranked:
            bf = None
            for f in e.get("findings", []):
                if bf is None or f.get("confidence", 0) > bf.get("confidence", 0):
                    bf = f
            severity = (bf or {}).get("severity") or (
                "medium" if any("privileged" in r for r in e.get("reasons", [])) else "low")
            candidates.append({
                "id": e["key"] if "key" in e else f"{e['method']} {e['path']}",
                "vulnerability_class": (bf or {}).get("vulnerability_class", "unknown"),
                "url": (origin + e["path"]) if origin else e["path"],
                "severity": severity,
                "confidence": (bf or {}).get("confidence", 0.0),
                "priority": e.get("score", 0.0),   # the fused ranking drives allocation
            })

        plan = self.plan_allocation(candidates)  # governor + remaining budget
        # Join the allocation back onto the ranked targets for a single view.
        alloc_by_id = {a["id"]: a for a in plan.get("allocations", [])}
        targets = []
        for e in ranked:
            key = f"{e['method']} {e['path']}"
            a = alloc_by_id.get(key, {})
            targets.append({
                "method": e["method"], "path": e["path"], "score": e.get("score"),
                "status": e.get("status"), "reasons": e.get("reasons", []),
                "action": a.get("action", "deferred"), "granted_tokens": a.get("granted_tokens", 0),
                "vulnerability_class": a.get("vulnerability_class", "unknown"),
                "severity": a.get("severity"),
            })
        return {"host": host, "targets": targets, "guidance": plan.get("guidance", []),
                "round_cost_tokens": plan.get("round_cost_tokens"),
                "budget": plan.get("total_budget"), "executed": False}

    async def run_engagement(self, host: str, base_url: str, *, max_targets: int = 5,
                             max_rounds: int = 3, execute: bool = False) -> dict:
        """The planner-executor RE-PLANNING LOOP (VulnBot Plan-Session /
        Task-Session / Summarizer). Each round: PLAN from the current fused
        worklist (governor-budgeted), EXECUTE the funded GET targets (fetch +
        analyze -- which folds new findings/surface/capabilities back into the
        state), then SUMMARIZE what changed and re-plan. Repeats until nothing new
        is worth testing, the effort budget is spent, or max_rounds -- so the
        driver adapts to what each round reveals rather than planning once.

        Plan-only unless `execute` is asked AND engagement.driver_execute is
        enabled in config (double-gated -- never tests automatically).

        WL-12 (E40): an executing call owns ONE run for all its rounds (or borrows
        the run that already encloses it). Every target GET and every page
        analysis (which borrows the run instead of creating its own) spends that
        run's single request ceiling under its scope, gate, TLS policy and
        cancellation. The owned run mirrors the RV-G route run
        (server._crawl_route_run): runs.max_requests -- falling back to the
        standalone-analysis ceiling, analyze.max_requests (1000), so the call is
        never unbounded -- runs.request_timeout_seconds, the live validator gate
        with mutating replay forced off, and server.allowed_hosts as a
        fail-closed scope. It is closed on every exit."""
        if not execute:
            plan = await self.plan_engagement(host, max_targets=max_targets, base_url=base_url)
            plan["note"] = "plan only -- pass execute=true (and enable engagement.driver_execute) to run these"
            return plan
        if not self.engagement_driver_execute:
            plan = await self.plan_engagement(host, max_targets=max_targets, base_url=base_url)
            plan["note"] = "execution refused: engagement.driver_execute is disabled in config.yaml"
            return plan

        driver_ceiling = (self.config.get("engagement", {}) or {}).get("driver_max_requests")
        if driver_ceiling is not None and (type(driver_ceiling) is not int or driver_ceiling < 0):
            raise ValueError("engagement.driver_max_requests must be a nonnegative integer")
        enclosing = _run_context_mod.current_run_context()
        owned = None
        if enclosing is None:
            cfg = self.config if isinstance(self.config, dict) else {}
            runs_cfg = cfg.get("runs", {}) or {}
            ceiling = runs_cfg.get("max_requests")
            if ceiling is None:
                ceiling = (cfg.get("analyze", {}) or {}).get("max_requests")
            ceiling = 1000 if ceiling is None else ceiling
            if isinstance(ceiling, bool) or not isinstance(ceiling, int) or ceiling < 0:
                raise ValueError("the engagement run ceiling (runs.max_requests, else "
                                 "analyze.max_requests) must be a nonnegative integer")
            owned = _run_context_mod.RunContext.create(
                allowed_hosts=self.allowed_hosts, config=cfg, max_requests=ceiling,
                gate_config={**per_run_gate_config(cfg, getattr(self, "validator_registry", None)),
                             "allow_mutating_replay": False},
                timeout=float(runs_cfg.get("request_timeout_seconds", 15.0)))

        p = urlsplit(base_url)
        origin = f"{p.scheme}://{p.netloc}"
        rounds: list[dict] = []
        seen_urls: set[str] = set()   # don't re-fetch the same target across rounds

        async with (owned if owned is not None else contextlib.nullcontext(enclosing)) as parent_run, _driver_scope(parent_run, driver_ceiling) as run:
            _tt = run.target_transport()
            for rnd in range(1, max(1, max_rounds) + 1):
                stop = ("run cancelled" if run.cancel.cancelled else
                        "run request ceiling reached" if run.budget.remaining == 0 else "")
                if stop:
                    rounds.append({"round": rnd, "stopped": stop})
                    break
                allowed, _ = self.effort_budget.allow()
                if not allowed:
                    rounds.append({"round": rnd, "stopped": "effort budget exhausted"})
                    break
                plan = await self.plan_engagement(host, max_targets=max_targets, base_url=base_url)
                funded = [t for t in plan["targets"]
                          if t["action"] != "deferred" and t["method"].upper() == "GET"]
                analyzed: list[dict] = []
                for t in funded:
                    if run.cancel.cancelled or run.budget.remaining == 0:
                        break
                    url = origin + t["path"].replace("{id}", "1")
                    if url in seen_urls or not scope_discovery.is_host_allowed(url, self.allowed_hosts):
                        continue
                    seen_urls.add(url)
                    try:
                        await global_throttle.acquire()
                        out = await _tt.send("GET", url, capability="engagement_execute",
                                             max_redirects=0)  # match follow_redirects=False
                        if not out.ok:
                            analyzed.append({"url": url, "error": out.error or out.outcome})
                            continue
                        exchange = HttpExchange(
                            url=url, method="GET", request_headers={}, request_body="",
                            response_status=out.status, response_headers=dict(out.headers),
                            response_body=(out.body or "")[: self.max_body_chars])
                        # Harness-fetched traffic, not a supplied capture (I02-C); the
                        # page analysis borrows this run rather than owning another.
                        result = await self.analyze(exchange, retain_observation=False,
                                                    run_context=run)
                        n = len([f for r in result.agent_reports for f in r.findings])
                        analyzed.append({"url": url, "findings": n})
                    except Exception as e:
                        analyzed.append({"url": url, "error": e.__class__.__name__})
                # SUMMARIZE this round (the condensed feedback the next plan reacts to).
                rounds.append(self._summarize_round(rnd, host, analyzed))
                if not analyzed:  # nothing new was funded/runnable -> converged
                    break
            remaining = run.budget.remaining
            run_info = {"run_id": run.run_id, "owned": owned is not None,
                        "max_requests": None if parent_run.budget.remaining is None else parent_run.budget.used + parent_run.budget.remaining,
                        "requests_used": run.budget.used, "cancelled": run.cancel.cancelled}
            if driver_ceiling is not None:
                run_info.update(driver_max_requests=driver_ceiling,
                                driver_requests_used=getattr(run.budget, "spent", None))

        after = await self.plan_engagement(host, max_targets=max_targets, base_url=base_url)
        return {"host": host, "executed": True, "rounds": rounds, "run": run_info,
                "targets_after": after["targets"], "guidance": after["guidance"],
                "summary": (await self._engagement_summary(host))}

    def _summarize_round(self, rnd: int, host: str, analyzed: list) -> dict:
        found = sum(a.get("findings", 0) for a in analyzed)
        return {"round": rnd, "targets_run": len(analyzed),
                "findings_this_round": found,
                "detail": analyzed[:20]}

    async def _engagement_summary(self, host: str) -> dict:
        from harness import engagement
        snap = await asyncio.to_thread(store.load_engagement, host)
        return engagement.EngagementState.from_dict(snap or {"host": host}).summary()

    async def _auto_escalate(self, host: str, source_url: str, credential_caps: list, st,
                             run_context=None) -> None:
        """Re-crawl the origin as each learned (derived) identity and fold the new
        surface into the engagement state. The credential headers are used here
        and discarded -- never persisted.

        I05: every probe and crawl request spends `run_context` (the analysis run
        that learned the credential) -- its budget, scope, gate and cancellation.
        The learned identity gets an escalation-only session in that run, removed
        again after the crawl, so it never joins the run's other checks.

        Blast-radius guards (this is active traffic fired as a side effect of
        analysis, so it is bounded three independent ways):
          1. DEDUP -- a derived identity already escalated (its
             recrawl_as_derived task is DONE in the graph) is skipped, so the
             same leaked token never triggers a second full crawl.
          2. VERIFY -- each credential is probed against the source URL, together
             with anonymous and invalid-token controls, before a crawl is spent
             on it (FR-6/F10); a stale/rejected token (>=400), or one that is no
             better than the anonymous/invalid baseline (a public resource or a
             login redirect), is discarded, not crawled.
          3. CAP -- a hard per-host ceiling (engagement.max_auto_escalations) on
             how many escalations fire in this process lifetime.
        Plus the usual scope gate + throttle on every request."""
        from harness import engagement, role_crawl
        from harness import task_graph
        parts = urlsplit(source_url)
        origin = f"{parts.scheme}://{parts.netloc}/"

        # Guard 1: drop caps whose derived identity was already escalated.
        fresh: list = []
        for cap in credential_caps:
            tid = task_graph.make_id(
                "recrawl_as_derived",
                f"derived:{cap.get('kind', 'cred')}@{engagement.normalize_path(source_url)}")
            t = st.graph.tasks.get(tid)
            if t is not None and t.status == task_graph.DONE:
                continue
            fresh.append(cap)
        if not fresh:
            return

        # Guard 3: per-host session cap. ARC-11: the slot is RESERVED here, before
        # the first await, so concurrent escalations of one host cannot all pass
        # the check and then all count; it is given back if no crawl lands.
        if not self._reserve_escalation(host):
            log.info("engagement auto-escalate: per-host cap (%d) reached for %s -- skipping",
                     self.engagement_max_escalations, host)
            return
        landed = False
        try:
            # Guard 2: verify each credential actually grants access before crawling.
            verified: list = []
            for cap in fresh:
                if await self._credential_grants_access(source_url, cap.get("headers", {}),
                                                        run_context=run_context):
                    verified.append(cap)
                else:
                    log.info("engagement auto-escalate: learned credential did not verify -- discarding")
            if not verified:
                return

            roles = [role_crawl.RoleSession(role="anonymous", headers={})]
            for cap in verified:
                roles.append(role_crawl.RoleSession(role="derived", headers=cap.get("headers", {})))
            session_refs = None
            if run_context is not None:
                from harness.run_context import ScopePolicy
                session_refs = []
                for index, role in enumerate(roles):
                    ref = f"auto-escalate:{index}:{role.principal_id()}"
                    run_context.sessions.register(
                        ref, role.principal_id(), dict(role.headers or {}),
                        allowed_origins=[ScopePolicy.origin_of(origin)], role=role.role)
                    session_refs.append(ref)
            try:
                result = await role_crawl.crawl_roles(
                    origin, roles, allowed_hosts=self.allowed_hosts, max_pages=20, max_endpoints=80,
                    run_context=run_context, session_refs=session_refs)
                st.ingest_role_crawl(result.to_dict())
                for cap in verified:
                    st.resolve_action("recrawl_as_derived",
                                      f"derived:{cap.get('kind', 'cred')}@{engagement.normalize_path(source_url)}")
                landed = True   # the reserved slot is kept
                log.info("engagement auto-escalate: re-crawled %s as derived identity, +%d endpoints (host total %d)",
                         origin, len(result.endpoints), self._escalation_counts.get(host, 0))
            except Exception as e:
                log.warning("engagement auto-escalate failed: %s", e)
            finally:
                for ref in session_refs or ():
                    await run_context.sessions.unregister(ref)
        finally:
            if not landed:   # unverified, failed or cancelled: the slot goes back
                self._release_escalation(host)

    def _escalation_lock(self) -> threading.Lock:
        # On the instance, not the counts dict (tests replace that dict).
        return self.__dict__.setdefault("_escalation_counts_lock", threading.Lock())

    def _reserve_escalation(self, host: str) -> bool:
        """ARC-11: take one of `host`'s auto-escalation slots, or False when the
        cap (engagement_max_escalations) is reached. Check and count are one step."""
        with self._escalation_lock():
            used = self._escalation_counts.get(host, 0)
            if used >= self.engagement_max_escalations:
                return False
            self._escalation_counts[host] = used + 1
            return True

    def _release_escalation(self, host: str) -> None:
        """ARC-11: give back a reserved slot whose escalation crawled nothing."""
        with self._escalation_lock():
            used = self._escalation_counts.get(host, 0)
            if used > 0:
                self._escalation_counts[host] = used - 1

    async def _credential_grants_access(self, url: str, headers: dict, *,
                                        run_context=None) -> bool:
        """FR-6 (F10): a learned credential "grants access" only when it produces
        a response DISTINGUISHABLE from both an anonymous control and an
        invalid-token control on the same URL -- not merely a non-error (<400)
        response. A single-probe <400 check (the old behaviour) is satisfied by
        a public resource (anonymous 200) or a login redirect just as well as by
        a real credential, which falsely "grants" access, inflates chain
        plausibility, and wastes crawl budget.

        Runs up to three probes on the same URL, all scope-gated + throttled,
        through the one throwaway TargetTransport (standalone context, closed in
        `finally` -- same shape as before):
          1. credentialed  -- the learned credential (send_creds).
          2. anonymous     -- no credential headers at all (send).
          3. invalid-token -- the credential with its value corrupted (send_creds).
        max_redirects=0 == follow_redirects=False, matching a raw client.

        Fast path: if the credentialed response is itself an error (not ok,
        no status, or status >= 400) there is no access at all -- return False
        without spending the two control probes.

        Grant (`True`) only when the credentialed response differs (status or
        body) from BOTH controls -- i.e. the credential changed what came back,
        not just "any request here gets <400". Conservative on control failure:
        if a control probe raises, or does not complete (outcome != ok, e.g. it
        was itself scope/gate/budget-denied or hit a transport error), we cannot
        establish a differential, so we fail closed (return False) rather than
        risk exactly the false grant this fix targets."""
        if not headers or not scope_discovery.is_host_allowed(url, self.allowed_hosts):
            return False
        # W-16: the credential probe goes through the single TargetTransport;
        # send_creds forwards the learned credential (ephemeral session scoped to the
        # URL's origin), matching a raw client that just sent it to `url`. I05: it
        # spends the analysis run when there is one; a standalone context otherwise.
        _tt, _owned = transport_for(
            run_context, allowed_hosts=self.allowed_hosts, config=self.config,
            active_mode=True)
        try:
            await global_throttle.acquire()
            cred = await _tt.send_creds("GET", url, capability="credential_probe",
                                        headers=headers, max_redirects=0)
            if not cred.ok or cred.status is None or cred.status >= 400:
                return False  # no access at all -- unchanged fast path, no controls needed

            try:
                await global_throttle.acquire()
                anon = await _tt.send("GET", url, capability="credential_probe",
                                      max_redirects=0)
                await global_throttle.acquire()
                invalid = await _tt.send_creds("GET", url, capability="credential_probe",
                                               headers=_invalidated_headers(headers),
                                               max_redirects=0)
            except Exception:
                return False  # control probe raised -- can't establish a differential
            if not anon.ok or not invalid.ok:
                return False  # control probe didn't complete -- can't establish a differential

            if _responses_materially_same(cred, anon) or _responses_materially_same(cred, invalid):
                return False  # public resource, or the token made no difference
            # R1: dissimilarity alone is not authorization (random/nonce bodies or
            # status jitter on a public endpoint would pass). Require a positive
            # access fact: BOTH controls were actually denied (401/403 or a
            # redirect away) while the credentialed request succeeded.
            def _denied(r) -> bool:
                s = r.status
                return s is not None and (s in (401, 403) or 300 <= s < 400)
            return _denied(anon) and _denied(invalid)
        except Exception:
            return False
        finally:
            if _owned is not None:
                await _owned.aclose()

    def _relink_chains(self, state, all_findings, responses: dict) -> list:
        """RB-5/INV-3 seam: pure chain-link recompute, no confirmation/severity/scope
        decision of its own -- that already happened upstream in `_confirm` /
        the second-order auto-confirm phase / the coverage-driven phase. Split out
        of `investigate_engagement` so a test can monkeypatch this one method to
        disable the final re-link and prove a chain composed across those later
        phases actually depends on it (not a tautology)."""
        from harness import chain_linker
        link = chain_linker.link_findings(state, all_findings, responses=responses)
        return list(link["chain_findings"])

    def _apply_business_context(self, state, captured, roles):
        """P2-1 seam: run the ONE business-context planning pass and fold its
        Application Semantic Model into `state`.

        Behind `self.business_context_enabled` (default off). When off, returns
        None immediately and touches nothing -- the loop behaves exactly as
        before (the negative control). When on, it builds the ASM from the
        already-discovered surface + captured exchanges (anonymized, structure-
        only unless coordinator.cloud_reasoning is set), RE-RANKS the worklist by
        business impact and records ranked chaining hypotheses as BLOCKED
        proposals. It performs ZERO live sends and NEVER confirms anything; every
        resulting probe still flows through the existing gated worklist/legs.

        Split out of investigate_engagement so it is testable at the caller level
        against a real EngagementState without driving the whole method. Returns
        the ApplicationSemanticModel or None."""
        if not getattr(self, "business_context_enabled", False):
            return None
        from harness import business_context_agent
        cloud_reasoning = bool(getattr(getattr(self, "coordinator", None),
                                       "cloud_reasoning", False))
        agent = business_context_agent.BusinessContextAgent(config=getattr(self, "config", {}))
        asm = agent.build_model(
            host=getattr(state, "host", "") or "",
            surface=list(state.endpoints.values()),
            exchanges=captured,
            roles=roles,
            cloud_reasoning=cloud_reasoning)
        state.apply_semantic_model(asm)
        return asm

    def _experiments_config(self) -> dict:
        eng = (getattr(self, "config", {}) or {}).get("engagement", {}) or {}
        return eng.get("experiments", {}) or {}

    def _experiment_ownership(self, state, run_context, base_url):
        """The engagement's ownership ledger for the experiment cycle: the one
        `_configure_ownership` builds from the operator's `authz.owners`
        declarations (cached on the run), so declared sharing governs the verdict
        and the experiment's own ownership fact lands where CrossIdentityValidator
        and the report read it. With nothing declared anywhere a run-scoped
        ledger is filed under the same cache key, so every later
        `_configure_ownership(...)` for this origin in the run finds it too."""
        from harness.principals import OwnershipLedger
        if run_context is None or not base_url:
            return OwnershipLedger()
        # `state.owners` is [] (not None) until an engagement declares some, and a
        # non-None value makes `_configure_ownership` REBUILD the ledger and replace
        # the cached one -- leaving every holder of the earlier ledger (the
        # cross-identity validator) blind to what this cycle records.
        ledger = self._configure_ownership(
            base_url, engagement_owners=getattr(state, "owners", None) or None,
            run_context=run_context, install=False)
        if ledger is not None:
            return ledger
        from urllib.parse import urlsplit
        from harness.protected_routes import _target_of
        origin = (urlsplit(base_url).scheme.lower(), _target_of(base_url))
        cached = getattr(run_context, "_declared_ownership", None)
        cached = cached if isinstance(cached, dict) else {}
        cached.setdefault(origin, OwnershipLedger())
        run_context._declared_ownership = cached
        return cached[origin]

    def _experiment_selection_readiness(self, action, run_context):
        """AR-09: every check a selection must pass before the controller may send,
        with no send and no graph change. Returns (refusal, ready); exactly one is
        None. `refusal` is a typed disposition; `ready` carries what the handoff
        needs to run the selected hypothesis."""
        from harness import experiment, experiment_planner
        def disposition(status, reason, **extra):
            return dict(status=status, readiness=reason, fresh_attempt_ids=[],
                        referenced_attempt_ids=[], budget_spent=0, **extra)
        def refuse(status, reason):
            return disposition(status, reason), None
        if set(action) != {"action", "kind", "hypothesis"}:
            return refuse("rejected", "selection fields must be action, kind, hypothesis")
        if not self._experiments_config().get("enabled", False):
            return refuse("disabled", "experiments disabled")
        context = getattr(run_context, "experiment_context", None)
        if not context:
            return refuse("needs_prerequisite", "owning engagement context unavailable")
        state, asm = context["state"], context["asm"]
        hypotheses = {h.id: h for h in getattr(asm, "chaining_hypotheses", [])}
        if experiment_planner.validate_instantiation(action.get("kind"), action.get("hypothesis"), hypotheses):
            return refuse("rejected", "unknown mechanism or hypothesis")
        hid = action["hypothesis"]
        hyp = hypotheses[hid]
        if action["kind"] not in experiment.BROWSER_KINDS and (action["kind"] != experiment.KIND or not experiment.supports(hyp)):
            return refuse("rejected", "hypothesis does not support this mechanism")
        if run_context.cancel.cancelled:
            return refuse("cancelled", "owning run cancelled")
        if not run_context.scope.in_scope(context["base_url"]):
            return refuse("blocked", "target outside owning scope")
        gate = run_context.gate.config
        if not gate.active_enabled or (action["kind"] != experiment.BROWSER_HASH and not gate.allow_mutating_replay):
            return refuse("blocked", "active and mutating permissions required")
        expectations = (self.config.get("engagement", {}) or {}).get("access_expectations", [])
        sessions = experiment.run_sessions(run_context)
        plan = (experiment.translate_browser(hid, asm, run_context, check_cost=False) if action['kind'] in experiment.BROWSER_KINDS else
                experiment.translate_cross_account(hyp, asm, expectations, sessions,
                    state.observed_values, base_url=context["base_url"]))
        if not plan.ready:
            return refuse("needs_prerequisite", "; ".join(plan.missing))
        if plan.experiment.kind != action["kind"]:
            return refuse("rejected", "declared mechanism does not match selection")
        from harness.run_context import ScopePolicy
        for step in (plan.experiment.setup_steps + plan.experiment.baseline_steps +
                     plan.experiment.attack_steps + plan.experiment.control_steps + plan.experiment.cleanup_steps):
            session = run_context.sessions.get(step.session_ref)
            if (session is None or session.health == 'expired' or
                    ScopePolicy.origin_of(step.url_template) not in session.allowed_origins or
                    not run_context.scope.in_scope(step.url_template)):
                return refuse("needs_prerequisite", "required identity is not authorized for step origin")
        return None, dict(state=state, asm=asm, hid=hid, plan=plan, context=context,
                          expectations=expectations, sessions=sessions)

    def _experiment_catalog(self, run_context) -> dict:
        """AR-09: the mechanisms the iterative worker may be offered right now.
        `ready` passes every pre-send check; `unavailable` names each declared
        candidate that does not, with its typed reason. Pure: nothing is sent."""
        from harness import experiment, security
        context = getattr(run_context, "experiment_context", None)
        if not context or not self._experiments_config().get("enabled", False):
            return {"ready": [], "unavailable": []}
        candidates = [(experiment.KIND, h.id) for h in getattr(context["asm"], "chaining_hypotheses", [])
                      if experiment.supports(h)]
        bindings = ((run_context.config or {}).get("engagement", {}) or {}).get("browser_bindings", []) or []
        candidates += [(b.get("mechanism"), b.get("hypothesis_id")) for b in bindings
                       if b.get("mechanism") in experiment.BROWSER_KINDS]
        catalog = {"ready": [], "unavailable": []}
        for kind, hid in dict.fromkeys(candidates):
            refusal, _ = self._experiment_selection_readiness(
                {"action": "experiment", "kind": kind, "hypothesis": hid}, run_context)
            entry = {"kind": kind, "hypothesis": hid}
            if refusal is None:
                catalog["ready"].append(entry)
            else:
                catalog["unavailable"].append(dict(entry, reason=security.sanitize_text(refusal["readiness"])))
        return catalog

    async def _handoff_experiment(self, action, run_context):
        """A closed selection of an existing hypothesis, never model-authored I/O."""
        from harness import experiment, task_graph, store
        from harness.assessment_health import stored_proof_artifacts_resolve
        def disposition(status, reason, **extra):
            return dict(status=status, readiness=reason, fresh_attempt_ids=[],
                        referenced_attempt_ids=[], budget_spent=0, **extra)
        refusal, ready = self._experiment_selection_readiness(action, run_context)
        if refusal is not None:
            return refusal
        state, asm, hid, plan, context = (ready[k] for k in ("state", "asm", "hid", "plan", "context"))
        expectations, sessions = ready["expectations"], ready["sessions"]
        experiment._evaluate_browser(state, asm, run_context)
        experiment.evaluate_experiments(state, asm, expectations, sessions,
                    base_url=context["base_url"])
        tasks = experiment.selected_experiment_tasks(state, {hid})
        fingerprint = experiment.experiment_applicability(plan.experiment, run_context, state.observed_values)
        for task in tasks:
            if task.status == task_graph.DONE and task.meta.get("applicability") == fingerprint:
                proof = next((p for p in store.proofs_for_run(run_context.run_id)
                              if p['proof_id'] == task.evidence_ref), None)
                if proof and proof['verdict'] in ('confirmed', 'controlled_negative') and stored_proof_artifacts_resolve(proof):
                    out = disposition("reused", "matching completed attempt")
                    out['referenced_attempt_ids'] = [task.evidence_ref]
                    return out
            if task.status == task_graph.FAILED and task.meta.get("applicability") == fingerprint:
                if run_context.experiment_runs >= int(self._experiments_config().get("max_runs", 4)):
                    return disposition("deferred", "engagement experiment max_runs exhausted")
                return disposition("inconclusive", "unchanged failed attempt requires new evidence")
            if task.status in (task_graph.DONE, task_graph.FAILED):
                state.graph.mark(task.id, task_graph.READY)
        if run_context.experiment_runs >= int(self._experiments_config().get("max_runs", 4)):
            return disposition("deferred", "engagement experiment max_runs exhausted")
        before = run_context.budget.used
        outcome = await self._run_experiments(state, asm, run_context,
            base_url=context["base_url"], captured=context.get("captured", ()), hypothesis_ids={hid})
        entries = (outcome or {}).get("completed", []) + (outcome or {}).get("failed", [])
        out = disposition("completed" if (outcome or {}).get("completed") else "inconclusive",
                          "controller attempt completed" if entries else "controller produced no attempt",
                          kind=action['kind'], hypothesis=hid, produced_values=sorted(state.observed_values))
        out['fresh_attempt_ids'] = [e['proof_id'] for e in entries]
        out['budget_spent'] = run_context.budget.used - before
        return out

    async def _run_experiments(self, state, asm, run_context, *, base_url="", captured=(),
                               ownership=None, hypothesis_ids=None, deadline=None):
        """Ticket G seam: run the graph -> experiment -> workflow -> proof -> graph
        cycle (experiment.run_experiment_loop) over the hypotheses of `asm`.

        Behind `engagement.experiments.enabled` (default off) and an owning
        RunContext: otherwise returns None and sends nothing -- the engagement
        behaves exactly as before (the negative control). The privacy expectations
        come only from `engagement.access_expectations`; a hypothesis without one
        is reported BLOCKED with the exact missing input, never guessed. Mutating
        sends stay gated by validators.active_enabled / allow_mutating_replay.

        Split out of investigate_engagement so the caller-level test can disable
        this one connection and prove the cycle depends on it."""
        eng = (getattr(self, "config", {}) or {}).get("engagement", {}) or {}
        cfg = self._experiments_config()
        if run_context is None or not cfg.get("enabled", False):
            return None
        from harness import experiment, experiment_planner
        planner = None
        # The planner reasons with the LOCAL agent model on the local client --
        # never the coordinator's cloud settings. No local model configured: no planner.
        local_model = ((self.config.get("agent_defaults") or {}).get("model") or "")
        if cfg.get("planner", False) and local_model:
            planner = experiment_planner.ExperimentPlanner(
                experiment_planner.ollama_propose_fn(self.ollama, local_model),
                captures=captured)
        ledger = ownership if ownership is not None else self._experiment_ownership(
            state, run_context, base_url)
        remaining = max(0, int(cfg.get("max_runs", 4)) - run_context.experiment_runs)
        result = await experiment.run_experiment_loop(
            state, run_context, ledger=ledger,
            expectations=eng.get("access_expectations", []) or [],
            sessions=experiment.run_sessions(run_context),
            max_runs=remaining, planner=planner, asm=asm, base_url=base_url,
            **({"hypothesis_ids": hypothesis_ids} if hypothesis_ids is not None else {}),
            **({"deadline": deadline} if deadline is not None else {}))

        return result

    async def _final_experiment_pass(self, state, asm, run_context, *, base_url="",
                                     captured=(), ownership=None, deadline=None):
        """AR-FP seam: the bounded final re-evaluation of experiment tasks, after the
        coverage phase and before their dispositions are taken.

        The experiments phase runs once, early. Later phases can change what an
        experiment needs: an iterative-worker hand-off runs only its selected
        hypothesis yet observes values that make other tasks READY, and a session
        refresh changes an attempt's applicability. This re-evaluates every task
        (`evaluate_experiments`, `_evaluate_browser`) against the final values and
        sessions, re-queues a FAILED task only when its applicability changed, and
        runs the READY ones through the same `_run_experiments` loop -- within the
        remaining max_runs, the run's request budget, `deadline` and the cancel
        token; no bound is raised. A READY task left unrun is marked deferred with
        the bound that stopped it. Disabled experiments or no owning run: None, and
        nothing is sent. Split out of investigate_engagement so a test can unplug it
        (the RB-5 `_relink_chains` precedent)."""
        cfg = self._experiments_config()
        if run_context is None or asm is None or not cfg.get("enabled", False):
            return None
        from harness import experiment, task_graph
        eng = (getattr(self, "config", {}) or {}).get("engagement", {}) or {}
        expectations = eng.get("access_expectations", []) or []
        sessions = experiment.run_sessions(run_context)
        experiment._evaluate_browser(state, asm, run_context)
        experiment.evaluate_experiments(state, asm, expectations, sessions, base_url=base_url)
        requeued, unchanged = [], []
        for task in experiment.experiment_tasks(state):
            if task.status != task_graph.FAILED:
                continue
            plan = (experiment.translate_browser(task.meta.get("hypothesis_id"), asm, run_context)
                    if task.meta.get("kind") in experiment.BROWSER_KINDS else
                    experiment.translate_cross_account(task, asm, expectations, sessions,
                                                       state.observed_values, base_url=base_url))
            if plan.ready and experiment.experiment_applicability(
                    plan.experiment, run_context, state.observed_values) != task.meta.get("applicability"):
                state.graph.mark(task.id, task_graph.READY)
                requeued.append(task.id)
            else:
                task.meta["final_pass"] = {"status": "failed_unchanged",
                                           "reason": "unchanged failed attempt requires new evidence"}
                unchanged.append(task.id)
        ready = [t.id for t in experiment.experiment_tasks(state) if t.status == task_graph.READY]
        max_runs = int(cfg.get("max_runs", 4))
        stopped_by = ("owning run cancelled" if run_context.cancel.cancelled else
                      "engagement experiment max_runs exhausted"
                      if run_context.experiment_runs >= max_runs else
                      "owning request budget exhausted" if run_context.budget.remaining == 0 else
                      experiment.STAGE_DEADLINE
                      if deadline is not None and time.monotonic() >= deadline else "")
        result = {"ready": ready, "requeued": requeued, "failed_unchanged": unchanged,
                  "completed": [], "failed": [], "runs": 0,
                  "stopped_by": stopped_by or "no ready experiment"}
        if ready and not stopped_by:
            loop = await self._run_experiments(state, asm, run_context, base_url=base_url,
                                               captured=captured, ownership=ownership,
                                               deadline=deadline) or {}
            result.update(completed=loop.get("completed", []), failed=loop.get("failed", []),
                          runs=loop.get("runs", 0), stopped_by=loop.get("stopped_by", ""))
            if result["stopped_by"] == "experiment max_runs exhausted":
                result["stopped_by"] = "engagement experiment max_runs exhausted"
        if result["stopped_by"] in experiment.BUDGET_REASONS:
            for task in experiment.experiment_tasks(state):
                if task.status == task_graph.READY:
                    task.meta["final_pass"] = {"status": "deferred", "reason": result["stopped_by"]}
        return result

    def _discovery_ffuf_kw(self) -> dict:
        """engagement.discovery_ffuf (default off) and, when it is on, a non-default
        engagement.discovery_ffuf_wordlist / discovery_ffuf_image; passed on only
        when they differ."""
        cfg = self.config if isinstance(self.config, dict) else {}
        eng = cfg.get("engagement") or {}
        if not eng.get("discovery_ffuf"):
            return {}
        wordlist = str(eng.get("discovery_ffuf_wordlist") or "harness")
        image = str(eng.get("discovery_ffuf_image") or "")
        return {"discovery_ffuf": True,
                **({"discovery_ffuf_wordlist": wordlist} if wordlist != "harness" else {}),
                **({"discovery_ffuf_image": image} if image else {})}

    def _discovery_recursion_kw(self) -> dict:
        """engagement.discovery_recursion_depth (default 0: off) with its request
        cap engagement.discovery_recursion_max_requests; passed on only when both
        are positive integers, so the default sends nothing new."""
        cfg = self.config if isinstance(self.config, dict) else {}
        eng = cfg.get("engagement") or {}

        def count(key: str) -> int:
            value = eng.get(key)
            if isinstance(value, bool):        # passive-only forces the knob to False
                return 0
            try:
                return max(0, int(value or 0))
            except (TypeError, ValueError):
                return 0
        depth = count("discovery_recursion_depth")
        cap = count("discovery_recursion_max_requests")
        if not depth or not cap:
            return {}
        return {"discovery_recursion_depth": depth, "discovery_recursion_max_requests": cap}

    # Roles registered as replay identities below are owned by this engagement
    # and released when it ends (never leak into a later engagement on the host).
    # A capture review left running beside the later phases is cancelled and awaited
    # when the engagement ends, however it ends (harness/review_overlap.py).
    @identity_headers.leased
    @review_overlap.reaps_review_overlaps
    async def investigate_engagement(self, base_url, roles, *, max_nodes: int = 8,
                                     step_budget: int = 16, discovery_max_probes: int = 6000,
                                     discovery_max_endpoints: int | None = None,
                                     discovery_max_pages: int = 40,
                                     active_discovery: bool = True,
                                     max_chain_rounds: int = 1, run_context=None,
                                     stop_on_confirm: bool = False,
                                     objective_class: str | None = None,
                                     objective_task: "ObjectiveTask | None" = None,
                                     objective_provider=None,
                                     seed_exchanges=None, coverage_checkpoint=None,
                                     protected_paths=None, owners=None) -> dict:
        """Milestone A+B, end to end: build the app model (active discovery ->
        per-role access matrix -> prioritised worklist), then drive the ITERATIVE
        agent top-down over that worklist -- each high-value node gets a bounded
        multi-step investigation, and findings fold back into the graph so a
        tested node sinks and is not re-tested. The harness chooses WHAT to test
        (the ranking) and HOW HARD (the step budget); this replaces firing every
        agent at every exchange.

        `roles` is a list of role_crawl.RoleSession. Requires iterative_agent
        enabled (run_active_probe enforces it). `max_chain_rounds` bounds the
        Milestone-C closed loop (re-test AS a credential learned from a finding).
        `discovery_max_endpoints` caps the method+path operations discovery probes
        with every role; None takes `engagement.discovery_max_endpoints` (default 0:
        every discovered operation, so the worklist sees the whole surface).
        `protected_paths` and `owners` are the operator's engagement declarations
        (I16): merged into the state after discovery, where the missing-auth (RV-S)
        and ownership (RV-T) confirmations read them. None or empty changes nothing."""
        ns = EngagementRun(
            base_url=base_url, roles=roles, max_nodes=max_nodes, step_budget=step_budget,
            discovery_max_probes=discovery_max_probes,
            discovery_max_endpoints=discovery_max_endpoints,
            discovery_max_pages=discovery_max_pages, active_discovery=active_discovery,
            max_chain_rounds=max_chain_rounds, run_context=run_context,
            stop_on_confirm=stop_on_confirm, objective_class=objective_class,
            objective_task=objective_task, objective_provider=objective_provider,
            seed_exchanges=seed_exchanges, coverage_checkpoint=coverage_checkpoint,
            protected_paths=protected_paths, owners=owners)
        await self._engagement_stage_discovery(ns)
        await self._engagement_stage_legs(ns)
        early = await self._engagement_stage_worklist(ns)
        if early is not None:  # objective mode finished the run in the worklist stage
            return early
        await self._engagement_stage_rounds(ns)
        await self._engagement_stage_coverage(ns)
        return await self._engagement_stage_finish(ns)
