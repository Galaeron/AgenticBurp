"""orchestrator_chain_worklist.py -- Stages 3-4 of investigate_engagement: the worklist sweep with its capture review, then
the chain rounds and second-order confirmation.

ARC-9 split of the old 2,600-line `investigate_engagement`: the body moved verbatim, cut at
top-level statements. A local that more than one stage touches is an attribute of the shared
`EngagementRun` (`ns`, built by the driver in orchestrator_chain.py); a stage that finishes
the run early returns the result, otherwise None."""
from __future__ import annotations

import time
from urllib.parse import urlsplit

# FR-6: need the module too (the driver scope reads its ambient run) -- aliased because
# investigate_engagement and several methods have a `run_context` parameter that would shadow it.
from harness import run_context as _run_context_mod
from harness import (
    global_throttle,
    objective_completion as _objective_completion_mod,
    review_overlap,
    scope_discovery,
)
from harness.models import HttpExchange
from harness.orchestrator_chain_support import _fold_worklist_summary
from harness.orchestrator_helpers import log, second_order_identities, shape_precondition_legs
from harness.orchestrator_review import review_captured_exchanges


class ChainWorklistMixin:
    async def _engagement_stage_worklist(self, ns):
        """Business context, experiments, the worklist sweep (with recrawl rounds) and the
        Phase-0.1 capture review. Returns the objective-mode result when the objective stops
        the run here; None otherwise."""
        from harness.models import Finding
        from harness.route_feed import RouteFeed
        from harness.ollama_client import context_window_error
        from harness.route_feed import endpoint_route_keys
        from harness import engagement_builder
        from harness import worklist_investigator
        # P2-1: ONE business-context planning pass, BEFORE the worklist sweep, so
        # its business-impact re-ranking actually changes what the bounded node
        # budget investigates first (a checkout/payment/role endpoint ahead of a
        # generic page). Default off -- when off this is a no-op and the ranking
        # is unchanged. It sends nothing and confirms nothing. Best-effort: an
        # ASM failure must never sink the engagement (same contract as the
        # additive phases above).
        ns._instr.phases.begin("business_context")
        ns._asm = None
        try:
            ns._asm = self._apply_business_context(ns.state, ns._all_captured, ns.roles)
        except Exception as e:
            log.warning("investigate_engagement: business-context pass failed: %s", e)
            ns._errors.append({"phase": "business_context", "error": f"{type(e).__name__}: {e}"})

        # Ticket G: the graph -> experiment -> workflow -> proof -> graph cycle for
        # the business-context hypotheses. Default off (engagement.experiments);
        # when off this returns None without a send. Best-effort like the passes
        # around it: a failure is recorded as an "experiments" phase error.
        if ns.run_context is not None:
            ns.run_context.experiment_context = {"state": ns.state, "asm": ns._asm, "base_url": ns.base_url, "captured": ns._all_captured}
        ns._instr.phases.begin("experiments")
        ns._experiments = None
        try:
            ns._experiments = await self._run_experiments(
                ns.state, ns._asm, ns.run_context, base_url=ns.base_url, captured=ns._all_captured,
                ownership=ns.ownership)
        except Exception as e:
            log.warning("investigate_engagement: experiments phase failed: %s", e)
            ns._errors.append({"phase": "experiments", "error": f"{type(e).__name__}: {e}"})

        ns._instr.phases.begin("worklist")
        ns.worklist_summary: dict = {}

        # Objective mode gets one deterministic pass over the real captured
        # request shapes before graph ranking. Ranking is intentionally generic
        # and can put many object-detail routes ahead of a filter/search sink;
        # spending the objective budget on those unrelated parameters recreates
        # the same latency failure this mode exists to prevent.
        _objective_outcomes: list[dict] = []
        if ns.stop_on_confirm and ns.objective_class:
            for _captured in ns._all_captured:
                try:
                    _objective_ex = (_captured if isinstance(_captured, HttpExchange)
                                     else HttpExchange(**_captured))
                except Exception:
                    continue
                _objective_path = urlsplit(_objective_ex.url).path or "/"
                _objective_node = {"method": _objective_ex.method,
                                   "path": _objective_path}
                warranted = [v for v, _ in shape_precondition_legs(
                    _objective_node, _objective_ex, ns.roles, ns.base_url)]
                if ns.objective_class not in warranted:
                    continue
                _objective_finding = await ns._confirm_leg(
                    ns.objective_class, _objective_ex, _objective_path)
                if not _objective_finding:
                    continue
                _objective_finding.setdefault("url", _objective_ex.url)
                ns.state.ingest_findings(
                    _objective_ex.url, _objective_ex.method, [_objective_finding])
                _objective_outcome_entry = {
                    "path": _objective_path,
                    "method": _objective_ex.method,
                    "specialty": ns.objective_class,
                    "findings": 1,
                    "findings_detail": [_objective_finding],
                    "precondition_findings": 1,
                    "confirmed": True,
                    "stop_reason": "deterministic_confirmation",
                }
                # Objective completion is a SEPARATE stage from confirmation
                # above and only ever runs when the caller declared an explicit
                # `objective_task` (never inferred from `objective_class`, a lab
                # title, or the finding's own text) -- see
                # harness/objective_completion.py's module docstring. Its
                # failure must never turn an already-confirmed finding back
                # into an unconfirmed one.
                if ns.objective_task is not None:
                    try:
                        from harness.validators.base import ValidationResult as _ValidationResult
                        _synthetic_confirmation = _ValidationResult(
                            validator=ns.objective_class, status="confirmed",
                            finding_class=ns.objective_class,
                            confidence=float(_objective_finding.get("confidence", 0.9) or 0.9),
                            confirmed=True)
                        _completion = await _objective_completion_mod.attempt_completion(
                            ns.objective_task, Finding(
                                vulnerability_class=ns.objective_class,
                                confidence=_synthetic_confirmation.confidence,
                                summary=_objective_finding.get("summary", ""),
                                evidence=_objective_finding.get("evidence", ""),
                                suggested_test="", basis="derived",
                                severity=_objective_finding.get("severity", "high")),
                            _objective_ex, _synthetic_confirmation,
                            run_context=ns.run_context, provider=ns.objective_provider)
                        _objective_outcome_entry["objective_completion"] = {
                            "status": _completion.status,
                            "action_class": _completion.action_class,
                            "summary": _completion.summary,
                            "evidence": _completion.evidence,
                            "requests_used": _completion.requests_used,
                        }
                    except Exception as e:
                        log.warning("investigate_engagement: objective completion "
                                    "stage failed: %s", e)
                        _objective_outcome_entry["objective_completion"] = {
                            "status": _objective_completion_mod.ERROR,
                            "summary": f"{type(e).__name__}: {e}",
                        }
                _objective_outcomes.append(_objective_outcome_entry)
                break

        _sweep_outcomes: list[dict] = []

        async def _investigate(st, rs, deadline=ns._investigation_deadline):
            # One summary per sweep, folded into worklist_summary: the main sweep,
            # every recrawl round and every chain round share it, and each sweep's
            # update() used to replace the last, so the run reported only its final
            # sweep beside outcomes aggregated over all of them.
            sweep: dict = {}
            outs = await worklist_investigator.investigate_worklist(
                ns._probe, st, ns.base_url, rs, confirm_fn=ns._confirm, precondition_fn=ns._precondition,
                max_nodes=ns.max_nodes, step_budget=ns.step_budget, summary_out=sweep,
                max_precondition_legs=ns._max_precondition_legs,
                stop_on_confirm=ns.stop_on_confirm, deadline=deadline,
                **ns._worklist_kwargs)
            _sweep_outcomes.extend(outs)
            _fold_worklist_summary(ns.worklist_summary, sweep, _sweep_outcomes)
            timed_out = (sweep.get("skipped_by_reason") or {}).get("time_budget", 0)
            if timed_out:
                ns._errors.append({"phase": "worklist",
                                   "error": f"investigation time budget reached: {timed_out} "
                                         "worklist node(s) not investigated"})
            return outs, [f for o in outs for f in o.get("findings_detail", [])]
        ns._investigate = _investigate

        _route_feed = None
        ns._recrawl_report: dict = {"enabled": ns._recrawl_cfg.enabled, "rounds": 0, "routes": 0}

        async def _recrawl_rounds(feed):
            """engagement.recrawl: while routes seen after discovery are pending, re-crawl
            them as every principal and investigate them (bounded by max_rounds, the
            per-run route budget, cancellation and the recrawl time-slice)."""
            if feed is None:
                return
            ns._instr.phases.begin("recrawl")
            deadline = ns._schedule.deadline_for("recrawl", ns._investigation_deadline)
            ns._instr.phases.set_budget("recrawl", ns._budget_left(deadline))
            while (ns._recrawl_report["rounds"] < ns._recrawl_cfg.max_rounds
                   and feed.pending() >= ns._recrawl_cfg.min_new_routes):
                if ns.run_context.cancel.cancelled:
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    ns._errors.append({"phase": "recrawl",
                                       "error": f"recrawl time budget reached: {feed.pending()} "
                                             "new route(s) not re-crawled"})
                    break
                ns._recrawl_report["rounds"] += 1
                fresh = feed.drain(ns._recrawl_cfg.max_routes_per_round)
                ns._recrawl_report["routes"] += len(fresh)
                st3, caps3 = await engagement_builder.recrawl_state(
                    ns.base_url, ns.roles, fresh, run_context=ns.run_context, host=ns.state.host,
                    deadline=deadline)
                outs3, found3 = await _investigate(st3, ns.roles, deadline=deadline)
                ns.outcomes.extend(outs3)
                ns.all_findings.extend(found3)
                ns.state.merge_from(st3)
                ns._all_captured.extend(caps3)
                log.info("investigate_engagement: recrawl round %d -- %d new route(s), %d node(s)",
                         ns._recrawl_report["rounds"], len(fresh), len(outs3))
            ns._recrawl_report["feed"] = feed.stats()

        # engagement.review_on_idle_seconds (0, off, by default): once the model has sat
        # idle that long while the worklist and recrawl rounds send their requests, the
        # capture review starts beside them, over the same captures, seen set, limit and
        # time budget as the capture_review pass; that pass, which drains it first, then
        # takes only what it left (harness/review_overlap.py, IdleReview).
        ns._idle_review = None
        _review_groups: dict | None = None
        if (not _objective_outcomes and not ns.stop_on_confirm
                and review_overlap.idle_seconds(self.config) > 0
                and review_overlap.review_uses_model(self)):
            _review_groups = {}

            async def _idle_review_call(captured, **bounds):
                return await review_captured_exchanges(
                    self, ns.state, captured, run_context=ns.run_context,
                    seen=ns._reviewed_captures, errors=ns._errors, stats=ns._review_stats,
                    groups=_review_groups, report_left=False, **bounds, **ns._review_kwargs)

            ns._idle_review = review_overlap.IdleReview(
                _idle_review_call, lambda: ns._all_captured,
                idle_seconds=review_overlap.idle_seconds(self.config),
                max_reviews=self.capture_review_limit, deadline=ns._investigation_deadline,
                review_seconds=(self.capture_review_seconds
                                if self.capture_review_seconds > 0 else None)).start()

        if _objective_outcomes:
            ns.outcomes = _objective_outcomes
            ns.all_findings = [f for o in ns.outcomes for f in o["findings_detail"]]
        else:
            # route_feed: from here on, every route the run first sees (validator and
            # model-directed probes, browser XHRs) is offered back for re-crawl.
            if ns._recrawl_cfg.enabled and ns.run_context is not None:
                _route_feed = RouteFeed(
                    origin=_run_context_mod.ScopePolicy.origin_of(ns.base_url),
                    in_scope=ns.run_context.scope.in_scope,
                    max_new_routes=ns._recrawl_cfg.max_new_routes,
                    known={key for ep in ns.state.endpoints.values()
                           for key in endpoint_route_keys(ep)})
                ns.run_context.route_feed = _route_feed
            _worklist_deadline = ns._schedule.deadline_for("worklist", ns._investigation_deadline)
            ns._instr.phases.set_budget("worklist", ns._budget_left(_worklist_deadline))
            ns.outcomes, ns.all_findings = await _investigate(ns.state, ns.roles, deadline=_worklist_deadline)
            ns._journal_phase("worklist")
            await _recrawl_rounds(_route_feed)

        # Phase 0.1 now runs after deterministic confirmation. Broad engagements
        # retain the full content review. Objective runners may stop once a
        # validator has independently confirmed a vulnerability, avoiding a slow
        # model pass after their success condition is already satisfied.
        _early_confirmed = any(
            f.get("confirmed")
            for o in ns.outcomes
            for f in (o.get("findings_detail", []) or [])
        )
        def _resume_report() -> dict:
            """What this run took from the journal instead of running (E7); {} without one."""
            if ns._journal is None:
                return {}
            ns._resumed_units["worklist"] = sum(1 for o in ns.outcomes if o.get("resumed"))
            ns._resumed_units["review"] = ns._review_summary.get("resumed", 0)
            return {"resume": {"root_job_id": ns._journal.root_job_id, "resumed": ns._resuming,
                               "resumed_units": dict(ns._resumed_units), "journal": ns._journal.stats()}}
        ns._resume_report = _resume_report

        def _objective_result(stopped: bool) -> dict:
            from harness.experiment import task_dispositions
            _context_error = context_window_error(self.ollama, ns._truncated_before)
            if _context_error:
                ns._errors.append(_context_error)
            return {
                "experiment_preflight": task_dispositions(ns.state,ns.run_context,
                    enabled=bool(self._experiments_config().get('enabled',False)),
                    max_runs=int(self._experiments_config().get('max_runs',4)),
                    planner_enabled=bool(self._experiments_config().get('planner',False))),
                **_resume_report(),
                "summary": ns.state.summary(),
                "worklist": ns.state.result_worklist(50),
                "outcomes": ns.outcomes,
                "worklist_summary": ns.worklist_summary,
                "chains": [],
                "chain_rounds": 0,
                "application_semantic_model": ns._asm.to_dict() if ns._asm else None,
                "experiments": ns._experiments,
                "execution_registry": ns._exec_registry.stats(),
                "coverage": {},
                "workflows": ns.workflow_results,
                "task_graph": ns.state.graph.to_dict(),
                "ready_tasks": ns.state.pending(),
                "blocked_tasks": ns.state.blocked(),
                "auth_bypass_candidates": ns.rc.auth_bypass_candidates,
                "idor_candidates": ns.rc.idor_candidates,
                "idor_findings": ns.rc.idor_findings,
                "errors": ns._errors,
                "review_stats": ns._review_stats,
                "degraded": bool(ns._errors),
                "stopped_on_confirmation": stopped,
                **ns._instr.result_blocks(),  # instrumentation + top-level costs (AR-10 P3)
            }

        if ns.stop_on_confirm and _early_confirmed:
            # Objective mode has reached its independently verified success
            # condition. Return the evidence now; continuing through chaining,
            # coverage driving, and broad model review can consume minutes and
            # cause the outer wall-clock guard to discard an already-confirmed
            # result as a timeout.
            return _objective_result(True)
        if ns.stop_on_confirm and ns.objective_class:
            # A class-scoped benchmark is a bounded deterministic measurement.
            # If none of its eligible request shapes confirms, preserve that
            # negative result instead of silently changing the experiment into
            # an open-ended model review of unrelated vulnerability classes.
            return _objective_result(False)
        ns._instr.phases.begin("capture_review")
        # The review taken up while the model sat idle stops here (its capture in flight
        # finishes): this pass reviews only what it left, within what it left of the
        # review limit and time budget.
        _main_limit = self.capture_review_limit
        _review_seconds = float(self.capture_review_seconds)
        if ns._idle_review is not None:
            await ns._idle_review.drain()
            if ns._idle_review.error:
                ns._errors.append({"phase": "capture_review", "error": ns._idle_review.error})
            _main_limit = max(0, self.capture_review_limit - ns._idle_review.reviewed)
            if _review_seconds > 0:
                _review_seconds = max(0.0, _review_seconds - ns._idle_review.busy_seconds)
        # One review time budget covers this pass and every chain round's pass.
        ns._review_deadline = (time.monotonic() + _review_seconds
                               if self.capture_review_seconds > 0 else None)
        if ns._investigation_deadline is not None:
            ns._review_deadline = min(ns._review_deadline or ns._investigation_deadline,
                                      ns._investigation_deadline)
        _review_budget = ns._review_deadline
        # phase_slices: review gets its share of what is left, so the chain rounds
        # after it are not starved; an explicit capture_review_seconds still binds.
        ns._review_deadline = ns._schedule.deadline_for("capture_review", ns._review_deadline)
        ns._instr.phases.set_budget("capture_review", ns._budget_left(ns._review_deadline))
        # engagement.review_overlap: when that share would stop a model-bound review
        # short of its own deadline, the review keeps going in the background while
        # the request-bound phases below send theirs, and is drained before the retry
        # rounds (harness/review_overlap.py). Otherwise it runs inline as before.
        ns._overlap = None
        if not (ns.stop_on_confirm and _early_confirmed):
            if (ns._review_deadline is not None
                    and (_review_budget is None or ns._review_deadline < _review_budget)
                    and review_overlap.enabled(self.config)
                    and review_overlap.review_uses_model(self)):
                _main_batch = list(ns._all_captured)

                async def _overlap_review(captured, **bounds):
                    # This pass's batch shares the idle review's limit and content
                    # groups; a chain round's batch is its own call, as before.
                    main = captured is _main_batch
                    return await review_captured_exchanges(
                        self, ns.state, captured, run_context=ns.run_context,
                        seen=ns._reviewed_captures, errors=ns._errors, stats=ns._review_stats,
                        max_reviews=_main_limit if main else self.capture_review_limit,
                        groups=_review_groups if main else None,
                        **bounds, **ns._review_kwargs)

                ns._overlap = review_overlap.ReviewOverlap(
                    _overlap_review, deadline=_review_budget).start(_main_batch)
                await ns._overlap.hold(ns._review_deadline)
            else:
                await review_captured_exchanges(
                    self, ns.state, ns._all_captured, run_context=ns.run_context,
                    seen=ns._reviewed_captures, errors=ns._errors, stats=ns._review_stats,
                    max_reviews=_main_limit, deadline=ns._review_deadline,
                    groups=_review_groups, **ns._review_kwargs)
                ns._journal_phase("review")

        # R19: supply link_findings the RESPONSE MAP it needs to detect a leaked
        # credential (url -> {headers, body}), built from the real captured
        # exchanges. Without it the closed loop was starved -- no response body was
        # ever inspected, so a leaked bearer/cookie never triggered a re-test.
        def _responses_from(captures) -> dict:
            out: dict = {}
            for cap in captures or []:
                try:
                    ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
                except Exception:
                    continue
                out[ex.url] = {"headers": dict(ex.response_headers or {}),
                               "body": ex.response_body or ""}
            return out
        ns._responses_from = _responses_from

        ns._responses: dict = _responses_from(getattr(ns.rc, "captured", None))
        try:
            ns._responses.update(_responses_from(ns.feature_caps))
        except NameError:
            pass

    async def _engagement_stage_rounds(self, ns):
        """Chain rounds (re-test as a credential a finding leaked) and second-order
        auto-confirmation."""
        from harness import chain_linker
        from harness import engagement_builder
        from harness import role_crawl
        ns._instr.phases.begin("chain_rounds")
        # Milestone C: link findings into escalation edges + composed chains, then
        # walk the closed loop -- re-test AS any credential a finding leaked.
        link = chain_linker.link_findings(ns.state, ns.all_findings, responses=ns._responses)
        ns.chains = list(link["chain_findings"])
        creds, ns.rounds, seen_ident = link["credential_caps"], 0, set()
        _chain_deadline = ns._schedule.deadline_for("chain_rounds", ns._investigation_deadline)
        ns._instr.phases.set_budget("chain_rounds", ns._budget_left(_chain_deadline))
        while creds and ns.rounds < ns.max_chain_rounds:
            if _chain_deadline is not None and time.monotonic() >= _chain_deadline:
                ns._errors.append({"phase": "chain_rounds",
                                   "error": f"investigation time budget reached: chain round "
                                         f"{ns.rounds + 1} of up to {ns.max_chain_rounds} not started"})
                break
            ns.rounds += 1
            derived = [role_crawl.RoleSession(role="anonymous", headers={})]
            for c in creds:
                ident = f"{c.get('kind')}@{c.get('source_url')}"
                if ident in seen_ident:
                    continue
                if await self._credential_grants_access(c.get("source_url", ns.base_url), c.get("headers", {})):
                    derived.append(role_crawl.RoleSession(role="derived", headers=c.get("headers", {})))
                    seen_ident.add(ident)
            if len(derived) < 2:
                break
            st2, rc2 = await engagement_builder.build_engagement(
                ns.base_url, derived, allowed_hosts=self.allowed_hosts,
                crawl_max_pages=ns.discovery_max_pages,
                max_endpoints=ns.discovery_max_endpoints,
                active_discovery=ns.active_discovery,
                discovery_max_probes=ns.discovery_max_probes, run_context=ns.run_context,
                **self._discovery_ffuf_kw(), **self._discovery_recursion_kw())
            outs2, new_findings = await ns._investigate(st2, derived, deadline=_chain_deadline)
            _review_round = not (ns.stop_on_confirm and any(f.get("confirmed") for f in new_findings))
            _round_in_background = _review_round and ns._overlap is not None and ns._overlap.accepting
            if _review_round and not _round_in_background:
                await review_captured_exchanges(
                    self, st2, getattr(rc2, "captured", None), run_context=ns.run_context,
                    seen=ns._reviewed_captures, errors=ns._errors, stats=ns._review_stats,
                    max_reviews=self.capture_review_limit, deadline=ns._review_deadline,
                    **ns._review_kwargs)
            ns.outcomes.extend(outs2)
            ns.all_findings.extend(new_findings)
            # R19: merge the derived-identity state back into the primary state, so
            # the surface + findings reachable ONLY as the leaked credential appear
            # in the final summary/worklist/coverage/report -- not just in a local
            # list. Also feed the re-crawl's responses into credential detection.
            ns.state.merge_from(st2)
            if ns.run_context is not None and getattr(ns.state, "client_routes", None) is not None:
                ns.run_context.client_routes = ns.state.client_routes
            if _round_in_background:   # reviewed into the merged state, in the background
                ns._overlap.extend(list(getattr(rc2, "captured", None) or []))
            ns._responses.update(ns._responses_from(getattr(rc2, "captured", None)))
            link = chain_linker.link_findings(ns.state, ns.all_findings, responses=ns._responses)
            ns.chains = list(link["chain_findings"])
            creds = link["credential_caps"]
        ns._journal_phase("chain")

        ns._instr.phases.begin("second_order")
        # Second-order auto-confirmation (V22 SQLi / V17 IDOR): actively run the
        # plant->trigger differential over each composed (A,B) pair. The plant is a
        # mutating write, so this is gated on allow_mutating_replay; inert by
        # default. Confirmed pairs fold in as confirmed findings.
        try:
            import json as _json
            import harness.chaining as _chaining
            import harness.second_order as _so
            from harness.safety_gate import get_default_gate as _gg2
            if _gg2().config.allow_mutating_replay:
                _MARK_FIELDS = ("q", "name", "value", "comment", "data", "note", "subject", "title")
                # R13: plant AS an authenticated attacker/owner (never anonymously),
                # and read AS the appropriate identity -- the planter for the SQLi
                # differential, a DISTINCT identity for the cross-identity IDOR read.
                _plant_headers, _other_headers = second_order_identities(ns.roles)
                _plant_send_headers = dict(_plant_headers)
                _plant_send_headers.setdefault("Content-Type", "application/json")

                async def _plant(a_url, marker, case_ref=""):
                    await global_throttle.acquire()
                    body = _json.dumps({f: marker for f in _MARK_FIELDS})
                    # ARCH-2: the plant travels the owning run's ONE TargetTransport
                    # (scope + gate + request budget + evidence, under the run's TLS
                    # trust), exactly like the read below -- never a separate
                    # verify=False client that bypassed central accounting and trust.
                    try:
                        out = await _so.send_through_run(
                            ns.run_context, "POST", a_url, allowed_hosts=self.allowed_hosts,
                            config=self.config, capability="second_order_plant",
                            headers=_plant_send_headers, body=body, case_ref=case_ref)
                    except Exception as e:
                        log.debug("second_order plant to %s failed: %s", a_url, e)
                        return False
                    # R13: a failed write is surfaced, not silently swallowed -- the
                    # confirmation must not proceed as if the value was stored. A
                    # blocked/budget/scope/cancelled outcome (out.ok False) or a non-2xx/3xx
                    # status is NOT a successful plant.
                    if not (out.ok and out.status is not None and 200 <= out.status < 400):
                        log.debug("second_order plant to %s returned %s/%s", a_url,
                                  out.outcome, out.status)
                        return False
                    return True

                async def _read(b_url, headers=None, case_ref=""):
                    await global_throttle.acquire()
                    # default the read identity to the PLANTER (so the SQLi differential
                    # reads its own stored value back); a cross-identity read passes the
                    # other identity explicitly.
                    hdrs = _plant_headers if headers is None else headers
                    hdrs = {k: v for k, v in (hdrs or {}).items() if (k or "").lower() != "content-type"}
                    # W-16/ARCH-2: second-order read through the single TargetTransport
                    # (this run's when present, else standalone), sharing the plant's
                    # case_ref so per-case accounting cannot be sidestepped.
                    try:
                        out = await _so.send_through_run(
                            ns.run_context, "GET", b_url, allowed_hosts=self.allowed_hosts,
                            config=self.config, capability="second_order_read",
                            headers=hdrs, case_ref=case_ref)
                        return (out.body or "") if out.ok else ""
                    except Exception:
                        return ""

                async def _confirm_sqli(a_url, b_url):
                    # ARCH-2: one stable case ref ties the plant and the trigger-read
                    # of THIS pair together, so per-case budget/evidence cannot be
                    # bypassed by omitting the case identity on either leg.
                    cr = f"second_order_sqli:{a_url}=>{b_url}"
                    return await _so.confirm_second_order_sqli(
                        plant=lambda m: _plant(a_url, m, case_ref=cr),
                        trigger=lambda: _read(b_url, case_ref=cr))

                async def _confirm_idor(a_url, b_url):
                    if not _other_headers:
                        # No DISTINCT second identity -> a cross-identity read would be a
                        # self-comparison. Do not fake-confirm (R13/R10).
                        return _so.SecondOrderResult(
                            confirmed=False,
                            reason="no distinct second identity configured for a cross-identity "
                                   "second-order IDOR read (would be a self-comparison)")
                    cr = f"second_order_idor:{a_url}=>{b_url}"
                    return await _so.confirm_second_order_idor(
                        plant=lambda m: _plant(a_url, m, case_ref=cr),
                        read_as_other=lambda: _read(b_url, _other_headers, case_ref=cr))

                _cands = _chaining.second_order_candidates(ns.all_findings)
                _confirmed_so = await _so.auto_confirm_candidates(
                    _cands, confirm_sqli=_confirm_sqli, confirm_idor=_confirm_idor,
                    is_allowed=lambda u: scope_discovery.is_host_allowed(u, self.allowed_hosts))
                for cf in _confirmed_so:
                    ns.all_findings.append(cf)
                    ns.state.ingest_findings(cf["url"], "GET", [cf])
                # Discovery-driven chain candidates (R14): POST-that-stores +
                # GET-that-renders pairs from the raw capture surface, catching
                # chains the finding-based path misses. TYPED ROUTING: each pair is
                # sent to the oracle its kind actually supports, never force-routed
                # to SQLi. auto_confirm_candidates only has the boolean-SQLi and
                # cross-identity oracles; a single-identity write->json-read pair
                # fits the boolean-SQLi differential (as second_order_sqli), while
                # an html-read (stored-XSS) pair is left to the stored_xss leg, not
                # fake-confirmed here. Source the exchanges from the REAL capture
                # store (rc.captured + feature_caps), not the never-populated
                # state.captured_exchanges.
                _all_exchanges = list(getattr(ns.rc, "captured", None) or [])
                try:
                    _all_exchanges.extend(ns.feature_caps)
                except NameError:
                    pass
                _disc_cands = _chaining.discovery_chain_candidates(_all_exchanges)
                _existing_pairs = {(c["a"].get("url"), c["b"].get("url")) for c in _cands}
                _disc_as_so = []
                for dc in _disc_cands:
                    if dc.get("kind") != "second_order":
                        continue  # stored_xss -> stored_xss leg, not the sqli/idor oracles
                    if (dc["write_url"], dc["read_url"]) in _existing_pairs:
                        continue
                    _disc_as_so.append({
                        "signature": "second_order_sqli",
                        "kind": "sqli",
                        "a": {"url": dc["write_url"], "vulnerability_class": "stored_write",
                              "summary": f"write at {dc['write_url']}"},
                        "b": {"url": dc["read_url"], "vulnerability_class": "sqli",
                              "summary": f"read at {dc['read_url']}"},
                    })
                if _disc_as_so:
                    _disc_confirmed = await _so.auto_confirm_candidates(
                        _disc_as_so, confirm_sqli=_confirm_sqli, confirm_idor=_confirm_idor,
                        is_allowed=lambda u: scope_discovery.is_host_allowed(u, self.allowed_hosts))
                    for cf in _disc_confirmed:
                        ns.all_findings.append(cf)
                        ns.state.ingest_findings(cf["url"], "GET", [cf])
        except Exception as e:  # auto-confirm is additive -- never sink the run
            log.warning("investigate_engagement: second-order auto-confirm failed: %s", e)
            ns._errors.append({"phase": "second_order_auto_confirm", "error": f"{type(e).__name__}: {e}"})

        # Flag-only hand-off: an UNCONFIRMED finding whose class has no automated
        # leg (and isn't business-logic, which has its own richer hand-off) is
        # surfaced as a BLOCKED human-verification task -- reported-not-verified,
        # never fabricated as confirmed and never dropped. This is the honest
        # disposition for the no-leg classes (V2/V37 and any other).
        for f in ns.all_findings:
            if f.get("confirmed"):
                continue
            url = f.get("url") or ""
            vc = f.get("vulnerability_class") or ""
            if not url or not vc:
                continue
            if not ns.state.flag_business_logic(vc, url):
                ns.state.flag_unconfirmable(vc, url)
