"""orchestrator_chain_finish.py -- Stage 6 of investigate_engagement: the follow-up passes and result assembly.

ARC-9 split of the old 2,600-line `investigate_engagement`: the body moved verbatim, cut at
top-level statements. A local that more than one stage touches is an attribute of the shared
`EngagementRun` (`ns`, built by the driver in orchestrator_chain.py); a stage that finishes
the run early returns the result, otherwise None."""
from __future__ import annotations

import asyncio
import time

from harness.circuit_breaker import get_ollama_circuit_breaker
from harness.orchestrator_helpers import log
from harness.orchestrator_review import review_captured_exchanges


class ChainFinishMixin:
    async def _engagement_stage_finish(self, ns):
        """After the drive: server-error follow-up, retry rounds, final pass, the final experiment
        pass, and result assembly (the engagement result dict is returned)."""
        from harness import final_pass as _final_pass_mod
        from harness.ollama_client import context_window_error
        from harness import coverage_tracker
        from harness.assessment_health import new_review_stats
        from harness import retry_rounds
        from harness import worklist_investigator
        # engagement.server_errors (harness/server_errors.py): the 5xx answers this run's
        # own sends drew. A stack trace is a confirmed disclosure; a database error is an
        # injection lead, and up to max_lead_confirmations leads go to the leg for their
        # class with the route's captured template. Runs here and again after the retry
        # rounds, for the errors their sends drew.
        _se_cfg = ((self.config.get("engagement") or {}).get("server_errors") or {})
        _server_error_report: dict = {"enabled": bool(_se_cfg.get("enabled", True)),
                                      "findings": 0, "leads": 0, "leads_dispatched": 0,
                                      "leads_confirmed": 0, "leads_not_dispatched": {}}
        _server_error_done: dict = {}   # finding key -> confirmed, as ingested

        def _server_error_exchange(method, url, lead):
            """The route's captured template as its lowest-trust reaching identity. A
            query parameter the lead names but the template lacks gets a neutral value."""
            from urllib.parse import parse_qsl, urlencode, urlsplit
            from harness.engagement import normalize_path
            ep = ns.state.endpoints.get(f"{method.upper()} {normalize_path(url)}")
            if ep is None:
                return None
            node = ep.to_dict()
            reach = node.get("reachable_roles") or []
            role = min(reach, key=worklist_investigator._trust) if reach else None
            ident = next((r for r in ns.roles if r.role == role), None)
            ex = worklist_investigator._seed_exchange(
                ns.base_url, node, dict(getattr(ident, "headers", None) or {}), "1")
            name = lead.get("parameter_name")
            if lead.get("parameter_location") == "query" and name and name not in {
                    k for k, _ in parse_qsl(urlsplit(ex.url).query, keep_blank_values=True)}:
                ex.url += ("&" if "?" in ex.url else "?") + urlencode({name: "1"})
            return ex

        async def _server_error_pass() -> int:
            ledger = getattr(ns.run_context, "server_errors", None) if ns.run_context is not None else None
            if ledger is None or not _server_error_report["enabled"]:
                return 0
            max_leads = int(_se_cfg.get("max_lead_confirmations", 0) or 0)
            skipped = _server_error_report["leads_not_dispatched"]
            changed = 0
            for f in ledger.findings():
                method = f.pop("method", "GET")
                key = f"{method} {f['url']} {f['vulnerability_class']}"
                if key in _server_error_done:
                    continue
                if not f.get("confirmed"):
                    _server_error_report["leads"] += 1
                    reason = ("max_lead_confirmations"
                              if _server_error_report["leads_dispatched"] >= max_leads
                              else "cancelled" if (ns.run_context is not None
                                                   and ns.run_context.cancel.cancelled)
                              else "deadline" if (ns._investigation_deadline is not None
                                                  and time.monotonic() >= ns._investigation_deadline)
                              else "")
                    exchange = None if reason else _server_error_exchange(method, f["url"], f)
                    if exchange is None:
                        reason = reason or "no_endpoint"
                        skipped[reason] = skipped.get(reason, 0) + 1
                    else:
                        _server_error_report["leads_dispatched"] += 1
                        try:
                            await ns._confirm(f, exchange)
                        except Exception as e:  # a lead stays a lead
                            log.debug("server-error lead on %s: %s", f["url"], e)
                        _server_error_report["leads_confirmed"] += int(bool(f.get("confirmed")))
                _server_error_report["findings"] += 1
                _server_error_done[key] = bool(f.get("confirmed"))
                ns.state.ingest_findings(f["url"], method, [f])
                ns.all_findings.append(dict(f, method=method))
                changed += 1
            return changed

        _server_error_changed = 0
        try:
            _server_error_changed += await _server_error_pass()
        except Exception as e:  # a report layer plus bounded legs -- never sink the run
            log.warning("investigate_engagement: server-error follow-up failed: %s", e)
            ns._errors.append({"phase": "server_errors", "error": f"{type(e).__name__}: {e}"})

        # The request-bound phases are over: a background capture review stops taking
        # captures (the one in flight finishes); the retry rounds review what is left.
        if ns._overlap is not None:
            await ns._overlap.drain()
            if ns._overlap.error:
                ns._errors.append({"phase": "capture_review", "error": ns._overlap.error})
            ns._journal_phase("review")

        # engagement.retry_rounds: until reserve_seconds before the deadline, sweep the
        # worklist and review captures again with growing budgets, for the nodes and
        # captures earlier passes left (harness/retry_rounds.py). Off by default.
        if ns._retry_ledger is not None:
            ns._instr.phases.begin("retry_rounds", budget_s=ns._budget_left(
                ns._investigation_deadline - ns._retry_cfg.reserve_seconds))

            async def _retry_sweep(budgets, deadline):
                summary: dict = {}
                outs = await worklist_investigator.investigate_worklist(
                    ns._probe, ns.state, ns.base_url, ns.roles, confirm_fn=ns._confirm,
                    precondition_fn=ns._precondition, max_nodes=budgets["max_nodes"],
                    step_budget=budgets["step_budget"],
                    max_precondition_legs=budgets["max_precondition_legs"],
                    summary_out=summary, stop_on_confirm=ns.stop_on_confirm, deadline=deadline,
                    **ns._retry_ledger.sweep_kwargs())
                fresh = [o for o in outs if not o.get("resumed")]
                ns.outcomes.extend(fresh)
                ns.all_findings.extend(f for o in fresh for f in o.get("findings_detail", []))
                return fresh, summary

            async def _retry_review(budgets, deadline):
                stats = new_review_stats()
                produced = await review_captured_exchanges(
                    self, ns.state, ns._all_captured, run_context=ns.run_context,
                    seen=ns._reviewed_captures, errors=ns._retry_report.setdefault("errors", []),
                    stats=stats, max_reviews=budgets["max_reviews"], deadline=deadline,
                    **ns._review_kwargs)
                return stats["reviewed"], produced

            try:
                ns._retry_report.update(await retry_rounds.run_retry_rounds(
                    ns._retry_cfg, ns._retry_ledger, deadline=ns._investigation_deadline,
                    base_budgets={"max_nodes": ns.max_nodes, "step_budget": ns.step_budget,
                                  "max_precondition_legs": ns._max_precondition_legs,
                                  "max_reviews": self.capture_review_limit},
                    sweep=_retry_sweep, review=_retry_review, reviewed=ns._reviewed_captures,
                    cancelled=lambda: bool(ns.run_context is not None
                                           and ns.run_context.cancel.cancelled)))
            except Exception as e:  # extra rounds are a bonus -- never sink the run
                log.warning("investigate_engagement: retry rounds failed: %s", e)
                ns._errors.append({"phase": "retry_rounds", "error": f"{type(e).__name__}: {e}"})
            log.info("investigate_engagement: retry rounds -- %d round(s), stopped by %s",
                     len(ns._retry_report.get("rounds") or []), ns._retry_report.get("stopped_by"))

        # R11-4 engagement.final_pass: with time left before the deadline (less its
        # reserve for finalise), one pass in priority order over the worklist nodes a
        # budget skipped, the drive legs never attempted and the replays the
        # per-endpoint share held (harness/final_pass.py). Every leg goes through the
        # same dispatch, gates and caps as before; the pass only reuses time.
        if ns._final_cfg.enabled and ns._final_ledger is not None:
            _final_stop_at = ns._investigation_deadline - ns._final_cfg.reserve_seconds
            ns._instr.phases.begin("final_pass", budget_s=ns._budget_left(_final_stop_at))
            _final_rounds = len(ns._retry_report.get("rounds") or [])

            def _final_cancelled():
                return bool(ns.run_context is not None and ns.run_context.cancel.cancelled)

            async def _final_worklist_nodes(stop_at):
                last = (ns._retry_report.get("rounds") or [None])[-1]
                by_reason = (last if last is not None
                             else (ns.worklist_summary.get("skipped_by_reason") or {}))
                left = (by_reason.get("budget_exhausted", 0) or 0) + (by_reason.get("time_budget", 0) or 0)
                unsettled = len(ns._final_ledger.outcomes) - len(ns._final_ledger.settled())
                if not left and not unsettled:
                    return None
                budgets = retry_rounds.round_budgets(
                    {"max_nodes": ns.max_nodes, "step_budget": ns.step_budget,
                     "max_precondition_legs": ns._max_precondition_legs}, ns._retry_cfg, _final_rounds + 1)
                summary: dict = {}
                outs = await worklist_investigator.investigate_worklist(
                    ns._probe, ns.state, ns.base_url, ns.roles, confirm_fn=ns._confirm,
                    precondition_fn=ns._precondition, max_nodes=budgets["max_nodes"],
                    step_budget=budgets["step_budget"],
                    max_precondition_legs=budgets["max_precondition_legs"],
                    summary_out=summary, stop_on_confirm=ns.stop_on_confirm, deadline=stop_at,
                    **ns._final_ledger.sweep_kwargs())
                fresh = [o for o in outs if not o.get("resumed")]
                for o in fresh:
                    o["final_pass"] = True
                ns.outcomes.extend(fresh)
                ns.all_findings.extend(f for o in fresh for f in o.get("findings_detail", []))
                skipped = summary.get("skipped_by_reason") or {}
                return {"budgets": budgets, "skipped_before": left, "ran": len(fresh),
                        "settled": sum(1 for o in fresh if retry_rounds.is_settled(o)),
                        "findings": sum(len(o.get("findings_detail") or []) for o in fresh),
                        "budget_exhausted": skipped.get("budget_exhausted", 0),
                        "time_budget": skipped.get("time_budget", 0)}

            async def _final_drive_legs(stop_at):
                if not ns._drive_hooks or not ns._coverage_trackers:
                    return None
                tracker = ns._coverage_trackers[-1]
                if not (tracker.queued - tracker.attempted):
                    return None
                used = ns.coverage.get("cases_driven" if ns._drive_hooks["case_mode"] else "legs_driven") or 0
                budget_left = max(0, int(self.coverage_leg_budget) - int(used))
                if budget_left <= 0:
                    return {"stopped_by": "leg budget", "dispatches": 0,
                            "queued_not_attempted": len(tracker.queued - tracker.attempted)}
                return await tracker.drive_remaining(
                    ns._drive_hooks["run_leg"], case_mode=ns._drive_hooks["case_mode"], budget=budget_left,
                    deadline=stop_at, field_cap=self.coverage_parameter_field_cap)

            async def _final_held_replays(stop_at):
                if not ns._held_cells or not ns._coverage_trackers:
                    return None
                tracker = ns._coverage_trackers[-1]
                cells = len(ns._held_cells)
                replays = sum(e["replays"] for e in ns._held_cells.values())
                # Each (endpoint, check) held gets its share again, for this pass.
                for entry in ns._held_cells.values():
                    ns._drive_hooks["spent"][entry["share_key"]] = 0.0
                ns._held_pass.update(active=True, stop_at=stop_at)
                ran = confirmed = 0
                stopped = None
                try:
                    for key in list(ns._held_cells):
                        if _final_cancelled():
                            stopped = "cancelled"
                            break
                        if time.monotonic() >= stop_at:
                            stopped = "deadline"
                            break
                        entry = ns._held_cells[key]
                        ep_key = f"{entry['method']} {entry['path']}"
                        res = await ns._run_leg_core(entry["identity"], entry["method"], entry["path"],
                                                     entry["check"], entry["case_key"],
                                                     remainder_only=entry["remainder_only"])
                        tracker.record_held_result(entry["identity"], ep_key, entry["check"],
                                                   entry["case_key"], res)
                        ran += 1
                        confirmed += bool(res is not None and res.confirmed)
                finally:
                    ns._held_pass.update(active=False, stop_at=None)
                return {"cells": cells, "replays": replays, "cells_run": ran, "confirmed": confirmed,
                        "cells_still_held": len(ns._held_cells),
                        "replays_still_held": sum(e["replays"] for e in ns._held_cells.values()),
                        "stopped_by": stopped}

            try:
                ns._final_report = await _final_pass_mod.run_final_pass(
                    ns._final_cfg, deadline=ns._investigation_deadline,
                    steps={"worklist_nodes": _final_worklist_nodes,
                           "drive_legs": _final_drive_legs,
                           "held_replays": _final_held_replays},
                    cancelled=_final_cancelled, clock=time.monotonic)
            except Exception as e:  # the pass is a bonus -- never sink the run
                log.warning("investigate_engagement: final pass failed: %s", e)
                ns._errors.append({"phase": "final_pass", "error": f"{type(e).__name__}: {e}"})
            for _step in ns._final_report.get("steps") or []:
                if _step.get("error"):
                    ns._errors.append({"phase": f"final_pass.{_step['step']}", "error": _step["error"]})
            if ns.coverage and ns._coverage_trackers and any(
                    _step.get("result") and _step["step"] in ("drive_legs", "held_replays")
                    for _step in ns._final_report.get("steps") or []):
                try:
                    ns.coverage = coverage_tracker.report_after_final_pass(
                        ns._coverage_trackers[-1], ns.coverage, investigated_keys=ns.investigated_keys,
                        final_pass={_step["step"]: _step.get("result")
                                    for _step in ns._final_report.get("steps") or []})
                except Exception as e:  # coverage is a report layer -- never sink the run
                    log.warning("investigate_engagement: coverage after final pass failed: %s", e)
                    ns._errors.append({"phase": "coverage_refresh",
                                       "error": f"{type(e).__name__}: {e}"})
            log.info("investigate_engagement: final pass -- %d step(s), stopped by %s",
                     len(ns._final_report.get("steps") or []), ns._final_report.get("stopped_by"))
        _final_ran = bool(ns._final_report.get("steps"))

        if ((ns._retry_ledger is not None and ns._retry_report.get("rounds")) or ns._overlap is not None
                or _final_ran):
            try:   # the server errors the rounds' (or the background review's) sends drew
                _server_error_changed += await _server_error_pass()
            except Exception as e:
                log.warning("investigate_engagement: server-error follow-up failed: %s", e)
                ns._errors.append({"phase": "server_errors", "error": f"{type(e).__name__}: {e}"})
        if ns.run_context is not None and _server_error_report["enabled"]:
            _server_error_report["ledger"] = ns.run_context.server_errors.report()
        # The matrix was built before the rounds and the server-error follow-up (and
        # while a background review was still running): record what they found into it.
        if ns.coverage and (_server_error_changed or ns._overlap is not None or _final_ran
                            or (ns._retry_ledger is not None and ns._retry_report.get("rounds"))):
            try:
                if ns._coverage_trackers:
                    ns.coverage = coverage_tracker.refresh_after_retry_rounds(
                        ns._coverage_trackers[-1], ns.coverage, ns.state, ns.roles,
                        investigated_keys=ns.investigated_keys)
                elif not ns.coverage.get("legs_driven"):   # the passive matrix: rebuild it
                    ns.coverage = coverage_tracker.build_coverage(
                        ns.state, ns.roles, investigated_keys=ns.investigated_keys)
            except Exception as e:  # coverage is a report layer -- never sink the run
                log.warning("investigate_engagement: coverage refresh failed: %s", e)
                ns._errors.append({"phase": "coverage_refresh",
                                   "error": f"{type(e).__name__}: {e}"})

        # AR-FP: the bounded final re-evaluation of experiment tasks over the values
        # and sessions every later phase left, before proofs are projected and the
        # dispositions taken. Best-effort like the experiments phase.
        # R11-4b: bounded by the coverage stage's deadline AND the investigation
        # deadline less the finalise reserve (engagement.final_pass.reserve_seconds,
        # read whether the final pass is on or not). Before, it took the coverage
        # deadline alone: with no coverage_drive_seconds it ran unbounded, and the
        # coverage deadline (not clamped to the investigation deadline) could let it
        # run into finalise's reserve or past the run's deadline. Once that bound has
        # passed (the retry rounds and final pass run past the coverage deadline), the
        # phase is recorded as skipped, with why; the pass then only re-evaluates and
        # marks the READY tasks deferred ("stage deadline reached") -- nothing is sent.
        _exp_final_bounds = [(d, why) for d, why in (
            (ns._coverage_deadline, "the coverage stage's deadline has passed"),
            (None if ns._investigation_deadline is None
             else ns._investigation_deadline - ns._final_cfg.reserve_seconds,
             "the investigation deadline less the finalise reserve "
             f"({ns._final_cfg.reserve_seconds:.0f} s) has passed")) if d is not None]
        _exp_final_stop_at, _exp_final_why = min(_exp_final_bounds, key=lambda b: b[0],
                                                 default=(None, None))
        _exp_final_skipped = (_exp_final_why if _exp_final_stop_at is not None
                              and time.monotonic() >= _exp_final_stop_at else None)
        if _exp_final_skipped:
            ns._instr.phases.skip("experiments_final", _exp_final_skipped)
        else:
            ns._instr.phases.begin("experiments_final")
            ns._instr.phases.set_budget("experiments_final", ns._budget_left(_exp_final_stop_at))
        _experiment_final_pass = None
        try:
            _experiment_final_pass = await self._final_experiment_pass(
                ns.state, ns._asm, ns.run_context, base_url=ns.base_url, captured=ns._all_captured,
                ownership=ns.ownership, deadline=_exp_final_stop_at)
        except Exception as e:
            log.warning("investigate_engagement: final experiment pass failed: %s", e)
            ns._errors.append({"phase": "experiments_final", "error": f"{type(e).__name__}: {e}"})
        if _exp_final_skipped and isinstance(_experiment_final_pass, dict):
            _experiment_final_pass["skipped"] = _exp_final_skipped

        from harness.experiment import project_proofs
        try:
            _experiment_projection = project_proofs(ns.state, ns.run_context)
        except Exception as exc:
            ns._errors.append({"phase":"experiment_projection", "error":type(exc).__name__})
            _experiment_projection = {"cases":[{"status":"unresolved", "reason":"experiment projection unavailable"}], "findings":[]}
        ns.coverage["experiment_cases"] = _experiment_projection["cases"]
        # r5: write operations the surface named but the run never sent, with why
        # (gate policy or path guard), so they are listed rather than omitted.
        ns.coverage["withheld_operations"] = list(getattr(ns.rc, "withheld_operations", None) or [])
        from harness.experiment import task_dispositions
        _experiment_dispositions = task_dispositions(ns.state, ns.run_context,
            enabled=bool(self._experiments_config().get('enabled', False)),
            max_runs=int(self._experiments_config().get('max_runs', 4)),
            planner_enabled=bool(self._experiments_config().get('planner',False)))
        ns._instr.phases.begin("finalise")
        # RB-5/INV-3: re-link chains over the FINAL findings set. The passes at
        # ~741/771 above (kept as-is, not removed) compute `chains` from
        # `all_findings` as it stood BEFORE the second-order auto-confirm phase
        # (~782-897) and the coverage-driven phase (~921-1012) run -- both of
        # which append NEW confirmed findings straight into `all_findings`/`state`
        # (`all_findings.append(cf)` + `state.ingest_findings(...)`) without
        # re-linking. A multi-step chain whose second constituent only confirms in
        # one of those later phases was therefore silently absent from the
        # returned `chains` (the SCORECARD "0 chains ... did not reproduce" gap,
        # INV-3). `all_findings` is append-only across every phase above, so
        # recomputing the link over the now-final superset can only ADD chains a
        # later-phase confirmation newly enables -- it never drops or mutates a
        # chain the 741/771 passes already linked, and it makes NO confirmation/
        # severity/scope decision itself (`_relink_chains` is a pure recompute over
        # already-decided findings). Best-effort, mirroring the coverage-build
        # phase just above: a late linking error must never sink the whole
        # engagement result, so on failure the prior `chains` snapshot is kept
        # unchanged.
        try:
            ns.chains = self._relink_chains(ns.state, ns.all_findings, ns._responses)
        except Exception as e:
            log.debug("investigate_engagement: final chain re-link failed: %s", e)
            ns._errors.append({"phase": "final_chain_relink", "error": f"{type(e).__name__}: {e}"})

        # B2-1: if the shared ollama circuit breaker is OPEN at result assembly,
        # agent/model calls made during this engagement short-circuited without
        # hitting the model -- reuse the existing errors -> degraded contract
        # (R30 above) rather than adding a parallel degraded signal. Best-effort:
        # must never sink the run.
        try:
            if get_ollama_circuit_breaker("ollama").is_open:
                ns._errors.append({"phase": "circuit_breaker",
                                 "error": "ollama circuit breaker is OPEN: agent calls "
                                          "may have short-circuited during this engagement"})
        except Exception as e:
            log.debug("investigate_engagement: circuit breaker check failed: %s", e)
        # Model calls that did not fit the context window had their replies
        # discarded: the same errors -> degraded contract.
        _context_error = context_window_error(self.ollama, ns._truncated_before)
        if _context_error:
            ns._errors.append(_context_error)

        from harness.assessment_health import assessment_health
        try:
            from harness.engagement import persist_surface
            await asyncio.to_thread(persist_surface, ns.state)
        except Exception as exc:
            ns._errors.append({"phase": "surface_persistence", "error": type(exc).__name__})
        health = assessment_health(ns.coverage, ns._errors)
        return {
            "assessment": health,
            "findings": [dict(f, url=f.get("url") or ep.path, method=ep.method)
                         for ep in ns.state.endpoints.values() for f in ep.findings] + _experiment_projection["findings"],
            **ns._resume_report(),
            "summary": ns.state.summary(),
            "worklist": ns.state.result_worklist(50),
            "outcomes": ns.outcomes,
            # 2026-09-17 coverage-recovery plan, Step 2: eligible/investigated
            # counts + a named, reasoned list of every eligible node this run did
            # NOT reach (budget_exhausted/unreachable/missing_template/
            # policy_blocked). A run must not be called "max coverage" if
            # skipped_by_reason shows eligible high-priority nodes were skipped.
            "worklist_summary": ns.worklist_summary,
            "chains": ns.chains,
            "chain_rounds": ns.rounds,
            # Crawl loop: what re-crawl rounds took from the route feed, the time each
            # sliced phase was granted, and the run's session refresh/stale events.
            "crawl_loop": {
                "per_principal": ns._per_principal,
                "spa_views": getattr(ns.rc, "spa_views", None) or [],
                "form_templates": getattr(ns.rc, "form_templates", None),
                "recrawl": ns._recrawl_report,
                "phase_schedule": ns._schedule.report() if ns._schedule.active else None,
                "review_overlap": ns._overlap.report() if ns._overlap is not None else None,
                "idle_review": ns._idle_review.report() if ns._idle_review is not None else None,
                "retry_rounds": ns._retry_report,
                # R11-4: the final pass over the work the phase budgets left.
                "final_pass": ns._final_report,
                "session_events": list(getattr(ns.run_context.freshness(), "events", []) or [])
                                  if ns.run_context is not None and hasattr(ns.run_context, "freshness") else [],
            },
            # P2-1: the Application Semantic Model built this run (None when the
            # business-context pass is off), so the API/report can show the
            # inferred roles/objects/workflows/value-flows/sinks and the ranked
            # chaining hypotheses that drove the re-ranking.
            # engagement.server_errors: the 5xx answers this run's own sends drew, and
            # the disclosures and injection leads followed up from them.
            "server_errors": _server_error_report,
            "application_semantic_model": ns._asm.to_dict() if ns._asm else None,
            "experiments": ns._experiments,
            "experiment_preflight": _experiment_dispositions,
            "experiment_final_pass": _experiment_final_pass,
            # E4: how many validator executions the run's registry served without
            # running again, and the requests that saved (by validator).
            "execution_registry": ns._exec_registry.stats(),
            "coverage": ns.coverage,
            "withheld_operations": ns.coverage.get("withheld_operations", []),
            "discovery_bounds": list(getattr(ns.rc, "discovery_bounds", None) or []),
            # E5b: each (endpoint, identity) the coverage drive could not replay
            # because no request was observed as that identity (and, R11-10, none
            # could be substituted from another identity's capture), once, with the
            # number of checks it blocked and what to supply.
            "prerequisite_blocks": sorted(ns._prerequisite_blocks.values(),
                                          key=lambda b: (b["endpoint"], b["identity"])),
            # Stage reservations in effect: requests withheld for the coverage drive,
            # what the earlier stages spent, and the stage time bounds (0 = none).
            "stage_budgets": {"coverage_request_reserve": ns._coverage_hold,
                              "requests_before_coverage": ns._requests_before_coverage,
                              "requests_at_end": getattr(ns._run_budget, "used", None),
                              "outer_wall_seconds": None, "outer_wall_owner": "caller",
                              "capture_review_seconds": self.capture_review_seconds,
                              "investigation_seconds": self.investigation_seconds,
                              "coverage_drive_seconds": self.coverage_drive_seconds,
                              # R11-4: time the drive took over from the last sliced phase.
                              "coverage_drive_rollover_seconds": round(ns._coverage_rollover, 3)},
            "workflows": ns.workflow_results,
            "task_graph": ns.state.graph.to_dict(),
            "ready_tasks": ns.state.pending(),
            "blocked_tasks": ns.state.blocked(),
            "auth_bypass_candidates": ns.rc.auth_bypass_candidates,
            "idor_candidates": ns.rc.idor_candidates,
            "idor_findings": ns.rc.idor_findings,
            # R30: operational failures are surfaced, not swallowed -- a run that
            # skipped a phase is declared degraded rather than presented as clean.
            "errors": ns._errors,
            "review_stats": ns._review_stats,
            "degraded": bool(ns._errors) or health["status"] == "incomplete",
            **ns._instr.result_blocks(),  # instrumentation + top-level costs (AR-10 P3)
        }
