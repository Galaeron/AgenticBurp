"""orchestrator_chain_discovery.py -- Stage 1 of investigate_engagement: setup and discovery.

ARC-9 split of the old 2,600-line `investigate_engagement`: the body moved verbatim, cut at
top-level statements. A local that more than one stage touches is an attribute of the shared
`EngagementRun` (`ns`, built by the driver in orchestrator_chain.py); a stage that finishes
the run early returns the result, otherwise None."""
from __future__ import annotations

import time

# FR-6: need the module too (the driver scope reads its ambient run) -- aliased because
# investigate_engagement and several methods have a `run_context` parameter that would shadow it.
from harness import run_context as _run_context_mod
from harness import run_journal
from harness.execution_registry import ExecutionRegistry
from harness.models import HttpExchange
from harness.orchestrator_helpers import log


class ChainDiscoveryMixin:
    async def _engagement_stage_discovery(self, ns):
        """Setup and discovery: the run's clocks, instrumentation, journal, discovery, operator
        declarations, retry/final-pass ledgers and review-stats seeds. Leaves everything the
        later stages read on `ns`."""
        # SEC-1: a cloud-suffixed model in any slot, without
        # ollama.allow_cloud_models, refuses the run here, before any model call.
        from harness import model_egress
        model_egress.refuse_cloud_models(
            self.config, model_egress.agent_models_of(getattr(self, "agent_manager", None)))
        from harness import engagement_builder
        from harness import worklist_investigator
        from harness import chain_linker
        # LB-6: a runner declares its objective on the RunContext it owns; an
        # explicit `objective_task` argument still takes precedence.
        if ns.objective_task is None and ns.run_context is not None:
            ns.objective_task = getattr(ns.run_context, "objective_task", None)
        from harness import role_crawl
        from harness.instrumentation import RunInstrumentation
        from harness.assessment_health import new_review_stats
        # Stage reservations: the coverage drive runs last, so withhold its share of
        # the one run ceiling from every earlier stage (released just before the
        # drive), and bound the investigation stages by wall-clock time.
        ns._investigation_deadline = (time.monotonic() + self.investigation_seconds
                                      if self.investigation_seconds > 0 else None)
        if ns.discovery_max_endpoints is None:
            ns.discovery_max_endpoints = (self.config.get("engagement") or {}).get(
                "discovery_max_endpoints", 0)
        ns.discovery_max_endpoints = max(0, int(ns.discovery_max_endpoints or 0))
        # Crawl loop (all off by default): per-principal crawls, route feedback with
        # re-crawl rounds, and per-phase time-slices of the deadline above.
        from harness.phase_schedule import PhaseSchedule
        from harness.route_feed import RecrawlConfig, RouteFeed, endpoint_route_keys
        ns._schedule = PhaseSchedule.from_config(self.config, ns._investigation_deadline,
                                                 clock=time.monotonic)

        def _budget_left(deadline):
            """R11-4: a phase's wall-time budget, for phase_timings (None: unbounded)."""
            return None if deadline is None else max(0.0, deadline - time.monotonic())
        ns._budget_left = _budget_left
        ns._recrawl_cfg = RecrawlConfig.from_config(self.config)
        ns._per_principal = bool((self.config.get("engagement") or {}).get("crawl_per_principal", False))
        ns._run_budget = getattr(ns.run_context or _run_context_mod.current_run_context(), "budget", None)
        ns._coverage_hold = (ns._run_budget.hold(self.coverage_request_reserve)
                             if self.coverage_request_reserve > 0 and hasattr(ns._run_budget, "hold") else 0)
        # E9: observation only. Each `phases.begin(...)` below closes the previous
        # phase and opens the next; nothing is reordered or skipped by it.
        ns._instr = RunInstrumentation(self, ns.run_context or _run_context_mod.current_run_context(),
                                       ns._run_budget)
        # R11-4b: the server reads it from the run when the job is cancelled before
        # this returns, so a cancelled job still reports its phase_timings.
        _instr_run = ns.run_context or _run_context_mod.current_run_context()
        if _instr_run is not None:
            try:
                _instr_run.instrumentation = ns._instr
            except Exception:   # a stand-in run object without the slot: observation only
                log.debug("run context takes no instrumentation", exc_info=True)
        # Warn before the run when a local model's context window cannot hold the
        # harness's largest prompt (job 0574e29a0799: Ollama cut 88 prompts). Not
        # instrumentation: it runs either way and asks Ollama, never the target.
        # The report rides in the instrumentation block.
        from harness.instrumentation import ollama_models
        from harness.ollama_client import (context_truncated_count, context_window_error,
                                           run_context_preflight)
        ns._truncated_before = context_truncated_count(self.ollama)
        ns._instr.context_preflight = await run_context_preflight(self.ollama, ollama_models(self))
        ns._instr.phases.begin("discovery")

        # E7: with a journal on the run, each finished unit is written as it completes, and
        # a journal that already holds units for this root job (an interrupted earlier
        # run, or the same run's earlier attempt) is resumed from instead of repeated.
        ns._journal = getattr(ns.run_context, "run_journal", None)
        ns._resumed_units = {"discovery": False, "worklist": 0, "review": 0, "coverage_checkpoint": False}

        def _journal_read(read, default):
            """A journal read that fails is a journal with nothing in it: the run goes on."""
            try:
                return read()
            except Exception as e:
                log.warning("investigate_engagement: journal read failed (%s)", type(e).__name__)
                return default
        ns._journal_read = _journal_read

        ns._resuming = ns._journal is not None and _journal_read(ns._journal.has_any, False)

        def _journal_put(unit, payload):
            if ns._journal is None:
                return
            try:
                ns._journal.put(unit, payload)
            except Exception as e:  # losing a unit costs a repeat on resume, never the run
                log.warning("investigate_engagement: journal write of %s failed: %s", unit, e)
        ns._journal_put = _journal_put

        def _journal_phase(name):
            _journal_put(f"phase:{name}", {"finished_at": time.time()})
        ns._journal_phase = _journal_phase

        _stored_discovery = _journal_read(lambda: ns._journal.get("discovery"), None) if ns._resuming else None
        if _stored_discovery is not None:
            try:
                ns.state, ns.rc = run_journal.restore_discovery(_stored_discovery, ns.roles)
                # Discovery registers the roles' sessions with the run; restoring it must too.
                engagement_builder.register_role_sessions(ns.run_context, ns.base_url, ns.roles)
                ns._resumed_units["discovery"] = True
            except Exception as e:
                log.warning("investigate_engagement: journaled discovery unusable (%s); "
                            "discovering again", type(e).__name__)
        if not ns._resumed_units["discovery"]:
            # Forms on fetched HTML documents as request templates (form_capture.py).
            _form_templates_cfg = ((self.config.get("engagement") or {})
                                   .get("form_templates") or {})
            ns.state, ns.rc = await engagement_builder.build_engagement(
                ns.base_url, ns.roles, allowed_hosts=self.allowed_hosts,
                crawl_max_pages=ns.discovery_max_pages,
                max_endpoints=ns.discovery_max_endpoints,
                active_discovery=ns.active_discovery,
                discovery_max_probes=ns.discovery_max_probes, run_context=ns.run_context,
                **self._discovery_ffuf_kw(),
                **self._discovery_recursion_kw(),
                **({"per_principal": True} if ns._per_principal else {}),
                **({"seed_exchanges": ns.seed_exchanges} if ns.seed_exchanges else {}),
                **({"driver_capture_config": self.config["driver_capture"]}
                   if (self.config.get("driver_capture") or {}).get("enabled") else {}),
                **({"form_templates_config": _form_templates_cfg}
                   if _form_templates_cfg.get("enabled") else {}))
            if ns._journal is not None:
                try:
                    _journal_put("discovery", run_journal.discovery_payload(ns.state, ns.rc, ns.roles))
                    _journal_phase("discovery")
                except Exception as e:
                    log.warning("investigate_engagement: journaling discovery failed: %s", e)

        # Client-side routes (client_routes.py), built or restored with discovery: the
        # XSS legs load the page route that issued an API call.
        if ns.run_context is not None and getattr(ns.state, "client_routes", None) is not None:
            ns.run_context.client_routes = ns.state.client_routes

        # I16: the operator's declarations for this engagement, added after discovery
        # (built or restored) so both paths carry them. Malformed entries are left to
        # the readers, which ignore them with a warning (fail closed).
        for _field, _declared in (("protected_paths", ns.protected_paths), ("owners", ns.owners)):
            if _declared:
                _have = getattr(ns.state, _field)
                _have.extend(entry for entry in _declared if entry not in _have)

        # Units an earlier attempt finished, passed to the phases that skip them. Their
        # findings come back marked `resumed_from`, a confirmation only while its proof
        # still resolves (run_journal.resume_finding).
        ns._worklist_kwargs: dict = {}
        ns._review_kwargs: dict = {}
        ns._review_summary: dict = {}
        if ns._journal is not None:
            _root = ns._journal.root_job_id
            ns._worklist_kwargs = {
                "completed": (_journal_read(lambda: {
                    unit[len("worklist:"):]: run_journal.resume_outcome(payload, _root)
                    for unit, payload in ns._journal.units("worklist:").items()}, {})
                              if ns._resuming else None),
                "on_outcome": lambda key, outcome: _journal_put(f"worklist:{key}", outcome)}
            ns._review_kwargs = {
                "resumed": (_journal_read(lambda: {
                    unit[len("review:"):]: {"findings": [run_journal.resume_finding(f, _root)
                                                         for f in payload.get("findings") or []]}
                    for unit, payload in ns._journal.units("review:").items()}, {})
                            if ns._resuming else None),
                "on_review": lambda key, payload: _journal_put(f"review:{key}", payload),
                "journal_key": ns._journal.exchange_key,
                "summary_out": ns._review_summary}
        # engagement.retry_rounds (off by default): record what every sweep and review
        # settles, so the time left after the coverage drive goes to the work they left.
        from harness import retry_rounds
        ns._retry_cfg = retry_rounds.RetryRoundsConfig.from_config(self.config)
        ns._retry_ledger = None
        ns._retry_report: dict = {"enabled": False}
        if ns._retry_cfg.enabled and ns._investigation_deadline is None:
            ns._retry_report = {"enabled": True, "rounds": [], "stopped_by": "no_deadline"}
        elif ns._retry_cfg.enabled:
            ns._retry_ledger = retry_rounds.RetryLedger()
            ns._worklist_kwargs = ns._retry_ledger.wire(ns._worklist_kwargs)
            ns._review_kwargs["model_failed"] = ns._retry_ledger.review_failed
        # R11-4 engagement.final_pass (off by default): before finalise, the time left
        # goes to the budget-skipped worklist nodes, the drive legs never attempted and
        # the replays the per-endpoint share held (harness/final_pass.py). It needs the
        # retry ledger's record of what each sweep settled; it shares the retry rounds'.
        from harness import final_pass as _final_pass_mod
        ns._final_cfg = _final_pass_mod.FinalPassConfig.from_config(self.config)
        ns._final_ledger = ns._retry_ledger
        ns._final_report: dict = {"enabled": False}
        if ns._final_cfg.enabled and ns._investigation_deadline is None:
            ns._final_report = {"enabled": True, "steps": [], "stopped_by": "no_deadline"}
        elif ns._final_cfg.enabled and ns._final_ledger is None:
            ns._final_ledger = retry_rounds.RetryLedger()
            ns._worklist_kwargs = ns._final_ledger.wire(ns._worklist_kwargs)
        # The shape-driven legs one sweep may attempt: by default no count bound when
        # the run is time-boxed (its deadline bounds them), else 24.
        ns._max_precondition_legs = worklist_investigator.resolve_precondition_legs(
            (self.config.get("engagement") or {}).get("max_precondition_legs"),
            time_boxed=ns._investigation_deadline is not None)

        # Operator/capture supplied shapes (for example the runner's successful
        # login setup exchange) are first-class evidence. They do not trigger new
        # traffic here; they only prevent session-setup forms from disappearing at
        # the discovery boundary before deterministic validators can inspect them.
        # build_engagement now imports these captures with their actual identity
        # and request shape, instead of granting every supplied capture anonymous
        # reachability here.

        # R30: operational failures in the additive phases below are caught so one
        # broken phase can't sink the run -- but they must not vanish silently. Each
        # is recorded here and surfaced in the result as `errors` + `degraded`, so a
        # run that skipped a phase is declared incomplete rather than looking clean.
        ns._errors: list[dict] = [
            {"phase": "discovery", "error": message}
            for message in getattr(ns.rc, "errors", [])
            if not message.startswith("[discovery] used spec ")
        ]
        ns._reviewed_captures: set[str] = set()
        ns._review_stats = new_review_stats()
        ns.workflow_results: list[dict] = []

        # Preserve real request shapes before any worklist leg runs. Full model
        # review is deliberately deferred until after the bounded deterministic
        # precondition sweep below; otherwise a handful of discovery captures can
        # consume the wall-clock budget before a three-request validator runs.
        for _cap in list(getattr(ns.rc, "captured", None) or []):
            try:
                _ex = _cap if isinstance(_cap, HttpExchange) else HttpExchange(**_cap)
                ns.state.record_template(_ex.url, _ex.method, _ex)
            except Exception:
                pass

        # Emit findings for sensitive files discovered during active probing
        # (/.env, /backup/, etc.). WL-05 (E39): a status code alone is only an
        # existence signal. A finding is confirmed only when discovery's record
        # says the 2xx body carried the artifact's content signature; a redirect,
        # an empty or HTML body or an unrecognised type stays an existence-only
        # candidate quoting the real status. A hit with no record (an older
        # producer) is never confirmed.
        from harness.api_surface_discovery import sensitive_file_finding
        _sf_recorded: set[str] = set()
        for sf_record in getattr(ns.rc, "sensitive_file_evidence", None) or []:
            sf_path = str(sf_record.get("path") or "")
            _sf_recorded.add(sf_path)
            ns.state.ingest_findings(f"{ns.base_url}{sf_path}", "GET",
                                     [sensitive_file_finding(sf_record)])
        for sf_path in getattr(ns.rc, "sensitive_file_hits", None) or []:
            if sf_path not in _sf_recorded:
                ns.state.ingest_findings(f"{ns.base_url}{sf_path}", "GET",
                                         [sensitive_file_finding({"path": sf_path})])

        # Stateful agent-role feature crawling (default off). Drive each role
        # through the app's real workflows and fold the captured, session-bearing
        # exchanges into the surface + content review -- the frontier gap
        # route-guessing can't close (sessions 11/13/15). The submits inside are
        # gated by allow_mutating_replay, so with mutating replay off this reduces
        # to an authenticated read-only walk.
        if self.engagement_feature_crawl:
            try:
                import harness.engagement as _eng
                from harness.safety_gate import get_default_gate as _get_gate
                discovered_paths = [ep.path for ep in ns.rc.endpoints] if ns.rc.endpoints else None
                # ARC-7: the crawl sends only through a run: this one, the enclosing
                # one, or a standalone one closed here.
                _fc_run = ns.run_context or _run_context_mod.current_run_context()
                _fc_owned = None
                if _fc_run is None:
                    _fc_owned = _fc_run = _run_context_mod.standalone_context(
                        self.allowed_hosts, config=self.config, active_mode=True)
                try:
                    ns.feature_caps = await engagement_builder.feature_crawl_captures(
                        ns.base_url, ns.roles, allowed_hosts=self.allowed_hosts,
                        submit_forms=_get_gate().config.allow_mutating_replay,
                        seed_paths=discovered_paths, run_context=_fc_run, errors=ns._errors,
                        **({"per_principal": True} if ns._per_principal else {}))
                finally:
                    if _fc_owned is not None:
                        await _fc_owned.aclose()
                # Make workflow routes and their real request shapes visible to
                # prioritisation. Content-level model review remains deferred.
                for ex in ns.feature_caps:
                    ns.state._ep(ex.method, _eng.normalize_path(ex.url))
                    ns.state.record_template(ex.url, ex.method, ex)
            except Exception as e:  # feature crawl is additive -- never sink the run
                log.warning("investigate_engagement: feature crawl failed: %s", e)
                ns._errors.append({"phase": "feature_crawl", "error": f"{type(e).__name__}: {e}"})

        # E4/E2: the run's one execution registry, made before the header audit so the
        # audit's csp/cors checks are recorded in it and the model-review path (which
        # reads it through run_context) does not run them again for the same route and
        # identity, nor the worklist or the drive any other check.
        ns._exec_registry = getattr(ns.run_context, "execution_registry", None)
        if not isinstance(ns._exec_registry, ExecutionRegistry):
            ns._exec_registry = ExecutionRegistry(budget=getattr(ns.run_context, "budget", None))
            if ns.run_context is not None:
                ns.run_context.execution_registry = ns._exec_registry
