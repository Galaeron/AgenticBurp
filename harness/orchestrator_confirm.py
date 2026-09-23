"""orchestrator_confirm.py -- ConfirmMixin mixin for Orchestrator (W-15 decomposition).

Confirmation/validation: coverage-proof binding, the _validate_findings
fan-out (with its nested _confirm/_cached_validate dispatch), and the
active-probe / retry-agent entry points.

Split out of orchestrator.py verbatim; `self` state is initialised in
Orchestrator.__init__ and resolved across mixins via the MRO.
"""
from __future__ import annotations

from harness.orchestrator_helpers import *  # noqa: F401,F403  (shared imports/helpers/constants)
from harness.validators.base import ValidationResult


class ConfirmMixin:
    async def get_run_derived_live_markers(self):
        """P0-2: the run-derived confirmation-trust-tier override.

        Off unless `leg_self_test.enabled` is set in config -- the static
        LIVE_VERIFIED_MARKERS table (confirmation_gate.py) stays the offline
        default for every run that doesn't opt in, so this changes nothing
        for the harness's existing default configuration or test suite.

        When enabled, runs harness.leg_self_test.run_self_test() (fires each
        active confirmation leg against the owned loopback fixture and its
        paired negative control -- see that module) AT MOST ONCE per
        Orchestrator instance, cached on `self`, and returns the resulting
        frozenset. That frozenset is meant to be passed straight through as
        `live_verified_markers` to confirmation_gate.leg_tier() /
        apply_confirmation_suppression(): a class not in it is never treated
        as "live" this run, only "provisional" (capped at medium) --
        DEMOTION only, never promotion beyond what confirmation_gate already
        allows for an explicit override.

        FAIL-SAFE: any exception out of the self-test (fixture wouldn't
        start, an import failed, anything) is swallowed and produces an
        EMPTY frozenset -- "could not measure" demotes every confirmable
        class to provisional this run, it never falls back to trusting the
        static table while claiming to be run-derived."""
        cfg = (getattr(self, "config", {}) or {}).get("leg_self_test", {}) or {}
        if not cfg.get("enabled", False):
            return None  # override absent -- confirmation_gate uses its static offline default
        cached = getattr(self, "_leg_self_test_cache", None)
        if cached is not None:
            return cached
        from harness import leg_self_test
        try:
            markers = await asyncio.to_thread(leg_self_test.run_self_test)
        except Exception:
            log.warning(
                "leg self-test crashed this run -- every confirmable class "
                "falls back to provisional (fail-safe)", exc_info=True)
            markers = frozenset()
        self._leg_self_test_cache = markers
        return markers

    async def _oracle_gate(self, finding, exchange) -> None:
        """P0.1-WIRE: run the deterministic verification oracle over a just-
        confirmed finding, behind config `oracle.enabled` (default false).

        Three operating modes, controlled by the `oracle` config section:

        1. `enabled=false, safe_passive_default=false` (old default): stamps
           the finding as a candidate WITHOUT any probe -- pure bookkeeping.
        2. `enabled=false, safe_passive_default=true` (new safe default): runs
           the oracle ONLY for validators with `active=False` (no live traffic).
           Pure re-analysis of the already-captured exchange; safe to ship ON.
        3. `enabled=true`: full oracle -- all applicable validators, including
           active ones (3x+ probes per finding). Must be explicitly opted in."""
        from harness import oracle_framework
        cfg = (getattr(self, "config", {}) or {}).get("oracle", {}) or {}
        enabled = cfg.get("enabled", False)
        safe_passive_default = cfg.get("safe_passive_default", True)

        if not enabled and not safe_passive_default:
            oracle_framework.stamp_finding(finding, None)
            return

        n_required = int(cfg.get("n_required", 3) or 3)
        registry = oracle_framework.OracleRegistry(
            self.validator_registry, n_required=n_required)

        if enabled:
            capsule = await registry.verify(finding, exchange)
        else:
            # safe_passive_default: passive-only oracle, zero new requests
            oracle = registry.oracle_for(finding, exchange, passive_only=True)
            capsule = await oracle.run(finding, exchange) if oracle is not None else None

        oracle_framework.stamp_finding(finding, capsule)

    async def run_active_probe(
        self,
        exchange: HttpExchange,
        hypothesis: str,
        specialty: str,
        *,
        model: str = "",
        step_budget: int | None = None,
        on_step=None,
    ) -> dict:
        """Drive the iterative agent (F4) against one captured exchange, then
        integrate its result through F2 (pivot_memory): hold the findings as
        unconfirmed, build independent-verification plans, remember them, and
        combine + pivot over the host's history. Returns both the raw iterative
        result and the integration outcome.

        Off unless iterative_agent.enabled is set in config -- this is a
        fundamentally more active mode than the passive pipeline. Mutating steps
        remain gated by the safety gate on top of that flag. Scope is enforced
        against allowed_hosts inside the agent."""
        if not self.iterative_agent_enabled:
            raise RuntimeError(
                "iterative agent is disabled (set iterative_agent.enabled in config.yaml)")

        from harness.iterative_agent import IterativeAgent
        from harness import pivot_memory
        from harness import activity_feed

        # Phase 4 cloud-coordinator seam: the iterative agent's reasoning runs on
        # the cloud model when the seam is toggled on (else local).
        chosen_model = model or self.reasoning_model()
        agent = IterativeAgent(
            self.ollama, chosen_model, self.allowed_hosts,
            max_steps=self.iterative_agent_max_steps,
        )

        # Publish each step to the live feed (V1), and still call any caller-
        # supplied on_step so both a UI poller and a direct subscriber see it.
        def _feed_step(step) -> None:
            activity_feed.publish(
                "iterative_step",
                f"{specialty} step {step.n}: {step.action.get('action', '?')} -> "
                f"{step.response_status if step.response_status is not None else (step.blocked or '-')}",
                agent=f"iterative:{specialty}",
                level="warn" if step.blocked else "info",
                detail={"n": step.n, "status": step.response_status})
            if on_step is not None:
                on_step(step)

        result = await agent.run(
            exchange, hypothesis, specialty,
            step_budget=step_budget or self.iterative_agent_max_steps,
            effort_budget=self.effort_budget,
            on_step=_feed_step,
        )
        outcome = await pivot_memory.integrate(result, exchange, model=chosen_model)
        return {"iterative_result": result.to_dict(), "integration": outcome.to_dict()}

    async def run_retry_agents(
        self,
        exchange: HttpExchange,
        agent_class: str,
        *,
        policy_overrides: dict | None = None,
        granted_tokens: int | None = None,
        prior_context: str = "",
    ) -> dict:
        """F5 retry loop: re-dispatch the SAME specialist agent on one exchange
        up to the per-vulnerability policy's cap, stopping as soon as it produces
        an actionable finding. Distinct from adaptive_respin, which spins a
        DIFFERENT agent; this spins the same one (the tester's "give this
        vulnerability N more tries" knob).

        Bounded by the PerVulnSpend tracker: max_retries, max_agents, an optional
        per-vuln token cap, an optional allocator-granted sub-cap, AND the global
        effort budget -- the loop stops the moment any of them says no. Every
        round's real token cost (measured from the ledger delta) is charged to
        the per-vuln spend so the caps mean tokens, not just call counts."""
        from harness import resource_governor
        if agent_class not in self.agent_manager.agents:
            raise ValueError(f"unknown agent class {agent_class!r}")

        policy = self.retry_budget_policy.merged_with(policy_overrides)
        spend = resource_governor.PerVulnSpend(
            policy=policy, global_budget=self.effort_budget, granted_tokens=granted_tokens)

        rounds: list[dict] = []
        all_reports: list[AgentReport] = []
        stop_reason = ""
        while True:
            ok, reason = spend.can_start_round(planned_agents=1)
            if not ok:
                stop_reason = reason
                break
            before = self.effort_budget.spent
            reports = await self.agent_manager.run_multiple_agents(
                [agent_class], exchange, self.max_body_chars, prior_context, self.effort_budget)
            spent = max(0, self.effort_budget.spent - before)
            found = self._has_actionable_finding(reports)
            spend.record_round(agents_run=1, tokens_spent=spent, found=found)
            all_reports.extend(reports)
            rounds.append({
                "pass": spend.passes_used, "tokens": spent, "found": found,
                "findings": [f.model_dump() for r in reports for f in r.findings],
            })
            if found and policy.stop_on_found:
                stop_reason = "actionable finding produced"
                break

        best = max((f for r in all_reports for f in r.findings),
                   key=lambda f: f.confidence, default=None)
        return {
            "agent_class": agent_class,
            "stop_reason": stop_reason,
            "found": spend.found,
            "spend": spend.to_dict(),
            "rounds": rounds,
            "best_finding": best.model_dump() if best else None,
        }

    async def _coverage_proof(self, *, identity: str, check, exchange,
                              result, case_key=None, run_context=None) -> tuple[str, str]:
        """Build and persist a case-bound ProofRecord for a coverage-DRIVEN leg
        result (T05/R26), so a coverage-driven confirmation is evidence with a
        stable case id -- the same T01 contract the captured-exchange path uses --
        instead of only a matrix cell. The case coordinates carry the concrete
        parameter (`case_key`) when the driver fanned out to one, else the
        endpoint/no-parameter case. Returns (proof_id, case_id), or ("","") if the
        proof could not be persisted. Best-effort: coverage is a report layer and
        never sinks the run."""
        try:
            _template_id = evidence._short(
                (exchange.method or "").upper(), exchange.url or "", exchange.request_body or "")
            from harness.categories import canonicalize as _canon
            check_id = check.id or _canon(check.vulnerability_class) or (check.vulnerability_class or "")
            ck = case_key
            if run_context is None:
                from harness.run_context import RunContext
                run_context = RunContext.create(
                    config=self.config, allowed_hosts=self.allowed_hosts)
            case = evidence.TestCaseRef.make(
                run_id=run_context.run_id, request_template_id=_template_id, check_id=check_id,
                principal_id=identity or "",
                parameter_location=(ck.parameter_location if ck else ""),
                parameter_name=(ck.case_parameter_name() if ck else ""),
                workflow_state_id=(ck.workflow_state_id if ck else ""))
            pr = evidence.ProofRecord.from_validation_result(
                case=case, validator=result.validator,
                validator_version=getattr(result, "version", "") or "",
                status=result.status, confirmed=result.confirmed,
                observed_result=(result.summary or result.evidence or "")[:500])
            ok, reason = await asyncio.to_thread(store.persist_proof_record, pr)
            if ok:
                return pr.proof_id, case.case_id
            log.warning("failed to persist coverage proof for %s: %s", result.validator, reason)
        except Exception as e:  # proof bookkeeping must never break coverage
            log.debug("coverage proof bookkeeping failed: %s", e)
        return "", ""

    async def _persist_confirmation_proof(
        self, *, case, validator_name: str, status: str, confirmed: bool,
        finding_ref: str, ledger_summary: str, ledger_data: dict,
        validator_version: str = "", observed_result: str = "",
        expected_invariant: str = "",
    ) -> tuple[bool, dict | None, str]:
        """RB-4/INV-2 shared proof+ledger persistence.

        The ONE place a case-bound ProofRecord is built/persisted
        (store.persist_proof_record) and the matching evidence_ledger
        VALIDATION_DECISION is emitted, so every confirmation call site --
        PASS1's _validate_findings below, AND PASS2's engagement graph loop
        (orchestrator_chain.py::_apply) -- reuses the SAME mechanism instead of
        a second, divergent implementation (the exact hazard INV-2 warns
        against: no 2nd ledger).

        Returns (ok, proof.to_dict() or None, reason). Read-only w.r.t.
        verdict/severity/scope/gate: this only ever adds a durable record. The
        ledger emit is best-effort and never raises (matches
        _validate_findings' original discipline for this call); a proof
        persistence failure DOES propagate to the caller (ok=False, or an
        exception from a malformed case/ProofRecord), exactly as
        _validate_findings' own try/except around this step already expects.
        """
        from harness import evidence_ledger
        try:
            evidence_ledger.emit(
                evidence_ledger.EventType.VALIDATION_DECISION, finding_ref,
                ledger_summary, data=ledger_data,
                provenance=evidence_ledger.Provenance.capture(
                    config=getattr(self, "config", {})),
                case_ref=case.case_id)
        except Exception:
            pass
        pr = evidence.ProofRecord.from_validation_result(
            case=case, validator=validator_name, validator_version=validator_version,
            status=status, confirmed=confirmed, observed_result=observed_result,
            expected_invariant=expected_invariant)
        ok, reason = await asyncio.to_thread(store.persist_proof_record, pr)
        if ok:
            return True, pr.to_dict(), reason
        return False, None, reason

    # ER-4: names scoped for the reproduction-replay determinism gate. A
    # single successful observation can confirm one of these active legs; a
    # flaky one-shot confirmation would not reproduce, inflating precision.
    _CONFIRM_REPLAY_SCOPE = frozenset({"ssrf", "ssti", "command_injection"})

    async def _maybe_replay(self, validator, finding, exchange):
        """ER-4: optional determinism gate wrapping validator.validate().

        DEFAULT OFF (self.confirm_replay false, or not set on this instance):
        awaits validate() exactly ONCE and returns that result object
        UNCHANGED -- byte-for-byte identical to calling validator.validate()
        directly. This is the common/shipped path.

        When confirm_replay is on AND validator.name is in the scoped set
        AND the first attempt confirmed, awaits validate() a SECOND time (via
        the same validate() path, so scope lock / global_throttle / safety
        gate budget / allow_mutating_replay the leg already enforces still
        apply -- no hand-rolled re-send). If the second run agrees
        (confirmed), the original (first) confirmed result is returned
        unchanged. If it disagrees, a downgraded ValidationResult (confirmed
        False, status "not_confirmed") is returned instead -- this is NOT a
        new downgrade mechanism, it simply means the finding never gets
        `finding.confirmed = True` set at the call site (~line 488), so
        confirmation_gate routes it through the existing provisional/unproven
        path exactly as it would any other not-confirmed active leg.
        """
        first = await validator.validate(finding, exchange)
        if not getattr(self, "confirm_replay", False):
            return first
        if getattr(validator, "name", None) not in self._CONFIRM_REPLAY_SCOPE:
            return first
        if not first.confirmed:
            return first
        second = await validator.validate(finding, exchange)
        if second.confirmed:
            return first
        # Disagreement: downgrade. Let the existing provisional/unproven path
        # (confirmation_gate) handle this finding from here -- no new
        # mechanism, just a not-confirmed result like any other.
        note = "replay disagreed: second confirmation attempt did not reproduce"
        summary = (first.summary or "") + ((" " + note) if first.summary else note)
        return ValidationResult(
            validator=first.validator,
            status="not_confirmed",
            finding_class=first.finding_class,
            confidence=first.confidence,
            confirmed=False,
            summary=summary,
            evidence=first.evidence,
            raw_output=first.raw_output,
            command=first.command,
        )

    async def _validate_findings(
        self, exchange: HttpExchange, reports: list[AgentReport], *, run_context=None
    ) -> tuple[list[ValidationReport], list[dict]]:
        """Run bounded, opt-in validators against model-generated hypotheses.

        Validators receive the original captured exchange, never a model-
        generated URL or shell command. This makes the LLM a planner and
        evidence extractor while deterministic/tool-backed validators are
        the confirmation layer.

        Each validator's own .plan() is persisted and the result is
        recorded through the same persist_validation_submission gate the
        Burp extension's typed executors use -- previously this method
        surfaced results only in the API response and the in-memory
        Finding.confirmed flag, never writing to validation_runs at all.
        That meant every local_tool (sqlmap) result -- confirmed or not --
        was invisible to anything that reads validation_runs, including
        the coverage ledger: a real, live-confirmed SQL injection would
        have been indistinguishable from "never tested" to that ledger.
        """
        # W-2: central scope backstop. No validator is dispatched against an
        # exchange whose host is out of scope -- regardless of whether each
        # validator also self-enforces. Self-enforcement is defense-in-depth,
        # not the boundary: one validator constructed without allowed_hosts
        # (e.g. the pre-W-1 CORS validator) would otherwise send unscoped live
        # traffic. analyze()'s entry-point check covers the captured-exchange
        # path; this guards every other route into validator dispatch (the
        # graph loop, autonomous discovery, credential re-tests).
        # active_mode=True here makes an EMPTY scope fail closed (W-17): live
        # validators must never dispatch against an undeclared scope once active
        # testing is on. Passive analysis (the agent path) is unaffected -- only
        # this live-send dispatch is gated.
        _active = getattr(self.validator_registry, "active_enabled", False)
        if not scope_discovery.is_host_allowed(
            exchange.url, getattr(self, "allowed_hosts", []), active_mode=_active
        ):
            log.warning(
                "validator dispatch skipped: exchange host %r is outside scope "
                "(active_mode=%s)",
                (urlparse(exchange.url).hostname or ""), _active,
            )
            # W-11: a run producing no confirmations because everything was out
            # of scope should say so at /telemetry, not silently.
            from harness import telemetry
            telemetry.record_event("validator_dispatch_scope_denied")
            return [], []
        jobs = []
        plans: list = []
        metas: list = []  # (finding, validator, exact case) parallel to jobs
        if run_context is None:
            from harness.run_context import RunContext
            run_context = RunContext.create(
                allowed_hosts=getattr(self, "allowed_hosts", []),
                config=getattr(self, "config", {}))
        _run_id = run_context.run_id
        _template_id = evidence._short(
            (exchange.method or "").upper(), exchange.url or "", exchange.request_body or "")
        from harness.categories import canonicalize as _vf_canon

        def _case_for(finding, report, report_index: int, finding_index: int):
            check = _vf_canon(finding.vulnerability_class) or (finding.vulnerability_class or "")
            finding_ref = finding.finding_id or evidence._short(
                report.agent, report_index, finding_index, finding.vulnerability_class,
                finding.summary, finding.evidence, finding.suggested_test, finding.basis)
            finding.finding_id = finding_ref
            return evidence.TestCaseRef.make(
                run_id=_run_id,
                request_template_id=finding.request_template_id or _template_id,
                check_id=check, principal_id=finding.principal_id or "captured",
                parameter_location=finding.parameter_location,
                parameter_name=finding.parameter_name,
                workflow_state_id=finding.workflow_state_id,
                finding_ref=finding_ref,
            )

        for report_index, report in enumerate(reports):
            for finding_index, finding in enumerate(report.findings):
                case = _case_for(finding, report, report_index, finding_index)
                validators = self.validator_registry.for_finding(finding, exchange)
                bind_context = getattr(self.validator_registry, "bind_run_context", None)
                if bind_context is not None:
                    validators = bind_context(validators, run_context)
                if not validators:
                    # P0-1: an honest "never tested" record -- this finding's class
                    # has no applicable confirmation leg, so no VALIDATION_DECISION
                    # will ever be emitted for it below. Recorded as an OBSERVATION
                    # (never VALIDATION_DECISION/FINDING_REVISION), so
                    # reconstruct()'s `complete` stays False for it, exactly as it
                    # should for a finding that was never actually confirmed or
                    # refuted. Read-only bookkeeping; does not affect dispatch.
                    try:
                        from harness import evidence_ledger
                        evidence_ledger.emit(
                            evidence_ledger.EventType.OBSERVATION, finding.finding_id,
                            f"no confirmation validator available for class "
                            f"{finding.vulnerability_class!r}",
                            data={"not_tested": f"no validator applies to "
                                                 f"vulnerability_class={finding.vulnerability_class!r}"},
                            provenance=evidence_ledger.Provenance.capture(
                                config=getattr(self, "config", {})),
                            case_ref=case.case_id)
                    except Exception:
                        pass
                for validator in validators:
                    jobs.append(self._maybe_replay(validator, finding, exchange))
                    plans.append(validator.plan(finding, exchange))
                    metas.append((finding, validator, case))
        if not jobs:
            return [], []
        # R29: bound this phase's concurrency instead of firing every
        # finding x validator job at once. Unbounded fan-out let dozens of live
        # probes hit the target simultaneously (agent concurrency did not cover
        # this phase). Mutating validators already serialise through the safety
        # gate's per-finding budget (R16).
        # getattr default tolerates test instances built via object.__new__
        # (which bypass __init__); real, config-constructed instances carry the
        # config value set in __init__ (W-13).
        results = await bounded_gather(jobs, getattr(self, "max_concurrent_validations", 6))
        output: list[ValidationReport] = []
        proofs: list[dict] = []
        for result, plan, meta in zip(results, plans, metas):
            finding, validator, case = meta
            if isinstance(result, Exception):
                log.warning("validator failed: %s", result)
                # W-11: count the crashed leg so a run where a validator throws on
                # every exchange (and thus confirms nothing) is visible at
                # /telemetry, not just in the logs.
                from harness import telemetry
                telemetry.record_swallowed_exception(
                    f"validator_dispatch.{getattr(validator, 'name', 'validator')}", result)
                # Preserve the operational failure as an ERROR proof (R30/T01): a
                # crashed leg is recorded honestly, never dropped and never read as
                # a boundary that held.
                try:
                    ep = evidence.ProofRecord.from_validation_result(
                        case=case,
                        validator=getattr(validator, "name", "validator"),
                        validator_version=getattr(validator, "version", ""),
                        status="error", confirmed=False, observed_result=str(result)[:300])
                    ok, reason = await asyncio.to_thread(store.persist_proof_record, ep)
                    if ok:
                        proofs.append(ep.to_dict())
                    else:
                        log.warning("failed to persist validator error proof: %s", reason)
                        output.append(ValidationReport(
                            validator=getattr(validator, "name", "validator"), status="error",
                            finding_class=finding.vulnerability_class, confirmed=False,
                            summary=f"proof persistence failed: {reason}", evidence=str(result)[:300]))
                except Exception as e:  # proof bookkeeping must never break analysis
                    log.warning("proof bookkeeping failed for errored validator: %s", e)
                    output.append(ValidationReport(
                        validator=getattr(validator, "name", "validator"), status="error",
                        finding_class=finding.vulnerability_class, confirmed=False,
                        summary=f"proof persistence failed: {e}", evidence=str(result)[:300]))
                continue
            output.append(ValidationReport(
                validator=result.validator,
                status=result.status,
                finding_class=result.finding_class,
                confidence=result.confidence,
                confirmed=result.confirmed,
                summary=result.summary,
                evidence=result.evidence,
            ))
            # P0-1/T01 (RB-4 shared helper): VALIDATION_DECISION -- "why was it
            # concluded (vulnerable or not)" -- plus the case-bound structured
            # proof for this attempt, built/persisted together by
            # _persist_confirmation_proof so PASS1 (here) and PASS2
            # (orchestrator_chain.py) share one mechanism instead of two.
            # Recorded for every reached verdict (confirmed, not_confirmed,
            # skipped), not only confirmations, so a REFUTED/UNVERIFIED
            # finding's reconstruction is just as complete, and each attempt
            # gets its OWN proof (unique proof_id). Additive -- the class-keyed
            # confirmed-flag binding below stays as the compatibility view
            # during migration (full case-bound confirmation is sequenced with
            # issue identity, T06).
            try:
                ok, proof_dict, reason = await self._persist_confirmation_proof(
                    case=case, validator_name=result.validator,
                    validator_version=getattr(validator, "version", ""),
                    status=result.status, confirmed=result.confirmed,
                    observed_result=(result.summary or result.evidence or "")[:500],
                    expected_invariant=getattr(validator, "expected_invariant", ""),
                    finding_ref=finding.finding_id,
                    ledger_summary=(
                        f"{result.validator}: {result.status}"
                        + (" (confirmed)" if result.confirmed else "")
                        + (f" -- {result.summary}" if result.summary else "")),
                    ledger_data={"validator": result.validator, "status": result.status,
                                 "confirmed": result.confirmed, "confidence": result.confidence,
                                 "evidence": (result.evidence or "")[:1000]},
                )
                if ok:
                    proofs.append(proof_dict)
                    if result.confirmed:
                        finding.confirmed = True
                        finding.confidence = max(finding.confidence, result.confidence)
                        finding.review_verdict = finding.review_verdict or "validator-confirmed"
                        finding.review_note = (finding.review_note or "") + (
                            " " if finding.review_note else "") + result.summary
                        finding.proof_id = proof_dict["proof_id"]
                        finding.case_id = case.case_id
                        # Shape-precondition placeholders start with empty evidence.
                        # Preserve any agent evidence; otherwise retain the
                        # confirming validator's observation on the finding.
                        if not finding.evidence:
                            finding.evidence = result.evidence or finding.evidence
                        # Step 4 (2026-09-17 coverage-recovery plan): the STRUCTURED
                        # leg name, set at the exact same moment as proof_id/case_id
                        # -- not recovered later by regex-parsing evidence text.
                        finding.confirmed_by_leg = result.validator
                        # P0.1-WIRE: oracle gate runs (or no-ops, per config)
                        # at the exact moment a finding is first confirmed.
                        await self._oracle_gate(finding, exchange)
                else:
                    log.warning("failed to persist proof for %s: %s", result.validator, reason)
                    output[-1] = ValidationReport(
                        validator=result.validator, status="error",
                        finding_class=result.finding_class, confidence=0.0, confirmed=False,
                        summary=f"proof persistence failed: {reason}", evidence=result.evidence)
            except Exception as e:
                log.warning("proof bookkeeping failed for %s: %s", result.validator, e)
                output[-1] = ValidationReport(
                    validator=result.validator, status="error",
                    finding_class=result.finding_class, confidence=0.0, confirmed=False,
                    summary=f"proof persistence failed: {e}", evidence=result.evidence)
            if plan is not None:
                await asyncio.to_thread(
                    store.persist_test_plans, exchange, [plan]
                )
                submission = ValidationSubmission(
                    plan_id=plan.id,
                    status=result.status,
                    confidence=result.confidence,
                    confirmed=result.confirmed,
                    summary=result.summary,
                    evidence=result.evidence or result.raw_output,
                    executor=f"{plan.execution_plane}:{plan.capability}",
                    source_exchange_hash=plan.source_exchange_hash,
                )
                ok, reason = await asyncio.to_thread(
                    store.persist_validation_submission, submission
                )
                if not ok:
                    log.warning(
                        "failed to persist local-tool validation result for plan %s: %s",
                        plan.id, reason
                    )
        
        # Deterministic cross-identity REJECT -> downgrade. A validator normally
        # may only CONFIRM (above), never lower a finding -- but an ACTIVE
        # cross-identity probe that showed every other identity and the anon
        # baseline were denied is direct, non-LLM evidence the single-exchange
        # access-control hypothesis is false, exactly like access_control_gate's
        # denial rule. Cap confidence and severity so the guess stops reading as
        # actionable, while keeping it (at low) for audit.
        for result, meta in zip(results, metas):
            finding, validator, _case = meta
            if (not isinstance(result, Exception)
                    and result.validator == "cross_identity"
                    and result.status == "not_confirmed"
                    and not finding.confirmed
                    and finding.confidence > _CROSS_IDENTITY_REJECT_CAP):
                finding.original_confidence = finding.confidence
                finding.confidence = _CROSS_IDENTITY_REJECT_CAP
                if finding.severity not in ("info", "low"):
                    finding.severity = "low"
                finding.review_verdict = "downgraded"
                finding.review_note = (finding.review_note or "") + (
                    " " if finding.review_note else "") + (
                    "Cross-identity probe: access correctly restricted (every configured other "
                    "identity and the anonymous baseline were denied), so this single-exchange "
                    "access-control claim is not demonstrated.")

        return output, proofs
