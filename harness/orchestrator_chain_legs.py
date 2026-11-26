"""orchestrator_chain_legs.py -- Stage 2 of investigate_engagement: the header audit and the confirmation legs.

ARC-9 split of the old 2,600-line `investigate_engagement`: the body moved verbatim, cut at
top-level statements. A local that more than one stage touches is an attribute of the shared
`EngagementRun` (`ns`, built by the driver in orchestrator_chain.py); a stage that finishes
the run early returns the result, otherwise None."""
from __future__ import annotations

import asyncio
from urllib.parse import urlsplit
import uuid

# FR-6: need the module too (the driver scope reads its ambient run) -- aliased because
# investigate_engagement and several methods have a `run_context` parameter that would shadow it.
from harness import run_context as _run_context_mod
from harness import evidence, global_throttle, scope_discovery, store
from harness.orchestrator_chain_support import (
    _ConfirmationCache,
    _USER_ENUMERATION,
    _access_control_shape_gap,
    _auth_sequence_shape_gap,
    _authentication_only_class,
    _harvest_object_ids,
    _missing_auth_class,
    _record_no_applicable_leg,
    _ssti_readback_urls,
)
from harness.orchestrator_helpers import log, shape_precondition_legs
from harness.orchestrator_review import universal_header_audit
# W-16: the single TargetTransport. Imported by name (not as the module) because
# investigate_engagement has a `run_context` parameter that would shadow the module;
# `transport_for(run_context, ...)` then reads as "use this run's transport, or a
# standalone one when it is None".
from harness.run_context import transport_for


class ChainLegsMixin:
    async def _engagement_stage_legs(self, ns):
        """Header audit and the confirmation legs: the run's execution registry, the validators the
        worklist confirms with, and the `_probe`/`_confirm`/`_apply`/`_precondition` closures
        the later stages drive."""
        from harness import engagement_builder
        from harness import role_crawl
        ns._instr.phases.begin("header_audit")
        # Universal header audit: run CORS, CSP, verbose-error validators
        # against EVERY captured exchange from discovery + feature_crawl.
        # This catches header-level issues the LLM agents never labelled.
        ns._all_captured = list(getattr(ns.rc, "captured", None) or [])
        try:
            ns._all_captured.extend(ns.feature_caps)  # noqa: F821 -- set in the feature_crawl block above
        except NameError:
            pass
        if not (ns.stop_on_confirm and ns.objective_class):
            try:
                await universal_header_audit(self, ns.state, ns._all_captured, run_context=ns.run_context)
            except Exception as e:
                log.warning("investigate_engagement: universal header audit failed: %s", e)
                ns._errors.append({"phase": "universal_header_audit", "error": f"{type(e).__name__}: {e}"})
                from harness import telemetry
                telemetry.record_swallowed_exception("universal_header_audit", e)

        async def _probe(exchange, hypothesis, specialty, sb):
            # ARCH-1: forward THIS engagement's run_context so the iterative
            # probe's sends spend the run's budget/transport, not a throwaway one.
            return await self.run_active_probe(exchange, hypothesis, specialty,
                                               step_budget=sb, run_context=ns.run_context,
                                               deadline=ns._investigation_deadline)
        ns._probe = _probe

        # Cross-identity confirmation for the investigation path: register the
        # roles as replay identities and confirm access-control findings the
        # iterative agent reaches -- turning its unconfirmed guesses into
        # deterministically CONFIRMED findings (via the Autorize-style replay), so
        # a proven bug lands as `validated` and outranks the model's claims.
        from harness import identity_headers
        from harness import access_control_gate
        from harness.validators.cross_identity_validator import CrossIdentityValidator
        from harness.validators.idor_read_validator import IdorReadValidator
        from harness.validators.browser_xss_validator import BrowserXssValidator
        from harness.validators.jwt_forge_validator import JwtForgeValidator
        from harness.validators.ssrf_validator import SsrfValidator
        from harness.validators.xxe_validator import XxeValidator
        from harness.validators.command_injection_validator import CommandInjectionValidator
        from harness.validators.ssti_validator import SstiValidator
        from harness.validators.path_traversal_validator import PathTraversalValidator
        from harness.validators.open_redirect_validator import OpenRedirectValidator
        from harness.validators.sequence_validator import SequenceValidator
        from harness.validators.deserialization_oob_validator import DeserializationOobValidator
        from harness.validators.auth_sequence_validator import AuthSequenceValidator, _is_logout_class
        from harness.validators.stored_xss_validator import StoredXssValidator
        from harness.validators.rate_limit_validator import RateLimitValidator
        from harness.validators.reset_token_validator import ResetTokenValidator
        from harness.validators.dom_xss_validator import DomXssValidator
        from harness.validators.toctou_validator import ToctouValidator
        from harness.validators.csrf_validator import CsrfValidator
        from harness.validators.nosql_validator import NosqlValidator
        from harness.validators.race_condition_validator import RaceConditionValidator
        from harness.validators.sqlmap import SqlmapValidator
        from harness.validators.client_trust_validator import ClientTrustValidator
        from harness.validators.base import ValidationResult
        from harness import missing_auth_probe
        from harness.models import Finding
        host = urlsplit(ns.base_url).hostname or ""
        if ns.run_context is not None:
            declarations = ((self.config.get("engagement", {}) or {})
                            .get("declared_workflows", []))
            if declarations:
                try:
                    executed = await engagement_builder.execute_declared_workflows(
                        declarations, ns.run_context)
                    ns.workflow_results = [r.to_dict() for r in executed]
                except Exception as e:
                    ns._errors.append({"phase": "declared_workflows",
                                       "error": f"{type(e).__name__}: {e}"})
        for r in ns.roles:
            if r.headers:
                # Register under a DISTINCT principal id (R10): two same-role users
                # with different credentials must not overwrite each other under a
                # shared `role` key. Role is still carried for privilege checks.
                identity_headers.set_identity(host, r.principal_id(), dict(r.headers), r.role)
        ns.ownership = self._configure_ownership(ns.base_url, engagement_owners=getattr(ns.state, "owners", None),
                                                 run_context=ns.run_context, install=False)
        if ns.run_context is not None:
            # R11-5: the engagement's protected routes, for the write checks.
            ns.run_context.protected_paths = list(getattr(ns.state, "protected_paths", None) or [])
        if (ns.ownership is None and ns.run_context is not None
                and self._experiments_config().get("enabled", False)):
            # Ticket G: share ONE ledger between the experiment cycle and the
            # cross-identity validator, so an ownership fact an experiment
            # establishes is what that validator consults.
            ns.ownership = self._experiment_ownership(ns.state, ns.run_context, ns.base_url)
        _xid_cfg = (self.config.get("validators", {}) or {}).get("cross_identity", {}) or {}
        from harness.config_schema import parse_validators_flags
        ns._xval = CrossIdentityValidator(
            allowed_hosts=self.allowed_hosts,
            timeout=float(_xid_cfg.get("timeout", 10.0)),
            max_identities=int(_xid_cfg.get("max_identities", 3)),
            run_context=ns.run_context,
            # WL-04: the registry's declared-ownership source (D1 seam); None means
            # a cross-identity match is a `supported` lead, never a confirmation.
            ownership=ns.ownership,
            # B1-T2: the same write policy the registry builds with, so what
            # applies()/write_admitted() admit is what this path executes.
            delete_restore_method=str(_xid_cfg.get("delete_restore_method", "")),
            allow_writes=parse_validators_flags(
                self.config.get("validators", {}) or {})["allow_mutating_replay"])
        # Single-principal IDOR read-differential: swap the object id (no second
        # account needed). Seed it with foreign ids observed elsewhere in the run
        # (other users mentioned in public content, ids seen in links) so a
        # username-keyed IDOR is reachable, not just numeric neighbours. Alone it
        # never confirms (RV-D2): one principal cannot show the object is
        # unauthorised. It confirms only when the shared ownership ledger
        # (declared, else self-observed) places the object with another account.
        _idor_cfg = (self.config.get("validators", {}) or {}).get("idor_read", {}) or {}
        ns._idor_read = IdorReadValidator(
            allowed_hosts=self.allowed_hosts,
            # Observed ids (mined from content) plus any target object ids the
            # operator declared for this engagement (e.g. a known victim account,
            # like a tester who was told which record to reach).
            candidate_ids=(list(_idor_cfg.get("candidate_ids", []) or [])
                           + _harvest_object_ids(ns._all_captured, {r.principal_id() for r in ns.roles})),
            ownership=ns.ownership, run_context=ns.run_context)
        ns._bxss = BrowserXssValidator(allowed_hosts=self.allowed_hosts, run_context=ns.run_context)
        ns._jwt = JwtForgeValidator(allowed_hosts=self.allowed_hosts,
                                    run_context=ns.run_context)
        from harness.collaborator import ConfiguredCollaborator
        _callbacks = getattr(getattr(self, "validator_registry", None), "collaborator", None) or ConfiguredCollaborator(self.config)
        ns._ssrf = SsrfValidator(allowed_hosts=self.allowed_hosts, collaborator=_callbacks, oob_callbacks_enabled=bool((self.config.get("validators") or {}).get("oob_callbacks_enabled", True)))
        ns._xxe = XxeValidator(allowed_hosts=self.allowed_hosts, collaborator=_callbacks, oob_callbacks_enabled=bool((self.config.get("validators") or {}).get("oob_callbacks_enabled", True)))
        ns._cmdi = CommandInjectionValidator(allowed_hosts=self.allowed_hosts,
                                             run_context=ns.run_context, collaborator=_callbacks, oob_callbacks_enabled=bool((self.config.get("validators") or {}).get("oob_callbacks_enabled", True)))
        # Stored SSTI often writes a preference/editor value and evaluates it on
        # a separate public render.  Supply only GET pages already observed in
        # this engagement; the validator keeps the set bounded and same-origin.
        _ssti_readbacks = _ssti_readback_urls(ns._all_captured)
        _ssti_readbacks.sort(key=lambda u: ("/post" not in urlsplit(u).path.lower(), u))
        ns._ssti = SstiValidator(allowed_hosts=self.allowed_hosts,
                                 run_context=ns.run_context,
                                 readback_urls=_ssti_readbacks)
        ns._path = PathTraversalValidator(allowed_hosts=self.allowed_hosts,
                                          run_context=ns.run_context)
        ns._redir = OpenRedirectValidator(allowed_hosts=self.allowed_hosts)
        ns._seq = SequenceValidator(allowed_hosts=self.allowed_hosts)
        ns._deser = DeserializationOobValidator(allowed_hosts=self.allowed_hosts)
        ns._auth = AuthSequenceValidator(allowed_hosts=self.allowed_hosts)
        _ct = ClientTrustValidator(allowed_hosts=self.allowed_hosts)
        # Write integrity: creates (or updates) that are read back and undone. Its
        # restore routes are the operator's declarations plus every route this
        # engagement observed; nothing is written for a create with no DELETE route.
        from harness.validators.write_integrity_validator import (
            WriteIntegrityValidator, chain_routes as _wi_routes)
        ns._wi_cfg = ((self.config.get("validators", {}) or {}).get("write_integrity", {}) or {})
        ns._wi = WriteIntegrityValidator(allowed_hosts=self.allowed_hosts, run_context=ns.run_context,
                                         restore_routes=ns._wi_cfg.get("restore_routes") or (),
                                         route_inventory=lambda: list(ns.state.endpoints),
                                         allow_writes=parse_validators_flags(
                                          self.config.get("validators", {}) or {})["allow_mutating_replay"])
        ns._wi.ownership = ns.ownership
        ns._sxss = StoredXssValidator(allowed_hosts=self.allowed_hosts, run_context=ns.run_context)
        ns._rate = RateLimitValidator(allowed_hosts=self.allowed_hosts,
                                      run_context=ns.run_context)
        ns._reset = ResetTokenValidator(allowed_hosts=self.allowed_hosts)
        ns._domxss = DomXssValidator(allowed_hosts=self.allowed_hosts, run_context=ns.run_context)
        ns._toctou = ToctouValidator(allowed_hosts=self.allowed_hosts,
                                     run_context=ns.run_context)
        _csrf = CsrfValidator(allowed_hosts=self.allowed_hosts,
                              run_context=ns.run_context)
        ns._nosql = NosqlValidator(allowed_hosts=self.allowed_hosts,
                                   run_context=ns.run_context)
        _race_cfg = ((self.config.get("validators", {}) or {}).get("race_condition", {}) or {})
        _race = RaceConditionValidator(
            timeout=float(_race_cfg.get("timeout", 15.0)),
            burst_size=int(_race_cfg.get("burst_size", 12)),
            run_context=ns.run_context,
            target_email=_race_cfg.get("target_email"),
            mailbox_url=_race_cfg.get("mailbox_url"),
            email_race_rounds=int(_race_cfg.get("email_race_rounds", 6)))
        _sql_cfg = ((self.config.get("validators", {}) or {}).get("sqlmap", {}) or {})
        _sqlmap = SqlmapValidator(
            binary=_sql_cfg.get("binary", "sqlmap"),
            timeout_seconds=int(_sql_cfg.get("timeout_seconds", 90)),
            level=int(_sql_cfg.get("level", 1)),
            risk=int(_sql_cfg.get("risk", 1)),
            create_endpoint_max_requests=int(_sql_cfg.get("create_endpoint_max_requests", 200)),
            container_image=_sql_cfg.get("container_image"),
            run_context=ns.run_context,
            allowed_hosts=self.allowed_hosts,
            quick_only=bool(ns.stop_on_confirm and ns.objective_class == "sqli"),
        )

        # Memoisation cache: avoid re-running the same validator on the same
        # endpoint during one investigate_engagement() call (see _ConfirmationCache).
        from harness.validators.base import (
            ValidationResult as _VR, observed_result_of, proof_artifact_kwargs)
        # E4: `_exec_registry` (made before the header audit) is also read by the
        # model-review path (orchestrator_confirm._validate_findings) through
        # run_context, so a check that ran for the worklist is not run again for the
        # review or the drive.
        ns._cached_validate = _ConfirmationCache(
            ns.run_context, lambda cls, exchange: _rb4_case(cls, exchange).case_id,
            registry=ns._exec_registry).confirm

        # RB-4/INV-2: this path (worklist_investigator's confirm_fn for agent
        # findings, and its precondition_fn for every shape-driven leg dispatch
        # through _confirm/_apply below) used to stamp `confirmed`/
        # `confirmed_by_leg` with NO persisted ProofRecord and NO evidence_ledger
        # VALIDATION_DECISION behind it -- the exact GT04/05/06 gap INV-2 traced
        # (docs/investigations/INV-2-proof-gap.md). One run-scoped id (not
        # per-call) so every case _apply builds this run shares a stable
        # run_id, matching how PASS1's RunContext-derived run_id is stable across
        # one analyze() call.
        _rb4_run_id = ns.run_context.run_id if ns.run_context is not None else uuid.uuid4().hex
        from harness.categories import canonicalize as _rb4_canon
        from harness import evidence_ledger

        def _rb4_principal_for(exchange) -> str:
            """Best-effort identity label for the case: the role whose headers
            match this exchange's request headers, else "" (anonymous/unlabelled).
            Only affects case-identity bookkeeping, never the confirmation verdict."""
            hdrs = dict(exchange.request_headers or {})
            if not hdrs:
                return "anonymous"
            for r in ns.roles:
                if dict(r.headers or {}) == hdrs:
                    pid = getattr(r, "principal_id", None)
                    return str(pid()) if callable(pid) else (getattr(r, "role", None) or "")
            return ""

        def _rb4_case(vulnerability_class, exchange):
            """The case _apply binds a graph-loop confirmation to."""
            check_id = _rb4_canon(vulnerability_class or "") or (vulnerability_class or "")
            template_id = evidence._short(
                (exchange.method or "").upper(), exchange.url or "", exchange.request_body or "")
            return evidence.TestCaseRef.make(
                run_id=_rb4_run_id, request_template_id=template_id,
                check_id=check_id, principal_id=_rb4_principal_for(exchange))

        def _proven_parameter(finding, res) -> tuple[str, str]:
            """(location, name) of the input the leg proved: the finding's own
            parameter, else the one the leg reports (tested_parameters for a
            per-parameter leg, sqlmap's single injection point), else ("", "")."""
            name = str(finding.get("parameter_name") or "")
            if name:
                return str(finding.get("parameter_location") or ""), name
            tested = tuple(getattr(res, "tested_parameters", ()) or ())
            if len(tested) == 1:
                return str(tested[0][0] or ""), str(tested[0][1] or "")
            points = {(p.get("place", ""), p.get("parameter", ""))
                      for p in (getattr(res, "injection_points", ()) or ())
                      if isinstance(p, dict) and p.get("parameter")}
            if len(points) == 1:
                return next(iter(points))
            return "", ""

        async def _bind_stored(finding, res, validator_name, exchange, **binding):
            # `binding`: store.bind_confirmation_proof's narrowing keywords; the
            # coverage drive passes them (its proofs prove no particular row).
            try:
                location, name = _proven_parameter(finding, res)
                proven = Finding(
                    vulnerability_class=finding.get("vulnerability_class") or validator_name,
                    confidence=float(finding.get("confidence", 0.9) or 0.9),
                    severity=finding.get("severity") or "high",
                    summary=finding.get("summary") or f"{validator_name} confirmed on {exchange.url}",
                    evidence=finding.get("evidence") or "",
                    suggested_test=finding.get("suggested_test") or "", basis="derived",
                    review_verdict="validator-confirmed", confirmed=True,
                    proof_id=finding["proof_id"], case_id=finding["case_id"],
                    confirmed_by_leg=validator_name,
                    parameter_location=location, parameter_name=name)
                await asyncio.to_thread(store.bind_confirmation_proof, exchange, proven,
                                        validator_name, **binding)
            except Exception as e:  # bookkeeping never sinks the graph loop
                log.debug("r5: binding %s proof to stored findings failed on %s: %s",
                          validator_name, exchange.url, e)
        ns._bind_stored = _bind_stored

        async def _apply(finding, res, leg, floor, exchange):
            # I04: an unconfirmed check that leaves a human-verifiable candidate
            # puts its copy-ready steps in the finding's next step.
            _guide = getattr(res, "manual_verification", "") if res is not None else ""
            if _guide and not res.confirmed:
                _previous = (finding.get("suggested_test") or "").strip()
                finding["manual_verification"] = _guide
                finding["suggested_test"] = _guide + (
                    f"\n\nAgent suggestion: {_previous}"
                    if _previous and _guide not in _previous else "")
            if res is not None and res.status == "confirmed" and res.confirmed:
                finding["confirmed"] = True
                finding["confidence"] = max(float(finding.get("confidence", 0) or 0), float(res.confidence or floor))
                finding["evidence"] = ((finding.get("evidence") or "") + f" || {leg} CONFIRMED: "
                                       + (res.summary or "")).strip(" |")
                # Step 4 (2026-09-17 coverage-recovery plan): the STRUCTURED leg
                # name, set at the SAME moment as the evidence stamp above -- this
                # is the dominant confirmation path in the graph loop (both
                # worklist_investigator's confirm_fn for agent findings and its
                # precondition_fn for every shape-driven leg dispatch through
                # here), and until now it stamped confirmation ONLY into the
                # free-text evidence string, recoverable only by regex.
                finding["confirmed_by_leg"] = leg.replace("-", "_")
                if getattr(res, "header_fingerprint", ""):
                    finding["header_fingerprint"] = res.header_fingerprint   # E2: issue grouping
                # RB-4/INV-2: route this GENUINE confirmation through the SAME
                # proof persistence + evidence_ledger emission PASS1's
                # _validate_findings uses (ConfirmMixin._persist_confirmation_proof)
                # -- reused, not reimplemented. Only reached when res.confirmed is
                # True (this whole block is inside that check), so a suppressed/
                # not-confirmed leg NEVER builds a case or persists a proof here --
                # no orphan proofs. Best-effort: any failure is logged and
                # swallowed, exactly like the coverage-driven leg's _coverage_proof
                # -- a proof/ledger hiccup must never sink the graph loop or alter
                # the confirmation this function already decided above.
                try:
                    case = _rb4_case(finding.get("vulnerability_class") or "", exchange)
                    validator_name = leg.replace("-", "_")
                    ok, proof_dict, reason = await self._persist_confirmation_proof(
                        case=case, validator_name=validator_name,
                        status=res.status, confirmed=res.confirmed,
                        observed_result=observed_result_of(res),
                        proof_artifacts=proof_artifact_kwargs(res),
                        finding_ref=case.case_id,
                        ledger_summary=(f"{validator_name}: {res.status} (confirmed)"
                                        + (f" -- {res.summary}" if res.summary else "")),
                        ledger_data={"validator": validator_name, "status": res.status,
                                     "confirmed": True, "confidence": res.confidence,
                                     "evidence": (res.evidence or "")[:1000]})
                    if ok:
                        finding["proof_id"] = proof_dict["proof_id"]
                        finding["case_id"] = case.case_id
                        # r5: bind the proof to the stored finding of its own
                        # class (and proven parameter) on this route, so the
                        # findings table carries the confirmation too.
                        await _bind_stored(finding, res, validator_name, exchange)
                        # The shape-driven legs' own probes (e.g.
                        # CrossIdentityValidator) don't thread case_ref through the
                        # shared TargetTransport, so a real reconstruct_persisted()
                        # read would otherwise see no EXECUTION event at all for
                        # this case (what_sent/what_came_back would stay empty even
                        # though `complete` is already True from VALIDATION_DECISION
                        # above). Stamp one summary EXECUTION event from data
                        # already in hand here -- instrumentation only, via the
                        # SAME evidence_ledger.emit API, never a second ledger.
                        evidence_ledger.emit(
                            evidence_ledger.EventType.EXECUTION, case.case_id,
                            f"{validator_name} probe against {exchange.url}"[:500],
                            data={"request": f"{(exchange.method or 'GET').upper()} {exchange.url}",
                                  "response": (res.evidence or res.summary or "")[:1000]},
                            provenance=evidence_ledger.Provenance.capture(
                                config=getattr(self, "config", {})),
                            case_ref=case.case_id)
                    else:
                        log.debug("RB-4: engagement-path proof persistence failed for "
                                 "%s leg on %s: %s", validator_name, exchange.url, reason)
                except Exception as e:
                    log.debug("RB-4: engagement-path proof bookkeeping failed for "
                             "%s leg on %s: %s", leg, exchange.url, e)

        def _as_finding(finding, default_class):
            return Finding(vulnerability_class=finding.get("vulnerability_class") or default_class,
                           confidence=float(finding.get("confidence", 0.5) or 0.5),
                           severity=finding.get("severity") or "medium",
                           summary=finding.get("summary") or default_class,
                           evidence=finding.get("evidence") or "",
                           suggested_test=finding.get("suggested_test") or "", basis="derived",
                           parameter_location=str(finding.get("parameter_location") or ""),
                           parameter_name=str(finding.get("parameter_name") or ""))
        ns._as_finding = _as_finding

        _protected: list = []   # RV-S: this target's declared routes, built on first use

        async def _confirm(finding, exchange):
            """Dispatch a finding to the deterministic confirmation leg for its class:
            access-control -> cross-identity replay; xss -> headless-browser execution.
            A confirmed finding is upgraded in place; anything else is left untouched."""
            vc = (finding.get("vulnerability_class") or "")
            low = vc.lower()
            _method = (exchange.method or "GET").upper()
            if _missing_auth_class(vc, _method):
                # Replay the captured read with every credential stripped. This is
                # not an IDOR/BFLA comparison and needs no second user. An anonymous
                # payload confirms only for a route declared protected (RV-G R15).
                # A model label or a privileged-looking path is a hypothesis, not
                # that declaration (RV-M M1); the operator's list of protected path
                # patterns is (RV-S: authz.protected_paths in config, plus the
                # engagement's protected_paths). A listed route must also return
                # the authenticated baseline's payload to the anonymous replay; an
                # unlisted route stays an unconfirmed `unauthenticated_access`
                # candidate.
                try:
                    from harness import protected_routes
                    parts = urlsplit(exchange.url)
                    path = parts.path or "/"
                    if parts.query:
                        path += "?" + parts.query
                    method = (exchange.method or "GET").upper()
                    if not _protected:
                        _protected.append(protected_routes.ProtectedRoutes.for_target(
                            self.config, ns.base_url,
                            engagement_paths=getattr(ns.state, "protected_paths", None)))
                    declared = _protected[0].match(method, exchange.url)
                    baseline = exchange.request_headers
                    # The anonymous replay keeps only public headers, so a supplied
                    # identity's custom header (X-Tenant) never rides along on it;
                    # the same names count as the baseline's credentials, so an app
                    # that authenticates only through one can confirm (RV-S
                    # residuals 2 and 3).
                    supplied = {k.lower() for r in ns.roles for k in (r.headers or {})}

                    def _credential(name):
                        return missing_auth_probe.credential_header(name, supplied)

                    if declared is not None and not any(_credential(k) for k in (baseline or {})):
                        # The probe identity of an anonymously reached node is
                        # anonymous, so the baseline borrows the highest-trust
                        # supplied identity's credential headers.
                        authed = [r for r in ns.roles if any(_credential(k) for k in (r.headers or {}))]
                        if authed:
                            top = max(authed, key=lambda r: role_crawl._trust(r.role))
                            baseline = {**(baseline or {}), **{
                                k: v for k, v in top.headers.items() if _credential(k)}}
                    # ARC-7: the probe sends only through a run. This analysis's run
                    # (or the enclosing one) when there is one, else a standalone one
                    # that is closed here.
                    _probe_run = ns.run_context or _run_context_mod.current_run_context()
                    _probe_owned = None
                    if _probe_run is None:
                        _probe_owned = _probe_run = _run_context_mod.standalone_context(
                            self.allowed_hosts, config=self.config, active_mode=True)
                    try:
                        outcome = await missing_auth_probe.probe(
                            ns.base_url, (method, path),
                            allowed_hosts=self.allowed_hosts,
                            baseline_headers=baseline,
                            send_garbage_token=False,
                            expected_protected=declared is not None,
                            protected_baseline=True,
                            run_context=_probe_run,
                            identity_headers=supplied)
                    finally:
                        if _probe_owned is not None:
                            await _probe_owned.aclose()
                    if outcome.finding is not None:
                        proof = outcome.finding
                        why = (f" Route declared protected by {declared.describe()}."
                               if declared is not None else "")
                        await _apply(
                            finding,
                            ValidationResult(
                                validator="missing_auth_probe",
                                status="confirmed" if proof.confirmed else "inconclusive",
                                finding_class="missing_authentication",
                                confidence=proof.confidence, confirmed=bool(proof.confirmed),
                                summary=proof.summary + why, evidence=proof.evidence + why),
                            "missing-auth", 0.85, exchange)
                        if proof.confirmed and declared is not None:
                            finding["protected_route"] = declared.to_dict()
                        elif declared is None and not finding.get("confirmed"):
                            # The route served data anonymously but is not declared:
                            # say how to declare it (I16), in the next step only, so
                            # the summary and evidence stay as they were.
                            _hint = _protected[0].declaration_hint(method, exchange.url)
                            _previous = (finding.get("suggested_test") or "").strip()
                            if _hint and _hint not in _previous:
                                finding["suggested_test"] = (
                                    f"{_hint}\n\n{_previous}" if _previous else _hint)
                except Exception:
                    return
            elif _wi_routes(vc, exchange) and (self.config.get("validators", {}) or {}).get(
                    "write_integrity", {}).get("enabled", True) is not False:
                # Before access control: "cross_identity_write" and friends are
                # creates this leg reads back and deletes, not object reads.
                try:
                    await _apply(finding, await ns._cached_validate(ns._wi, _as_finding(finding, "write_integrity"), exchange, routed_class="write_integrity"),
                           "write-integrity", 0.9, exchange)
                except Exception:
                    return
            elif (access_control_gate._is_access_control_class(vc)
                  and not _authentication_only_class(vc)):
                _gap = _access_control_shape_gap(exchange, ns._xval)
                if _gap:
                    # No baseline GET to a POST route, no replay of a list read.
                    _record_no_applicable_leg(finding, "cross-identity", _gap)
                    return
                # populate the candidate baseline: the probe role's own response.
                # A write takes its own owner baseline inside the write leg.
                if (_method == "GET" and exchange.response_status is None
                        and scope_discovery.is_host_allowed(exchange.url, self.allowed_hosts)):
                    # W-16: baseline read through the single TargetTransport (this run's
                    # when present, else a standalone one). send_creds forwards the probe
                    # role's own credentials; max_redirects=0 == follow_redirects=False.
                    _tt, _owned = transport_for(ns.run_context, allowed_hosts=self.allowed_hosts,
                                                config=self.config, active_mode=True)
                    try:
                        await global_throttle.acquire()
                        out = await _tt.send_creds("GET", exchange.url,
                                                   capability="access_control_baseline",
                                                   headers=exchange.request_headers, max_redirects=0)
                        if not out.ok:
                            return
                        exchange.response_status, exchange.response_body = out.status, (out.body or "")
                    except Exception:
                        return
                    finally:
                        if _owned is not None:
                            await _owned.aclose()
                try:
                    await _apply(finding, await ns._cached_validate(ns._xval, _as_finding(finding, "idor"), exchange, routed_class="idor"), "cross-identity", 0.9, exchange)
                    # Single-principal follow-up: if no second identity confirmed a
                    # cross-identity breach, run the object-id read differential
                    # (own vs foreign vs absent) as the captured principal. It never
                    # confirms (RV-D2), so `_apply` leaves the finding unconfirmed
                    # and keeps only any manual-verification guidance it carries.
                    if not finding.get("confirmed"):
                        await _apply(finding, await ns._cached_validate(ns._idor_read, _as_finding(finding, "idor"), exchange, routed_class="idor"), "idor-read", 0.75, exchange)
                except Exception:
                    return
            elif ("dom" in low and "xss" in low) or "dom_xss" in low or "dom-based" in low or "client-side xss" in low:
                # DOM-based XSS: fragment-payload browser execution (client-side
                # source->sink), distinct from server-reflected browser_xss.
                try:
                    await _apply(finding, await ns._cached_validate(ns._domxss, _as_finding(finding, "dom_xss"), exchange, routed_class="dom_xss"),
                           "dom-xss", 0.95, exchange)
                except Exception:
                    return
            elif "xss" in low or "cross-site scripting" in low or "cross_site" in low:
                # browser_xss executes payloads in a real browser; it CONFIRMS reflected
                # XSS and (crucially for a JSON API) declines what never reaches an HTML
                # sink. Skips gracefully if no browser engine is installed.
                try:
                    await _apply(finding, await ns._cached_validate(ns._bxss, _as_finding(finding, "xss"), exchange, routed_class="xss"), "browser-xss", 0.95, exchange)
                    # reflected browser_xss handles GET reflections; a write-shaped
                    # exchange may instead be a STORED-XSS plant point -- try that leg too.
                    if not finding.get("confirmed") and (exchange.method or "GET").upper() in ("POST", "PUT", "PATCH"):
                        await _apply(finding, await ns._cached_validate(ns._sxss, _as_finding(finding, "xss"), exchange, routed_class="xss"), "stored-xss", 0.9, exchange)
                except Exception:
                    return
            elif "jwt" in low or "algorithm confusion" in low or "algorithm_confusion" in low or "weak_token" in low:
                try:
                    await _apply(finding, await ns._cached_validate(ns._jwt, _as_finding(finding, "jwt"), exchange, routed_class="jwt"), "jwt-forge", 0.9, exchange)
                except Exception:
                    return
            elif "ssrf" in low or "server-side request" in low or "server_side_request" in low:
                try:
                    await _apply(finding, await ns._cached_validate(ns._ssrf, _as_finding(finding, "ssrf"), exchange, routed_class="ssrf"), "ssrf", 0.95, exchange)
                except Exception:
                    return
            elif "xxe" in low or "xml external" in low or "xml_external" in low:
                try:
                    await _apply(finding, await ns._cached_validate(ns._xxe, _as_finding(finding, "xxe"), exchange, routed_class="xxe"), "xxe", 0.95, exchange)
                except Exception:
                    return
            elif ("sqli" in low or "sql injection" in low
                  or "sql_injection" in low) and "nosql" not in low:
                # ("nosql injection" contains "sql injection": a NoSQL finding is the
                # nosql leg's, below, never sqlmap's.)
                try:
                    await _apply(
                        finding,
                        await ns._cached_validate(_sqlmap, _as_finding(finding, "sqli"), exchange, routed_class="sqli"),
                        "sqlmap", 0.95, exchange)
                except Exception:
                    return
            elif "nosql" in low or "mongodb injection" in low or "mongo injection" in low:
                try:
                    await _apply(finding, await ns._cached_validate(
                        ns._nosql, _as_finding(finding, "nosql"), exchange,
                        routed_class="nosql"),
                        "nosql", 0.95, exchange)
                except Exception:
                    return
            elif "race_condition" in low or "race condition" in low:
                try:
                    await _apply(finding, await ns._cached_validate(
                        _race, _as_finding(finding, "race_condition"), exchange,
                        routed_class="race_condition"),
                        "race-condition", 0.95, exchange)
                except Exception:
                    return
            elif "command" in low or low in ("rce", "remote code execution", "code injection", "shell injection"):
                try:
                    await _apply(finding, await ns._cached_validate(ns._cmdi, _as_finding(finding, "command_injection"), exchange, routed_class="command_injection"),
                           "command-injection", 0.95, exchange)
                except Exception:
                    return
            elif "ssti" in low or "template injection" in low:
                try:
                    await _apply(finding, await ns._cached_validate(ns._ssti, _as_finding(finding, "ssti"), exchange, routed_class="ssti"), "ssti", 0.95, exchange)
                except Exception:
                    return
            elif "traversal" in low or "lfi" in low or "file inclusion" in low:
                try:
                    await _apply(finding, await ns._cached_validate(ns._path, _as_finding(finding, "path_traversal"), exchange, routed_class="path_traversal"),
                           "path-traversal", 0.95, exchange)
                except Exception:
                    return
            elif "redirect" in low:
                try:
                    await _apply(finding, await ns._cached_validate(ns._redir, _as_finding(finding, "open_redirect"), exchange, routed_class="open_redirect"),
                           "open-redirect", 0.9, exchange)
                except Exception:
                    return
            elif ("toctou" in low or "time-of-check" in low or "time of check" in low
                  or "check-then-act" in low or "check then act" in low
                  or ("privilege" in low and "race" in low) or ("race" in low and "escalat" in low)):
                # TOCTOU privilege-escalation race: concurrent check-then-write.
                # Must precede the mass/privilege->sequence branch below.
                try:
                    await _apply(finding, await ns._cached_validate(ns._toctou, _as_finding(finding, "toctou"), exchange, routed_class="toctou"),
                           "toctou", 0.85, exchange)
                except Exception:
                    return
            elif "mass" in low or "assignment" in low or "privilege" in low or low in ("api_security", "api security"):
                try:
                    await _apply(finding, await ns._cached_validate(ns._seq, _as_finding(finding, "mass_assignment"), exchange, routed_class="mass_assignment"),
                           "sequence", 0.9, exchange)
                except Exception:
                    return
            elif "deserial" in low or "pickle" in low or "object injection" in low:
                try:
                    await _apply(finding, await ns._cached_validate(ns._deser, _as_finding(finding, "deserialization"), exchange, routed_class="deserialization"),
                           "deserialization", 0.95, exchange)
                except Exception:
                    return
            elif ("session fixation" in low or "session_fixation" in low or "weak password" in low
                  or "weak_password" in low or _USER_ENUMERATION.search(low)
                  or "broken authentication" in low
                  or "broken_authentication" in low or "2fa" in low or "mfa" in low
                  or "two_factor" in low or "two-factor" in low or "multi_factor" in low
                  or "second factor" in low or _is_logout_class(low)):
                # Only an ACCOUNT enumeration is this leg's ("Broken Object/Resource
                # Enumeration" is not), and only on a captured credential write.
                _gap = _auth_sequence_shape_gap(exchange)
                if _gap:
                    _record_no_applicable_leg(finding, "auth-sequence", _gap)
                    return
                try:
                    await _apply(finding, await ns._cached_validate(ns._auth, _as_finding(finding, low or "broken_authentication"), exchange, routed_class=low or "broken_authentication"),
                           "auth-sequence", 0.85, exchange)
                except Exception:
                    return
            elif ("client_trust" in low or "business" in low or "client-side" in low or "price" in low
                  or "excessive trust" in low or "logic_flaw" in low):
                try:
                    await _apply(finding, await ns._cached_validate(_ct, _as_finding(finding, "business_logic"), exchange, routed_class="business_logic"),
                           "client-trust", 0.9, exchange)
                except Exception:
                    return
            elif "rate limit" in low or "rate_limit" in low or "lockout" in low or "brute" in low:
                try:
                    await _apply(finding, await ns._cached_validate(ns._rate, _as_finding(finding, "rate_limit"), exchange, routed_class="rate_limit"),
                           "rate-limit", 0.85, exchange)
                except Exception:
                    return
            elif "csrf" in low or "cross-site request forgery" in low or "cross site request forgery" in low:
                try:
                    await _apply(finding, await ns._cached_validate(
                        _csrf, _as_finding(finding, "csrf"), exchange,
                        routed_class="csrf"),
                        "csrf", 0.95, exchange)
                except Exception:
                    return
            elif ("reset_token" in low or "reset token" in low or "predictable token" in low
                  or "weak token" in low or "token entropy" in low):
                try:
                    await _apply(finding, await ns._cached_validate(ns._reset, _as_finding(finding, "reset_token"), exchange, routed_class="reset_token"),
                           "reset-token", 0.9, exchange)
                except Exception:
                    return
            else:
                # r5: "Information Disclosure", "Exposed ... Data" on a non-admin
                # read: no engagement leg tests the class. Say so; never a negative.
                _record_no_applicable_leg(
                    finding, "", f"no engagement confirmation leg tests class {vc!r}")
        ns._confirm = _confirm

        # --- proactive, precondition-driven leg routing (HANDOVER_6 §4) ---------
        # Run a confirmation leg wherever the ENDPOINT'S SHAPE warrants it, not only
        # where an agent already produced a matching finding. Shape routing is the
        # module-level `shape_precondition_legs` (pure, unit-tested); the legs
        # themselves are the same deterministic validators `_confirm` dispatches to,
        # so we reuse `_confirm` here and keep only what it CONFIRMS.
        async def _confirm_leg(vclass, exchange, path):
            """Synthesise a low-confidence hypothesis of `vclass`, run it through the
            shared `_confirm` dispatcher, and return it only if a leg CONFIRMED it.
            Runs on an isolated copy so a leg that populates a baseline response
            (cross-identity) can't mutate the exchange the agent probe later uses."""
            f = {"vulnerability_class": vclass, "confidence": 0.3, "severity": "high",
                 "summary": f"{vclass} precondition on {path}", "evidence": "",
                 "suggested_test": "", "basis": "derived", "proactive_leg": vclass}
            await _confirm(f, exchange.model_copy())
            return f if f.get("confirmed") else None
        ns._confirm_leg = _confirm_leg

        async def _precondition(node, exchange):
            """Legs the node's shape warrants, run regardless of agent labels.
            Returns only CONFIRMED findings."""
            path = node.get("path", "/")
            confirmed = []
            for vclass, ex in shape_precondition_legs(node, exchange, ns.roles, ns.base_url):
                if ns.objective_class and vclass != ns.objective_class:
                    continue
                r = await _confirm_leg(vclass, ex, path)
                if r:
                    confirmed.append(r)
            return confirmed
        ns._precondition = _precondition

        # Lets the worklist spend its precondition budget only on nodes that
        # warrant a leg (pure: shape routing sends nothing).
        _precondition.warranted = lambda node, exchange: any(
            not ns.objective_class or vclass == ns.objective_class
            for vclass, _ in shape_precondition_legs(node, exchange, ns.roles, ns.base_url))
