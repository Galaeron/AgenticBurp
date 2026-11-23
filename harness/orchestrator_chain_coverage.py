"""orchestrator_chain_coverage.py -- Stage 5 of investigate_engagement: the coverage drive.

ARC-9 split of the old 2,600-line `investigate_engagement`: the body moved verbatim, cut at
top-level statements. A local that more than one stage touches is an attribute of the shared
`EngagementRun` (`ns`, built by the driver in orchestrator_chain.py); a stage that finishes
the run early returns the result, otherwise None."""
from __future__ import annotations

import time

from harness.coverage_model import derive_input_cases_from_template
from harness.models import HttpExchange
from harness.orchestrator_chain_support import _CAPTURE_INPUT_LOCATIONS, _unbuilt
from harness.orchestrator_helpers import coverage_confirmation_finding, log
from harness.validators.injection_targets import REQUEST_LEVEL_INPUTS, case_target


class ChainCoverageMixin:
    async def _engagement_stage_coverage(self, ns):
        """The coverage drive: reconcile the finished engagement into the coverage matrix and
        run its legs, with the retry rollover and the request-bound phase end."""
        from harness.validators.base import ValidationResult as _VR
        from harness import worklist_investigator
        # Coverage matrix (I1/I2/I5): reconcile the finished engagement into the
        # auditable identity x endpoint x check matrix -- every applicable check is
        # confirmed / detected (from real findings), not_detected (only from a REAL
        # driven leg execution, R01), or skipped WITH A REASON, so "what was NOT
        # tested and why" is answerable. `investigated_keys` only phrases the skip
        # reason for legs that were never recorded as executed; it never infers a
        # not_detected. The coverage-driver path records live leg outcomes cell-by-cell.
        ns._instr.phases.begin("coverage_drive")
        ns._requests_before_coverage = getattr(ns._run_budget, "used", None)
        if ns._coverage_hold:
            if ns._overlap is not None:   # the reserve is the drive's: the review stops here
                await ns._overlap.drain("coverage request reserve")
            ns._run_budget.release_hold()
        # R11-4 engagement.coverage_drive_rollover (off by default): the drive also gets
        # the time the last sliced phase left unused (PhaseSchedule.rollover), up to
        # the investigation deadline. r11's chain rounds used 0.4 s of a 3 h slice
        # while the drive stopped at its own 5 h with 283 legs not attempted. The
        # per-endpoint check share stays a share of coverage_drive_seconds.
        ns._coverage_rollover = 0.0
        if (self.coverage_drive_seconds > 0
                and (self.config.get("engagement") or {}).get("coverage_drive_rollover", False)):
            ns._coverage_rollover = ns._schedule.rollover()
        ns._coverage_deadline = (time.monotonic() + self.coverage_drive_seconds + ns._coverage_rollover
                                 if self.coverage_drive_seconds > 0 else None)
        if ns._coverage_rollover and ns._investigation_deadline is not None:
            ns._coverage_deadline = min(ns._coverage_deadline, ns._investigation_deadline)
        ns._instr.phases.set_budget("coverage_drive", ns._budget_left(ns._coverage_deadline))
        ns.coverage: dict = {}
        # The driven tracker, kept so retry rounds' findings can be recorded into it
        # (coverage_tracker.refresh_after_retry_rounds).
        ns._coverage_trackers: list = []
        ns._prerequisite_blocks: dict = {}   # (endpoint, identity) -> grouped entry (E5b)
        # R11-4: what the final pass needs to go on with the drive -- its leg callable,
        # its mode, the replays the per-endpoint share held, and the share ledger.
        ns._drive_hooks: dict = {}
        ns._held_cells: dict = {}            # cell key -> the held replays of that cell
        ns._held_pass: dict = {"active": False, "stop_at": None}
        try:
            from harness import coverage_tracker
            # E7: a caller's checkpoint wins; otherwise the journal's, when an earlier attempt
            # got far enough to write one. It is handed back every N legs of the drive.
            _coverage_kwargs: dict = {"tracker_out": ns._coverage_trackers}
            if ns._journal is not None:
                _coverage_kwargs["on_checkpoint"] = lambda cp: ns._journal_put("coverage:checkpoint", cp)
                _stored_checkpoint = (ns._journal_read(lambda: ns._journal.get("coverage:checkpoint"), None)
                                      if ns._resuming and ns.coverage_checkpoint is None else None)
                if _stored_checkpoint is not None:
                    ns.coverage_checkpoint = _stored_checkpoint
                    ns._resumed_units["coverage_checkpoint"] = True
            investigated_paths = {o.get("path") for o in ns.outcomes if o.get("path")}
            ns.investigated_keys = {k for k in ns.state.endpoints
                                    if k.split(" ", 1)[-1] in investigated_paths}
            if self.engagement_coverage_drive:
                # I1 matrix-driver: build a confirmation->validator map (reusing the
                # instances above + a few cheap extra legs) and actively fire each
                # applicable leg-backed cell, recording the real leg status.
                from harness.validators.verb_tamper_validator import VerbTamperValidator
                from harness.validators.csrf_validator import CsrfValidator
                from harness.validators.file_upload_validator import FileUploadValidator
                _val_by_conf = {
                    "cross_identity": ns._xval, "idor_read": ns._idor_read, "jwt_forge": ns._jwt, "browser_xss": ns._bxss,
                    "stored_xss": ns._sxss, "ssrf": ns._ssrf, "xxe": ns._xxe,
                    "command_injection": ns._cmdi, "ssti": ns._ssti, "path_traversal": ns._path,
                    "open_redirect": ns._redir, "sequence": ns._seq, "deserialization_oob": ns._deser,
                    "auth_sequence": ns._auth, "rate_limit": ns._rate, "reset_token": ns._reset,
                    "dom_xss": ns._domxss, "toctou": ns._toctou, "write_integrity": ns._wi,
                    # Its override POSTs can create; they are undone through the
                    # same restore routes as write_integrity's creates.
                    "verb_tamper": VerbTamperValidator(allowed_hosts=self.allowed_hosts,
                                                         run_context=ns.run_context,
                                                         restore_routes=ns._wi_cfg.get("restore_routes") or (),
                                                         route_inventory=lambda: list(ns.state.endpoints)),
                    "csrf": CsrfValidator(allowed_hosts=self.allowed_hosts,
                                           run_context=ns.run_context),
                    "nosql": ns._nosql,
                    "file_upload": FileUploadValidator(allowed_hosts=self.allowed_hosts,
                                                         run_context=ns.run_context),
                }
                _sqlmap_inst = self.validator_registry.validators.get("sqlmap")
                if _sqlmap_inst is not None:
                    _val_by_conf["sqlmap"] = _sqlmap_inst
                # These registered validators have check-specific oracles. Do not
                # wire generic recon/crypto here: their aggregate verdict cannot
                # establish each individual header, metadata, method or TLS check.
                # security_headers, error_handling and content_exposure are passive:
                # they judge the captured response. listing_exposure, filter_bypass,
                # metrics_exposure, sensitive_file and well_known send GETs (exposure_leads).
                # client_trust (BUSL-02), websocket (CLNT-10) and oauth (ATHZ-05) each
                # answer one row; capability_for_check holds their gates and shapes.
                for name in ("csp", "cors", "header_injection", "http_request_smuggling",
                             "race_condition", "security_headers", "error_handling",
                             "content_exposure", "listing_exposure", "filter_bypass",
                             "metrics_exposure", "sensitive_file", "well_known",
                             "client_trust", "websocket", "oauth", "business_flow"):
                    registered = self.validator_registry.validators.get(name)
                    if registered is not None:
                        _val_by_conf[name] = self.validator_registry.bind_run_context(
                            [registered], ns.run_context)[0]
                # An explicit disabled setting also applies to locally assembled
                # legs. Never advertise an unavailable validator as executable.
                # cross_identity is the exception: its flag arms the registry's
                # tester-fed instance (off in the committed config), while this leg
                # is built above from the engagement's own identities whatever that
                # flag says. Honouring it here dropped IDOR/BOLA from every drive.
                _validator_config = self.config.get("validators", {})
                _val_by_conf = {name: validator for name, validator in _val_by_conf.items()
                                if _validator_config.get("enabled", True)
                                and (name == "cross_identity"
                                     or _validator_config.get(name, {}).get("enabled", True))}
                # Key headers by DURABLE PRINCIPAL id (R02), matching the coverage
                # identity, so two same-role accounts don't collapse/overwrite.
                def _pid(r):
                    p = getattr(r, "principal_id", None)
                    return str(p()) if callable(p) else (getattr(r, "role", None) or "anonymous")
                _role_headers = {_pid(r): dict(r.headers or {}) for r in ns.roles}

                def _capability_decision(check, exchange):
                    resolve = getattr(self.validator_registry, "capability_for_check", None)
                    if resolve is None:
                        # Explicit compatibility for legacy injected registries.
                        return {"status": "ready", "reason_code": "legacy_adapter",
                                "reason": "legacy caller capability adapter",
                                "finding_class": check.leg_class or check.vulnerability_class,
                                "mechanism_id": "legacy:" + check.confirmation}
                    return resolve(check, exchange, run_context=ns.run_context,
                                   validator=_val_by_conf.get(check.confirmation, False))

                def _known_capture_exchange(identity, node):
                    # Readiness must never turn an unresolved route placeholder
                    # into an allegedly observed id=1 (or repeat a single id for
                    # several unrelated placeholders).
                    template = node.get("template") or {}
                    slots = (node.get("path") or "").count("{id}")
                    ids = template.get("path_ids") or []
                    complete = len(ids) == slots and all(v is not None and str(v) not in ("", "{id}") for v in ids)
                    legacy = slots == 1 and template.get("object_id") is not None and str(template["object_id"]) not in ("", "{id}")
                    if slots and not complete and not legacy:
                        return None, {"status": "needs_prerequisite", "reason_code": "missing_object_id",
                                      "reason": "route placeholders have no complete observed object identifiers", "finding_class": None}
                    if legacy:
                        node = dict(node, template=dict(template, object_id=str(template["object_id"])))
                    route = _client_route_of(node)
                    if route is not None:
                        # A client-side route the run knows only from the page: load
                        # the route's own page, its parameters blank.
                        node = dict(node, template=node.get("template") or route.template())
                        ex = worklist_investigator._seed_exchange(
                            ns.base_url, node, _role_headers.get(identity, {}), "")
                        return ex.model_copy(update={"url": route.seed_url(ns.base_url)}), None
                    return worklist_investigator._seed_exchange(
                        ns.base_url, node, _role_headers.get(identity, {}), ""), None

                def _client_route_of(node):
                    """The client-side route (client_routes.py) a coverage endpoint with
                    no captured request stands for, or None."""
                    key = f"{node.get('method') or 'GET'} {node.get('path') or ''}"
                    routes = getattr(ns.state, "client_routes", None)
                    if routes is None or key in ns.state.endpoints:
                        return None
                    try:
                        return routes.route_for_key(key)
                    except Exception:
                        return None

                async def _run_captured_leg(identity, method, path, check, case_key=None, node=None,
                                            remainder_only=False):
                    validator = _val_by_conf.get(check.confirmation)
                    if validator is None:
                        return None  # e.g. sqlmap/race_condition -- not driven here
                    node = node or {"method": method, "path": path}
                    # R05: replay the captured template for this endpoint if we have
                    # one, so the coverage-driven leg sends the real shape too.
                    _ep_obj = ns.state.endpoints.get(f"{method} {path}")
                    if "template" not in node and _ep_obj is not None and getattr(_ep_obj, "template", None):
                        node["template"] = _ep_obj.template
                    ex, problem = _known_capture_exchange(identity, node)
                    capability = problem or _capability_decision(check, ex)
                    if capability["status"] != "ready":
                        from harness.validators.base import ValidationResult
                        status = ("blocked" if capability["status"] == "policy_denied" else
                                  "inconclusive" if capability["status"] == "needs_prerequisite" else "skipped")
                        refused = ValidationResult(check.confirmation, status, check.vulnerability_class,
                            summary=f"{capability['reason_code']}: {capability['reason']}")
                        # Nothing was sent; a missing prerequisite is this capture's.
                        return _unbuilt(refused) if capability["status"] == "needs_prerequisite" else refused
                    try:
                        leg_case = self._coverage_case(identity=identity, check=check, exchange=ex,
                                                       case_key=case_key, run_context=ns.run_context)
                    except Exception:
                        leg_case = None
                    leg_finding = ns._as_finding({"vulnerability_class": capability["finding_class"]},
                                                 capability["finding_class"])
                    # Per-parameter dispatch: the driver hands a parameter case only
                    # to a leg that can test that input alone; bind the leg to it.
                    target = case_target(check.confirmation, case_key) if case_key is not None else None
                    # The per-finding mutating ceiling (R16) counts per case: each
                    # dispatch, per-parameter or request-level, is its own account,
                    # keyed on its case, so one leg may spend the per-check ceiling
                    # and never starves another input or captured variant. A leg the
                    # ceiling cuts off reports itself incomplete, not clean.
                    ceiling_key = (leg_case.case_id if leg_case is not None else
                                   "|".join((identity, method, path, check.id, *(target or ()))))
                    leg_finding = leg_finding.model_copy(update={"finding_id": ceiling_key})
                    if target is not None:
                        leg_finding = leg_finding.model_copy(update={
                            "parameter_location": target[0], "parameter_name": target[1],
                            "parameter_only": True})
                    elif remainder_only and check.confirmation in REQUEST_LEVEL_INPUTS:
                        # Every parameter case was tested alone: the request-level
                        # attempt tests only the input no parameter case names.
                        leg_finding = leg_finding.model_copy(update={
                            "parameter_location": REQUEST_LEVEL_INPUTS[check.confirmation],
                            "parameter_name": "", "parameter_only": True})
                    # EFF-2: the catalog chose this leg for the check's class, so only
                    # the result itself (an observation) can say it proved another.
                    res = await ns._cached_validate(
                        validator, leg_finding, ex,
                        case_ref=leg_case.case_id if leg_case is not None else "",
                        routed_class=capability["finding_class"], catalog_bound=True)
                    source = (node.get("capture") or {}).get("substituted_from")
                    if source and res is not None:
                        # R11-10: the cell, the proof and the finding all say whose
                        # capture this was; it is never this identity's own request.
                        import dataclasses as _dc
                        said = (f"substituted_from:{source}: replayed from {source}'s capture "
                                f"with {identity}'s credentials substituted")
                        res = _dc.replace(res, summary=f"{said}; {res.summary or ''}".rstrip("; "),
                                          limitation=(f"{said}; {res.limitation}"
                                                      if res.limitation else ""))
                    # T05/R26: bind a case-bound structured proof to this driven leg
                    # (concrete parameter case when the driver fanned out to one),
                    # so a coverage-driven confirmation carries a stable case id to
                    # the T01 proof store -- not just a matrix cell.
                    proof_id, case_id = await self._coverage_proof(
                        identity=identity, check=check, exchange=ex, result=res,
                        case_key=case_key, run_context=ns.run_context, case=leg_case)
                    # R06: a coverage-driven CONFIRMATION enters the SAME finding
                    # pipeline as every other confirmed finding -- ingested into
                    # `state` (=> worklist, summary, report, persistence, chain
                    # linking), not merely recorded as a matrix cell.
                    cf = coverage_confirmation_finding(res, check, ex.url, identity)
                    if cf is not None and source:
                        cf.update(replayed_from_identity=source, credential_substitution=True)
                    if cf is not None:
                        if res.confirmed and case_id:
                            cf["proof_id"] = proof_id
                            cf["case_id"] = case_id
                        ns.state.ingest_findings(ex.url, method, [cf])
                        ns.all_findings.append(cf)
                        # r10: the stored findings (findings API, report) must hear of
                        # the proof too, as the graph loop's do (_bind_stored). Only a
                        # confirmed, persisted proof binds; no request is sent here.
                        if res.status == "confirmed" and res.confirmed and proof_id and case_id:
                            leg_name = res.validator or check.confirmation

                            def _speaks_for(vulnerability_class, _v=validator, _ex=ex):
                                return _v.applies(ns._as_finding(
                                    {"vulnerability_class": vulnerability_class},
                                    vulnerability_class), _ex)
                            proven = dict(cf)
                            if target is not None:
                                proven.update(parameter_location=target[0],
                                              parameter_name=target[1])
                            await ns._bind_stored(
                                proven, res, leg_name, ex, principal_bound=True,
                                accepts_class=_speaks_for,
                                proof_note=f"{leg_name} CONFIRMED: " + (res.summary or "")
                                + (f" ({res.evidence})" if res.evidence else ""))
                    return res

                # E5b: whether each (endpoint, identity) has a request to replay,
                # worked out ONCE here rather than per check. Only requests that were
                # observed as that identity count here. An identity with none is
                # either credited to a peer (caller-independent check) or, for an
                # identity-bound check, replays another identity's capture with its
                # own credentials (R11-10 substitution, _substituted_variants below).
                from harness.engagement import (capture_identity_key, identity_variants,
                                                replayable_variants, substituted_variant)
                _identity_role = {_pid(r): r.role for r in ns.roles}
                _replayable = {
                    (ep_key, identity): replayable_variants(ep, capture_identity_key(headers))
                    for ep_key, ep in ns.state.endpoints.items() if ep.capture_variants
                    for identity, headers in _role_headers.items()}
                # Captures merged into one replay (replay_dedupe), for the report.
                _replay_merge = {"captures": 0, "replays": 0, "endpoints": set()}
                for (ep_key, identity), kept in _replayable.items():
                    every = identity_variants(ns.state.endpoints[ep_key],
                                              capture_identity_key(_role_headers[identity]))
                    _replay_merge["captures"] += len(every)
                    _replay_merge["replays"] += len(kept)
                    if len(kept) < len(every):
                        _replay_merge["endpoints"].add(ep_key)
                # Per-(endpoint, check) wall-time bound while the drive is time-bound:
                # one slow endpoint (a long-poll route captured 23 times in r9) must
                # not take the time every other endpoint's checks needed. Access-control
                # checks compare identities, so each identity gets its own share.
                _share = float(getattr(self, "coverage_endpoint_check_share", 0.0) or 0.0)
                _endpoint_check_cap = (self.coverage_drive_seconds * _share
                                       if self.coverage_drive_seconds > 0 and _share > 0 else None)
                _endpoint_check_spent: dict = {}
                _endpoint_check_capped: dict = {}
                _PER_IDENTITY_SHARE = frozenset({"cross_identity", "idor_read"})

                def _capture_peer(ep_key, identity, check):
                    """R11-10: for a check whose verdict does not depend on the caller,
                    another identity that holds a replayable capture of the endpoint
                    runs it for every identity; nothing is sent as this one. None for
                    an identity-bound check: that cell stays missing_principal."""
                    if not getattr(check, "caller_independent", False):
                        return None
                    return next((other for other in sorted(_role_headers)
                                 if other != identity and _replayable.get((ep_key, other))),
                                None)

                def _covered_elsewhere(peer):
                    return {"status": "needs_prerequisite", "reason_code": "covered_by_identity",
                            "covered_by": peer, "finding_class": None,
                            "reason": f"{peer} holds the capture and runs this caller-independent check"}

                # R11-10 (owner decision 2026-11-19): an identity-bound check whose
                # identity holds no capture of the endpoint replays ANOTHER
                # identity's capture with only this identity's credentials (none for
                # anonymous): a capture carries no headers, and _seed_exchange
                # attaches the replaying identity's own. The send takes the same
                # path, gate, mutating rules and ceilings as an own-capture replay.
                # A passive leg judges a captured response, which would be the
                # source's, so it is never substituted.
                _substitution = bool(getattr(self, "coverage_identity_substitution", False))
                _substituted: dict = {}

                def _substituted_variants(ep_key, identity, check):
                    if (not _substitution or getattr(check, "caller_independent", False)
                            or check.confirmation in coverage_tracker._PASSIVE_LEG_CONFIRMATIONS
                            or identity not in _role_headers):
                        return []
                    if (ep_key, identity) not in _substituted:
                        target_key = capture_identity_key(_role_headers[identity])
                        found = []
                        for source in sorted(_role_headers):
                            if source == identity:
                                continue
                            found = [v for v in (substituted_variant(
                                         v, target_key, source, _role_headers[source])
                                         for v in _replayable.get((ep_key, source)) or [])
                                     if v is not None]
                            if found:
                                break
                        _substituted[(ep_key, identity)] = found
                    return _substituted[(ep_key, identity)]

                def _captured_readiness(identity, method, path, check):
                    if check.id == "WSTG-CRYP-01":
                        return _capability_decision(check, HttpExchange(url=ns.base_url, method="GET"))
                    preliminary = _capability_decision(check, None)
                    if preliminary["status"] in {"unsupported", "disabled", "policy_denied"}:
                        return preliminary
                    ep_key = f"{method} {path}"
                    ep = ns.state.endpoints.get(ep_key)
                    if ep is not None and ep.capture_variants:
                        variants = _replayable.get((ep_key, identity))
                        if variants is None:
                            variants = replayable_variants(ep, capture_identity_key(_role_headers.get(identity, {})))
                        if not variants:
                            peer = _capture_peer(ep_key, identity, check)
                            if peer is not None:
                                return _covered_elsewhere(peer)
                            variants = _substituted_variants(ep_key, identity, check)
                        if not variants:
                            role = _identity_role.get(identity, identity)
                            block = ns._prerequisite_blocks.setdefault((ep_key, identity), {
                                "endpoint": ep_key, "identity": identity,
                                "missing": "no request captured as this identity",
                                "action": "capture this request signed in as " + role
                                          + " (or add it to the role crawl seed)",
                                "checks_affected": 0})
                            block["checks_affected"] += 1
                            return {"status": "needs_prerequisite", "reason_code": "missing_principal",
                                    "reason": "capture the request as this identity", "finding_class": None}
                        selected_roles = [r for r in ns.roles if _pid(r) == identity]
                        nodes = worklist_investigator.captured_nodes(
                            dict(ep.to_dict(), capture_variants=variants), ns.base_url, selected_roles,
                            include_probes=True)
                    else:
                        nodes = [{"method": method, "path": path,
                                  "template": getattr(ep, "template", {}) if ep else {}}]
                    decisions = []
                    for node in nodes:
                        problem = worklist_investigator.capture_problem(node) if node.get("capture") else None
                        if problem:
                            decisions.append({"status": "needs_prerequisite", "reason_code": problem.split(":",1)[0],
                                              "reason": "supply a complete authorized capture", "finding_class": None})
                            continue
                        exchange, problem = _known_capture_exchange(identity, node)
                        decision = problem or _capability_decision(check, exchange)
                        if decision["status"] == "ready":
                            return decision
                        decisions.append(decision)
                    return decisions[0] if decisions else preliminary

                async def _run_leg_core(identity, method, path, check, case_key=None, *,
                                        remainder_only=False):
                    ep_key = f"{method} {path}"
                    ep = ns.state.endpoints.get(ep_key)
                    if ep is None or not ep.capture_variants:
                        return await _run_captured_leg(identity, method, path, check, case_key,
                                                       remainder_only=remainder_only)
                    variants = _replayable.get((ep_key, identity))
                    if variants is None:
                        variants = replayable_variants(
                            ep, capture_identity_key(_role_headers.get(identity, {})))
                    if not variants:
                        peer = _capture_peer(ep_key, identity, check)
                        if peer is not None:
                            # R11-10: nothing is sent as this identity; the tracker
                            # credits the cell to the peer's verdict.
                            return _VR(check.confirmation, "inconclusive", check.vulnerability_class,
                                       summary=f"covered_by_identity:{peer}: {peer} holds the "
                                               "capture and runs this caller-independent check")
                        variants = _substituted_variants(ep_key, identity, check)
                    if not variants:
                        # The cell's reason stays "missing_principal"; the pair is
                        # reported once, with how many checks it blocked.
                        role = _identity_role.get(identity, identity)
                        block = ns._prerequisite_blocks.setdefault((ep_key, identity), {
                            "endpoint": ep_key, "identity": identity,
                            "missing": "no request captured as this identity",
                            "action": ("capture this request with no credentials"
                                       if role == "anonymous" else
                                       f"capture this request while signed in as {role}")
                                      + " (or add it to the role crawl seed)",
                            "checks_affected": 0})
                        block["checks_affected"] += 1
                        return _VR(check.confirmation, "inconclusive", check.vulnerability_class,
                                   summary="missing_principal: capture the request as this identity")
                    selected_roles = [r for r in ns.roles if _pid(r) == identity]
                    outcomes, held_back = [], []
                    share_key = (ep_key, check.id) + (
                        (identity,) if check.confirmation in _PER_IDENTITY_SHARE else ())
                    # R11-4: a replay the share held is remembered, with the verdicts
                    # of the replays that ran, so the final pass sends only it.
                    cell_key = (identity, ep_key, check.id,
                                case_key.coord_id() if case_key is not None else None)
                    held_entry = ns._held_cells.get(cell_key) if ns._held_pass["active"] else None
                    if held_entry is not None:
                        outcomes = list(held_entry["prior"])
                    held_nodes: set = set()
                    # A per-parameter dispatch of a query or body input replays only
                    # the captures that carry that input; any other capture cannot
                    # test it, and the leg would only decline it.
                    named = ((case_key.parameter_location, case_key.parameter_name)
                             if case_target(check.confirmation, case_key) is not None
                             and case_key.parameter_location in _CAPTURE_INPUT_LOCATIONS else None)
                    for node in worklist_investigator.captured_nodes(
                            dict(ep.to_dict(), capture_variants=variants), ns.base_url, selected_roles,
                            include_probes=True):
                        replay_key = worklist_investigator.node_key(node)
                        if held_entry is not None and replay_key not in held_entry["nodes"]:
                            continue   # its verdict is in `prior`; it is not sent again
                        problem = worklist_investigator.capture_problem(node)
                        if problem:
                            outcomes.append(_unbuilt(_VR(
                                check.confirmation, "inconclusive", check.vulnerability_class,
                                summary=problem + ": supply a complete authorized capture")))
                        elif named is not None and named not in {
                                (c.parameter_location, c.parameter_name)
                                for c in derive_input_cases_from_template(node.get("template"))}:
                            outcomes.append(_unbuilt(_VR(
                                check.confirmation, "skipped", check.vulnerability_class,
                                summary=f"no capture of this identity carries {case_key.label()}, "
                                        "so this leg cannot test it on its own; nothing was sent")))
                        elif ((_endpoint_check_cap is not None
                               and _endpoint_check_spent.get(share_key, 0.0) >= _endpoint_check_cap)
                              or (held_entry is not None
                                  and time.monotonic() >= ns._held_pass["stop_at"])):
                            # A started replay always finishes; only the next one waits.
                            held_nodes.add(replay_key)
                            capped = _endpoint_check_capped.setdefault(share_key, {
                                "endpoint": ep_key, "check": check.id,
                                "identity": identity if len(share_key) > 2 else None,
                                "seconds_spent": 0.0, "replays_not_run": 0})
                            capped["seconds_spent"] = round(_endpoint_check_spent[share_key], 1)
                            capped["replays_not_run"] += 1
                            held_back.append(_VR(
                                check.confirmation, "inconclusive", check.vulnerability_class,
                                summary=("endpoint_check_time_share: this check used its "
                                         f"{_endpoint_check_cap:.1f} s share of the coverage drive "
                                         "on this endpoint; this capture was not replayed")))
                        else:
                            started = time.monotonic()
                            try:
                                outcomes.append(await _run_captured_leg(
                                    identity, method, path, check, case_key, node,
                                    remainder_only=remainder_only))
                            finally:
                                _endpoint_check_spent[share_key] = (
                                    _endpoint_check_spent.get(share_key, 0.0)
                                    + time.monotonic() - started)
                    # R11-4: remember the held replays for the final pass (or forget
                    # them once it ran them all, or a capture of the cell confirmed).
                    if held_back and not any(r is not None and r.confirmed for r in outcomes):
                        ns._held_cells[cell_key] = {
                            "identity": identity, "method": method, "path": path, "check": check,
                            "case_key": case_key, "remainder_only": remainder_only,
                            "share_key": share_key, "prior": list(outcomes),
                            "nodes": held_nodes, "replays": len(held_back)}
                    else:
                        ns._held_cells.pop(cell_key, None)
                    # A replay the time share held back leaves the cell open, unless
                    # another capture of it already confirmed (that proof was recorded).
                    if not any(r is not None and r.confirmed for r in outcomes):
                        outcomes += held_back
                    # A passive leg judges each captured response on its own; one it
                    # skips (a redirect, a body that was not kept) says nothing about
                    # the cell, so it never hides another capture's verdict.
                    if check.confirmation in coverage_tracker._PASSIVE_LEG_CONFIRMATIONS:
                        outcomes = [r for r in outcomes if r is None or r.status != "skipped"] or outcomes
                    # A capture no request could be built from for this leg (a route
                    # placeholder with no observed id, no parameter to carry the
                    # probe, not the input this case names) sent nothing and says
                    # nothing about the cell. It never hides the verdict and sends of
                    # a capture that ran (r10: about 180 cells reported such a refusal,
                    # with no sends, although readiness had found another capture of
                    # the cell ready). When no capture could be built, the first
                    # refusal stands.
                    outcomes = [r for r in outcomes
                                if r is None or not getattr(r, "replay_unbuilt", False)] or outcomes
                    # Every proof instance was recorded above. A positive instance
                    # does not turn another unanswered variant into a clean cell.
                    incomplete = [r for r in outcomes if r is None or r.status not in
                                  {"confirmed", "not_confirmed", "controlled_negative", "safe"}]
                    if incomplete:
                        return next((r for r in incomplete if r is not None), None)
                    return next((r for r in outcomes if r.confirmed), outcomes[0] if outcomes else None)
                ns._run_leg_core = _run_leg_core

                async def _run_leg(identity, method, path, check):
                    return await _run_leg_core(identity, method, path, check, None)

                if self.engagement_coverage_case_drive:
                    # T05/R26: finer, per-input driving -- fan each parameter leg over
                    # the endpoint's concrete inputs so a confirmation binds to the
                    # exact parameter case and un-run inputs stay visibly pending.
                    ns.coverage = await coverage_tracker.build_coverage_cases_driven(
                        ns.state, ns.roles, _run_leg_core, budget=self.coverage_leg_budget, readiness=_captured_readiness,
                        per_cell_case_budget=self.coverage_case_budget,
                        parameter_field_cap=self.coverage_parameter_field_cap,
                        driveable=set(_val_by_conf.keys()), investigated_keys=ns.investigated_keys,
                        checkpoint=ns.coverage_checkpoint,
                        context_key=coverage_tracker.resume_context_key(self.config),
                        deadline=ns._coverage_deadline, **_coverage_kwargs)
                else:
                    ns.coverage = await coverage_tracker.build_coverage_driven(
                        ns.state, ns.roles, _run_leg, budget=self.coverage_leg_budget, readiness=_captured_readiness,
                        driveable=set(_val_by_conf.keys()), investigated_keys=ns.investigated_keys,
                        checkpoint=ns.coverage_checkpoint,
                        context_key=coverage_tracker.resume_context_key(self.config),
                        deadline=ns._coverage_deadline, **_coverage_kwargs)
                ns._drive_hooks.update(run_leg=(_run_leg_core if self.engagement_coverage_case_drive
                                                else _run_leg),
                                       case_mode=bool(self.engagement_coverage_case_drive),
                                       spent=_endpoint_check_spent)
                if ns.coverage.get("checkpoint"):
                    ns._journal_put("coverage:checkpoint", ns.coverage["checkpoint"])
                    ns._journal_phase("coverage")
                if ns.coverage.get("drive_stopped_by") == "time budget":
                    ns._errors.append({"phase": "coverage_drive",
                                       "error": "coverage drive time budget reached: "
                                             f"{ns.coverage.get('queued_not_attempted', 0)} queued "
                                             "leg(s) not attempted"})
                if _replay_merge["replays"] < _replay_merge["captures"]:
                    ns.coverage["replay_merge"] = {
                        "captures": _replay_merge["captures"], "replays": _replay_merge["replays"],
                        "endpoints": sorted(_replay_merge["endpoints"])}
                if _endpoint_check_capped:
                    capped = sorted(_endpoint_check_capped.values(),
                                    key=lambda c: (c["endpoint"], c["check"], c["identity"] or ""))
                    ns.coverage["endpoint_check_time_capped"] = capped
                    ns._errors.append({"phase": "coverage_drive",
                                       "error": "per-endpoint check time share reached: "
                                             f"{sum(c['replays_not_run'] for c in capped)} captured "
                                             f"replay(s) not run on {len(capped)} endpoint check(s)"})
            else:
                ns.coverage = coverage_tracker.build_coverage(ns.state, ns.roles,
                                                              investigated_keys=ns.investigated_keys)
        except Exception as e:  # coverage is a report layer -- never sink the run
            log.warning("investigate_engagement: coverage build failed: %s", e)
            ns._errors.append({"phase": "coverage_build", "error": f"{type(e).__name__}: {e}"})
