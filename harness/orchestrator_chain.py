"""orchestrator_chain.py -- ChainMixin mixin for Orchestrator (W-15 decomposition).

The graph-driven engagement loop: plan/run_engagement, auto-escalation,
credential-grant checks, and investigate_engagement (with its nested
_confirm dispatcher and precondition legs).

Split out of orchestrator.py verbatim; `self` state is initialised in
Orchestrator.__init__ and resolved across mixins via the MRO.
"""
from __future__ import annotations

from orchestrator_helpers import *  # noqa: F401,F403  (shared imports/helpers/constants)
# W-16: the single TargetTransport. Imported by name (not as the module) because
# investigate_engagement has a `run_context` parameter that would shadow the module;
# `transport_for(run_context, ...)` then reads as "use this run's transport, or a
# standalone one when it is None".
from run_context import transport_for


class ChainMixin:
    async def plan_engagement(self, host: str, *, max_targets: int = 10,
                              base_url: str = "") -> dict:
        """The engagement driver, planning mode (no side effects): read the fused
        worklist back out, take the top untested endpoints, and run them through
        the F5 budget governor -- returning a ranked, budgeted 'test next' queue
        with the governor's full/reduced/deferred decisions and guidance. The
        endpoint's fused score IS its allocation priority, so the whole
        signal-fusion pipeline drives what gets budget. Pure planning: nothing is
        fetched or analyzed here."""
        import engagement, resource_governor
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
        enabled in config (double-gated -- never tests automatically)."""
        if not execute:
            plan = await self.plan_engagement(host, max_targets=max_targets, base_url=base_url)
            plan["note"] = "plan only -- pass execute=true (and enable engagement.driver_execute) to run these"
            return plan
        if not self.engagement_driver_execute:
            plan = await self.plan_engagement(host, max_targets=max_targets, base_url=base_url)
            plan["note"] = "execution refused: engagement.driver_execute is disabled in config.yaml"
            return plan

        p = urlsplit(base_url)
        origin = f"{p.scheme}://{p.netloc}"
        rounds: list[dict] = []
        seen_urls: set[str] = set()   # don't re-fetch the same target across rounds

        for rnd in range(1, max(1, max_rounds) + 1):
            allowed, _ = self.effort_budget.allow()
            if not allowed:
                rounds.append({"round": rnd, "stopped": "effort budget exhausted"})
                break
            plan = await self.plan_engagement(host, max_targets=max_targets, base_url=base_url)
            funded = [t for t in plan["targets"]
                      if t["action"] != "deferred" and t["method"].upper() == "GET"]
            analyzed: list[dict] = []
            # W-16: the driver's target GETs go through the single TargetTransport.
            # No run of its own, so a standalone context (scope == is_host_allowed,
            # so reachability is unchanged); one transport reused across the round.
            _tt, _owned = transport_for(
                None, allowed_hosts=self.allowed_hosts, config=self.config)
            try:
                for t in funded:
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
                        result = await self.analyze(exchange)
                        n = len([f for r in result.agent_reports for f in r.findings])
                        analyzed.append({"url": url, "findings": n})
                    except Exception as e:
                        analyzed.append({"url": url, "error": e.__class__.__name__})
            finally:
                if _owned is not None:
                    await _owned.aclose()
            # SUMMARIZE this round (the condensed feedback the next plan reacts to).
            rounds.append(self._summarize_round(rnd, host, analyzed))
            if not analyzed:  # nothing new was funded/runnable -> converged
                break

        after = await self.plan_engagement(host, max_targets=max_targets, base_url=base_url)
        return {"host": host, "executed": True, "rounds": rounds,
                "targets_after": after["targets"], "guidance": after["guidance"],
                "summary": (await self._engagement_summary(host))}

    def _summarize_round(self, rnd: int, host: str, analyzed: list) -> dict:
        found = sum(a.get("findings", 0) for a in analyzed)
        return {"round": rnd, "targets_run": len(analyzed),
                "findings_this_round": found,
                "detail": analyzed[:20]}

    async def _engagement_summary(self, host: str) -> dict:
        import engagement
        snap = await asyncio.to_thread(store.load_engagement, host)
        return engagement.EngagementState.from_dict(snap or {"host": host}).summary()

    async def _auto_escalate(self, host: str, source_url: str, credential_caps: list, st) -> None:
        """Re-crawl the origin as each learned (derived) identity and fold the new
        surface into the engagement state. The credential headers are used here
        and discarded -- never persisted.

        Blast-radius guards (this is active traffic fired as a side effect of
        analysis, so it is bounded three independent ways):
          1. DEDUP -- a derived identity already escalated (its
             recrawl_as_derived task is DONE in the graph) is skipped, so the
             same leaked token never triggers a second full crawl.
          2. VERIFY -- each credential is probed once against the source URL
             before a crawl is spent on it; a stale/rejected token (>=400, or
             no better than the anonymous baseline) is discarded, not crawled.
          3. CAP -- a hard per-host ceiling (engagement.max_auto_escalations) on
             how many escalations fire in this process lifetime.
        Plus the usual scope gate + throttle on every request."""
        import engagement, role_crawl
        import task_graph
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

        # Guard 3: per-host session cap.
        if self._escalation_counts.get(host, 0) >= self.engagement_max_escalations:
            log.info("engagement auto-escalate: per-host cap (%d) reached for %s -- skipping",
                     self.engagement_max_escalations, host)
            return

        # Guard 2: verify each credential actually grants access before crawling.
        verified: list = []
        for cap in fresh:
            if await self._credential_grants_access(source_url, cap.get("headers", {})):
                verified.append(cap)
            else:
                log.info("engagement auto-escalate: learned credential did not verify -- discarding")
        if not verified:
            return

        roles = [role_crawl.RoleSession(role="anonymous", headers={})]
        for cap in verified:
            roles.append(role_crawl.RoleSession(role="derived", headers=cap.get("headers", {})))
        try:
            result = await role_crawl.crawl_roles(
                origin, roles, allowed_hosts=self.allowed_hosts, max_pages=20, max_endpoints=80)
            st.ingest_role_crawl(result.to_dict())
            for cap in verified:
                st.resolve_action("recrawl_as_derived",
                                  f"derived:{cap.get('kind', 'cred')}@{engagement.normalize_path(source_url)}")
            self._escalation_counts[host] = self._escalation_counts.get(host, 0) + 1
            log.info("engagement auto-escalate: re-crawled %s as derived identity, +%d endpoints (host total %d)",
                     origin, len(result.endpoints), self._escalation_counts[host])
        except Exception as e:
            log.warning("engagement auto-escalate failed: %s", e)

    async def _credential_grants_access(self, url: str, headers: dict) -> bool:
        """One probe to check a learned credential actually works: the source URL
        with the credential must return a non-error (<400) response. Scope-gated +
        throttled. A stale, revoked, or honeypot token fails here and never earns
        a full crawl."""
        if not headers or not scope_discovery.is_host_allowed(url, self.allowed_hosts):
            return False
        # W-16: the credential probe goes through the single TargetTransport. It is a
        # one-off throwaway send, so a standalone context; send_creds forwards the
        # learned credential (ephemeral session scoped to the URL's origin), matching
        # a raw client that just sent it to `url`. max_redirects=0 == follow_redirects=False.
        _tt, _owned = transport_for(
            None, allowed_hosts=self.allowed_hosts, config=self.config)
        try:
            await global_throttle.acquire()
            out = await _tt.send_creds("GET", url, capability="credential_probe",
                                       headers=headers, max_redirects=0)
            return bool(out.ok and out.status is not None and out.status < 400)
        except Exception:
            return False
        finally:
            if _owned is not None:
                await _owned.aclose()

    async def investigate_engagement(self, base_url, roles, *, max_nodes: int = 8,
                                     step_budget: int = 16, discovery_max_probes: int = 6000,
                                     max_chain_rounds: int = 1, run_context=None) -> dict:
        """Milestone A+B, end to end: build the app model (active discovery ->
        per-role access matrix -> prioritised worklist), then drive the ITERATIVE
        agent top-down over that worklist -- each high-value node gets a bounded
        multi-step investigation, and findings fold back into the graph so a
        tested node sinks and is not re-tested. The harness chooses WHAT to test
        (the ranking) and HOW HARD (the step budget); this replaces firing every
        agent at every exchange.

        `roles` is a list of role_crawl.RoleSession. Requires iterative_agent
        enabled (run_active_probe enforces it). `max_chain_rounds` bounds the
        Milestone-C closed loop (re-test AS a credential learned from a finding)."""
        import engagement_builder
        import worklist_investigator
        import chain_linker
        import role_crawl
        state, rc = await engagement_builder.build_engagement(
            base_url, roles, allowed_hosts=self.allowed_hosts,
            discovery_max_probes=discovery_max_probes, run_context=run_context)

        # R30: operational failures in the additive phases below are caught so one
        # broken phase can't sink the run -- but they must not vanish silently. Each
        # is recorded here and surfaced in the result as `errors` + `degraded`, so a
        # run that skipped a phase is declared incomplete rather than looking clean.
        _errors: list[dict] = []
        workflow_results: list[dict] = []

        # Phase 0.1: promote every substantive 2xx encountered during discovery
        # into full content-level review before prioritising/iterating. A body
        # that is correctly access-scoped but itself leaks otherwise never
        # becomes an analyzable exchange -- see review_captured_exchanges.
        await review_captured_exchanges(
            self, state, getattr(rc, "captured", None), run_context=run_context)

        # Emit findings for sensitive files discovered during active probing
        # (/.env, /backup/, etc.). These are confirmed by their mere existence
        # at a web-accessible path.
        for sf_path in getattr(rc, "sensitive_file_hits", []):
            state.ingest_findings(
                f"{base_url}{sf_path}", "GET",
                [{"vulnerability_class": "sensitive_file_exposure",
                  "severity": "high", "confidence": 0.95,
                  "summary": f"Sensitive file accessible: {sf_path}",
                  "evidence": f"HTTP 200 at {sf_path}",
                  "confirmed": True,
                  "confirmation_method": "sensitive_file_probe"}])

        # Stateful agent-role feature crawling (default off). Drive each role
        # through the app's real workflows and fold the captured, session-bearing
        # exchanges into the surface + content review -- the frontier gap
        # route-guessing can't close (sessions 11/13/15). The submits inside are
        # gated by allow_mutating_replay, so with mutating replay off this reduces
        # to an authenticated read-only walk.
        if self.engagement_feature_crawl:
            try:
                import engagement as _eng
                from safety_gate import get_default_gate as _get_gate
                discovered_paths = [ep.path for ep in rc.endpoints] if rc.endpoints else None
                feature_caps = await engagement_builder.feature_crawl_captures(
                    base_url, roles, allowed_hosts=self.allowed_hosts,
                    submit_forms=_get_gate().config.allow_mutating_replay,
                    seed_paths=discovered_paths, run_context=run_context)
                # make the workflow surface visible to prioritisation + coverage,
                # then run the same content-level review as discovery captures.
                for ex in feature_caps:
                    state._ep(ex.method, _eng.normalize_path(ex.url))
                await review_captured_exchanges(
                    self, state, feature_caps, run_context=run_context)
            except Exception as e:  # feature crawl is additive -- never sink the run
                log.warning("investigate_engagement: feature crawl failed: %s", e)
                _errors.append({"phase": "feature_crawl", "error": f"{type(e).__name__}: {e}"})

        # Universal header audit: run CORS, CSP, verbose-error validators
        # against EVERY captured exchange from discovery + feature_crawl.
        # This catches header-level issues the LLM agents never labelled.
        _all_captured = list(getattr(rc, "captured", None) or [])
        try:
            _all_captured.extend(feature_caps)  # noqa: F821 -- set in the feature_crawl block above
        except NameError:
            pass
        try:
            await universal_header_audit(self, state, _all_captured)
        except Exception as e:
            log.warning("investigate_engagement: universal header audit failed: %s", e)
            _errors.append({"phase": "universal_header_audit", "error": f"{type(e).__name__}: {e}"})
            import telemetry
            telemetry.record_swallowed_exception("universal_header_audit", e)

        async def _probe(exchange, hypothesis, specialty, sb):
            return await self.run_active_probe(exchange, hypothesis, specialty, step_budget=sb)

        # Cross-identity confirmation for the investigation path: register the
        # roles as replay identities and confirm access-control findings the
        # iterative agent reaches -- turning its unconfirmed guesses into
        # deterministically CONFIRMED findings (via the Autorize-style replay), so
        # a proven bug lands as `validated` and outranks the model's claims.
        import identity_headers
        import access_control_gate
        from validators.cross_identity_validator import CrossIdentityValidator
        from validators.browser_xss_validator import BrowserXssValidator
        from validators.jwt_forge_validator import JwtForgeValidator
        from validators.ssrf_validator import SsrfValidator
        from validators.xxe_validator import XxeValidator
        from validators.command_injection_validator import CommandInjectionValidator
        from validators.ssti_validator import SstiValidator
        from validators.path_traversal_validator import PathTraversalValidator
        from validators.open_redirect_validator import OpenRedirectValidator
        from validators.sequence_validator import SequenceValidator
        from validators.deserialization_oob_validator import DeserializationOobValidator
        from validators.auth_sequence_validator import AuthSequenceValidator
        from validators.stored_xss_validator import StoredXssValidator
        from validators.rate_limit_validator import RateLimitValidator
        from validators.reset_token_validator import ResetTokenValidator
        from validators.dom_xss_validator import DomXssValidator
        from validators.toctou_validator import ToctouValidator
        from models import Finding
        host = urlsplit(base_url).hostname or ""
        if run_context is not None:
            declarations = ((self.config.get("engagement", {}) or {})
                            .get("declared_workflows", []))
            if declarations:
                try:
                    executed = await engagement_builder.execute_declared_workflows(
                        declarations, run_context)
                    workflow_results = [r.to_dict() for r in executed]
                except Exception as e:
                    _errors.append({"phase": "declared_workflows",
                                    "error": f"{type(e).__name__}: {e}"})
        for r in roles:
            if r.headers:
                # Register under a DISTINCT principal id (R10): two same-role users
                # with different credentials must not overwrite each other under a
                # shared `role` key. Role is still carried for privilege checks.
                identity_headers.set_identity(host, r.principal_id(), dict(r.headers), r.role)
        _xid_cfg = (self.config.get("validators", {}) or {}).get("cross_identity", {}) or {}
        _xval = CrossIdentityValidator(
            allowed_hosts=self.allowed_hosts,
            timeout=float(_xid_cfg.get("timeout", 10.0)),
            max_identities=int(_xid_cfg.get("max_identities", 3)),
            run_context=run_context)
        _bxss = BrowserXssValidator(allowed_hosts=self.allowed_hosts)
        _jwt = JwtForgeValidator(allowed_hosts=self.allowed_hosts,
                                 run_context=run_context)
        _ssrf = SsrfValidator(allowed_hosts=self.allowed_hosts)
        _xxe = XxeValidator(allowed_hosts=self.allowed_hosts)
        _cmdi = CommandInjectionValidator(allowed_hosts=self.allowed_hosts)
        _ssti = SstiValidator(allowed_hosts=self.allowed_hosts)
        _path = PathTraversalValidator(allowed_hosts=self.allowed_hosts)
        _redir = OpenRedirectValidator(allowed_hosts=self.allowed_hosts)
        _seq = SequenceValidator(allowed_hosts=self.allowed_hosts)
        _deser = DeserializationOobValidator(allowed_hosts=self.allowed_hosts)
        _auth = AuthSequenceValidator(allowed_hosts=self.allowed_hosts)
        _sxss = StoredXssValidator(allowed_hosts=self.allowed_hosts)
        _rate = RateLimitValidator(allowed_hosts=self.allowed_hosts,
                                   run_context=run_context)
        _reset = ResetTokenValidator(allowed_hosts=self.allowed_hosts)
        _domxss = DomXssValidator(allowed_hosts=self.allowed_hosts)
        _toctou = ToctouValidator(allowed_hosts=self.allowed_hosts,
                                  run_context=run_context)

        # Memoisation cache: avoid re-running the same validator on the same
        # endpoint during one investigate_engagement() call. Keyed by
        # confirmation_cache_key() -- which includes the IDENTITY (auth headers)
        # and finding subtype, not just (validator, method, url, body), so a probe
        # AS one identity never returns a result computed AS another (R03).
        from validators.base import ValidationResult as _VR
        _confirmation_cache: dict[tuple, _VR] = {}

        async def _cached_validate(validator, finding_obj, exchange):
            """Wrapper around validator.validate() that caches results within this
            run. The key includes identity + finding class (R03) so cross-identity
            / cross-subtype cases do not collide. A hit returns the previous
            ValidationResult without any HTTP/container work."""
            key = confirmation_cache_key(
                validator.name, exchange,
                getattr(finding_obj, "vulnerability_class", None))
            if key in _confirmation_cache:
                return _confirmation_cache[key]
            result = await validator.validate(finding_obj, exchange)
            _confirmation_cache[key] = result
            return result

        def _apply(finding, res, leg, floor):
            if res is not None and res.status == "confirmed" and res.confirmed:
                finding["confirmed"] = True
                finding["confidence"] = max(float(finding.get("confidence", 0) or 0), float(res.confidence or floor))
                finding["evidence"] = ((finding.get("evidence") or "") + f" || {leg} CONFIRMED: "
                                       + (res.summary or "")).strip(" |")

        def _as_finding(finding, default_class):
            return Finding(vulnerability_class=finding.get("vulnerability_class") or default_class,
                           confidence=float(finding.get("confidence", 0.5) or 0.5),
                           severity=finding.get("severity") or "medium",
                           summary=finding.get("summary") or default_class,
                           evidence=finding.get("evidence") or "",
                           suggested_test=finding.get("suggested_test") or "", basis="derived")

        async def _confirm(finding, exchange):
            """Dispatch a finding to the deterministic confirmation leg for its class:
            access-control -> cross-identity replay; xss -> headless-browser execution.
            A confirmed finding is upgraded in place; anything else is left untouched."""
            vc = (finding.get("vulnerability_class") or "")
            low = vc.lower()
            if access_control_gate._is_access_control_class(vc):
                # populate the candidate baseline: the probe role's own response.
                if exchange.response_status is None and scope_discovery.is_host_allowed(exchange.url, self.allowed_hosts):
                    # W-16: baseline read through the single TargetTransport (this run's
                    # when present, else a standalone one). send_creds forwards the probe
                    # role's own credentials; max_redirects=0 == follow_redirects=False.
                    _tt, _owned = transport_for(run_context, allowed_hosts=self.allowed_hosts,
                                                config=self.config)
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
                    _apply(finding, await _cached_validate(_xval, _as_finding(finding, "idor"), exchange), "cross-identity", 0.9)
                except Exception:
                    return
            elif ("dom" in low and "xss" in low) or "dom_xss" in low or "dom-based" in low or "client-side xss" in low:
                # DOM-based XSS: fragment-payload browser execution (client-side
                # source->sink), distinct from server-reflected browser_xss.
                try:
                    _apply(finding, await _cached_validate(_domxss, _as_finding(finding, "dom_xss"), exchange),
                           "dom-xss", 0.95)
                except Exception:
                    return
            elif "xss" in low or "cross-site scripting" in low or "cross_site" in low:
                # browser_xss executes payloads in a real browser; it CONFIRMS reflected
                # XSS and (crucially for a JSON API) declines what never reaches an HTML
                # sink. Skips gracefully if no browser engine is installed.
                try:
                    _apply(finding, await _cached_validate(_bxss, _as_finding(finding, "xss"), exchange), "browser-xss", 0.95)
                    # reflected browser_xss handles GET reflections; a write-shaped
                    # exchange may instead be a STORED-XSS plant point -- try that leg too.
                    if not finding.get("confirmed") and (exchange.method or "GET").upper() in ("POST", "PUT", "PATCH"):
                        _apply(finding, await _cached_validate(_sxss, _as_finding(finding, "xss"), exchange), "stored-xss", 0.9)
                except Exception:
                    return
            elif "jwt" in low or "algorithm confusion" in low or "algorithm_confusion" in low or "weak_token" in low:
                try:
                    _apply(finding, await _cached_validate(_jwt, _as_finding(finding, "jwt"), exchange), "jwt-forge", 0.9)
                except Exception:
                    return
            elif "ssrf" in low or "server-side request" in low or "server_side_request" in low:
                try:
                    _apply(finding, await _cached_validate(_ssrf, _as_finding(finding, "ssrf"), exchange), "ssrf", 0.95)
                except Exception:
                    return
            elif "xxe" in low or "xml external" in low or "xml_external" in low:
                try:
                    _apply(finding, await _cached_validate(_xxe, _as_finding(finding, "xxe"), exchange), "xxe", 0.95)
                except Exception:
                    return
            elif "command" in low or low in ("rce", "remote code execution", "code injection", "shell injection"):
                try:
                    _apply(finding, await _cached_validate(_cmdi, _as_finding(finding, "command_injection"), exchange),
                           "command-injection", 0.95)
                except Exception:
                    return
            elif "ssti" in low or "template injection" in low:
                try:
                    _apply(finding, await _cached_validate(_ssti, _as_finding(finding, "ssti"), exchange), "ssti", 0.95)
                except Exception:
                    return
            elif "traversal" in low or "lfi" in low or "file inclusion" in low:
                try:
                    _apply(finding, await _cached_validate(_path, _as_finding(finding, "path_traversal"), exchange),
                           "path-traversal", 0.95)
                except Exception:
                    return
            elif "redirect" in low:
                try:
                    _apply(finding, await _cached_validate(_redir, _as_finding(finding, "open_redirect"), exchange),
                           "open-redirect", 0.9)
                except Exception:
                    return
            elif ("toctou" in low or "time-of-check" in low or "time of check" in low
                  or "check-then-act" in low or "check then act" in low
                  or ("privilege" in low and "race" in low) or ("race" in low and "escalat" in low)):
                # TOCTOU privilege-escalation race: concurrent check-then-write.
                # Must precede the mass/privilege->sequence branch below.
                try:
                    _apply(finding, await _cached_validate(_toctou, _as_finding(finding, "toctou"), exchange),
                           "toctou", 0.85)
                except Exception:
                    return
            elif "mass" in low or "assignment" in low or "privilege" in low or low in ("api_security", "api security"):
                try:
                    _apply(finding, await _cached_validate(_seq, _as_finding(finding, "mass_assignment"), exchange),
                           "sequence", 0.9)
                except Exception:
                    return
            elif "deserial" in low or "pickle" in low or "object injection" in low:
                try:
                    _apply(finding, await _cached_validate(_deser, _as_finding(finding, "deserialization"), exchange),
                           "deserialization", 0.95)
                except Exception:
                    return
            elif ("session fixation" in low or "session_fixation" in low or "weak password" in low
                  or "weak_password" in low or "enumeration" in low or "broken authentication" in low
                  or "broken_authentication" in low):
                try:
                    _apply(finding, await _cached_validate(_auth, _as_finding(finding, low or "broken_authentication"), exchange),
                           "auth-sequence", 0.85)
                except Exception:
                    return
            elif "rate limit" in low or "rate_limit" in low or "lockout" in low or "brute" in low:
                try:
                    _apply(finding, await _cached_validate(_rate, _as_finding(finding, "rate_limit"), exchange),
                           "rate-limit", 0.85)
                except Exception:
                    return
            elif ("reset_token" in low or "reset token" in low or "predictable token" in low
                  or "weak token" in low or "token entropy" in low):
                try:
                    _apply(finding, await _cached_validate(_reset, _as_finding(finding, "reset_token"), exchange),
                           "reset-token", 0.9)
                except Exception:
                    return

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

        async def _precondition(node, exchange):
            """Legs the node's shape warrants, run regardless of agent labels.
            Returns only CONFIRMED findings."""
            path = node.get("path", "/")
            confirmed = []
            for vclass, ex in shape_precondition_legs(node, exchange, roles, base_url):
                r = await _confirm_leg(vclass, ex, path)
                if r:
                    confirmed.append(r)
            return confirmed

        async def _investigate(st, rs):
            outs = await worklist_investigator.investigate_worklist(
                _probe, st, base_url, rs, confirm_fn=_confirm, precondition_fn=_precondition,
                max_nodes=max_nodes, step_budget=step_budget)
            return outs, [f for o in outs for f in o.get("findings_detail", [])]

        outcomes, all_findings = await _investigate(state, roles)

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

        _responses: dict = _responses_from(getattr(rc, "captured", None))
        try:
            _responses.update(_responses_from(feature_caps))
        except NameError:
            pass

        # Milestone C: link findings into escalation edges + composed chains, then
        # walk the closed loop -- re-test AS any credential a finding leaked.
        link = chain_linker.link_findings(state, all_findings, responses=_responses)
        chains = list(link["chain_findings"])
        creds, rounds, seen_ident = link["credential_caps"], 0, set()
        while creds and rounds < max_chain_rounds:
            rounds += 1
            derived = [role_crawl.RoleSession(role="anonymous", headers={})]
            for c in creds:
                ident = f"{c.get('kind')}@{c.get('source_url')}"
                if ident in seen_ident:
                    continue
                if await self._credential_grants_access(c.get("source_url", base_url), c.get("headers", {})):
                    derived.append(role_crawl.RoleSession(role="derived", headers=c.get("headers", {})))
                    seen_ident.add(ident)
            if len(derived) < 2:
                break
            st2, rc2 = await engagement_builder.build_engagement(
                base_url, derived, allowed_hosts=self.allowed_hosts,
                discovery_max_probes=discovery_max_probes, run_context=run_context)
            # Phase 0.1: content-level review of the re-crawl's captures too, so a
            # response reachable only as the newly-leaked identity is reviewed.
            await review_captured_exchanges(self, st2, getattr(rc2, "captured", None))
            outs2, new_findings = await _investigate(st2, derived)
            outcomes.extend(outs2)
            all_findings.extend(new_findings)
            # R19: merge the derived-identity state back into the primary state, so
            # the surface + findings reachable ONLY as the leaked credential appear
            # in the final summary/worklist/coverage/report -- not just in a local
            # list. Also feed the re-crawl's responses into credential detection.
            state.merge_from(st2)
            _responses.update(_responses_from(getattr(rc2, "captured", None)))
            link = chain_linker.link_findings(state, all_findings, responses=_responses)
            chains = list(link["chain_findings"])
            creds = link["credential_caps"]

        # Second-order auto-confirmation (V22 SQLi / V17 IDOR): actively run the
        # plant->trigger differential over each composed (A,B) pair. The plant is a
        # mutating write, so this is gated on allow_mutating_replay; inert by
        # default. Confirmed pairs fold in as confirmed findings.
        try:
            import json as _json, chaining as _chaining, second_order as _so
            from safety_gate import GatedAsyncClient as _GAC, get_default_gate as _gg2
            if _gg2().config.allow_mutating_replay:
                _MARK_FIELDS = ("q", "name", "value", "comment", "data", "note", "subject", "title")
                # R13: plant AS an authenticated attacker/owner (never anonymously),
                # and read AS the appropriate identity -- the planter for the SQLi
                # differential, a DISTINCT identity for the cross-identity IDOR read.
                _plant_headers, _other_headers = second_order_identities(roles)
                _plant_send_headers = dict(_plant_headers)
                _plant_send_headers.setdefault("Content-Type", "application/json")

                async def _plant(a_url, marker):
                    await global_throttle.acquire()
                    body = _json.dumps({f: marker for f in _MARK_FIELDS})
                    try:
                        async with _GAC(_gg2(), "second_order", timeout=10.0,
                                        follow_redirects=False, verify=False) as c:
                            resp = await c.request("POST", a_url, headers=_plant_send_headers,
                                                   content=body)
                        # R13: a failed write is surfaced, not silently swallowed --
                        # the confirmation must not proceed as if the value was stored.
                        if not (200 <= resp.status_code < 400):
                            log.debug("second_order plant to %s returned %s", a_url, resp.status_code)
                            return False
                        return True
                    except Exception as e:
                        log.debug("second_order plant to %s failed: %s", a_url, e)
                        return False

                async def _read(b_url, headers=None):
                    await global_throttle.acquire()
                    # default the read identity to the PLANTER (so the SQLi differential
                    # reads its own stored value back); a cross-identity read passes the
                    # other identity explicitly.
                    hdrs = _plant_headers if headers is None else headers
                    hdrs = {k: v for k, v in (hdrs or {}).items() if (k or "").lower() != "content-type"}
                    # W-16: second-order read through the single TargetTransport (this run's
                    # when present, else standalone). send_creds forwards the read identity's
                    # credentials; max_redirects=0 == follow_redirects=False.
                    _tt, _owned = transport_for(run_context, allowed_hosts=self.allowed_hosts,
                                                config=self.config)
                    try:
                        out = await _tt.send_creds("GET", b_url, capability="second_order_read",
                                                   headers=hdrs, max_redirects=0)
                        return (out.body or "") if out.ok else ""
                    except Exception:
                        return ""
                    finally:
                        if _owned is not None:
                            await _owned.aclose()

                async def _confirm_sqli(a_url, b_url):
                    return await _so.confirm_second_order_sqli(
                        plant=lambda m: _plant(a_url, m), trigger=lambda: _read(b_url))

                async def _confirm_idor(a_url, b_url):
                    if not _other_headers:
                        # No DISTINCT second identity -> a cross-identity read would be a
                        # self-comparison. Do not fake-confirm (R13/R10).
                        return _so.SecondOrderResult(
                            confirmed=False,
                            reason="no distinct second identity configured for a cross-identity "
                                   "second-order IDOR read (would be a self-comparison)")
                    return await _so.confirm_second_order_idor(
                        plant=lambda m: _plant(a_url, m),
                        read_as_other=lambda: _read(b_url, _other_headers))

                _cands = _chaining.second_order_candidates(all_findings)
                _confirmed_so = await _so.auto_confirm_candidates(
                    _cands, confirm_sqli=_confirm_sqli, confirm_idor=_confirm_idor,
                    is_allowed=lambda u: scope_discovery.is_host_allowed(u, self.allowed_hosts))
                for cf in _confirmed_so:
                    all_findings.append(cf)
                    state.ingest_findings(cf["url"], "GET", [cf])
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
                _all_exchanges = list(getattr(rc, "captured", None) or [])
                try:
                    _all_exchanges.extend(feature_caps)
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
                        all_findings.append(cf)
                        state.ingest_findings(cf["url"], "GET", [cf])
        except Exception as e:  # auto-confirm is additive -- never sink the run
            log.warning("investigate_engagement: second-order auto-confirm failed: %s", e)
            _errors.append({"phase": "second_order_auto_confirm", "error": f"{type(e).__name__}: {e}"})

        # Flag-only hand-off: an UNCONFIRMED finding whose class has no automated
        # leg (and isn't business-logic, which has its own richer hand-off) is
        # surfaced as a BLOCKED human-verification task -- reported-not-verified,
        # never fabricated as confirmed and never dropped. This is the honest
        # disposition for the no-leg classes (V2/V37 and any other).
        for f in all_findings:
            if f.get("confirmed"):
                continue
            url = f.get("url") or ""
            vc = f.get("vulnerability_class") or ""
            if not url or not vc:
                continue
            if not state.flag_business_logic(vc, url):
                state.flag_unconfirmable(vc, url)

        # Coverage matrix (I1/I2/I5): reconcile the finished engagement into the
        # auditable identity x endpoint x check matrix -- every applicable check is
        # confirmed / detected (from real findings), not_detected (only from a REAL
        # driven leg execution, R01), or skipped WITH A REASON, so "what was NOT
        # tested and why" is answerable. `investigated_keys` only phrases the skip
        # reason for legs that were never recorded as executed; it never infers a
        # not_detected. The coverage-driver path records live leg outcomes cell-by-cell.
        coverage: dict = {}
        try:
            import coverage_tracker
            investigated_paths = {o.get("path") for o in outcomes if o.get("path")}
            investigated_keys = {k for k in state.endpoints
                                 if k.split(" ", 1)[-1] in investigated_paths}
            if self.engagement_coverage_drive:
                # I1 matrix-driver: build a confirmation->validator map (reusing the
                # instances above + a few cheap extra legs) and actively fire each
                # applicable leg-backed cell, recording the real leg status.
                from validators.verb_tamper_validator import VerbTamperValidator
                from validators.csrf_validator import CsrfValidator
                from validators.file_upload_validator import FileUploadValidator
                _val_by_conf = {
                    "cross_identity": _xval, "jwt_forge": _jwt, "browser_xss": _bxss,
                    "stored_xss": _sxss, "ssrf": _ssrf, "xxe": _xxe,
                    "command_injection": _cmdi, "ssti": _ssti, "path_traversal": _path,
                    "open_redirect": _redir, "sequence": _seq, "deserialization_oob": _deser,
                    "auth_sequence": _auth, "rate_limit": _rate, "reset_token": _reset,
                    "dom_xss": _domxss, "toctou": _toctou,
                    "verb_tamper": VerbTamperValidator(allowed_hosts=self.allowed_hosts,
                                                         run_context=run_context),
                    "csrf": CsrfValidator(allowed_hosts=self.allowed_hosts,
                                           run_context=run_context),
                    "file_upload": FileUploadValidator(allowed_hosts=self.allowed_hosts),
                }
                _sqlmap_inst = self.validator_registry.validators.get("sqlmap")
                if _sqlmap_inst is not None:
                    _val_by_conf["sqlmap"] = _sqlmap_inst
                # Key headers by DURABLE PRINCIPAL id (R02), matching the coverage
                # identity, so two same-role accounts don't collapse/overwrite.
                def _pid(r):
                    p = getattr(r, "principal_id", None)
                    return str(p()) if callable(p) else (getattr(r, "role", None) or "anonymous")
                _role_headers = {_pid(r): dict(r.headers or {}) for r in roles}

                async def _run_leg_core(identity, method, path, check, case_key=None):
                    validator = _val_by_conf.get(check.confirmation)
                    if validator is None:
                        return None  # e.g. sqlmap/race_condition -- not driven here
                    node = {"method": method, "path": path}
                    # R05: replay the captured template for this endpoint if we have
                    # one, so the coverage-driven leg sends the real shape too.
                    _ep_obj = state.endpoints.get(f"{method} {path}")
                    if _ep_obj is not None and getattr(_ep_obj, "template", None):
                        node["template"] = _ep_obj.template
                    ex = worklist_investigator._seed_exchange(
                        base_url, node, _role_headers.get(identity, {}), "1")
                    res = await _cached_validate(
                        validator, _as_finding({"vulnerability_class": check.vulnerability_class},
                                               check.vulnerability_class), ex)
                    # T05/R26: bind a case-bound structured proof to this driven leg
                    # (concrete parameter case when the driver fanned out to one),
                    # so a coverage-driven confirmation carries a stable case id to
                    # the T01 proof store -- not just a matrix cell.
                    proof_id, case_id = await self._coverage_proof(
                        identity=identity, check=check, exchange=ex, result=res,
                        case_key=case_key, run_context=run_context)
                    # R06: a coverage-driven CONFIRMATION enters the SAME finding
                    # pipeline as every other confirmed finding -- ingested into
                    # `state` (=> worklist, summary, report, persistence, chain
                    # linking), not merely recorded as a matrix cell.
                    cf = coverage_confirmation_finding(res, check, ex.url, identity)
                    if cf is not None:
                        if res.confirmed and case_id:
                            cf["proof_id"] = proof_id
                            cf["case_id"] = case_id
                        state.ingest_findings(ex.url, method, [cf])
                        all_findings.append(cf)
                    return res

                async def _run_leg(identity, method, path, check):
                    return await _run_leg_core(identity, method, path, check, None)

                if self.engagement_coverage_case_drive:
                    # T05/R26: finer, per-input driving -- fan each parameter leg over
                    # the endpoint's concrete inputs so a confirmation binds to the
                    # exact parameter case and un-run inputs stay visibly pending.
                    coverage = await coverage_tracker.build_coverage_cases_driven(
                        state, roles, _run_leg_core, budget=self.coverage_leg_budget,
                        per_cell_case_budget=self.coverage_case_budget,
                        driveable=set(_val_by_conf.keys()), investigated_keys=investigated_keys)
                else:
                    coverage = await coverage_tracker.build_coverage_driven(
                        state, roles, _run_leg, budget=self.coverage_leg_budget,
                        driveable=set(_val_by_conf.keys()), investigated_keys=investigated_keys)
            else:
                coverage = coverage_tracker.build_coverage(state, roles,
                                                           investigated_keys=investigated_keys)
        except Exception as e:  # coverage is a report layer -- never sink the run
            log.warning("investigate_engagement: coverage build failed: %s", e)
            _errors.append({"phase": "coverage_build", "error": f"{type(e).__name__}: {e}"})

        return {
            "summary": state.summary(),
            "worklist": state.worklist(50),
            "outcomes": outcomes,
            "chains": chains,
            "chain_rounds": rounds,
            "coverage": coverage,
            "workflows": workflow_results,
            "task_graph": state.graph.to_dict(),
            "ready_tasks": state.pending(),
            "blocked_tasks": state.blocked(),
            "auth_bypass_candidates": rc.auth_bypass_candidates,
            "idor_candidates": rc.idor_candidates,
            "idor_findings": rc.idor_findings,
            # R30: operational failures are surfaced, not swallowed -- a run that
            # skipped a phase is declared degraded rather than presented as clean.
            "errors": _errors,
            "degraded": bool(_errors),
        }
