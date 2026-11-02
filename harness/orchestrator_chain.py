"""orchestrator_chain.py -- ChainMixin mixin for Orchestrator (W-15 decomposition).

The graph-driven engagement loop: plan/run_engagement, auto-escalation,
credential-grant checks, and investigate_engagement (with its nested
_confirm dispatcher and precondition legs).

Split out of orchestrator.py verbatim; `self` state is initialised in
Orchestrator.__init__ and resolved across mixins via the MRO.
"""
from __future__ import annotations

import contextlib
import copy
import time
import uuid

from harness import identity_compare
from harness import identity_headers
from harness.orchestrator_helpers import *  # noqa: F401,F403  (shared imports/helpers/constants)
from harness.circuit_breaker import get_ollama_circuit_breaker
# W-16: the single TargetTransport. Imported by name (not as the module) because
# investigate_engagement has a `run_context` parameter that would shadow the module;
# `transport_for(run_context, ...)` then reads as "use this run's transport, or a
# standalone one when it is None".
from harness.run_context import transport_for, ExecutionOutcome, case_scope, count_sends
from harness.execution_registry import ExecutionRegistry
from harness import run_journal
# FR-6: need the module too (the driver scope reads its ambient run) -- aliased for the
# same shadowing reason as above (several methods below have a `run_context` parameter).
from harness import run_context as _run_context_mod
from harness.security import is_credential_header
from harness import objective_completion as _objective_completion_mod
from harness.objective_profiles import ObjectiveTask


# FR-6 (F10) sentinel appended to a header value to make it a genuinely invalid
# credential control -- see `_invalidated_headers` below.
_FR6_INVALID_SENTINEL = "_fr6_invalid"


class _ConfirmationCache:
    """Within-run memo of confirmation results for investigate_engagement().

    Delegates to the run's ExecutionRegistry (execution_registry.py), whose key
    includes the IDENTITY (auth headers) and finding subtype, so a probe AS one
    identity never returns a result computed AS another (R03), and which the
    model-review path shares so one run does not repeat a check across paths.
    Each entry also remembers the case its sends were recorded under."""

    def __init__(self, run_context, case_for, registry=None):
        self._run_context = run_context
        self._case_for = case_for  # (vulnerability_class, exchange) -> case id
        self._registry = registry if registry is not None else ExecutionRegistry(
            budget=getattr(run_context, "budget", None))

    async def validate(self, validator, finding_obj, exchange, case_ref=None):
        """Wrapper around validator.validate() that caches results within this
        run. A hit returns the previous ValidationResult without any
        HTTP/container work.

        The leg's sends are recorded under `case_ref` (default: the case
        _apply builds for this class and exchange), so the exchanges its
        result names resolve for that case's proof. A hit for the same case
        returns the cached result. A hit for another case returns a copy
        without the named exchanges, which were recorded under the first case
        and do not resolve here: that proof stays a candidate. The cached
        original is never changed."""
        if case_ref is None:
            try:
                case_ref = self._case_for(getattr(finding_obj, "vulnerability_class", ""), exchange)
            except Exception:
                case_ref = ""
        async def run_it():
            # Answered run-transport sends of this dispatch (batch 02). Kept apart
            # from sent_count, whose absence still means "decide from status"
            # for validators that send through a host tool.
            with case_scope(case_ref), count_sends() as sent:
                result = await validator.validate(finding_obj, exchange)
            if result is not None:
                result.observed_sends = sent[0]
            if result is not None and not getattr(result, "attempt_id", ""):
                # Batch 02: the stable id of this one real execution.
                from harness.coverage_tracker import new_attempt_id
                result.attempt_id = new_attempt_id()
            return result
        result = await self._registry.run(validator, finding_obj, exchange,
                                          case_ref=case_ref, call=run_it)
        # A same-case hit is the cached object itself: it carries the original
        # attempt id, which the matrix merges by id, so no fresh attempt is
        # counted twice. A hit for another case is the registry's covered copy.
        return result


import re as _re

# Foreign object identifiers to try in a single-principal IDOR read (usernames of
# OTHER people mentioned in public content, numeric ids seen in links). Purely a
# seed list: the IDOR read validator never confirms (RV-D2), so its best result
# for any id is an inconclusive candidate and a stray id cannot confirm anything.
_ID_QUERY_KEYS = {"id", "user", "user_id", "userid", "uid", "account", "account_id",
                  "customer", "customer_id", "profile", "pid", "oid", "owner"}
_AUTHOR_MENTION = _re.compile(
    r'(?:author|username|posted by|created by|by)["\'\s:>]{1,4}([A-Za-z][A-Za-z0-9_.\-]{2,30})',
    _re.IGNORECASE)


def _harvest_object_ids(captured, own_ids) -> list[str]:
    """Mine candidate foreign object ids from the run's own observed traffic:
    values of id-like query params seen in links, and other people's usernames
    mentioned in public content. Excludes the current principal(s)' own ids and is
    bounded. This is observed data, never a guessed wordlist."""
    from urllib.parse import urlsplit, parse_qsl
    own = {str(x).lower() for x in (own_ids or set())}
    seen: list[str] = []

    def _add(v: str):
        v = (v or "").strip()
        if (v and v.lower() not in own and v not in seen
                and 1 <= len(v) <= 32 and v.lower() not in ("anonymous", "user", "admin", "me")):
            seen.append(v)

    for cap in (captured or []):
        try:
            ex = cap if hasattr(cap, "url") else None
            url = (ex.url if ex is not None else (cap.get("url") if isinstance(cap, dict) else "")) or ""
            body = (ex.response_body if ex is not None
                    else (cap.get("response_body") if isinstance(cap, dict) else "")) or ""
        except Exception:
            continue
        for k, val in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if k.lower() in _ID_QUERY_KEYS:
                _add(val)
        for m in _AUTHOR_MENTION.finditer(body or ""):
            _add(m.group(1))
        if len(seen) >= 8:
            break
    return seen[:8]


def _ssti_readback_urls(captured) -> list[str]:
    """Candidate SSTI readback pages: same-origin GET urls already observed in
    this engagement with a 2xx response, excluding destructive-looking paths.

    `captured` (normally `_all_captured`) is a UNION of two shapes by design:
    `HttpExchange` objects (feature_workflow's own captures) and the dict form
    role_crawl's discovery captures use (`HttpExchange(...).model_dump()`,
    required by test_role_crawl.py's dict-indexed assertions on
    RoleCrawlResult.captured). `_harvest_object_ids` above already tolerates
    both; this normalizes each item the same way before reading any field, so
    a dict element no longer crashes here. A malformed item is skipped, not
    fatal -- it just never becomes a readback candidate."""
    urls: list[str] = []
    for cap in (captured or []):
        try:
            cap_ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
        except Exception:
            continue
        if (cap_ex.method or "GET").upper() != "GET":
            continue
        _parts = urlsplit(cap_ex.url or "")
        _path_low = (_parts.path or "/").lower()
        if any(token in _path_low for token in
               ("logout", "signout", "delete", "remove", "destroy", "reset")):
            continue
        if cap_ex.response_status is not None and not (200 <= cap_ex.response_status < 300):
            continue
        urls.append(cap_ex.url)
    return urls


def _invalidated_headers(headers: dict) -> dict:
    """Return a copy of `headers` with the credential corrupted, for the
    invalid-token control probe in `_credential_grants_access`. Corrupts the
    VALUE of every header recognised as a credential header
    (`security.is_credential_header`: authorization/cookie, API-key and token
    schemes, ...) so the server should reject it. If none of the supplied headers
    are recognised credential headers (a scheme the classifier does not know),
    corrupts every supplied header's value instead, so the control is always
    genuinely invalid rather than an accidental no-op. Header NAMES are always preserved
    so routing/auth dispatch is unchanged -- only the value is corrupted."""
    out = dict(headers or {})
    cred_keys = [k for k in out if is_credential_header(k)]
    for k in (cred_keys or list(out.keys())):
        out[k] = f"{out[k]}{_FR6_INVALID_SENTINEL}"
    return out


def _responses_equivalent(a: ExecutionOutcome, b: ExecutionOutcome) -> bool:
    """True when two probe outcomes represent the same access: identical status
    AND identical body. A None/errored outcome's status is treated as None and
    its body as "" (matching `ExecutionOutcome`'s own defaults), consistently
    for both sides. Deliberately simple and exact -- no fuzzy body diffing --
    so only a clear, real difference ever counts as evidence of a genuine
    credential grant."""
    a_status = a.status if a is not None else None
    b_status = b.status if b is not None else None
    a_body = (a.body or "") if a is not None else ""
    b_body = (b.body or "") if b is not None else ""
    return a_status == b_status and a_body == b_body


def _responses_materially_same(a: ExecutionOutcome, b: ExecutionOutcome) -> bool:
    """Noise-tolerant counterpart to _responses_equivalent: two probe outcomes
    represent the SAME access (not an authorization grant) when they share a
    status and their bodies are similar above identity_compare.MATCH_THRESHOLD.
    Per-request noise (nonce/timestamp/CSRF/ads/rate-limit/login pages) stays
    below the grant signal because trigram similarity of a body differing only
    in one volatile token lands well above the match threshold, while two
    genuinely different resources fall below it. Reuses the same
    None->status / errored->body normalization _responses_equivalent applies."""
    a_status = a.status if a is not None else None
    b_status = b.status if b is not None else None
    a_body = (a.body or "") if a is not None else ""
    b_body = (b.body or "") if b is not None else ""
    return a_status == b_status and identity_compare.similarity(a_body, b_body) >= identity_compare.MATCH_THRESHOLD


class _DriverBudget:
    """Atomic child reservations spend the parent budget without replacing it."""
    def __init__(self, parent, maximum):
        import threading
        self.parent, self.maximum, self.spent = parent, maximum, 0
        self.lock = threading.Lock()

    def reserve(self, n=1, label=""):
        with self.lock:
            # A parent that predates labels (no by_label) is reserved unlabelled.
            if self.spent + n > self.maximum or not (
                    self.parent.reserve(n, label=label) if hasattr(self.parent, "by_label")
                    else self.parent.reserve(n)):
                return False
            self.spent += n
            return True

    @property
    def by_label(self):
        return self.parent.by_label

    @property
    def remaining(self):
        remaining = self.parent.remaining
        own = max(0, self.maximum - self.spent)
        return own if remaining is None else min(own, remaining)

    @property
    def used(self):
        return self.parent.used


@contextlib.asynccontextmanager
async def _driver_scope(run, maximum):
    import copy
    from dataclasses import replace
    from harness.safety_gate import push_gate, pop_gate
    child = copy.copy(run)
    child.budget = run.budget if maximum is None else _DriverBudget(run.budget, maximum)
    child.gate = copy.copy(run.gate)
    child.gate.config = replace(run.gate.config, allow_mutating_replay=False)
    gate_restore = push_gate(child.gate)
    # Task-local binding: sibling drivers retain their own child budget.
    token = _run_context_mod._ambient_run.set(child)
    try:
        yield child
    finally:
        _run_context_mod._ambient_run.reset(token)
        pop_gate(gate_restore)
        # A lazily opened default client belongs to this child, not its parent.
        if child._default_client is not None and child._default_client is not run._default_client:
            await child._default_client.aclose()


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

        # Guard 3: per-host session cap.
        if self._escalation_counts.get(host, 0) >= self.engagement_max_escalations:
            log.info("engagement auto-escalate: per-host cap (%d) reached for %s -- skipping",
                     self.engagement_max_escalations, host)
            return

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
            self._escalation_counts[host] = self._escalation_counts.get(host, 0) + 1
            log.info("engagement auto-escalate: re-crawled %s as derived identity, +%d endpoints (host total %d)",
                     origin, len(result.endpoints), self._escalation_counts[host])
        except Exception as e:
            log.warning("engagement auto-escalate failed: %s", e)
        finally:
            for ref in session_refs or ():
                await run_context.sessions.unregister(ref)

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
            run_context, allowed_hosts=self.allowed_hosts, config=self.config)
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

    # Roles registered as replay identities below are owned by this engagement
    # and released when it ends (never leak into a later engagement on the host).
    @identity_headers.leased
    async def investigate_engagement(self, base_url, roles, *, max_nodes: int = 8,
                                     step_budget: int = 16, discovery_max_probes: int = 6000,
                                     discovery_max_endpoints: int = 150,
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
        `protected_paths` and `owners` are the operator's engagement declarations
        (I16): merged into the state after discovery, where the missing-auth (RV-S)
        and ownership (RV-T) confirmations read them. None or empty changes nothing."""
        from harness import engagement_builder
        from harness import worklist_investigator
        from harness import chain_linker
        from harness import role_crawl
        from harness.instrumentation import RunInstrumentation
        from harness.assessment_health import new_review_stats
        # Stage reservations: the coverage drive runs last, so withhold its share of
        # the one run ceiling from every earlier stage (released just before the
        # drive), and bound the investigation stages by wall-clock time.
        _investigation_deadline = (time.monotonic() + self.investigation_seconds
                                   if self.investigation_seconds > 0 else None)
        _run_budget = getattr(run_context or _run_context_mod.current_run_context(), "budget", None)
        _coverage_hold = (_run_budget.hold(self.coverage_request_reserve)
                          if self.coverage_request_reserve > 0 and hasattr(_run_budget, "hold") else 0)
        # E9: observation only. Each `phases.begin(...)` below closes the previous
        # phase and opens the next; nothing is reordered or skipped by it.
        _instr = RunInstrumentation(self, run_context or _run_context_mod.current_run_context(),
                                    _run_budget)
        _instr.phases.begin("discovery")

        # E7: with a journal on the run, each finished unit is written as it completes, and
        # a journal that already holds units for this root job (an interrupted earlier
        # run, or the same run's earlier attempt) is resumed from instead of repeated.
        _journal = getattr(run_context, "run_journal", None)
        _resumed_units = {"discovery": False, "worklist": 0, "review": 0, "coverage_checkpoint": False}

        def _journal_read(read, default):
            """A journal read that fails is a journal with nothing in it: the run goes on."""
            try:
                return read()
            except Exception as e:
                log.warning("investigate_engagement: journal read failed (%s)", type(e).__name__)
                return default

        _resuming = _journal is not None and _journal_read(_journal.has_any, False)

        def _journal_put(unit, payload):
            if _journal is None:
                return
            try:
                _journal.put(unit, payload)
            except Exception as e:  # losing a unit costs a repeat on resume, never the run
                log.warning("investigate_engagement: journal write of %s failed: %s", unit, e)

        def _journal_phase(name):
            _journal_put(f"phase:{name}", {"finished_at": time.time()})

        _stored_discovery = _journal_read(lambda: _journal.get("discovery"), None) if _resuming else None
        if _stored_discovery is not None:
            try:
                state, rc = run_journal.restore_discovery(_stored_discovery, roles)
                # Discovery registers the roles' sessions with the run; restoring it must too.
                engagement_builder.register_role_sessions(run_context, base_url, roles)
                _resumed_units["discovery"] = True
            except Exception as e:
                log.warning("investigate_engagement: journaled discovery unusable (%s); "
                            "discovering again", type(e).__name__)
        if not _resumed_units["discovery"]:
            state, rc = await engagement_builder.build_engagement(
                base_url, roles, allowed_hosts=self.allowed_hosts,
                crawl_max_pages=discovery_max_pages,
                max_endpoints=discovery_max_endpoints,
                active_discovery=active_discovery,
                discovery_max_probes=discovery_max_probes, run_context=run_context,
                **({"seed_exchanges": seed_exchanges} if seed_exchanges else {}),
                **({"driver_capture_config": self.config["driver_capture"]}
                   if (self.config.get("driver_capture") or {}).get("enabled") else {}))
            if _journal is not None:
                try:
                    _journal_put("discovery", run_journal.discovery_payload(state, rc, roles))
                    _journal_phase("discovery")
                except Exception as e:
                    log.warning("investigate_engagement: journaling discovery failed: %s", e)

        # I16: the operator's declarations for this engagement, added after discovery
        # (built or restored) so both paths carry them. Malformed entries are left to
        # the readers, which ignore them with a warning (fail closed).
        for _field, _declared in (("protected_paths", protected_paths), ("owners", owners)):
            if _declared:
                _have = getattr(state, _field)
                _have.extend(entry for entry in _declared if entry not in _have)

        # Units an earlier attempt finished, passed to the phases that skip them. Their
        # findings come back marked `resumed_from`, a confirmation only while its proof
        # still resolves (run_journal.resume_finding).
        _worklist_kwargs: dict = {}
        _review_kwargs: dict = {}
        _review_summary: dict = {}
        if _journal is not None:
            _root = _journal.root_job_id
            _worklist_kwargs = {
                "completed": (_journal_read(lambda: {
                    unit[len("worklist:"):]: run_journal.resume_outcome(payload, _root)
                    for unit, payload in _journal.units("worklist:").items()}, {})
                              if _resuming else None),
                "on_outcome": lambda key, outcome: _journal_put(f"worklist:{key}", outcome)}
            _review_kwargs = {
                "resumed": (_journal_read(lambda: {
                    unit[len("review:"):]: {"findings": [run_journal.resume_finding(f, _root)
                                                         for f in payload.get("findings") or []]}
                    for unit, payload in _journal.units("review:").items()}, {})
                            if _resuming else None),
                "on_review": lambda key, payload: _journal_put(f"review:{key}", payload),
                "summary_out": _review_summary}

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
        _errors: list[dict] = [
            {"phase": "discovery", "error": message}
            for message in getattr(rc, "errors", [])
            if not message.startswith("[discovery] used spec ")
        ]
        _reviewed_captures: set[str] = set()
        _review_stats = new_review_stats()
        workflow_results: list[dict] = []

        # Preserve real request shapes before any worklist leg runs. Full model
        # review is deliberately deferred until after the bounded deterministic
        # precondition sweep below; otherwise a handful of discovery captures can
        # consume the wall-clock budget before a three-request validator runs.
        for _cap in list(getattr(rc, "captured", None) or []):
            try:
                _ex = _cap if isinstance(_cap, HttpExchange) else HttpExchange(**_cap)
                state.record_template(_ex.url, _ex.method, _ex)
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
        for sf_record in getattr(rc, "sensitive_file_evidence", None) or []:
            sf_path = str(sf_record.get("path") or "")
            _sf_recorded.add(sf_path)
            state.ingest_findings(f"{base_url}{sf_path}", "GET",
                                  [sensitive_file_finding(sf_record)])
        for sf_path in getattr(rc, "sensitive_file_hits", None) or []:
            if sf_path not in _sf_recorded:
                state.ingest_findings(f"{base_url}{sf_path}", "GET",
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
                discovered_paths = [ep.path for ep in rc.endpoints] if rc.endpoints else None
                feature_caps = await engagement_builder.feature_crawl_captures(
                    base_url, roles, allowed_hosts=self.allowed_hosts,
                    submit_forms=_get_gate().config.allow_mutating_replay,
                    seed_paths=discovered_paths, run_context=run_context, errors=_errors)
                # Make workflow routes and their real request shapes visible to
                # prioritisation. Content-level model review remains deferred.
                for ex in feature_caps:
                    state._ep(ex.method, _eng.normalize_path(ex.url))
                    state.record_template(ex.url, ex.method, ex)
            except Exception as e:  # feature crawl is additive -- never sink the run
                log.warning("investigate_engagement: feature crawl failed: %s", e)
                _errors.append({"phase": "feature_crawl", "error": f"{type(e).__name__}: {e}"})

        # E4/E2: the run's one execution registry, made before the header audit so the
        # audit's csp/cors checks are recorded in it and the model-review path (which
        # reads it through run_context) does not run them again for the same route and
        # identity, nor the worklist or the drive any other check.
        _exec_registry = getattr(run_context, "execution_registry", None)
        if not isinstance(_exec_registry, ExecutionRegistry):
            _exec_registry = ExecutionRegistry(budget=getattr(run_context, "budget", None))
            if run_context is not None:
                run_context.execution_registry = _exec_registry

        _instr.phases.begin("header_audit")
        # Universal header audit: run CORS, CSP, verbose-error validators
        # against EVERY captured exchange from discovery + feature_crawl.
        # This catches header-level issues the LLM agents never labelled.
        _all_captured = list(getattr(rc, "captured", None) or [])
        try:
            _all_captured.extend(feature_caps)  # noqa: F821 -- set in the feature_crawl block above
        except NameError:
            pass
        if not (stop_on_confirm and objective_class):
            try:
                await universal_header_audit(self, state, _all_captured, run_context=run_context)
            except Exception as e:
                log.warning("investigate_engagement: universal header audit failed: %s", e)
                _errors.append({"phase": "universal_header_audit", "error": f"{type(e).__name__}: {e}"})
                from harness import telemetry
                telemetry.record_swallowed_exception("universal_header_audit", e)

        async def _probe(exchange, hypothesis, specialty, sb):
            # ARCH-1: forward THIS engagement's run_context so the iterative
            # probe's sends spend the run's budget/transport, not a throwaway one.
            return await self.run_active_probe(exchange, hypothesis, specialty,
                                               step_budget=sb, run_context=run_context)

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
        from harness.validators.auth_sequence_validator import AuthSequenceValidator
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
        ownership = self._configure_ownership(base_url, engagement_owners=getattr(state, "owners", None),
                                              run_context=run_context, install=False)
        if (ownership is None and run_context is not None
                and self._experiments_config().get("enabled", False)):
            # Ticket G: share ONE ledger between the experiment cycle and the
            # cross-identity validator, so an ownership fact an experiment
            # establishes is what that validator consults.
            ownership = self._experiment_ownership(state, run_context, base_url)
        _xid_cfg = (self.config.get("validators", {}) or {}).get("cross_identity", {}) or {}
        _xval = CrossIdentityValidator(
            allowed_hosts=self.allowed_hosts,
            timeout=float(_xid_cfg.get("timeout", 10.0)),
            max_identities=int(_xid_cfg.get("max_identities", 3)),
            run_context=run_context,
            # WL-04: the registry's declared-ownership source (D1 seam); None means
            # a cross-identity match is a `supported` lead, never a confirmation.
            ownership=ownership)
        # Single-principal IDOR read-differential: swap the object id (no second
        # account needed). Seed it with foreign ids observed elsewhere in the run
        # (other users mentioned in public content, ids seen in links) so a
        # username-keyed IDOR is reachable, not just numeric neighbours. It never
        # confirms (RV-D2): one principal cannot show the object is unauthorised,
        # so its best result is an inconclusive candidate; only cross_identity
        # confirms IDOR.
        _idor_cfg = (self.config.get("validators", {}) or {}).get("idor_read", {}) or {}
        _idor_read = IdorReadValidator(
            allowed_hosts=self.allowed_hosts,
            # Observed ids (mined from content) plus any target object ids the
            # operator declared for this engagement (e.g. a known victim account,
            # like a tester who was told which record to reach).
            candidate_ids=(list(_idor_cfg.get("candidate_ids", []) or [])
                           + _harvest_object_ids(_all_captured, {r.principal_id() for r in roles})))
        _bxss = BrowserXssValidator(allowed_hosts=self.allowed_hosts, run_context=run_context)
        _jwt = JwtForgeValidator(allowed_hosts=self.allowed_hosts,
                                 run_context=run_context)
        from harness.collaborator import ConfiguredCollaborator
        _callbacks = getattr(getattr(self, "validator_registry", None), "collaborator", None) or ConfiguredCollaborator(self.config)
        _ssrf = SsrfValidator(allowed_hosts=self.allowed_hosts, collaborator=_callbacks, oob_callbacks_enabled=bool((self.config.get("validators") or {}).get("oob_callbacks_enabled", True)))
        _xxe = XxeValidator(allowed_hosts=self.allowed_hosts, collaborator=_callbacks, oob_callbacks_enabled=bool((self.config.get("validators") or {}).get("oob_callbacks_enabled", True)))
        _cmdi = CommandInjectionValidator(allowed_hosts=self.allowed_hosts,
                                          run_context=run_context, collaborator=_callbacks, oob_callbacks_enabled=bool((self.config.get("validators") or {}).get("oob_callbacks_enabled", True)))
        # Stored SSTI often writes a preference/editor value and evaluates it on
        # a separate public render.  Supply only GET pages already observed in
        # this engagement; the validator keeps the set bounded and same-origin.
        _ssti_readbacks = _ssti_readback_urls(_all_captured)
        _ssti_readbacks.sort(key=lambda u: ("/post" not in urlsplit(u).path.lower(), u))
        _ssti = SstiValidator(allowed_hosts=self.allowed_hosts,
                              run_context=run_context,
                              readback_urls=_ssti_readbacks)
        _path = PathTraversalValidator(allowed_hosts=self.allowed_hosts,
                                       run_context=run_context)
        _redir = OpenRedirectValidator(allowed_hosts=self.allowed_hosts)
        _seq = SequenceValidator(allowed_hosts=self.allowed_hosts)
        _deser = DeserializationOobValidator(allowed_hosts=self.allowed_hosts)
        _auth = AuthSequenceValidator(allowed_hosts=self.allowed_hosts)
        _ct = ClientTrustValidator(allowed_hosts=self.allowed_hosts)
        _sxss = StoredXssValidator(allowed_hosts=self.allowed_hosts, run_context=run_context)
        _rate = RateLimitValidator(allowed_hosts=self.allowed_hosts,
                                   run_context=run_context)
        _reset = ResetTokenValidator(allowed_hosts=self.allowed_hosts)
        _domxss = DomXssValidator(allowed_hosts=self.allowed_hosts, run_context=run_context)
        _toctou = ToctouValidator(allowed_hosts=self.allowed_hosts,
                                  run_context=run_context)
        _csrf = CsrfValidator(allowed_hosts=self.allowed_hosts,
                              run_context=run_context)
        _nosql = NosqlValidator(allowed_hosts=self.allowed_hosts,
                                run_context=run_context)
        _race_cfg = ((self.config.get("validators", {}) or {}).get("race_condition", {}) or {})
        _race = RaceConditionValidator(
            timeout=float(_race_cfg.get("timeout", 15.0)),
            burst_size=int(_race_cfg.get("burst_size", 12)),
            run_context=run_context,
            target_email=_race_cfg.get("target_email"),
            mailbox_url=_race_cfg.get("mailbox_url"),
            email_race_rounds=int(_race_cfg.get("email_race_rounds", 6)))
        _sql_cfg = ((self.config.get("validators", {}) or {}).get("sqlmap", {}) or {})
        _sqlmap = SqlmapValidator(
            binary=_sql_cfg.get("binary", "sqlmap"),
            timeout_seconds=int(_sql_cfg.get("timeout_seconds", 90)),
            level=int(_sql_cfg.get("level", 1)),
            risk=int(_sql_cfg.get("risk", 1)),
            container_image=_sql_cfg.get("container_image"),
            run_context=run_context,
            allowed_hosts=self.allowed_hosts,
            quick_only=bool(stop_on_confirm and objective_class == "sqli"),
        )

        # Memoisation cache: avoid re-running the same validator on the same
        # endpoint during one investigate_engagement() call (see _ConfirmationCache).
        from harness.validators.base import (
            ValidationResult as _VR, observed_result_of, proof_artifact_kwargs)
        # E4: `_exec_registry` (made before the header audit) is also read by the
        # model-review path (orchestrator_confirm._validate_findings) through
        # run_context, so a check that ran for the worklist is not run again for the
        # review or the drive.
        _cached_validate = _ConfirmationCache(
            run_context, lambda cls, exchange: _rb4_case(cls, exchange).case_id,
            registry=_exec_registry).validate

        # RB-4/INV-2: this path (worklist_investigator's confirm_fn for agent
        # findings, and its precondition_fn for every shape-driven leg dispatch
        # through _confirm/_apply below) used to stamp `confirmed`/
        # `confirmed_by_leg` with NO persisted ProofRecord and NO evidence_ledger
        # VALIDATION_DECISION behind it -- the exact GT04/05/06 gap INV-2 traced
        # (docs/investigations/INV-2-proof-gap.md). One run-scoped id (not
        # per-call) so every case _apply builds this run shares a stable
        # run_id, matching how PASS1's RunContext-derived run_id is stable across
        # one analyze() call.
        _rb4_run_id = run_context.run_id if run_context is not None else uuid.uuid4().hex
        from harness.categories import canonicalize as _rb4_canon
        from harness import evidence_ledger

        def _rb4_principal_for(exchange) -> str:
            """Best-effort identity label for the case: the role whose headers
            match this exchange's request headers, else "" (anonymous/unlabelled).
            Only affects case-identity bookkeeping, never the confirmation verdict."""
            hdrs = dict(exchange.request_headers or {})
            if not hdrs:
                return "anonymous"
            for r in roles:
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

        _protected: list = []   # RV-S: this target's declared routes, built on first use

        async def _confirm(finding, exchange):
            """Dispatch a finding to the deterministic confirmation leg for its class:
            access-control -> cross-identity replay; xss -> headless-browser execution.
            A confirmed finding is upgraded in place; anything else is left untouched."""
            vc = (finding.get("vulnerability_class") or "")
            low = vc.lower()
            if low in ("auth_bypass", "missing_authentication", "missing authentication"):
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
                            self.config, base_url,
                            engagement_paths=getattr(state, "protected_paths", None)))
                    declared = _protected[0].match(method, exchange.url)
                    baseline = exchange.request_headers
                    # The anonymous replay keeps only public headers, so a supplied
                    # identity's custom header (X-Tenant) never rides along on it;
                    # the same names count as the baseline's credentials, so an app
                    # that authenticates only through one can confirm (RV-S
                    # residuals 2 and 3).
                    supplied = {k.lower() for r in roles for k in (r.headers or {})}

                    def _credential(name):
                        return missing_auth_probe.credential_header(name, supplied)

                    if declared is not None and not any(_credential(k) for k in (baseline or {})):
                        # The probe identity of an anonymously reached node is
                        # anonymous, so the baseline borrows the highest-trust
                        # supplied identity's credential headers.
                        authed = [r for r in roles if any(_credential(k) for k in (r.headers or {}))]
                        if authed:
                            top = max(authed, key=lambda r: role_crawl._trust(r.role))
                            baseline = {**(baseline or {}), **{
                                k: v for k, v in top.headers.items() if _credential(k)}}
                    outcome = await missing_auth_probe.probe(
                        base_url, (method, path),
                        allowed_hosts=self.allowed_hosts,
                        baseline_headers=baseline,
                        send_garbage_token=False,
                        expected_protected=declared is not None,
                        protected_baseline=True,
                        run_context=run_context,
                        identity_headers=supplied)
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
            elif access_control_gate._is_access_control_class(vc):
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
                    await _apply(finding, await _cached_validate(_xval, _as_finding(finding, "idor"), exchange), "cross-identity", 0.9, exchange)
                    # Single-principal follow-up: if no second identity confirmed a
                    # cross-identity breach, run the object-id read differential
                    # (own vs foreign vs absent) as the captured principal. It never
                    # confirms (RV-D2), so `_apply` leaves the finding unconfirmed
                    # and keeps only any manual-verification guidance it carries.
                    if not finding.get("confirmed"):
                        await _apply(finding, await _cached_validate(_idor_read, _as_finding(finding, "idor"), exchange), "idor-read", 0.75, exchange)
                except Exception:
                    return
            elif ("dom" in low and "xss" in low) or "dom_xss" in low or "dom-based" in low or "client-side xss" in low:
                # DOM-based XSS: fragment-payload browser execution (client-side
                # source->sink), distinct from server-reflected browser_xss.
                try:
                    await _apply(finding, await _cached_validate(_domxss, _as_finding(finding, "dom_xss"), exchange),
                           "dom-xss", 0.95, exchange)
                except Exception:
                    return
            elif "xss" in low or "cross-site scripting" in low or "cross_site" in low:
                # browser_xss executes payloads in a real browser; it CONFIRMS reflected
                # XSS and (crucially for a JSON API) declines what never reaches an HTML
                # sink. Skips gracefully if no browser engine is installed.
                try:
                    await _apply(finding, await _cached_validate(_bxss, _as_finding(finding, "xss"), exchange), "browser-xss", 0.95, exchange)
                    # reflected browser_xss handles GET reflections; a write-shaped
                    # exchange may instead be a STORED-XSS plant point -- try that leg too.
                    if not finding.get("confirmed") and (exchange.method or "GET").upper() in ("POST", "PUT", "PATCH"):
                        await _apply(finding, await _cached_validate(_sxss, _as_finding(finding, "xss"), exchange), "stored-xss", 0.9, exchange)
                except Exception:
                    return
            elif "jwt" in low or "algorithm confusion" in low or "algorithm_confusion" in low or "weak_token" in low:
                try:
                    await _apply(finding, await _cached_validate(_jwt, _as_finding(finding, "jwt"), exchange), "jwt-forge", 0.9, exchange)
                except Exception:
                    return
            elif "ssrf" in low or "server-side request" in low or "server_side_request" in low:
                try:
                    await _apply(finding, await _cached_validate(_ssrf, _as_finding(finding, "ssrf"), exchange), "ssrf", 0.95, exchange)
                except Exception:
                    return
            elif "xxe" in low or "xml external" in low or "xml_external" in low:
                try:
                    await _apply(finding, await _cached_validate(_xxe, _as_finding(finding, "xxe"), exchange), "xxe", 0.95, exchange)
                except Exception:
                    return
            elif ("sqli" in low or "sql injection" in low
                  or "sql_injection" in low):
                try:
                    await _apply(
                        finding,
                        await _cached_validate(_sqlmap, _as_finding(finding, "sqli"), exchange),
                        "sqlmap", 0.95, exchange)
                except Exception:
                    return
            elif "nosql" in low or "mongodb injection" in low or "mongo injection" in low:
                try:
                    await _apply(finding, await _cached_validate(
                        _nosql, _as_finding(finding, "nosql"), exchange),
                        "nosql", 0.95, exchange)
                except Exception:
                    return
            elif "race_condition" in low or "race condition" in low:
                try:
                    await _apply(finding, await _cached_validate(
                        _race, _as_finding(finding, "race_condition"), exchange),
                        "race-condition", 0.95, exchange)
                except Exception:
                    return
            elif "command" in low or low in ("rce", "remote code execution", "code injection", "shell injection"):
                try:
                    await _apply(finding, await _cached_validate(_cmdi, _as_finding(finding, "command_injection"), exchange),
                           "command-injection", 0.95, exchange)
                except Exception:
                    return
            elif "ssti" in low or "template injection" in low:
                try:
                    await _apply(finding, await _cached_validate(_ssti, _as_finding(finding, "ssti"), exchange), "ssti", 0.95, exchange)
                except Exception:
                    return
            elif "traversal" in low or "lfi" in low or "file inclusion" in low:
                try:
                    await _apply(finding, await _cached_validate(_path, _as_finding(finding, "path_traversal"), exchange),
                           "path-traversal", 0.95, exchange)
                except Exception:
                    return
            elif "redirect" in low:
                try:
                    await _apply(finding, await _cached_validate(_redir, _as_finding(finding, "open_redirect"), exchange),
                           "open-redirect", 0.9, exchange)
                except Exception:
                    return
            elif ("toctou" in low or "time-of-check" in low or "time of check" in low
                  or "check-then-act" in low or "check then act" in low
                  or ("privilege" in low and "race" in low) or ("race" in low and "escalat" in low)):
                # TOCTOU privilege-escalation race: concurrent check-then-write.
                # Must precede the mass/privilege->sequence branch below.
                try:
                    await _apply(finding, await _cached_validate(_toctou, _as_finding(finding, "toctou"), exchange),
                           "toctou", 0.85, exchange)
                except Exception:
                    return
            elif "mass" in low or "assignment" in low or "privilege" in low or low in ("api_security", "api security"):
                try:
                    await _apply(finding, await _cached_validate(_seq, _as_finding(finding, "mass_assignment"), exchange),
                           "sequence", 0.9, exchange)
                except Exception:
                    return
            elif "deserial" in low or "pickle" in low or "object injection" in low:
                try:
                    await _apply(finding, await _cached_validate(_deser, _as_finding(finding, "deserialization"), exchange),
                           "deserialization", 0.95, exchange)
                except Exception:
                    return
            elif ("session fixation" in low or "session_fixation" in low or "weak password" in low
                  or "weak_password" in low or "enumeration" in low or "broken authentication" in low
                  or "broken_authentication" in low or "2fa" in low or "mfa" in low
                  or "two_factor" in low or "two-factor" in low or "multi_factor" in low
                  or "second factor" in low):
                try:
                    await _apply(finding, await _cached_validate(_auth, _as_finding(finding, low or "broken_authentication"), exchange),
                           "auth-sequence", 0.85, exchange)
                except Exception:
                    return
            elif ("client_trust" in low or "business" in low or "client-side" in low or "price" in low
                  or "excessive trust" in low or "logic_flaw" in low):
                try:
                    await _apply(finding, await _cached_validate(_ct, _as_finding(finding, "business_logic"), exchange),
                           "client-trust", 0.9, exchange)
                except Exception:
                    return
            elif "rate limit" in low or "rate_limit" in low or "lockout" in low or "brute" in low:
                try:
                    await _apply(finding, await _cached_validate(_rate, _as_finding(finding, "rate_limit"), exchange),
                           "rate-limit", 0.85, exchange)
                except Exception:
                    return
            elif "csrf" in low or "cross-site request forgery" in low or "cross site request forgery" in low:
                try:
                    await _apply(finding, await _cached_validate(
                        _csrf, _as_finding(finding, "csrf"), exchange),
                        "csrf", 0.95, exchange)
                except Exception:
                    return
            elif ("reset_token" in low or "reset token" in low or "predictable token" in low
                  or "weak token" in low or "token entropy" in low):
                try:
                    await _apply(finding, await _cached_validate(_reset, _as_finding(finding, "reset_token"), exchange),
                           "reset-token", 0.9, exchange)
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
                if objective_class and vclass != objective_class:
                    continue
                r = await _confirm_leg(vclass, ex, path)
                if r:
                    confirmed.append(r)
            return confirmed

        # P2-1: ONE business-context planning pass, BEFORE the worklist sweep, so
        # its business-impact re-ranking actually changes what the bounded node
        # budget investigates first (a checkout/payment/role endpoint ahead of a
        # generic page). Default off -- when off this is a no-op and the ranking
        # is unchanged. It sends nothing and confirms nothing. Best-effort: an
        # ASM failure must never sink the engagement (same contract as the
        # additive phases above).
        _instr.phases.begin("business_context")
        _asm = None
        try:
            _asm = self._apply_business_context(state, _all_captured, roles)
        except Exception as e:
            log.warning("investigate_engagement: business-context pass failed: %s", e)
            _errors.append({"phase": "business_context", "error": f"{type(e).__name__}: {e}"})

        # Ticket G: the graph -> experiment -> workflow -> proof -> graph cycle for
        # the business-context hypotheses. Default off (engagement.experiments);
        # when off this returns None without a send. Best-effort like the passes
        # around it: a failure is recorded as an "experiments" phase error.
        if run_context is not None:
            run_context.experiment_context = {"state": state, "asm": _asm, "base_url": base_url, "captured": _all_captured}
        _instr.phases.begin("experiments")
        _experiments = None
        try:
            _experiments = await self._run_experiments(
                state, _asm, run_context, base_url=base_url, captured=_all_captured,
                ownership=ownership)
        except Exception as e:
            log.warning("investigate_engagement: experiments phase failed: %s", e)
            _errors.append({"phase": "experiments", "error": f"{type(e).__name__}: {e}"})

        _instr.phases.begin("worklist")
        worklist_summary: dict = {}

        # Objective mode gets one deterministic pass over the real captured
        # request shapes before graph ranking. Ranking is intentionally generic
        # and can put many object-detail routes ahead of a filter/search sink;
        # spending the objective budget on those unrelated parameters recreates
        # the same latency failure this mode exists to prevent.
        _objective_outcomes: list[dict] = []
        if stop_on_confirm and objective_class:
            for _captured in _all_captured:
                try:
                    _objective_ex = (_captured if isinstance(_captured, HttpExchange)
                                     else HttpExchange(**_captured))
                except Exception:
                    continue
                _objective_path = urlsplit(_objective_ex.url).path or "/"
                _objective_node = {"method": _objective_ex.method,
                                   "path": _objective_path}
                warranted = [v for v, _ in shape_precondition_legs(
                    _objective_node, _objective_ex, roles, base_url)]
                if objective_class not in warranted:
                    continue
                _objective_finding = await _confirm_leg(
                    objective_class, _objective_ex, _objective_path)
                if not _objective_finding:
                    continue
                _objective_finding.setdefault("url", _objective_ex.url)
                state.ingest_findings(
                    _objective_ex.url, _objective_ex.method, [_objective_finding])
                _objective_outcome_entry = {
                    "path": _objective_path,
                    "method": _objective_ex.method,
                    "specialty": objective_class,
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
                if objective_task is not None:
                    try:
                        from harness.validators.base import ValidationResult as _ValidationResult
                        _synthetic_confirmation = _ValidationResult(
                            validator=objective_class, status="confirmed",
                            finding_class=objective_class,
                            confidence=float(_objective_finding.get("confidence", 0.9) or 0.9),
                            confirmed=True)
                        _completion = await _objective_completion_mod.attempt_completion(
                            objective_task, Finding(
                                vulnerability_class=objective_class,
                                confidence=_synthetic_confirmation.confidence,
                                summary=_objective_finding.get("summary", ""),
                                evidence=_objective_finding.get("evidence", ""),
                                suggested_test="", basis="derived",
                                severity=_objective_finding.get("severity", "high")),
                            _objective_ex, _synthetic_confirmation,
                            run_context=run_context, provider=objective_provider)
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

        async def _investigate(st, rs):
            outs = await worklist_investigator.investigate_worklist(
                _probe, st, base_url, rs, confirm_fn=_confirm, precondition_fn=_precondition,
                max_nodes=max_nodes, step_budget=step_budget, summary_out=worklist_summary,
                stop_on_confirm=stop_on_confirm, deadline=_investigation_deadline,
                **_worklist_kwargs)
            timed_out = (worklist_summary.get("skipped_by_reason") or {}).get("time_budget", 0)
            if timed_out:
                _errors.append({"phase": "worklist",
                                "error": f"investigation time budget reached: {timed_out} "
                                         "worklist node(s) not investigated"})
            return outs, [f for o in outs for f in o.get("findings_detail", [])]

        if _objective_outcomes:
            outcomes = _objective_outcomes
            all_findings = [f for o in outcomes for f in o["findings_detail"]]
        else:
            outcomes, all_findings = await _investigate(state, roles)
            _journal_phase("worklist")

        # Phase 0.1 now runs after deterministic confirmation. Broad engagements
        # retain the full content review. Objective runners may stop once a
        # validator has independently confirmed a vulnerability, avoiding a slow
        # model pass after their success condition is already satisfied.
        _early_confirmed = any(
            f.get("confirmed")
            for o in outcomes
            for f in (o.get("findings_detail", []) or [])
        )
        def _resume_report() -> dict:
            """What this run took from the journal instead of running (E7); {} without one."""
            if _journal is None:
                return {}
            _resumed_units["worklist"] = sum(1 for o in outcomes if o.get("resumed"))
            _resumed_units["review"] = _review_summary.get("resumed", 0)
            return {"resume": {"root_job_id": _journal.root_job_id, "resumed": _resuming,
                               "resumed_units": dict(_resumed_units), "journal": _journal.stats()}}

        def _objective_result(stopped: bool) -> dict:
            from harness.experiment import task_dispositions
            return {
                "experiment_preflight": task_dispositions(state,run_context,
                    enabled=bool(self._experiments_config().get('enabled',False)),
                    max_runs=int(self._experiments_config().get('max_runs',4)),
                    planner_enabled=bool(self._experiments_config().get('planner',False))),
                **_resume_report(),
                "summary": state.summary(),
                "worklist": state.result_worklist(50),
                "outcomes": outcomes,
                "worklist_summary": worklist_summary,
                "chains": [],
                "chain_rounds": 0,
                "application_semantic_model": _asm.to_dict() if _asm else None,
                "experiments": _experiments,
                "execution_registry": _exec_registry.stats(),
                "coverage": {},
                "workflows": workflow_results,
                "task_graph": state.graph.to_dict(),
                "ready_tasks": state.pending(),
                "blocked_tasks": state.blocked(),
                "auth_bypass_candidates": rc.auth_bypass_candidates,
                "idor_candidates": rc.idor_candidates,
                "idor_findings": rc.idor_findings,
                "errors": _errors,
                "review_stats": _review_stats,
                "degraded": bool(_errors),
                "stopped_on_confirmation": stopped,
                "instrumentation": _instr.snapshot(),
            }

        if stop_on_confirm and _early_confirmed:
            # Objective mode has reached its independently verified success
            # condition. Return the evidence now; continuing through chaining,
            # coverage driving, and broad model review can consume minutes and
            # cause the outer wall-clock guard to discard an already-confirmed
            # result as a timeout.
            return _objective_result(True)
        if stop_on_confirm and objective_class:
            # A class-scoped benchmark is a bounded deterministic measurement.
            # If none of its eligible request shapes confirms, preserve that
            # negative result instead of silently changing the experiment into
            # an open-ended model review of unrelated vulnerability classes.
            return _objective_result(False)
        _instr.phases.begin("capture_review")
        # One review time budget covers this pass and every chain round's pass.
        _review_deadline = (time.monotonic() + self.capture_review_seconds
                            if self.capture_review_seconds > 0 else None)
        if _investigation_deadline is not None:
            _review_deadline = min(_review_deadline or _investigation_deadline,
                                   _investigation_deadline)
        if not (stop_on_confirm and _early_confirmed):
            await review_captured_exchanges(
                self, state, _all_captured, run_context=run_context,
                seen=_reviewed_captures, errors=_errors, stats=_review_stats,
                max_reviews=self.capture_review_limit, deadline=_review_deadline,
                **_review_kwargs)
            _journal_phase("review")

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

        _instr.phases.begin("chain_rounds")
        # Milestone C: link findings into escalation edges + composed chains, then
        # walk the closed loop -- re-test AS any credential a finding leaked.
        link = chain_linker.link_findings(state, all_findings, responses=_responses)
        chains = list(link["chain_findings"])
        creds, rounds, seen_ident = link["credential_caps"], 0, set()
        while creds and rounds < max_chain_rounds:
            if _investigation_deadline is not None and time.monotonic() >= _investigation_deadline:
                _errors.append({"phase": "chain_rounds",
                                "error": f"investigation time budget reached: chain round "
                                         f"{rounds + 1} of up to {max_chain_rounds} not started"})
                break
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
                crawl_max_pages=discovery_max_pages,
                max_endpoints=discovery_max_endpoints,
                active_discovery=active_discovery,
                discovery_max_probes=discovery_max_probes, run_context=run_context)
            outs2, new_findings = await _investigate(st2, derived)
            if not (stop_on_confirm and any(f.get("confirmed") for f in new_findings)):
                await review_captured_exchanges(
                    self, st2, getattr(rc2, "captured", None), run_context=run_context,
                    seen=_reviewed_captures, errors=_errors, stats=_review_stats,
                    max_reviews=self.capture_review_limit, deadline=_review_deadline,
                    **_review_kwargs)
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
        _journal_phase("chain")

        _instr.phases.begin("second_order")
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
                _plant_headers, _other_headers = second_order_identities(roles)
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
                            run_context, "POST", a_url, allowed_hosts=self.allowed_hosts,
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
                            run_context, "GET", b_url, allowed_hosts=self.allowed_hosts,
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
        _instr.phases.begin("coverage_drive")
        _requests_before_coverage = getattr(_run_budget, "used", None)
        if _coverage_hold:
            _run_budget.release_hold()
        _coverage_deadline = (time.monotonic() + self.coverage_drive_seconds
                              if self.coverage_drive_seconds > 0 else None)
        coverage: dict = {}
        _prerequisite_blocks: dict = {}   # (endpoint, identity) -> grouped entry (E5b)
        try:
            from harness import coverage_tracker
            # E7: a caller's checkpoint wins; otherwise the journal's, when an earlier attempt
            # got far enough to write one. It is handed back every N legs of the drive.
            _coverage_kwargs: dict = {}
            if _journal is not None:
                _coverage_kwargs = {"on_checkpoint": lambda cp: _journal_put("coverage:checkpoint", cp)}
                _stored_checkpoint = (_journal_read(lambda: _journal.get("coverage:checkpoint"), None)
                                      if _resuming and coverage_checkpoint is None else None)
                if _stored_checkpoint is not None:
                    coverage_checkpoint = _stored_checkpoint
                    _resumed_units["coverage_checkpoint"] = True
            investigated_paths = {o.get("path") for o in outcomes if o.get("path")}
            investigated_keys = {k for k in state.endpoints
                                 if k.split(" ", 1)[-1] in investigated_paths}
            if self.engagement_coverage_drive:
                # I1 matrix-driver: build a confirmation->validator map (reusing the
                # instances above + a few cheap extra legs) and actively fire each
                # applicable leg-backed cell, recording the real leg status.
                from harness.validators.verb_tamper_validator import VerbTamperValidator
                from harness.validators.csrf_validator import CsrfValidator
                from harness.validators.file_upload_validator import FileUploadValidator
                _val_by_conf = {
                    "cross_identity": _xval, "idor_read": _idor_read, "jwt_forge": _jwt, "browser_xss": _bxss,
                    "stored_xss": _sxss, "ssrf": _ssrf, "xxe": _xxe,
                    "command_injection": _cmdi, "ssti": _ssti, "path_traversal": _path,
                    "open_redirect": _redir, "sequence": _seq, "deserialization_oob": _deser,
                    "auth_sequence": _auth, "rate_limit": _rate, "reset_token": _reset,
                    "dom_xss": _domxss, "toctou": _toctou,
                    "verb_tamper": VerbTamperValidator(allowed_hosts=self.allowed_hosts,
                                                         run_context=run_context),
                    "csrf": CsrfValidator(allowed_hosts=self.allowed_hosts,
                                           run_context=run_context),
                    "nosql": _nosql,
                    "file_upload": FileUploadValidator(allowed_hosts=self.allowed_hosts),
                }
                _sqlmap_inst = self.validator_registry.validators.get("sqlmap")
                if _sqlmap_inst is not None:
                    _val_by_conf["sqlmap"] = _sqlmap_inst
                # These registered validators have check-specific oracles. Do not
                # wire generic recon/crypto here: their aggregate verdict cannot
                # establish each individual header, metadata, method or TLS check.
                for name in ("csp", "cors", "header_injection",
                             "http_request_smuggling", "race_condition"):
                    registered = self.validator_registry.validators.get(name)
                    if registered is not None:
                        _val_by_conf[name] = self.validator_registry.bind_run_context(
                            [registered], run_context)[0]
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
                _role_headers = {_pid(r): dict(r.headers or {}) for r in roles}

                def _capability_decision(check, exchange):
                    resolve = getattr(self.validator_registry, "capability_for_check", None)
                    if resolve is None:
                        # Explicit compatibility for legacy injected registries.
                        return {"status": "ready", "reason_code": "legacy_adapter",
                                "reason": "legacy caller capability adapter",
                                "finding_class": check.vulnerability_class,
                                "mechanism_id": "legacy:" + check.confirmation}
                    return resolve(check, exchange, run_context=run_context,
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
                    return worklist_investigator._seed_exchange(
                        base_url, node, _role_headers.get(identity, {}), ""), None

                async def _run_captured_leg(identity, method, path, check, case_key=None, node=None):
                    validator = _val_by_conf.get(check.confirmation)
                    if validator is None:
                        return None  # e.g. sqlmap/race_condition -- not driven here
                    node = node or {"method": method, "path": path}
                    # R05: replay the captured template for this endpoint if we have
                    # one, so the coverage-driven leg sends the real shape too.
                    _ep_obj = state.endpoints.get(f"{method} {path}")
                    if "template" not in node and _ep_obj is not None and getattr(_ep_obj, "template", None):
                        node["template"] = _ep_obj.template
                    ex, problem = _known_capture_exchange(identity, node)
                    capability = problem or _capability_decision(check, ex)
                    if capability["status"] != "ready":
                        from harness.validators.base import ValidationResult
                        status = ("blocked" if capability["status"] == "policy_denied" else
                                  "inconclusive" if capability["status"] == "needs_prerequisite" else "skipped")
                        return ValidationResult(check.confirmation, status, check.vulnerability_class,
                            summary=f"{capability['reason_code']}: {capability['reason']}")
                    try:
                        leg_case = self._coverage_case(identity=identity, check=check, exchange=ex,
                                                       case_key=case_key, run_context=run_context)
                    except Exception:
                        leg_case = None
                    res = await _cached_validate(
                        validator, _as_finding({"vulnerability_class": capability["finding_class"]},
                                               capability["finding_class"]), ex,
                        case_ref=leg_case.case_id if leg_case is not None else "")
                    # T05/R26: bind a case-bound structured proof to this driven leg
                    # (concrete parameter case when the driver fanned out to one),
                    # so a coverage-driven confirmation carries a stable case id to
                    # the T01 proof store -- not just a matrix cell.
                    proof_id, case_id = await self._coverage_proof(
                        identity=identity, check=check, exchange=ex, result=res,
                        case_key=case_key, run_context=run_context, case=leg_case)
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

                # E5b: whether each (endpoint, identity) has a request to replay,
                # worked out ONCE here rather than per check. Only requests that were
                # observed as that identity count; nothing is built for an identity
                # that was never probed or captured on the endpoint.
                from harness.engagement import capture_identity_key, replayable_variants
                _identity_role = {_pid(r): r.role for r in roles}
                _replayable = {
                    (ep_key, identity): replayable_variants(ep, capture_identity_key(headers))
                    for ep_key, ep in state.endpoints.items() if ep.capture_variants
                    for identity, headers in _role_headers.items()}

                def _captured_readiness(identity, method, path, check):
                    if check.id == "WSTG-CRYP-01":
                        return _capability_decision(check, HttpExchange(url=base_url, method="GET"))
                    preliminary = _capability_decision(check, None)
                    if preliminary["status"] in {"unsupported", "disabled", "policy_denied"}:
                        return preliminary
                    ep_key = f"{method} {path}"
                    ep = state.endpoints.get(ep_key)
                    if ep is not None and ep.capture_variants:
                        variants = _replayable.get((ep_key, identity))
                        if variants is None:
                            variants = replayable_variants(ep, capture_identity_key(_role_headers.get(identity, {})))
                        if not variants:
                            role = _identity_role.get(identity, identity)
                            block = _prerequisite_blocks.setdefault((ep_key, identity), {
                                "endpoint": ep_key, "identity": identity,
                                "missing": "no request captured as this identity",
                                "action": "capture this request signed in as " + role
                                          + " (or add it to the role crawl seed)",
                                "checks_affected": 0})
                            block["checks_affected"] += 1
                            return {"status": "needs_prerequisite", "reason_code": "missing_principal",
                                    "reason": "capture the request as this identity", "finding_class": None}
                        selected_roles = [r for r in roles if _pid(r) == identity]
                        nodes = worklist_investigator.captured_nodes(
                            dict(ep.to_dict(), capture_variants=variants), base_url, selected_roles,
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

                async def _run_leg_core(identity, method, path, check, case_key=None):
                    ep_key = f"{method} {path}"
                    ep = state.endpoints.get(ep_key)
                    if ep is None or not ep.capture_variants:
                        return await _run_captured_leg(identity, method, path, check, case_key)
                    variants = _replayable.get((ep_key, identity))
                    if variants is None:
                        variants = replayable_variants(
                            ep, capture_identity_key(_role_headers.get(identity, {})))
                    if not variants:
                        # The cell's reason stays "missing_principal"; the pair is
                        # reported once, with how many checks it blocked.
                        role = _identity_role.get(identity, identity)
                        block = _prerequisite_blocks.setdefault((ep_key, identity), {
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
                    selected_roles = [r for r in roles if _pid(r) == identity]
                    outcomes = []
                    for node in worklist_investigator.captured_nodes(
                            dict(ep.to_dict(), capture_variants=variants), base_url, selected_roles,
                            include_probes=True):
                        problem = worklist_investigator.capture_problem(node)
                        if problem:
                            outcomes.append(_VR(check.confirmation, "inconclusive", check.vulnerability_class,
                                                summary=problem + ": supply a complete authorized capture"))
                        else:
                            outcomes.append(await _run_captured_leg(identity, method, path, check, case_key, node))
                    # Every proof instance was recorded above. A positive instance
                    # does not turn another unanswered variant into a clean cell.
                    incomplete = [r for r in outcomes if r is None or r.status not in
                                  {"confirmed", "not_confirmed", "controlled_negative", "safe"}]
                    if incomplete:
                        return next((r for r in incomplete if r is not None), None)
                    return next((r for r in outcomes if r.confirmed), outcomes[0] if outcomes else None)

                async def _run_leg(identity, method, path, check):
                    return await _run_leg_core(identity, method, path, check, None)

                if self.engagement_coverage_case_drive:
                    # T05/R26: finer, per-input driving -- fan each parameter leg over
                    # the endpoint's concrete inputs so a confirmation binds to the
                    # exact parameter case and un-run inputs stay visibly pending.
                    coverage = await coverage_tracker.build_coverage_cases_driven(
                        state, roles, _run_leg_core, budget=self.coverage_leg_budget, readiness=_captured_readiness,
                        per_cell_case_budget=self.coverage_case_budget,
                        driveable=set(_val_by_conf.keys()), investigated_keys=investigated_keys,
                        checkpoint=coverage_checkpoint,
                        context_key=coverage_tracker.resume_context_key(self.config),
                        deadline=_coverage_deadline, **_coverage_kwargs)
                else:
                    coverage = await coverage_tracker.build_coverage_driven(
                        state, roles, _run_leg, budget=self.coverage_leg_budget, readiness=_captured_readiness,
                        driveable=set(_val_by_conf.keys()), investigated_keys=investigated_keys,
                        checkpoint=coverage_checkpoint,
                        context_key=coverage_tracker.resume_context_key(self.config),
                        deadline=_coverage_deadline, **_coverage_kwargs)
                if coverage.get("checkpoint"):
                    _journal_put("coverage:checkpoint", coverage["checkpoint"])
                    _journal_phase("coverage")
                if coverage.get("drive_stopped_by") == "time budget":
                    _errors.append({"phase": "coverage_drive",
                                    "error": "coverage drive time budget reached: "
                                             f"{coverage.get('queued_not_attempted', 0)} queued "
                                             "leg(s) not attempted"})
            else:
                coverage = coverage_tracker.build_coverage(state, roles,
                                                           investigated_keys=investigated_keys)
        except Exception as e:  # coverage is a report layer -- never sink the run
            log.warning("investigate_engagement: coverage build failed: %s", e)
            _errors.append({"phase": "coverage_build", "error": f"{type(e).__name__}: {e}"})

        # AR-FP: the bounded final re-evaluation of experiment tasks over the values
        # and sessions every later phase left, before proofs are projected and the
        # dispositions taken. Inside the coverage stage's deadline; best-effort like
        # the experiments phase.
        _instr.phases.begin("experiments_final")
        _experiment_final_pass = None
        try:
            _experiment_final_pass = await self._final_experiment_pass(
                state, _asm, run_context, base_url=base_url, captured=_all_captured,
                ownership=ownership, deadline=_coverage_deadline)
        except Exception as e:
            log.warning("investigate_engagement: final experiment pass failed: %s", e)
            _errors.append({"phase": "experiments_final", "error": f"{type(e).__name__}: {e}"})

        from harness.experiment import project_proofs
        try:
            _experiment_projection = project_proofs(state, run_context)
        except Exception as exc:
            _errors.append({"phase":"experiment_projection", "error":type(exc).__name__})
            _experiment_projection = {"cases":[{"status":"unresolved", "reason":"experiment projection unavailable"}], "findings":[]}
        coverage["experiment_cases"] = _experiment_projection["cases"]
        from harness.experiment import task_dispositions
        _experiment_dispositions = task_dispositions(state, run_context,
            enabled=bool(self._experiments_config().get('enabled', False)),
            max_runs=int(self._experiments_config().get('max_runs', 4)),
            planner_enabled=bool(self._experiments_config().get('planner',False)))
        _instr.phases.begin("finalise")
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
            chains = self._relink_chains(state, all_findings, _responses)
        except Exception as e:
            log.debug("investigate_engagement: final chain re-link failed: %s", e)
            _errors.append({"phase": "final_chain_relink", "error": f"{type(e).__name__}: {e}"})

        # B2-1: if the shared ollama circuit breaker is OPEN at result assembly,
        # agent/model calls made during this engagement short-circuited without
        # hitting the model -- reuse the existing errors -> degraded contract
        # (R30 above) rather than adding a parallel degraded signal. Best-effort:
        # must never sink the run.
        try:
            if get_ollama_circuit_breaker("ollama").is_open:
                _errors.append({"phase": "circuit_breaker",
                                 "error": "ollama circuit breaker is OPEN: agent calls "
                                          "may have short-circuited during this engagement"})
        except Exception as e:
            log.debug("investigate_engagement: circuit breaker check failed: %s", e)

        from harness.assessment_health import assessment_health
        try:
            from harness.engagement import persist_surface
            await asyncio.to_thread(persist_surface, state)
        except Exception as exc:
            _errors.append({"phase": "surface_persistence", "error": type(exc).__name__})
        health = assessment_health(coverage, _errors)
        return {
            "assessment": health,
            "findings": [dict(f, url=f.get("url") or ep.path, method=ep.method)
                         for ep in state.endpoints.values() for f in ep.findings] + _experiment_projection["findings"],
            **_resume_report(),
            "summary": state.summary(),
            "worklist": state.result_worklist(50),
            "outcomes": outcomes,
            # 2026-09-17 coverage-recovery plan, Step 2: eligible/investigated
            # counts + a named, reasoned list of every eligible node this run did
            # NOT reach (budget_exhausted/unreachable/missing_template/
            # policy_blocked). A run must not be called "max coverage" if
            # skipped_by_reason shows eligible high-priority nodes were skipped.
            "worklist_summary": worklist_summary,
            "chains": chains,
            "chain_rounds": rounds,
            # P2-1: the Application Semantic Model built this run (None when the
            # business-context pass is off), so the API/report can show the
            # inferred roles/objects/workflows/value-flows/sinks and the ranked
            # chaining hypotheses that drove the re-ranking.
            "application_semantic_model": _asm.to_dict() if _asm else None,
            "experiments": _experiments,
            "experiment_preflight": _experiment_dispositions,
            "experiment_final_pass": _experiment_final_pass,
            # E4: how many validator executions the run's registry served without
            # running again, and the requests that saved (by validator).
            "execution_registry": _exec_registry.stats(),
            "coverage": coverage,
            # E5b: each (endpoint, identity) the coverage drive could not replay
            # because no request was observed as that identity, once, with the
            # number of checks it blocked and what to supply.
            "prerequisite_blocks": sorted(_prerequisite_blocks.values(),
                                          key=lambda b: (b["endpoint"], b["identity"])),
            # Stage reservations in effect: requests withheld for the coverage drive,
            # what the earlier stages spent, and the stage time bounds (0 = none).
            "stage_budgets": {"coverage_request_reserve": _coverage_hold,
                              "requests_before_coverage": _requests_before_coverage,
                              "requests_at_end": getattr(_run_budget, "used", None),
                              "outer_wall_seconds": None, "outer_wall_owner": "caller",
                              "capture_review_seconds": self.capture_review_seconds,
                              "investigation_seconds": self.investigation_seconds,
                              "coverage_drive_seconds": self.coverage_drive_seconds},
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
            "review_stats": _review_stats,
            "degraded": bool(_errors) or health["status"] == "incomplete",
            "instrumentation": _instr.snapshot(),
        }
