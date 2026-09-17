"""
Worklist investigator -- Milestone B: per-node multi-step investigation.

Pass 1 fired every agent at every captured request, once each, and gave up when
one shot found nothing. This drives the ITERATIVE agent instead, TOP-DOWN off the
harness's own prioritised worklist (engagement_builder): take the highest-value
node, derive a hypothesis from what the access matrix already knows about it, and
give it a bounded send->observe->adapt investigation -- N steps, stop on confirm
or budget -- rather than a single guess. Findings fold back into the graph, so a
node that's been investigated changes status and sinks in the ranking: the harness
does not re-test what it has already worked.

This is the loop the earlier sessions described ("an agent with a number of
interactions / reasoning steps") wired to coverage + prioritisation: what to test
is chosen by the graph, how hard to test it is the per-node step budget.

`probe_fn` is the investigation seam -- in production it is
orchestrator.run_active_probe (the iterative agent + pivot integration); tests
inject a stub. No LLM or network logic lives here, only the derive -> drive ->
integrate loop.
"""
from __future__ import annotations

import logging
from urllib.parse import urlsplit

from harness.models import HttpExchange
from harness.safety_gate import SafetyGateBlocked

log = logging.getLogger("harness.worklist_investigator")

# Trust order so the driver probes from the LOWEST-privilege identity that can
# reach a node -- proving a bug from a weak role is the stronger result.
_TRUST = {"anonymous": 0, "user": 1, "agent": 2, "service": 2, "manager": 3, "admin": 4}


def _trust(role: str) -> int:
    return _TRUST.get((role or "").lower(), 1)


def _derive_probe(node: dict) -> tuple[str, str] | None:
    """Map a worklist node to (specialty, hypothesis), or None to skip a node
    with no actionable signal. The signal is what the access matrix already
    established -- object-scoping, an unconfirmed IDOR candidate, or a low-trust
    role reaching a privileged-looking path -- so the hypothesis is grounded, not
    a blind guess."""
    method, path = node.get("method", "GET"), node.get("path", "/")
    reach = node.get("reachable_roles", []) or []
    reasons = node.get("reasons", []) or []
    findings = node.get("findings", []) or []
    has_idor = any((f.get("vulnerability_class") or "").lower().startswith(("idor", "insecure direct"))
                   or "object" in (f.get("vulnerability_class") or "").lower() for f in findings)
    low_trust_priv = any("privileged-looking" in r and "reach" in r for r in reasons) or \
        any("authz gap" in r.lower() for r in reasons)

    if node.get("object_scoped") or has_idor:
        return "idor", (
            f"Object-scoped endpoint {method} {path} is reachable by {', '.join(reach) or 'unknown roles'}. "
            f"Enumerate the object id to reach another identity's object and confirm broken "
            f"object-level authorization (IDOR/BOLA).")
    if low_trust_priv:
        return "auth", (
            f"{method} {path} is a privileged-looking endpoint reachable by a low-trust role "
            f"({', '.join(reach) or 'unknown'}). Probe for broken function-level authorization / auth bypass.")
    return None


# Keywords a derived specialty's confirmation would carry, so R21 can tell whether
# THIS node's derived check is already proven (skip only the agent re-probe) versus
# the endpoint merely holding some OTHER confirmed class.
_SPECIALTY_KEYWORDS = {
    "idor": ("idor", "insecure direct", "object-level", "object level", "bola",
             "broken access", "access_control", "access control"),
    "auth": ("auth", "bfla", "function-level", "function level", "privilege",
             "missing authorization", "missing_authorization"),
}


def _derived_class_confirmed(node: dict, specialty: str) -> bool:
    """True iff the node already has a CONFIRMED finding of the derived specialty's
    class (R21) -- so we skip only the redundant agent re-probe for that class, not
    all further work on the endpoint."""
    kws = _SPECIALTY_KEYWORDS.get(specialty, (specialty,))
    for f in node.get("findings") or []:
        if f.get("confirmed"):
            cls = (f.get("vulnerability_class") or "").lower()
            if any(k in cls for k in kws):
                return True
    return False


def _parent_template_object_id(state, node: dict) -> str | None:
    """A concrete, real object id borrowed from a PARENT object-scoped route's
    own captured template, for a NESTED child route (e.g.
    /api/tickets/{id}/comments derived from /api/tickets/{id}) that has no
    template -- hence no real id -- of its own.

    Without this, a nested route with no capture of its own falls back to the
    generic id_fill ("1"), which may not correspond to ANY real object for
    ANY identity -- cross-identity replay against a nonexistent object is
    indistinguishable from "properly denied" (a 404, not a 200), so the leg
    can never confirm. The object a SIBLING route (the same {id}, one path
    segment shorter) was captured against DOES exist, so replaying the nested
    route with THAT id gives cross-identity confirmation something real to
    compare (2026-09-17 coverage-recovery plan, Step 3).

    Walks the path's `{id}` occurrences from the LAST toward the first, so a
    doubly-nested route (/a/{id}/b/{id}/c) still tries its immediate parent
    first. Returns None when the node already has its own object id, or no
    ancestor route with one is known -- callers keep their own id_fill."""
    tmpl = node.get("template") or {}
    if tmpl.get("object_id"):
        return None
    path = node.get("path") or "/"
    method = (node.get("method") or "GET").upper()
    segments = path.split("/")
    id_positions = [i for i, s in enumerate(segments) if s == "{id}"]
    for cut in reversed(id_positions):
        parent_path = "/".join(segments[:cut + 1]) or "/"
        if parent_path == path:
            continue  # not actually a proper ancestor
        parent = state.endpoints.get(f"{method} {parent_path}") if state else None
        if parent is not None and parent.template and parent.template.get("object_id"):
            return parent.template["object_id"]
    return None


def _seed_exchange(base_url: str, node: dict, headers: dict, id_fill: str,
                   template: dict | None = None) -> HttpExchange:
    """Build the probe exchange for a node. When a captured request TEMPLATE exists
    (R05), replay its real body, query and content-type, and fill `{id}` with the
    OBSERVED object id rather than "1" -- overlaying the probe identity's own auth
    headers so we test AS that identity but with the captured request's real shape.
    With no template it fabricates as before (empty body, id_fill, no query)."""
    template = template or node.get("template") or None
    id_val = (template.get("object_id") if template and template.get("object_id") else id_fill)
    body = (template.get("body", "") if template else "") or ""
    query = (template.get("query", "") if template else "") or ""
    ctype = (template.get("content_type", "") if template else "") or ""

    path = node.get("path", "/").replace("{id}", id_val)
    url = base_url.rstrip("/") + path
    if query and "?" not in url:
        url = f"{url}?{query}"

    # Identity headers win (we probe AS the probe identity); the captured
    # Content-Type is carried over when the identity didn't set one -- it is what a
    # shape leg (xxe/form/upload) needs. Other captured headers are NOT replayed
    # (they may carry the captor's own session -- an identity/scope concern).
    merged = dict(headers or {})
    if ctype and not any((k or "").lower() == "content-type" for k in merged):
        merged["Content-Type"] = ctype

    return HttpExchange(
        url=url, method=node.get("method", "GET"),
        request_headers=merged, request_body=body,
        response_status=None, response_headers={}, response_body="",
    )


def _findings_from_outcome(outcome: dict) -> list[dict]:
    """Pull the findings the probe produced (iterative agent + pivot integration),
    as plain dicts ready for EngagementState.ingest_findings."""
    out: list[dict] = []
    ir = (outcome or {}).get("iterative_result", {}) or {}
    out.extend(ir.get("findings", []) or [])
    integ = (outcome or {}).get("integration", {}) or {}
    out.extend(integ.get("held_findings", []) or [])
    return out


# 2026-09-17 coverage-recovery plan, Step 2: the four honest reasons a
# high-priority, applicable node can go uninvestigated. Exhaustive by
# construction -- every skip in investigate_worklist maps to exactly one of
# these, so a caller can tell "we chose not to reach it" apart from "we never
# got the chance."
SKIP_BUDGET_EXHAUSTED = "budget_exhausted"
SKIP_UNREACHABLE = "unreachable"
SKIP_MISSING_TEMPLATE = "missing_template"
SKIP_POLICY_BLOCKED = "policy_blocked"


def _skip_reason(node: dict, eligible: bool, investigated: int, max_nodes: int,
                 policy_blocked_leg: bool) -> str:
    """Why a node that reached the end of one sweep iteration with no agent
    probe run was left uninvestigated -- checked in priority order so a node
    that is BOTH unreachable and over budget reports the more actionable
    reason (there was never anything to do here vs. we ran out of budget)."""
    if policy_blocked_leg:
        return SKIP_POLICY_BLOCKED
    if not (node.get("reachable_roles") or []):
        return SKIP_UNREACHABLE
    if eligible and investigated >= max_nodes:
        return SKIP_BUDGET_EXHAUSTED
    return SKIP_MISSING_TEMPLATE


async def investigate_worklist(
    probe_fn,
    state,
    base_url: str,
    roles,
    *,
    confirm_fn=None,
    precondition_fn=None,
    max_nodes: int = 8,
    max_precondition_legs: int = 24,
    step_budget: int = 16,
    id_fill: str = "1",
    worklist_limit: int = 200,
    summary_out: dict | None = None,
) -> list[dict]:
    """Drive `probe_fn` over the top `max_nodes` actionable worklist nodes.

    `probe_fn(exchange, hypothesis, specialty, step_budget) -> outcome dict`.

    `confirm_fn(finding_dict, exchange)`, if given, runs a deterministic
    confirmation (e.g. the cross-identity replay) on each AGENT finding BEFORE it
    folds into the graph -- so a confirmed access-control finding lands as
    `validated`, sinks in the ranking, and outranks the agent's unconfirmed
    guesses. It mutates the finding in place (may set confirmed=True + boost
    confidence).

    `precondition_fn(node, exchange) -> list[confirmed finding dicts]`, if given,
    runs the deterministic confirmation legs a node's SHAPE warrants -- object-
    scoped -> cross-identity, JWT-carrying -> jwt-forge, XML body -> xxe, ... --
    REGARDLESS of whether an agent produced a matching finding. This is the fix
    for the detection->confirmation coupling (HANDOVER_6 §3/§4): a perfect leg
    used to contribute nothing unless an agent first flagged that exact class on
    that exact exchange. Driven by shape, a leg runs on every endpoint it could
    prove -- including nodes with NO actionable agent hypothesis at all (a JWT-
    carrying endpoint the agent probe would skip still gets its alg:none forged).
    It returns only CONFIRMED findings (shape is a reason to TRY; confirmation is
    still deterministic), so it never adds unconfirmed shape-guesses as noise.

    `worklist_limit` bounds how much of the ranked worklist is even considered
    (2026-09-17 coverage-recovery plan, Step 2) -- it defaults far above
    `max_nodes` so honest budget/skip accounting covers the real candidate
    set, not a silently-truncated top slice.

    `summary_out`, if given a dict, is updated in place with `eligible`
    (agent-actionable, not-yet-confirmed nodes seen this sweep),
    `investigated` (agent probes actually run), and `skipped` (a list of
    `{path, method, reason}` for every eligible-or-applicable node this sweep
    did NOT investigate, `reason` being one of budget_exhausted, unreachable,
    missing_template, policy_blocked) plus `skipped_by_reason` counts. This is
    what makes a "max coverage" claim checkable instead of asserted: a run
    with a nonempty `skipped_by_reason[budget_exhausted]` reached its node
    budget with eligible work still on the table.

    Returns a per-node outcome list; findings are folded back into `state`."""
    role_headers = {r.role: dict(r.headers or {}) for r in roles}
    outcomes: list[dict] = []
    investigated = 0
    precondition_run = 0
    eligible_count = 0
    skipped: list[dict] = []

    for node in state.worklist(worklist_limit):
        derived = _derive_probe(node)
        # R21: completion belongs to an (endpoint, check) case, not the whole
        # endpoint -- a "validated" endpoint may still hold UNRELATED vulnerabilities.
        # So we no longer skip a validated endpoint wholesale; we skip only the
        # redundant AGENT re-probe when THIS node's derived class is already confirmed
        # here. Shape-driven precondition legs (other classes) still run, and because
        # validated endpoints sink in the fused-score ordering they only draw leftover
        # budget.
        derived_confirmed = derived is not None and _derived_class_confirmed(node, derived[0])
        eligible = derived is not None and not derived_confirmed
        if eligible:
            eligible_count += 1
        do_agent = eligible and investigated < max_nodes
        # Step 3 (2026-09-17 coverage-recovery plan): a proven-dead endpoint
        # (every probed role got a server error) or a malformed/encoded
        # discovery artifact must not spend the shared max_precondition_legs
        # budget -- that budget is what a real, live endpoint (e.g. a captured
        # /api/integrations POST) needs to actually get its SSRF/xxe/mass-
        # assignment leg attempted, and it is finite while decoys can be
        # numerous (the same route guessed under a dozen path prefixes).
        is_junk_node = bool(node.get("dead_endpoint")) or bool(node.get("malformed_or_encoded"))
        do_precond = (precondition_fn is not None and precondition_run < max_precondition_legs
                     and not is_junk_node)
        if not do_agent and not do_precond:
            skipped.append({"path": node.get("path"), "method": node.get("method", "GET"),
                            "reason": _skip_reason(node, eligible, investigated, max_nodes, False)})
            continue  # no agent hypothesis AND no shape-driven leg to run -- skip

        reach = node.get("reachable_roles", []) or []
        # probe from the lowest-trust identity that can reach it (strongest proof).
        probe_role = min(reach, key=_trust) if reach else (roles[0].role if roles else "anonymous")
        headers = role_headers.get(probe_role, {})
        parent_id = _parent_template_object_id(state, node)
        exchange = _seed_exchange(base_url, node, headers, parent_id or id_fill)

        node_findings: list[dict] = []

        # 1. Proactive, precondition-driven legs (shape, not agent label). Cheap
        #    for a node whose shape warrants nothing (returns [] with no network).
        precond_findings: list[dict] = []
        policy_blocked_leg = False
        if do_precond:
            # R23: the precondition budget bounds ATTEMPTS, not confirmations. Count
            # the attempt here (a leg was run on this node) regardless of whether it
            # confirmed -- otherwise max_precondition_legs was a confirmation ceiling
            # that never bit on the far-more-common no-finding path.
            precondition_run += 1
            try:
                precond_findings = await precondition_fn(node, exchange) or []
            except SafetyGateBlocked:
                # The leg was attempted but the safety gate denied the send --
                # a concrete, reportable reason (policy_blocked), distinct from
                # "this node's shape warranted nothing."
                policy_blocked_leg = True
                precond_findings = []
            except Exception as e:  # a leg failure must not sink the sweep
                log.debug("precondition_fn failed on %s %s: %s",
                          node.get("method"), node.get("path"), e)
                precond_findings = []
            if precond_findings:
                for f in precond_findings:
                    f.setdefault("url", exchange.url)
                node_findings.extend(precond_findings)

        # 2. The iterative agent probe (unchanged) -- only when a specialty
        #    derived and the agent budget remains.
        agent_stop = None
        if do_agent:
            specialty, hypothesis = derived
            investigated += 1
            try:
                outcome = await probe_fn(exchange, hypothesis, specialty, step_budget)
            except Exception as e:  # one node's failure must not sink the sweep
                log.warning("investigate_worklist: node %s %s failed: %s",
                            node.get("method"), node.get("path"), e)
                if node_findings:  # still keep any proactively-confirmed findings
                    state.ingest_findings(exchange.url, exchange.method, node_findings)
                outcomes.append({"path": node.get("path"), "specialty": specialty,
                                 "error": repr(e), "precondition_findings": len(precond_findings),
                                 "findings_detail": list(node_findings)})
                continue
            agent_findings = _findings_from_outcome(outcome)
            for f in agent_findings:
                f.setdefault("url", exchange.url)  # stamp the concrete url for chain/capability linking
            if confirm_fn is not None:
                for f in agent_findings:
                    try:
                        await confirm_fn(f, exchange)  # deterministic confirmation, mutates f in place
                    except Exception as e:  # confirmation is a bonus -- never sink the finding
                        log.debug("confirm_fn failed on %s: %s", exchange.url, e)
            node_findings.extend(agent_findings)
            agent_stop = (outcome or {}).get("iterative_result", {}).get("stop_reason")

        if not do_agent and not precond_findings:
            skipped.append({"path": node.get("path"), "method": node.get("method", "GET"),
                            "reason": _skip_reason(node, eligible, investigated, max_nodes,
                                                   policy_blocked_leg)})
            continue  # a shape-scan that confirmed nothing -- don't record an empty outcome

        if node_findings:
            state.ingest_findings(exchange.url, exchange.method, node_findings)
        outcomes.append({
            "path": node.get("path"),
            "specialty": derived[0] if derived else None,
            "probe_role": probe_role,
            "findings": len(node_findings),
            "findings_detail": node_findings,
            "precondition_findings": len(precond_findings),
            "confirmed": any(f.get("confirmed") for f in node_findings),
            "stop_reason": agent_stop,
        })

    log.info("investigate_worklist: %s -- investigated %d nodes, %d proactive legs attempted, "
             "%d node(s) skipped (of %d eligible)",
             base_url, investigated, precondition_run, len(skipped), eligible_count)
    if summary_out is not None:
        by_reason: dict[str, int] = {}
        for s in skipped:
            by_reason[s["reason"]] = by_reason.get(s["reason"], 0) + 1
        summary_out.update({
            "eligible": eligible_count,
            "investigated": investigated,
            "skipped": skipped,
            "skipped_by_reason": by_reason,
        })
    return outcomes
