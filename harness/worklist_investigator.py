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

    Returns a per-node outcome list; findings are folded back into `state`."""
    role_headers = {r.role: dict(r.headers or {}) for r in roles}
    outcomes: list[dict] = []
    investigated = 0
    precondition_run = 0

    for node in state.worklist(50):
        derived = _derive_probe(node)
        # R21: completion belongs to an (endpoint, check) case, not the whole
        # endpoint -- a "validated" endpoint may still hold UNRELATED vulnerabilities.
        # So we no longer skip a validated endpoint wholesale; we skip only the
        # redundant AGENT re-probe when THIS node's derived class is already confirmed
        # here. Shape-driven precondition legs (other classes) still run, and because
        # validated endpoints sink in the fused-score ordering they only draw leftover
        # budget.
        derived_confirmed = derived is not None and _derived_class_confirmed(node, derived[0])
        do_agent = derived is not None and not derived_confirmed and investigated < max_nodes
        do_precond = precondition_fn is not None and precondition_run < max_precondition_legs
        if not do_agent and not do_precond:
            continue  # no agent hypothesis AND no shape-driven leg to run -- skip

        reach = node.get("reachable_roles", []) or []
        # probe from the lowest-trust identity that can reach it (strongest proof).
        probe_role = min(reach, key=_trust) if reach else (roles[0].role if roles else "anonymous")
        headers = role_headers.get(probe_role, {})
        exchange = _seed_exchange(base_url, node, headers, id_fill)

        node_findings: list[dict] = []

        # 1. Proactive, precondition-driven legs (shape, not agent label). Cheap
        #    for a node whose shape warrants nothing (returns [] with no network).
        precond_findings: list[dict] = []
        if do_precond:
            # R23: the precondition budget bounds ATTEMPTS, not confirmations. Count
            # the attempt here (a leg was run on this node) regardless of whether it
            # confirmed -- otherwise max_precondition_legs was a confirmation ceiling
            # that never bit on the far-more-common no-finding path.
            precondition_run += 1
            try:
                precond_findings = await precondition_fn(node, exchange) or []
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

    log.info("investigate_worklist: %s -- investigated %d nodes, %d proactive legs attempted",
             base_url, investigated, precondition_run)
    return outcomes
