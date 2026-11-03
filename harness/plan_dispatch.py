"""Dispatch planner test plans to the harness's own validators.

`planner.plans_for_findings` turns every hypothesis into a declarative plan
named by CAPABILITY (reflection_context_validation, jwt_validation, ...). Most
of those plans carry execution_plane "burp", and before this module nothing in
the autonomous path read them back: the validator that implements the
capability ran under its own plan id (or none), so the planner plan stayed
`proposed` forever. The 8h Juice Shop run (b32e2cd106d2) left 62 of 110 plans
that way, every XSS, JWT, cross-identity, SQLi, NoSQL and CSRF plan among them.

`dispatch_plans` closes that gap for one analysed exchange, highest priority
first:
  * a plan whose capability's validator already ran on the same class is bound
    to that result (store.record_plan_dispatch);
  * a plan whose validator did not run is dispatched to it, within a per-call
    cap and the run's request budget, through the normal _validate_findings
    path -- so scope, safety gate, mutating ceilings and proof records all
    apply unchanged;
  * a plan no local validator can run is marked `not_dispatchable` with the
    reason, instead of looking like work that is still queued.

`injection_followups` covers the other half of the gap: a model finding whose
class did not canonicalize ("Authentication Bypass / SQL Injection") produced
no plan at all. A recognised injection token in its class or summary yields one
derived finding per request parameter, which the planner and validators route
like any other hypothesis.
"""
from __future__ import annotations

import logging
import re

from harness.categories import canonicalize
from harness.models import AgentReport, Finding, HttpExchange, TestPlan

log = logging.getLogger(__name__)

# Planner capability -> the registry validator names (Validator.name) that
# implement it locally. A capability absent here has no harness-side executor.
CAPABILITY_VALIDATORS: dict[str, tuple[str, ...]] = {
    "reflection_context_validation": ("browser_xss", "dom_xss", "stored_xss"),
    "jwt_validation": ("jwt_forge",),
    "cross_identity_compare": ("cross_identity", "idor_read"),
    "authorization_boundary_compare": ("cross_identity", "idor_read", "verb_tamper"),
    "csrf_validation": ("csrf",),
    "nosql_validation": ("nosql",),
    "sql_injection_validation": ("sqlmap",),
    "command_injection_validation": ("command_injection",),
    "ssti_validation": ("ssti",),
    "open_redirect_validation": ("open_redirect",),
    "xxe_validation": ("xxe",),
    "controlled_callback_probe": ("ssrf",),
    "file_upload_validation": ("file_upload",),
    "cors_misconfiguration_detection": ("cors_validator",),
    "api_security_validation": ("api_security_validator",),
    "bounded_rate_limit_probe": ("rate_limit",),
    "workflow_replay_compare": ("sequence",),
    "web_cache_poisoning_detection": ("web_cache_poisoning_validator",),
    "csp_clickjacking_validation": ("csp_validator",),
    "header_injection_validation": ("header_injection_validator",),
    "race_condition_validation": ("race_condition_validator",),
    "http_request_smuggling_detection": ("http_request_smuggling_validator",),
    "oauth_flow_validation": ("oauth_validator",),
    "crypto_transport_validation": ("crypto_validator",),
    "websocket_cswsh_validation": ("websocket_validator",),
    "attack_surface_mapping": ("recon_validator",),
    "session_fixation_compare": ("auth_sequence",),
    "logout_invalidation_compare": ("auth_sequence",),
    "info_disclosure_scan": ("verbose_error_validator",),
    "deserialization_format_confirmation": ("deserialization_validator", "deserialization_oob"),
}

# Plans dispatched (validator actually invoked) per analysed exchange. Binding
# an existing result is free and is not counted. Overridable with
# validators.plan_dispatch_max; config.yaml is left untouched.
DEFAULT_MAX_DISPATCH = 6

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def plan_priority(plan: TestPlan) -> tuple:
    """Sort key, highest priority first: severity, escalation, confidence, then
    capabilities that can confirm a vulnerability. Ties keep the planner order."""
    from harness import store
    return (-_SEVERITY_RANK.get((plan.severity or "").lower(), 0),
            0 if plan.escalated else 1,
            -float(plan.confidence or 0.0),
            0 if store.capability_can_confirm(plan.capability) else 1)


def prioritize(plans: list[TestPlan]) -> list[TestPlan]:
    return sorted(plans, key=plan_priority)


def dispatch_limit(config: dict | None) -> int:
    raw = ((config or {}).get("validators", {}) or {}).get("plan_dispatch_max")
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        return DEFAULT_MAX_DISPATCH
    return raw


def _canon(value: str) -> str:
    return canonicalize(value or "") or (value or "").strip().lower()


def _budget_spent(run_context) -> bool:
    budget = getattr(run_context, "budget", None)
    remaining = getattr(budget, "remaining", None)
    return isinstance(remaining, int) and remaining <= 0


def _undispatchable_reason(registry, names: tuple[str, ...], finding, exchange, agent) -> str:
    """Why none of `names` ran for this finding, in the operator's terms."""
    validators = {getattr(v, "name", k): v for k, v in (getattr(registry, "validators", {}) or {}).items()}
    present = [validators[n] for n in names if n in validators]
    if not present:
        return f"no enabled harness validator ({', '.join(names)}) is registered"
    if not getattr(registry, "enabled", True):
        return "validators are disabled"
    if all(v.active for v in present) and not getattr(registry, "active_enabled", False):
        return "active validation is off (validators.active_enabled)"
    return f"{', '.join(n for n in names if n in validators)} declined this request shape"


def _record(plan: TestPlan, report) -> bool:
    from harness import store
    ok, reason = store.record_plan_dispatch(
        plan.id, status=report.status, validator=report.validator,
        summary=(report.summary or "")[:500], confidence=report.confidence,
        confirmed=report.confirmed, evidence=(report.evidence or "")[:1000])
    if not ok and reason != "plan already has a result":
        log.warning("plan dispatch: could not record %s: %s", plan.id, reason)
    return ok


async def dispatch_plans(orch, exchange: HttpExchange, plans: list[TestPlan],
                         reports: list[AgentReport], validation_reports: list, *,
                         run_context=None, max_dispatch: int | None = None,
                         validated: bool = False) -> dict:
    """Bind, dispatch or explain every plan for this exchange (see module doc).

    `plans` must already be persisted. `validation_reports` are this exchange's
    validator results so far; a dispatched result is appended to it.
    `validated=True` says `reports` already went through _validate_findings
    (analyze()): a plan whose validator did not run then is explained, never
    re-sent. Returns the plan ids per outcome, and `cases`: finding_ref -> the
    case a dispatched validator opened for it."""
    import asyncio
    from harness import store
    out = {"bound": [], "dispatched": [], "not_dispatchable": [], "deferred": [],
           "cases": {}}
    if not plans:
        return out
    limit = dispatch_limit(getattr(orch, "config", {})) if max_dispatch is None else max_dispatch
    registry = getattr(orch, "validator_registry", None)
    # Every finding of a class rides one dispatch, so per-parameter follow-ups
    # of one class are each tested (the planner keeps one plan per class).
    by_class: dict[str, tuple[str, list[Finding]]] = {}
    for report in reports:
        for f in report.findings:
            by_class.setdefault(f.vulnerability_class, (report.agent, []))[1].append(f)

    def _ran(plan, names):
        wanted = {_canon(plan.finding_class), _canon(plan.category or "")} - {""}
        return next((vr for vr in validation_reports
                     if vr.validator in names and _canon(vr.finding_class) in wanted), None)

    dispatched = 0
    for plan in prioritize(plans):
        names = CAPABILITY_VALIDATORS.get(plan.capability, ())
        if not names:
            reason = (f"no harness validator implements {plan.capability}; "
                      f"needs the {plan.execution_plane} execution plane")
            if await asyncio.to_thread(store.mark_plan_not_dispatchable, plan.id, reason):
                out["not_dispatchable"].append(plan.id)
            continue
        hit = _ran(plan, names)
        if hit is not None:
            if await asyncio.to_thread(_record, plan, hit):
                out["bound"].append(plan.id)
            continue
        source = by_class.get(plan.finding_class)
        if source is None or registry is None:
            reason = "the plan's source finding is not part of this analysis"
            if await asyncio.to_thread(store.mark_plan_not_dispatchable, plan.id, reason):
                out["not_dispatchable"].append(plan.id)
            continue
        agent, findings = source
        if validated:
            reason = (f"{', '.join(names)} did not run for this finding: "
                      + _undispatchable_reason(registry, names, findings[0], exchange, agent))
            if await asyncio.to_thread(store.mark_plan_not_dispatchable, plan.id, reason):
                out["not_dispatchable"].append(plan.id)
            continue
        if dispatched >= limit or _budget_spent(run_context):
            # Left proposed on purpose: budget, not inability, stopped it.
            out["deferred"].append(plan.id)
            continue
        dispatched += 1
        new_reports, proofs = await orch._validate_findings(
            exchange, [AgentReport(agent=agent or plan.category or "", model="plan_dispatch",
                                   findings=findings)],
            run_context=run_context, only_validators=frozenset(names))
        validation_reports.extend(new_reports)
        for proof in proofs:
            if proof.get("finding_ref") and proof.get("case_id"):
                out["cases"].setdefault(proof["finding_ref"], proof["case_id"])
        hit = _ran(plan, names)
        if hit is not None:
            if await asyncio.to_thread(_record, plan, hit):
                out["dispatched"].append(plan.id)
            continue
        reason = _undispatchable_reason(registry, names, findings[0], exchange, agent)
        if await asyncio.to_thread(store.mark_plan_not_dispatchable, plan.id, reason):
            out["not_dispatchable"].append(plan.id)
    if any(out.values()):
        log.info("plan dispatch %s %s: bound %d, dispatched %d, not dispatchable %d, deferred %d",
                 exchange.method, exchange.url.split("?", 1)[0], len(out["bound"]),
                 len(out["dispatched"]), len(out["not_dispatchable"]), len(out["deferred"]))
    return out


# Injection class named inside a free-text class or summary. Ordered so the
# more specific token wins ("nosql injection" before "sql injection").
_INJECTION_TOKENS: tuple[tuple[str, re.Pattern], ...] = (
    ("nosql", re.compile(r"\bno-?sql\b", re.I)),
    ("sqli", re.compile(r"\bsql[\s_-]*injection\b|\bsqli\b", re.I)),
    ("command_injection", re.compile(r"\b(?:os\s+)?command[\s_-]*injection\b", re.I)),
    ("ssti", re.compile(r"\bssti\b|\btemplate[\s_-]*injection\b", re.I)),
    ("xss", re.compile(r"\bxss\b|\bcross[\s-]*site[\s-]*scripting\b", re.I)),
)

# Derived follow-ups stay hypotheses: capped well below actionable.
_FOLLOWUP_CONFIDENCE_CAP = 0.35


def injection_classes(finding: Finding) -> list[str]:
    """Injection classes the model named for this finding that its own class
    does not already route to."""
    own = canonicalize(finding.vulnerability_class or "")
    text = " ".join([finding.vulnerability_class or "", finding.summary or ""])
    found: list[str] = []
    for cls, rx in _INJECTION_TOKENS:
        if cls == own or cls in found or not rx.search(text):
            continue
        if cls == "sqli" and "nosql" in found:
            # "NoSQL injection" also matches the plain SQL-injection pattern.
            if not re.search(r"(?<!no)(?<!no-)\bsql[\s_-]*injection\b", text, re.I):
                continue
        found.append(cls)
    return found


def injection_followups(findings: list[Finding], exchange: HttpExchange) -> list[Finding]:
    """One derived finding per (named injection class, request parameter).

    Parameters come from the captured request itself (query first, then the
    JSON/form body), never from the model. A request with no parameter gets a
    single request-level follow-up, so the class is still planned."""
    from harness.validators.injection_targets import param_targets
    targets = param_targets(exchange)
    out: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for f in findings:
        for cls in injection_classes(f):
            for location, name in (targets or [("", "")]):
                key = (cls, location, name)
                if key in seen:
                    continue
                seen.add(key)
                where = f" parameter {name!r} ({location})" if name else " request"
                out.append(Finding(
                    vulnerability_class=cls,
                    confidence=min(float(f.confidence or 0.0), _FOLLOWUP_CONFIDENCE_CAP),
                    severity=f.severity or "medium",
                    summary=(f"{cls} follow-up on the{where}: the model named {cls} in "
                             f"{f.vulnerability_class!r}"),
                    evidence="", suggested_test=f.suggested_test or "", basis="derived",
                    parameter_location=location, parameter_name=name,
                    principal_id=getattr(f, "principal_id", "") or ""))
    return out
