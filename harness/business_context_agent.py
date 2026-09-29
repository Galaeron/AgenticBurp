"""BusinessContextAgent -- P2-1: one bounded application-context planning pass.

Routing + detection elsewhere are per-exchange and class-shaped. This agent is
the opposite: ONE pass over the whole discovered surface that answers "what is
this application for" and writes an `ApplicationSemanticModel` (ASM) the
engagement loop re-ranks and proposes chains from. It is NOT a per-exchange
specialist -- it runs once per engagement, behind a default-off flag, and never
sends a request or confirms anything.

What it produces (all HYPOTHESES): apparent roles + privilege order, business
objects and the endpoints that read/write them, ordered value-bearing workflows,
client-trusted value flows (price/quantity/role/is_admin/id), sensitive sinks
(payment/PII/admin/file), and RANKED chaining hypotheses linking an object/
workflow weakness to a sink.

Design constraints (P2-1, enforced by tests):
  - STRUCTURE-ONLY, ANONYMIZED input by default (mirrors feature_projection.py):
    method / path template with ids collapsed to `{id}` / parameter NAMES /
    roles / response shape -- never raw bodies/values/ids. A richer projection
    that could carry raw content is built ONLY when `cloud_reasoning` is
    explicitly enabled (an off-host data-egress decision, like the existing
    cloud flags). The shipped deterministic core reasons purely over the
    anonymized projection, so it performs no egress at all.
  - The ASM is hypotheses, not facts: this module NEVER sets `confirmed`, NEVER
    produces a validator-ready URL/command, and produces ZERO live sends.
  - Every chaining hypothesis emits an evidence-ledger HYPOTHESIS event (P0-1)
    keyed on the hypothesis id, so a later proposed chain step is reconstructable
    to its originating hypothesis and the observed (structure-only) evidence.
  - Treat all response/body text as untrusted (P1-1): the deterministic core
    keys only off endpoint SHAPE and parameter NAMES, never off attacker-
    controllable response prose.

Deterministic and network/LLM-free, so it is unit-tested without a live model.
"""
from __future__ import annotations

import logging
import re

from harness.application_semantic_model import (
    ApplicationSemanticModel, Role, BusinessObject, Workflow, ValueFlow,
    SensitiveSink, ChainingHypothesis, endpoint_key,
)

log = logging.getLogger("harness.business_context_agent")


def enabled(config: dict | None) -> bool:
    """Whether the business-context pass is on. DEFAULT OFF."""
    return bool((config or {}).get("business_context", {}).get("enabled", False))


# --- vocabularies (names/shapes only; no response prose) ---------------------

# Coarse privilege ordering. Higher = more privileged. Unknown roles -> 1
# (a named identity that isn't clearly anonymous is at least a low-trust user).
_ROLE_RANK = {
    "anonymous": 0, "anon": 0, "guest": 0, "public": 0,
    "user": 1, "customer": 1, "member": 1, "buyer": 1, "derived": 1,
    "staff": 2, "support": 2, "editor": 2, "seller": 2, "vendor": 2,
    "manager": 3, "moderator": 3,
    "admin": 4, "administrator": 4,
    "superadmin": 5, "root": 5, "owner": 5,
}

# param NAME (substring, lowercased) -> value-flow kind. Order matters: the
# first matching entry wins, so more specific tokens precede generic ones.
_CLIENT_TRUSTED_PARAMS: tuple[tuple[str, str], ...] = (
    ("is_admin", "role"), ("isadmin", "role"), ("is_staff", "role"),
    ("role", "role"), ("privilege", "role"), ("permission", "role"),
    ("admin", "role"), ("superuser", "role"),
    ("price", "price"), ("amount", "price"), ("subtotal", "price"),
    ("total", "price"), ("cost", "price"), ("discount", "price"),
    ("coupon", "price"), ("voucher", "price"), ("promo", "price"),
    ("balance", "price"), ("credit", "price"), ("fee", "price"),
    ("quantity", "quantity"), ("qty", "quantity"), ("count", "quantity"),
    ("account_id", "identifier"), ("accountid", "identifier"),
    ("user_id", "identifier"), ("userid", "identifier"), ("uid", "identifier"),
    ("customer_id", "identifier"), ("owner_id", "identifier"),
    ("order_id", "identifier"), ("object_id", "identifier"),
    ("is_verified", "state"), ("verified", "state"), ("is_active", "state"),
    ("status", "state"), ("state", "state"), ("approved", "state"), ("enabled", "state"),
)

# path shape -> sensitive-sink category.
_SINK_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("payment", re.compile(r"(pay|payment|checkout|charge|refund|transfer|withdraw|deposit|billing|invoice|wallet)", re.I)),
    ("admin_config", re.compile(r"(admin|administrator|manage|management|config|configuration|settings|internal|console)", re.I)),
    ("pii_export", re.compile(r"(export|download|report|dump|users?|accounts?|customers?|profile)", re.I)),
    ("file_store", re.compile(r"(upload|attachment|document|media|files?)", re.I)),
)

# Ordered commerce-workflow stages: (stage label, path-shape regex). A workflow
# is emitted when >= 2 distinct stages are present, ordered by this index.
_WORKFLOW_STAGES: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("browse", re.compile(r"(products?|catalog|items?|shop|search|browse|listing)", re.I)),
    ("cart", re.compile(r"(cart|basket|bag)", re.I)),
    ("checkout", re.compile(r"(checkout)", re.I)),
    ("payment", re.compile(r"(pay|payment|charge)", re.I)),
    ("order", re.compile(r"(orders?|purchase|confirm)", re.I)),
    ("fulfil", re.compile(r"(fulfil|fulfill|ship|deliver|dispatch)", re.I)),
)

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Path segments that are structural, not the business noun.
_STRUCTURAL_SEG = re.compile(r"^(api|v\d+|rest|graphql|public|internal|app|web|www|index|home)$", re.I)
_ID_SEG = re.compile(r"^(\{id\}|\{[^}]+\})$")


def _role_rank(role: str) -> int:
    low = (role or "").lower()
    for token, rank in _ROLE_RANK.items():
        if token in low:
            return rank
    return 1  # a named-but-unrecognised identity is at least a low-trust user


def _value_flow_kind(param: str) -> str | None:
    low = (param or "").lower()
    for token, kind in _CLIENT_TRUSTED_PARAMS:
        if token in low:
            return kind
    return None


def _singular(noun: str) -> str:
    n = (noun or "").lower()
    if n.endswith("ies") and len(n) > 3:
        return n[:-3] + "y"
    if n.endswith("ses") and len(n) > 3:
        return n[:-2]
    if n.endswith("s") and not n.endswith("ss") and len(n) > 1:
        return n[:-1]
    return n


def _primary_noun(path: str) -> str | None:
    """The business object a path addresses -- the last non-structural,
    non-id segment (so /api/v1/orders/{id}/items -> 'item', /orders/{id} ->
    'order'). None for a bare '/' or an all-structural path."""
    segs = [s for s in (path or "").split("/") if s]
    noun = None
    for seg in segs:
        if _ID_SEG.match(seg) or _STRUCTURAL_SEG.match(seg):
            continue
        noun = seg
    return _singular(noun) if noun else None


class _ProjectedEndpoint:
    """The structure-only view of one endpoint the heuristics reason over.
    Holds NO raw values -- only method, path template, parameter NAMES,
    reachable roles, and object-scoping."""
    __slots__ = ("method", "path", "key", "param_names", "object_scoped", "reachable_roles", "is_write")

    def __init__(self, method, path, param_names, object_scoped, reachable_roles):
        self.method = (method or "GET").upper()
        self.path = path or "/"
        self.key = endpoint_key(self.method, self.path)
        self.param_names = param_names            # set[str] -- NAMES only
        self.object_scoped = bool(object_scoped)
        self.reachable_roles = list(reachable_roles or [])
        self.is_write = self.method in _WRITE_METHODS


def _acc(obj, name, default=None):
    """Read an attribute (SurfaceEndpoint / dataclass) or a dict key."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _template_param_names(template: dict | None) -> set[str]:
    """Parameter NAMES from a captured request template -- query keys + JSON/form
    body keys -- with all VALUES dropped. Robust to non-JSON bodies (names only,
    never a value)."""
    names: set[str] = set()
    if not template:
        return names
    from urllib.parse import parse_qsl
    query = template.get("query") or ""
    for k, _v in parse_qsl(query, keep_blank_values=True):
        if k:
            names.add(k)
    body = template.get("body") or ""
    stripped = body.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            import json
            data = json.loads(body)
            if isinstance(data, dict):
                names.update(str(k) for k in data.keys())
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                names.update(str(k) for k in data[0].keys())
        except Exception:
            pass
    else:
        # x-www-form-urlencoded or similar: names only.
        for k, _v in parse_qsl(body, keep_blank_values=True):
            if k:
                names.add(k)
    return names


class BusinessContextAgent:
    """Builds an ApplicationSemanticModel from an anonymized surface projection.

    Stateless apart from config + a ledger handle; safe to construct per
    engagement.
    """

    def __init__(self, config: dict | None = None, *, ledger=None):
        self.config = config or {}
        self._ledger = ledger  # None -> the process-wide default ledger via emit()

    # -- anonymized projection (the egress boundary) --------------------------

    def project_surface(self, surface, exchanges=None, *, cloud_reasoning: bool = False):
        """Project the surface + captured exchanges to the STRUCTURE-ONLY view
        the heuristics consume.

        By default (`cloud_reasoning=False`) the projection carries only method,
        path TEMPLATE (ids already collapsed to `{id}` by normalize_path), param
        NAMES, reachable roles and object-scoping -- never a raw body/value/id.
        This is the exact anonymization boundary feature_projection.py enforces
        for the cloud coordinator; the deterministic model needs nothing more, so
        it never has a reason to see raw content. `cloud_reasoning=True` is the
        only path allowed to attach raw values (for a future off-host reasoning
        step); the shipped core does not use it.
        """
        by_key: dict[str, _ProjectedEndpoint] = {}

        def _merge(method, path, param_names, object_scoped, reachable_roles):
            pe = _ProjectedEndpoint(method, path, set(param_names), object_scoped, reachable_roles)
            existing = by_key.get(pe.key)
            if existing is None:
                by_key[pe.key] = pe
            else:
                existing.param_names |= pe.param_names
                existing.object_scoped = existing.object_scoped or pe.object_scoped
                for r in pe.reachable_roles:
                    if r not in existing.reachable_roles:
                        existing.reachable_roles.append(r)

        for ep in surface or []:
            method = _acc(ep, "method", "GET")
            path = _acc(ep, "path", "/")
            template = _acc(ep, "template", None)
            names = _template_param_names(template)
            _merge(method, path, names, _acc(ep, "object_scoped", False), _acc(ep, "reachable_roles", []))

        # Captured exchanges: run each through feature_projection so ONLY names/
        # shape survive (values/ids/bodies are dropped there), then fold the
        # param names in. cloud_reasoning does not relax this default path.
        for ex in exchanges or []:
            try:
                from harness import feature_projection
                from harness.models import HttpExchange
                exo = ex if isinstance(ex, HttpExchange) else HttpExchange(**ex)
                proj = feature_projection.project_exchange(exo)
                names = set(proj.query_param_names) | set(proj.body_param_names)
                # normalize the path the same way SurfaceEndpoint keys are
                from harness.engagement import normalize_path
                _merge(exo.method, normalize_path(exo.url), names,
                       proj.has_resource_id, [])
            except Exception as e:
                log.debug("project_surface: skipping unprojectable exchange: %s", e)

        return list(by_key.values())

    # -- the build -----------------------------------------------------------

    def build_model(self, host, surface, exchanges=None, *, roles=None,
                    openapi=None, cloud_reasoning: bool = False) -> ApplicationSemanticModel:
        """Build the ASM for `host`. `surface` is a list of SurfaceEndpoint (or
        dicts); `exchanges` optional HttpExchange (or dicts); `roles` optional
        RoleSession list (or role-name strings). Deterministic; no send, no
        confirmation. Emits a HYPOTHESIS ledger event per chaining hypothesis."""
        projected = self.project_surface(surface, exchanges, cloud_reasoning=cloud_reasoning)
        asm = ApplicationSemanticModel(host=host or "", built_from_raw=bool(cloud_reasoning))

        asm.roles = self._infer_roles(projected, roles)
        asm.business_objects = self._infer_objects(projected)
        asm.workflows = self._infer_workflows(projected)
        asm.value_flows = self._infer_value_flows(projected)
        asm.sensitive_sinks = self._infer_sinks(projected)
        asm.chaining_hypotheses = self._infer_hypotheses(asm, projected)

        self._emit_hypotheses(asm)
        log.info("business_context_agent: %s -- %d roles, %d objects, %d workflows, "
                 "%d value-flows, %d sinks, %d hypotheses",
                 asm.host, len(asm.roles), len(asm.business_objects), len(asm.workflows),
                 len(asm.value_flows), len(asm.sensitive_sinks), len(asm.chaining_hypotheses))
        return asm

    def _infer_roles(self, projected, roles) -> list:
        names: dict[str, str] = {}  # name -> source
        for r in roles or []:
            name = r if isinstance(r, str) else (_acc(r, "role", None) or _acc(r, "name", None))
            if name:
                names.setdefault(str(name), "seed")
        for pe in projected:
            for r in pe.reachable_roles:
                if r:
                    names.setdefault(str(r), "surface")
        out = [Role(name=n, privilege_rank=_role_rank(n), source=src) for n, src in names.items()]
        out.sort(key=lambda r: (r.privilege_rank, r.name))
        return out

    def _infer_objects(self, projected) -> list:
        objs: dict[str, BusinessObject] = {}
        for pe in projected:
            noun = _primary_noun(pe.path)
            if not noun:
                continue
            o = objs.get(noun)
            if o is None:
                o = BusinessObject(name=noun)
                objs[noun] = o
            (o.write_endpoints if pe.is_write else o.read_endpoints).append(pe.key)
            if pe.object_scoped or "{id}" in pe.path:
                o.object_scoped = True
            for name in pe.param_names:
                if _value_flow_kind(name) == "identifier" and name not in o.id_params:
                    o.id_params.append(name)
        return list(objs.values())

    def _infer_workflows(self, projected) -> list:
        # stage index -> ordered list of endpoint keys realising it
        stage_hits: dict[int, list] = {}
        for pe in projected:
            for idx, (_label, rx) in enumerate(_WORKFLOW_STAGES):
                if rx.search(pe.path):
                    stage_hits.setdefault(idx, [])
                    if pe.key not in stage_hits[idx]:
                        stage_hits[idx].append(pe.key)
        present = sorted(stage_hits.keys())
        if len(present) < 2:
            return []
        steps: list = []
        stages: list = []
        for idx in present:
            label = _WORKFLOW_STAGES[idx][0]
            for key in stage_hits[idx]:
                steps.append(key)
                stages.append(label)
        return [Workflow(name="commerce", category="commerce", steps=steps, stages=stages)]

    def _infer_value_flows(self, projected) -> list:
        by_param: dict[str, ValueFlow] = {}
        for pe in projected:
            for name in pe.param_names:
                kind = _value_flow_kind(name)
                if not kind:
                    continue
                vf = by_param.get(name)
                if vf is None:
                    vf = ValueFlow(param=name, kind=kind,
                                   note="client-supplied field the server may trust")
                    by_param[name] = vf
                if pe.key not in vf.endpoints:
                    vf.endpoints.append(pe.key)
        # deterministic order: highest-signal kinds first, then name
        _kind_order = {"role": 0, "price": 1, "quantity": 2, "identifier": 3, "state": 4}
        return sorted(by_param.values(), key=lambda v: (_kind_order.get(v.kind, 9), v.param))

    def _infer_sinks(self, projected) -> list:
        by_cat: dict[str, SensitiveSink] = {}
        for pe in projected:
            for cat, rx in _SINK_PATTERNS:
                if rx.search(pe.path):
                    s = by_cat.get(cat)
                    if s is None:
                        s = SensitiveSink(name=cat, category=cat)
                        by_cat[cat] = s
                    if pe.key not in s.endpoints:
                        s.endpoints.append(pe.key)
                    break  # first (highest-impact) matching category wins per endpoint
        return list(by_cat.values())

    def _infer_hypotheses(self, asm: ApplicationSemanticModel, projected) -> list:
        hyps: list[ChainingHypothesis] = []
        low_trust_keys = {pe.key for pe in projected
                          if any(_role_rank(r) <= 1 for r in pe.reachable_roles)}

        def _add(source, target, rationale, rank, classes, endpoints, evidence):
            hid = ChainingHypothesis.make_id(asm.host, source, target)
            hyps.append(ChainingHypothesis(
                id=hid, source=source, target=target, rationale=rationale,
                rank=round(min(rank, 1.0), 3), classes=list(classes),
                endpoints=sorted(set(endpoints)), evidence=list(evidence)))

        # H1: an object addressed by id, plus a sensitive sink -> IDOR/BOLA into
        # that sink. The canonical "chain an object weakness into an impact".
        for obj in asm.business_objects:
            if not obj.object_scoped:
                continue
            obj_eps = obj.read_endpoints + obj.write_endpoints
            for sink in asm.sensitive_sinks:
                rank = 0.4
                ev = [f"object '{obj.name}' is addressed by id ({obj.id_params or '{id}'})",
                      f"sensitive {sink.category} sink present"]
                if any(k in low_trust_keys for k in obj_eps):
                    rank += 0.2
                    ev.append("a low-trust role reaches the object")
                if obj.write_endpoints:
                    rank += 0.1
                    ev.append("the object has write endpoints")
                _add(f"IDOR/BOLA on {obj.name}",
                     f"{sink.category} sink",
                     f"'{obj.name}' is object-scoped; if its id is not authorization-checked, an "
                     f"attacker may reach another principal's {obj.name} and pivot into the "
                     f"{sink.category} sink.",
                     rank, ["idor", sink.category], obj_eps + sink.endpoints, ev)

        # H2: a client-trusted price/quantity field on a workflow step -> value
        # tampering / business-logic manipulation.
        workflow_keys = {k for wf in asm.workflows for k in wf.steps}
        for vf in asm.value_flows:
            if vf.kind not in ("price", "quantity"):
                continue
            on_workflow = [k for k in vf.endpoints if k in workflow_keys]
            if not on_workflow:
                continue
            _add(f"client-trusted '{vf.param}' in a workflow",
                 "price/quantity manipulation",
                 f"'{vf.param}' is a client-supplied {vf.kind} field on a value-bearing workflow "
                 f"step; if the server trusts it, the order value can be manipulated.",
                 0.5, ["business_logic", "mass_assignment"], on_workflow,
                 [f"'{vf.param}' ({vf.kind}) on a workflow step"])

        # H3: a client-trusted role/state field on a write endpoint -> mass
        # assignment / privilege escalation.
        admin_sink_eps = [k for s in asm.sensitive_sinks if s.category == "admin_config"
                          for k in s.endpoints]
        write_keys = {pe.key for pe in projected if pe.is_write}
        for vf in asm.value_flows:
            if vf.kind not in ("role", "state"):
                continue
            on_write = [k for k in vf.endpoints if k in write_keys]
            if not on_write:
                continue
            _add(f"mass-assignment of '{vf.param}'",
                 "privilege escalation" + (" / admin_config sink" if admin_sink_eps else ""),
                 f"'{vf.param}' is a client-supplied {vf.kind} field accepted on a write endpoint; "
                 f"if it is mass-assignable, an attacker may escalate privilege.",
                 0.55, ["mass_assignment", "broken_access_control"],
                 on_write + admin_sink_eps, [f"'{vf.param}' ({vf.kind}) on a write endpoint"])

        hyps.sort(key=lambda h: (-h.rank, h.id))
        return hyps

    def _emit_hypotheses(self, asm: ApplicationSemanticModel) -> None:
        """One evidence-ledger HYPOTHESIS event per chaining hypothesis, keyed on
        the hypothesis id, so a later proposed chain step is reconstructable to
        its origin + the structure-only evidence it rests on (P0-1). Best-effort:
        a ledger hiccup must never break the planning pass."""
        try:
            from harness import evidence_ledger
        except Exception:  # pragma: no cover
            return
        prov = evidence_ledger.Provenance.capture(config=self.config,
                                                  prompt_version="business_context_agent/1")
        for hyp in asm.chaining_hypotheses:
            try:
                evidence_ledger.emit(
                    evidence_ledger.EventType.HYPOTHESIS, hyp.id,
                    f"business-context chain hypothesis: {hyp.source} -> {hyp.target} "
                    f"(rank {hyp.rank:.2f})"[:500],
                    data={
                        "kind": "business_context_chain_hypothesis",
                        "source": hyp.source, "target": hyp.target,
                        "classes": hyp.classes, "endpoints": hyp.endpoints,
                        "evidence": hyp.evidence, "rank": hyp.rank,
                        "host": asm.host, "confirmed": False,
                    },
                    provenance=prov, case_ref=hyp.id, ledger=self._ledger)
            except Exception as e:  # pragma: no cover
                log.debug("business_context_agent: ledger emit failed for %s: %s", hyp.id, e)
