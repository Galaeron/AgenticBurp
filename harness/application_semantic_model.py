"""Application Semantic Model (ASM) -- P2-1's data spine.

The engagement machinery (engagement_builder / worklist_investigator /
chain_linker / second_order) can link findings to capabilities, but it has NO
model of what the application is *for* -- its roles, business objects, value-
bearing workflows, and the client-trusted fields a human pentester reasons over
to build high-value chains ("this is checkout -> a price field is client-trusted
-> chain IDOR on the order object into a discount -> escalate to fulfilment").

This module is the STRUCTURE of that model. It is deliberately pure data +
serialization + one deterministic scorer (`business_impact_for`): no network, no
LLM, no import of the engagement/orchestrator machinery, so it is trivially
unit-tested and safe to serialize into state and the report.

Hard invariants (P2-1 design constraints -- enforced by tests):
  - The ASM is HYPOTHESES, not facts. Nothing here carries a `confirmed` flag,
    nothing here holds a validator-ready URL or command. It may only inform
    RE-RANKING and PROPOSE chains; confirmation stays with the deterministic
    legs + confirmation_gate.
  - Endpoints are recorded as `"METHOD /normalized/path"` KEYS (path templates,
    ids collapsed to `{id}`), never concrete URLs with live ids/values -- so the
    model itself is structure-only and safe to persist/transmit.

`BusinessContextAgent` (business_context_agent.py) BUILDS an instance of this
from an anonymized surface projection; `EngagementState.apply_semantic_model`
CONSUMES one to re-rank the worklist and surface proposed chains.
"""
from __future__ import annotations

import functools
import hashlib
from dataclasses import dataclass, field, asdict


@functools.lru_cache(maxsize=1)
def _normalizer():
    """The one path normalizer, borrowed from engagement so a key built here
    aligns with a SurfaceEndpoint's key (both collapse /orders/42 -> /orders/{id}).
    Lazily imported to keep this module free of an engagement import at load
    time; falls back to a trivial normalizer if engagement is unavailable."""
    try:
        from harness.engagement import normalize_path
        return normalize_path
    except Exception:  # pragma: no cover - engagement is always importable in the harness
        def _n(p: str) -> str:
            return (p or "/").split("?", 1)[0].split("#", 1)[0] or "/"
        return _n


def endpoint_key(method: str, path: str) -> str:
    """`"METHOD /normalized/path"` -- the stable key both this model and
    SurfaceEndpoint use, so membership tests line up regardless of which side
    built the key."""
    norm = _normalizer()
    return f"{(method or 'GET').upper()} {norm(path)}"


# --- the model's parts -------------------------------------------------------


@dataclass
class Role:
    """An apparent principal + a coarse privilege rank (higher = more
    privileged). Ranks order roles for hypothesis reasoning; they are not an
    authorization decision."""
    name: str
    privilege_rank: int = 0
    source: str = ""  # "seed" | "surface" | "openapi"


@dataclass
class BusinessObject:
    """A value-bearing domain object (order, invoice, user, cart) with the
    endpoints that read/write it and the id parameter NAMES it is addressed by."""
    name: str
    id_params: list = field(default_factory=list)     # param NAMES, never values
    read_endpoints: list = field(default_factory=list)   # "METHOD /path" keys
    write_endpoints: list = field(default_factory=list)
    object_scoped: bool = False  # any endpoint addresses a specific instance by id


@dataclass
class Workflow:
    """An ordered multi-step flow (add-to-cart -> checkout -> pay -> fulfil) and
    the endpoint keys that realise each stage, ordered by the canonical stage
    index -- so "checkout comes after cart" is explicit."""
    name: str
    category: str = ""                       # e.g. "commerce"
    steps: list = field(default_factory=list)   # ordered ["METHOD /path" keys]
    stages: list = field(default_factory=list)  # ordered stage labels, parallel to steps


@dataclass
class ValueFlow:
    """A client-supplied field the server may TRUST (price, quantity, role,
    is_admin, account_id). The single highest-signal business-logic lever."""
    param: str                                # the parameter NAME (never a value)
    kind: str = ""                            # "price" | "quantity" | "role" | "identifier" | "state"
    endpoints: list = field(default_factory=list)  # "METHOD /path" keys carrying it
    note: str = ""


@dataclass
class SensitiveSink:
    """An endpoint family whose misuse has real impact -- payment, PII export,
    admin/config, file store."""
    name: str
    category: str                             # "payment" | "pii_export" | "admin_config" | "file_store"
    endpoints: list = field(default_factory=list)


@dataclass
class ChainingHypothesis:
    """A RANKED, candidate chain linking a plausible weakness on object/workflow
    A to impact on sink B. A hypothesis, never a confirmation: it may only be
    PROPOSED to the operator / fed to the chain proposer, never marked confirmed
    and never handed to a validator as a send target.

    `id` is stable (host + source/target signature) so a ledger HYPOTHESIS event
    keyed on it lets a later proposed step be reconstructed to its origin."""
    id: str
    source: str                               # human-readable weakness ("IDOR on order")
    target: str                               # human-readable impact ("payment sink")
    rationale: str
    rank: float = 0.0                         # 0..1, higher = more promising
    classes: list = field(default_factory=list)     # vuln classes involved, e.g. ["idor", "payment"]
    endpoints: list = field(default_factory=list)   # "METHOD /path" keys involved
    evidence: list = field(default_factory=list)     # structure-only signals it rests on

    @staticmethod
    def make_id(host: str, source: str, target: str) -> str:
        raw = f"{host}|{source}|{target}".encode("utf-8", "ignore")
        return "bch:" + hashlib.sha1(raw).hexdigest()[:12]


# --- category weights for the re-rank scorer ---------------------------------
# Higher = more business impact. Tuned so a value-bearing checkout/payment
# endpoint clearly outranks a generic static page in fused_score() (whose other
# additive terms top out around +0.7), without ever resurrecting a dead/
# malformed endpoint (those stay multiplicatively demoted in fused_score()).
_SINK_WEIGHT = {"payment": 0.6, "admin_config": 0.55, "pii_export": 0.45, "file_store": 0.35}
_WORKFLOW_STEP_WEIGHT = 0.3
_VALUE_FLOW_WEIGHT = {"price": 0.45, "quantity": 0.35, "role": 0.5, "identifier": 0.3, "state": 0.3}
_HYPOTHESIS_ENDPOINT_WEIGHT = 0.3
_BUSINESS_SCORE_CAP = 1.5


@dataclass
class ApplicationSemanticModel:
    """The whole model for one host. Pure data: to_dict/from_dict round-trip and
    `business_impact_for` is the only behaviour (a deterministic sum)."""
    host: str = ""
    roles: list = field(default_factory=list)               # [Role]
    business_objects: list = field(default_factory=list)    # [BusinessObject]
    workflows: list = field(default_factory=list)           # [Workflow]
    value_flows: list = field(default_factory=list)         # [ValueFlow]
    sensitive_sinks: list = field(default_factory=list)     # [SensitiveSink]
    chaining_hypotheses: list = field(default_factory=list)  # [ChainingHypothesis]
    # Provenance/audit: whether raw (non-anonymized) input was used to build it.
    built_from_raw: bool = False

    def business_impact_for(self, method: str, path: str) -> tuple[float, list]:
        """The re-rank contribution for one endpoint + the reasons that drove it.

        Returns (score, reasons). ZERO with no reasons when the endpoint carries
        no business signal -- so applying an ASM never changes the RELATIVE order
        of endpoints it says nothing about, and NOT applying one (the negative
        control) leaves fused_score() completely unchanged."""
        key = endpoint_key(method, path)
        score = 0.0
        reasons: list = []

        for sink in self.sensitive_sinks:
            if key in sink.endpoints:
                w = _SINK_WEIGHT.get(sink.category, 0.3)
                score += w
                reasons.append(f"sensitive sink ({sink.category}) +{w:.2f}")
                break  # one sink category is enough; don't double-count families

        for wf in self.workflows:
            if key in wf.steps:
                score += _WORKFLOW_STEP_WEIGHT
                reasons.append(f"step in workflow '{wf.name}' +{_WORKFLOW_STEP_WEIGHT:.2f}")
                break

        seen_kinds: set = set()
        for vf in self.value_flows:
            if key in vf.endpoints and vf.kind not in seen_kinds:
                w = _VALUE_FLOW_WEIGHT.get(vf.kind, 0.3)
                score += w
                reasons.append(f"client-trusted '{vf.param}' ({vf.kind}) +{w:.2f}")
                seen_kinds.add(vf.kind)

        best_hyp = 0.0
        for hyp in self.chaining_hypotheses:
            if key in hyp.endpoints and hyp.rank > best_hyp:
                best_hyp = hyp.rank
        if best_hyp > 0:
            contrib = round(_HYPOTHESIS_ENDPOINT_WEIGHT * best_hyp, 4)
            score += contrib
            reasons.append(f"in a ranked chaining hypothesis (rank {best_hyp:.2f}) +{contrib:.2f}")

        score = min(score, _BUSINESS_SCORE_CAP)
        return round(score, 4), reasons

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "built_from_raw": self.built_from_raw,
            "roles": [asdict(r) for r in self.roles],
            "business_objects": [asdict(o) for o in self.business_objects],
            "workflows": [asdict(w) for w in self.workflows],
            "value_flows": [asdict(v) for v in self.value_flows],
            "sensitive_sinks": [asdict(s) for s in self.sensitive_sinks],
            "chaining_hypotheses": [asdict(h) for h in self.chaining_hypotheses],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ApplicationSemanticModel":
        d = d or {}
        return cls(
            host=d.get("host", ""),
            built_from_raw=bool(d.get("built_from_raw", False)),
            roles=[Role(**r) for r in d.get("roles", []) or []],
            business_objects=[BusinessObject(**o) for o in d.get("business_objects", []) or []],
            workflows=[Workflow(**w) for w in d.get("workflows", []) or []],
            value_flows=[ValueFlow(**v) for v in d.get("value_flows", []) or []],
            sensitive_sinks=[SensitiveSink(**s) for s in d.get("sensitive_sinks", []) or []],
            chaining_hypotheses=[ChainingHypothesis(**h) for h in d.get("chaining_hypotheses", []) or []],
        )

    def summary(self) -> dict:
        """Compact counts for a run summary / API surface."""
        return {
            "host": self.host,
            "roles": len(self.roles),
            "business_objects": len(self.business_objects),
            "workflows": len(self.workflows),
            "value_flows": len(self.value_flows),
            "sensitive_sinks": len(self.sensitive_sinks),
            "chaining_hypotheses": len(self.chaining_hypotheses),
        }
