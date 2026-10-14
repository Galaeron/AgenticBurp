"""Phase 2.1 -- does a model's finding label route to any validator (by class)?

The miss being measured: the model emits a vulnerability_class in free-form
wording ("MASS ASSIGNMENT / EXCESSIVE DATA BINDING", "Broken Access Control"),
while validators route by canonical class. This measures compatibility with
declared class vocabulary, not observed production dispatch or discarded
findings. Unsupported classes and descriptive observations may also miss.

``routes_to_validator(label)`` uses the harness's OWN routing: the base
``Validator.applies`` class gate (canonicalize + raw + distinctive_token against
each registered validator's finding_classes), bypassing subclass shape checks so
this is a pure LABEL/vocabulary question, plus the access-control markers the
cross-identity validator auto-arms on. Shape, scope, active-mode and identity
requirements must be checked separately through the production caller. A future
agent-aware route needs its own caller-level coverage; this predicate does not
automatically measure that additional dispatch path.
"""
from __future__ import annotations

from functools import lru_cache

from harness.access_control_gate import _is_access_control_class
from harness.models import Finding, HttpExchange
from harness.validators.base import Validator
from harness.validators.registry import ValidatorRegistry

# The base class gate ignores the exchange entirely (see validators/base.py), so a
# single throwaway exchange is enough -- routing here is purely about the label.
_DUMMY_EXCHANGE = HttpExchange(url="https://route.test/x", method="GET",
                               request_headers={}, request_body="")


@lru_cache(maxsize=1)
def _validators() -> tuple:
    """The validator set a standard active engagement arms (enabled + active)."""
    reg = ValidatorRegistry({"validators": {"enabled": True, "active_enabled": True}})
    return tuple(reg.validators.values())


def _finding(label: str) -> Finding:
    return Finding(vulnerability_class=label, confidence=0.5, severity="low",
                   summary="", evidence="", suggested_test="", basis="derived")


def routes_to_validator(label: str) -> bool:
    """True if `label` reaches at least one validator by class.

    Access-control wording is handled by the cross-identity validator's markers;
    everything else by the base Validator class gate against each registered
    validator's finding_classes. Called via Validator.applies(v, ...) so a
    validator's own shape-based applies() override does not mask the pure
    class-routing question.
    """
    if _is_access_control_class(label):
        return True
    finding = _finding(label)
    return any(Validator.applies(v, finding, _DUMMY_EXCHANGE) for v in _validators())


def routes_by_agent(agent: str) -> bool:
    """True if a finding's PRODUCING AGENT maps to a validator.

    AgentReport.agent is set programmatically by each specialist agent (never by
    model output) and matches categories.CANONICAL_CATEGORIES, so it is the
    reliable routing signal the free-text label is not. An agent routes exactly
    when its canonical category reaches a validator -- the same predicate as the
    label, applied to the agent name. Detection/recon agents with no confirming
    validator (anomaly, ai_security, chain_detector, ...) correctly do NOT route:
    their findings are observations, not confirmable hypotheses.
    """
    return routes_to_validator(agent)


def classify_findings(pairs) -> dict:
    """Agent-aware routing study over (agent, label) finding pairs.

    Compares three strategies on the SAME real findings:
      - label only   -- today's dispatch keys off vulnerability_class,
      - agent only    -- route by the reliable producing agent,
      - combined      -- label OR agent (what Phase 2.2 implements: fall back to
                         the agent when the model's wording does not route).
    Returns occurrence-weighted miss rates for each, plus the residual agents
    whose findings still reach nothing under the combined route. This is a
    vocabulary/target study, NOT a measurement of production dispatch (see the
    module docstring) -- a caller-level test must establish production separately.
    """
    from collections import Counter
    pairs = [(a or "", l or "") for a, l in pairs]
    n = len(pairs)
    label_route = {l: routes_to_validator(l) for _, l in pairs}
    agent_route = {a: routes_by_agent(a) for a, _ in pairs}
    label_miss = sum(1 for _, l in pairs if not label_route[l])
    agent_miss = sum(1 for a, _ in pairs if not agent_route[a])
    combined_miss = sum(1 for a, l in pairs if not (label_route[l] or agent_route[a]))
    residual = Counter(a for a, l in pairs if not (label_route[l] or agent_route[a]))

    def rate(m):
        return round(m / n, 4) if n else 0.0

    return {
        "total_findings": n,
        "label_miss": label_miss, "label_miss_rate": rate(label_miss),
        "agent_miss": agent_miss, "agent_miss_rate": rate(agent_miss),
        "combined_miss": combined_miss, "combined_miss_rate": rate(combined_miss),
        "residual_unrouted_agents": dict(residual.most_common()),
    }


def classify(labels) -> dict:
    """Routing summary over a label frequency map {label: count}.

    Returns distinct- and occurrence-weighted miss rates plus the sorted list of
    missing labels, so the baseline fixture records both "how much of the
    vocabulary is unroutable" and "how many findings that costs".
    """
    counts = dict(labels)
    distinct = sorted(counts)
    missing = sorted(l for l in distinct if not routes_to_validator(l))
    total_findings = sum(counts.values())
    missed_findings = sum(counts[l] for l in missing)
    return {
        "distinct_labels": len(distinct),
        "distinct_missing": len(missing),
        "distinct_miss_rate": round(len(missing) / len(distinct), 4) if distinct else 0.0,
        "total_findings": total_findings,
        "findings_missed": missed_findings,
        "weighted_miss_rate": round(missed_findings / total_findings, 4) if total_findings else 0.0,
        "missing_labels": missing,
    }
