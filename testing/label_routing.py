"""Phase 2.1 -- does a model's finding label route to any validator (by class)?

The miss being measured: the model emits a vulnerability_class in free-form
wording ("MASS ASSIGNMENT / EXCESSIVE DATA BINDING", "Broken Access Control"),
while validators route by canonical class. A label that canonicalizes to nothing
any validator declares reaches NO validator and the finding is silently dropped
-- not for want of a validator, but for want of matching vocabulary. That is the
loss Phase 2.2 (constrain the label set + route by agent) sets out to remove.

``routes_to_validator(label)`` uses the harness's OWN routing: the base
``Validator.applies`` class gate (canonicalize + raw + distinctive_token against
each registered validator's finding_classes), bypassing subclass shape checks so
this is a pure LABEL/vocabulary question, plus the access-control markers the
cross-identity validator auto-arms on. It therefore tracks the real routing: when
Phase 2.2 changes the vocabulary / routing, this predicate and the miss rate move
with it, which is what makes the committed baseline a regression ratchet.
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
