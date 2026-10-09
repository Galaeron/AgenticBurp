from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from harness.models import Finding, HttpExchange, TestPlan
from harness.categories import canonicalize, distinctive_token


@dataclass
class ValidationResult:
    validator: str
    status: str  # confirmed | not_confirmed | skipped | error
    finding_class: str
    confidence: float = 0.0
    confirmed: bool = False
    summary: str = ""
    evidence: str = ""
    raw_output: str = ""
    command: list[str] = field(default_factory=list)
    # RA-7: set ONLY on a genuine control-held cross-identity reject (every
    # considered identity + anon baseline denied) -- distinguishes that from
    # an inconclusive not_confirmed observation (reached-but-unproven, or
    # ownership-authorized). Empty string means "not a control-held reject";
    # trailing + defaulted so all existing positional/keyword construction
    # of ValidationResult stays valid.
    control_outcome: str = ""


class Validator(ABC):
    name: str = "base"
    finding_classes: set[str] = set()
    active: bool = False

    def plan(self, finding: Finding, exchange: HttpExchange) -> TestPlan | None:
        """Return a declarative plan when this capability can be executed by Burp."""
        return None

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        # Same free-text-vs-exact-match problem as planner.py had: an LLM
        # writing "SQL Injection" instead of "sqli" must still match here.
        # Fall back to the raw lowercase string too, so a validator whose
        # finding_classes set happens to contain a phrase not yet in
        # categories.py's synonym table (e.g. "sql injection" itself)
        # still works during the transition.
        raw = finding.vulnerability_class.lower()
        category = canonicalize(finding.vulnerability_class)
        fcs = self.finding_classes
        if raw in fcs or (category is not None and category in fcs):
            return True
        # Review pt 6 -- synonym/canonical spelling mismatch: a validator may
        # declare a SYNONYM in finding_classes (e.g. verbose_error lists
        # "information_disclosure") while the agent writes the CANONICAL class
        # ("info_disclosure"), or vice-versa. Compare on canonical identity so
        # the two spellings of the same class never silently fail to route.
        canon_fcs = {canonicalize(fc) or fc for fc in fcs}
        if category is not None and category in canon_fcs:
            return True
        # Review pt 6 -- embedded-title token: the model often writes a
        # specific finding TITLE that embeds an unambiguous class token
        # ("Missing CSRF Token", "JWT None Algorithm") which canonicalize()
        # deliberately leaves unmapped. Route on that token only when it maps
        # to one of THIS validator's own classes -- never a global guess.
        if category is None:
            tok = distinctive_token(raw)
            if tok is not None and tok in canon_fcs:
                return True
        return False

    @abstractmethod
    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        raise NotImplementedError
