from __future__ import annotations
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from harness.models import Finding, HttpExchange, TestPlan
from harness.categories import canonicalize, distinctive_token

# Review pt 6 (second pass): an agent routinely writes a human-readable label
# ("Verbose Error", "Stack Trace", "Missing CSRF Token") whose snake_case form
# IS a declared finding class, but lowercasing alone leaves the spaces in, so
# "verbose error" never matched "verbose_error". Collapse runs of whitespace,
# hyphens and slashes to a single underscore so the natural label reaches the
# validator that declares its snake_case class. canonicalize() stays strict and
# is unchanged -- this only adds a literal snake_case candidate.
_LABEL_SEP_RE = re.compile(r"[\s/\\-]+")


def _snake_label(raw: str) -> str:
    return _LABEL_SEP_RE.sub("_", raw).strip("_")


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
    # I04: operator guidance when a check cannot confirm automatically but the
    # shape stays worth a human look (e.g. CSRF). Never confirmation authority.
    manual_verification: str = ""


def _enclosing_run():
    """The entered RunContext enclosing this call, if any (I05)."""
    from harness.run_context import current_run_context
    return current_run_context()


class Validator(ABC):
    name: str = "base"
    finding_classes: set[str] = set()
    active: bool = False
    _bound_run = None

    @property
    def run_context(self):
        """I05: the run this validator sends under. An explicitly bound run wins;
        an unbound validator dispatched inside an entered run uses that run, so its
        plain-client fallback cannot escape the run's budget, scope, cancellation
        and TLS policy (the same rule as I03's GatedAsyncClient routing)."""
        if self._bound_run is not None:
            return self._bound_run
        return _enclosing_run()

    @run_context.setter
    def run_context(self, value) -> None:
        self._bound_run = value

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
        norm = _snake_label(raw)  # "verbose error" -> "verbose_error" (pt 6)
        category = canonicalize(finding.vulnerability_class)
        fcs = self.finding_classes
        if raw in fcs or norm in fcs or (category is not None and category in fcs):
            return True
        # Review pt 6 -- synonym/canonical spelling mismatch: a validator may
        # declare a SYNONYM in finding_classes (e.g. verbose_error lists
        # "information_disclosure") while the agent writes the CANONICAL class
        # ("info_disclosure"), or vice-versa. Compare on canonical identity so
        # the two spellings of the same class never silently fail to route.
        # The snake_case label is also compared here so a validator that only
        # declares a synonym still catches the spaced natural label.
        canon_fcs = {canonicalize(fc) or fc for fc in fcs}
        if (category is not None and category in canon_fcs) or norm in canon_fcs:
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
