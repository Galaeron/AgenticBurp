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
    # I04: operator guidance when a check cannot confirm automatically but the
    # shape stays worth a human look (e.g. CSRF). Never confirmation authority.
    manual_verification: str = ""
    # Ticket 6: the run-transport exchanges this verdict rests on. The
    # orchestrator copies them onto the case's ProofRecord; strict accounting
    # counts a vulnerability only when all three roles name distinct, case-bound,
    # successfully executed exchanges with intact evidence blobs. Empty on a
    # legacy result (its proof stays a candidate).
    baseline_artifact_id: str = ""
    attack_artifact_id: str = ""
    control_artifact_ids: tuple[str, ...] = ()

    def with_artifacts(self, *, baseline=None, attack=None, controls=()) -> "ValidationResult":
        """Name the sends behind this verdict; each is an ExecutionOutcome, a
        run-transport httpx.Response, an artifact id, or None. Returns self."""
        self.baseline_artifact_id = artifact_id_of(baseline)
        self.attack_artifact_id = artifact_id_of(attack)
        self.control_artifact_ids = tuple(i for i in map(artifact_id_of, controls) if i)
        return self


def artifact_id_of(sent) -> str:
    """The run's exchange artifact id behind one send: an ExecutionOutcome, an
    httpx.Response built by the run transport (GatedAsyncClient), a SentAnswer,
    or an id.
    "" for a send that never went through a run (plain client, Burp, fakes)."""
    if sent is None:
        return ""
    if isinstance(sent, str):
        return sent
    artifact_id = getattr(sent, "artifact_id", None)
    if isinstance(artifact_id, str):
        return artifact_id
    extensions = getattr(sent, "extensions", None)
    if isinstance(extensions, dict):
        return extensions.get("harness_artifact_id", "") or ""
    return ""


class SentAnswer(tuple):
    """A probe seam's plain tuple answer (e.g. (status, body)) that also carries
    the run's exchange artifact id. Unpacks exactly like the tuple, so a test
    stub returning a bare tuple keeps working (its artifact id is just "")."""
    artifact_id = ""

    def __new__(cls, values, artifact_id: str = ""):
        answer = super().__new__(cls, values)
        answer.artifact_id = artifact_id or ""
        return answer


def proof_artifact_kwargs(result) -> dict:
    """ProofRecord.from_validation_result keyword arguments for the exchanges a
    result names. Only a reached verdict (confirmed / not_confirmed) that names
    at least one exchange declares executed=True; anything else stays legacy."""
    if (getattr(result, "status", "") or "").lower() not in ("confirmed", "not_confirmed"):
        return {}
    baseline = getattr(result, "baseline_artifact_id", "") or ""
    attack = getattr(result, "attack_artifact_id", "") or ""
    controls = tuple(getattr(result, "control_artifact_ids", ()) or ())
    if not (baseline or attack or controls):
        return {}
    return {"executed": True, "baseline_artifact_id": baseline,
            "attack_artifact_id": attack, "control_artifact_ids": controls}


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
