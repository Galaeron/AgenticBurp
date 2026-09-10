"""
evidence.py -- case-bound structured proof (Astra T01).

The confirmation layer already produces a per-validator `ValidationResult`
(status + boolean + confidence + mostly free-text evidence) and a
`ValidationReport` compatibility view. What it lacks is a stable binding between
*which concrete test scenario* was run and *what was proved*, so:

  - two same-class hypotheses on the same endpoint both inherit one class-keyed
    confirmation (the remaining R28 gap), and
  - "confirmed" mixes a leg that actually executed a controlled comparison with a
    leg that merely errored, skipped, or was gate-blocked.

This module adds the missing records WITHOUT replacing the existing result types
(they stay as compatibility views during migration):

  - `TestCaseRef`  -- identifies ONE concrete scenario within a run: run + request
    template + check + principal + optional input location/name + optional
    workflow state. Its `case_id` is a deterministic hash of those parts, so a
    different parameter or principal is a different case (two same-class findings
    no longer share one proof), while the same scenario re-tested is the same case.
  - `ExchangeArtifact` -- a reference to one request/response actually sent, with
    its transport outcome and a redacted export view (credentials never live in an
    id or an export).
  - `ProofRecord` -- one attempt: the validator + version, the baseline/attack/
    control artifacts, the expected invariant, the observed result, and a `Verdict`
    that is honest about execution. A proof is immutable (frozen); an ERROR can
    never become a CONTROLLED_NEGATIVE, because you cannot mutate it and the
    constructor rejects an executed-verdict with `executed=False`.
  - `Verdict` -- confirmed | controlled_negative | inconclusive | blocked | error.
    A not-applicable capability is an *applicability* decision (coverage), never a
    negative security verdict, so it is deliberately NOT a Verdict here.

`ProofLedger` groups attempts by case and answers "the strongest proof for this
case," append-only: a later INCONCLUSIVE attempt never erases an earlier CONFIRMED
one. Persistence (store.py) mirrors these semantics in SQLite.

Issue identity is deliberately OUT of scope here: proof ids identify attempts, case
ids identify scenarios, and issue ids (Astra T06) are separate so retesting a case
never spawns a new issue. Pure/deterministic; no network, no model call.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum


def _short(*parts: object) -> str:
    """A stable 16-hex-char id from the given parts (order-significant)."""
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


class Verdict(str, Enum):
    """The outcome of one confirmation attempt, honest about execution.

    Maps onto the existing `ValidationResult.status` vocabulary (confirmed /
    not_confirmed / skipped / error) plus a gate BLOCKED state, so the rest of the
    harness keeps using that vocabulary while proofs record the richer meaning.
    """
    CONFIRMED = "confirmed"                     # a leg executed and proved the invariant
    CONTROLLED_NEGATIVE = "controlled_negative"  # a leg executed and the invariant held (no bug)
    INCONCLUSIVE = "inconclusive"               # no verdict produced (skipped / not run / unsupported)
    BLOCKED = "blocked"                         # the safety gate denied the send
    ERROR = "error"                             # the leg ran but failed (transport/exception)

    @classmethod
    def from_validation(cls, status: str, confirmed: bool, *, blocked: bool = False,
                        controlled: bool = False, executed: bool = False) -> "Verdict":
        """Classify a ValidationResult (status, confirmed) into a Verdict.

        An `error` status is ALWAYS `ERROR` and can never be read as a controlled
        negative -- a failed leg is not evidence that the boundary held."""
        if blocked:
            return cls.BLOCKED
        s = (status or "").lower()
        if confirmed and s == "confirmed":
            return cls.CONFIRMED
        if s == "error":
            return cls.ERROR
        if s == "not_confirmed":
            return cls.CONTROLLED_NEGATIVE if controlled and executed else cls.INCONCLUSIVE
        # "skipped", "", or anything else without a real verdict.
        return cls.INCONCLUSIVE

    def rank(self) -> int:
        """Strength ordering for best-proof selection (higher = stronger)."""
        return {
            Verdict.CONFIRMED: 4,
            Verdict.CONTROLLED_NEGATIVE: 3,
            Verdict.INCONCLUSIVE: 1,
            Verdict.BLOCKED: 1,
            Verdict.ERROR: 0,
        }[self]


# Verdicts that assert a leg actually executed its comparison. Constructing one of
# these with executed=False is a contradiction the ProofRecord constructor rejects.
_EXECUTED_VERDICTS = frozenset({Verdict.CONFIRMED, Verdict.CONTROLLED_NEGATIVE})


@dataclass(frozen=True)
class TestCaseRef:
    """A reference to one concrete test scenario within a run.

    `case_id` is derived from the identity-bearing fields, so it is stable across
    re-tests of the same scenario and distinct across parameters/principals. Empty
    optional fields collapse to the endpoint/parameter-agnostic case (R26 fills the
    input location/name later; T07 fills workflow_state_id)."""
    run_id: str
    request_template_id: str
    check_id: str
    principal_id: str = ""
    parameter_location: str = ""   # "query" | "body_json" | "header" | ... ("" = whole request)
    parameter_name: str = ""       # param name or JSON pointer
    workflow_state_id: str = ""
    finding_ref: str = ""
    case_id: str = ""

    def __post_init__(self) -> None:
        if not self.case_id:
            object.__setattr__(self, "case_id", self.recompute_id())

    def recompute_id(self) -> str:
        parts = (self.run_id, self.request_template_id, self.check_id,
                 self.principal_id, self.parameter_location, self.parameter_name,
                 self.workflow_state_id)
        # Old persisted cases predate finding_ref; retain their original hash so
        # additive migration does not make their case_id look forged.
        return _short(*parts, self.finding_ref) if self.finding_ref else _short(*parts)

    @property
    def consistent(self) -> bool:
        """Whether case_id matches its identity-bearing fields (a forged/unknown
        case ref -- e.g. a proof pointing at a case that was never built -- fails
        this and is rejected by the store)."""
        return bool(self.run_id) and bool(self.check_id) and self.case_id == self.recompute_id()

    @classmethod
    def make(cls, *, run_id: str, request_template_id: str, check_id: str,
             principal_id: str = "", parameter_location: str = "", parameter_name: str = "",
             workflow_state_id: str = "", finding_ref: str = "") -> "TestCaseRef":
        return cls(run_id=run_id, request_template_id=request_template_id, check_id=check_id,
                   principal_id=principal_id, parameter_location=parameter_location,
                   parameter_name=parameter_name, workflow_state_id=workflow_state_id,
                   finding_ref=finding_ref)

    def to_dict(self) -> dict:
        return {"run_id": self.run_id, "request_template_id": self.request_template_id,
                "check_id": self.check_id, "principal_id": self.principal_id,
                "parameter_location": self.parameter_location, "parameter_name": self.parameter_name,
                "workflow_state_id": self.workflow_state_id, "finding_ref": self.finding_ref,
                "case_id": self.case_id}

    @classmethod
    def from_dict(cls, d: dict) -> "TestCaseRef":
        return cls(run_id=d.get("run_id", ""), request_template_id=d.get("request_template_id", ""),
                   check_id=d.get("check_id", ""), principal_id=d.get("principal_id", ""),
                   parameter_location=d.get("parameter_location", ""),
                   parameter_name=d.get("parameter_name", ""),
                   workflow_state_id=d.get("workflow_state_id", ""),
                   finding_ref=d.get("finding_ref", ""),
                   case_id=d.get("case_id", ""))


@dataclass(frozen=True)
class ExchangeArtifact:
    """A reference to one request/response actually sent during a proof attempt.

    Raw local-replay references are kept distinct from the redacted export view: a
    reader of an export never needs (and never sees) live credentials, and the
    artifact id is a hash of non-secret coordinates, never of a header value."""
    artifact_id: str
    request_ref: str = ""          # pointer/hash into a raw exchange store (not the bytes)
    response_ref: str = ""
    actual_destination: str = ""   # the origin actually hit (post-redirect), for scope audit
    transport_outcome: str = ""    # "ok" | "blocked" | "timeout" | "error:<detail>"
    session_ref: str = ""          # reference to the session used (never the cookie value)
    timestamp: float = 0.0

    @classmethod
    def make(cls, *, request_ref: str = "", response_ref: str = "", actual_destination: str = "",
             transport_outcome: str = "ok", session_ref: str = "",
             timestamp: float | None = None) -> "ExchangeArtifact":
        ts = time.time() if timestamp is None else timestamp
        aid = _short(request_ref, response_ref, actual_destination, session_ref, ts)
        return cls(artifact_id=aid, request_ref=request_ref, response_ref=response_ref,
                   actual_destination=actual_destination, transport_outcome=transport_outcome,
                   session_ref=session_ref, timestamp=ts)

    def redacted_view(self) -> dict:
        """The export-safe view: coordinates + outcome, never raw refs/session."""
        return {"artifact_id": self.artifact_id, "actual_destination": self.actual_destination,
                "transport_outcome": self.transport_outcome, "timestamp": self.timestamp}

    def to_dict(self) -> dict:
        return {"artifact_id": self.artifact_id, "request_ref": self.request_ref,
                "response_ref": self.response_ref, "actual_destination": self.actual_destination,
                "transport_outcome": self.transport_outcome, "session_ref": self.session_ref,
                "timestamp": self.timestamp}

    @classmethod
    def from_dict(cls, d: dict) -> "ExchangeArtifact":
        return cls(artifact_id=d.get("artifact_id", ""), request_ref=d.get("request_ref", ""),
                   response_ref=d.get("response_ref", ""),
                   actual_destination=d.get("actual_destination", ""),
                   transport_outcome=d.get("transport_outcome", ""),
                   session_ref=d.get("session_ref", ""), timestamp=d.get("timestamp", 0.0))


@dataclass(frozen=True)
class ProofRecord:
    """One immutable confirmation attempt bound to a concrete case.

    Immutability is the point: a proof cannot be relabelled after the fact, so an
    ERROR can never become a CONTROLLED_NEGATIVE, and a confirmed proof cannot be
    silently downgraded. `executed` records whether the leg actually sent its
    probe; an executed-verdict (confirmed/controlled_negative) with executed=False
    is a contradiction the constructor rejects.

    `legacy=True` marks a confirmation that predates this schema: it is retained
    with explicit provenance and NO fabricated baseline/attack/control artifacts --
    the review's rule that a legacy unstructured result must not acquire a
    fabricated proof, and an existing confirmed record must not be downgraded merely
    because it is old."""
    proof_id: str
    case: TestCaseRef
    validator: str
    verdict: Verdict
    validator_version: str = ""
    baseline_artifact_id: str = ""
    attack_artifact_id: str = ""
    control_artifact_ids: tuple[str, ...] = ()
    expected_invariant: str = ""
    observed_result: str = ""
    limitation: str = ""
    executed: bool = False
    legacy: bool = False
    created_at: float = 0.0

    def __post_init__(self) -> None:
        if isinstance(self.verdict, str) and not isinstance(self.verdict, Verdict):
            object.__setattr__(self, "verdict", Verdict(self.verdict))
        if self.verdict in _EXECUTED_VERDICTS and not self.executed:
            raise ValueError(
                f"verdict {self.verdict.value!r} asserts an executed comparison but "
                f"executed=False -- a non-executed leg cannot confirm or controlled-negate")
        if self.verdict == Verdict.CONTROLLED_NEGATIVE and not self.control_artifact_ids:
            raise ValueError(
                "controlled_negative requires control artifact references; a bare "
                "not_confirmed observation is inconclusive")
        if not self.proof_id:
            object.__setattr__(self, "proof_id", uuid.uuid4().hex)
        if not self.created_at:
            object.__setattr__(self, "created_at", time.time())

    @property
    def confirmed(self) -> bool:
        return self.verdict == Verdict.CONFIRMED

    @classmethod
    def from_validation_result(cls, *, case: TestCaseRef, validator: str, status: str,
                               confirmed: bool, validator_version: str = "",
                               observed_result: str = "", expected_invariant: str = "",
                               limitation: str = "", blocked: bool = False,
                               executed: bool | None = None, controlled: bool = False,
                               baseline_artifact_id: str = "", attack_artifact_id: str = "",
                               control_artifact_ids: tuple[str, ...] = ()) -> "ProofRecord":
        """Build a proof from a validator compatibility result.

        Legacy validators did not report whether the comparison and its controls
        actually executed.  Their bare ``not_confirmed`` therefore remains
        inconclusive.  A controlled negative requires an explicit ``executed=True``
        contract *and* at least one control artifact.  Artifact-free results remain
        readable, but are labelled legacy/unstructured instead of being presented as
        migrated structured proof.
        """
        control_artifact_ids = tuple(control_artifact_ids)
        has_artifacts = bool(baseline_artifact_id or attack_artifact_id or control_artifact_ids)
        explicit_execution = executed is True
        controlled_negative = controlled and explicit_execution and bool(control_artifact_ids)
        verdict = Verdict.from_validation(
            status, confirmed, blocked=blocked,
            controlled=controlled_negative, executed=explicit_execution,
        )
        # Confirmed legacy results are retained rather than downgraded merely because
        # the old validator could not emit the new execution/artifact contract.
        record_executed = explicit_execution or (
            not blocked and confirmed and (status or "").lower() == "confirmed"
        )
        legacy = not has_artifacts
        if legacy:
            legacy_note = "legacy/unstructured result: no resolvable exchange artifacts were captured"
            limitation = f"{limitation}; {legacy_note}" if limitation else legacy_note
        return cls(proof_id="", case=case, validator=validator, verdict=verdict,
                   validator_version=validator_version, observed_result=observed_result,
                   expected_invariant=expected_invariant, limitation=limitation,
                   baseline_artifact_id=baseline_artifact_id, attack_artifact_id=attack_artifact_id,
                   control_artifact_ids=control_artifact_ids, executed=record_executed,
                   legacy=legacy)

    @classmethod
    def legacy_confirmed(cls, *, case: TestCaseRef, validator: str, observed_result: str = "",
                         validator_version: str = "") -> "ProofRecord":
        """Retain a pre-schema confirmation with explicit legacy provenance and no
        fabricated artifacts. Used by the migration so an old confirmed record is
        neither dropped nor dressed up as a structured proof it never had."""
        return cls(proof_id="", case=case, validator=validator, verdict=Verdict.CONFIRMED,
                   validator_version=validator_version, observed_result=observed_result,
                   expected_invariant="", executed=True, legacy=True,
                   limitation="legacy pre-schema confirmation: structured baseline/attack/"
                              "control artifacts were not captured under the proof contract")

    def to_dict(self) -> dict:
        return {"proof_id": self.proof_id, "case": self.case.to_dict(), "validator": self.validator,
                "verdict": self.verdict.value, "validator_version": self.validator_version,
                "baseline_artifact_id": self.baseline_artifact_id,
                "attack_artifact_id": self.attack_artifact_id,
                "control_artifact_ids": list(self.control_artifact_ids),
                "expected_invariant": self.expected_invariant, "observed_result": self.observed_result,
                "limitation": self.limitation, "executed": self.executed, "legacy": self.legacy,
                "created_at": self.created_at}

    @classmethod
    def from_dict(cls, d: dict) -> "ProofRecord":
        return cls(proof_id=d.get("proof_id", ""), case=TestCaseRef.from_dict(d.get("case", {}) or {}),
                   validator=d.get("validator", ""), verdict=Verdict(d.get("verdict", "inconclusive")),
                   validator_version=d.get("validator_version", ""),
                   baseline_artifact_id=d.get("baseline_artifact_id", ""),
                   attack_artifact_id=d.get("attack_artifact_id", ""),
                   control_artifact_ids=tuple(d.get("control_artifact_ids", []) or []),
                   expected_invariant=d.get("expected_invariant", ""),
                   observed_result=d.get("observed_result", ""), limitation=d.get("limitation", ""),
                   executed=bool(d.get("executed", False)), legacy=bool(d.get("legacy", False)),
                   created_at=d.get("created_at", 0.0))


class ProofLedger:
    """In-memory, append-only collection of proofs grouped by case.

    `best_proof` returns the strongest attempt for a case; a later weaker attempt
    (e.g. a skipped re-run) never erases a stronger earlier one. Rejects a proof
    whose case ref is inconsistent (a forged/unknown case)."""

    def __init__(self) -> None:
        self._by_case: dict[str, list[ProofRecord]] = {}

    def record(self, proof: ProofRecord) -> ProofRecord:
        if not proof.case.consistent:
            raise ValueError(f"proof references an unknown/forged case {proof.case.case_id!r}")
        self._by_case.setdefault(proof.case.case_id, []).append(proof)
        return proof

    def proofs_for(self, case_id: str) -> list[ProofRecord]:
        return list(self._by_case.get(case_id, ()))

    def best_proof(self, case_id: str) -> ProofRecord | None:
        proofs = self._by_case.get(case_id)
        if not proofs:
            return None
        # Strongest verdict wins; ties break to the most recent attempt.
        return max(proofs, key=lambda p: (p.verdict.rank(), p.created_at))

    def all(self) -> list[ProofRecord]:
        return [p for proofs in self._by_case.values() for p in proofs]

    def to_dicts(self) -> list[dict]:
        return [p.to_dict() for p in self.all()]
