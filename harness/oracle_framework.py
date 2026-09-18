"""
Deterministic verification oracle framework (precision item #1).

The single sqlmap validator already models the pattern we want everywhere: a
probe that reproduces the bug, plus an internal negative control that must stay
clean. This module GENERALISES that into a per-class oracle registry so any
confirmation leg (`validators/*`) can be promoted from "a leg said yes once" to
"an oracle PROVED it" -- reproduced N-of-N and paired with a controlled negative
that came back clean on a safe input.

The problem it attacks is the project's measured weakness: precision. A finding
whose leg confirmed it a single time is not the same as a finding whose leg
confirmed it three times running AND declined to fire on a benign variant of the
same request. The former is a *candidate*; only the latter is *verified*. Flaky
one-off confirmations (collaborator-timing luck, an sqlmap boolean that happened
to differ once) are exactly the false positives that inflate the FP rate, and an
N-of-N gate with a negative control is what filters them.

Design:

  * `Oracle` wraps one `Validator` plus an optional `negative_control` builder.
    - `reproduce()` runs `validate()` `n_required` times; a reproduction passes
      only when EVERY run confirms (N-of-N, not best-of-N).
    - `negative_control` (when available) builds a benign variant of the exchange
      the same probe is run against; the oracle PASSES the control only when the
      probe declines to confirm on it. No builder for the class -> the control is
      "unavailable", and the finding can reach at most `candidate` -- never
      `verified` -- because we cannot rule out a probe that confirms on anything.
  * `run()` returns a `ProofCapsule`: the full reproduction + control record, an
    auditable artifact (item #10's fix-verifier and item #2's report both read it).
  * `OracleRegistry.oracle_for()` picks the oracle for a finding/exchange from a
    `ValidatorRegistry`, reusing the exact validator instances the graph loop uses.

Purity/safety: this module SENDS live probes (through the validators, which are
scope-gated and safety-gated exactly as before) only when a caller invokes it.
Nothing here runs by default; `orchestrator`/`engagement` call it behind the
`oracle.enabled` config flag (default off), matching how every other active leg is
armed. The dataclasses and the state derivation are pure and hermetically tested.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from harness.categories import canonicalize
from harness.models import Finding, HttpExchange
from harness.validators.base import Validator, ValidationResult

log = logging.getLogger("harness.oracle_framework")

# Finding verification states surfaced to the operator (item #2). Deliberately
# ONLY two: an oracle either proved the finding to the N-of-N + negative-control
# standard (VERIFIED) or it did not (CANDIDATE). This is a stricter, orthogonal
# axis to confirmation_gate's CONFIRMED/SUSPECTED/LEAD lifecycle: a finding can be
# `confirmed=True` (a leg fired once) yet still only a CANDIDATE here until an
# oracle reproduces it. VERIFIED is the higher bar.
STATE_VERIFIED = "verified"
STATE_CANDIDATE = "candidate"

# A builder takes the original (vulnerable) exchange and returns a benign variant
# the probe should NOT confirm on -- or None when it cannot construct one for this
# specific exchange (e.g. the injectable parameter isn't present), which the oracle
# treats the same as "no builder registered": control unavailable.
NegativeControlBuilder = Callable[[HttpExchange], Optional[HttpExchange]]


@dataclass
class ProofCapsule:
    """Auditable record of one oracle run. Pure data -- no behaviour."""
    validator: str
    finding_class: str
    n_required: int
    n_confirmed: int
    reproduced: bool                      # confirmed on EVERY reproduction attempt
    negative_control_available: bool
    negative_control_clean: bool          # probe declined to confirm on the benign variant
    verified: bool                        # reproduced AND (control clean OR ... see below)
    # Q03/Q11: a non-reproduction is only a CLEAN NEGATIVE when the probe actually
    # EXECUTED and returned not_confirmed. A skipped/errored/blocked probe is
    # INCONCLUSIVE -- it must never be counted as a clean negative (that would let a
    # target that was merely unreachable read as "fixed"). True only when at least
    # one reproduction attempt ran to a not_confirmed verdict and none errored/skipped.
    reproduction_clean_negative: bool = False
    reason: str = ""
    reproductions: list[ValidationResult] = field(default_factory=list)
    negative_control_result: Optional[ValidationResult] = None
    created_at: float = field(default_factory=time.time)

    def capsule_id(self) -> str:
        """Stable id over the decisive facts of this capsule (not the timestamp),
        so re-running an identical proof yields the same id -- what the fix-verifier
        (item #10) keys a regression comparison on."""
        canon = canonicalize(self.finding_class) or (self.finding_class or "").lower()
        return hashlib.sha256("\x1f".join([
            self.validator or "",
            canon,
            str(self.n_required),
            str(self.n_confirmed),
            "1" if self.reproduced else "0",
            "1" if self.negative_control_available else "0",
            "1" if self.negative_control_clean else "0",
            "1" if self.verified else "0",
        ]).encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "capsule_id": self.capsule_id(),
            "validator": self.validator,
            "finding_class": self.finding_class,
            "n_required": self.n_required,
            "n_confirmed": self.n_confirmed,
            "reproduced": self.reproduced,
            "negative_control_available": self.negative_control_available,
            "negative_control_clean": self.negative_control_clean,
            "verified": self.verified,
            "reproduction_clean_negative": self.reproduction_clean_negative,
            "reason": self.reason,
        }


def _is_confirmed(result: ValidationResult | None) -> bool:
    return bool(result is not None and result.confirmed and result.status == "confirmed")


def _clean_negative(results: list[ValidationResult]) -> bool:
    """A reproduction run is a CLEAN executed negative only when the probe actually
    ran to a not_confirmed verdict on every attempt (no skipped/error/blocked). An
    unreachable/errored probe is INCONCLUSIVE, not a negative (Q03/Q11)."""
    if not results:
        return False
    statuses = [(r.status or "").lower() for r in results]
    if any(s in ("skipped", "error", "blocked") for s in statuses):
        return False
    return all(s == "not_confirmed" for s in statuses)


class Oracle:
    """A per-class verification oracle: one validator + an optional negative control."""

    def __init__(
        self,
        validator: Validator,
        *,
        negative_control: NegativeControlBuilder | None = None,
        n_required: int = 3,
        require_negative_control: bool = True,
    ):
        if n_required < 1:
            raise ValueError("n_required must be >= 1")
        self.validator = validator
        self.negative_control = negative_control
        self.n_required = int(n_required)
        # When True (the default), a finding can only be VERIFIED if a negative
        # control was available AND came back clean. When False, a reproduced
        # finding is verified even without a control (used for classes whose leg
        # is inherently self-controlling, e.g. an OOB collaborator hit -- a
        # callback carrying our unique token cannot be a benign coincidence).
        self.require_negative_control = bool(require_negative_control)

    @property
    def name(self) -> str:
        return getattr(self.validator, "name", "oracle")

    async def reproduce(
        self, finding: Finding, exchange: HttpExchange
    ) -> tuple[bool, list[ValidationResult]]:
        """Run the probe n_required times. Reproduction passes only N-of-N."""
        results: list[ValidationResult] = []
        for _ in range(self.n_required):
            res = await self.validator.validate(finding, exchange)
            results.append(res)
            if not _is_confirmed(res):
                # A single miss breaks N-of-N -- stop early, it can't reproduce.
                return False, results
        return True, results

    async def run_negative_control(
        self, finding: Finding, exchange: HttpExchange
    ) -> tuple[bool, bool, Optional[ValidationResult]]:
        """Returns (available, clean, result). `clean` is True only when the probe
        declined to confirm on the benign variant. Unavailable -> (False, False, None)."""
        if self.negative_control is None:
            return False, False, None
        benign = self.negative_control(exchange)
        if benign is None:
            return False, False, None
        res = await self.validator.validate(finding, benign)
        return True, (not _is_confirmed(res)), res

    async def run(self, finding: Finding, exchange: HttpExchange) -> ProofCapsule:
        reproduced, reps = await self.reproduce(finding, exchange)
        n_confirmed = sum(1 for r in reps if _is_confirmed(r))

        if not reproduced:
            clean_neg = _clean_negative(reps)
            return ProofCapsule(
                validator=self.name,
                finding_class=finding.vulnerability_class,
                n_required=self.n_required,
                n_confirmed=n_confirmed,
                reproduced=False,
                negative_control_available=False,
                negative_control_clean=False,
                verified=False,
                reproduction_clean_negative=clean_neg,
                reason=(f"did not reproduce: {n_confirmed}/{self.n_required} confirmed "
                        + ("(clean executed negative)" if clean_neg
                           else "(INCONCLUSIVE -- probe skipped/errored, not a clean negative)")),
                reproductions=reps,
            )

        available, clean, neg = await self.run_negative_control(finding, exchange)

        if self.require_negative_control and not available:
            verified = False
            reason = ("reproduced N-of-N but NO negative control was available for this "
                      "class/exchange -- cannot rule out a probe that confirms on any input; "
                      "stays a candidate")
        elif available and not clean:
            verified = False
            reason = ("reproduced N-of-N but the negative control ALSO confirmed on a benign "
                      "variant -- the probe is not discriminating; likely false positive")
        else:
            verified = True
            reason = ("reproduced N-of-N"
                      + (" and the negative control stayed clean" if available
                         else " (leg is self-controlling; no benign-variant control needed)"))

        return ProofCapsule(
            validator=self.name,
            finding_class=finding.vulnerability_class,
            n_required=self.n_required,
            n_confirmed=n_confirmed,
            reproduced=True,
            negative_control_available=available,
            negative_control_clean=clean,
            verified=verified,
            reason=reason,
            reproductions=reps,
            negative_control_result=neg,
        )


class OracleRegistry:
    """Maps a finding/exchange to the Oracle that can verify it.

    Built over a `ValidatorRegistry` so it reuses the exact validator instances
    (and their scope/safety gating) the graph loop already uses. Negative-control
    builders come from `negative_controls.BUILDERS`; a class with no builder gets
    an oracle whose control is "unavailable" (reproduced findings stay candidates).
    Classes whose leg is inherently self-controlling (OOB collaborator legs) are
    registered with `require_negative_control=False`.
    """

    def __init__(
        self,
        validator_registry,
        *,
        n_required: int = 3,
        negative_control_builders: dict[str, NegativeControlBuilder] | None = None,
        self_controlling_validators: frozenset[str] | None = None,
    ):
        from harness import negative_controls
        self._registry = validator_registry
        self.n_required = int(n_required)
        self._builders = (negative_control_builders
                          if negative_control_builders is not None
                          else negative_controls.BUILDERS)
        # OOB collaborator legs prove execution by a unique-token callback that
        # cannot occur by benign coincidence -- self-controlling, no benign-variant
        # control required to reach VERIFIED.
        self._self_controlling = (self_controlling_validators
                                  if self_controlling_validators is not None
                                  else negative_controls.SELF_CONTROLLING)

    def oracle_for(self, finding: Finding, exchange: HttpExchange) -> Oracle | None:
        """Pick an oracle for this finding: the applicable, active validator whose
        class matches, wrapped with its negative control. None when nothing applies."""
        candidates = self._registry.for_finding(finding, exchange)
        for validator in candidates:
            name = getattr(validator, "name", "")
            builder = self._builders.get(name)
            return Oracle(
                validator,
                negative_control=builder,
                n_required=self.n_required,
                require_negative_control=(name not in self._self_controlling),
            )
        return None

    async def verify(self, finding: Finding, exchange: HttpExchange) -> ProofCapsule | None:
        oracle = self.oracle_for(finding, exchange)
        if oracle is None:
            return None
        return await oracle.run(finding, exchange)


def derive_verification_state(finding) -> str:
    """Pure map from a finding's stamped fields to a verification state (item #2).

    VERIFIED requires an oracle to have set `oracle_verified=True` (an N-of-N +
    negative-control proof). A `confirmed=True` finding with no oracle proof is a
    CANDIDATE -- a leg fired, but the stricter oracle bar was not met (or the oracle
    never ran). This never runs a probe; it only reads what the oracle stamped."""
    if isinstance(finding, dict):
        oracle_verified = bool(finding.get("oracle_verified", False))
    else:
        oracle_verified = bool(getattr(finding, "oracle_verified", False))
    return STATE_VERIFIED if oracle_verified else STATE_CANDIDATE


def stamp_finding(finding, capsule: ProofCapsule | None) -> None:
    """Write an oracle capsule's verdict onto a Finding (or finding dict) in place.

    Sets `oracle_verified`, `oracle_capsule_id`, `oracle_reason`, and
    `verification_state`. A None capsule (no oracle applied) leaves the finding a
    candidate without claiming an oracle ran."""
    verified = bool(capsule and capsule.verified)
    cid = capsule.capsule_id() if capsule else ""
    reason = capsule.reason if capsule else "no oracle applied"
    state = STATE_VERIFIED if verified else STATE_CANDIDATE
    if isinstance(finding, dict):
        finding["oracle_verified"] = verified
        finding["oracle_capsule_id"] = cid
        finding["oracle_reason"] = reason
        finding["verification_state"] = state
    else:
        # Finding is a pydantic model; these are declared fields (see models.py).
        finding.oracle_verified = verified
        finding.oracle_capsule_id = cid
        finding.oracle_reason = reason
        finding.verification_state = state
