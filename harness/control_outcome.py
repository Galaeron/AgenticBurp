"""What a validator's negative control said about a `not_confirmed` verdict (EFF-1).

A `not_confirmed` status says only that the leg did not confirm. Whether that
silence REFUTES the finding depends on whether the leg observed the defence hold
for this case, so every result carries one of three control states:

  held     -- `CONTROL_HELD`: the validator delivered the attack to the case and
              observed the defence working against a reference it also observed
              (another identity denied while the owner is allowed, a forged field
              absent from a read-back that shows the field, a rotated session id).
              Only this state is a controlled negative.
  failed   -- `CONTROL_FAILED`: the control itself did not behave (a negative
              control reached the protected page), so the comparison says nothing.
  unknown  -- everything else: `""` (the validator did not say), `CONTROL_NOT_RUN`
              (a tool error, nothing to compare), and the reason markers below.

Absence of an oracle signal (no callback, no reflection, no evaluated product, no
file contents) is not a held control; such a negative stays `unknown`, which the
confirmation gate reports as inconclusive, never as refuted. The per-validator
decision is recorded in docs/CONTROL_OUTCOME_INVENTORY.md.
"""
from __future__ import annotations

from typing import Literal

CONTROL_HELD = "control_held"
CONTROL_FAILED = "control_failed"
CONTROL_NOT_RUN = "not_run"
UNSET = ""
# Reason markers in the unknown family: the negative did not cover the case.
INCONCLUSIVE = "inconclusive"
NAMED_PARAMETER_UNTESTED = "named_parameter_untested"
PARTIAL_COVERAGE = "partial_coverage"

ControlOutcome = Literal["", "control_held", "control_failed", "not_run", "inconclusive",
                         "named_parameter_untested", "partial_coverage"]
ControlState = Literal["held", "failed", "unknown"]


def control_state(outcome: str | None) -> ControlState:
    """The tri-state reading of a control_outcome value; an unrecognised or
    missing value is "unknown", never "held"."""
    value = (outcome or "").strip().lower()
    if value == CONTROL_HELD:
        return "held"
    if value == CONTROL_FAILED:
        return "failed"
    return "unknown"


def is_controlled_negative(status: str | None, confirmed: bool, outcome: str | None) -> bool:
    """True only for a not_confirmed, unconfirmed result whose control held."""
    return ((status or "").strip().lower() == "not_confirmed" and not confirmed
            and control_state(outcome) == "held")


def covers_case(outcome: str | None) -> bool:
    """Coverage reading, independent of the control: True when the leg did not mark
    its result as leaving the case (or its control) unexercised. A result with no
    outcome still covers its case; it just does not refute it."""
    return (outcome or "").strip().lower() in (UNSET, CONTROL_HELD)
