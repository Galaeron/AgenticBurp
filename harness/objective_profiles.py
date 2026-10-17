"""
Objective profiles -- the typed contract an objective-completion run declares
up front, kept separate from the deterministic confirmation validators.

Confirmation (harness/validators/*.py) answers one question: does the
vulnerability exist? An `ObjectiveProfile` + `ObjectiveTask` answer a second,
independent question: does executing a specific benchmark objective reach a
declared end state? `harness/objective_completion.py` is the only caller that
consumes these.

Nothing here is inferred from a lab title, a finding's free-text summary, or
response content. A profile only exists for a vulnerability class this module
explicitly registers; a task only exists when a caller supplies one with an
explicit `target_path`. `objective_completion.attempt_completion` must return
`objective_not_attempted` for every other case -- see its module docstring.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ObjectiveProfile:
    """Class-level completion policy. Immutable and registered once; carries
    no run-specific data (that's `ObjectiveTask.target_path`)."""

    vulnerability_class: str
    # The single template/action primitive a completion payload for this
    # class may use. `objective_completion._ACTION_TEMPLATES` is the
    # authoritative allow-list keyed by this value -- adding an action class
    # here without a matching entry there is a configuration error, not a
    # silent capability.
    action_class: str
    # How the declared end state is checked, independent of the model's or
    # the validator's own claim. "" means no independent oracle is wired yet,
    # which makes every completion attempt for this profile return
    # `objective_not_completed` rather than `completed` (see
    # `objective_completion._check_oracle`).
    oracle: str = ""
    max_completion_requests: int = 2
    requires_mutating_authorization: bool = True


# SSTI's declared destructive objective: delete a caller-named disposable
# file through the confirmed template-evaluation point. Confirmation itself
# stays the existing arithmetic-canary proof in `validators/ssti_validator.py`
# and never changes; this profile only governs what happens *after* that
# proof already succeeded.
SSTI_FILE_DELETE = ObjectiveProfile(
    vulnerability_class="ssti",
    action_class="file_delete",
    oracle="file_absent",
)

# IDOR/access-control's declared NON-destructive objective: reach a
# caller-declared protected resource with a plain GET and have an
# independent oracle GET confirm its content is reachable. Confirmation
# itself stays the existing read differential in
# `validators/idor_read_validator.py` and never changes; this profile only
# governs what happens *after* that proof already succeeded. Unlike
# SSTI_FILE_DELETE the action is a read (GET), never a mutation, so it needs
# no `allow_mutating_replay` opt-in -- GET is always the safety gate's SAFE
# risk tier (see `safety_gate.SafetyGate.classify`).
ACCESS_ADMIN_READ = ObjectiveProfile(
    vulnerability_class="idor",
    action_class="http_get",
    oracle="content_present",
    requires_mutating_authorization=False,
)

_REGISTRY: dict[str, ObjectiveProfile] = {
    SSTI_FILE_DELETE.vulnerability_class: SSTI_FILE_DELETE,
    ACCESS_ADMIN_READ.vulnerability_class: ACCESS_ADMIN_READ,
}


def resolve_profile(vulnerability_class: str | None) -> ObjectiveProfile | None:
    """The registered profile for a canonical vulnerability class, or None.
    None is a valid, expected answer for every class without a completion
    contract yet -- callers must treat that as `objective_not_attempted`,
    never fall back to guessing an action class."""
    if not vulnerability_class:
        return None
    return _REGISTRY.get(vulnerability_class.strip().lower())


@dataclass(frozen=True)
class ObjectiveTask:
    """One run's explicit declaration of what to complete. Always supplied by
    the caller (a benchmark manifest entry, a smoke-runner flag, or a test) --
    never constructed from observed content."""

    profile: ObjectiveProfile
    target_path: str
    # Optional URL the oracle can GET to observe the declared end state (e.g.
    # a fixture's own `/status?file=...` endpoint, or -- for a read-only
    # reach-state objective like ACCESS_ADMIN_READ -- the protected resource
    # itself, re-fetched independently of the completion action's own
    # response). Empty means no independent oracle is reachable for this
    # run, which caps the outcome at `objective_not_completed` even when the
    # action was sent and appeared to succeed.
    oracle_url: str = ""
    # Optional substring the "content_present" oracle must find in its
    # independent GET's body before it will report the objective complete.
    # Unused by "file_absent". Empty means the oracle falls back to a bare
    # HTTP 200 check on its own (still never trusting the action send's own
    # response body).
    oracle_marker: str = ""
