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

from dataclasses import dataclass, replace

# How much an objective's action may change the target. A DESTRUCTIVE objective
# is never attempted unless the run's caller opted in explicitly
# (`ObjectiveTask.destructive_opt_in`), even when the safety gate itself would
# authorize the mutating send.
READ_ONLY = "read_only"
DESTRUCTIVE = "destructive"
MUTATION_LEVELS = (READ_ONLY, DESTRUCTIVE)


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
    mutation_level: str = DESTRUCTIVE


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
# itself comes from the chain's confirmation preflight, where only the
# cross_identity leg (a second identity) confirms IDOR: the single-principal
# read differential in `validators/idor_read_validator.py` never confirms
# (RV-D2), so it cannot open this objective. This profile only governs what
# happens *after* that proof already succeeded. Unlike
# SSTI_FILE_DELETE the action is a read (GET), never a mutation, so it needs
# no `allow_mutating_replay` opt-in -- GET is always the safety gate's SAFE
# risk tier (see `safety_gate.SafetyGate.classify`).
ACCESS_ADMIN_READ = ObjectiveProfile(
    vulnerability_class="idor",
    action_class="http_get",
    oracle="content_present",
    requires_mutating_authorization=False,
    mutation_level=READ_ONLY,
)

_REGISTRY: dict[str, ObjectiveProfile] = {
    SSTI_FILE_DELETE.vulnerability_class: SSTI_FILE_DELETE,
    ACCESS_ADMIN_READ.vulnerability_class: ACCESS_ADMIN_READ,
}


# Names a runner/benchmark declaration may use to pick a registered profile.
PROFILES_BY_NAME: dict[str, ObjectiveProfile] = {
    "ssti_file_delete": SSTI_FILE_DELETE,
    "access_admin_read": ACCESS_ADMIN_READ,
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
    # The caller's explicit opt-in for a DESTRUCTIVE profile. Off by default:
    # without it `attempt_completion` returns `objective_not_attempted` before
    # anything is sent.
    destructive_opt_in: bool = False


@dataclass(frozen=True)
class ObjectiveDeclaration:
    """LB-6: the typed objective profile a benchmark/smoke runner accepts.

    Every field restates the registered profile it names, so a declaration can
    narrow a profile (a lower request ceiling) but never widen it: a different
    action class, mutation level or oracle adapter is rejected, not honoured.
    The declared end state (`target_path`, `oracle_url`, `oracle_marker`) is the
    only run-specific data. `to_task` turns it into the `ObjectiveTask` the run
    carries on its `RunContext`."""

    profile_name: str
    target_path: str
    action_class: str
    mutation_level: str
    oracle: str
    oracle_url: str = ""
    oracle_marker: str = ""
    max_completion_requests: int = 2

    @property
    def profile(self) -> ObjectiveProfile:
        return PROFILES_BY_NAME[self.profile_name]

    @classmethod
    def from_mapping(cls, data: dict) -> "ObjectiveDeclaration":
        if not isinstance(data, dict):
            raise ValueError("objective profile must be a JSON object")
        name = str(data.get("profile") or "").strip().lower()
        profile = PROFILES_BY_NAME.get(name)
        if profile is None:
            raise ValueError(f"unknown objective profile {name!r}; registered: "
                             f"{sorted(PROFILES_BY_NAME)}")
        end_state = data.get("required_end_state") or {}
        if not isinstance(end_state, dict):
            raise ValueError("required_end_state must be an object")
        target_path = str(end_state.get("target_path") or "").strip()
        if not target_path:
            raise ValueError("required_end_state.target_path is required")
        declared = {
            "action_class": str(data.get("action_class") or ""),
            "mutation_level": str(data.get("mutation_level") or ""),
            "oracle": str(data.get("oracle") or ""),
        }
        for key, value in declared.items():
            if value != getattr(profile, key):
                raise ValueError(f"objective profile {name!r} has {key} "
                                 f"{getattr(profile, key)!r}; the declaration says {value!r}")
        ceilings = data.get("ceilings") or {}
        if not isinstance(ceilings, dict):
            raise ValueError("ceilings must be an object")
        ceiling = ceilings.get("max_completion_requests", profile.max_completion_requests)
        if (isinstance(ceiling, bool) or not isinstance(ceiling, int)
                or not 1 <= ceiling <= profile.max_completion_requests):
            raise ValueError(f"ceilings.max_completion_requests must be an integer from 1 "
                             f"to {profile.max_completion_requests}")
        return cls(profile_name=name, target_path=target_path,
                   oracle_url=str(end_state.get("oracle_url") or ""),
                   oracle_marker=str(end_state.get("oracle_marker") or ""),
                   max_completion_requests=ceiling, **declared)

    def to_task(self, *, allow_destructive: bool = False) -> ObjectiveTask:
        profile = replace(self.profile, max_completion_requests=self.max_completion_requests)
        return ObjectiveTask(
            profile=profile, target_path=self.target_path, oracle_url=self.oracle_url,
            oracle_marker=self.oracle_marker,
            destructive_opt_in=bool(allow_destructive) and self.mutation_level == DESTRUCTIVE)

    def describe(self) -> dict:
        return {"profile": self.profile_name,
                "vulnerability_class": self.profile.vulnerability_class,
                "action_class": self.action_class, "mutation_level": self.mutation_level,
                "oracle": self.oracle, "target_path": self.target_path,
                "oracle_url": self.oracle_url,
                "max_completion_requests": self.max_completion_requests}
