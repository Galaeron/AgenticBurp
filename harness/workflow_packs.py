"""SC-11: versioned workflow/chain data packs with a strict schema + fixtures.

AgenticVibe already has a richer *executable* workflow engine than the upstream
playbook/chain YAML we are borrowing from (see :mod:`harness.workflow_engine`:
prereq graph, typed extractors, principals, assertions, cleanup, variants). What
is worth borrowing is the *packaging*: shipping workflow definitions as versioned
data with a strict, machine-checkable contract, so a pack can be compiled and
validated deterministically and a fingerprint mismatch halts execution
**programmatically** rather than as prose guidance to a model.

A :class:`WorkflowPack` wraps one engine ``Workflow`` with the contract metadata a
data pack needs:

* ``schema_version`` -- the pack-schema version this module understands; an
  unknown one is rejected (fail closed).
* ``engine_min`` / ``engine_max`` -- the supported ``workflow_engine.ENGINE_VERSION``
  range; a pack authored against a different engine refuses to compile.
* ``taxonomy`` / ``impact`` / ``required_capabilities`` -- what class of issue this
  proves, its impact envelope, and the capabilities an engagement must grant.
* ``fingerprint`` -- a precondition probe (request + assertions). At run time a
  mismatch transitions the pack to a terminal ``FINGERPRINT_MISMATCH`` state and
  the main workflow is never executed -- an enforced state transition, not a
  model instruction.
* ``proof_contract`` -- which step reaching which status constitutes proof, so a
  vulnerable target and a patched one land in *opposite* evidence states.
* ``negative_fixture`` / ``cleanup_contract`` -- the expected refuting outcome and
  the cleanup steps that must run.

Strictness reuses SC-4: unknown assertion kinds are rejected by
``workflow_engine._load_assertion``, and this module additionally rejects unknown
*fields* at every level (the engine's own ``workflow_from_dict`` is lenient about
extra keys) and rejects cyclic prerequisites with a precise diagnostic.

This is data + a validator + a runner; nothing in the default pipeline compiles
or runs a pack yet, so importing this module sends no traffic and changes no
verdict. Auto-selecting which pack applies to a live target is deferred.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from harness import workflow_engine
from harness.workflow_engine import (
    Assertion, Workflow, WorkflowStep, WorkflowResult, _load_assertion,
    workflow_from_dict,
)

PACK_SCHEMA_VERSION = 1

_PACK_DATA_DIR = Path(__file__).resolve().parent / "workflow_pack_data"

# Allowed field sets -- unknown keys anywhere are rejected (fail closed).
_PACK_FIELDS = frozenset({
    "pack_id", "schema_version", "engine_min", "engine_max", "taxonomy",
    "required_capabilities", "impact", "fingerprint", "proof_contract",
    "negative_fixture", "cleanup_contract", "workflow",
})
_FINGERPRINT_FIELDS = frozenset({"method", "url_template", "session_ref", "assertions"})
_PROOF_FIELDS = frozenset({"proof_step", "proven_status", "refuted_statuses"})
_NEGATIVE_FIXTURE_FIELDS = frozenset({"description", "expected_state"})
_CLEANUP_CONTRACT_FIELDS = frozenset({"required_steps"})
_IMPACT_FIELDS = frozenset({"severity", "scope", "cwe"})
_WORKFLOW_FIELDS = frozenset({"id", "version", "invariant", "steps"})
_STEP_FIELDS = frozenset({
    "id", "method", "url_template", "session_ref", "body_template",
    "prerequisites", "extractors", "assertions", "transition", "cleanup",
})
_EXTRACTOR_FIELDS = frozenset({"name", "kind", "expression", "required"})
_ASSERTION_FIELDS = frozenset({"kind", "expression", "expected"})

# StepStatus values a proof contract may reference.
_STEP_STATUS_VALUES = frozenset(s.value for s in workflow_engine.StepStatus)


class PackEvidenceState(str, Enum):
    """Terminal evidence state of a pack run."""
    PENDING = "pending"
    FINGERPRINT_MISMATCH = "fingerprint_mismatch"
    PROVEN = "proven"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


_TERMINAL_FIXTURE_STATES = frozenset({
    PackEvidenceState.PROVEN.value, PackEvidenceState.REFUTED.value,
    PackEvidenceState.INCONCLUSIVE.value,
})


class PackValidationError(ValueError):
    """Raised when a pack dict violates the strict schema. A ValueError subclass
    so existing ``except ValueError`` load paths keep catching it."""


@dataclass(frozen=True)
class Fingerprint:
    method: str
    url_template: str
    session_ref: str
    assertions: tuple = ()

    def as_step(self) -> WorkflowStep:
        return WorkflowStep(id="fingerprint", method=self.method,
                            url_template=self.url_template, session_ref=self.session_ref,
                            assertions=tuple(self.assertions))


@dataclass(frozen=True)
class ProofContract:
    proof_step: str
    proven_status: str = "passed"
    refuted_statuses: tuple = ("failed", "blocked", "cancelled")


@dataclass
class WorkflowPack:
    pack_id: str
    schema_version: int
    engine_min: int
    engine_max: int
    taxonomy: str
    required_capabilities: tuple
    impact: dict
    fingerprint: Fingerprint
    proof_contract: ProofContract
    negative_fixture: dict
    cleanup_contract: dict
    workflow: Workflow

    def fingerprint_workflow(self) -> Workflow:
        """A one-step Workflow that PASSES iff the fingerprint holds. Runs through
        the same engine/caller as the main workflow, so a mismatch is a real
        FAILED step, not a soft signal."""
        return Workflow(id=f"{self.pack_id}:fingerprint",
                        steps=(self.fingerprint.as_step(),),
                        version=self.workflow.version)

    def classify(self, result: WorkflowResult) -> PackEvidenceState:
        """Map a workflow result to the pack's evidence state via the proof
        contract: the proof step reaching ``proven_status`` is PROVEN; reaching a
        ``refuted_statuses`` value is REFUTED; anything else (or a missing proof
        step) is INCONCLUSIVE."""
        step = next((s for s in result.steps if s.step_id == self.proof_contract.proof_step), None)
        if step is None:
            return PackEvidenceState.INCONCLUSIVE
        status = step.status.value
        if status == self.proof_contract.proven_status:
            return PackEvidenceState.PROVEN
        if status in self.proof_contract.refuted_statuses:
            return PackEvidenceState.REFUTED
        return PackEvidenceState.INCONCLUSIVE

    def to_dict(self) -> dict:
        return {
            "pack_id": self.pack_id,
            "schema_version": self.schema_version,
            "engine_min": self.engine_min,
            "engine_max": self.engine_max,
            "taxonomy": self.taxonomy,
            "required_capabilities": list(self.required_capabilities),
            "impact": dict(self.impact),
            "proof_contract": {
                "proof_step": self.proof_contract.proof_step,
                "proven_status": self.proof_contract.proven_status,
                "refuted_statuses": list(self.proof_contract.refuted_statuses),
            },
            "negative_fixture": dict(self.negative_fixture),
            "cleanup_contract": dict(self.cleanup_contract),
            "workflow_id": self.workflow.id,
            "workflow_version": self.workflow.version,
        }


@dataclass
class PackRun:
    pack_id: str
    state: PackEvidenceState
    fingerprint_matched: bool
    reason: str = ""
    fingerprint_result: WorkflowResult | None = None
    workflow_result: WorkflowResult | None = None

    def to_dict(self) -> dict:
        return {
            "pack_id": self.pack_id, "state": self.state.value,
            "fingerprint_matched": self.fingerprint_matched, "reason": self.reason,
            "fingerprint_result": self.fingerprint_result.to_dict() if self.fingerprint_result else None,
            "workflow_result": self.workflow_result.to_dict() if self.workflow_result else None,
        }


def _reject_unknown(d: dict, allowed: frozenset, ctx: str) -> None:
    if not isinstance(d, dict):
        raise PackValidationError(f"{ctx}: expected an object, got {type(d).__name__}")
    extra = set(map(str, d.keys())) - allowed
    if extra:
        raise PackValidationError(f"{ctx}: unknown field(s): {sorted(extra)}")


def _require(d: dict, key: str, ctx: str):
    if key not in d:
        raise PackValidationError(f"{ctx}: missing required field {key!r}")
    return d[key]


def _detect_prerequisite_cycle(steps: list) -> None:
    """Reject cyclic prerequisites with a precise diagnostic BEFORE the engine's
    ordering check turns a cycle into a generic 'forward prerequisites' error.
    Unknown prereq ids are left for workflow_from_dict/Workflow to report."""
    graph = {str(s.get("id", "")): [str(p) for p in (s.get("prerequisites", []) or [])]
             for s in steps}
    WHITE, GREY, BLACK = 0, 1, 2
    color = {n: WHITE for n in graph}
    stack: list[str] = []

    def visit(node: str) -> None:
        color[node] = GREY
        stack.append(node)
        for nxt in graph.get(node, []):
            if nxt not in color:
                continue  # unknown prereq: not a cycle; engine reports it
            if color[nxt] == GREY:
                cycle = stack[stack.index(nxt):] + [nxt]
                raise PackValidationError(
                    f"cyclic prerequisites: {' -> '.join(cycle)}")
            if color[nxt] == WHITE:
                visit(nxt)
        stack.pop()
        color[node] = BLACK

    for node in list(graph):
        if color[node] == WHITE:
            visit(node)


def _validate_workflow_strict(wf: dict) -> Workflow:
    """Reject unknown fields at workflow/step/extractor/assertion level (the
    engine's workflow_from_dict silently drops extras), reject cyclic
    prerequisites, then delegate the semantic parse to the engine loader (which
    enforces SC-4 assertion strictness, unique/ordered ids, extractor kinds)."""
    _reject_unknown(wf, _WORKFLOW_FIELDS, "workflow")
    steps = wf.get("steps", [])
    if not isinstance(steps, list) or not steps:
        raise PackValidationError("workflow: 'steps' must be a non-empty list")
    for raw in steps:
        _reject_unknown(raw, _STEP_FIELDS, f"step {raw.get('id', '?')!r}")
        for ex in raw.get("extractors", []) or []:
            _reject_unknown(ex, _EXTRACTOR_FIELDS, f"step {raw.get('id', '?')!r} extractor")
        for a in raw.get("assertions", []) or []:
            _reject_unknown(a, _ASSERTION_FIELDS, f"step {raw.get('id', '?')!r} assertion")
    _detect_prerequisite_cycle(steps)
    try:
        return workflow_from_dict(wf)
    except (ValueError, KeyError) as exc:
        raise PackValidationError(f"workflow: {exc}") from exc


def _parse_fingerprint(data: dict) -> Fingerprint:
    _reject_unknown(data, _FINGERPRINT_FIELDS, "fingerprint")
    try:
        assertions = tuple(_load_assertion(a) for a in data.get("assertions", []) or [])
    except (ValueError, KeyError, TypeError) as exc:
        raise PackValidationError(f"fingerprint assertion: {exc}") from exc
    if not assertions:
        raise PackValidationError("fingerprint: at least one assertion is required "
                                  "(an unconditioned fingerprint cannot mismatch)")
    return Fingerprint(
        method=str(_require(data, "method", "fingerprint")).upper(),
        url_template=str(_require(data, "url_template", "fingerprint")),
        session_ref=str(_require(data, "session_ref", "fingerprint")),
        assertions=assertions)


def _parse_proof_contract(data: dict, step_ids: set, ctx_steps: list) -> ProofContract:
    _reject_unknown(data, _PROOF_FIELDS, "proof_contract")
    proof_step = str(_require(data, "proof_step", "proof_contract"))
    if proof_step not in step_ids:
        raise PackValidationError(
            f"proof_contract: proof_step {proof_step!r} is not a workflow step")
    proven = str(data.get("proven_status", "passed"))
    refuted = tuple(str(s) for s in data.get("refuted_statuses", ("failed", "blocked", "cancelled")))
    for status in (proven, *refuted):
        if status not in _STEP_STATUS_VALUES:
            raise PackValidationError(
                f"proof_contract: {status!r} is not a valid step status "
                f"({sorted(_STEP_STATUS_VALUES)})")
    if proven in refuted:
        raise PackValidationError(
            f"proof_contract: proven_status {proven!r} also listed as refuting")
    # A proof step that is a cleanup step can never reach PASSED as proof.
    if any(str(s.get("id")) == proof_step and bool(s.get("cleanup")) for s in ctx_steps):
        raise PackValidationError(
            f"proof_contract: proof_step {proof_step!r} is a cleanup step")
    return ProofContract(proof_step, proven, refuted)


def compile_pack(data: dict) -> WorkflowPack:
    """Deterministically compile+validate a pack dict into a WorkflowPack, or
    raise PackValidationError. Same input always yields the same result/first
    error (no ordering-dependent or nondeterministic checks)."""
    _reject_unknown(data, _PACK_FIELDS, "pack")
    pack_id = str(_require(data, "pack_id", "pack"))

    schema_version = _require(data, "schema_version", "pack")
    if schema_version != PACK_SCHEMA_VERSION:
        raise PackValidationError(
            f"pack {pack_id!r}: unsupported schema_version {schema_version!r} "
            f"(this build understands {PACK_SCHEMA_VERSION})")

    try:
        engine_min = int(data.get("engine_min", workflow_engine.ENGINE_VERSION))
        engine_max = int(data.get("engine_max", workflow_engine.ENGINE_VERSION))
    except (TypeError, ValueError) as exc:
        raise PackValidationError(
            f"pack {pack_id!r}: engine_min/engine_max must be integers") from exc
    if engine_min > engine_max:
        raise PackValidationError(
            f"pack {pack_id!r}: engine_min {engine_min} > engine_max {engine_max}")
    if not (engine_min <= workflow_engine.ENGINE_VERSION <= engine_max):
        raise PackValidationError(
            f"pack {pack_id!r}: engine {workflow_engine.ENGINE_VERSION} outside "
            f"supported range [{engine_min}, {engine_max}]")

    impact = data.get("impact", {}) or {}
    _reject_unknown(impact, _IMPACT_FIELDS, "impact")

    required_capabilities = tuple(str(c) for c in data.get("required_capabilities", []) or [])

    wf_dict = _require(data, "workflow", "pack")
    if not isinstance(wf_dict, dict):
        raise PackValidationError("pack: 'workflow' must be an object")
    workflow = _validate_workflow_strict(wf_dict)
    step_ids = {s.id for s in workflow.steps}

    fingerprint = _parse_fingerprint(_require(data, "fingerprint", "pack"))
    proof_contract = _parse_proof_contract(
        _require(data, "proof_contract", "pack"), step_ids, wf_dict.get("steps", []))

    negative_fixture = data.get("negative_fixture", {}) or {}
    _reject_unknown(negative_fixture, _NEGATIVE_FIXTURE_FIELDS, "negative_fixture")
    expected_state = str(negative_fixture.get("expected_state", PackEvidenceState.REFUTED.value))
    if expected_state not in _TERMINAL_FIXTURE_STATES:
        raise PackValidationError(
            f"negative_fixture: expected_state {expected_state!r} must be one of "
            f"{sorted(_TERMINAL_FIXTURE_STATES)}")
    negative_fixture = dict(negative_fixture)
    negative_fixture["expected_state"] = expected_state

    cleanup_contract = data.get("cleanup_contract", {}) or {}
    _reject_unknown(cleanup_contract, _CLEANUP_CONTRACT_FIELDS, "cleanup_contract")
    cleanup_step_ids = {s.id for s in workflow.steps if s.cleanup}
    for step_id in cleanup_contract.get("required_steps", []) or []:
        if str(step_id) not in cleanup_step_ids:
            raise PackValidationError(
                f"cleanup_contract: required_step {step_id!r} is not a cleanup step "
                f"in the workflow")

    return WorkflowPack(
        pack_id=pack_id, schema_version=int(schema_version),
        engine_min=engine_min, engine_max=engine_max,
        taxonomy=str(data.get("taxonomy", "")),
        required_capabilities=required_capabilities, impact=dict(impact),
        fingerprint=fingerprint, proof_contract=proof_contract,
        negative_fixture=negative_fixture, cleanup_contract=dict(cleanup_contract),
        workflow=workflow)


def validate_pack(data: dict) -> tuple[bool, list[str]]:
    """Deterministic validate: (ok, errors). errors holds the first schema
    violation (compile fails closed on the first problem) or is empty."""
    try:
        compile_pack(data)
        return True, []
    except ValueError as exc:  # PackValidationError is a ValueError subclass
        return False, [str(exc)]


def load_pack_file(path) -> WorkflowPack:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return compile_pack(data)


def shipped_pack_paths() -> list[Path]:
    """All versioned pack data files that ship in-repo, in a stable sorted order."""
    if not _PACK_DATA_DIR.is_dir():
        return []
    return sorted(_PACK_DATA_DIR.glob("*.pack.json"))


def load_shipped_packs() -> list[WorkflowPack]:
    return [load_pack_file(p) for p in shipped_pack_paths()]


async def run_pack(pack: WorkflowPack, run_context) -> PackRun:
    """Run a pack through the REAL engagement caller
    (:func:`harness.engagement_builder.execute_declared_workflows`), enforcing the
    fingerprint gate as a hard state transition: if the fingerprint step does not
    PASS, the main workflow is never dispatched and the pack is FINGERPRINT_MISMATCH.
    Otherwise the workflow runs and the proof contract classifies the result."""
    from harness import engagement_builder

    fp_result = (await engagement_builder.execute_declared_workflows(
        [pack.fingerprint_workflow()], run_context))[0]
    if not fp_result.complete:
        return PackRun(pack.pack_id, PackEvidenceState.FINGERPRINT_MISMATCH,
                       fingerprint_matched=False,
                       reason="target fingerprint did not hold; execution halted",
                       fingerprint_result=fp_result)

    wf_result = (await engagement_builder.execute_declared_workflows(
        [pack.workflow], run_context))[0]
    state = pack.classify(wf_result)
    return PackRun(pack.pack_id, state, fingerprint_matched=True,
                   reason=f"proof step {pack.proof_contract.proof_step!r} classified as {state.value}",
                   fingerprint_result=fp_result, workflow_result=wf_result)


def main(argv=None) -> int:
    """Deterministic compile/validate command:

        python -m harness.workflow_packs [PATH ...]

    Validates each given .pack.json file (or every shipped pack when no path is
    given), printing 'OK <path>' / 'FAIL <path>: <error>' in sorted order.
    Exit status is nonzero iff any pack failed to compile."""
    import argparse

    parser = argparse.ArgumentParser(prog="harness.workflow_packs",
                                     description="Compile/validate workflow packs.")
    parser.add_argument("paths", nargs="*", help="pack .json files (default: shipped packs)")
    args = parser.parse_args(argv)

    paths = [Path(p) for p in args.paths] if args.paths else shipped_pack_paths()
    if not paths:
        print("no packs to validate")
        return 0

    failures = 0
    for path in sorted(paths, key=str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            compile_pack(data)
            print(f"OK   {path}")
        except (PackValidationError, ValueError, OSError) as exc:
            failures += 1
            print(f"FAIL {path}: {exc}")
    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
