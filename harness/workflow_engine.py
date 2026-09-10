"""Versioned, explicit authenticated workflow records (Astra T07).

This is deliberately separate from feature_workflow's opportunistic crawler: a
Workflow describes a known state machine whose prerequisites and extracted values
must be satisfied before a dependent request can run.  Missing values BLOCK; they
are never replaced with guessed object IDs or tokens.
"""
from __future__ import annotations

import json
import re
import asyncio
from dataclasses import replace
from dataclasses import dataclass, field
from enum import Enum
from html.parser import HTMLParser
from urllib.parse import urljoin


class ExtractorKind(str, Enum):
    JSON_POINTER = "json_pointer"
    LOCATION = "location"
    HTML_HIDDEN = "html_hidden"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"
    CLEANED = "cleaned"


@dataclass(frozen=True)
class Extractor:
    name: str
    kind: ExtractorKind
    expression: str = ""
    required: bool = True


@dataclass(frozen=True)
class Assertion:
    kind: str
    expression: str = ""
    expected: object = None


@dataclass(frozen=True)
class WorkflowStep:
    id: str
    method: str
    url_template: str
    session_ref: str
    body_template: str = ""
    prerequisites: tuple[str, ...] = ()
    extractors: tuple[Extractor, ...] = ()
    assertions: tuple[Assertion, ...] = ()
    transition: str = ""
    cleanup: bool = False

    def __post_init__(self):
        if not self.id or not self.url_template or not self.session_ref:
            raise ValueError("workflow step requires id, URL template, and session_ref")


@dataclass(frozen=True)
class Workflow:
    id: str
    steps: tuple[WorkflowStep, ...]
    version: int = 1
    invariant: str = ""

    def __post_init__(self):
        ids = [s.id for s in self.steps]
        if not self.id or self.version < 1 or len(ids) != len(set(ids)):
            raise ValueError("workflow requires an id, positive version, and unique step ids")
        known: set[str] = set()
        for step in self.steps:
            missing = set(step.prerequisites) - known
            if missing:
                raise ValueError(f"step {step.id} has forward/unknown prerequisites: {sorted(missing)}")
            known.add(step.id)


@dataclass
class StepResult:
    step_id: str
    status: StepStatus
    reason: str = ""
    status_code: int | None = None
    artifact_id: str = ""
    extracted: dict[str, str] = field(default_factory=dict)


@dataclass
class WorkflowResult:
    workflow_id: str
    version: int
    steps: list[StepResult] = field(default_factory=list)
    values: dict[str, str] = field(default_factory=dict)
    cleanup_registered: list[str] = field(default_factory=list)
    cleanup_completed: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return bool(self.steps) and all(s.status in (StepStatus.PASSED, StepStatus.CLEANED)
                                        for s in self.steps)

    def to_dict(self) -> dict:
        return {
            "workflow_id": self.workflow_id, "version": self.version,
            "complete": self.complete, "values": dict(self.values),
            "cleanup_registered": list(self.cleanup_registered),
            "cleanup_completed": list(self.cleanup_completed),
            "steps": [{"step_id": s.step_id, "status": s.status.value,
                       "reason": s.reason, "status_code": s.status_code,
                       "artifact_id": s.artifact_id, "extracted": dict(s.extracted)}
                      for s in self.steps],
        }


_VAR = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_.-]*)\}\}")


def bind_template(template: str, values: dict[str, str]) -> tuple[str, tuple[str, ...]]:
    """Bind ``{{name}}`` placeholders. Return unresolved names instead of guessing."""
    missing: list[str] = []
    def repl(match):
        name = match.group(1)
        if name not in values:
            missing.append(name)
            return match.group(0)
        return str(values[name])
    return _VAR.sub(repl, template or ""), tuple(dict.fromkeys(missing))


def json_pointer(body: str, pointer: str) -> str | None:
    try:
        cur = json.loads(body or "")
        if pointer == "":
            return str(cur)
        if not pointer.startswith("/"):
            return None
        for token in pointer[1:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            cur = cur[int(token)] if isinstance(cur, list) else cur[token]
        if isinstance(cur, (dict, list)):
            return json.dumps(cur, sort_keys=True, separators=(",", ":"))
        return "" if cur is None else str(cur)
    except (ValueError, TypeError, KeyError, IndexError):
        return None


class _HiddenParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.values: dict[str, str] = {}
    def handle_starttag(self, tag, attrs):
        a = {str(k).lower(): (v or "") for k, v in attrs}
        if tag.lower() == "input" and a.get("type", "").lower() == "hidden" and a.get("name"):
            self.values[a["name"]] = a.get("value", "")


def extract_value(extractor: Extractor, *, body: str, headers: dict,
                  response_url: str) -> str | None:
    if extractor.kind == ExtractorKind.JSON_POINTER:
        return json_pointer(body, extractor.expression)
    if extractor.kind == ExtractorKind.LOCATION:
        loc = next((v for k, v in (headers or {}).items() if str(k).lower() == "location"), None)
        return urljoin(response_url, loc) if loc else None
    if extractor.kind == ExtractorKind.HTML_HIDDEN:
        parser = _HiddenParser()
        try:
            parser.feed(body or "")
        except Exception:
            return None
        return parser.values.get(extractor.expression)
    return None


def extract_all(extractors: tuple[Extractor, ...], *, body: str, headers: dict,
                response_url: str) -> tuple[dict[str, str], tuple[str, ...]]:
    values: dict[str, str] = {}
    missing: list[str] = []
    for ex in extractors:
        value = extract_value(ex, body=body, headers=headers, response_url=response_url)
        if value is None:
            if ex.required:
                missing.append(ex.name)
        else:
            values[ex.name] = value
    return values, tuple(missing)


def _assertions_hold(assertions: tuple[Assertion, ...], *, status: int | None,
                     body: str) -> tuple[bool, str]:
    for assertion in assertions:
        if assertion.kind == "status" and status != int(assertion.expected):
            return False, f"expected HTTP {assertion.expected}, got {status}"
        if assertion.kind == "body_contains" and str(assertion.expected) not in (body or ""):
            return False, f"response omitted required marker {assertion.expected!r}"
        if assertion.kind == "json_pointer":
            actual = json_pointer(body, assertion.expression)
            if actual is None or (assertion.expected is not None and actual != str(assertion.expected)):
                return False, f"JSON assertion {assertion.expression} did not hold"
    return True, ""


async def execute_workflow(workflow: Workflow, run_context, *, initial_values=None,
                           capability: str = "workflow", refresh_fn=None,
                           max_refresh_attempts: int = 1,
                           resume: WorkflowResult | None = None) -> WorkflowResult:
    """Execute an explicit workflow through the run-scoped policy executor.

    Cleanup steps are deferred and registered as soon as their prerequisite step
    succeeds. They run in reverse registration order on success, failure, or
    cancellation. A 401 is classified as session expiry and may invoke the bounded
    refresh callback; a 403 is access denial and is never refreshed.
    """
    from run_context import TypedRequest

    if resume and (resume.workflow_id != workflow.id or resume.version != workflow.version):
        raise ValueError("resume record belongs to a different workflow/version")
    result = WorkflowResult(workflow.id, workflow.version,
                            values=dict((resume.values if resume else {}) or {}))
    result.values.update(initial_values or {})
    by_id = {s.id: s for s in workflow.steps}
    cleanup_steps = [s for s in workflow.steps if s.cleanup]
    normal_steps = [s for s in workflow.steps if not s.cleanup]
    statuses: dict[str, StepStatus] = {
        s.step_id: s.status for s in (resume.steps if resume else [])
        if s.status in (StepStatus.PASSED, StepStatus.CLEANED)}
    already_passed = {sid for sid, status in statuses.items() if status == StepStatus.PASSED}
    executor = run_context.executor()

    async def run_step(step: WorkflowStep, *, is_cleanup=False) -> StepResult:
        if run_context.cancel.cancelled and not is_cleanup:
            return StepResult(step.id, StepStatus.CANCELLED, "run cancelled")
        failed_prereqs = [p for p in step.prerequisites
                          if statuses.get(p) not in (StepStatus.PASSED, StepStatus.CLEANED)]
        if failed_prereqs:
            return StepResult(step.id, StepStatus.BLOCKED,
                              f"unsatisfied prerequisites: {', '.join(failed_prereqs)}")
        url, missing_url = bind_template(step.url_template, result.values)
        body, missing_body = bind_template(step.body_template, result.values)
        missing = tuple(dict.fromkeys(missing_url + missing_body))
        if missing:
            return StepResult(step.id, StepStatus.BLOCKED,
                              f"missing extracted values: {', '.join(missing)}")
        attempts = 0
        while True:
            outcome = await executor.execute(
                TypedRequest(step.method, url, body=body or None), capability=capability,
                session_ref=step.session_ref,
                case_ref=f"{workflow.id}:{workflow.version}:{step.id}",
                allow_cancelled_cleanup=is_cleanup)
            if outcome.status != 401 or refresh_fn is None or attempts >= max_refresh_attempts:
                break
            attempts += 1
            refreshed = await refresh_fn(step.session_ref, run_context)
            if not refreshed:
                break
        artifact_id = getattr(outcome.artifact, "artifact_id", "") if outcome.artifact else ""
        if not outcome.ok:
            status = StepStatus.CANCELLED if outcome.outcome == "cancelled" else StepStatus.BLOCKED
            return StepResult(step.id, status, outcome.error or outcome.outcome,
                              outcome.status, artifact_id)
        if outcome.status == 401:
            return StepResult(step.id, StepStatus.FAILED, "session expired", 401, artifact_id)
        if outcome.status == 403:
            return StepResult(step.id, StepStatus.FAILED, "access denied", 403, artifact_id)
        values, missing_extract = extract_all(
            step.extractors, body=outcome.body, headers=outcome.headers,
            response_url=outcome.final_url or url)
        if missing_extract:
            return StepResult(step.id, StepStatus.BLOCKED,
                              f"required extraction missing: {', '.join(missing_extract)}",
                              outcome.status, artifact_id, values)
        holds, reason = _assertions_hold(step.assertions, status=outcome.status, body=outcome.body)
        if not holds:
            return StepResult(step.id, StepStatus.FAILED, reason, outcome.status,
                              artifact_id, values)
        result.values.update(values)
        return StepResult(step.id, StepStatus.CLEANED if is_cleanup else StepStatus.PASSED,
                          step.transition, outcome.status, artifact_id, values)

    try:
        for step in normal_steps:
            if step.id in already_passed:
                continue
            sr = await run_step(step)
            result.steps.append(sr)
            statuses[step.id] = sr.status
            if sr.status == StepStatus.PASSED:
                for cleanup in cleanup_steps:
                    if cleanup.id not in result.cleanup_registered and step.id in cleanup.prerequisites:
                        result.cleanup_registered.append(cleanup.id)
            if sr.status in (StepStatus.BLOCKED, StepStatus.FAILED, StepStatus.CANCELLED):
                # Preserve dependency records: later normal steps are emitted as blocked.
                continue
    finally:
        for cleanup_id in reversed(result.cleanup_registered):
            cleanup = by_id[cleanup_id]
            sr = await run_step(cleanup, is_cleanup=True)
            result.steps.append(sr)
            statuses[cleanup.id] = sr.status
            if sr.status == StepStatus.CLEANED:
                result.cleanup_completed.append(cleanup.id)
    return result


@dataclass(frozen=True)
class MisuseVariant:
    kind: str
    step_id: str
    session_ref: str = ""


def misuse_variants(workflow: Workflow, *, alternate_session_ref: str = "") -> tuple[MisuseVariant, ...]:
    """Deterministic initial T07 variants; these are plans, not confirmations."""
    out: list[MisuseVariant] = []
    for step in workflow.steps:
        if step.cleanup:
            continue
        if step.prerequisites:
            out.append(MisuseVariant("skip_prerequisite", step.id))
        out.append(MisuseVariant("repeat", step.id))
        if alternate_session_ref and alternate_session_ref != step.session_ref:
            out.append(MisuseVariant("switch_principal", step.id, alternate_session_ref))
    return tuple(out)


async def execute_misuse_variant(workflow: Workflow, variant: MisuseVariant, run_context,
                                 *, initial_values=None) -> WorkflowResult:
    """Execute one bounded misuse plan through the same policy executor.

    The caller supplies extracted IDs/tokens when intentionally skipping setup;
    missing values still block. A repeat contains exactly two target sends. A
    principal switch changes only the selected step's session reference.
    """
    target = next((s for s in workflow.steps if s.id == variant.step_id), None)
    if target is None or target.cleanup:
        raise ValueError("misuse variant references an unknown/non-executable step")
    cleanup = tuple(s for s in workflow.steps if s.cleanup)
    if variant.kind == "skip_prerequisite":
        selected = replace(target, prerequisites=())
        shaped = Workflow(f"{workflow.id}:skip:{target.id}", (selected,) + tuple(
            replace(c, prerequisites=(selected.id,)) for c in cleanup),
            workflow.version, workflow.invariant)
    elif variant.kind == "switch_principal":
        selected = replace(target, session_ref=variant.session_ref)
        prefix = tuple(s for s in workflow.steps if not s.cleanup and s.id != target.id)
        # Keep only the target's actual prerequisite prefix.
        needed = set(target.prerequisites)
        prefix = tuple(s for s in prefix if s.id in needed)
        shaped = Workflow(f"{workflow.id}:switch:{target.id}", prefix + (selected,) + cleanup,
                          workflow.version, workflow.invariant)
    elif variant.kind == "repeat":
        first = replace(target, id=f"{target.id}:first", prerequisites=())
        second = replace(target, id=f"{target.id}:repeat", prerequisites=(first.id,))
        shaped = Workflow(f"{workflow.id}:repeat:{target.id}", (first, second),
                          workflow.version, workflow.invariant)
    else:
        raise ValueError(f"unknown misuse variant: {variant.kind}")
    return await execute_workflow(shaped, run_context, initial_values=initial_values,
                                  capability=f"workflow:{variant.kind}")


def workflow_from_dict(data: dict) -> Workflow:
    """Parse the declarative config/API representation without accepting code."""
    steps = []
    for raw in data.get("steps", []):
        extractors = tuple(Extractor(
            str(e["name"]), ExtractorKind(str(e["kind"])), str(e.get("expression", "")),
            bool(e.get("required", True))) for e in raw.get("extractors", []))
        assertions = tuple(Assertion(str(a["kind"]), str(a.get("expression", "")),
                                     a.get("expected")) for a in raw.get("assertions", []))
        steps.append(WorkflowStep(
            id=str(raw["id"]), method=str(raw.get("method", "GET")).upper(),
            url_template=str(raw["url_template"]), session_ref=str(raw["session_ref"]),
            body_template=str(raw.get("body_template", "")),
            prerequisites=tuple(str(x) for x in raw.get("prerequisites", [])),
            extractors=extractors, assertions=assertions,
            transition=str(raw.get("transition", "")), cleanup=bool(raw.get("cleanup", False))))
    return Workflow(str(data["id"]), tuple(steps), int(data.get("version", 1)),
                    str(data.get("invariant", "")))
