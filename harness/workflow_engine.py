"""Versioned, explicit authenticated workflow records (Astra T07).

This is deliberately separate from feature_workflow's opportunistic crawler: a
Workflow describes a known state machine whose prerequisites and extracted values
must be satisfied before a dependent request can run.  Missing values BLOCK; they
are never replaced with guessed object IDs or tokens.
"""
from __future__ import annotations

import json
import re
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
