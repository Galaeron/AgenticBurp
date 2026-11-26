"""Coverage data model: phases, cell statuses and results, the (parameter, location) case
key and the derivation of input cases from a captured request or a client route template.

Part of the ARC-9 split of harness.coverage_model. Import these names from
harness.coverage_model, the facade, not from this module.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qsl

from harness.client_routes import (
    PAGE, SEGMENT, route_params_of_template, route_segments_of_template,
)


# ---------------------------------------------------------------------------
# Phase (I4): every check belongs to exactly one phase
# ---------------------------------------------------------------------------

class Phase(str, Enum):
    DOMAIN = "domain"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"


# ---------------------------------------------------------------------------
# Cell status (I2/I5): the auditable lifecycle of each matrix cell
# ---------------------------------------------------------------------------

class CellStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    SKIPPED = "skipped"
    ERROR = "error"
    # T05: case-level verdict semantics that mirror evidence.Verdict, so a child
    # case records the same honest distinction a ProofRecord does. These are NEW
    # values -- an old persisted "not_detected" is NEVER re-read as a controlled
    # negative (the review's explicit rule); the mapping is one-directional.
    CONTROLLED_NEGATIVE = "controlled_negative"  # a leg executed and the boundary held
    BLOCKED = "blocked"                          # the safety gate denied the send
    INCONCLUSIVE = "inconclusive"                # no usable verdict (skipped/unsupported)


# Statuses that represent a real, executed verdict (used by aggregation and the
# honest "attempted vs pending" accounting). A CONTROLLED_NEGATIVE counts as a
# conclusive negative; BLOCKED/INCONCLUSIVE/SKIPPED/PENDING/RUNNING do NOT.
_CONCLUSIVE_STATUSES = frozenset({
    CellStatus.CONFIRMED, CellStatus.DETECTED, CellStatus.NOT_DETECTED,
    CellStatus.CONTROLLED_NEGATIVE,
})
# Statuses meaning "this case is not yet conclusively tested" -- their presence
# forbids a parent cell from ever claiming endpoint-wide testing completion.
_OPEN_STATUSES = frozenset({
    CellStatus.PENDING, CellStatus.RUNNING, CellStatus.SKIPPED,
    CellStatus.BLOCKED, CellStatus.INCONCLUSIVE,
})
# Cells `CoverageMatrix.not_tested()` lists: never attempted (not applicable,
# skipped, still pending), attempted without an executed verdict (blocked,
# inconclusive, errored) or still running when the report was taken (RV-O O6).
# The fallback reasons cover a cell recorded without one.
_NOT_TESTED_STATUSES = frozenset({
    CellStatus.NOT_APPLICABLE, CellStatus.SKIPPED,
    CellStatus.PENDING, CellStatus.RUNNING,
    CellStatus.BLOCKED, CellStatus.INCONCLUSIVE, CellStatus.ERROR,
})
_NOT_TESTED_REASONS = {
    CellStatus.PENDING: "the check has not been attempted yet",
    CellStatus.RUNNING: "the check was still running when the report was taken",
    CellStatus.BLOCKED: "the send was refused, so the check did not execute",
    CellStatus.INCONCLUSIVE: "the check gave no usable verdict",
    CellStatus.ERROR: "the attempt errored before a verdict",
}


ATTEMPT_SCHEMA_VERSION = 2


def _merge_facts(*groups) -> tuple:
    """Union of attempt facts (dicts by id, or ids), first-seen order."""
    out, seen = [], set()
    for group in groups:
        for item in group or ():
            key = item.get("id") if isinstance(item, dict) else item
            if key not in seen:
                seen.add(key)
                out.append(item)
    return tuple(out)


@dataclass
class CellResult:
    """One cell in the coverage matrix: (identity, endpoint, check).

    `validator` names the leg/check ASSOCIATED with this result -- it is
    populated both when a leg actually ran AND when an agent's finding was
    merely attributed to a check's catalog confirmation name with no request
    ever sent (R07). `executed` is the separate, narrower signal: True only
    when a deterministic leg actually dispatched a request/comparison for
    this cell (`record_execution_events`, `drive_coverage_legs`,
    `drive_coverage_cases`); False for a purely agent-attributed result
    (`record_findings_from_state`). A validator NAME is provenance, not
    execution evidence -- callers that need "did this actually run" must
    read `executed`, never infer it from `validator` being truthy.

    Batch 02 attempt facts, append-only and independent of the verdict:
    `attempts` are the fresh dispatches that sent requests for this cell in
    this run, each {"id": stable attempt id, "sent": answered run-transport
    sends, or None when unknown};
    `referenced_attempts` are ids of prior executions this verdict reuses
    (an execution-registry hit, a checkpoint resume) with zero new sends.
    A verdict label never erases them."""
    status: CellStatus = CellStatus.PENDING
    reason: str = ""
    severity: str | None = None
    confidence: float | None = None
    validator: str | None = None
    evidence: str | None = None
    executed: bool = False
    attempts: tuple = ()
    referenced_attempts: tuple = ()

    def to_dict(self) -> dict:
        d: dict = {"status": self.status.value, "reason": self.reason}
        if self.severity:
            d["severity"] = self.severity
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.validator:
            d["validator"] = self.validator
        if self.evidence:
            d["evidence"] = self.evidence
        if self.executed:
            d["executed"] = self.executed
        if self.attempts:
            d["attempts"] = [dict(a) for a in self.attempts]
        if self.referenced_attempts:
            d["referenced_attempts"] = list(self.referenced_attempts)
        return d

    @classmethod
    def not_applicable(cls, reason: str) -> "CellResult":
        return cls(status=CellStatus.NOT_APPLICABLE, reason=reason)

    @classmethod
    def from_dict(cls, d: dict) -> "CellResult":
        return cls(
            status=CellStatus(d.get("status", "pending")),
            reason=d.get("reason", ""),
            severity=d.get("severity"),
            confidence=d.get("confidence"),
            validator=d.get("validator"),
            evidence=d.get("evidence"),
            executed=bool(d.get("executed", False)),
            # Legacy (pre-v2) cells carry no attempt facts: read as none.
            attempts=tuple(dict(a) for a in d.get("attempts") or ()),
            referenced_attempts=tuple(d.get("referenced_attempts") or ()),
        )


# ---------------------------------------------------------------------------
# CaseKey (T05/R26): the concrete input/state coordinate WITHIN a cell
# ---------------------------------------------------------------------------
#
# A coverage cell (identity × endpoint × check) is too coarse for a parameter
# check: SQLi on `?search=` and SQLi on `?sort=` are different scenarios, and
# confirming one must not mark the other tested. A `CaseKey` names the concrete
# input (or explicit no-parameter value for a domain/endpoint check), aligned
# field-for-field with `evidence.TestCaseRef` so a coverage case and its T01
# proof share one identity:
#
#   parameter_location  ""|"query"|"body_json"|"body_form"|"header"|"path"
#   parameter_name      the identity name -- a raw name, a JSON Pointer, or a
#                       case-folded header name (originals kept in display_name)
#   occurrence          0-based index so a repeated `?id=&id=` yields two cases
#   workflow_state_id   optional T07 state ("" until a workflow supplies it)
#
# `display_name` preserves the ORIGINAL replay representation (a header's real
# casing, the raw parameter spelling) so an export can replay the exact request
# even though identity folds case. It is deliberately NOT part of the identity.


# Header names that are transport/hop-by-hop plumbing, not user-controllable
# application input -- excluded from derived header cases so coverage does not
# invent parameters (T05: "derive testable inputs ... not invented parameters").
_NON_INPUT_HEADERS = frozenset({
    "host", "content-length", "connection", "accept-encoding", "accept-language",
    "te", "trailer", "transfer-encoding", "upgrade", "keep-alive", "proxy-authorization",
    "content-type", "accept", "date",
})


@dataclass(frozen=True)
class CaseKey:
    """One concrete input/state coordinate within a coverage cell (T05/R26)."""
    parameter_location: str = ""      # "" = the whole request (no-parameter case)
    parameter_name: str = ""          # raw name | JSON Pointer | folded header name
    occurrence: int = 0               # occurrence identity for a repeated name
    workflow_state_id: str = ""       # T07 fills this
    display_name: str = ""            # original replay spelling (not identity)

    def coord_id(self) -> str:
        """Stable id over the IDENTITY fields only (display_name excluded), used
        as the child-case key and to distinguish siblings."""
        joined = "\x1f".join(str(p) for p in (
            self.parameter_location, self.parameter_name, self.occurrence,
            self.workflow_state_id))
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]

    @property
    def is_no_parameter(self) -> bool:
        return not self.parameter_location and not self.parameter_name

    def case_parameter_name(self) -> str:
        """The name to carry into `evidence.TestCaseRef.parameter_name`. A repeated
        parameter folds its occurrence into the name so two occurrences get DISTINCT
        TestCaseRef.case_ids even though TestCaseRef has no occurrence field -- the
        coverage identity and the proof identity stay 1:1. The encoding is
        `<name>[occ:<n>]`, a structured token that does NOT collide with a literal
        parameter named `<name>[<n>]` (the previous `id[1]` form did -- review R07)."""
        if self.occurrence:
            return f"{self.parameter_name}[occ:{self.occurrence}]"
        return self.parameter_name

    def label(self) -> str:
        """Human-readable label for reports/audits."""
        if self.is_no_parameter:
            base = "<no-parameter>"
        else:
            base = f"{self.parameter_location}:{self.display_name or self.parameter_name}"
            if self.occurrence:
                base += f"#{self.occurrence}"
        if self.workflow_state_id:
            base += f"@{self.workflow_state_id}"
        return base

    def to_dict(self) -> dict:
        return {"parameter_location": self.parameter_location,
                "parameter_name": self.parameter_name, "occurrence": self.occurrence,
                "workflow_state_id": self.workflow_state_id,
                "display_name": self.display_name}

    @classmethod
    def from_dict(cls, d: dict) -> "CaseKey":
        return cls(parameter_location=d.get("parameter_location", ""),
                   parameter_name=d.get("parameter_name", ""),
                   occurrence=int(d.get("occurrence", 0) or 0),
                   workflow_state_id=d.get("workflow_state_id", ""),
                   display_name=d.get("display_name", ""))


NO_PARAMETER_CASE = CaseKey()


def _json_pointers(obj, prefix: str = "") -> list[str]:
    """RFC 6901 JSON Pointers to every LEAF of a parsed JSON body (T05: nested
    body fields use JSON Pointer). `~` and `/` in a key are escaped `~0`/`~1`.
    An empty container is itself a testable leaf (you can send a value there)."""
    def esc(token: str) -> str:
        return token.replace("~", "~0").replace("/", "~1")
    out: list[str] = []
    if isinstance(obj, dict):
        if not obj:
            out.append(prefix or "/")
        for k, v in obj.items():
            out.extend(_json_pointers(v, f"{prefix}/{esc(str(k))}"))
    elif isinstance(obj, list):
        if not obj:
            out.append(prefix or "/")
        for i, v in enumerate(obj):
            out.extend(_json_pointers(v, f"{prefix}/{i}"))
    else:
        out.append(prefix or "")
    return out


def derive_input_cases(*, query: str = "", body: str = "", content_type: str = "",
                       headers: dict | None = None, object_id=None,
                       include_headers: bool = False,
                       workflow_state_id: str = "") -> list[CaseKey]:
    """Enumerate the concrete input CaseKeys a captured request actually exposes
    (T05). Deterministic and purely structural -- it reads the real query/body/
    headers, never invents a parameter that was not present. The caller decides
    which cases apply to which check (parameter-phase checks fan out over these;
    domain/endpoint checks use the single NO_PARAMETER_CASE).
    """
    cases: list[CaseKey] = []
    seen_coords: set[str] = set()

    def _add(ck: CaseKey) -> None:
        cid = ck.coord_id()
        if cid not in seen_coords:
            seen_coords.add(cid)
            cases.append(ck)

    # Query parameters -- occurrence identity for repeats (`?id=1&id=2`).
    occ_q: dict[str, int] = {}
    for name, _val in parse_qsl(query or "", keep_blank_values=True):
        occ = occ_q.get(name, 0)
        occ_q[name] = occ + 1
        _add(CaseKey("query", name, occ, workflow_state_id, name))

    # Request body -- JSON (pointer per leaf) or form-encoded (name + occurrence).
    body = body or ""
    ct = (content_type or "").lower()
    stripped = body.strip()
    looks_json = "json" in ct or (stripped[:1] in "{[" if stripped else False)
    if stripped and looks_json:
        try:
            parsed = json.loads(body)
            for ptr in _json_pointers(parsed):
                _add(CaseKey("body_json", ptr, 0, workflow_state_id, ptr))
        except (ValueError, TypeError):
            looks_json = False  # fall through to form parsing
    if stripped and not looks_json:
        if "urlencoded" in ct or ("=" in body and "\n" not in stripped):
            occ_f: dict[str, int] = {}
            for name, _val in parse_qsl(body, keep_blank_values=True):
                occ = occ_f.get(name, 0)
                occ_f[name] = occ + 1
                _add(CaseKey("body_form", name, occ, workflow_state_id, name))

    # Object identifier in the path (an IDOR/traversal input the URL carries).
    if object_id not in (None, ""):
        _add(CaseKey("path", "object_id", 0, workflow_state_id, str(object_id)))

    # Request headers (case-insensitive identity, original casing preserved).
    if include_headers and headers:
        for hname, _hval in headers.items():
            canon = (hname or "").lower()
            if not canon or canon in _NON_INPUT_HEADERS or canon.startswith(":"):
                continue
            _add(CaseKey("header", canon, 0, workflow_state_id, hname))

    return cases


def derive_input_cases_from_template(template: dict | None,
                                     workflow_state_id: str = "") -> list[CaseKey]:
    """Convenience over `derive_input_cases` for an endpoint `template` dict
    (engagement.template_from_exchange: method/query/body/content_type/object_id)."""
    template = template or {}
    from harness.models import body_is_placeholder
    body = template.get("body", "") or ""
    if body_is_placeholder(body):
        body = ""   # R11-9: the crawler's guess names no input of the endpoint
    cases = derive_input_cases(
        query=template.get("query", "") or "", body=body,
        content_type=template.get("content_type", "") or "",
        object_id=template.get("object_id"), workflow_state_id=workflow_state_id)
    # A client-side route (client_routes.py) adds the inputs page script reads: a
    # parameter of the fragment route ("route") or of the page query ("page"). A
    # page parameter the captured query already names is that query case.
    location, names = route_params_of_template(template)
    if location:
        have = {c.parameter_name for c in cases if c.parameter_location == "query"}
        for name in names:
            if location == PAGE and name in have:
                continue
            ck = CaseKey(location, name, 0, workflow_state_id, name)
            if all(c.coord_id() != ck.coord_id() for c in cases):
                cases.append(ck)
    # A router-declared `:name` segment of the route path (`/item/:id`).
    for name in route_segments_of_template(template):
        ck = CaseKey(SEGMENT, name, 0, workflow_state_id, name)
        if all(c.coord_id() != ck.coord_id() for c in cases):
            cases.append(ck)
    return cases


# ---------------------------------------------------------------------------
# Applicability predicates — shape-based, deterministic (I1/I5)
# ---------------------------------------------------------------------------

_CAPTURED_INPUT_LOCATIONS = frozenset({"query", "body_form", "body_json"})


def captured_parameter_names(endpoint: dict) -> list[str]:
    """`location:name` of every query, form or JSON-body parameter a capture of the
    endpoint carried (its template and each capture variant), blank values
    included: `?q=` names `q`. A JSON body's root container names no input."""
    templates = [endpoint.get("template")] + [
        (v or {}).get("template") for v in (endpoint.get("capture_variants") or [])]
    names: list[str] = []
    for tmpl in templates:
        if not isinstance(tmpl, dict):
            continue
        for case in derive_input_cases_from_template(tmpl):
            label = f"{case.parameter_location}:{case.parameter_name}"
            if (case.parameter_location in _CAPTURED_INPUT_LOCATIONS
                    and case.parameter_name not in ("", "/") and label not in names):
                names.append(label)
    return names
