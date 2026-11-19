"""
Deterministic WSTG/PortSwigger-Academy-driven coverage model.

The spine of the coverage engine (I1–I5 from the operator's expanded goal):

- **Check catalog**: a fixed, code-defined list of security checks, each tagged
  with a WSTG/Academy id, a phase (domain|endpoint|parameter — I4), a mapped
  vulnerability class, and a deterministic applicability predicate (I1/I5).
- **CoverageMatrix**: identity × endpoint × check, each cell recording an
  auditable status (I2/I5). Naturally memoises (item #4) and is the report
  substrate. Integrates with the existing EngagementState/validators rather
  than replacing them.
- **Check.confirmation**: how a check is confirmed — a deterministic leg/tool
  name where one exists (I3), else "agent" or "manual".

Every check declares WHY it applies or doesn't (the predicate's `reason`), so
"what was NOT tested and why" (I2/I5) is always answerable.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable
from urllib.parse import parse_qsl, urlsplit

from harness.categories import canonicalize
from harness.client_routes import (CLIENT_ROUTE_LEGS, PAGE, SEGMENT, route_params_of_template,
                                   route_segments_of_template)
from harness.wstg_ids import WSTG_RELEASE_LABEL, is_current_wstg_id


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


def _has_params(endpoint: dict) -> tuple[bool, str]:
    path = endpoint.get("path", "")
    if "?" in path or "{" in path or re.search(r"/\d+(?:/|$)", path):
        return True, "endpoint has parameters or path variables"
    # The endpoint key's path is normalized without its query, so a GET whose
    # captures carry `?q=` (even blank) was never read as taking input: r7's search
    # endpoint got no injection cell at all. The captured request decides.
    captured = captured_parameter_names(endpoint)
    if captured:
        return True, f"a captured request carries parameter(s) {', '.join(captured[:3])}"
    methods = endpoint.get("methods", ())
    if any(m in ("POST", "PUT", "PATCH") for m in methods):
        return True, "endpoint accepts body-bearing methods"
    return False, "no parameters or body-bearing methods detected"

def _accepts_input(endpoint: dict) -> tuple[bool, str]:
    has, reason = _has_params(endpoint)
    if has:
        return True, reason
    return False, "endpoint does not accept user-controllable input"

def _is_authed(endpoint: dict) -> tuple[bool, str]:
    access = endpoint.get("access", {})
    reachable = endpoint.get("reachable_roles", [])
    if access or reachable:
        return True, "endpoint has role/access data"
    return False, "no role/access information available"

def _is_object_scoped(endpoint: dict) -> tuple[bool, str]:
    if endpoint.get("object_scoped"):
        return True, "endpoint is object-scoped (e.g. /resource/{id})"
    path = endpoint.get("path", "")
    if re.search(r"/\{?id\}?|/\d+(?:/|$)", path):
        return True, "path contains an object identifier"
    return False, "not object-scoped"

def _accepts_xml(endpoint: dict) -> tuple[bool, str]:
    methods = endpoint.get("methods", ())
    if any(m in ("POST", "PUT", "PATCH") for m in methods):
        path = (endpoint.get("path", "") or "").lower()
        if any(k in path for k in ("import", "xml", "upload", "feed", "rss", "soap")):
            return True, "body-bearing method on an XML-associated path"
    return False, "no XML-accepting indicators"

def _has_url_param(endpoint: dict) -> tuple[bool, str]:
    path = endpoint.get("path", "")
    if "?" in path:
        return True, "endpoint has query parameters"
    lower = (path or "").lower()
    if any(k in lower for k in ("redirect", "url", "next", "return", "goto", "link",
                                 "forward", "continue", "callback", "proxy", "fetch")):
        return True, "path suggests URL/redirect parameter"
    return False, "no URL parameter indicators"

def _has_auth_endpoint(endpoint: dict) -> tuple[bool, str]:
    path = (endpoint.get("path", "") or "").lower()
    if any(k in path for k in ("login", "auth", "signin", "sign-in", "session",
                                "token", "oauth", "register", "signup", "sign-up",
                                "password", "reset", "mfa", "2fa", "verify")):
        return True, "authentication-related endpoint"
    return False, "not an authentication endpoint"

_LOOKUP_IDENTIFIERS = ("username", "user", "email", "login", "userid", "user_name")


def _has_auth_endpoint_or_lookup(endpoint: dict) -> tuple[bool, str]:
    """An auth endpoint, or a GET whose capture names an account in its query (a
    recovery lookup such as ?email=). R11-8 (c): r11 never opened the enumeration
    cell on a lookup whose path names no auth word."""
    hit, reason = _has_auth_endpoint(endpoint)
    if hit:
        return hit, reason
    if "GET" in (endpoint.get("methods") or ("GET",)) and any(
            name.lower() in {f"query:{k}" for k in _LOOKUP_IDENTIFIERS}
            for name in captured_parameter_names(endpoint)):
        return True, "a captured GET names an account identifier in its query"
    return False, reason


def _has_file_path_segment(endpoint: dict) -> tuple[bool, str]:
    path = endpoint.get("path", "")
    if re.search(r"/(upload|file|download|media|attachment|avatar|image|doc|asset)s?(/|$)", path, re.I):
        return True, "path suggests file handling"
    if re.search(r"/\d+(?:/|$)", path) and any(
            k in (path or "").lower() for k in ("upload", "file", "attachment", "media")):
        return True, "object-scoped file endpoint"
    return False, "no file-handling indicators"

def _always_applicable(_endpoint: dict) -> tuple[bool, str]:
    return True, "domain-level check (applies to all endpoints)"

def _has_cookie_or_session(endpoint: dict) -> tuple[bool, str]:
    if _has_auth_endpoint(endpoint)[0]:
        return True, "authentication endpoint likely involves sessions"
    access = endpoint.get("access", {})
    if access:
        return True, "endpoint has access-control data suggesting session use"
    return False, "no session/cookie indicators"

def _accepts_body(endpoint: dict) -> tuple[bool, str]:
    methods = endpoint.get("methods", ())
    if any(m in ("POST", "PUT", "PATCH") for m in methods):
        return True, "endpoint accepts body-bearing methods"
    return False, "endpoint does not accept request bodies"


def _accepts_create(endpoint: dict) -> tuple[bool, str]:
    methods = endpoint.get("methods", ())
    if "POST" in methods:
        return True, "endpoint accepts POST (a create)"
    return False, "endpoint accepts no POST create"


# --- WG-2: narrow predicates for the rows of already-registered validators. Each
# fires only where the exchange shape fits the validator's own oracle, so a new row
# does not add coverage-drive work on endpoints its leg would decline anyway.

def _query_and_body_keys(endpoint: dict) -> set[str]:
    """Lower-cased parameter names visible on the endpoint: the path's own query
    string plus the captured template's query and (form or JSON top-level) body."""
    template = endpoint.get("template") or {}
    path = endpoint.get("path", "") or ""
    keys = {k.lower() for k, _ in parse_qsl(urlsplit(path).query, keep_blank_values=True)}
    keys |= {k.lower() for k, _ in parse_qsl(template.get("query", "") or "",
                                             keep_blank_values=True)}
    body = template.get("body", "") or ""
    if body:
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            keys |= {k.lower() for k, _ in parse_qsl(body, keep_blank_values=True)}
        else:
            if isinstance(parsed, dict):
                keys |= {str(k).lower() for k in parsed}
    return keys

def _issues_session_cookie(endpoint: dict) -> tuple[bool, str]:
    headers = endpoint.get("response_headers") or {}
    if endpoint.get("sets_cookie") or any((k or "").lower() == "set-cookie" for k in headers):
        return True, "response sets a cookie"
    path = (endpoint.get("path", "") or "").lower()
    if any(k in path for k in ("login", "signin", "sign-in", "logon", "session")):
        return True, "login/session endpoint issues the session cookie"
    return False, "no Set-Cookie response or login/session endpoint"

def _is_websocket_endpoint(endpoint: dict) -> tuple[bool, str]:
    if endpoint.get("websocket") or (endpoint.get("upgrade") or "").lower() == "websocket":
        return True, "endpoint performs a WebSocket upgrade"
    path = (endpoint.get("path", "") or "").lower()
    if re.search(r"(^|/)(ws|wss|websockets?|socket\.io|sockjs|cable)(/|$|\?)", path):
        return True, "path is a WebSocket handshake endpoint"
    return False, "no WebSocket upgrade indicators"

_OAUTH_PARAMS = frozenset({"redirect_uri", "response_type", "client_id"})

def _has_oauth_params(endpoint: dict) -> tuple[bool, str]:
    if _query_and_body_keys(endpoint) & _OAUTH_PARAMS:
        return True, "request carries OAuth parameters (redirect_uri/response_type/client_id)"
    path = (endpoint.get("path", "") or "").lower()
    if "oauth" in path or re.search(r"/authorize(/|$|\?)", path):
        return True, "OAuth authorization endpoint"
    return False, "no OAuth parameters or authorization endpoint"

def _has_denied_role(endpoint: dict) -> tuple[bool, str]:
    access = endpoint.get("access") or {}
    if any(str(v) in ("401", "403", "405") for v in access.values()):
        return True, "a role is denied (401/403/405), so a verb alternate can be tested"
    return False, "no denied role recorded (verb tampering needs a denial to bypass)"

_CLIENT_VALUE_FIELD = re.compile(
    r"price|amount|total|cost|discount|quantity|qty|subtotal|fee|balance")
_CLIENT_VALUE_PATH = ("cart", "checkout", "basket", "order", "payment", "purchase")

def _flow_shape(kind: str):
    """A predicate: the endpoint's captured write has the business-flow shape `kind`."""
    def predicate(endpoint: dict) -> tuple[bool, str]:
        from harness.validators.business_flow_validator import endpoint_flow_kind
        got = endpoint_flow_kind(endpoint)
        if got == kind:
            return True, f"captured write has the {kind} flow shape"
        return False, f"no captured write with the {kind} flow shape"
    predicate.__name__ = f"_flow_shape_{kind}"
    return predicate


def _has_client_value_field(endpoint: dict) -> tuple[bool, str]:
    if not _accepts_body(endpoint)[0]:
        return False, "no body-bearing write to tamper"
    if any(_CLIENT_VALUE_FIELD.search(k) for k in _query_and_body_keys(endpoint)):
        return True, "write carries a client-supplied value field (price/amount/total)"
    body = (endpoint.get("template") or {}).get("body") or ""
    if body:
        # The leg's own recogniser (payment source, plan/tier, currency, coupon,
        # role/status flag), so the row applies wherever the leg has a field to tamper.
        from harness.validators.client_trust_validator import body_trust_fields
        found = body_trust_fields(body)
        if found:
            return True, f"write carries a server-owned {found[0].family} field ({found[0].key})"
    path = (endpoint.get("path", "") or "").lower()
    if any(k in path for k in _CLIENT_VALUE_PATH):
        return True, "write on a cart/checkout/order/payment path"
    return False, "no client-supplied value field on this write"

def _is_file_upload_write(endpoint: dict) -> tuple[bool, str]:
    # The file_upload leg skips any non-POST/PUT/PATCH exchange, so a file-handling
    # path alone (a GET /download/...) gives it nothing to run.
    if not _accepts_body(endpoint)[0]:
        return False, "no body-bearing write to upload through"
    has, reason = _has_file_path_segment(endpoint)
    if has:
        return True, f"body-bearing write; {reason}"
    return False, reason

def _is_get(endpoint: dict) -> tuple[bool, str]:
    if any(m in ("GET", "HEAD") for m in endpoint.get("methods", ())):
        return True, "GET response can be cached"
    return False, "not a GET/HEAD endpoint (not cached)"

def _is_authed_get(endpoint: dict) -> tuple[bool, str]:
    if not _is_get(endpoint)[0]:
        return False, "not a GET/HEAD endpoint (not cached)"
    if _is_authed(endpoint)[0]:
        return True, "authenticated GET content could be cached for another user"
    return False, "no role/access information (no per-user content to deceive a cache with)"


# Predicate type: endpoint dict → (applicable: bool, reason: str)
ApplicabilityPredicate = Callable[[dict], tuple[bool, str]]


# ---------------------------------------------------------------------------
# Check — one entry in the catalog
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExternalRef:
    """An independently-verified external reference for a check.

    Kept structured (not a bare string) so a report can distinguish a genuine WSTG
    test id from an OWASP-API entry or an Academy topic, and so we never encode a
    catalog id we cannot stand behind. `catalog` names the source (e.g. "WSTG",
    "OWASP API Security Top 10 2023", "PortSwigger Academy"); `ref` is the id within
    it (e.g. "WSTG-INJT-05", "API3:2023") or "" for a URL-only reference."""
    catalog: str
    ref: str = ""
    url: str = ""
    title: str = ""
    version: str = ""


@dataclass(frozen=True)
class Check:
    """A single security check in the catalog.

    The `id` is the check's PRIMARY identifier. For checks that map cleanly onto a
    WSTG test it is the current WSTG id (WG-1: checked against the vendored list in
    `harness/wstg_ids.py`; `wstg_version` names the release it is anchored to). For a
    scenario with NO clean WSTG mapping it is an INTERNAL `AV-*` id, and the real
    external sources live in `external_refs` -- so the catalog never falsely labels a
    scenario with a WSTG id that means something else. IDs the catalog used before
    WG-1 resolve through `LEGACY_CHECK_ID_ALIASES`. WSTG and Academy are *reference
    catalogs* here, not an exploitation runner.
    """
    id: str                              # e.g. "WSTG-INJT-05" or an internal "AV-*" id
    name: str                            # human-readable
    phase: Phase
    vulnerability_class: str             # maps to categories.canonicalize
    applicability: ApplicabilityPredicate
    confirmation: str                    # "sqlmap" | "cross_identity" | "agent" | "manual" | ...
    description: str = ""
    academy_ref: str = ""                # PortSwigger Academy topic name if applicable
    academy_url: str = ""                # optional full Academy topic URL (scenario reference)
    wstg_version: str = WSTG_RELEASE_LABEL   # the WSTG release a genuine WSTG id is anchored to
    external_refs: tuple[ExternalRef, ...] = ()   # independently-verified external sources
    origin_scoped: bool = False  # A transport/deployment fact, not a response policy.
    # WG-2 (4): finding-class tokens (lower-case; space and snake forms) that pick out
    # THIS row among the rows sharing its canonical class, so one finding is attributed
    # to the one cell it names, not to every sibling. Required on every row of a shared
    # class (`shared_class_specificity_problems`); no token may sit on two rows.
    specific_classes: tuple[str, ...] = ()
    # WG-2 (3): the class the coverage driver hands the leg. Empty = vulnerability_class.
    # Lets a shared-class row route to its own sub-check (e.g. auth_sequence's enum leg).
    leg_class: str = ""

    def applies(self, endpoint: dict) -> tuple[bool, str]:
        """Deterministic applicability + the rationale for WHY it applies or doesn't.

        A client-side route input (client_routes.py) is loaded in a browser, so it
        applies to the browser XSS legs only. A route the run knows only from the
        page (no captured request of its own) is that leg's endpoint alone."""
        location, names = route_params_of_template(endpoint.get("template"))
        names = names + [":" + s for s in route_segments_of_template(endpoint.get("template"))]
        if endpoint.get("client_route_only"):
            if self.confirmation in CLIENT_ROUTE_LEGS and names:
                return True, (f"client-side route reads {location} parameter(s) "
                              f"{', '.join(names[:3])}")
            return False, "client-side route: only the browser XSS legs load it"
        applicable, reason = self.applicability(endpoint)
        if not applicable and self.confirmation in CLIENT_ROUTE_LEGS and names:
            return True, (f"client-side route reads {location} parameter(s) "
                          f"{', '.join(names[:3])}")
        return applicable, reason

    def canonical_class(self) -> str | None:
        return canonicalize(self.vulnerability_class)

    def is_wstg(self) -> bool:
        """Whether the primary id is a genuine WSTG test id."""
        return self.id.startswith("WSTG-")

    def reference_label(self) -> str:
        """A human label for the primary id: versioned for a genuine WSTG id, else the
        internal id marked as such (external sources are in `external_refs`)."""
        if self.is_wstg():
            # A numbered release reads "WSTG v4.2"; the unnumbered master set reads
            # "WSTG latest" (never "vlatest").
            version = self.wstg_version
            prefix = "v" if version[:1].isdigit() else ""
            return f"{self.id} (WSTG {prefix}{version})"
        return f"{self.id} (internal scenario)"

    # Back-compat alias; only meaningful for genuine WSTG ids.
    def wstg_ref(self) -> str:
        return self.reference_label()


# ---------------------------------------------------------------------------
# The catalog — the fixed check list (I1)
# ---------------------------------------------------------------------------

CHECK_CATALOG: tuple[Check, ...] = (
    # === DOMAIN phase ===
    Check("WSTG-CRYP-01", "TLS/SSL configuration", Phase.DOMAIN,
          "crypto", _always_applicable, "crypto",
          "Verify TLS versions, cipher suites, certificate validity",
          "Server-side TLS", origin_scoped=True,
          specific_classes=(
              "tls", "ssl", "ssl/tls", "weak tls", "weak_tls", "tls configuration",
              "tls_configuration", "tls misconfiguration", "tls_misconfiguration",
              "weak cipher", "weak_cipher", "weak ciphers", "weak_ciphers",
          )),
    Check("WSTG-CONF-07", "HTTP Strict Transport Security", Phase.DOMAIN,
          "misconfig", _always_applicable, "crypto",
          "Check HSTS header presence and configuration",
          specific_classes=(
              "hsts", "missing hsts", "missing_hsts", "strict transport security",
              "strict-transport-security", "strict_transport_security",
              "http strict transport security", "http_strict_transport_security",
          )),
    # WG-2: CONF-12 is the natural primary row for a bare "csp" finding (it names the
    # policy itself), so "csp" is one of its specific_classes; framing goes to CLNT-09.
    Check("WSTG-CONF-12", "Content Security Policy", Phase.DOMAIN,
          "csp", _always_applicable, "csp",
          "Evaluate CSP header directives",
          "Content security policy",
          specific_classes=(
              "csp", "content security policy", "content_security_policy", "missing csp",
              "missing_csp", "weak csp", "weak_csp", "csp bypass", "csp_bypass",
          )),
    Check("WSTG-CLNT-07", "CORS policy", Phase.DOMAIN,
          "cors", _always_applicable, "cors",
          "Test Cross-Origin Resource Sharing configuration",
          "CORS"),
    Check("WSTG-INFO-02", "Server fingerprinting", Phase.DOMAIN,
          "recon", _always_applicable, "recon",
          "Identify web server software and version",
          specific_classes=(
              "server fingerprinting", "server_fingerprinting", "web server fingerprinting",
              "fingerprinting", "server banner", "server_banner", "banner grabbing",
              "version disclosure", "version_disclosure", "technology fingerprinting",
          )),
    Check("WSTG-INFO-05", "Information in comments/metadata", Phase.DOMAIN,
          "info_disclosure", _always_applicable, "recon",
          "Check for sensitive data in HTML comments, headers, metadata",
          specific_classes=(
              "html comments", "html_comments", "information in comments",
              "information_in_comments", "sensitive comments", "sensitive_comments",
              "source code comments", "source_code_comments", "metadata", "metadata leakage",
              "metadata_leakage",
          )),
    Check("WSTG-CONF-06", "HTTP methods", Phase.DOMAIN,
          "misconfig", _always_applicable, "recon",
          "Test which HTTP methods are enabled",
          specific_classes=(
              "http methods", "http_methods", "dangerous http methods",
              "dangerous_http_methods", "unsafe http methods", "unsafe_http_methods", "trace",
              "trace method", "trace_method", "http trace", "http_trace", "trace enabled",
              "trace_enabled", "cross-site tracing", "cross_site_tracing", "xst",
          )),
    # The passive security_headers adapter (main, dbb0dab7) judges this row; WG-1
    # moved it from v4.2 CONF-02 to current CONF-14.
    Check("WSTG-CONF-14", "Security headers", Phase.DOMAIN,
          "misconfig", _always_applicable, "security_headers",
          "Check the captured response's X-Content-Type-Options and Referrer-Policy "
          "(CSP: WSTG-CONF-12; framing: WSTG-CLNT-09; HSTS: WSTG-CONF-07)",
          specific_classes=(
              "security headers", "security_headers", "security header", "security_header",
              "missing security headers", "missing_security_headers",
              "missing security header", "missing_security_header", "x-content-type-options",
              "x_content_type_options",
          )),
    # WG-2: the csp validator also audits framing (X-Frame-Options / CSP
    # frame-ancestors); phased and scoped like its CONF-12 sibling.
    Check("WSTG-CLNT-09", "Clickjacking", Phase.DOMAIN,
          "clickjacking", _always_applicable, "csp",
          "Check that responses forbid framing (X-Frame-Options or CSP frame-ancestors)",
          "Clickjacking",
          specific_classes=(
              "clickjacking", "click jacking", "click_jacking", "x-frame-options",
              "x_frame_options", "missing x-frame-options", "missing_x_frame_options",
              "frame-ancestors", "frame_ancestors", "ui redressing", "ui_redressing",
          )),
    # WG-2: host-level like CRYP-01; the subdomain_takeover validator checks dangling
    # DNS / unclaimed-service fingerprints for the engagement's hosts.
    Check("WSTG-CONF-10", "Subdomain takeover", Phase.DOMAIN,
          "subdomain_takeover", _always_applicable, "subdomain_takeover",
          "Check in-scope hosts for dangling DNS records pointing at unclaimed services"),
    # The genuine WSTG-CONF-09. It is a host/deployment file-permission review, not
    # something a black-box HTTP client can confirm -- so it is a MANUAL check.
    Check("WSTG-CONF-09", "Test File Permission", Phase.DOMAIN,
          "misconfig", _always_applicable, "manual",
          "Verify server files/directories use least privilege (config, key material, "
          "backups, source not world-readable/writable). Requires host access.",
          external_refs=(
              ExternalRef("WSTG", "WSTG-CONF-09",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/"
                          "4-Web_Application_Security_Testing/"
                          "02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission",
                          "Test File Permission", version="4.2"),
          ), origin_scoped=True,
          specific_classes=(
              "file permission", "file_permission", "file permissions", "file_permissions",
              "insecure file permissions", "insecure_file_permissions",
          )),

    # === ENDPOINT phase ===
    # WG-2: ATHZ-04 is the natural primary row for a bare "idor" finding; BFLA and
    # function-level wording names ATHZ-02. The tokens include coverage_tracker's
    # access-control free-text words, which resolve through specific_classes too.
    Check("WSTG-ATHZ-04", "IDOR / Broken Object-Level Authorization", Phase.ENDPOINT,
          "idor", _is_object_scoped, "cross_identity",
          "Test access to other users' objects by varying identifiers",
          "Insecure direct object references (IDOR)",
          specific_classes=(
              "idor", "bola", "broken object level authorization",
              "broken_object_level_authorization", "insecure direct object reference",
              "insecure_direct_object_reference", "insecure direct object references",
              "insecure_direct_object_references", "object level authorization",
              "object_level_authorization", "object-level", "object level",
              "insecure direct object",
          )),
    Check("WSTG-ATHZ-02", "Broken Function-Level Authorization", Phase.ENDPOINT,
          "idor", _is_authed, "cross_identity",
          "Access admin/privileged functions as a lower-privilege user",
          "Access control vulnerabilities",
          specific_classes=(
              "bfla", "broken function level authorization",
              "broken_function_level_authorization", "function level authorization",
              "function_level_authorization", "function-level", "function level",
              "broken function", "broken_function",
          )),
    # WG-2: the five rows of class "auth" have no primary row: a bare "auth" finding
    # is attributed to none of them as CONFIRMED. Tokens come from auth_sequence's
    # finding_classes; leg_class routes the driver to the matching sub-check.
    Check("WSTG-ATHN-04", "Authentication bypass", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "auth_sequence",
          "Test for authentication bypass techniques",
          "Authentication vulnerabilities",
          specific_classes=(
              "authentication bypass", "authentication_bypass", "auth bypass", "auth_bypass",
              "login bypass", "login_bypass", "bypass authentication",
              "bypass_authentication",
          )),
    Check("WSTG-ATHN-07", "Weak password policy", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "auth_sequence",
          "Test password complexity requirements",
          "Authentication vulnerabilities",
          specific_classes=(
              "weak_password", "weak password", "weak passwords", "weak_passwords",
              "weak password policy", "weak_password_policy", "password policy",
              "password_policy",
          ),
          leg_class="weak_password"),
    # WG-2: auth_sequence's username-enumeration and second-factor legs. Every row
    # class must canonicalize, and no canonical class or synonym names enumeration
    # or MFA, so both carry "auth" like ATHN-04/07. The coverage driver passes that
    # class to the leg, which routes bare "auth" to no check; a narrower synonym in
    # categories.py is the follow-up that lets the driver fire these legs.
    Check("WSTG-IDNT-04", "Account enumeration", Phase.ENDPOINT,
          "auth", _has_auth_endpoint_or_lookup, "auth_sequence",
          "Test whether login/registration/reset responses distinguish existing from "
          "unknown usernames",
          "Authentication vulnerabilities",
          specific_classes=(
              "username_enumeration", "username enumeration", "user enumeration",
              "user_enumeration", "account enumeration", "account_enumeration",
              "email enumeration", "email_enumeration",
          ),
          leg_class="username_enumeration"),
    Check("WSTG-ATHN-11", "Multi-factor authentication", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "auth_sequence",
          "Test whether a session that passed only the first factor reaches pages the "
          "second factor gates",
          "Authentication vulnerabilities",
          specific_classes=(
              "2fa_bypass", "2fa bypass", "mfa_bypass", "mfa bypass", "two_factor_bypass",
              "two-factor bypass", "two factor bypass", "multi_factor_bypass",
              "multi-factor bypass", "multi factor bypass", "second factor bypass",
              "second_factor_bypass", "mfa", "2fa", "multi-factor authentication",
              "multi_factor_authentication", "two-factor authentication",
              "two_factor_authentication",
          ),
          leg_class="2fa_bypass"),
    Check("WSTG-ATHN-03", "Weak lockout mechanism", Phase.ENDPOINT,
          "rate_limit", _has_auth_endpoint, "rate_limit",
          "Test account lockout / rate limiting after repeated attempts",
          "Authentication vulnerabilities"),
    Check("WSTG-ATHN-09", "Weak password-reset token", Phase.ENDPOINT,
          "reset_token", _has_auth_endpoint, "reset_token",
          "Test password-reset tokens for predictability (sequential, timestamp, "
          "below-entropy-floor, or derived from a known value)",
          "Authentication vulnerabilities"),
    # WG-2: SESS-01's deterministic check is token predictability
    # (reset_token_validator.analyze_tokens), so it confirms via reset_token, not
    # auth_sequence. That leg replays a token-issuing POST to sample tokens, so the
    # row is scoped to auth endpoints like ATHN-09, not every session-bearing one.
    Check("WSTG-SESS-01", "Session management", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "reset_token",
          "Test issued tokens for predictability (sequential, timestamp-derived, "
          "below the entropy floor, or derived from a known value)",
          "Authentication vulnerabilities",
          specific_classes=(
              "session management", "session_management", "broken session management",
              "broken_session_management", "session management schema",
              "session token predictability", "session_token_predictability",
              "predictable session token", "predictable_session_token",
              "predictable session id", "predictable_session_id", "weak session token",
              "weak_session_token",
          ),
          leg_class="token entropy"),
    Check("WSTG-SESS-02", "Cookie attributes", Phase.ENDPOINT,
          "crypto", _issues_session_cookie, "crypto",
          "Audit Set-Cookie for the Secure, HttpOnly and SameSite attributes",
          specific_classes=(
              "cookie attributes", "cookie_attributes", "insecure cookie", "insecure_cookie",
              "insecure cookie attributes", "insecure_cookie_attributes", "cookie flags",
              "cookie_flags", "cookie security", "cookie_security", "secure flag",
              "secure_flag", "missing secure flag", "missing_secure_flag", "httponly",
              "httponly flag", "httponly_flag", "missing httponly", "missing_httponly",
              "samesite", "samesite flag", "samesite_flag", "missing samesite",
              "missing_samesite",
          )),
    Check("WSTG-SESS-03", "Session fixation", Phase.ENDPOINT,
          "session_fixation", _has_auth_endpoint, "auth_sequence",
          "Test if session tokens are regenerated after login"),
    # WG-3: auth_sequence's logout leg (session_timeout class) mints a fresh throwaway
    # login from a captured login and never logs the operator out, so the row is
    # scoped to auth endpoints like SESS-03. Idle/absolute timeout (SESS-07) has no leg.
    Check("WSTG-SESS-06", "Logout functionality", Phase.ENDPOINT,
          "session_timeout", _has_auth_endpoint, "auth_sequence",
          "Test whether logout invalidates the session server-side (the pre-logout "
          "cookie must stop reaching authenticated pages)"),
    # The file_upload leg uploads only a BENIGN disallowed-extension (.html) file and
    # checks it is stored and served back: BUSL-08 (unexpected file types). In
    # scheme-1 data (pre-WG-1, unmarked) "WSTG-BUSL-08" meant the TOCTOU row and still
    # resolves to ATHZ-03; see CHECK_ID_SCHEME and REUSED_LEGACY_IDS.
    Check("WSTG-BUSL-08", "Upload of unexpected file types", Phase.ENDPOINT,
          "file_upload", _is_file_upload_write, "file_upload",
          "Upload a benign file of a disallowed type (.html) and check whether the "
          "server stores it and serves it back as an active context",
          "File upload vulnerabilities",
          specific_classes=(
              "unrestricted file upload", "unrestricted_file_upload",
              "upload of unexpected file types", "upload_of_unexpected_file_types",
              "unexpected file type", "unexpected_file_type", "unexpected file types",
              "unexpected_file_types", "disallowed file type", "disallowed_file_type",
              "file type bypass", "file_type_bypass", "file extension bypass",
              "file_extension_bypass", "upload filter bypass", "upload_filter_bypass",
          )),
    # BUSL-09 is malicious-file upload and stays manual; the benign leg is BUSL-08.
    Check("WSTG-BUSL-09", "File upload", Phase.ENDPOINT,
          "file_upload", _has_file_path_segment, "manual",
          "Test upload endpoints against malicious files (manual). The benign "
          "disallowed-extension leg (file_upload) belongs to WSTG-BUSL-08.",
          "File upload vulnerabilities",
          specific_classes=(
              "malicious file upload", "malicious_file_upload", "upload of malicious files",
              "upload_of_malicious_files", "malicious file", "malicious_file",
              "webshell upload", "webshell_upload", "web shell upload", "web_shell_upload",
              "malware upload", "malware_upload", "eicar",
          )),
    Check("WSTG-ATHZ-01", "Path traversal", Phase.ENDPOINT,
          "path_traversal", _has_file_path_segment, "path_traversal",
          "Test for directory traversal in file-serving endpoints",
          "Path traversal",
          specific_classes=(
              "path traversal", "path_traversal", "directory traversal",
              "directory_traversal", "file path traversal", "dot dot slash", "lfi",
              "local file inclusion", "arbitrary file read",
          )),
    Check("WSTG-ERRH-01", "Error handling / stack traces", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "error_handling",
          "Check captured error responses for stack traces and framework error pages "
          "(passive: errors are not provoked)",
          specific_classes=(
              "verbose_error", "verbose error", "verbose errors", "verbose_errors",
              "verbose_error_disclosure", "verbose error disclosure", "stack_trace",
              "stack trace", "stack trace disclosure", "stack_trace_disclosure", "debug_info",
              "debug info", "debug_mode", "debug mode", "error_disclosure",
              "error disclosure", "error handling", "error_handling",
              "improper error handling", "improper_error_handling",
          )),
    # r5: /ftp, /metrics and whoami?callback= only met recon (WSTG-INFO-05), which is
    # not a verdict. No single WSTG v4.2 test owns these, so the id is internal.
    Check("AV-EXPOSURE-01", "Directory index, metrics or JSONP exposure", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "content_exposure",
          "Check captured 2xx responses for a directory index, a Prometheus metrics "
          "exposition or a JSONP callback wrapper (passive: nothing is sent)",
          external_refs=(
              ExternalRef("WSTG", "WSTG-CONF-04",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/"
                          "4-Web_Application_Security_Testing/"
                          "02-Configuration_and_Deployment_Management_Testing/"
                          "04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                          "Review Old Backup and Unreferenced Files for Sensitive Information",
                          version="4.2"),
              ExternalRef("CWE", "CWE-548", "https://cwe.mitre.org/data/definitions/548.html",
                          "Exposure of Information Through Directory Listing"),
          ),
          specific_classes=(
              "content_exposure", "content exposure", "jsonp", "jsonp exposure",
              "jsonp_exposure", "jsonp callback", "jsonp_callback",
          )),
    # r9: the model raised listing, backup and metrics leads that no leg decided, and
    # AV-EXPOSURE-01 judged the same captures with no exchange behind its verdict.
    # These legs send GETs (validators.active_enabled) and keep the exchanges as proof.
    # Their shape gate (a listing / an exposition) is in capability_for_check.
    Check("AV-EXPOSURE-02", "Sensitive files served from a directory listing", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "listing_exposure",
          "When a captured 2xx response is a directory listing (HTML index or JSON file "
          "list), GET each listed file and classify its content: backups, configuration, "
          "keys and keystores, credentials, documents marked confidential, data dumps, "
          "package manifests",
          external_refs=(
              ExternalRef("WSTG", "WSTG-CONF-04",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/"
                          "4-Web_Application_Security_Testing/"
                          "02-Configuration_and_Deployment_Management_Testing/"
                          "04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                          "Review Old Backup and Unreferenced Files for Sensitive Information",
                          version="4.2"),
              ExternalRef("CWE", "CWE-530", "https://cwe.mitre.org/data/definitions/530.html",
                          "Exposure of Backup File to an Unauthorized Control Sphere"),
              ExternalRef("CWE", "CWE-538", "https://cwe.mitre.org/data/definitions/538.html",
                          "Insertion of Sensitive Information into Externally-Accessible File or Directory"),
          ),
          specific_classes=(
              "listing_exposure", "directory listing", "directory_listing",
              "directory indexing", "directory_indexing", "exposed_directory_listing",
              "directory index",
          )),
    Check("AV-FILTER-01", "File-extension filter bypass (NUL encoding)", Phase.ENDPOINT,
          "path_filter_bypass", _always_applicable, "filter_bypass",
          "When a directory listing names a file the server refuses while it serves a "
          "sibling, GET the refused name with a NUL encoding before an allowed extension "
          "(name%2500.ext, name%00.ext). Positive control: the same encoding on a served "
          "listed file returns its exact bytes. Negative control: on a nonexistent name it "
          "returns no file",
          external_refs=(
              ExternalRef("CWE", "CWE-158", "https://cwe.mitre.org/data/definitions/158.html",
                          "Improper Neutralization of Null Byte or NUL Character"),
              ExternalRef("CWE", "CWE-20", "https://cwe.mitre.org/data/definitions/20.html",
                          "Improper Input Validation"),
          ),
          specific_classes=(
              "path_filter_bypass", "filter_bypass", "extension_filter_bypass",
              "null_byte_injection", "poison_null_byte", "null byte",
          )),
    Check("AV-EXPOSURE-03", "Metrics endpoint exposed without authentication", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "metrics_exposure",
          "When a captured 2xx response is a metrics exposition, GET it without "
          "credentials (must still be an exposition) and GET a nonexistent sibling (must "
          "not be one); record the families, label keys and versions it reveals",
          external_refs=(
              ExternalRef("CWE", "CWE-200", "https://cwe.mitre.org/data/definitions/200.html",
                          "Exposure of Sensitive Information to an Unauthorized Actor"),
              ExternalRef("CWE", "CWE-306", "https://cwe.mitre.org/data/definitions/306.html",
                          "Missing Authentication for Critical Function"),
          ),
          specific_classes=(
              "metrics_exposure", "metrics exposure", "exposed_metrics_endpoint",
              "public_metrics_endpoint", "unauthenticated_metrics",
          )),
    Check("AV-EXPOSURE-04", "Sensitive file served without authentication", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "sensitive_file",
          "When a captured 2xx GET is a single file whose name and content classify as "
          "sensitive (backup, key, credentials, dump, confidential document, manifest), GET "
          "it without credentials (must still classify) and GET a nonexistent sibling with "
          "the same extension (must not serve it); file values are never recorded",
          external_refs=(
              ExternalRef("CWE", "CWE-538", "https://cwe.mitre.org/data/definitions/538.html",
                          "Insertion of Sensitive Information into Externally-Accessible File or Directory"),
              ExternalRef("CWE", "CWE-530", "https://cwe.mitre.org/data/definitions/530.html",
                          "Exposure of Backup File to an Unauthorized Control Sphere"),
          ),
          specific_classes=(
              "sensitive_file", "exposed_backup_file", "config_file_exposure",
              "exposed_configuration", "credential_exposure",
              "confidential_document_exposure", "exposed_file",
          )),
    Check("AV-WELLKNOWN-01", "security.txt and CSAF provider metadata", Phase.DOMAIN,
          "recon", _always_applicable, "well_known",
          "Once per origin, GET /.well-known/security.txt (RFC 9116) and "
          "/.well-known/csaf/provider-metadata.json; what is published is an observation, "
          "not a vulnerability",
          external_refs=(
              ExternalRef("RFC", "RFC 9116", "https://www.rfc-editor.org/rfc/rfc9116",
                          "A File Format to Aid in Security Vulnerability Disclosure"),
              ExternalRef("OASIS", "CSAF 2.0",
                          "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html",
                          "Common Security Advisory Framework Version 2.0"),
          ), origin_scoped=True,
          specific_classes=(
              "well_known", "well known", "security.txt", "security_txt", "csaf",
              "csaf_provider_metadata",
          )),
    # Mass assignment had NO WSTG v4.2 test, so it carried the internal id
    # AV-MASSASSIGN-01 (still an alias); current WSTG adds it as INJT-20. The
    # API-layer sources stay in external_refs. See coverage_manifest.
    Check("WSTG-INJT-20", "Mass assignment (server-controlled field protection)", Phase.ENDPOINT,
          "api_security", _accepts_body, "sequence",
          "An ordinary update must not let a client set server-controlled fields "
          "(role, is_admin, balance); send those fields and verify they do not persist.",
          academy_ref="Mass assignment",
          external_refs=(
              ExternalRef("PortSwigger Academy", "",
                          "https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerabilities",
                          "Exploiting mass assignment vulnerabilities"),
              ExternalRef("OWASP API Security Top 10 2023", "API3:2023",
                          "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                          "Broken Object Property Level Authorization (subsumes mass assignment)"),
              ExternalRef("OWASP API Security Top 10 2019", "API6:2019",
                          "https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/",
                          "Mass Assignment"),
          ),
          specific_classes=(
              "mass assignment", "mass_assignment", "mass assignment update",
              "mass_assignment_update",
          )),
    Check("WSTG-INJT-16", "HTTP request smuggling", Phase.ENDPOINT,
          "http_request_smuggling", _accepts_body, "http_request_smuggling",
          "Test CL/TE and TE/CL desync",
          "HTTP request smuggling"),
    Check("WSTG-INJT-15", "HTTP header injection / CRLF", Phase.ENDPOINT,
          "header_injection", _accepts_input, "header_injection",
          "Inject CRLF sequences in header-reflected parameters"),
    # WSTG-SESS-05 is the current WSTG id for CSRF (was mislabelled SESS-09 --
    # weakness #7). WG-2: the row names the registered csrf leg, which runs the
    # token-strip/SameSite property check. Its verdict is still retired to an
    # observation (ORACLE_RETIREMENTS.md), so a CONFIRMED CSRF needs a browser PoC;
    # the manifest keeps the manual aspect for that.
    Check("WSTG-SESS-05", "CSRF", Phase.ENDPOINT,
          "csrf", _accepts_body, "csrf",
          "Test state-changing requests for anti-CSRF protections",
          "Cross-site request forgery (CSRF)"),
    # WG-2 rows for registered validators that had none.
    Check("WSTG-ATHZ-05", "OAuth weaknesses", Phase.ENDPOINT,
          "oauth", _has_oauth_params, "oauth",
          "Test OAuth flows for redirect_uri validation, state/PKCE and token leakage",
          "OAuth authentication"),
    Check("WSTG-CLNT-10", "WebSockets", Phase.ENDPOINT,
          "websocket", _is_websocket_endpoint, "websocket",
          "Test whether the WebSocket handshake accepts a cross-origin Origin "
          "(cross-site WebSocket hijacking)",
          "WebSockets"),
    # WG-2: "http method" (singular) is a verb_tamper_validator finding class, so it
    # names this row; the plural "http methods" / TRACE wording names CONF-06.
    Check("WSTG-INJT-03", "HTTP verb tampering", Phase.ENDPOINT,
          "misconfig", _has_denied_role, "verb_tamper",
          "Replay a denied request with read-only method alternates and override headers",
          specific_classes=(
              "verb tamper", "verb_tamper", "verb tampering", "verb_tampering",
              "http verb tampering", "http_verb_tampering", "method tampering",
              "method_tampering", "http method", "http_method", "method override",
              "method_override",
          )),
    Check("WSTG-BUSL-02", "Ability to forge requests", Phase.ENDPOINT,
          "business_logic", _has_client_value_field, "client_trust",
          "Tamper a server-owned value field (price/amount/total) and check whether an "
          "independent read reflects it",
          "Business logic vulnerabilities",
          specific_classes=(
              "client_trust", "client trust", "client-side controls", "client_side_controls",
              "price manipulation", "price_manipulation", "excessive trust",
          )),
    # The web_cache_poisoning validator has two legs: an unkeyed X-Forwarded-Host
    # reflection (host header injection) and a static-suffix cache-deception probe
    # (path confusion).
    Check("WSTG-INJT-17", "Host header injection", Phase.ENDPOINT,
          "web_cache_poisoning", _is_get, "web_cache_poisoning",
          "Test whether X-Forwarded-Host / Host values are reflected into cacheable responses",
          "Web cache poisoning",
          specific_classes=(
              "host header injection", "host_header_injection", "host header poisoning",
              "host_header_poisoning", "x-forwarded-host", "x_forwarded_host",
              "unkeyed header", "unkeyed_header",
          )),
    Check("WSTG-CONF-13", "Path confusion", Phase.ENDPOINT,
          "web_cache_poisoning", _is_authed_get, "web_cache_poisoning",
          "Test whether a static-looking path suffix makes authenticated content cacheable "
          "(web cache deception)",
          "Web cache deception",
          specific_classes=(
              "cache deception", "cache_deception", "web cache deception",
              "web_cache_deception", "path confusion", "path_confusion",
          )),

    # === PARAMETER phase ===
    Check("WSTG-INJT-05", "SQL injection", Phase.PARAMETER,
          "sqli", _accepts_input, "sqlmap",
          "Test all input parameters for SQL injection",
          "SQL injection"),
    Check("WSTG-INJT-01", "Reflected XSS", Phase.PARAMETER,
          "xss", _accepts_input, "browser_xss",
          "Test input reflection in HTML responses for script injection",
          "Cross-site scripting (XSS)",
          specific_classes=(
              "reflected xss", "reflected_xss", "reflected cross-site scripting",
              "reflected_cross_site_scripting", "non-persistent xss",
          )),
    Check("WSTG-INJT-02", "Stored XSS", Phase.PARAMETER,
          "xss", _accepts_body, "stored_xss",
          "Test stored input rendered in HTML context",
          "Stored cross-site scripting",
          specific_classes=(
              "stored xss", "stored_xss", "persistent xss", "persistent_xss",
              "second order xss", "second_order_xss", "stored cross-site scripting",
              "stored_cross_site_scripting",
          )),
    Check("WSTG-CLNT-01", "DOM-based XSS", Phase.PARAMETER,
          "dom_xss", _accepts_input, "dom_xss",
          "Test client-side sources (location.hash/.search) flowing to a DOM sink",
          "DOM-based cross-site scripting"),
    Check("WSTG-INJT-12", "Command injection", Phase.PARAMETER,
          "command_injection", _accepts_input, "command_injection",
          "Test for OS command injection in parameters",
          "OS command injection"),
    Check("WSTG-INJT-18", "Server-side template injection", Phase.PARAMETER,
          "ssti", _accepts_input, "ssti",
          "Test for template expression evaluation",
          "Server-side template injection (SSTI)"),
    Check("WSTG-INJT-07", "XXE", Phase.PARAMETER,
          "xxe", _accepts_xml, "xxe",
          "Test XML-accepting endpoints for external entity processing",
          "XML external entity (XXE) injection"),
    Check("WSTG-INJT-19", "SSRF", Phase.PARAMETER,
          "ssrf", _has_url_param, "ssrf",
          "Test URL parameters for server-side request forgery",
          "Server-side request forgery (SSRF)"),
    # WSTG has no server-side open-redirect test; CLNT-04 (Client-side URL Redirect)
    # is the closest. NoSQL is the INJT-05 sub-test 05.6, so it cannot collide with
    # the SQL-injection row.
    Check("WSTG-CLNT-04", "Open redirect", Phase.PARAMETER,
          "open_redirect", _has_url_param, "open_redirect",
          "Test redirect parameters for off-site redirection",
          "Open redirection"),
    Check("WSTG-INJT-05.6", "NoSQL injection", Phase.PARAMETER,
          "nosql", _accepts_input, "nosql",
          "Test for NoSQL query manipulation",
          "NoSQL injection"),
    Check("WSTG-SESS-10", "JWT weaknesses", Phase.PARAMETER,
          "jwt", _is_authed, "jwt_forge",
          "Test JWT algorithm confusion, key disclosure, claim tampering",
          "JWT attacks"),
    Check("WSTG-INJT-23", "Insecure deserialization", Phase.PARAMETER,
          "deserialization", _accepts_body, "deserialization_oob",
          "Test for unsafe deserialization of user-supplied data",
          "Insecure deserialization"),
    Check("WSTG-BUSL-05", "Race conditions", Phase.PARAMETER,
          "race_condition", _accepts_body, "race_condition",
          "Test for TOCTOU and concurrent-request bugs",
          "Race conditions"),
    # The TOCTOU row confirms a privilege field flipped, so it is ATHZ-03 (Privilege
    # Escalation); BUSL-05 is already the generic race row above.
    Check("WSTG-ATHZ-03", "TOCTOU privilege-escalation race", Phase.ENDPOINT,
          "toctou", _accepts_body, "toctou",
          "Concurrent copies of an authority-changing write race a check-then-write "
          "window; confirm a privilege field flipped under concurrency via re-read",
          "Race conditions"),
    # Write-path checks (write_integrity): each create is answered by a plain-create
    # control, read back by every registered identity, and DELETEd again before the
    # verdict; a path with no restore route is skipped, never written.
    Check("AV-WRITE-XID-01", "Cross-identity write (another principal's object referenced)",
          Phase.ENDPOINT, "cross_identity_write", _accepts_body, "write_integrity",
          "A write must not attach to, or create under, an object another principal owns; "
          "swap the owner reference for the second identity's id and read the result back.",
          "Access control vulnerabilities",
          external_refs=(
              ExternalRef("OWASP API Security Top 10 2023", "API1:2023",
                          "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                          "Broken Object Level Authorization"),
          ),
          specific_classes=(
              "cross_identity_write", "cross_identity_create", "cross_user_write",
              "bola_write", "idor_write", "foreign_reference_write",
          )),
    Check("AV-WRITE-AUTHOR-01", "Forged authorship (author/owner field set by the client)",
          Phase.ENDPOINT, "forged_authorship", _accepts_body, "write_integrity",
          "The server must derive an author or owner field from the session; send another "
          "identity's value and verify the stored object keeps the caller's own.",
          "Access control vulnerabilities",
          external_refs=(
              ExternalRef("OWASP API Security Top 10 2023", "API3:2023",
                          "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                          "Broken Object Property Level Authorization"),
          ),
          specific_classes=(
              "forged_authorship", "authorship_forgery", "author_spoofing", "forged_owner",
              "owner_spoofing", "impersonated_write",
          )),
    Check("AV-WRITE-BIZ-01", "Business-rule tampering (quantity, rating or amount bounds)",
          Phase.ENDPOINT, "business_rule_tamper", _accepts_body, "write_integrity",
          "A write must reject a negative or out-of-range quantity, rating or amount; send the "
          "in-range control and the tampered value, read both back, and restore the original.",
          "Business logic vulnerabilities",
          external_refs=(
              ExternalRef("WSTG", "WSTG-BUSL-01",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation",
                          "Test Business Logic Data Validation", version="4.2"),
          ),
          specific_classes=(
              "business_rule_tamper", "business_rule_bypass", "numeric_tamper",
              "negative_quantity", "quantity_tampering", "rating_tampering",
              "out_of_bounds_value", "negative_total",
          )),
    Check("AV-MASSASSIGN-02", "Mass assignment at create (privileged field on a new object)",
          Phase.ENDPOINT, "mass_assignment_create", _accepts_create, "write_integrity",
          "A create must not let a client set server-controlled fields; create once plainly and "
          "once with role/admin fields, read both back, and delete both.",
          "Mass assignment",
          external_refs=(
              ExternalRef("OWASP API Security Top 10 2023", "API3:2023",
                          "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                          "Broken Object Property Level Authorization (subsumes mass assignment)"),
          ),
          specific_classes=(
              "mass_assignment_create", "mass assignment create",
              "mass_assignment_at_create", "registration_mass_assignment",
          )),
    Check("AV-WRITE-VALID-01", "Weak create validation (empty required fields, duplicates)",
          Phase.ENDPOINT, "create_validation", _accepts_create, "write_integrity",
          "A create must reject empty required fields and a duplicate of a unique field; "
          "send each, read the stored objects back, and delete them.",
          "Business logic vulnerabilities",
          external_refs=(
              ExternalRef("WSTG", "WSTG-BUSL-01",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation",
                          "Test Business Logic Data Validation", version="4.2"),
          ),
          specific_classes=(
              "create_validation", "weak_create_validation", "duplicate_registration",
              "empty_required_fields", "missing_required_field_validation",
          )),
    # R11-7 business flows (business_flow_validator): replay the run's own captured
    # flow on a run-owned identity, read the resulting state back, restore what can be.
    Check("WSTG-BUSL-10", "Payment functionality (settlement tamper, payment skip)",
          Phase.ENDPOINT, "payment_tamper", _flow_shape("payment_tamper"), "business_flow",
          "Replay the captured cart steps and settlement untampered, then with a client-chosen "
          "amount, quantity or delivery value (or the payment dropped); confirm only when the "
          "read-back order total or balance shows less was charged than the control.",
          "Business logic vulnerabilities",
          specific_classes=(
              "payment_tamper", "payment tamper", "payment_tampering", "payment tampering",
              "checkout_tamper", "checkout tampering", "settlement_tamper", "payment_bypass",
              "payment bypass", "payment_skip", "order_total_tamper", "wallet_payment_skip",
          )),
    Check("AV-BUSL-COUPON-01", "Coupon or voucher misuse (forged, expired, another user's code)",
          Phase.ENDPOINT, "coupon_misuse", _flow_shape("coupon_misuse"), "business_flow",
          "Apply a forged code, an expired code and another run identity's code to the captured "
          "coupon write; confirm when the basket or order read-back shows the discount, then "
          "clear the code again.",
          "Business logic vulnerabilities",
          external_refs=(
              ExternalRef("WSTG", "WSTG-BUSL-10",
                          "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/10-Test-Payment-Functionality",
                          "Test Payment Functionality"),
          ),
          specific_classes=(
              "coupon_misuse", "coupon misuse", "coupon_forgery", "coupon forgery",
              "coupon_reuse", "expired_coupon", "voucher_misuse", "promo_code_abuse",
              "discount_code_abuse", "cross_user_coupon",
          )),
    Check("WSTG-BUSL-06", "Circumvention of work flows (2FA disable without step-up)",
          Phase.ENDPOINT, "mfa_disable_stepup", _flow_shape("mfa_disable_stepup"), "business_flow",
          "Replay the captured 2FA-disable request with its password or TOTP field dropped or "
          "wrong; confirm when the status read-back shows 2FA off, then re-enable it from the "
          "run's captured enable request or name it as left disabled.",
          "Authentication vulnerabilities",
          specific_classes=(
              "mfa_disable_stepup", "mfa disable stepup", "2fa_disable", "2fa disable",
              "mfa_disable", "two_factor_disable", "mfa_step_up_bypass",
              "2fa_disable_without_password",
          )),
)

CHECKS_BY_ID: dict[str, Check] = {c.id: c for c in CHECK_CATALOG}


def specific_class_token(text: str) -> str:
    """Fold a finding-class spelling to the snake token `specific_classes` match on:
    lower-case, one trailing "(...)" dropped, runs of space / hyphen / slash -> "_"."""
    low = re.sub(r"\s*\([^)]*\)\s*$", "", (text or "").strip().lower())
    return re.sub(r"[\s\-/]+", "_", low).strip("_")


def shared_class_specificity_problems(checks=None) -> list[str]:
    """WG-2 (4) guard, pure so a test can inject a bad row set. Returns one message
    per problem (empty = sound):
    - every row whose canonical class is shared by another row declares
      `specific_classes`;
    - no token (after `specific_class_token`) sits on two rows;
    - no token canonicalizes to the class of a DIFFERENT row, so a specific token
      never steals a finding that belongs to another class's row. A token whose
      class no row carries (e.g. "bfla", "missing security headers") may sit on a
      row: there is no other row to steal from, and the token is its only route."""
    checks = CHECK_CATALOG if checks is None else tuple(checks)
    problems: list[str] = []
    by_class: dict[str, list] = {}
    for c in checks:
        by_class.setdefault(canonicalize(c.vulnerability_class) or c.vulnerability_class,
                            []).append(c)
    for cls, rows in sorted(by_class.items()):
        if len(rows) < 2:
            continue
        for c in rows:
            if not c.specific_classes:
                problems.append(f"{c.id}: shares class {cls!r} with "
                                f"{len(rows) - 1} other row(s) but declares no specific_classes")
    owner: dict[str, str] = {}
    for c in checks:
        row_cls = canonicalize(c.vulnerability_class) or c.vulnerability_class
        for tok in c.specific_classes:
            key = specific_class_token(tok)
            if not key:
                problems.append(f"{c.id}: empty specific_classes token {tok!r}")
                continue
            prev = owner.get(key)
            if prev is not None and prev != c.id:
                problems.append(f"{c.id}: token {tok!r} is already on {prev}")
            owner.setdefault(key, c.id)
            tok_cls = canonicalize(tok)
            if tok_cls is not None and tok_cls != row_cls and tok_cls in by_class:
                problems.append(f"{c.id}: token {tok!r} canonicalizes to {tok_cls!r}, "
                                f"not the row class {row_cls!r}")
    return problems

# WG-1: the ONE table of pre-WG-1 check ids (WSTG v4.2 numbering, plus the old
# internal mass-assignment id) -> the current catalog id. Coverage cells, evidence
# files and event ledgers written by r9, r10 and earlier carry these; every reader
# resolves them through `resolve_check_id`. An id in neither CHECKS_BY_ID nor this
# table is rejected, never guessed. A key that is also a current id must be declared
# in REUSED_LEGACY_IDS (the import guard enforces it).
#
# ID schemes: data stamped `check_id_scheme: 2` (CHECK_ID_SCHEME) uses current WSTG
# ids; data with no stamp is scheme 1 (pre-WG-1, v4.2 numbering). Everything written
# before the stamp existed is unmarked, which is safe: post-WG-1 writers never wrote
# "WSTG-BUSL-08", and no other alias key is a current id.
CHECK_ID_SCHEME = 2
LEGACY_CHECK_ID_SCHEME = 1

LEGACY_CHECK_ID_ALIASES: dict[str, str] = {
    "WSTG-CONF-05": "WSTG-CONF-12",      # v4.2 CONF-05 = admin interfaces; CSP is CONF-12
    "WSTG-CONF-08": "WSTG-CLNT-07",      # v4.2 CONF-08 = RIA cross-domain policy; CORS is CLNT-07
    "WSTG-CONF-02": "WSTG-CONF-14",      # v4.2 CONF-02 = platform config; headers are CONF-14
    "WSTG-ATHN-01": "WSTG-ATHN-04",      # v4.2 ATHN-01 = encrypted channel; bypass is ATHN-04
    "WSTG-BUSV-04": "WSTG-INJT-16",      # no BUSV category exists; smuggling is INJT-16
    "WSTG-INPV-14": "WSTG-INJT-15",      # v4.2 INPV-14 = incubated; CRLF splitting is INJT-15
    "WSTG-INPV-05": "WSTG-INJT-05",      # INPV-* was renumbered INJT-*
    "WSTG-INPV-01": "WSTG-INJT-01",
    "WSTG-INPV-02": "WSTG-INJT-02",
    "WSTG-INPV-12": "WSTG-INJT-12",
    "WSTG-INPV-18": "WSTG-INJT-18",
    "WSTG-INPV-07": "WSTG-INJT-07",
    "WSTG-INPV-19": "WSTG-INJT-19",
    "WSTG-INPV-17": "WSTG-CLNT-04",      # v4.2 INPV-17 = Host header; redirect is CLNT-04
    "WSTG-INPV-06": "WSTG-INJT-05.6",    # v4.2 INPV-06 = LDAP; NoSQL is sub-test INJT-05.6
    "WSTG-CRYP-04": "WSTG-SESS-10",      # v4.2 CRYP-04 = weak encryption; JWT is SESS-10
    "WSTG-INPV-11": "WSTG-INJT-23",      # v4.2 INPV-11 = code injection; deserialization is INJT-23
    "WSTG-BUSL-07": "WSTG-BUSL-05",      # v4.2 BUSL-07 = misuse defenses; race is BUSL-05
    "WSTG-BUSL-08": "WSTG-ATHZ-03",      # v4.2 BUSL-08 = unexpected file types; TOCTOU is ATHZ-03
    "AV-MASSASSIGN-01": "WSTG-INJT-20",  # internal id; current WSTG adds Mass Assignment
}

# Alias keys that are ALSO current catalog ids but meant something else in scheme 1.
# They resolve through the alias table only in scheme-1 data; in scheme-2 data they
# are the current row. WSTG-BUSL-08 was the v4.2-era TOCTOU row; today it is
# "Upload of Unexpected File Types" (the file_upload leg).
REUSED_LEGACY_IDS: frozenset[str] = frozenset({"WSTG-BUSL-08"})


class UnknownCheckIdError(KeyError):
    """A check id that is neither a current catalog id nor a known legacy alias."""


def check_id_scheme_of(value) -> int:
    """The id scheme a stored `check_id_scheme` value names: absent (None) is scheme 1;
    1 or 2 is itself. Anything else raises ValueError -- an unknown scheme is never
    read as a known one."""
    if value is None:
        return LEGACY_CHECK_ID_SCHEME
    if isinstance(value, int) and not isinstance(value, bool) and value in (
            LEGACY_CHECK_ID_SCHEME, CHECK_ID_SCHEME):
        return value
    raise ValueError(f"unsupported check_id_scheme {value!r}")


def is_legacy_check_id(check_id: str, scheme: int = CHECK_ID_SCHEME) -> bool:
    """True when `check_id`, read under `scheme`, is a legacy alias that resolves to
    another id. In scheme 1 every alias key is legacy; in scheme 2 a reused id
    (REUSED_LEGACY_IDS) is the current row, not an alias."""
    if check_id not in LEGACY_CHECK_ID_ALIASES:
        return False
    if scheme == LEGACY_CHECK_ID_SCHEME:
        return True
    if scheme == CHECK_ID_SCHEME:
        return check_id not in REUSED_LEGACY_IDS
    raise ValueError(f"unsupported check_id_scheme {scheme!r}")


def resolve_check_id(check_id: str, *, scheme: int = CHECK_ID_SCHEME) -> str:
    """Return the current catalog id for `check_id` read under `scheme`.

    Scheme 1 (pre-WG-1 data): an alias key resolves through the table (BUSL-08 ->
    ATHZ-03); a current id resolves to itself. Scheme 2 (current): a current id
    resolves to itself; a non-reused alias still resolves (tolerant reads). Raises
    `UnknownCheckIdError` for anything else -- an unknown id is never silently
    mapped to a neighbour."""
    if is_legacy_check_id(check_id, scheme):
        target = LEGACY_CHECK_ID_ALIASES[check_id]
        if target in CHECKS_BY_ID:
            return target
        raise UnknownCheckIdError(check_id)
    if check_id in CHECKS_BY_ID:
        return check_id
    raise UnknownCheckIdError(check_id)


def _check_catalog_ids() -> None:
    """Import-time guard: every WSTG-labelled row names a current WSTG test, no alias
    shadows a current id unless it is declared in REUSED_LEGACY_IDS, every declared
    reused id really is both an alias key and a current id, and every alias lands on
    a catalog row."""
    for c in CHECK_CATALOG:
        if c.is_wstg() and not is_current_wstg_id(c.id):
            raise ValueError(f"catalog id {c.id!r} is not in harness/wstg_ids.py")
    for old, new in LEGACY_CHECK_ID_ALIASES.items():
        if old in CHECKS_BY_ID and old not in REUSED_LEGACY_IDS:
            raise ValueError(f"legacy alias {old!r} shadows a current catalog id")
        if new not in CHECKS_BY_ID:
            raise ValueError(f"legacy alias {old!r} -> {new!r} has no catalog row")
    for reused in REUSED_LEGACY_IDS:
        if reused not in LEGACY_CHECK_ID_ALIASES or reused not in CHECKS_BY_ID:
            raise ValueError(f"reused legacy id {reused!r} is not both a legacy alias "
                             f"and a current catalog id")


_check_catalog_ids()


# ---------------------------------------------------------------------------
# WG-2: confirmation kinds <-> registered validators
# ---------------------------------------------------------------------------

# Confirmation kinds that deliberately name no `validators/registry.py` validator.
NON_VALIDATOR_CONFIRMATIONS: dict[str, str] = {
    "manual": "needs a human, a browser PoC or host access; never automated coverage",
    "agent": "confirmed by the LLM agent's own evidence, not a deterministic leg",
}

# Registered validators that confirm no catalog row, each with the reason.
VALIDATOR_ROW_EXCLUSIONS: dict[str, str] = {
    "api_security": "mass-assignment / resource-consumption probes from one exchange; the "
                    "mass-assignment row (WSTG-INJT-20) confirms via the sequence leg",
    "deserialization": "passive serialized-format fingerprint, no verdict of its own; "
                       "WSTG-INJT-23 confirms via deserialization_oob",
    "idor_read": "single-principal read differential; WSTG-ATHZ-04 confirms via "
                 "cross_identity (switching or adding a kind is an owner decision)",
    "verbose_error": "passive stack-trace scan; WSTG-ERRH-01 is judged by the passive "
                     "error_handling adapter instead",
    "challenge_echo": "R11-8 (c): routed by capture shape on the analyze path; it records "
                      "leads until the owner signs off, so a WSTG-BUSL-07 row (and its "
                      "drive) is an owner decision",
}

# Current WSTG tests deliberately left without a row, each with the reason.
EXCLUDED_CATALOG_ROWS: dict[str, str] = {
    "WSTG-INJT-14": "no registry validator confirms it: the second-order differentials "
                    "(second_order.py) run inside orchestrator_chain and their findings "
                    "carry second_order_sqli / second_order_idor, which canonicalize to no "
                    "class; a row needs a categories.py synonym and a kind decision",
}


def catalog_kind_problems(rows, registered_names, exclusions=None, *,
                          non_validator=None, excluded_rows=None) -> list[str]:
    """Every problem between catalog confirmation kinds and the registered
    validators; empty means consistent. A row's kind must be a registered validator
    or a documented non-validator kind; every registered validator must confirm a
    row or sit on `exclusions` with a reason; an exclusion must not be stale (the
    validator gained a row, or is no longer registered); an excluded row id must not
    have a row."""
    exclusions = VALIDATOR_ROW_EXCLUSIONS if exclusions is None else exclusions
    non_validator = NON_VALIDATOR_CONFIRMATIONS if non_validator is None else non_validator
    excluded_rows = EXCLUDED_CATALOG_ROWS if excluded_rows is None else excluded_rows
    registered = set(registered_names)
    rows = tuple(rows)
    kinds = {r.confirmation for r in rows}
    problems: list[str] = []
    for r in rows:
        if r.confirmation not in non_validator and r.confirmation not in registered:
            problems.append(f"{r.id}: confirmation {r.confirmation!r} names no registered "
                            f"validator and is not a documented non-validator kind")
    for name in sorted(registered):
        if name in kinds:
            if name in exclusions:
                problems.append(f"{name}: excluded but a row names it (stale exclusion)")
        elif not (exclusions.get(name) or "").strip():
            problems.append(f"{name}: registered validator has no catalog row and no "
                            f"exclusion reason")
    for name in sorted(set(exclusions) - registered):
        problems.append(f"{name}: excluded but not registered (stale exclusion)")
    ids = {r.id for r in rows}
    for row_id, why in sorted(excluded_rows.items()):
        if row_id in ids:
            problems.append(f"{row_id}: on the excluded-row list but has a row")
        elif not (why or "").strip():
            problems.append(f"{row_id}: excluded row has no reason")
    return problems


CHECKS_BY_PHASE: dict[Phase, list[Check]] = {}
for _c in CHECK_CATALOG:
    CHECKS_BY_PHASE.setdefault(_c.phase, []).append(_c)


# ---------------------------------------------------------------------------
# Coverage matrix — identity × endpoint × check (I2)
# ---------------------------------------------------------------------------

class CoverageMatrix:
    """The auditable coverage matrix.

    Keys: (identity, endpoint_key, check_id) → CellResult.
    endpoint_key is "METHOD path" matching EngagementState.endpoints keys.
    """

    def __init__(self) -> None:
        self._cells: dict[tuple[str, str, str], CellResult] = {}
        # T05: child cases UNDER a cell -- {(identity, ep, check): {coord_id: (CaseKey, CellResult)}}.
        # A cell with child cases derives its status by aggregation; a cell with
        # none behaves exactly as before (leaf cell), so every existing caller,
        # test, and serialized matrix is unaffected.
        self._cases: dict[tuple[str, str, str], dict[str, tuple[CaseKey, CellResult]]] = {}

    def get(self, identity: str, endpoint_key: str, check_id: str) -> CellResult | None:
        return self._cells.get((identity, endpoint_key, check_id))

    def set(self, identity: str, endpoint_key: str, check_id: str, result: CellResult) -> None:
        self._cells[(identity, endpoint_key, check_id)] = result

    def fill_applicability(self, identities: list[str], endpoints: dict[str, dict],
                           checks: tuple[Check, ...] | None = None) -> int:
        """Pre-fill cells based on each check's applicability predicate.

        Returns the number of cells set to not_applicable. Cells already
        populated (e.g. from a prior run) are not overwritten.
        """
        checks = checks or CHECK_CATALOG
        na_count = 0
        for identity in identities:
            for ep_key, ep_data in endpoints.items():
                for check in checks:
                    key = (identity, ep_key, check.id)
                    if key in self._cells:
                        continue
                    applicable, reason = check.applies(ep_data)
                    if not applicable:
                        self._cells[key] = CellResult.not_applicable(reason)
                        na_count += 1
                    else:
                        self._cells[key] = CellResult(
                            status=CellStatus.PENDING,
                            reason=reason)
        return na_count

    def record(self, identity: str, endpoint_key: str, check_id: str, *,
               status: CellStatus, reason: str = "", severity: str | None = None,
               confidence: float | None = None, validator: str | None = None,
               evidence: str | None = None, executed: bool = False,
               attempts=(), referenced_attempts=()) -> CellResult:
        """Record a check result. Does NOT overwrite a CONFIRMED cell.

        `executed` (R07) must be True only when a deterministic leg actually
        dispatched a request/comparison for this cell -- callers recording a
        purely agent-attributed result (no leg ran) must leave it False.
        Attempt facts (batch 02) are merged even where the verdict is locked,
        and a later record never clears an earlier execution."""
        key = (identity, endpoint_key, check_id)
        existing = self._cells.get(key)
        if existing and (existing.reason.startswith("origin_scoped:")
                         or existing.status == CellStatus.CONFIRMED):
            # Endpoint findings cannot recreate a host-level denominator, and a
            # confirmed verdict stays; only the attempt facts are added.
            existing.executed = existing.executed or executed
            existing.attempts = _merge_facts(existing.attempts, attempts)
            existing.referenced_attempts = _merge_facts(
                existing.referenced_attempts, referenced_attempts)
            return existing
        result = CellResult(status=status, reason=reason, severity=severity,
                            confidence=confidence, validator=validator, evidence=evidence,
                            executed=executed or bool(existing and existing.executed),
                            attempts=_merge_facts(existing and existing.attempts, attempts),
                            referenced_attempts=_merge_facts(
                                existing and existing.referenced_attempts, referenced_attempts))
        self._cells[key] = result
        return result

    # --- child cases (T05/R26): concrete inputs/states under a cell ---

    def expand_cases(self, identity: str, endpoint_key: str, check_id: str,
                     case_keys, *, budget_remaining: int | None = None) -> dict:
        """Register concrete child cases under an applicable cell, LAZILY within a
        budget (T05). Each case starts PENDING; once `budget_remaining` is spent the
        rest are registered SKIPPED with an explicit "budget exhausted" reason so
        they stay VISIBLE and are never counted as executed. Returns
        {added, budget_skipped}. Already-registered cases are left untouched.

        `budget_remaining is None` means unbounded. A non-positive budget registers
        every case as budget-skipped (nothing attempted)."""
        key = (identity, endpoint_key, check_id)
        bucket = self._cases.setdefault(key, {})
        added = 0
        budget_skipped = 0
        for ck in case_keys:
            cid = ck.coord_id()
            if cid in bucket:
                continue
            if budget_remaining is not None and budget_remaining <= 0:
                bucket[cid] = (ck, CellResult(
                    status=CellStatus.SKIPPED,
                    reason=f"case budget exhausted before {ck.label()} was attempted "
                           f"(visible, not counted as tested)"))
                budget_skipped += 1
                continue
            bucket[cid] = (ck, CellResult(status=CellStatus.PENDING,
                                          reason=f"case {ck.label()} awaiting attempt"))
            added += 1
            if budget_remaining is not None:
                budget_remaining -= 1
        if bucket:
            self._aggregate_cell(key)
        return {"added": added, "budget_skipped": budget_skipped}

    def record_case(self, identity: str, endpoint_key: str, check_id: str,
                    case_key: CaseKey, *, status: CellStatus, reason: str = "",
                    severity: str | None = None, confidence: float | None = None,
                    validator: str | None = None, evidence: str | None = None,
                    executed: bool = False, attempts=(), referenced_attempts=()) -> CellResult:
        """Record the outcome of ONE concrete case, then re-aggregate its parent
        cell. A CONFIRMED case is never overwritten (same monotonicity as `record`).
        Registers the case if `expand_cases` had not already."""
        key = (identity, endpoint_key, check_id)
        bucket = self._cases.setdefault(key, {})
        cid = case_key.coord_id()
        existing = bucket.get(cid)
        prior = existing[1] if existing else None
        if prior and prior.status == CellStatus.CONFIRMED:
            prior.executed = prior.executed or executed
            prior.attempts = _merge_facts(prior.attempts, attempts)
            prior.referenced_attempts = _merge_facts(prior.referenced_attempts, referenced_attempts)
            self._aggregate_cell(key)
            return prior
        result = CellResult(status=status, reason=reason, severity=severity,
                            confidence=confidence, validator=validator, evidence=evidence,
                            executed=executed or bool(prior and prior.executed),
                            attempts=_merge_facts(prior and prior.attempts, attempts),
                            referenced_attempts=_merge_facts(
                                prior and prior.referenced_attempts, referenced_attempts))
        # Preserve the original replay spelling if the caller passed a bare key.
        stored_key = existing[0] if existing else case_key
        bucket[cid] = (stored_key, result)
        self._aggregate_cell(key)
        return result

    def cases_for_cell(self, identity: str, endpoint_key: str,
                       check_id: str) -> list[tuple[CaseKey, CellResult]]:
        return list(self._cases.get((identity, endpoint_key, check_id), {}).values())

    def has_cases(self, identity: str, endpoint_key: str, check_id: str) -> bool:
        return bool(self._cases.get((identity, endpoint_key, check_id)))

    def pending_cases(self) -> list[tuple[str, str, str, CaseKey]]:
        """(identity, endpoint_key, check_id, CaseKey) for every child case still
        PENDING -- the case-granular work-program the driver fires."""
        out: list[tuple[str, str, str, CaseKey]] = []
        for (i, e, c), bucket in self._cases.items():
            for _cid, (ck, res) in bucket.items():
                if res.status == CellStatus.PENDING:
                    out.append((i, e, c, ck))
        return out

    def _aggregate_cell(self, key: tuple[str, str, str]) -> None:
        """Roll the child-case statuses up into the parent cell (T05).

        Rule: a CONFIRMED child marks the cell CONFIRMED (endpoint risk), but the
        cell may claim completion (not_detected/controlled_negative) ONLY when
        EVERY child is a conclusive negative -- any open child (pending, skipped,
        budget-exhausted, blocked, inconclusive) keeps the cell PENDING. This is
        what forbids "one input tested" from reading as "endpoint tested". A
        directly-recorded CONFIRMED/DETECTED on the cell (e.g. from a finding) is
        folded in as a participant so the case layer never erases it."""
        bucket = self._cases.get(key)
        if not bucket:
            return
        statuses = {res.status for _ck, res in bucket.values()}
        prior = self._cells.get(key)
        if prior and prior.status in (CellStatus.CONFIRMED, CellStatus.DETECTED):
            statuses.add(prior.status)

        n_cases = len(bucket)
        confirmed = sum(1 for _c, r in bucket.values() if r.status == CellStatus.CONFIRMED)
        # Completion (not_detected / controlled_negative) requires EVERY child to be
        # a conclusive negative. An errored, blocked, inconclusive, or still-open
        # child forbids the cell from claiming the endpoint was fully tested (R06):
        # a negative sibling next to an errored one is NOT "all tested".
        _NEG = {CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE}
        if CellStatus.CONFIRMED in statuses:
            agg, reason = CellStatus.CONFIRMED, f"{confirmed}/{n_cases} case(s) confirmed"
        elif CellStatus.DETECTED in statuses:
            agg, reason = CellStatus.DETECTED, "a case was detected but unconfirmed"
        elif statuses <= {CellStatus.CONTROLLED_NEGATIVE}:
            agg, reason = CellStatus.CONTROLLED_NEGATIVE, f"all {n_cases} case(s) held under a controlled negative"
        elif statuses <= _NEG:
            agg, reason = CellStatus.NOT_DETECTED, f"all {n_cases} case(s) tested, none detected"
        elif statuses & _OPEN_STATUSES:
            n_open = sum(1 for _c, r in bucket.values() if r.status in _OPEN_STATUSES)
            agg, reason = CellStatus.PENDING, (
                f"{n_open}/{n_cases} case(s) not yet conclusively tested "
                f"-- endpoint not marked complete")
        elif CellStatus.ERROR in statuses:
            # remaining mix is negatives + errors (no open child): an unresolved
            # error means the cell is not a clean completion.
            agg, reason = CellStatus.ERROR, "a case attempt errored -- endpoint not marked complete"
        else:
            agg, reason = CellStatus.PENDING, "cases awaiting attempt"
        attempts = _merge_facts(prior and prior.attempts,
                                *(r.attempts for _ck, r in bucket.values()))
        referenced = _merge_facts(prior and prior.referenced_attempts,
                                  *(r.referenced_attempts for _ck, r in bucket.values()))
        # Never downgrade a locked CONFIRMED cell (its attempt facts still grow).
        if prior and prior.status == CellStatus.CONFIRMED and agg != CellStatus.CONFIRMED:
            prior.executed = prior.executed or any(r.executed for _ck, r in bucket.values())
            prior.attempts, prior.referenced_attempts = attempts, referenced
            return
        # R07: carry the representative child's executed/validator signal into
        # the rolled-up parent cell, so a matrix reader iterating top-level
        # cells (coverage_summary.py) sees whether the aggregate verdict
        # actually came from an executed leg -- never defaulting to
        # executed=False just because the parent cell itself never called
        # `record()` directly.
        # Execution is a fact of any child send, independent of the rolled-up
        # verdict. Pending siblings and prior risk must not erase that fact.
        rep_executed = any(r.executed for _ck, r in bucket.values()) or bool(
            prior and prior.executed)
        rep_validator: str | None = None
        for _ck, r in bucket.values():
            if r.status == agg:
                rep_validator = rep_validator or r.validator
        if prior and prior.status == agg:
            rep_validator = rep_validator or prior.validator
        self._cells[key] = CellResult(status=agg, reason=reason, validator=rep_validator,
                                      executed=rep_executed, attempts=attempts,
                                      referenced_attempts=referenced)

    # --- queries ---

    def cells(self) -> dict[tuple[str, str, str], CellResult]:
        return dict(self._cells)

    def for_endpoint(self, endpoint_key: str) -> dict[tuple[str, str], CellResult]:
        """All (identity, check_id) → result for one endpoint."""
        return {(i, c): r for (i, e, c), r in self._cells.items() if e == endpoint_key}

    def for_identity(self, identity: str) -> dict[tuple[str, str], CellResult]:
        """All (endpoint_key, check_id) → result for one identity."""
        return {(e, c): r for (i, e, c), r in self._cells.items() if i == identity}

    def for_check(self, check_id: str) -> dict[tuple[str, str], CellResult]:
        """All (identity, endpoint_key) → result for one check."""
        return {(i, e): r for (i, e, c), r in self._cells.items() if c == check_id}

    def summary(self) -> dict:
        """Aggregate counts by status, phase, and check."""
        by_status: dict[str, int] = {}
        by_phase: dict[str, dict[str, int]] = {}
        by_check: dict[str, dict[str, int]] = {}
        for (_, _, check_id), result in self._cells.items():
            s = result.status.value
            by_status[s] = by_status.get(s, 0) + 1
            check = CHECKS_BY_ID.get(check_id)
            if check:
                phase = check.phase.value
                by_phase.setdefault(phase, {})
                by_phase[phase][s] = by_phase[phase].get(s, 0) + 1
                by_check.setdefault(check_id, {})
                by_check[check_id][s] = by_check[check_id].get(s, 0) + 1
        total = len(self._cells)
        # Honest, separated counts (R02). Only cells where a leg was actually
        # executed count as an attempt. SKIPPED, PENDING, RUNNING and
        # NOT_APPLICABLE are NOT attempts and must never inflate a "tested"
        # number -- that is exactly what made 3,633 skipped cells look tested.
        # A CONTROLLED_NEGATIVE is a real executed verdict (the boundary held), so
        # it counts as conclusive/attempted. BLOCKED (gate-denied) and INCONCLUSIVE
        # (no verdict) are NOT executed -- they never inflate "attempted"/"tested".
        conclusive = (by_status.get("confirmed", 0) + by_status.get("detected", 0)
                      + by_status.get("not_detected", 0)
                      + by_status.get("controlled_negative", 0))
        attempted = conclusive + by_status.get("error", 0)
        return {
            "total_cells": total,
            # attempted: an execution was actually launched (produced a verdict, or errored).
            "attempted": attempted,
            # conclusive: the attempt produced a usable verdict.
            "conclusive": conclusive,
            # `tested` is retained for back-compat but is now an alias of `conclusive`
            # -- it deliberately EXCLUDES skipped/error/pending/running/not_applicable.
            "tested": conclusive,
            "not_applicable": by_status.get("not_applicable", 0),
            "pending": by_status.get("pending", 0),
            "skipped": by_status.get("skipped", 0),
            "running": by_status.get("running", 0),
            "error": by_status.get("error", 0),
            "confirmed": by_status.get("confirmed", 0),
            "detected": by_status.get("detected", 0),
            "not_detected": by_status.get("not_detected", 0),
            "controlled_negative": by_status.get("controlled_negative", 0),
            "blocked": by_status.get("blocked", 0),
            "inconclusive": by_status.get("inconclusive", 0),
            "by_status": by_status,
            "by_phase": by_phase,
            "by_check": by_check,
            # T05: aggregate child-case counts, so the coverage report shows the
            # finer parameter/state granularity WITHOUT changing the cell counts.
            "cases": self.case_summary(),
        }

    def case_summary(self) -> dict:
        """Aggregate counts over all child cases (T05). Same honest accounting as
        the cell summary: only real verdicts count as attempted/conclusive."""
        by_status: dict[str, int] = {}
        total = 0
        for bucket in self._cases.values():
            for _ck, res in bucket.values():
                total += 1
                by_status[res.status.value] = by_status.get(res.status.value, 0) + 1
        conclusive = (by_status.get("confirmed", 0) + by_status.get("detected", 0)
                      + by_status.get("not_detected", 0)
                      + by_status.get("controlled_negative", 0))
        return {
            "total_cases": total,
            "attempted": conclusive + by_status.get("error", 0),
            "conclusive": conclusive,
            "confirmed": by_status.get("confirmed", 0),
            "detected": by_status.get("detected", 0),
            "not_detected": by_status.get("not_detected", 0),
            "controlled_negative": by_status.get("controlled_negative", 0),
            "pending": by_status.get("pending", 0),
            "skipped": by_status.get("skipped", 0),
            "blocked": by_status.get("blocked", 0),
            "inconclusive": by_status.get("inconclusive", 0),
            "error": by_status.get("error", 0),
            "by_status": by_status,
        }

    def cases_not_tested(self) -> list[dict]:
        """Every child case that was NOT conclusively tested, with its reason
        (T05: budget-exhausted/pending/blocked cases stay visible and honest)."""
        out: list[dict] = []
        for (identity, ep_key, check_id), bucket in self._cases.items():
            for _cid, (ck, res) in bucket.items():
                if res.status in _CONCLUSIVE_STATUSES:
                    continue
                out.append({
                    "identity": identity, "endpoint": ep_key, "check": check_id,
                    "case": ck.label(), "parameter_location": ck.parameter_location,
                    "parameter_name": ck.parameter_name, "occurrence": ck.occurrence,
                    "status": res.status.value, "reason": res.reason,
                })
        return out

    def not_tested(self) -> list[dict]:
        """Cells that were NOT tested, with the reason (I2/I5). A leg that was
        blocked, gave no verdict or errored is listed too (RV-M M2, after R11),
        and so is a cell still pending or running (RV-O O6): only an executed
        verdict is tested, so the list must name those cells. A pending parent
        whose detail lives in child cases (T05) is left to `cases_not_tested`,
        which names each open case, as finalize_pending_reasons leaves it."""
        result = []
        for (identity, ep_key, check_id), cell in self._cells.items():
            if cell.status in (CellStatus.PENDING, CellStatus.RUNNING) \
                    and self._cases.get((identity, ep_key, check_id)):
                continue
            if cell.status in _NOT_TESTED_STATUSES:
                result.append({
                    "identity": identity,
                    "endpoint": ep_key,
                    "check": check_id,
                    "status": cell.status.value,
                    "reason": cell.reason or _NOT_TESTED_REASONS.get(cell.status, ""),
                })
        return result

    def to_dict(self) -> dict:
        out: dict = {
            # WG-2: the id scheme the keys below use; an unmarked dict is scheme 1.
            "check_id_scheme": CHECK_ID_SCHEME,
            "cells": {
                f"{i}|{e}|{c}": r.to_dict()
                for (i, e, c), r in self._cells.items()
            },
        }
        # T05: child cases, additive -- an older reader ignores the key and a
        # matrix with no cases omits it, so round-tripping stays compatible.
        if self._cases:
            out["cases"] = {
                f"{i}|{e}|{c}": [
                    {"key": ck.to_dict(), "result": res.to_dict()}
                    for ck, res in bucket.values()
                ]
                for (i, e, c), bucket in self._cases.items()
            }
        # Batch 02: versioned only when attempt facts exist, so a legacy matrix
        # round-trips unchanged; a reader without the key sees none.
        if any(r.attempts or r.referenced_attempts for r in self._cells.values()):
            out["attempt_schema_version"] = ATTEMPT_SCHEMA_VERSION
        return out

    @classmethod
    def from_dict(cls, d: dict) -> "CoverageMatrix":
        """WG-1: a cell or case stored under a legacy check id (pre-WG-1 WSTG v4.2
        numbering) loads under its current id. When a matrix holds BOTH spellings of
        one cell, the entry already under the current id wins. An id that is neither
        current nor a known alias is kept verbatim -- never mapped onto a neighbour.
        The dict's `check_id_scheme` (absent = 1) decides how a reused id reads: a
        "WSTG-BUSL-08" key is the TOCTOU row (ATHZ-03) in scheme 1 and the
        file-upload row in scheme 2."""
        m = cls()
        scheme = check_id_scheme_of(d.get("check_id_scheme"))

        def split_key(key_str: str) -> tuple[tuple[str, str, str], bool] | None:
            parts = key_str.split("|", 2)
            if len(parts) != 3:
                return None
            check_id = parts[2]
            if is_legacy_check_id(check_id, scheme):
                return (parts[0], parts[1], resolve_check_id(check_id, scheme=scheme)), True
            return (parts[0], parts[1], check_id), False

        # Current-id entries first, so a legacy duplicate never overwrites one.
        cells = []
        for key_str, cell_dict in (d.get("cells", {}) or {}).items():
            parsed = split_key(key_str)
            if parsed is not None:
                cells.append((parsed[1], parsed[0], cell_dict))
        for legacy, key, cell_dict in sorted(cells, key=lambda t: t[0]):
            if legacy and key in m._cells:
                continue
            m._cells[key] = CellResult.from_dict(cell_dict)

        buckets = []
        for key_str, cases in (d.get("cases", {}) or {}).items():
            parsed = split_key(key_str)
            if parsed is not None:
                buckets.append((parsed[1], parsed[0], cases))
        for legacy, key, cases in sorted(buckets, key=lambda t: t[0]):
            bucket = m._cases.setdefault(key, {})
            for entry in cases or []:
                ck = CaseKey.from_dict(entry.get("key", {}) or {})
                res = CellResult.from_dict(entry.get("result", {}) or {})
                if legacy and ck.coord_id() in bucket:
                    continue
                bucket[ck.coord_id()] = (ck, res)
        return m
