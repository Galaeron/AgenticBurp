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

from categories import canonicalize


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


@dataclass
class CellResult:
    """One cell in the coverage matrix: (identity, endpoint, check)."""
    status: CellStatus = CellStatus.PENDING
    reason: str = ""
    severity: str | None = None
    confidence: float | None = None
    validator: str | None = None
    evidence: str | None = None

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
    return derive_input_cases(
        query=template.get("query", "") or "", body=template.get("body", "") or "",
        content_type=template.get("content_type", "") or "",
        object_id=template.get("object_id"), workflow_state_id=workflow_state_id)


# ---------------------------------------------------------------------------
# Applicability predicates — shape-based, deterministic (I1/I5)
# ---------------------------------------------------------------------------

def _has_params(endpoint: dict) -> tuple[bool, str]:
    path = endpoint.get("path", "")
    if "?" in path or "{" in path or re.search(r"/\d+(?:/|$)", path):
        return True, "endpoint has parameters or path variables"
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
    it (e.g. "WSTG-INPV-05", "API3:2023") or "" for a URL-only reference."""
    catalog: str
    ref: str = ""
    url: str = ""
    title: str = ""
    version: str = ""


@dataclass(frozen=True)
class Check:
    """A single security check in the catalog.

    The `id` is the check's PRIMARY identifier. For checks that map cleanly onto a
    WSTG test it is the versioned WSTG id (the stable WSTG id + `wstg_version` it is
    anchored to). For a scenario with NO clean WSTG mapping (e.g. mass assignment,
    which is an API-layer issue with no dedicated WSTG v4.2 test) it is an INTERNAL
    `AV-*` id, and the real external sources live in `external_refs` -- so the catalog
    never falsely labels a scenario with a WSTG id that means something else. WSTG and
    Academy are *reference catalogs* here, not an exploitation runner.
    """
    id: str                              # e.g. "WSTG-INPV-05" or internal "AV-MASSASSIGN-01"
    name: str                            # human-readable
    phase: Phase
    vulnerability_class: str             # maps to categories.canonicalize
    applicability: ApplicabilityPredicate
    confirmation: str                    # "sqlmap" | "cross_identity" | "agent" | "manual" | ...
    description: str = ""
    academy_ref: str = ""                # PortSwigger Academy topic name if applicable
    academy_url: str = ""                # optional full Academy topic URL (scenario reference)
    wstg_version: str = "4.2"            # the WSTG release a genuine WSTG id is anchored to
    external_refs: tuple[ExternalRef, ...] = ()   # independently-verified external sources

    def applies(self, endpoint: dict) -> tuple[bool, str]:
        """Deterministic applicability + the rationale for WHY it applies or doesn't."""
        return self.applicability(endpoint)

    def canonical_class(self) -> str | None:
        return canonicalize(self.vulnerability_class)

    def is_wstg(self) -> bool:
        """Whether the primary id is a genuine WSTG test id."""
        return self.id.startswith("WSTG-")

    def reference_label(self) -> str:
        """A human label for the primary id: versioned for a genuine WSTG id, else the
        internal id marked as such (external sources are in `external_refs`)."""
        if self.is_wstg():
            return f"{self.id} (WSTG v{self.wstg_version})"
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
          "Server-side TLS"),
    Check("WSTG-CONF-07", "HTTP Strict Transport Security", Phase.DOMAIN,
          "misconfig", _always_applicable, "crypto",
          "Check HSTS header presence and configuration"),
    Check("WSTG-CONF-05", "Content Security Policy", Phase.DOMAIN,
          "csp", _always_applicable, "csp",
          "Evaluate CSP header directives",
          "Content security policy"),
    Check("WSTG-CONF-08", "CORS policy", Phase.DOMAIN,
          "cors", _always_applicable, "cors",
          "Test Cross-Origin Resource Sharing configuration",
          "CORS"),
    Check("WSTG-INFO-02", "Server fingerprinting", Phase.DOMAIN,
          "recon", _always_applicable, "recon",
          "Identify web server software and version"),
    Check("WSTG-INFO-05", "Information in comments/metadata", Phase.DOMAIN,
          "info_disclosure", _always_applicable, "recon",
          "Check for sensitive data in HTML comments, headers, metadata"),
    Check("WSTG-CONF-06", "HTTP methods", Phase.DOMAIN,
          "misconfig", _always_applicable, "recon",
          "Test which HTTP methods are enabled"),
    Check("WSTG-CONF-02", "Security headers", Phase.DOMAIN,
          "misconfig", _always_applicable, "recon",
          "Check X-Frame-Options, X-Content-Type-Options, etc."),
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
          )),

    # === ENDPOINT phase ===
    Check("WSTG-ATHZ-04", "IDOR / Broken Object-Level Authorization", Phase.ENDPOINT,
          "idor", _is_object_scoped, "cross_identity",
          "Test access to other users' objects by varying identifiers",
          "Insecure direct object references (IDOR)"),
    Check("WSTG-ATHZ-02", "Broken Function-Level Authorization", Phase.ENDPOINT,
          "idor", _is_authed, "cross_identity",
          "Access admin/privileged functions as a lower-privilege user",
          "Access control vulnerabilities"),
    Check("WSTG-ATHN-01", "Authentication bypass", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "auth_sequence",
          "Test for authentication bypass techniques",
          "Authentication vulnerabilities"),
    Check("WSTG-ATHN-07", "Weak password policy", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "auth_sequence",
          "Test password complexity requirements",
          "Authentication vulnerabilities"),
    Check("WSTG-ATHN-03", "Weak lockout mechanism", Phase.ENDPOINT,
          "rate_limit", _has_auth_endpoint, "rate_limit",
          "Test account lockout / rate limiting after repeated attempts",
          "Authentication vulnerabilities"),
    Check("WSTG-ATHN-09", "Weak password-reset token", Phase.ENDPOINT,
          "reset_token", _has_auth_endpoint, "reset_token",
          "Test password-reset tokens for predictability (sequential, timestamp, "
          "below-entropy-floor, or derived from a known value)",
          "Authentication vulnerabilities"),
    Check("WSTG-SESS-01", "Session management", Phase.ENDPOINT,
          "auth", _has_cookie_or_session, "auth_sequence",
          "Test session token generation, fixation, timeout",
          "Authentication vulnerabilities"),
    Check("WSTG-SESS-03", "Session fixation", Phase.ENDPOINT,
          "session_fixation", _has_auth_endpoint, "auth_sequence",
          "Test if session tokens are regenerated after login"),
    Check("WSTG-BUSL-09", "File upload", Phase.ENDPOINT,
          "file_upload", _has_file_path_segment, "manual",
          "Test file type/size/content validation on upload endpoints",
          "File upload vulnerabilities"),
    Check("WSTG-ATHZ-01", "Path traversal", Phase.ENDPOINT,
          "path_traversal", _has_file_path_segment, "path_traversal",
          "Test for directory traversal in file-serving endpoints",
          "Path traversal"),
    Check("WSTG-ERRH-01", "Error handling / stack traces", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "recon",
          "Trigger errors and check for verbose stack traces / debug info"),
    # Mass assignment is an API-layer scenario with NO dedicated WSTG v4.2 test
    # (WSTG-CONF-09 is "Test File Permission" -- a different thing), so it carries an
    # internal id and its real sources live in external_refs. See coverage_manifest.
    Check("AV-MASSASSIGN-01", "Mass assignment (server-controlled field protection)", Phase.ENDPOINT,
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
          )),
    Check("WSTG-BUSV-04", "HTTP request smuggling", Phase.ENDPOINT,
          "http_request_smuggling", _accepts_body, "http_request_smuggling",
          "Test CL/TE and TE/CL desync",
          "HTTP request smuggling"),
    Check("WSTG-INPV-14", "HTTP header injection / CRLF", Phase.ENDPOINT,
          "header_injection", _accepts_input, "header_injection",
          "Inject CRLF sequences in header-reflected parameters"),
    # WSTG-SESS-05 is the current WSTG id for CSRF (was mislabelled SESS-09 --
    # weakness #7). Confirmation is "manual": the csrf leg's autonomous verdict was
    # retired to an observation (ORACLE_RETIREMENTS.md), so CSRF needs a human/PoC.
    Check("WSTG-SESS-05", "CSRF", Phase.ENDPOINT,
          "csrf", _accepts_body, "manual",
          "Test state-changing requests for anti-CSRF protections",
          "Cross-site request forgery (CSRF)"),

    # === PARAMETER phase ===
    Check("WSTG-INPV-05", "SQL injection", Phase.PARAMETER,
          "sqli", _accepts_input, "sqlmap",
          "Test all input parameters for SQL injection",
          "SQL injection"),
    Check("WSTG-INPV-01", "Reflected XSS", Phase.PARAMETER,
          "xss", _accepts_input, "browser_xss",
          "Test input reflection in HTML responses for script injection",
          "Cross-site scripting (XSS)"),
    Check("WSTG-INPV-02", "Stored XSS", Phase.PARAMETER,
          "xss", _accepts_body, "stored_xss",
          "Test stored input rendered in HTML context",
          "Stored cross-site scripting"),
    Check("WSTG-CLNT-01", "DOM-based XSS", Phase.PARAMETER,
          "dom_xss", _accepts_input, "dom_xss",
          "Test client-side sources (location.hash/.search) flowing to a DOM sink",
          "DOM-based cross-site scripting"),
    Check("WSTG-INPV-12", "Command injection", Phase.PARAMETER,
          "command_injection", _accepts_input, "command_injection",
          "Test for OS command injection in parameters",
          "OS command injection"),
    Check("WSTG-INPV-18", "Server-side template injection", Phase.PARAMETER,
          "ssti", _accepts_input, "ssti",
          "Test for template expression evaluation",
          "Server-side template injection (SSTI)"),
    Check("WSTG-INPV-07", "XXE", Phase.PARAMETER,
          "xxe", _accepts_xml, "xxe",
          "Test XML-accepting endpoints for external entity processing",
          "XML external entity (XXE) injection"),
    Check("WSTG-INPV-19", "SSRF", Phase.PARAMETER,
          "ssrf", _has_url_param, "ssrf",
          "Test URL parameters for server-side request forgery",
          "Server-side request forgery (SSRF)"),
    Check("WSTG-INPV-17", "Open redirect", Phase.PARAMETER,
          "open_redirect", _has_url_param, "open_redirect",
          "Test redirect parameters for off-site redirection",
          "Open redirection"),
    Check("WSTG-INPV-06", "NoSQL injection", Phase.PARAMETER,
          "nosql", _accepts_input, "agent",
          "Test for NoSQL query manipulation",
          "NoSQL injection"),
    Check("WSTG-CRYP-04", "JWT weaknesses", Phase.PARAMETER,
          "jwt", _is_authed, "jwt_forge",
          "Test JWT algorithm confusion, key disclosure, claim tampering",
          "JWT attacks"),
    Check("WSTG-INPV-11", "Insecure deserialization", Phase.PARAMETER,
          "deserialization", _accepts_body, "deserialization_oob",
          "Test for unsafe deserialization of user-supplied data",
          "Insecure deserialization"),
    Check("WSTG-BUSL-07", "Race conditions", Phase.PARAMETER,
          "race_condition", _accepts_body, "race_condition",
          "Test for TOCTOU and concurrent-request bugs",
          "Race conditions"),
    Check("WSTG-BUSL-08", "TOCTOU privilege-escalation race", Phase.ENDPOINT,
          "toctou", _accepts_body, "toctou",
          "Concurrent copies of an authority-changing write race a check-then-write "
          "window; confirm a privilege field flipped under concurrency via re-read",
          "Race conditions"),
)

CHECKS_BY_ID: dict[str, Check] = {c.id: c for c in CHECK_CATALOG}
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
               evidence: str | None = None) -> CellResult:
        """Record a check result. Does NOT overwrite a CONFIRMED cell."""
        key = (identity, endpoint_key, check_id)
        existing = self._cells.get(key)
        if existing and existing.status == CellStatus.CONFIRMED:
            return existing
        result = CellResult(status=status, reason=reason, severity=severity,
                            confidence=confidence, validator=validator, evidence=evidence)
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
                    validator: str | None = None, evidence: str | None = None) -> CellResult:
        """Record the outcome of ONE concrete case, then re-aggregate its parent
        cell. A CONFIRMED case is never overwritten (same monotonicity as `record`).
        Registers the case if `expand_cases` had not already."""
        key = (identity, endpoint_key, check_id)
        bucket = self._cases.setdefault(key, {})
        cid = case_key.coord_id()
        existing = bucket.get(cid)
        if existing and existing[1].status == CellStatus.CONFIRMED:
            self._aggregate_cell(key)
            return existing[1]
        result = CellResult(status=status, reason=reason, severity=severity,
                            confidence=confidence, validator=validator, evidence=evidence)
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
        # Never downgrade a locked CONFIRMED cell.
        if prior and prior.status == CellStatus.CONFIRMED and agg != CellStatus.CONFIRMED:
            return
        self._cells[key] = CellResult(status=agg, reason=reason)

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
        """Cells that were NOT tested, with the reason (I2/I5)."""
        result = []
        for (identity, ep_key, check_id), cell in self._cells.items():
            if cell.status in (CellStatus.NOT_APPLICABLE, CellStatus.SKIPPED):
                result.append({
                    "identity": identity,
                    "endpoint": ep_key,
                    "check": check_id,
                    "status": cell.status.value,
                    "reason": cell.reason,
                })
        return result

    def to_dict(self) -> dict:
        out: dict = {
            "cells": {
                f"{i}|{e}|{c}": r.to_dict()
                for (i, e, c), r in self._cells.items()
            }
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
        return out

    @classmethod
    def from_dict(cls, d: dict) -> "CoverageMatrix":
        m = cls()
        for key_str, cell_dict in (d.get("cells", {}) or {}).items():
            parts = key_str.split("|", 2)
            if len(parts) == 3:
                m._cells[(parts[0], parts[1], parts[2])] = CellResult.from_dict(cell_dict)
        for key_str, cases in (d.get("cases", {}) or {}).items():
            parts = key_str.split("|", 2)
            if len(parts) != 3:
                continue
            bucket = m._cases.setdefault((parts[0], parts[1], parts[2]), {})
            for entry in cases or []:
                ck = CaseKey.from_dict(entry.get("key", {}) or {})
                res = CellResult.from_dict(entry.get("result", {}) or {})
                bucket[ck.coord_id()] = (ck, res)
        return m
