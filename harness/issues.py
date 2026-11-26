"""issues.py -- stable issue identity + reproducible export (Astra T06).

The harness already has two identities from T01/T05: a *case* id (one concrete
test scenario -- principal + request template + check + input/state) and a
*proof* id (one attempt at that scenario). What it lacks is the third: a stable
*issue* id for the underlying bug that several findings/cases share, so that:

  - retesting a scenario (a new run, a new case/proof) maps back to the SAME
    issue instead of spawning a new one -- a patched-fixture retest links to the
    original issue rather than deleting history; and
  - grouping is conservative: it keys on endpoint family + method + canonical
    class + affected input + authorization boundary, so two SQLi inputs on one
    endpoint stay distinct, read and write boundaries stay distinct, and an
    unknown value never acts as a wildcard that collapses unrelated findings.

An `Issue` keeps ALL of its member findings (their urls/object ids, evidence,
and case/proof references) -- never just a winning representative and a count --
and `export_issue`/`replay_view` render a reproducible, secret-free report: the
prerequisites, principal aliases, request sequence, expected-vs-observed
behavior, impact, proof references, limitations, and retest instructions.

Pure and deterministic; no network, no model call. Issue ids deliberately EXCLUDE
the run id so they are stable across runs (the whole point of retest linkage).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import NamedTuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from harness.categories import (canonicalize, distinctive_token, finding_class,
                                 is_lead_label)
from harness.engagement import normalize_path
from harness import security

_ISSUE_VERSION = 2   # 2: csp/cors issues group by host + header_fingerprint (E2)

# Method -> the authorization boundary it crosses. A safe method reads; a
# body/state method writes. Kept explicit (not merely implied by the method) so
# the same class on the same endpoint under a read vs a write stays two issues.
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", ""})


def _boundary_for(method: str) -> str:
    return "read" if (method or "").upper() in _READ_METHODS else "write"


def _short(*parts: object) -> str:
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _affected_input(finding: dict) -> str:
    """The concrete input coordinate (T05) a finding concerns, as a stable token.
    Empty when the finding is whole-request/endpoint-scoped -- and an empty value
    groups only with other empties, never as a wildcard over known inputs."""
    loc = (finding.get("parameter_location") or "").strip()
    name = (finding.get("parameter_name") or "").strip()
    if not loc and not name:
        return ""
    # headers fold case for identity (the coverage layer already lower-cases them)
    return f"{loc}:{name}"


# RB-3 (INV-4): the `vulnerability_class` prefixes orchestrator_detect.py's
# `_resolve_known_vulnerabilities`/`_check_registry_ages` stamp onto a
# dependency/banner advisory (`known-vulnerable-dependency:<component>`,
# `recently-published-dependency:<component>`). A finding in this family is a
# HOST-level fact about the running software (e.g. "this host runs a
# vulnerable Werkzeug version"), observed passively from a response header/
# manifest -- not an endpoint- or method-scoped claim, and it never carries a
# parameter_location/parameter_name (so `_affected_input` above is always "").
_DEPENDENCY_CLASS_PREFIXES = ("known-vulnerable-dependency:", "recently-published-dependency:")


def _is_dependency_class(vulnerability_class: str) -> bool:
    return (vulnerability_class or "").strip().lower().startswith(_DEPENDENCY_CLASS_PREFIXES)


# E2: a header-policy finding (a missing or weak CSP, a CORS grant) is a fact about
# the response-header policy a host serves, which one header set repeats on every
# route. These canonical classes group by host + class + the policy's fingerprint
# (Finding.header_fingerprint), not by endpoint family, so 30 routes serving one
# policy are one issue listing 30 routes; routes with different policies stay apart.
#
# Finding dedup (juice-shop-8h, 2026-11-03): insecure transport and missing security
# headers are host-wide facts the model files once per endpoint (28 transport rows over
# 15 routes in one run). They join this set and, unlike csp/cors, group by host even
# when no policy fingerprint is known: transport is decided by the scheme, which the
# host key already carries, and a model finding never has a fingerprint. A known
# fingerprint still splits different policies.
_HOST_WIDE_CLASSES = frozenset({"insecure_transport", "missing_headers"})
_HEADER_POLICY_CLASSES = frozenset({"csp", "cors"}) | _HOST_WIDE_CLASSES

# Batch 08 / AR-08b: confirmation mechanisms whose proven flaw is a host trust policy,
# not a route (a token verifier accepting forgeries). One policy fingerprint on several
# routes is one issue listing every route. The per-mechanism decisions and reasons are
# in .test-work/ar08b-issue-identity-20261102/BATCH.md; assessment_health reads this set.
ROUTE_INDEPENDENT_MECHANISMS = frozenset({"jwt_forge"})


def _policy_of(finding: dict) -> str:
    """The policy fingerprint a confirmation was decided under: the one persisted
    with its proof (AR-08a, surfaced by store.all_host_findings) wins over the
    in-run Finding.header_fingerprint. "" (unknown) never merges routes."""
    return finding.get("policy_fingerprint") or finding.get("header_fingerprint") or ""


def _route_independent_identity(finding: dict) -> str:
    """The trust-boundary identity of a route-independent mechanism's finding, or ""
    when it is not one (or its policy is unknown). Mechanism, policy fingerprint,
    principal and workflow state: a different policy or principal is another issue."""
    validator = finding.get("validator") or ""
    policy = _policy_of(finding)
    if validator not in ROUTE_INDEPENDENT_MECHANISMS or not policy:
        return ""
    return "\x1f".join(("mechanism", validator, policy, finding.get("principal_id") or "",
                        finding.get("workflow_state_id") or ""))


# --------------------------------------------------------------------------- #
# Header-policy identity from the recorded policy (r10 report noise, 2026-11-13)
# --------------------------------------------------------------------------- #
# r10 reported one csp issue per route (101 confirmed rows over 45 routes, one absent
# CSP) and one misconfig issue per route for one missing X-Content-Type-Options. Stored
# rows carry no fingerprint (a coverage or passive proof names no artifact), so E2 fell
# back to the endpoint key. A header-policy row now keys on origin + class + header
# name + the observed policy, read from what the row recorded, strongest first:
#   1. the persisted or in-run policy fingerprint: E2's key, unchanged;
#   2. the csp validator's observed values (CSP, report-only CSP, X-Frame-Options) in
#      its own evidence: the same fingerprint E2 computes in-run, so issue ids agree;
#   3. the security-header audit's failure lines (header name, absent or bad value);
#   4. the csp validator's failing-test lines when no value is recorded (a proof bound
#      to a model row): a partial record, the values themselves unknown;
#   5. nothing recorded: origin + class + header name, and the issue says so.
# The identity is the recorded value, so two routes whose recorded values differ never
# share a key. 4 and 5, and a value the validator recorded cut short, are "not
# recorded": the export and the report say the routes may differ.
#
# Classes (categories.py): csp -- a missing or weak CSP, and framing protection, which
# the taxonomy files as csp ("clickjacking", "missing x frame options"); missing_headers
# -- missing security headers, HSTS among them; and a misconfig row whose record is the
# security-header audit (security_headers_validator files WSTG-CONF-14 as misconfig;
# any other misconfig row keeps its endpoint key). A label the taxonomy does not map
# that names a policy header and its absence ("Missing Strict-Transport-Security
# Header", "csp_missing") is read as that header's class, for issue grouping only.
# cors and insecure_transport keep E2: a CORS grant depends on the request Origin and
# the route, and transport is the scheme the origin already carries.

class HeaderPolicy(NamedTuple):
    vulnerability_class: str          # the issue's class
    headers: tuple[str, ...]          # lower-case response header names
    identity: str                     # the observed policy: the issue key's last element
    recorded: bool                    # False: the value is not recorded; routes may differ
    observed: tuple[tuple[str, str], ...] = ()   # (header, value as recorded) for display


_CSP_VALIDATOR = "csp_validator"
_AUDIT_VALIDATOR = "security_headers_validator"
_CSP_HEADERS = ("content-security-policy", "content-security-policy-report-only", "x-frame-options")
# Validator write limits: csp_validator cuts a value at 300 characters and appends
# "...", security_headers_validator quotes the first 60 characters of a bad value.
_CSP_VALUE_LIMIT = 300
_AUDIT_VALUE_LIMIT = 60
# csp and missing_headers key on the record while E2 groups them (_HEADER_POLICY_CLASSES).
_RECORDED_POLICY_CLASSES = frozenset({"csp", "missing_headers"})

# Policy header -> (class, label phrases that name it, read as words).
_POLICY_HEADERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "content-security-policy": ("csp", ("content security policy", "csp")),
    "x-frame-options": ("csp", ("x frame options", "clickjacking", "frame ancestors")),
    "strict-transport-security": ("missing_headers", ("strict transport security", "hsts")),
    "x-content-type-options": ("missing_headers", ("x content type options", "nosniff")),
    "referrer-policy": ("missing_headers", ("referrer policy",)),
    "permissions-policy": ("missing_headers", ("permissions policy", "feature policy")),
}
_ABSENCE_RE = re.compile(r"\b(?:missing|absent|lacks?|lacking|no|without|weak|not set)\b")

_CSP_OBSERVED_RE = re.compile(
    r"Content-Security-Policy: (?P<csp>.*?) \| Content-Security-Policy-Report-Only: (?P<ro>.*?)"
    r" \| X-Frame-Options: (?P<xfo>.*?)(?= \| |$)", re.S)
_CSP_TEST_RE = re.compile(r"(CSP Presence|CSP Directive Analysis|Framing Protection): ")
_CSP_TEST_HEADER = {"CSP Presence": "content-security-policy",
                    "CSP Directive Analysis": "content-security-policy",
                    "Framing Protection": "x-frame-options"}
_AUDIT_RE = re.compile(
    r"(?P<nosniff>X-Content-Type-Options) is (?:missing|(?P<q>['\"])(?P<value>.*?)(?P=q), not 'nosniff')"
    r"|(?P<referrer>Referrer-Policy) resolves to '(?P<policy>[^']*)'")


def _label_words(text: str) -> str:
    return " ".join(re.sub(r"[-_‐-―]", " ", (text or "").lower()).split())


def _named_headers(label: str) -> tuple[str, ...]:
    words = _label_words(label)
    return tuple(h for h, (_, phrases) in _POLICY_HEADERS.items()
                 if any(re.search(rf"\b{re.escape(p)}\b", words) for p in phrases))


def _header_label_class(label: str) -> str:
    """The header-policy class a label names, else "". Grouping only: a label the
    taxonomy recognises keeps its own class, and categories.canonicalize (which routes
    validators) is not changed."""
    if canonicalize(label) or distinctive_token(label):
        return ""
    words = _label_words(label)
    found = canonicalize(re.sub(r"\s+headers?$", "", words))
    if found in _RECORDED_POLICY_CLASSES:
        return found
    classes = {_POLICY_HEADERS[h][0] for h in _named_headers(label)}
    return next(iter(classes)) if len(classes) == 1 and _ABSENCE_RE.search(words) else ""


def _recorded_texts(finding: dict, owner: str) -> list[str]:
    """What the owning validator recorded for this row: the evidence when it wrote the
    row, and, when the row's linked proof is its own, that proof's observed result and
    the proof note the binding appended (`<validator> CONFIRMED: ...`,
    store.bind_confirmation_proof). A model's own wording is never read."""
    head, *notes = (finding.get("evidence") or "").split(" || ")
    texts = [head] if (finding.get("agent") or "") == owner else []
    if (finding.get("validator") or "") == owner:
        marker = f"{owner} CONFIRMED: "
        texts.append(finding.get("proof_observed_result") or "")
        texts += [note[len(marker):] for note in notes if note.startswith(marker)]
    return [t for t in texts if t]


def _policy_identity(headers: tuple[str, ...], values: tuple) -> str:
    from harness.validators.base import header_fingerprint
    return "hdr:" + ",".join(headers) + "=" + header_fingerprint(*values)


def _shown(value) -> str:
    return "absent" if value is None else (value or "(empty)")


def _csp_policy(finding: dict, label: str) -> HeaderPolicy:
    from harness.validators.base import header_fingerprint
    fingerprint = _policy_of(finding)
    if fingerprint:
        return HeaderPolicy("csp", _CSP_HEADERS, fingerprint, True)
    texts = _recorded_texts(finding, _CSP_VALIDATOR)
    for text in texts:
        m = _CSP_OBSERVED_RE.search(text)
        if not m:
            continue
        raw = (m.group("csp"), m.group("ro"), m.group("xfo"))
        values = tuple(None if v == "absent" else ("" if v == "(empty)" else v) for v in raw)
        cut = any(v and len(v) > _CSP_VALUE_LIMIT and v.endswith("...") for v in values)
        observed = tuple(zip(_CSP_HEADERS, (_shown(v) for v in values)))
        if cut:   # only a prefix is recorded: equal prefixes may still differ
            return HeaderPolicy("csp", _CSP_HEADERS, "hdr~" + header_fingerprint(*values),
                                False, observed)
        return HeaderPolicy("csp", _CSP_HEADERS, header_fingerprint(*values), True, observed)
    tests: dict[str, str] = {}
    for text in texts:
        marks = list(_CSP_TEST_RE.finditer(text))
        for here, after in zip(marks, marks[1:] + [None]):
            detail = text[here.end():after.start() if after else len(text)]
            detail = re.sub(r"\s*(?:\((?:critical|high|medium|low|info)\))?\s*[|-]?\s*$", "", detail)
            tests.setdefault(here.group(1), " ".join(detail.split()).lower())
    if tests:
        headers = tuple(sorted({_CSP_TEST_HEADER[t] for t in tests}))
        return HeaderPolicy("csp", headers, "tests:" + _short(*sorted(f"{t}: {d}" for t, d in tests.items())),
                            False)
    headers = tuple(h for h in _named_headers(label) if _POLICY_HEADERS[h][0] == "csp") \
        or ("content-security-policy",)
    return HeaderPolicy("csp", headers, "hdr:" + ",".join(headers) + "=?", False)


def _audit_policy(finding: dict, cls: str) -> HeaderPolicy | None:
    """The security-header audit's recorded failures (WSTG-CONF-14), or None."""
    for text in _recorded_texts(finding, _AUDIT_VALIDATOR):
        states: dict[str, str | None] = {}
        for m in _AUDIT_RE.finditer(text):
            if m.group("nosniff"):
                states.setdefault("x-content-type-options", m.group("value"))
            else:
                states.setdefault("referrer-policy", m.group("policy"))
        if states:
            headers = tuple(sorted(states))
            values = tuple(states[h] for h in headers)
            cut = any(v is not None and len(v) >= _AUDIT_VALUE_LIMIT for v in values)
            observed = tuple(zip(headers, (_shown(v) for v in values)))
            return HeaderPolicy(cls, headers, ("hdr~" if cut else "") + _policy_identity(headers, values),
                                not cut, observed)
    return None


def header_policy(finding: dict) -> HeaderPolicy | None:
    """The response-header policy a finding is about, read from its record (see the
    block comment above), or None when it is not a header-policy finding."""
    vc = finding.get("vulnerability_class", "") or ""
    if _is_dependency_class(vc):
        return None
    canon = issue_class(vc)
    if canon == "misconfig":
        return _audit_policy(finding, "misconfig")
    if canon not in _RECORDED_POLICY_CLASSES:
        canon = _header_label_class(vc)
    if canon not in _RECORDED_POLICY_CLASSES or canon not in _HEADER_POLICY_CLASSES:
        return None
    if canon == "csp":
        return _csp_policy(finding, vc)
    fingerprint = _policy_of(finding)
    headers = _named_headers(vc)
    if fingerprint:
        return HeaderPolicy(canon, headers, fingerprint, True)
    audited = _audit_policy(finding, canon)
    if audited:
        return audited
    # Unnamed headers keep E2's host-wide key ("") and issue id.
    return HeaderPolicy(canon, headers, ("hdr:" + ",".join(headers) + "=?") if headers else "", False)


# --------------------------------------------------------------------------- #
# Redaction -- an export/replay must never carry a live secret
# --------------------------------------------------------------------------- #

# Secret-bearing key names, matched in query strings, form bodies, JSON, and headers.
_SECRET_KEYS = (r"session|sessionid|session_id|token|access_token|refresh_token|id_token|sid|"
                r"jsessionid|csrf|xsrf|api[_-]?key|apikey|secret|client_secret|password|passwd|"
                r"pwd|passwd|auth|authorization|cookie|bearer|private_key")

_SECRET_PATTERNS = (
    # Authorization: Bearer <token> / Basic <b64>
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 <REDACTED>"),
    # Cookie / Set-Cookie / Authorization header lines
    (re.compile(r"(?i)\b(set-cookie|cookie|authorization)\s*:\s*[^\r\n]+"), r"\1: <REDACTED>"),
    # key=value in a form/query (secret keys only)
    (re.compile(r"(?i)\b(" + _SECRET_KEYS + r")=([^&\s;]+)"), r"\1=<REDACTED>"),
    # JSON "key": "value" or "key": value (secret keys only)
    (re.compile(r'(?i)("(?:' + _SECRET_KEYS + r')")(\s*:\s*)("[^"]*"|[^,}\s]+)'), r"\1\2<REDACTED>"),
    # a bare JWT (three base64url segments)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"), "<REDACTED-JWT>"),
)


def redact(text: str) -> str:
    """Mask anything that looks like a credential/session value in free text --
    Authorization/Cookie lines, secret-keyed query/form/JSON values, and bare JWTs.
    Conservative and idempotent: it never fabricates, only masks recognizable
    secret shapes."""
    from harness import security
    out = security.sanitize_text(text or "")
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out


def redact_url(url: str) -> str:
    """Return a URL with any credential in userinfo or a secret query parameter
    masked (R03) -- so an exported/affected URL never leaks a `?token=...` or
    `user:pass@` while keeping the endpoint itself legible."""
    if not url:
        return url or ""
    from harness import security
    url = security.redact_secrets_in_url(url)
    try:
        parts = urlsplit(url)
    except ValueError:
        return redact(url)
    netloc = parts.netloc
    if "@" in netloc:  # user:pass@host -> mask the userinfo
        netloc = "<REDACTED>@" + netloc.rsplit("@", 1)[1]
    query = parts.query
    if query:
        secret_re = re.compile(r"(?i)^(" + _SECRET_KEYS + r")$")
        pairs = [(k, "<REDACTED>" if secret_re.match(k) else v)
                 for k, v in parse_qsl(query, keep_blank_values=True)]
        query = urlencode(pairs, safe="<>")   # keep the <REDACTED> placeholder legible
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


# --------------------------------------------------------------------------- #
# Issue
# --------------------------------------------------------------------------- #

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Issue:
    """A stable-identity grouping of findings that share one underlying bug."""
    issue_id: str
    endpoint_family: str
    method: str
    vulnerability_class: str          # canonical
    affected_input: str               # "" = whole-request
    authorization_boundary: str       # "read" | "write"
    host: str = ""                    # application namespace (scheme+host)
    members: list[dict] = field(default_factory=list)   # the raw finding dicts, ALL kept
    version: int = _ISSUE_VERSION

    # --- aggregates over members (a proven member floats the issue up) ---

    @property
    def confirmed(self) -> bool:
        return any(m.get("confirmed") for m in self.members)

    @property
    def lead(self) -> bool:
        """R11-2: every member is labelled a lead ("potential_idor"). The marker is a
        flag, not part of the class: a lead and a confirmed finding of the class on
        one route are one issue, which is no longer a lead."""
        return bool(self.members) and all(
            is_lead_label(m.get("vulnerability_class")) for m in self.members)

    @property
    def oracle_verified(self) -> bool:
        """R06: the oracle-verification axis (orthogonal to `confirmed`, the
        legacy "a leg fired once" bar) must survive issue aggregation and
        export -- a leg-confirmed issue whose oracle never reproduced it is
        NOT the same claim as one the oracle actually verified."""
        return any(m.get("oracle_verified") for m in self.members)

    @property
    def verification_state(self) -> str:
        """The strongest operator-facing oracle label across members:
        "verified" if any member reached it, else "candidate" -- distinct
        from `confirmed`, which only means a leg fired at least once."""
        return "verified" if self.oracle_verified else "candidate"

    @property
    def oracle_capsule_ids(self) -> list[str]:
        return sorted({m.get("oracle_capsule_id") for m in self.members if m.get("oracle_capsule_id")})

    @property
    def severity(self) -> str:
        return min((m.get("severity", "info") or "info" for m in self.members),
                   key=lambda s: _SEV_ORDER.get(s.lower(), 99), default="info")

    @property
    def confidence(self) -> float:
        return max((float(m.get("confidence", 0.0) or 0.0) for m in self.members), default=0.0)

    @property
    def case_ids(self) -> list[str]:
        return sorted({m.get("case_id") for m in self.members if m.get("case_id")})

    @property
    def proof_ids(self) -> list[str]:
        return sorted({m.get("proof_id") for m in self.members if m.get("proof_id")})

    @property
    def affected_instances(self) -> list[str]:
        """Every concrete URL (object id) the bug was observed on -- kept in full,
        so grouping never loses which instances were affected."""
        seen, out = set(), []
        for m in self.members:
            u = m.get("url") or ""
            if u and u not in seen:
                seen.add(u)
                out.append(u)
        return out

    @property
    def best_member(self) -> dict:
        """The strongest single observation (confirmed > oracle-verified > not a
        demoted LEAD > severe > confident), used for the export's headline evidence
        and triage -- without discarding the others. The verdict terms come before
        severity so a merged issue never shows a weaker verdict than a member has."""
        return max(self.members, key=verdict_rank) if self.members else {}

    @property
    def member_ids(self) -> list[str]:
        """Every member's finding id (fingerprint when it has none), in member order."""
        return [m.get("finding_id") or m.get("fingerprint") or "" for m in self.members]

    @property
    def header_policy(self) -> HeaderPolicy | None:
        """The members' header policy (see `header_policy`): every header named, and
        recorded only when every member recorded its value. None when no member is a
        header-policy finding."""
        policies = [p for p in (header_policy(m) for m in self.members) if p is not None]
        if not policies:
            return None
        return HeaderPolicy(policies[0].vulnerability_class,
                            tuple(sorted({h for p in policies for h in p.headers})),
                            policies[0].identity, all(p.recorded for p in policies),
                            next((p.observed for p in policies if p.observed), ()))


def verdict_rank(m: dict) -> tuple:
    """Order observations strongest-verdict first, then severity, then confidence."""
    from harness.confirmation_gate import STATE_LEAD, finding_lifecycle_state
    return (1 if m.get("confirmed") else 0,
            1 if m.get("oracle_verified") else 0,
            0 if finding_lifecycle_state(m) == STATE_LEAD else 1,
            -_SEV_ORDER.get((m.get("severity") or "info").lower(), 99),
            float(m.get("confidence", 0.0) or 0.0))


def _host_of(url: str) -> str:
    """The application/target namespace of a URL (scheme+host+port). Without it,
    same-path findings on different targets collide (review R04)."""
    if not url:
        return ""
    try:
        p = urlsplit(url)
    except ValueError:
        return ""
    if not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}" if p.scheme else p.netloc


def issue_key(finding: dict, *, recorded_policy: bool = True) -> tuple:
    """The conservative grouping key (T06). Application namespace (scheme+host),
    endpoint family (object ids collapsed), method, canonical class, affected
    input, and authorization boundary. When the affected input is UNKNOWN, a
    per-finding disambiguator (finding_id/fingerprint) is added so two distinct
    unattributed findings do NOT collapse into one issue (review R04); attributed
    inputs and repeated object ids that share a known input still group. Finding
    dedup (2026-11-03): the disambiguator is dropped when the class is canonical
    (`issue_class`), except for an input-bearing class on a row stored before its
    input was recorded, which keeps its stored fingerprint.

    RB-3 (INV-4) exception: a dependency/banner-class finding (see
    `_is_dependency_class`) is a host-level advisory about running software,
    not an endpoint-scoped claim -- the identical advisory can be
    independently re-observed on many different exchanges/endpoints (each
    carrying its own url/finding_id), and, having no parameter_location/
    parameter_name, would otherwise always hit the UNKNOWN-input branch above
    and get the finding_id/fingerprint disambiguator appended -- turning every
    repeat into its own issue. That disambiguator exists to stop an unknown
    input acting as a wildcard over otherwise-unrelated findings (R04); it is
    not needed here because `canon` already carries the exact component
    identity (canonicalize() returns None for these compound
    "prefix:<component>" strings -- no CANONICAL_CATEGORIES/_SYNONYMS entry
    matches -- so `canon` falls back to the raw lowercased string, keeping two
    DIFFERENT components, e.g. Werkzeug vs Flask, on different keys). So this
    branch groups by host + canonical class/component only: endpoint_family
    and method are dropped (irrelevant to a host-wide banner) and no
    disambiguator is added, letting genuinely identical advisories collapse to
    ONE issue regardless of which exchange first surfaced them.

    E2 exception: a header-policy finding (csp, cors; see `_HEADER_POLICY_CLASSES`)
    groups by host + class + the policy fingerprint (`_policy_of`), with no endpoint
    family or method. insecure_transport and missing_headers do too, and also when
    the policy is unknown (`_HOST_WIDE_CLASSES`).

    Recorded-policy exception (2026-11-13): a header-policy row (`header_policy`) groups
    by host + class + the header names and observed policy its record holds, a stored
    row as much as an in-run one. `recorded_policy=False` gives the key as it was before
    (pivot_memory's same-route attach reads that one, so binding is unchanged).

    AR-08b exception: a finding confirmed by a route-independent mechanism (see
    `ROUTE_INDEPENDENT_MECHANISMS`) with a known policy groups by host + class +
    affected input (the carrier) + read/write boundary + `_route_independent_identity`
    (mechanism, policy, principal, workflow state), with no endpoint family or method.
    The read/write boundary is kept so a read and a write never merge."""
    url = finding.get("url", "")
    host = _host_of(url)
    method = (finding.get("method") or "").upper()
    vc = finding.get("vulnerability_class", "") or ""
    if _is_dependency_class(vc):
        return (host, "", "", canonicalize(vc) or vc.strip().lower(), "", "read", "")
    canon = issue_class(vc)
    policy = header_policy(finding) if recorded_policy else None
    if policy is not None:
        return (host, "", "", policy.vulnerability_class, "", "read", policy.identity)
    # Without a fingerprint (a model finding, or a proof stored before AR-08a) nothing
    # says the policy is the same, so it keeps the endpoint-family key below rather
    # than matching every route -- except for the host-wide classes (see above).
    if canon in _HEADER_POLICY_CLASSES and (_policy_of(finding) or canon in _HOST_WIDE_CLASSES):
        return (host, "", "", canon, "", "read", _policy_of(finding))
    affected = _affected_input(finding)
    identity = _route_independent_identity(finding)
    if identity:
        return (host, "", "", canon, affected, _boundary_for(method), identity)
    family = normalize_path(url) if url else ""
    # Unknown input is not a wildcard: keep distinct findings distinct -- unless the
    # class is canonical. Then (host, endpoint family, method, class, boundary) already
    # names one issue, and the disambiguator only split every model finding (which never
    # carries an input) into its own issue. A raw-label fallback still keeps it.
    # A row stored before the findings table recorded its input (`input_recorded`
    # False) may have named one: for an input-bearing class its stored fingerprint,
    # which always hashed the input, keeps different inputs apart.
    if affected:
        disambiguator = ""
    elif canon in _CANONICAL_SET:
        disambiguator = (finding.get("fingerprint") or "") if (
            canon in _INPUT_BEARING_CLASSES and finding.get("input_recorded") is False) else ""
    else:
        disambiguator = finding.get("finding_id") or finding.get("fingerprint") or ""
    return (host, family, method, canon, affected, _boundary_for(method), disambiguator)


def issue_class(vulnerability_class: str) -> str:
    """The class an issue groups on: categories.finding_class, the one reading the
    R11-1 class gate and proof binding also use (EFF-2), so an issue groups on the
    class its proof was bound by. The stored finding fingerprint keeps
    categories.legacy_canonicalize so suppressions stay valid."""
    return finding_class(vulnerability_class)


from harness.categories import CANONICAL_CATEGORIES as _CANONICAL_CATEGORIES  # noqa: E402
from harness.categories import GROUPING_CLASSES as _GROUPING_CLASSES  # noqa: E402

# Classes that name one issue on (host, family, method, class, boundary) by themselves.
_CANONICAL_SET = frozenset(_CANONICAL_CATEGORIES) | frozenset(_GROUPING_CLASSES)
# Classes whose identity is the injected input, not the route or object.
_INPUT_BEARING_CLASSES = frozenset({
    "sqli", "nosql", "xss", "dom_xss", "command_injection", "ssti", "path_traversal",
    "xxe", "header_injection", "open_redirect", "ssrf", "file_upload", "deserialization"})


def issue_id_for(key: tuple) -> str:
    """Deterministic, run-independent id for a grouping key, so a retest maps to
    the same issue. Versioned so the scheme can evolve without silently colliding."""
    return _short(_ISSUE_VERSION, *key)


def group_findings_into_issues(findings: list[dict]) -> list[Issue]:
    """Group findings into stable issues by the conservative key, keeping ALL
    members. Chain hypotheses (potential-attack-chain:*) are left to the report's
    own chain section and skipped here. Order-stable on first appearance."""
    by_key: dict[tuple, Issue] = {}
    order: list[tuple] = []
    for f in findings:
        if (f.get("vulnerability_class", "") or "").startswith("potential-attack-chain:"):
            continue
        key = issue_key(f)
        issue = by_key.get(key)
        if issue is None:
            host, family, method, canon, ainput, boundary, _disambig = key
            issue = Issue(issue_id=issue_id_for(key), endpoint_family=family, method=method,
                          vulnerability_class=canon, affected_input=ainput,
                          authorization_boundary=boundary, host=host)
            by_key[key] = issue
            order.append(key)
        issue.members.append(f)
    return [by_key[k] for k in order]


def apply_merge_overrides(issues: list[Issue], merges: dict[str, str]) -> list[Issue]:
    """Apply operator-declared merge overrides on top of the automatic
    grouping (P1.8's "root-cause dedup" -- an operator's "these two issues
    are actually the same underlying bug" call that the conservative
    automatic key alone cannot make).

    `merges` maps a SOURCE issue_id to the TARGET issue_id it should be
    folded into -- typically `store.all_issue_merges(host)`. Resolved
    transitively (A->B, B->C folds A and B into C); a cycle or a target that
    is not among `issues` leaves that entry unresolved rather than dropping
    data or looping forever. Every member from every folded issue survives
    on the resulting Issue (duplicate members, from applying the override to
    the target issue itself, are not double-counted).

    Reversible BY CONSTRUCTION: `merges` is plain, separately-persisted data
    (see store.record_issue_merge/remove_issue_merge) applied on top of
    `group_findings_into_issues`'s deterministic output -- it never mutates
    a finding or an Issue. Removing an entry and recomputing from the SAME
    `issues` restores the pre-merge grouping exactly; no history is lost."""
    by_id = {iss.issue_id: iss for iss in issues}

    def _resolve(issue_id: str, seen: frozenset[str] = frozenset()) -> str:
        target = merges.get(issue_id)
        if not target or target not in by_id or target == issue_id or issue_id in seen:
            return issue_id
        return _resolve(target, seen | {issue_id})

    merged: dict[str, Issue] = {}
    order: list[str] = []
    for iss in issues:
        final_id = _resolve(iss.issue_id)
        canonical_source = by_id[final_id]
        canonical = merged.get(final_id)
        if canonical is None:
            canonical = Issue(
                issue_id=canonical_source.issue_id,
                endpoint_family=canonical_source.endpoint_family,
                method=canonical_source.method,
                vulnerability_class=canonical_source.vulnerability_class,
                affected_input=canonical_source.affected_input,
                authorization_boundary=canonical_source.authorization_boundary,
                host=canonical_source.host,
            )
            merged[final_id] = canonical
            order.append(final_id)
        for member in iss.members:
            if member not in canonical.members:
                canonical.members.append(member)
    return [merged[k] for k in order]


# --------------------------------------------------------------------------- #
# Root causes (EFF-3)
# --------------------------------------------------------------------------- #
# r11 reported "117 unique" vulnerabilities against about 16-18 root causes: one CSP
# issue had 135 records, and 15 groups were a proof of one class filed under another.
# Three counts, each with its unit (ISSUE_UNITS), are reported side by side:
# occurrences (records), issues (issue_key groups) and root causes (root_cause_key).

ROOT_CAUSE_VERSION = 1

# The class a confirming mechanism (proof_records.validator, confirmed_by_leg) proves,
# primary first. A confirmed record whose label reads as one of these classes keeps
# it; any other label is a wrong-class duplicate and takes the primary class. A
# mechanism not listed here leaves the label's class as it is.
ROOT_CAUSE_MECHANISMS: dict[str, tuple[str, ...]] = {
    # Injection legs.
    "sqlmap": ("sqli",), "nosql": ("nosql",), "command_injection": ("command_injection",),
    "ssti": ("ssti",), "xxe": ("xxe",), "ssrf": ("ssrf",), "path_traversal": ("path_traversal",),
    "filter_bypass_validator": ("path_traversal",), "open_redirect": ("open_redirect",),
    "file_upload": ("file_upload",), "header_injection_validator": ("header_injection",),
    "browser_xss": ("xss",), "stored_xss": ("xss",), "dom_xss": ("dom_xss",),
    "deserialization_validator": ("deserialization",),
    "deserialization_oob": ("deserialization",),
    "http_request_smuggling_validator": ("http_request_smuggling",),
    "web_cache_poisoning_validator": ("web_cache_poisoning",),
    # Access control and business rules.
    "cross_identity": ("idor", "bfla"), "idor_read": ("idor",),
    "write_integrity": ("business_logic", "idor", "bfla", "api_security"),
    "client_trust": ("business_logic",), "business_flow": ("business_logic",),
    "csrf": ("csrf",), "rate_limit": ("rate_limit",), "verb_tamper": ("misconfig",),
    "race_condition_validator": ("race_condition", "toctou"), "toctou": ("toctou",),
    # Session and token policy.
    "jwt_forge": ("jwt",), "password_change_session": ("session_after_password_change",),
    "auth_sequence": ("auth", "session_fixation", "session_timeout", "session_expiry"),
    "reset_token": ("reset_token",), "oauth_validator": ("oauth",),
    "websocket_validator": ("websocket",),
    # Exposure.
    "api_security_validator": ("api_security",),
    "metrics_exposure_validator": ("metrics_exposure",),
    "sensitive_file_validator": ("info_disclosure",),
    "listing_exposure_validator": ("info_disclosure",),
    "content_exposure_validator": ("info_disclosure",),
    "well_known_validator": ("recon",), "recon_validator": ("recon",),
    "subdomain_takeover_validator": ("subdomain_takeover",),
    # Header and configuration legs.
    "csp_validator": ("csp",), "security_headers_validator": ("missing_headers",),
    "cors_validator": ("cors",), "crypto_validator": ("crypto",),
    "verbose_error_validator": ("verbose_error",), "error_handling_validator": ("verbose_error",),
}

# Root-cause classes that are one host's header or configuration policy. The names are
# scanner_overlap.SCANNER_OVERLAP_CLASSES (framing folded into csp, as the taxonomy
# files it; JWT header hygiene goes to the session-token rule) plus transport and TLS.
_CONFIG_ROOT_CLASSES = frozenset({"csp", "cors", "missing_headers", "cookie_flags",
                                  "verbose_error", "server_banner", "insecure_transport",
                                  "crypto"})
_OVERLAP_ROOT_CLASS = {"clickjacking": "csp", "jwt_header": "jwt"}
# One host's session-token or session-lifetime policy.
_SESSION_ROOT_CLASSES = frozenset({"jwt", "session_fixation", "session_timeout",
                                   "session_expiry", "session_after_password_change"})
# Object- and function-level authorization.
_ACCESS_ROOT_CLASSES = frozenset({"idor", "bfla"})
# api_security_validator's wording (validators/api_security_validator._probe_exposure)
# for credential material inside the caller's session token, against a credential
# field in the response body. Only the token reading is a host-wide root cause.
_TOKEN_CLAIM_MARK = "accepts a session token whose payload carries"
_RESPONSE_FIELD_MARK = "unmasked credential field"
# cross_identity_validator's proof summaries name the identity that crossed into the
# case principal's object: the second principal of an access-control pair, which no
# record field carries (captured_principal_id is the case principal's own capture).
_CROSSING_PRINCIPAL_RES = (re.compile(r"^Cross-identity \(([^)]+)\):"),
                           re.compile(r"^Broken object-level write authorization: ['\"]([^'\"]+)['\"]"))

ISSUE_UNITS = {
    "occurrences": "finding records: every stored or in-run row, repeats included",
    "issues": "issue groups by issues.issue_key: host, endpoint family, method, class, "
              "affected input and read/write boundary",
    "root_causes": "root-cause groups by issues.root_cause_key: one per host policy, "
                   "injectable parameter, authorization check or endpoint flaw",
}


def _confirming_mechanism(finding: dict) -> str:
    """The mechanism that confirmed the record, or "" when it is not confirmed."""
    if not finding.get("confirmed"):
        return ""
    for key in ("validator", "confirmed_by_leg", "confirmation_method"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def root_cause_class(finding: dict) -> str:
    """The class a record counts under for root causes: what its confirming mechanism
    proved (ROOT_CAUSE_MECHANISMS), else the label's class (issue_class), else, for an
    unconfirmed or unlisted record, the scanner-overlap reading of a header or
    configuration label ("Missing HSTS header" -> missing_headers)."""
    label = issue_class(finding.get("vulnerability_class", "") or "")
    proven = ROOT_CAUSE_MECHANISMS.get(_confirming_mechanism(finding))
    if proven:
        return label if label in proven else proven[0]
    if label in _CONFIG_ROOT_CLASSES or label in _SESSION_ROOT_CLASSES:
        return label
    from harness import scanner_overlap
    overlap = scanner_overlap.overlap_class(finding)
    if overlap:
        return _OVERLAP_ROOT_CLASS.get(overlap, overlap)
    return label


def _principal_pair(finding: dict, observed: str) -> tuple[str, ...]:
    """The sorted principals of an access-control record (see root_cause_key)."""
    names = {str(finding.get("principal_id") or "").strip()}
    for pattern in _CROSSING_PRINCIPAL_RES:
        match = pattern.match(observed.strip())
        if match:
            names.add(match.group(1).strip())
    return tuple(sorted(n for n in names if n))


def root_cause_key(finding: dict) -> tuple | None:
    """The root-cause grouping key (EFF-3), or None for a chain hypothesis.

    Every key starts with the host (scheme://host:port, lower case) and a rule name.
    The class is root_cause_class: a confirmed record takes the class its mechanism
    proved, so a wrong-class duplicate (an sqli label on a well-known observation)
    adds no root cause of its own. Rules, first match wins:

    | Rule          | Classes                                              | Key after host   |
    |---------------|------------------------------------------------------|------------------|
    | `dependency`  | known-vulnerable- / recently-published-dependency:*  | component        |
    | `config`      | csp (framing), cors, missing_headers, cookie_flags,  | class            |
    |               | verbose_error, server_banner, insecure_transport,    |                  |
    |               | crypto                                               |                  |
    | `session`     | jwt, session_fixation / _timeout / _expiry,          | class            |
    |               | session_after_password_change; an api_security       |                  |
    |               | proof of a secret in the session token only          |                  |
    | `injection`   | sqli, nosql, xss, dom_xss, command_injection, ssti,  | endpoint         |
    |               | path_traversal, xxe, header_injection, open_redirect,| template,        |
    |               | ssrf, file_upload, deserialization                   | input, class     |
    | `access`      | idor, bfla                                           | endpoint         |
    |               |                                                      | template,        |
    |               |                                                      | principal pair   |
    | `endpoint`    | everything else                                      | endpoint         |
    |               |                                                      | template, class  |

    - The endpoint template is engagement.normalize_path (object ids to {id}, no
      query, no trailing slash) folded to lower case: /Metrics and /metrics are one
      route on a case-insensitive router. The method is not part of it.
    - The input is the record's parameter_location:parameter_name; "" (none
      recorded) groups only with other unattributed records of that class there.
    - The principal pair is unordered: the record's principal_id and the identity a
      cross_identity proof names as crossing into that principal's object. A reading
      B's object and B reading A's are one missing check. A record that names one
      principal keys on that one; captured_principal_id is not a second principal.
    - Unlike issue_key, a header policy groups per host and class whatever its value
      or route, and an unknown input adds no per-record disambiguator.
    - A class the taxonomy does not read (free text) keeps its label: two different
      unread labels on one route stay two root causes."""
    vc = finding.get("vulnerability_class", "") or ""
    if vc.startswith("potential-attack-chain:"):
        return None
    url = finding.get("url", "") or ""
    host = _host_of(url).lower()
    if _is_dependency_class(vc):
        return (host, "dependency", canonicalize(vc) or vc.strip().lower())
    cls = root_cause_class(finding)
    if cls in _CONFIG_ROOT_CLASSES:
        return (host, "config", cls)
    observed = str(finding.get("proof_observed_result") or finding.get("observed_result") or "")
    if cls in _SESSION_ROOT_CLASSES or (
            cls == "api_security" and _TOKEN_CLAIM_MARK in observed
            and _RESPONSE_FIELD_MARK not in observed):
        return (host, "session", cls)
    template = normalize_path(url).lower() if url else ""
    if cls in _INPUT_BEARING_CLASSES:
        return (host, "injection", template, _affected_input(finding), cls)
    if cls in _ACCESS_ROOT_CLASSES:
        return (host, "access", template, _principal_pair(finding, observed))
    return (host, "endpoint", template, cls)


def root_cause_id_for(key: tuple) -> str:
    """Deterministic, run-independent id for a root-cause key."""
    return _short("root-cause", ROOT_CAUSE_VERSION, *key)


def count_units(findings: list[dict]) -> dict:
    """The three counts over the same records, each with its unit (ISSUE_UNITS):
    occurrences, issues (issue_key groups, before operator merge overrides) and root
    causes (root_cause_key groups). Chain hypotheses are not counted, as in
    group_findings_into_issues."""
    rows = [f for f in findings
            if not (f.get("vulnerability_class", "") or "").startswith("potential-attack-chain:")]
    return {"occurrences": len(rows),
            "issues": len({issue_key(f) for f in rows}),
            "root_causes": len({root_cause_key(f) for f in rows}),
            "units": dict(ISSUE_UNITS)}


# --------------------------------------------------------------------------- #
# Export -- reproducible, secret-free
# --------------------------------------------------------------------------- #

def _principal_aliases(issue: Issue) -> dict[str, str]:
    """Map the real principal labels seen on the members to stable aliases (P1,
    P2, ...) so an export names *which identity* without leaking a credential."""
    principals: list[str] = []
    for m in issue.members:
        p = m.get("principal_id") or m.get("identity") or ""
        if p and p not in principals:
            principals.append(p)
    return {f"P{i+1}": p for i, p in enumerate(principals)}


def _normalize_attempts(value) -> list[dict]:
    """Accept a single proof dict or a list of them; return a list."""
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    return [v for v in value if isinstance(v, dict)]


def _proof_references(issue: Issue, proofs_by_case: dict) -> list[dict]:
    """Reference the case/proof artifacts, resolving each verdict by the EXACT
    proof id (R09) and listing EVERY recorded attempt per case (R08) -- so a
    patched-fixture retest's outcome is preserved as its own attempt rather than
    overwriting the original. A member's own proof pointer is emitted only when the
    ledger has no recorded attempt for its case, and never with a fabricated verdict."""
    refs: list[dict] = []
    seen: set[tuple] = set()
    for m in issue.members:
        cid = m.get("case_id") or ""
        attempts = _normalize_attempts(proofs_by_case.get(cid)) if cid else []
        if attempts:
            for pr in attempts:
                pid = pr.get("proof_id", "")
                if (cid, pid) in seen:
                    continue
                seen.add((cid, pid))
                refs.append({"case_id": cid, "proof_id": pid, "verdict": pr.get("verdict", "")})
        else:
            pid = m.get("proof_id") or ""
            if (cid or pid) and (cid, pid) not in seen:
                seen.add((cid, pid))
                # no recorded attempt -> reference the pointer WITHOUT a verdict and
                # mark it unavailable: a dangling pointer is not replayable evidence (I02-A)
                refs.append({"case_id": cid, "proof_id": pid, "verdict": None,
                             "availability": "unavailable"})
    return refs


def _audited_oracle_state(issue: Issue, proofs_by_case: dict) -> tuple[bool, str, list[str]]:
    """R01: evidence_audit.audit_proof's real production consumer. Rather than
    exporting the raw, self-reported Finding.oracle_verified/verification_state
    fields at face value, audit EACH member's "verified" claim against its own
    linked, PERSISTED proof (via proofs_by_case, the same ledger
    _proof_references already resolves). A member claiming verified with no
    matching, executed, CONFIRMED proof reachable here is downgraded to
    candidate in the export -- a claim without an auditable backing proof is
    unverifiable, never exported as verified (R02's rule, enforced at the
    export boundary rather than left as an unused helper)."""
    from harness import evidence_audit
    from harness.evidence import Verdict
    verified_any = False
    capsule_ids: set[str] = set()
    for m in issue.members:
        if not (m.get("oracle_verified") or m.get("verification_state") == "verified"):
            continue
        cid = m.get("case_id") or ""
        attempts = _normalize_attempts(proofs_by_case.get(cid)) if cid else []
        best = None
        if attempts:
            try:
                best = max(attempts, key=lambda p: Verdict(p.get("verdict", "inconclusive")).rank())
            except ValueError:
                best = attempts[0]
        run_id = ((best or {}).get("case") or {}).get("run_id", "")
        if evidence_audit.audit_proof(m, best, run_id) == evidence_audit.AUDIT_VERIFIED:
            verified_any = True
            if m.get("oracle_capsule_id"):
                capsule_ids.add(m["oracle_capsule_id"])
    return verified_any, ("verified" if verified_any else "candidate"), sorted(capsule_ids)


def _member_tool_reported(m: dict, proofs_by_case: dict) -> bool:
    """True when a member's own proof is an external tool's detection the harness did
    not reproduce: the store row's `evidence_source`, else its exact recorded proof."""
    from harness.evidence import is_tool_reported
    if is_tool_reported(m):
        return True
    cid, pid = m.get("case_id") or "", m.get("proof_id") or ""
    return any(p.get("proof_id") == pid and is_tool_reported(p)
               for p in (_normalize_attempts(proofs_by_case.get(cid)) if cid and pid else []))


def evidence_state(issue: Issue, proofs_by_case: dict | None = None) -> str:
    """The issue's evidence tier: "confirmed" when a confirmed member rests on the
    harness's own proof, "tool_reported" when every confirmed member's proof is an
    external tool's unreproduced detection, else "candidate". A tool-reported issue
    is neither confirmed nor a generic candidate."""
    proofs_by_case = proofs_by_case or {}
    confirmed = [m for m in issue.members if m.get("confirmed")]
    if not confirmed:
        return "candidate"
    if all(_member_tool_reported(m, proofs_by_case) for m in confirmed):
        return "tool_reported"
    return "confirmed"


_ROUTE_STATE_RANK = {"candidate": 0, "tool_reported": 1, "confirmed": 2}


def _route_status(issue: Issue, proofs_by_case: dict) -> dict[str, str]:
    """Each affected route's own state, strongest member first: "confirmed" (the
    harness's own proof), "tool_reported" (an external tool's only), else "candidate"."""
    status: dict[str, str] = {}
    for m in issue.members:
        if not m.get("url"):
            continue
        route = normalize_path(m["url"])
        state = ("candidate" if not m.get("confirmed") else
                 "tool_reported" if _member_tool_reported(m, proofs_by_case) else "confirmed")
        if _ROUTE_STATE_RANK[state] >= _ROUTE_STATE_RANK[status.get(route, "candidate")]:
            status[route] = state
    return dict(sorted(status.items()))


def _member_evidence(issue: Issue) -> list[dict]:
    """Per-member evidence, redacted -- so grouping keeps every affected instance's
    own evidence (R10), not only the best member's."""
    out = []
    for m in issue.members:
        out.append({
            "url": redact_url(m.get("url", "")),
            "case_id": m.get("case_id") or "",
            "proof_id": m.get("proof_id") or "",
            "confirmed": bool(m.get("confirmed")),
            "proof_status": m.get("proof_status") or "none",
            "evidence": redact((m.get("evidence") or "")[:400]),
        })
    return out


def export_issue(issue: Issue, *, proofs_by_case: dict | None = None) -> dict:
    """A redacted, shareable export of one issue (T06): enough to understand and
    reproduce the bug without any embedded secret. `proofs_by_case` maps a case id
    to its recorded proof attempt(s) (a dict or a list); verdicts are resolved by
    exact proof id and the full attempt history is preserved."""
    proofs_by_case = proofs_by_case or {}
    best = issue.best_member
    aliases = _principal_aliases(issue)
    proof_refs = _proof_references(issue, proofs_by_case)
    has_proof = any(r.get("proof_id") and r.get("availability") != "unavailable" for r in proof_refs)
    audited_verified, audited_verification_state, audited_capsule_ids = \
        _audited_oracle_state(issue, proofs_by_case)
    state = evidence_state(issue, proofs_by_case)
    confirmed = state == "confirmed"
    policy = issue.header_policy

    boundary_word = "read" if issue.authorization_boundary == "read" else "state-changing"
    first_alias = next(iter(aliases), None)

    # Honest artifact accounting (R10): findings persist references, not raw
    # request/response bytes, so the export says what is and is NOT resolvable.
    missing_artifacts = []
    if not has_proof:
        missing_artifacts.append("no structured proof attempt is linked to this issue")
    missing_artifacts.append("raw captured request/response bytes are not stored with the finding; "
                             "replay from the linked proof/exchange artifacts")

    return security.sanitize_data({
        "issue_id": issue.issue_id,
        "version": issue.version,
        "title": f"{issue.vulnerability_class} on {redact_url(issue.host)}{issue.endpoint_family or '/'}"
                 + (f" [{issue.affected_input}]" if issue.affected_input else ""),
        "vulnerability_class": issue.vulnerability_class,
        "severity": issue.severity,
        "confidence": round(issue.confidence, 3),
        "confirmed": confirmed,
        # "confirmed" | "tool_reported" | "candidate" (see evidence_state).
        "evidence_state": state,
        **__import__("harness.confirmation_gate", fromlist=["finding_triage"]).finding_triage(
            {**best, "confirmed": confirmed}),
        # R01/R06: oracle verification state must survive export, distinct
        # from the legacy `confirmed` (leg fired once) axis -- a consumer
        # reading only `confirmed` cannot tell a leg-confirmed-but-unverified
        # claim from an oracle-verified one. AUDITED (evidence_audit.audit_proof)
        # against the linked proof ledger, not the members' raw self-reported
        # fields -- a "verified" claim with no reachable backing proof exports
        # as candidate (see _audited_oracle_state).
        "oracle_verified": audited_verified,
        "verification_state": audited_verification_state,
        "oracle_capsule_ids": audited_capsule_ids,
        "host": redact_url(issue.host),
        "endpoint_family": issue.endpoint_family,
        "method": issue.method,
        "affected_input": issue.affected_input or "(whole request)",
        "authorization_boundary": issue.authorization_boundary,
        "prerequisites": [
            f"A session/credentials for principal {alias}" for alias in aliases
        ] or ["A session able to reach the endpoint"],
        "principal_aliases": aliases,
        "request_sequence": [
            f"1. Establish a session for {first_alias}."
            if first_alias else "1. Establish a session able to reach the endpoint.",
            f"2. Send the {issue.method or 'captured'} request to {issue.endpoint_family or 'the endpoint'}"
            + (f", varying {issue.affected_input}" if issue.affected_input else " as captured")
            + ".",
            "3. Compare the observed response against the expected-vs-observed note below.",
        ],
        "expected_vs_observed": {
            "expected": _expected_invariant(issue),
            "observed": redact((best.get("summary") or best.get("evidence") or "")[:600]),
        },
        "impact": _impact_line(issue, state),
        "evidence": redact((best.get("evidence") or "")[:800]),
        "member_evidence": _member_evidence(issue),
        "proof_references": proof_refs,
        "affected_instances": [redact_url(u) for u in issue.affected_instances],
        "instances_count": len(issue.members),
        "member_ids": issue.member_ids,
        **({"affected_routes": sorted({normalize_path(u) for u in issue.affected_instances})}
           if policy is not None or issue.vulnerability_class in _HEADER_POLICY_CLASSES
           or any(_route_independent_identity(m) for m in issue.members) else {}),
        # A header-policy issue names its headers, whether their value is recorded
        # (False: grouped by header name, the routes may differ) and each route's state.
        **({"header_policy": {"headers": list(policy.headers), "recorded": policy.recorded,
                              "observed": dict(policy.observed)},
            "route_status": _route_status(issue, proofs_by_case)} if policy is not None else {}),
        "captured_auth_contexts": sorted({member.get("captured_principal_id") for member in issue.members
                                          if member.get("captured_principal_id")}),
        "artifacts": {"replayable": has_proof, "missing": missing_artifacts},
        "limitations": _limitations(issue, state),
        "retest": (
            f"Re-run the same {issue.method or 'captured'} request on a patched build; "
            f"a fix means the {boundary_word} attempt no longer succeeds. This retest "
            f"maps to issue {issue.issue_id} (stable id), so the result links to this "
            f"issue -- and is appended as a new attempt -- instead of opening a new one."),
        # I16 (I04 parity): the representative finding's next step, as the API,
        # Burp "Next step" and the Markdown report already show it.
        "suggested_test": redact((best.get("suggested_test") or "")[:1200]),
    })


def replay_view(issue: Issue) -> dict:
    """A LOCAL replay representation: the request steps to reproduce, with
    credential/session values replaced by placeholders (never the real values).
    Instances and sample evidence are redacted -- no secret survives even locally."""
    aliases = _principal_aliases(issue)
    steps = []
    for alias, principal in (aliases or {"P1": ""}).items():
        steps.append({
            "principal_alias": alias,
            "authorization": f"<<SESSION:{alias}>>",   # placeholder, filled from the operator's vault
            "note": f"session for {alias}" if principal else "session able to reach the endpoint",
        })
    return {
        "issue_id": issue.issue_id,
        "method": issue.method,
        "host": redact_url(issue.host),
        "endpoint_family": security.sanitize_text(issue.endpoint_family),
        "affected_input": security.sanitize_text(issue.affected_input),
        "principals": steps,
        "instances": [redact_url(u) for u in issue.affected_instances],
        # request bodies/evidence are redacted even in the local view -- the
        # placeholder tells the operator where their own session value goes.
        "sample_evidence": redact((issue.best_member.get("evidence") or "")[:400]),
    }


# --- small English helpers (generic, never target-specific claims) ---

# Class-keyed expected invariant (R10): the security property the class violates,
# so the export does not label every GET issue an "authorization read".
_CLASS_INVARIANTS: dict[str, str] = {
    "idor": "A principal must only access objects it is authorized to; an object reference "
            "must be authorized server-side, not merely hard to guess.",
    "sqli": "User input must not alter SQL query structure (parameterized queries).",
    "xss": "User input rendered in a page must be context-encoded so it cannot execute as script.",
    "ssrf": "The server must not fetch attacker-controlled URLs / internal addresses.",
    "csrf": "A state-changing request must require an unpredictable, validated anti-CSRF token.",
    "auth": "Authentication and session handling must resist bypass, fixation, and weak credentials.",
    "jwt": "A single signing algorithm must be enforced and every token signature verified.",
    "path_traversal": "A user-supplied path must not escape its intended base directory.",
    "command_injection": "User input must never reach a shell/command interpreter.",
    "ssti": "User input must not be evaluated as a server-side template expression.",
    "open_redirect": "A redirect target must be validated against an allowlist.",
    "xxe": "The XML parser must not resolve external entities / DTDs.",
}


def _expected_invariant(issue: Issue) -> str:
    inv = _CLASS_INVARIANTS.get(issue.vulnerability_class)
    if inv:
        return inv
    if issue.authorization_boundary == "read":
        return ("A principal should only read objects it is authorized to read; an "
                "unauthorized or cross-identity read should be denied.")
    return ("A state-changing request should be accepted only from an authorized "
            "principal with valid anti-CSRF protection and enforced input validation.")


def _impact_line(issue: Issue, state: str = "") -> str:
    n = len({m.get("url") for m in issue.members if m.get("url")})
    scope = f" across {n} observed instance(s)" if n > 1 else ""
    state = state or ("confirmed" if issue.confirmed else "candidate")
    verdict = {"confirmed": "confirmed",
               "tool_reported": "tool-reported (not reproduced by the harness)"}.get(
                   state, "suspected (unconfirmed)")
    return (f"{verdict.capitalize()} {issue.vulnerability_class} at "
            f"{issue.endpoint_family or 'the host'}{scope}.")


def _limitations(issue: Issue, state: str = "") -> list[str]:
    lims = []
    if state == "tool_reported":
        lims.append("Reported by an external tool only; the harness did not reproduce it with "
                    "its own exchanges, so it is not counted as confirmed.")
    elif not issue.confirmed:
        lims.append("No member of this issue is validator-confirmed; treat as a hypothesis "
                    "pending manual verification.")
    if not issue.proof_ids:
        lims.append("No structured proof is linked to this issue; evidence is unstructured.")
    policy = issue.header_policy
    if policy is not None and not policy.recorded:
        routes = {normalize_path(u) for u in issue.affected_instances}
        lims.append("The observed header value was not recorded for every member"
                    + ("; these routes are grouped by header name only and may differ."
                       if len(routes) > 1 else "."))
    if not issue.affected_input:
        lims.append("The specific affected input was not attributed; the issue is scoped to "
                    "the whole request.")
    return lims
