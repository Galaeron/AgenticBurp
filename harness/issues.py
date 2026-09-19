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
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from harness.categories import canonicalize
from harness.engagement import normalize_path

_ISSUE_VERSION = 1

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
    out = text or ""
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out


def redact_url(url: str) -> str:
    """Return a URL with any credential in userinfo or a secret query parameter
    masked (R03) -- so an exported/affected URL never leaks a `?token=...` or
    `user:pass@` while keeping the endpoint itself legible."""
    if not url:
        return url or ""
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
        """The strongest single observation (confirmed > severe > confident), used
        for the export's headline evidence -- without discarding the others."""
        def rank(m):
            return (1 if m.get("confirmed") else 0,
                    -_SEV_ORDER.get((m.get("severity") or "info").lower(), 99),
                    float(m.get("confidence", 0.0) or 0.0))
        return max(self.members, key=rank) if self.members else {}


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


def issue_key(finding: dict) -> tuple:
    """The conservative grouping key (T06). Application namespace (scheme+host),
    endpoint family (object ids collapsed), method, canonical class, affected
    input, and authorization boundary. When the affected input is UNKNOWN, a
    per-finding disambiguator (finding_id/fingerprint) is added so two distinct
    unattributed findings do NOT collapse into one issue (review R04); attributed
    inputs and repeated object ids that share a known input still group."""
    url = finding.get("url", "")
    host = _host_of(url)
    family = normalize_path(url) if url else ""
    method = (finding.get("method") or "").upper()
    vc = finding.get("vulnerability_class", "") or ""
    canon = canonicalize(vc) or vc.strip().lower()
    affected = _affected_input(finding)
    # Unknown input is not a wildcard: keep distinct findings distinct.
    disambiguator = "" if affected else (finding.get("finding_id") or finding.get("fingerprint") or "")
    return (host, family, method, canon, affected, _boundary_for(method), disambiguator)


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
                # no ledger attempt -> reference the pointer WITHOUT a verdict
                refs.append({"case_id": cid, "proof_id": pid, "verdict": None})
    return refs


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
    has_proof = any(r.get("proof_id") for r in proof_refs)

    boundary_word = "read" if issue.authorization_boundary == "read" else "state-changing"
    first_alias = next(iter(aliases), None)

    # Honest artifact accounting (R10): findings persist references, not raw
    # request/response bytes, so the export says what is and is NOT resolvable.
    missing_artifacts = []
    if not has_proof:
        missing_artifacts.append("no structured proof attempt is linked to this issue")
    missing_artifacts.append("raw captured request/response bytes are not stored with the finding; "
                             "replay from the linked proof/exchange artifacts")

    return {
        "issue_id": issue.issue_id,
        "version": issue.version,
        "title": f"{issue.vulnerability_class} on {redact_url(issue.host)}{issue.endpoint_family or '/'}"
                 + (f" [{issue.affected_input}]" if issue.affected_input else ""),
        "vulnerability_class": issue.vulnerability_class,
        "severity": issue.severity,
        "confidence": round(issue.confidence, 3),
        "confirmed": issue.confirmed,
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
        "impact": _impact_line(issue),
        "evidence": redact((best.get("evidence") or "")[:800]),
        "member_evidence": _member_evidence(issue),
        "proof_references": proof_refs,
        "affected_instances": [redact_url(u) for u in issue.affected_instances],
        "instances_count": len(issue.members),
        "artifacts": {"replayable": has_proof, "missing": missing_artifacts},
        "limitations": _limitations(issue),
        "retest": (
            f"Re-run the same {issue.method or 'captured'} request on a patched build; "
            f"a fix means the {boundary_word} attempt no longer succeeds. This retest "
            f"maps to issue {issue.issue_id} (stable id), so the result links to this "
            f"issue -- and is appended as a new attempt -- instead of opening a new one."),
    }


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
        "endpoint_family": issue.endpoint_family,
        "affected_input": issue.affected_input,
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


def _impact_line(issue: Issue) -> str:
    n = len({m.get("url") for m in issue.members if m.get("url")})
    scope = f" across {n} observed instance(s)" if n > 1 else ""
    verdict = "confirmed" if issue.confirmed else "suspected (unconfirmed)"
    return (f"{verdict.capitalize()} {issue.vulnerability_class} at "
            f"{issue.endpoint_family or 'the host'}{scope}.")


def _limitations(issue: Issue) -> list[str]:
    lims = []
    if not issue.confirmed:
        lims.append("No member of this issue is validator-confirmed; treat as a hypothesis "
                    "pending manual verification.")
    if not issue.proof_ids:
        lims.append("No structured proof is linked to this issue; evidence is unstructured.")
    if not issue.affected_input:
        lims.append("The specific affected input was not attributed; the issue is scoped to "
                    "the whole request.")
    return lims
