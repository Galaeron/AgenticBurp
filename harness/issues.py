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

from categories import canonicalize
from engagement import normalize_path

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

_SECRET_PATTERNS = (
    # Authorization: Bearer <token> / Basic <b64>
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 <REDACTED>"),
    # Cookie / Set-Cookie header values
    (re.compile(r"(?i)\b(set-)?cookie:\s*[^\r\n]+"), r"cookie: <REDACTED>"),
    # session=..., token=..., sid=..., password=... in a form/query
    (re.compile(r"(?i)\b(session|sessionid|token|access_token|refresh_token|sid|jsessionid|"
                r"csrf|xsrf|api[_-]?key|secret|password|passwd|pwd)=([^&\s;]+)"), r"\1=<REDACTED>"),
    # a bare JWT (three base64url segments)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"), "<REDACTED-JWT>"),
)


def redact(text: str) -> str:
    """Mask anything that looks like a credential/session value. Conservative and
    idempotent -- it never fabricates, only masks recognizable secret shapes."""
    out = text or ""
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out


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


def issue_key(finding: dict) -> tuple[str, str, str, str, str]:
    """The conservative grouping key (T06). Endpoint family (object ids collapsed),
    method, canonical class, affected input, and authorization boundary."""
    family = normalize_path(finding.get("url", "")) if finding.get("url") else ""
    method = (finding.get("method") or "").upper()
    vc = finding.get("vulnerability_class", "") or ""
    canon = canonicalize(vc) or vc.strip().lower()
    return (family, method, canon, _affected_input(finding), _boundary_for(method))


def issue_id_for(key: tuple[str, str, str, str, str]) -> str:
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
            family, method, canon, ainput, boundary = key
            issue = Issue(issue_id=issue_id_for(key), endpoint_family=family, method=method,
                          vulnerability_class=canon, affected_input=ainput,
                          authorization_boundary=boundary)
            by_key[key] = issue
            order.append(key)
        issue.members.append(f)
    return [by_key[k] for k in order]


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


def export_issue(issue: Issue, *, proofs_by_case: dict | None = None) -> dict:
    """A redacted, shareable export of one issue (T06): enough to understand and
    reproduce the bug without any embedded secret. `proofs_by_case` (case_id ->
    proof dict) enriches proof references with the recorded verdict when available."""
    proofs_by_case = proofs_by_case or {}
    best = issue.best_member
    aliases = _principal_aliases(issue)
    alias_of = {v: k for k, v in aliases.items()}

    proof_refs = []
    for m in issue.members:
        cid, pid = m.get("case_id"), m.get("proof_id")
        if not cid and not pid:
            continue
        ref = {"case_id": cid or "", "proof_id": pid or ""}
        pr = proofs_by_case.get(cid) if cid else None
        if pr:
            ref["verdict"] = pr.get("verdict", "")
        proof_refs.append(ref)

    boundary_word = "read" if issue.authorization_boundary == "read" else "state-changing"
    principal_note = (f"as principal {alias_of.get((best.get('principal_id') or best.get('identity') or ''), 'P?')}"
                      if aliases else "as the captured identity")

    return {
        "issue_id": issue.issue_id,
        "version": issue.version,
        "title": f"{issue.vulnerability_class} on {issue.endpoint_family or '(host)'}"
                 + (f" [{issue.affected_input}]" if issue.affected_input else ""),
        "vulnerability_class": issue.vulnerability_class,
        "severity": issue.severity,
        "confidence": round(issue.confidence, 3),
        "confirmed": issue.confirmed,
        "endpoint_family": issue.endpoint_family,
        "method": issue.method,
        "affected_input": issue.affected_input or "(whole request)",
        "authorization_boundary": issue.authorization_boundary,
        "prerequisites": [
            f"An authenticated session for {alias}" if alias != "P?" else "A session"
            for alias in aliases
        ] or ["A session able to reach the endpoint"],
        "principal_aliases": aliases,
        "request_sequence": [
            f"1. Establish {list(aliases)[0] if aliases else 'a session'} "
            f"({principal_note.replace('as ', '')}).",
            f"2. Send the {issue.method or 'captured'} request to "
            f"{issue.endpoint_family or 'the endpoint'} "
            + (f"varying {issue.affected_input}" if issue.affected_input else "as captured")
            + ".",
            "3. Compare the observed response against the expected-vs-observed note below.",
        ],
        "expected_vs_observed": {
            "expected": _expected_invariant(issue),
            "observed": redact((best.get("summary") or best.get("evidence") or "")[:600]),
        },
        "impact": _impact_line(issue),
        "evidence": redact((best.get("evidence") or "")[:800]),
        "proof_references": proof_refs,
        "affected_instances": issue.affected_instances,
        "instances_count": len(issue.members),
        "limitations": _limitations(issue),
        "retest": (
            f"Re-run the same {issue.method or 'captured'} request on a patched build; "
            f"a fix means the {boundary_word} attempt no longer succeeds. This retest "
            f"maps to issue {issue.issue_id} (stable id), so the result links to this "
            f"issue instead of opening a new one."),
    }


def replay_view(issue: Issue) -> dict:
    """A LOCAL replay representation: the request steps to reproduce, with
    credential/session values replaced by placeholders (never the real values)."""
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
        "endpoint_family": issue.endpoint_family,
        "affected_input": issue.affected_input,
        "principals": steps,
        "instances": issue.affected_instances,
        # request bodies/evidence are redacted even in the local view -- the
        # placeholder tells the operator where their own session value goes.
        "sample_evidence": redact((issue.best_member.get("evidence") or "")[:400]),
    }


# --- small English helpers (generic, never target-specific claims) ---

def _expected_invariant(issue: Issue) -> str:
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
