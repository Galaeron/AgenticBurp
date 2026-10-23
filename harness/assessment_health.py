"""Assessment completeness is distinct from successful job termination."""
from __future__ import annotations

import hashlib
import json
from collections import deque
from urllib.parse import urlsplit

from harness.models import HttpExchange


def review_frontier(captured, *, seen=None):
    """Deduplicate exact observations and interleave routes and identities.

    Keep different bodies, credentials and responses. Polling on one route must
    not consume the review budget before another route gets its first review.
    Original observations are retained by the caller, never removed from storage.
    """
    seen = seen if seen is not None else set()
    groups = {}
    for cap in captured or []:
        try:
            ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
        except (TypeError, ValueError):
            continue
        headers = {k.lower(): v for k, v in (ex.request_headers or {}).items()}
        record = [ex.method, ex.url, headers, ex.request_body, ex.response_status,
                  {k.lower(): v for k, v in (ex.response_headers or {}).items()}, ex.response_body]
        key = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
        if key in seen:
            continue
        # Do not mark reviewed until actually selected by the consumer.
        identity = tuple(sorted((k, v) for k, v in headers.items()
                                if k in {"authorization", "cookie", "x-api-key", "x-auth-token"}))
        parts = urlsplit(ex.url)
        group = (ex.method, parts.netloc, parts.path, identity)
        groups.setdefault(group, deque()).append((key, ex))
    while groups:
        for group in list(groups):
            key, ex = groups[group].popleft()
            if not groups[group]:
                del groups[group]
            if key not in seen:
                seen.add(key)
                yield ex


def assessment_health(coverage, errors=(), *, stopped_on_confirmation=False):
    audited = (coverage or {}).get("audited") or {}
    applicable = audited.get("applicable")
    executed = (audited.get("executed") or {}).get("numerator", 0)
    incomplete = audited.get("not_a_clean_negative") or {}
    reasons = []
    if errors:
        reasons.append("one or more assessment phases reported errors or truncation")
    if not stopped_on_confirmation:
        if applicable is None or applicable == 0:
            reasons.append("no applicable coverage established")
        elif executed < applicable:
            reasons.append(f"{applicable - executed} applicable checks lack recorded execution")
        if incomplete.get("executed_attempts", 0):
            reasons.append("some executed checks did not reach a conclusive result")
    return {"status": "incomplete" if reasons else "complete",
            "reasons": reasons, "applicable": applicable, "executed": executed,
            "objective_only": bool(stopped_on_confirmation)}


def confirmed_issue_inventory(findings, run_id, proof_lookup):
    """Resolve exact proof/case/run pointers before counting unique cases."""
    proven = {}
    for finding in findings:
        case_id, proof_id = finding.get("case_id"), finding.get("proof_id")
        if not finding.get("confirmed") or not case_id or not proof_id:
            continue
        if any(p.get("proof_id") == proof_id and (p.get("case") or {}).get("case_id") == case_id
               and (p.get("case") or {}).get("run_id") == run_id and p.get("verdict") == "confirmed"
               for p in proof_lookup(case_id)):
            proven[case_id] = {k: finding.get(k) for k in
                              ("finding_id", "case_id", "proof_id", "url", "vulnerability_class")}
    return list(proven.values())
