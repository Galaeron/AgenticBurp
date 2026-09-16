"""
Chain linker -- Milestone C: link findings to each other and to the surface.

Milestones A/B give coverage, prioritisation, and per-node investigation. But a
finding in isolation is only half the story of a real engagement: one finding
UNLOCKS the next (an auth bypass yields a session; a leaked id makes a second
endpoint exploitable; two individually-valid findings compose into a worse one).
This pass writes those links into the engagement graph, so vulnerabilities are
connected, not a flat list -- and so the harness can walk them:

  1. ESCALATION edges (deterministic, engagement.detect_capabilities): a finding
     that grants a capability -- a replayable credential, or an access-control
     finding that makes an area reachable -- becomes a task-graph edge
     (obtain -> recrawl_as_derived, or recrawl_area). Credential capabilities are
     returned so the caller can drive the closed loop (re-test AS the new
     identity); their header values travel with the return, never into the graph.

  2. CHAIN composition (rule-based, chaining.detect): two findings whose classes
     match a known escalation pattern (sqli+idor, admin_exposure+access_control,
     xxe+ssrf, ...) yield a `potential-attack-chain` finding, added to the graph
     as a `chain` task so the operator sees the composed hypothesis.

Deterministic and network-free -- pure linking over findings the earlier passes
produced. The re-test-as-derived-identity loop it feeds is the orchestrator's
(it needs live traffic); this decides WHAT links exist.
"""
from __future__ import annotations

import logging

from harness import access_control_gate
from harness import chaining
import harness.engagement as eng

log = logging.getLogger("harness.chain_linker")


def _canon_class(vc: str) -> str:
    """Canonicalise a finding's class so LLM free-text labels link the same as
    the deterministic ones. The iterative agent emits things like 'IDOR/BOLA' or
    'Broken Function-Level Authorization' which engagement._canon returns None
    for -- so detect_capabilities/chaining silently skipped them. The
    access-control MARKER set (access_control_gate) does recognise them, so map
    the whole access-control family to a canonical token the linkers key off."""
    low = (vc or "").lower()
    if access_control_gate._is_access_control_class(vc or ""):
        if "idor" in low or "object" in low or "bola" in low:
            return "idor"
        return "broken_access_control"
    try:
        from harness.categories import canonicalize
        return canonicalize(vc) or low
    except Exception:
        return low


def _canon_finding(f: dict) -> dict:
    """A shallow copy with a canonical vulnerability_class -- other fields intact."""
    g = dict(f)
    g["vulnerability_class"] = _canon_class(f.get("vulnerability_class", ""))
    return g


def _chain_input(findings: list[dict]) -> list[dict]:
    """Project findings to the shape chaining.detect expects, dropping any that
    can't be placed on the surface (no url -> nothing to chain to).

    PROVENANCE is preserved (R20): confirmed / basis / evidence / identity / id are
    carried through so chaining.detect can tell a VERIFIED input from a SPECULATIVE
    one (attribution.chain_input_speculative reads confirmed+basis) and so a chain
    can reference which findings it rests on. Dropping these silently made every
    chain look equally trustworthy regardless of whether its inputs were proven."""
    out: list[dict] = []
    for f in findings:
        url = f.get("url")
        if not url:
            continue
        proj = {
            "url": url,
            "vulnerability_class": _canon_class(f.get("vulnerability_class", "")),
            "severity": f.get("severity", "info"),
            "confidence": f.get("confidence", 0.0),
            "summary": f.get("summary", "") or "",
            "confirmed": bool(f.get("confirmed", False)),
            "basis": f.get("basis", ""),
        }
        for k in ("evidence", "identity", "id", "confirmation_method"):
            if f.get(k):
                proj[k] = f[k]
        out.append(proj)
    return out


def link_findings(state, findings: list[dict], *, responses: dict | None = None) -> dict:
    """Populate `state`'s graph with escalation edges + composed chains for
    `findings` (dicts, each carrying at least `url` + `vulnerability_class`).

    `responses` optionally maps url -> {"headers":{...}, "body":"..."} so a
    credential leaked in a response can be detected (the closed-loop trigger);
    access-control "reachable area" edges need no response body.

    Returns {"chain_findings": [...], "credential_caps": [...]} and mutates the
    graph in place. `credential_caps` carry ephemeral headers for the caller's
    re-test loop -- they are NOT persisted."""
    responses = responses or {}
    credential_caps: list[dict] = []

    # 1. escalation edges
    for f in findings:
        url = f.get("url")
        if not url:
            continue
        r = responses.get(url, {})
        caps = eng.detect_capabilities(_canon_finding(f), r.get("headers", {}), r.get("body", ""), url)
        credential_caps.extend(state.apply_capabilities(caps, url))

    # 2. chain composition -> record each as a graph task so it's inspectable
    chain_findings = chaining.detect(_chain_input(findings))
    for cf in chain_findings:
        signature = cf.vulnerability_class.split(":", 1)[-1]
        state.graph.add("chain", signature, reason=cf.summary, source=cf.evidence[:200])

    log.info("chain_linker: %d escalation credential(s), %d composed chain(s)",
             len(credential_caps), len(chain_findings))
    return {
        "chain_findings": [cf.model_dump() for cf in chain_findings],
        "credential_caps": credential_caps,
    }
