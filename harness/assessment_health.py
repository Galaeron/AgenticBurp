"""Assessment completeness is distinct from successful job termination."""
from __future__ import annotations

import hashlib
import json
from collections import deque
from urllib.parse import urlsplit

from harness.models import HttpExchange


def review_frontier(captured, *, seen=None, with_keys=False):
    """Deduplicate exact observations and interleave routes and identities.
    With `with_keys` each item is (observation key, exchange): the key is the sha256
    that decides "seen", stable across runs for the same observation.

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
                yield (key, ex) if with_keys else ex


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


def stored_proof_artifacts_resolve(proof):
    """Require exact case-bound successful execution events and intact evidence blobs."""
    from harness import store
    case = proof.get('case') or {}
    case_id = case.get('case_id')
    refs = [proof.get('baseline_artifact_id'), proof.get('attack_artifact_id'),
            *(proof.get('control_artifact_ids') or [])]
    if not case_id or not all(refs) or len(set(refs)) < 3:
        return False
    events = store.ledger_events_for(case_id)
    if case.get('finding_ref') and case['finding_ref'] != case_id:
        events += store.ledger_events_for(case['finding_ref'])
    found = set()
    for event in events:
        data = event.get('data') or {}
        if (event.get('case_ref') == case_id and event.get('event_type') == 'execution'
                and data.get('outcome') == 'ok' and data.get('artifact_id') in refs
                and data.get('request') and data.get('response')
                and store.evidence_blob_resolves(data.get('request_blob', ''))
                and store.evidence_blob_resolves(data.get('response_blob', ''))):
            found.add(data['artifact_id'])
    return all(ref in found for ref in refs)


def confirmed_issue_accounting(findings, run_id, proof_lookup, *, run_proofs=(), artifact_resolver=None):
    """Keep legacy case counts readable without presenting them as vulnerabilities.

    Every proof instance stays visible. Vulnerability grouping requires intact
    structured controls; unknown/legacy confirmations remain candidates. The
    grouping key never crosses principal, parameter or workflow boundaries.
    """
    proofs = {p.get('proof_id'): p for p in run_proofs if p.get('proof_id')}
    referenced, excluded = {}, []
    cache = {}
    candidate_cases = set()
    for finding in findings:
        case_id, proof_id = finding.get('case_id'), finding.get('proof_id')
        if not finding.get('confirmed'):
            status = finding.get('verification_state') or finding.get('status')
            if status in ('not_confirmed', 'controlled_negative', 'refuted', 'blocked', 'error', 'skipped'):
                continue
            candidate_cases.add(case_id or finding.get('finding_id') or hashlib.sha256(
                json.dumps(finding, sort_keys=True, default=str).encode()).hexdigest())
            continue
        if not case_id or not proof_id:
            excluded.append({'case_id': case_id, 'proof_id': proof_id, 'reason': 'missing case/proof pointer'})
            continue
        if case_id not in cache:
            cache[case_id] = proof_lookup(case_id)
            proofs.update({p['proof_id']: p for p in cache[case_id] if p.get('proof_id')})
        proof = next((p for p in cache[case_id] if p.get('proof_id') == proof_id), None)
        if proof is None:
            reason = 'proof not found for case'
        elif (proof.get('case') or {}).get('run_id') != run_id:
            reason = 'proof belongs to another run'
        elif (proof.get('case') or {}).get('case_id') != case_id:
            reason = 'proof belongs to another case'
        elif proof.get('verdict') != 'confirmed':
            reason = 'proof verdict is not confirmed'
        else:
            referenced.setdefault(proof_id, finding)
            continue
        excluded.append({'case_id': case_id, 'proof_id': proof_id, 'reason': reason})

    instances, groups, counted_cases = [], {}, set()
    for proof_id, proof in sorted(proofs.items()):
        case = proof.get('case') or {}
        if case.get('run_id') != run_id:
            continue
        finding = referenced.get(proof_id)
        validator = proof.get('validator', '')
        cls = ((finding or {}).get('vulnerability_class') or case.get('check_id') or validator).lower()
        claimed = ('hardening' if validator in ('csp_validator', 'crypto_validator', 'verbose_error_validator')
                   else 'reconnaissance' if validator == 'recon_validator' else 'vulnerability')
        refs = [proof.get('baseline_artifact_id'), proof.get('attack_artifact_id'),
                *(proof.get('control_artifact_ids') or [])]
        structured = bool(proof.get('executed') and not proof.get('legacy', True)
                          and len(set(refs)) >= 3 and all(refs))
        resolved = bool(structured and artifact_resolver and artifact_resolver(proof))
        kind = claimed if claimed != 'vulnerability' or resolved else 'candidate'
        reason = (None if finding else 'not referenced by a confirmed finding')
        instance = {key: proof.get(key) for key in ('proof_id', 'validator', 'verdict', 'executed', 'legacy',
                    'baseline_artifact_id', 'attack_artifact_id', 'control_artifact_ids')}
        instance.update(case=dict(case), kind=kind, claimed_kind=claimed, artifacts_resolved=resolved,
                        referenced=bool(finding), exclusion_reason=reason)
        if finding:
            counted_cases.add(case['case_id'])
            parts = urlsplit(finding.get('url') or '')
            origin = f'{parts.scheme}://{parts.hostname or ""}'
            if parts.port:
                origin += f':{parts.port}'
            instance['route'] = origin + parts.path
            # Site-policy observations may share a presentation group across routes;
            # vulnerability claims merge only with an explicit root-cause identifier.
            root = ((finding.get('root_cause_id') or case['case_id']) if claimed == 'vulnerability'
                    else (origin, validator, cls))
            boundary = (case.get('principal_id', ''), case.get('parameter_location', ''),
                        case.get('parameter_name', ''), case.get('workflow_state_id', ''))
            key = json.dumps([run_id, kind, cls, validator, origin, root, boundary], sort_keys=True)
            group = groups.setdefault(key, {'group_id': hashlib.sha256(key.encode()).hexdigest()[:20],
                          'kind': kind, 'vulnerability_class': cls, 'principal_id': boundary[0],
                          'proof_ids': [], 'case_ids': [], 'routes': []})
            group['proof_ids'].append(proof_id)
            group['case_ids'] = sorted(set([*group['case_ids'], case['case_id']]))
            group['routes'] = sorted(set([*group['routes'], instance['route']]))
            if kind == 'candidate':
                candidate_cases.add(case['case_id'])
                instance['limitation'] = 'legacy, missing controls or unresolved exchange artifacts'
        instances.append(instance)
    counts = {kind: sum(g['kind'] == kind for g in groups.values())
              for kind in ('vulnerability', 'hardening', 'reconnaissance')}
    ledger_confirmed = [p for p in instances if p['verdict'] == 'confirmed']
    return {'schema_version': 1, 'run_id': run_id,
            'units': {'confirmed_issues': 'unique proof-bound cases (compatibility count)',
                      'vulnerabilities': 'distinct structured, artifact-resolved vulnerability groups',
                      'observations': 'presentation groups retaining route/principal proof instances'},
            'counts': {'proof_bound_cases': len(counted_cases),
                       'ledger_confirmed_proof_instances': len(ledger_confirmed),
                       'unreferenced_confirmed_proof_instances': sum(not p['referenced'] for p in ledger_confirmed),
                       'vulnerabilities': counts['vulnerability'],
                       'hardening_observations': counts['hardening'],
                       'reconnaissance': counts['reconnaissance'],
                       'candidate_cases': len(candidate_cases), 'excluded_records': len(excluded)},
            'groups': list(groups.values()), 'proof_instances': instances, 'excluded': excluded,
            'limitations': ['Presentation grouping is not proof of a shared root cause.',
                           'Legacy confirmations are retained; they do not count as resolved vulnerabilities.']}
