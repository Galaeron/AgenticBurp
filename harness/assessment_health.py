"""Assessment completeness is distinct from successful job termination."""
from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from urllib.parse import urlsplit

from harness.models import HttpExchange

# E1 review tiers, highest priority first. `review_stats.by_tier` uses these names.
TIER_NAMES = ("authenticated_api", "anonymous_api", "other_non_html", "html")
# review_frontier: of every TIER_SHARE_PERIOD picks, the last goes to a lower tier
# (in turn) and the rest to the highest non-empty tier. See review_frontier.
TIER_SHARE_PERIOD = 4
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Response headers that carry the security posture (E1). Access-Control-Allow-* is
# matched by prefix and Set-Cookie is reduced to its cookie names (values are
# per-session). The extended set adds what the hardening agents also read.
_SECURITY_HEADERS = ("content-security-policy", "content-security-policy-report-only",
                     "x-frame-options", "strict-transport-security")
_HARDENING_EXTRA_HEADERS = ("x-content-type-options", "referrer-policy", "permissions-policy",
                            "feature-policy", "x-xss-protection", "cache-control", "vary",
                            "server", "x-powered-by")
_COOKIE_START = re.compile(r"(?:^|\n|,\s*)\s*([^=;,\s]+)=")
_COOKIE_SPLIT = re.compile(r"\n|,\s*(?=[^=;,\s]+=)")


def new_review_stats() -> dict:
    """The empty `review_stats` block the capture review fills in."""
    return {"reviewed": 0, "grouped": [], "unreviewed": 0, "by_tier": dict.fromkeys(TIER_NAMES, 0),
            "elided": []}


def _lower(headers) -> dict:
    return {str(k).lower(): v for k, v in (headers or {}).items()}


def _identity(ex) -> tuple:
    """The credential headers that say who sent the request, as sorted pairs."""
    from harness.security import is_identity_credential_header
    return tuple(sorted((k, v) for k, v in _lower(ex.request_headers).items()
                        if is_identity_credential_header(k)))


def identity_kind(ex) -> str:
    return "authenticated" if _identity(ex) else "anon"


def content_type_family(ex) -> str:
    """html | json | xml | text | other, from the response Content-Type (or, when it
    is absent, a look at the first bytes of the body)."""
    ctype = str(_lower(ex.response_headers).get("content-type") or "").split(";")[0].strip().lower()
    if ctype:
        for family in ("html", "json", "xml"):
            if family in ctype:
                return family
        return "text" if ctype.startswith("text/") else "other"
    head = (ex.response_body or "").lstrip()[:200].lower()
    if head.startswith(("<!doctype html", "<html")) or "<html" in head:
        return "html"
    if head.startswith(("{", "[")):
        return "json"
    return "xml" if head.startswith("<?xml") else "other"


def _first_segment(url: str) -> str:
    return urlsplit(url).path.lstrip("/").split("/", 1)[0].lower()


def capture_tier(ex) -> int:
    """0 authenticated JSON/API or write, 1 anonymous JSON/API or write, 2 other
    non-HTML, 3 HTML (index into TIER_NAMES)."""
    family = content_type_family(ex)
    if (ex.method or "").upper() in _WRITE_METHODS or family == "json":
        return 0 if _identity(ex) else 1
    return 3 if family == "html" else 2


def _route_family(ex) -> tuple:
    """What takes turns inside a tier: one identity on one first path segment."""
    return (_identity(ex), _first_segment(ex.url))


def _cookie_facts(value, *, flags: bool) -> tuple:
    cookies = []
    for raw in _COOKIE_SPLIT.split(str(value or "")):
        name = _COOKIE_START.match(raw.strip())
        if not name:
            continue
        attrs = ()
        if flags:
            attrs = tuple(sorted(
                (a.split("=", 1)[0].strip().lower() + ("=" + a.split("=", 1)[1].strip().lower()
                 if a.strip().lower().startswith("samesite") and "=" in a else ""))
                for a in raw.split(";")[1:]
                if a.strip() and a.split("=", 1)[0].strip().lower() not in ("expires", "max-age", "path", "domain")))
        cookies.append((name.group(1),) + attrs)
    return tuple(sorted(set(cookies)))


def security_header_fingerprint(response_headers, *, extended: bool = False) -> tuple:
    """A stable, value-free-of-secrets summary of a response's security headers:
    CSP, X-Frame-Options, HSTS, every Access-Control-Allow-* and the Set-Cookie
    names. `extended` adds the cache, banner and hardening headers the
    csp/cors/misconfig/web_cache_poisoning agents also read."""
    low = _lower(response_headers)
    names = _SECURITY_HEADERS + (_HARDENING_EXTRA_HEADERS if extended else ())
    pairs = [(k, str(low[k]).strip()) for k in names if k in low]
    pairs += [(k, str(v).strip()) for k, v in sorted(low.items()) if k.startswith("access-control-allow-")]
    return tuple(pairs), _cookie_facts(low.get("set-cookie"), flags=extended)


def _group_key(ex):
    """Identity of a capture's CONTENT for the review (E1), or None when the capture
    must never be grouped: it carries its own input (a query string, a request body)
    or names an object (an id-like path segment). Two captures with the same key
    would be reviewed by the same model on the same bytes."""
    from harness.engagement import path_id_values
    parts = urlsplit(ex.url)
    if parts.query or (ex.request_body or "").strip() or path_id_values(ex.url):
        return None
    body = hashlib.sha256((ex.response_body or "").encode("utf-8", "replace")).hexdigest()
    # Every response header NAME counts, not only the security set: an extra debug or
    # banner header on one route is something to review there.
    return ((ex.method or "").upper(), parts.netloc.lower(), ex.response_status, _identity(ex),
            content_type_family(ex), body, tuple(sorted(_lower(ex.response_headers))),
            security_header_fingerprint(ex.response_headers, extended=True))


def observation_key(ex) -> str:
    """The exact-observation key review_frontier marks in `seen`."""
    headers = {k.lower(): v for k, v in (ex.request_headers or {}).items()}
    record = [ex.method, ex.url, headers, ex.request_body, ex.response_status,
              {k.lower(): v for k, v in (ex.response_headers or {}).items()}, ex.response_body]
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()


def review_frontier(captured, *, seen=None, group_identical: bool = False, on_grouped=None):
    """Deduplicate exact observations, then order what is left for review.

    Order (E1): by tier -- authenticated JSON/API or write, anonymous JSON/API
    or write, other non-HTML, HTML (see capture_tier) -- interleaved so that no
    tier starves (r5: all 71 reviews went to tier 0 and 365 captures were never
    reached). The highest non-empty tier (tier 0 while it lasts) takes the first
    TIER_SHARE_PERIOD - 1 picks of every TIER_SHARE_PERIOD; the remaining pick goes
    to the lower non-empty tiers in turn. With TIER_SHARE_PERIOD = 4 and all four
    tiers non-empty, tier 0 gets 3 of every 4 reviews and each lower tier at least
    one in every window of N = 4 * 3 = 12 consecutive picks (fewer non-empty lower
    tiers make the window shorter). The order is deterministic. Inside a tier the
    identity + first-path-segment families take turns, and inside a family the
    individual routes do, so polling on one route or one route family cannot
    consume the review budget before another gets its first review. Nothing is
    dropped by the ordering; only a consumer's own bound can leave a capture
    unreviewed. Keep different bodies, credentials and responses. Original
    observations are retained by the caller, never removed from storage.

    `group_identical` (content review only): captures that share a `_group_key`
    -- same identity, method, status, content family, body bytes and security
    headers, and no input or object id of their own -- yield only the first as the
    representative. When the representative is taken, each other capture of its
    group is marked in `seen` (so it is never reviewed again) and
    `on_grouped(capture, representative)` is called for it. A group whose
    representative is never taken leaves its members untouched.
    """
    seen = seen if seen is not None else set()
    tiers: dict[int, dict[tuple, dict[tuple, deque]]] = {}
    queued: set[str] = set()
    representatives: dict[tuple, str] = {}
    followers: dict[str, list] = {}
    for cap in captured or []:
        try:
            ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
        except (TypeError, ValueError):
            continue
        key = observation_key(ex)
        if key in seen or key in queued:
            continue
        queued.add(key)
        # Do not mark reviewed until actually selected by the consumer.
        if group_identical:
            content = _group_key(ex)
            if content is not None:
                rep = representatives.setdefault(content, key)
                if rep != key:
                    followers.setdefault(rep, []).append((key, ex))
                    continue
        parts = urlsplit(ex.url)
        group = (ex.method, parts.netloc, parts.path, _identity(ex))
        tiers.setdefault(capture_tier(ex), {}).setdefault(_route_family(ex), {}) \
            .setdefault(group, deque()).append((key, ex))
    picks = 0
    last_lower = -1
    while tiers:
        live = sorted(tiers)
        primary, lower = live[0], live[1:]
        if lower and picks % TIER_SHARE_PERIOD == TIER_SHARE_PERIOD - 1:
            # The lower-tier slot: the next non-empty lower tier after the last one
            # served, wrapping round, so the lower tiers take turns.
            tier = next((t for t in lower if t > last_lower), lower[0])
            last_lower = tier
        else:
            tier = primary
        families = tiers[tier]
        # Popping and re-inserting moves a family/group to the back of its
        # insertion-ordered dict: that is the round-robin.
        family = next(iter(families))
        groups = families.pop(family)
        group = next(iter(groups))
        queue = groups.pop(group)
        key, ex = queue.popleft()
        if queue:
            groups[group] = queue
        if groups:
            families[family] = groups
        if not families:
            del tiers[tier]
        if key in seen:
            continue      # the slot is not used up: the same turn picks again
        picks += 1
        seen.add(key)
        for member_key, member in followers.get(key, ()):
            if member_key not in seen:
                seen.add(member_key)
                if on_grouped is not None:
                    on_grouped(member, ex)
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
            "requests_driven": (audited.get("drive") or {}).get("requests_driven"),
            "conclusive": (audited.get("drive") or {}).get("conclusive"),
            "objective_only": bool(stopped_on_confirmation)}


def _run_scope(run_id):
    """(runs, several): one run id, or every attempt of a resumed assessment (the job
    and the jobs it resumed, oldest first). r9 resumed twice; the last job counted
    only its own attempt and reported none of the 196 confirmations before it."""
    runs = (frozenset([run_id]) if run_id is None or isinstance(run_id, str)
            else frozenset(run_id))
    return runs, len(runs) > 1


_ATTEMPT_CASE_FIELDS = ('request_template_id', 'check_id', 'principal_id',
                        'parameter_location', 'parameter_name', 'workflow_state_id')


def attempt_case_key(case: dict) -> str:
    """A case's identity without its run. case_id hashes the run id, so the same
    request, check, principal, input and workflow state tested by two attempts has
    two case ids; across attempts it is one case. finding_ref is left out too: it
    names one attempt's finding or hypothesis."""
    return json.dumps([str((case or {}).get(k) or '') for k in _ATTEMPT_CASE_FIELDS])


def confirmed_issue_inventory(findings, run_id, proof_lookup):
    """Resolve exact proof/case/run pointers before counting unique cases.

    `run_id` is one run, or a collection of attempt run ids: then a case confirmed
    by several attempts is one case (attempt_case_key)."""
    runs, several = _run_scope(run_id)
    proven = {}
    for finding in findings:
        case_id, proof_id = finding.get("case_id"), finding.get("proof_id")
        if not finding.get("confirmed") or not case_id or not proof_id:
            continue
        # A tool-reported proof (an external tool's unreproduced detection) is not
        # a harness confirmation; it is accounted on its own (confirmed_issue_accounting).
        proof = next((p for p in proof_lookup(case_id)
                      if p.get("proof_id") == proof_id and (p.get("case") or {}).get("case_id") == case_id
                      and (p.get("case") or {}).get("run_id") in runs and p.get("verdict") == "confirmed"
                      and not is_tool_reported(p)), None)
        if proof is not None:
            proven[attempt_case_key(proof["case"]) if several else case_id] = {
                k: finding.get(k) for k in ("finding_id", "case_id", "proof_id", "url", "vulnerability_class")}
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


# Batch 08: mechanisms whose proven flaw is a host trust policy, not a route: the same
# policy fingerprint on several routes is one issue with several locations. AR-08b:
# one set, shared with the report path's issue key (issues.py).
from harness.issues import (ISSUE_UNITS, ROUTE_INDEPENDENT_MECHANISMS, issue_class,  # noqa: E402
                            root_cause_id_for, root_cause_key)
from harness.evidence import is_tool_reported  # noqa: E402
_ORPHAN_REASONS = {'proof not found for case', 'proof belongs to another run', 'proof belongs to another case'}


_ROOT_CAUSE_KINDS = ('vulnerability', 'hardening', 'reconnaissance', 'candidate', 'tool_reported')


def _root_cause_id(finding, proof, case, validator):
    """The root-cause id of one confirmed proof instance, or None for a chain
    hypothesis: the finding as its proof decided it (mechanism, observed result,
    and the case's principal and input win over the finding's own fields)."""
    view = dict(finding, confirmed=True, validator=validator,
                proof_observed_result=proof.get('observed_result') or '')
    for key in ('principal_id', 'parameter_location', 'parameter_name'):
        if case.get(key):
            view[key] = case[key]
    key = root_cause_key(view)
    return root_cause_id_for(key) if key is not None else None


def confirmed_issue_accounting(findings, run_id, proof_lookup, *, run_proofs=(), artifact_resolver=None):
    """Keep legacy case counts readable without presenting them as vulnerabilities.

    Every proof instance stays visible. Vulnerability grouping requires intact
    structured controls; unknown/legacy confirmations remain candidates. The
    grouping key never crosses principal, parameter or workflow boundaries.

    `run_id` is one run, or the attempt run ids of a resumed assessment, oldest
    first: every attempt's proofs are counted, and a case two attempts confirmed is
    one case and one group (attempt_case_key). With one run the output is the
    single-run accounting, unchanged.
    """
    runs, several = _run_scope(run_id)

    def case_key(case):
        return attempt_case_key(case) if several else case['case_id']
    proofs = {p.get('proof_id'): p for p in run_proofs if p.get('proof_id')}
    # Batch 08: the policy a confirmation was decided under travels on the finding
    # (Finding.header_fingerprint, set by the confirm path). AR-08a: it is also
    # persisted with the proof (store.proof_identity), which wins, so store-only
    # proofs group as in-run ones; a proof and finding that both lack it read as
    # unknown, which never merges routes.
    policy_of = {}
    for finding in findings:
        if finding.get('proof_id') and finding.get('header_fingerprint'):
            policy_of.setdefault(finding['proof_id'], finding['header_fingerprint'])
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
        elif (proof.get('case') or {}).get('run_id') not in runs:
            reason = 'proof belongs to another run'
        elif (proof.get('case') or {}).get('case_id') != case_id:
            reason = 'proof belongs to another case'
        elif proof.get('verdict') != 'confirmed':
            reason = 'proof verdict is not confirmed'
        else:
            referenced.setdefault(proof_id, finding)
            continue
        excluded.append({'case_id': case_id, 'proof_id': proof_id, 'reason': reason})

    instances, groups, counted_cases, tool_reported_cases = [], {}, set(), set()
    # A reused result carries the original attempt's artifacts; it is a reference,
    # never a second execution (batch 08).
    first_attempt = {}
    for proof in sorted(proofs.values(), key=lambda p: (p.get('created_at') or 0, p.get('proof_id'))):
        if (proof.get('case') or {}).get('run_id') in runs and proof.get('executed')                 and proof.get('attack_artifact_id'):
            first_attempt.setdefault((proof['attack_artifact_id'], proof.get('baseline_artifact_id') or ''),
                                     proof['proof_id'])
    for proof_id, proof in sorted(proofs.items()):
        case = proof.get('case') or {}
        if case.get('run_id') not in runs:
            continue
        finding = referenced.get(proof_id)
        validator = proof.get('validator', '')
        # The report's class (issues.issue_class), not the raw label: r9 grouped
        # "info_disclosure" and "information_disclosure" on one origin as two issues.
        cls = issue_class((finding or {}).get('vulnerability_class') or case.get('check_id') or validator)
        claimed = ('hardening' if validator in ('csp_validator', 'crypto_validator', 'verbose_error_validator',
                                                'security_headers_validator', 'error_handling_validator',
                                                'content_exposure_validator')
                   else 'reconnaissance' if validator in ('recon_validator', 'well_known_validator')
                   else 'vulnerability')
        refs = [proof.get('baseline_artifact_id'), proof.get('attack_artifact_id'),
                *(proof.get('control_artifact_ids') or [])]
        structured = bool(proof.get('executed') and not proof.get('legacy', True)
                          and len(set(refs)) >= 3 and all(refs))
        resolved = bool(structured and artifact_resolver and artifact_resolver(proof))
        # An external tool's detection the harness did not reproduce is its own tier:
        # never confirmed, never proof-bound, never folded into the generic candidates.
        tool_reported = is_tool_reported(proof)
        kind = ('tool_reported' if tool_reported
                else claimed if claimed != 'vulnerability' or resolved else 'candidate')
        reason = (None if finding else 'not referenced by a confirmed finding')
        instance = {key: proof.get(key) for key in ('proof_id', 'validator', 'verdict', 'executed', 'legacy',
                    'baseline_artifact_id', 'attack_artifact_id', 'control_artifact_ids')}
        instance.update(case=dict(case), kind=kind, claimed_kind=claimed, artifacts_resolved=resolved,
                        referenced=bool(finding), exclusion_reason=reason,
                        policy_fingerprint=proof.get('policy_fingerprint') or policy_of.get(proof_id, ''))
        original = first_attempt.get((proof.get('attack_artifact_id') or '', proof.get('baseline_artifact_id') or ''))
        if original and original != proof_id:
            instance['reuses_attempt_of'] = original
        if finding:
            if tool_reported:
                tool_reported_cases.add(case_key(case))
                instance['limitation'] = 'reported by an external tool; the harness did not reproduce it'
            else:
                counted_cases.add(case_key(case))
            parts = urlsplit(finding.get('url') or '')
            origin = f'{parts.scheme}://{parts.hostname or ""}'
            if parts.port:
                origin += f':{parts.port}'
            instance['route'] = origin + parts.path
            # Site-policy observations may share a presentation group across routes;
            # vulnerability claims merge only with an explicit root-cause identifier.
            # Batch 08: a route-independent mechanism with a known policy fingerprint
            # groups on (host, mechanism, boundary, check family, policy); an unknown
            # policy never merges routes.
            policy = instance['policy_fingerprint']
            if claimed != 'vulnerability':
                root = (origin, validator, cls)
            elif finding.get('root_cause_id'):
                root = finding['root_cause_id']
            elif validator in ROUTE_INDEPENDENT_MECHANISMS and policy:
                root = ('mechanism', validator, proof.get('validator_version') or '', policy)
            else:
                root = case_key(case)
            boundary = (case.get('principal_id', ''), case.get('parameter_location', ''),
                        case.get('parameter_name', ''), case.get('workflow_state_id', ''))
            scope = sorted(runs) if several else next(iter(runs))
            key = json.dumps([scope, kind, cls, validator, origin, root, boundary], sort_keys=True)
            group = groups.setdefault(key, {'group_id': hashlib.sha256(key.encode()).hexdigest()[:20],
                          'kind': kind, 'vulnerability_class': cls, 'principal_id': boundary[0],
                          'proof_ids': [], 'case_ids': [], 'routes': [],
                          'identity': {'host': origin, 'mechanism': validator, 'check_family': cls,
                                       'principal_boundary': list(boundary), 'policy_fingerprint': policy
                                       if claimed == 'vulnerability' else ''}})
            group['proof_ids'].append(proof_id)
            group['case_ids'] = sorted(set([*group['case_ids'], case['case_id']]))
            group['routes'] = sorted(set([*group['routes'], instance['route']]))
            # EFF-3: the root cause this instance shows (issues.root_cause_key), read
            # from what its mechanism proved on the case's input and principal. An
            # explicit root_cause_id on the finding stays the operator's decision.
            rc_id = finding.get('root_cause_id') or _root_cause_id(finding, proof, case, validator)
            if rc_id:
                instance['root_cause_id'] = rc_id
                group['root_cause_ids'] = sorted({*group.get('root_cause_ids', ()), rc_id})
            if kind == 'candidate':
                candidate_cases.add(case_key(case))
                instance['limitation'] = 'legacy, missing controls or unresolved exchange artifacts'
        instances.append(instance)
    counts = {kind: sum(g['kind'] == kind for g in groups.values())
              for kind in ('vulnerability', 'hardening', 'reconnaissance')}
    root_causes = {kind: set() for kind in _ROOT_CAUSE_KINDS}
    for group in groups.values():
        root_causes[group['kind']].update(group.get('root_cause_ids', ()))
    ledger_confirmed = [p for p in instances if p['verdict'] == 'confirmed' and p['kind'] != 'tool_reported']
    orphans = [dict(e, repair='re-link the finding to a stored proof of this case and run, or re-run '
                              'its check; the link is not shown as proof') for e in excluded
               if e['reason'] in _ORPHAN_REASONS]
    attempts = ({'run_id': list(run_id)[-1], 'attempt_run_ids': list(run_id)} if several
                else {'run_id': next(iter(runs))})
    return {'schema_version': 1, **attempts,
            'units': {'confirmed_issues': 'proof-bound cases, each case counted once (compatibility count, '
                                          'not vulnerabilities)',
                      'vulnerabilities': 'structured, artifact-resolved vulnerability groups: one per proof-bound '
                                         'case and boundary, not per root cause (see vulnerability_root_causes)',
                      'root_causes': '<kind>_root_causes: ' + ISSUE_UNITS['root_causes'] + ', over the groups '
                                     'of that kind; a root cause proven under two kinds counts under each',
                      'observations': 'presentation groups retaining route/principal proof instances',
                      'tool_reported': 'cases whose only proof is an external tool detection the harness '
                                       'did not reproduce (neither confirmed nor a generic candidate)'},
            'counts': {'proof_bound_cases': len(counted_cases),
                       'ledger_confirmed_proof_instances': len(ledger_confirmed),
                       'unreferenced_confirmed_proof_instances': sum(not p['referenced'] for p in ledger_confirmed),
                       'vulnerabilities': counts['vulnerability'],
                       **{f'{kind}_root_causes': len(root_causes[kind]) for kind in _ROOT_CAUSE_KINDS},
                       'hardening_observations': counts['hardening'],
                       'reconnaissance': counts['reconnaissance'],
                       'candidate_cases': len(candidate_cases - tool_reported_cases),
                       'tool_reported_cases': len(tool_reported_cases),
                       'tool_reported_issues': sum(g['kind'] == 'tool_reported' for g in groups.values()),
                       'excluded_records': len(excluded),
                       'executed_attempts': len(set(first_attempt.values())),
                       'reused_proof_references': sum(bool(p.get('reuses_attempt_of')) for p in instances),
                       'orphaned_proof_links': len(orphans)},
            'groups': list(groups.values()), 'proof_instances': instances, 'excluded': excluded,
            'orphaned_proof_links': orphans,
            'limitations': ['Presentation grouping is not proof of a shared root cause.',
                           'Legacy confirmations are retained; they do not count as resolved vulnerabilities.']}


# EFF-3: r11's headline read "117 unique proof-backed vulnerabilities" from
# confirmed_vulnerabilities, which counts one group per proof-bound case: r11 had about
# 16-18 root causes. A run result and its manifest carry both counts, each with its unit.
VULNERABILITY_COUNT_UNITS = {'confirmed_vulnerabilities': 'proof_bound_vulnerability_groups',
                             'confirmed_vulnerability_root_causes': 'root_causes'}


def headline_counts(accounting) -> dict:
    """The run-level vulnerability counts of an issue accounting, each beside its unit
    (VULNERABILITY_COUNT_UNITS): the per-case groups runs have always reported and the
    root causes those groups show (issues.root_cause_key). None when unknown."""
    counts = (accounting or {}).get('counts') or {}
    return {'confirmed_vulnerabilities': counts.get('vulnerabilities'),
            'confirmed_vulnerabilities_unit': VULNERABILITY_COUNT_UNITS['confirmed_vulnerabilities'],
            'confirmed_vulnerability_root_causes': counts.get('vulnerability_root_causes'),
            'confirmed_vulnerability_root_causes_unit':
                VULNERABILITY_COUNT_UNITS['confirmed_vulnerability_root_causes']}
