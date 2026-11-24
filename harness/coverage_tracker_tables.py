"""Policy tables and pure helpers of the coverage tracker: how a leg or case result maps to a
cell status, which legs confirm which rows, fair-share scheduling of the drive queue,
attempt facts and the resume-context key.

Part of the ARC-9 split of harness.coverage_tracker. Import these names from
harness.coverage_tracker, the facade, not from this module.
"""
from __future__ import annotations

import hashlib
import uuid
from collections import deque

from harness.coverage_model import CHECKS_BY_ID, CellStatus, Check


_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_PHASE_TURN = {"parameter": 0, "endpoint": 1, "domain": 2}


def _check_of(item):
    check = item[2]
    return check if isinstance(check, Check) else CHECKS_BY_ID.get(check)


def _fair_cells(items, unauthenticated=frozenset()):
    """Order queued cells so a budget is shared across check classes, and within
    each check across identities and routes.

    One queue per check id, each in `_spread_cells` order; the queues are visited
    round-robin, one cell per check per pass, so a check applicable to every route
    (CORS, CSP, function-level authz on each read) cannot use the budget a check
    with few cells (an injection leg on a captured parameter) needed. In r7 the
    drive spent its time on per-route endpoint checks: one cell per (identity,
    route) per pass let a read route finish its four checks while a write route
    got four of its twenty, and 913 legs stayed queued, most PUT/PATCH
    function-level authz cells and the search route's injection among them.
    Within a pass, parameter-phase checks come first, then endpoint, then domain
    checks; an authorization check (WSTG-ATHZ) takes its write-method cells first,
    because a write is where a missing function-level check does harm."""
    ordered = [queue for _cid, queue in _check_queues(items, unauthenticated)]
    while ordered:
        for queue in list(ordered):
            yield queue.popleft()
            if not queue:
                ordered.remove(queue)


def _check_queues(items, unauthenticated=frozenset()) -> list[tuple[str, deque]]:
    """The per-check queues `_fair_cells` visits, as (check id, queue) in turn order."""
    queues: dict[str, deque] = {}
    turn: dict[str, tuple] = {}
    for item in _spread_cells(items, unauthenticated):
        check = _check_of(item)
        cid = getattr(check, "id", None) or str(item[2])
        queues.setdefault(cid, deque()).append(item)
        if cid not in turn:
            phase = getattr(getattr(check, "phase", None), "value", "")
            turn[cid] = (_PHASE_TURN.get(phase, 1), len(turn))
    for cid, queue in queues.items():
        if cid.startswith("WSTG-ATHZ"):
            queues[cid] = deque(sorted(queue, key=lambda it: str(it[1]).partition(" ")[0].upper()
                                       not in _WRITE_METHODS))
    return [(cid, queues[cid]) for cid in sorted(queues, key=turn.__getitem__)]


def _time_fair_cells(items, unauthenticated=frozenset(), spent=None):
    """`_fair_cells` for a time-bound drive: the next cell comes from the check that
    has used the least drive time so far. `spent` (check id -> seconds) is read
    before every pick, so the driver adds each dispatch's wall time to it as it
    goes; ties go to the check served fewer cells, then to `_fair_cells` turn
    order, so legs that take no time are visited exactly as `_fair_cells` would.

    One cell per check per pass shares a COUNT, not time: in r10 every check got
    about 172 cells before the 5 h deadline, sqlmap's 172 took most of the drive
    (26,522 of 36,059 sends), and 912 cells of quick checks (CORS, cross-identity,
    JWT forge, CSP) were left queued. A check whose queue is empty drops out, so
    its unused share goes to the checks still waiting."""
    spent = {} if spent is None else spent
    queues = _check_queues(items, unauthenticated)
    rank = {cid: n for n, (cid, _queue) in enumerate(queues)}
    served = dict.fromkeys(rank, 0)
    live = dict(queues)
    while live:
        cid = min(live, key=lambda c: (spent.get(c, 0.0), served[c], rank[c]))
        queue = live[cid]
        served[cid] += 1
        yield queue.popleft()
        if not queue:
            del live[cid]


def _spread_cells(items, unauthenticated=frozenset()):
    """Order queued cells so a small leg budget spreads over identities and routes.

    One group per (identity, endpoint), visited endpoint by endpoint with that
    endpoint's identities in turn, signed-in principals ahead of `unauthenticated`
    ones; each pass takes one check from every group, and the first check rotates
    from group to group so the check mix varies. Visiting the groups in matrix
    order drained the first identity (alphabetically, anonymous) before any other."""
    groups = {}
    for item in items:
        groups.setdefault(item[:2], []).append(item)
    endpoint_rank = {}
    for _ident, endpoint in groups:
        endpoint_rank.setdefault(endpoint, len(endpoint_rank))
    ordered = sorted(groups, key=lambda g: (g[0] in unauthenticated, endpoint_rank[g[1]]))
    queues = []
    for index, group in enumerate(ordered):
        values = groups[group]
        offset = index % len(values)
        queues.append(deque(values[offset:] + values[:offset]))
    while queues:
        for queue in list(queues):
            yield queue.popleft()
            if not queue:
                queues.remove(queue)


def _covered_status(result, status):
    """A result the execution registry served from another case (E4) carries no
    artifacts of its own, so it cannot make this cell CONFIRMED or
    CONTROLLED_NEGATIVE; its summary names the case that holds the proof."""
    if getattr(result, "covered_by", "") and status in {CellStatus.CONFIRMED,
                                                        CellStatus.CONTROLLED_NEGATIVE}:
        return CellStatus.INCONCLUSIVE
    return status


def _executed(result, status):
    count = getattr(result, "sent_count", None)
    if count is not None:
        return count > 0
    return status in {CellStatus.CONFIRMED, CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE}


def new_attempt_id() -> str:
    """A unique, immutable id for one fresh dispatch that sent requests."""
    return f"att-{uuid.uuid4().hex[:16]}"


def _attempt_facts(result, status):
    """(executed, attempts, referenced_attempts) for one leg result (batch 02).

    A result the run's confirmation cache served from an earlier execution
    (`reused_attempt_id`) or the registry served from another case
    (`covered_by`) references that execution and is never a fresh send. Any
    other result that sent requests is one fresh attempt, with the id the
    cache stamped at the real send when there is one."""
    executed = _executed(result, status)
    reused = getattr(result, "reused_attempt_id", "") or ""
    covered = getattr(result, "covered_by", "") or ""
    if reused or covered:
        return executed, (), (reused or f"case:{covered}",)
    attempt_id = getattr(result, "attempt_id", "") or ""
    if attempt_id and getattr(result, "_attempt_claimed", False):
        # A same-case cache hit hands back the very object an earlier record
        # already claimed: it references that execution, sending nothing new.
        return executed, (), (attempt_id,)
    if attempt_id:
        try:
            result._attempt_claimed = True
        except AttributeError:
            pass
    sent = next((n for n in (getattr(result, "sent_count", None), getattr(result, "observed_sends", None))
                 if isinstance(n, int) and not isinstance(n, bool)), None)
    if not executed:
        # A leg that drove requests but ended without a conclusive status is still
        # a fresh attempt for the drive-volume figure; it stays unexecuted, so it
        # never counts as tested.
        if sent:
            return False, ({"id": attempt_id or new_attempt_id(), "sent": sent},), ()
        return False, (), ()
    return True, ({"id": attempt_id or new_attempt_id(), "sent": sent},), ()


def resume_context_key(config):
    from pathlib import Path
    from harness.run_manifest import config_fingerprint, source_fingerprint
    source = source_fingerprint(Path(__file__).resolve().parents[1])
    return hashlib.sha256((source['sha256'] + config_fingerprint(config)).encode()).hexdigest()

# A driven leg's result status -> its matrix cell status (R11). Only an EXECUTED
# negative ("not_confirmed", or a validator's "safe") becomes NOT_DETECTED, i.e. tested
# coverage. A leg that was blocked (budget, safety gate, scope), skipped, or gave no
# verdict is untested. A status nobody mapped fails conservatively to INCONCLUSIVE,
# never to an optimistic negative -- the same rule drive_coverage_cases applies (R06).
_LEG_STATUS = {
    "confirmed": CellStatus.CONFIRMED,
    "not_confirmed": CellStatus.NOT_DETECTED,
    "safe": CellStatus.NOT_DETECTED,
    "controlled_negative": CellStatus.CONTROLLED_NEGATIVE,
    "blocked": CellStatus.BLOCKED,
    "inconclusive": CellStatus.INCONCLUSIVE,
    "skipped": CellStatus.SKIPPED,
    "error": CellStatus.ERROR,
}
_LEG_STATUS_UNKNOWN = CellStatus.INCONCLUSIVE
# The case driver's mapping: it keeps a validator's controlled_negative distinct.
# A validator's "safe" is its executed negative here too, as in _LEG_STATUS (r3:
# 208 CORS cases that sent their probes and passed stayed inconclusive without it).
_CASE_STATUS = {"confirmed": CellStatus.CONFIRMED, "not_confirmed": CellStatus.NOT_DETECTED,
                "safe": CellStatus.NOT_DETECTED,
                "controlled_negative": CellStatus.CONTROLLED_NEGATIVE,
                "blocked": CellStatus.BLOCKED, "inconclusive": CellStatus.INCONCLUSIVE,
                "skipped": CellStatus.SKIPPED, "error": CellStatus.ERROR}
# Cell statuses that mean the leg actually dispatched its comparison (an errored
# attempt was dispatched; a blocked/skipped/no-verdict one was not).
_LEG_EXECUTED = frozenset({CellStatus.CONFIRMED, CellStatus.NOT_DETECTED,
                           CellStatus.CONTROLLED_NEGATIVE, CellStatus.ERROR})

# R11-10: the readiness codes (and restored cell-reason prefixes) that mean the
# cell's identity holds no capture of the endpoint.
_NO_CAPTURE_CODES = ("missing_principal", "covered_by_identity")
_CONCLUSIVE = frozenset({CellStatus.CONFIRMED, CellStatus.DETECTED, CellStatus.NOT_DETECTED,
                         CellStatus.CONTROLLED_NEGATIVE})
# Which other identity a credited cell names: a conclusive (executed first) verdict,
# then one still open, then a not-applicable one.
_PEER_ORDER = (CellStatus.CONFIRMED, CellStatus.DETECTED, CellStatus.NOT_DETECTED,
               CellStatus.CONTROLLED_NEGATIVE)


def _peer_rank(cell) -> tuple:
    if cell.status in _PEER_ORDER:
        return (0, _PEER_ORDER.index(cell.status), not cell.executed)
    return (2 if cell.status == CellStatus.NOT_APPLICABLE else 1, 0, not cell.executed)

# Trust ordering mirrors worklist_investigator: the driver probes from the
# lowest-trust identity that can reach a node, so a finding is attributed there.
_TRUST = {"anonymous": 0, "user": 1, "agent": 2, "service": 2, "manager": 3, "admin": 4}


def _trust(role: str) -> int:
    return _TRUST.get((role or "").lower(), 1)


def _principal_of(r) -> str:
    """The durable principal id for a role session (R02): the identity track's
    RoleSession.principal_id() when available, so two same-role accounts (Alice and
    Bob, both `user`) stay DISTINCT coverage identities. Falls back to role/str for
    plain stubs."""
    pid = getattr(r, "principal_id", None)
    if callable(pid):
        try:
            got = pid()
            if got:
                return str(got)
        except Exception:
            pass
    return getattr(r, "role", None) or (r if isinstance(r, str) else str(r))


def _role_of(r) -> str:
    if isinstance(r, str):
        return r
    return getattr(r, "role", None) or "anonymous"


# Confirmation methods that are deterministic legs (vs "agent"/"manual"): an
# applicable cell for one of these, on an investigated endpoint, can be marked
# "attempted -> not_detected" because the shape-driven precondition path runs it
# regardless of an agent label.
_LEG_CONFIRMATIONS = {
    "sqlmap", "cross_identity", "browser_xss", "jwt_forge", "xxe", "ssrf", "ssti",
    "command_injection", "path_traversal", "open_redirect", "sequence",
    "deserialization_oob", "auth_sequence", "stored_xss", "verb_tamper", "csrf",
    "file_upload", "rate_limit", "reset_token", "dom_xss", "toctou", "race_condition",
    "csp", "cors", "nosql", "header_injection", "http_request_smuggling",
    "security_headers", "error_handling", "content_exposure", "write_integrity",
    "listing_exposure", "filter_bypass", "metrics_exposure", "sensitive_file", "well_known",
    # WG-2 item 5. Each keeps its own gate: client_trust tampers are writes (readiness
    # needs active_enabled and allow_mutating_replay); websocket and oauth are active.
    "client_trust", "websocket", "oauth",
    # R11-7: multi-step flows; needs an explicit mutating_ceiling_by_check.business_flow.
    "business_flow",
    # R11-8 (b): a write with its restore; readiness needs allow_mutating_replay and
    # mutating_ceiling_by_check.password_change_session >= 2 (capability_for_check).
    "password_change_session",
}
# Catalog confirmation kinds that name a registered validator but are NOT drive legs,
# each with the reason. Driving one would write a cell verdict its probe does not
# establish. harness.test_catalog_validator_rows requires every row kind to be in
# _LEG_CONFIRMATIONS, here, or a non-validator kind ("manual", "agent").
UNDRIVEN_ROW_CONFIRMATIONS: dict[str, str] = {
    "crypto": "one aggregate verdict over TLS, HSTS and cookie attributes: on plain HTTP its "
              "TLS test always reports a weakness, so it would confirm SESS-02 and CONF-07 "
              "cells whatever their cookies or headers say",
    "recon": "fingerprinting, comment and method enumeration have no per-check verdict "
             "(capability_for_check reports check_adapter_missing for INFO-02, INFO-05, CONF-06)",
    "web_cache_poisoning": "never confirms (retired verdict) and reports a found reflection as "
                           "not_confirmed; one aggregate verdict runs both the INJT-17 and CONF-13 "
                           "probes, and the deception probe drops the identity's credentials",
    "subdomain_takeover": "fetches third-party hosts named in a response body (outside the "
                          "engagement scope) and does no DNS lookup, so its negative does not "
                          "answer CONF-10; the row applies to every endpoint, one skip each",
}


def leg_table_problems(rows, legs=None, undriven=None, non_validator=None) -> list[str]:
    """Every problem between catalog confirmation kinds and the drive-leg table;
    empty means consistent. Each row kind is a drive leg, an undriven kind with a
    reason, or a non-validator kind; the two tables are disjoint; neither names a
    kind no row uses (a stale entry)."""
    from harness.coverage_model import NON_VALIDATOR_CONFIRMATIONS
    legs = _LEG_CONFIRMATIONS if legs is None else set(legs)
    undriven = UNDRIVEN_ROW_CONFIRMATIONS if undriven is None else undriven
    non_validator = NON_VALIDATOR_CONFIRMATIONS if non_validator is None else non_validator
    kinds = {r.confirmation for r in rows}
    problems: list[str] = []
    for kind in sorted(kinds - legs - set(undriven) - set(non_validator)):
        problems.append(f"{kind}: row kind is neither a drive leg nor undriven with a reason")
    for kind in sorted(set(undriven)):
        if kind in legs:
            problems.append(f"{kind}: both a drive leg and undriven")
        elif not (undriven[kind] or "").strip():
            problems.append(f"{kind}: undriven with no reason")
    for kind in sorted((legs | set(undriven)) - kinds):
        problems.append(f"{kind}: in the leg table but no row names it (stale entry)")
    return problems


# Legs that judge the captured response and send nothing. They run first and spend
# no dispatch budget, so they never crowd out a leg that sends.
_PASSIVE_LEG_CONFIRMATIONS = frozenset({"security_headers", "error_handling", "content_exposure"})


def _passive_first(cells):
    """`cells` ((identity, endpoint, check id or Check), ...) with the passive legs
    first; each group keeps its order."""
    def confirmation(cell):
        check = cell[2] if isinstance(cell[2], Check) else CHECKS_BY_ID.get(cell[2])
        return getattr(check, "confirmation", "")
    return sorted(cells, key=lambda cell: confirmation(cell) not in _PASSIVE_LEG_CONFIRMATIONS)

# E7: a drive hands its checkpoint to `on_checkpoint` after every this many completed
# legs, so a run that dies inside a long drive resumes from the last of them.
CHECKPOINT_EVERY_LEGS = 25


def _listed_in_compact_ledger(row: dict) -> bool:
    """A ledger row the job result keeps: the cell is shape-applicable, or it has a
    non-default state -- a not-applicable cell that was queued, attempted, sent or
    resumed must stay visible, or a real attempt would be hidden in a count."""
    return bool(row["shape_applicable"] or row["queued"] or row["attempted"]
                or row["sent"] or row["fresh_sent"] or row["resumed"])


# What the funnel's count names mean. `sent` keeps its key for compatibility but
# counts cells with a recorded execution, not requests.
DRIVE_LABELS = {
    "requests_driven": "requests sent by this run's fresh attempts (deduplicated by attempt id)",
    "conclusive": "cells with an executed conclusive verdict",
    "driven_not_conclusive": "cells whose fresh attempts sent requests but reached no conclusive verdict",
    "sent": "cells with a recorded execution (CellResult.executed); not a request count",
}


def _drive_volume(matrix, rows) -> dict:
    """Requests driven next to conclusive cells, so effort and answers read apart."""
    seen, requests = set(), 0
    for cell in matrix.cells().values():
        for attempt in cell.attempts:
            if attempt.get("id") not in seen:
                seen.add(attempt.get("id"))
                requests += attempt.get("sent") or 0
    return {"requests_driven": requests,
            "conclusive": sum(bool(row["conclusive"]) for row in rows),
            "driven_not_conclusive": sum(bool(row["fresh_sends"] and not row["conclusive"]) for row in rows),
            "labels": DRIVE_LABELS}


def _reaches(ident: str, ep: dict, identity_roles: dict[str, str]) -> bool:
    """Whether coverage identity `ident` (a principal id) reached endpoint `ep`:
    its own access cell decides, so a principal denied with 403 is not counted
    as reaching because another principal of its role did (or one NAMED like
    its role); without a cell, its role in the role view (engagement.principal_reached)."""
    from harness.engagement import principal_reached
    return principal_reached(ep.get("access_by_principal"), ep.get("reachable_roles"),
                             ident, identity_roles.get(ident, ident))
