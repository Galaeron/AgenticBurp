"""
Coverage tracker -- drive the WSTG check catalog as a live cell-filler (I1/I2/I5).

`coverage_model` is the data spine: a fixed check catalog and an identity ×
endpoint × check matrix with auditable cell statuses. It was data-only -- nothing
filled it during a run, so the harness could not answer the operator's actual
definition of coverage: "every applicable check × endpoint × identity was
attempted (or skipped with a reason)."

This module closes that. Given the final engagement state (endpoints, per-role
access, the findings each produced) it:

  1. FILLS APPLICABILITY deterministically -- each check's shape predicate marks
     a cell not_applicable(reason) or pending (I1/I5).
  2. Encodes REACHABILITY -- a cell for an identity that never reached the
     endpoint is skipped with that reason, not silently blank.
  3. RECORDS OUTCOMES -- a confirmed finding -> CONFIRMED, an unconfirmed one ->
     DETECTED, on the check(s) its class maps to, attributed to the probe identity
     (the lowest-trust role that reached the endpoint -- the strongest proof).
  4. Marks ATTEMPTED -- an applicable cell whose check has a deterministic leg, on
     an endpoint this run actually investigated, that produced nothing -> the leg
     was run and found nothing (not_detected), distinct from never-attempted.

The result is the auditable report substrate (I2): summary counts, per-check
rollups, and the explicit "not tested + why" list. Pure and deterministic -- no
network, no LLM; it reconciles what the run already produced.
"""
from __future__ import annotations

import logging
import time
import hashlib
import json
import uuid
from collections import deque


def _fair_cells(items, unauthenticated=frozenset()):
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

from harness.categories import canonicalize
from harness.validators.injection_targets import PER_PARAMETER_FIELD_CAP, case_target
from harness.coverage_model import (
    ATTEMPT_SCHEMA_VERSION, CHECK_CATALOG, CHECKS_BY_ID, Check, CellStatus, CellResult, CoverageMatrix,
)

log = logging.getLogger("harness.coverage_tracker")

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
}

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


class CoverageTracker:
    """Reconciles a finished engagement into a filled CoverageMatrix."""

    def __init__(self, checks: tuple[Check, ...] = CHECK_CATALOG):
        self.matrix = CoverageMatrix()
        self.checks = checks
        self.attempted = set()
        self.queued = set()
        self.reused = set()
        self.readiness: dict[tuple, dict] = {}
        self.endpoints = {}
        self.identity_roles: dict[str, str] = {}
        self.driveable = None  # None means no driver supplied; an empty set means none available.
        self.checkpoint_signature = ""
        self.context_key = ""
        # E7: called with checkpoint() every CHECKPOINT_EVERY_LEGS completed legs.
        self.on_checkpoint = None
        # Why a drive stopped with queued cells left: "leg budget" or "time budget".
        self.stopped_by = None
        # canonical vulnerability_class -> [check_id]; plus the raw class token so
        # a check class canonicalize() returns None for (e.g. "misconfig") still maps.
        self._class_to_checks: dict[str, list[str]] = {}
        for c in checks:
            for token in {c.vulnerability_class, canonicalize(c.vulnerability_class) or c.vulnerability_class}:
                self._class_to_checks.setdefault(token, []).append(c.id)

    # --- mapping a finding's class to catalog checks ---

    def checks_for_class(self, vuln_class: str) -> list[str]:
        """Catalog check ids a finding of `vuln_class` bears on. Tries the
        canonical class, then the access-control free-text family (which the
        canonicaliser returns None for), then a whole-word fallback against each
        check's own class token. Whole-word so a short token like 'auth' does not
        spuriously match inside 'authorization'."""
        import re as _re
        raw = (vuln_class or "").lower().strip()
        canon = canonicalize(vuln_class)
        # 1. exact canonical / raw token match.
        ids: list[str] = []
        for key in (canon, raw):
            if key and key in self._class_to_checks:
                ids.extend(self._class_to_checks[key])
        if ids:
            return sorted(set(ids))
        # 2. access-control free-text family (canonicalize misses these; BFLA and
        #    function-level authz map to WSTG-ATHZ-02, IDOR/BOLA to WSTG-ATHZ-04).
        if any(w in raw for w in ("bfla", "function-level", "function level", "broken function")):
            return ["WSTG-ATHZ-02"]
        if any(w in raw for w in ("idor", "bola", "object-level", "object level",
                                   "insecure direct object")):
            return sorted(c.id for c in self.checks if c.vulnerability_class == "idor")
        # 3. whole-word fallback against check class tokens.
        for c in self.checks:
            ct = c.vulnerability_class.lower()
            if len(ct) >= 4 and _re.search(r"\b" + _re.escape(ct) + r"\b", raw):
                ids.append(c.id)
        return sorted(set(ids))

    # --- build the matrix from the engagement ---

    def build(self, endpoints: dict[str, dict], identities: list[str],
              identity_roles: dict[str, str] | None = None) -> dict:
        """Fill applicability across identities × endpoints × checks, then mark
        reachability skips. `identities` are durable principal ids (R02);
        `identity_roles` maps each to its role for reachability (reachable_roles is
        role-based) -- defaulting a principal to itself when unmapped. `endpoints`
        maps endpoint_key -> a dict carrying path/methods/access/reachable_roles/
        object_scoped (see `endpoint_view`). Returns {applicable, not_applicable,
        skipped_reach}."""
        identity_roles = identity_roles or {}
        self.endpoints = endpoints
        self.identity_roles = dict(identity_roles)
        na = self.matrix.fill_applicability(identities, endpoints, self.checks)
        # One engagement is one origin. Transport/deployment checks have one
        # representative; response policies (CSP, CORS, HSTS, etc.) remain per
        # route and identity because those responses can differ.
        for check in self.checks:
            if not check.origin_scoped or not identities or not endpoints:
                continue
            ep_key = min(endpoints, key=lambda k: (
                not bool(endpoints[k].get("reachable_roles")),
                not k.startswith("GET "), k))
            ident = self._probe_identity(endpoints[ep_key], identities, identity_roles)
            for key, cell in list(self.matrix.cells().items()):
                if key[2] == check.id and key[:2] != (ident, ep_key):
                    if cell.status != CellStatus.NOT_APPLICABLE:
                        na += 1
                    self.matrix.set(*key, CellResult.not_applicable(
                        f"origin_scoped: represented by {ident} / {ep_key}"))
        skipped = 0
        for ep_key, ep in endpoints.items():
            reach = [str(r) for r in (ep.get("reachable_roles") or [])]
            if not reach:
                continue  # reachability unknown -> leave applicable cells pending
            for ident in identities:
                if _reaches(ident, ep, identity_roles):
                    continue
                # this identity never reached this endpoint -> not attemptable as it
                for check in self.checks:
                    cell = self.matrix.get(ident, ep_key, check.id)
                    if cell and cell.status == CellStatus.PENDING:
                        self.matrix.record(
                            ident, ep_key, check.id, status=CellStatus.SKIPPED,
                            reason=f"identity {ident!r} did not reach this endpoint in the access matrix")
                        skipped += 1
        applicable = sum(1 for c in self.matrix.cells().values() if c.status == CellStatus.PENDING)
        return {"applicable": applicable, "not_applicable": na, "skipped_reachability": skipped}

    def _probe_identity(self, ep: dict, identities: list[str],
                        identity_roles: dict[str, str] | None = None) -> str:
        identity_roles = identity_roles or {}
        pool = [i for i in identities if _reaches(i, ep, identity_roles)] or list(identities)
        return (min(pool, key=lambda i: _trust(identity_roles.get(i, i))) if pool
                else (identities[0] if identities else "anonymous"))

    def record_findings_from_state(self, endpoints: dict[str, dict], identities: list[str],
                                   identity_roles: dict[str, str] | None = None) -> int:
        """Record CONFIRMED/DETECTED cells from the findings attached to each
        endpoint, attributed to the endpoint's probe identity. Returns cells set."""
        n = 0
        for ep_key, ep in endpoints.items():
            findings = ep.get("findings") or []
            if not findings:
                continue
            ident = self._probe_identity(ep, identities, identity_roles)
            for f in findings:
                vc = f.get("vulnerability_class", "")
                confirmed = bool(f.get("confirmed"))
                status = CellStatus.CONFIRMED if confirmed else CellStatus.DETECTED
                for check_id in self.checks_for_class(vc):
                    self.matrix.record(
                        ident, ep_key, check_id, status=status,
                        reason=f"{'confirmed' if confirmed else 'detected'} {vc}",
                        severity=f.get("severity"), confidence=f.get("confidence"),
                        validator=CHECKS_BY_ID.get(check_id).confirmation if check_id in CHECKS_BY_ID else None,
                        evidence=(f.get("summary") or "")[:200])
                    n += 1
        return n

    def record_execution_events(self, events) -> int:
        """Record REAL leg executions into the matrix (R01).

        Each event is a mapping identifying a cell (`identity`, `endpoint_key`, and
        either a `check_id` or a `confirmation` leg name) plus the observed
        `status` ("confirmed" | "detected" | "not_detected"/"not_confirmed" |
        "error" | "skipped"). It records that a specific leg ACTUALLY RAN on a
        specific cell and what it found.

        This REPLACES the former `mark_leg_attempts` inference, which fabricated a
        `not_detected` verdict on every applicable cell of an endpoint the worklist
        merely "investigated" -- without any evidence a leg ran there for that
        identity/check. No event => no attempt recorded; the cell stays pending and
        `finalize_pending_reasons` marks it skipped with an explicit reason. Returns
        the number of cells updated."""
        _STATUS = {
            "confirmed": CellStatus.CONFIRMED, "detected": CellStatus.DETECTED,
            "not_detected": CellStatus.NOT_DETECTED, "not_confirmed": CellStatus.NOT_DETECTED,
            "error": CellStatus.ERROR, "skipped": CellStatus.SKIPPED,
        }
        n = 0
        for ev in events or []:
            ident = ev.get("identity")
            ep_key = ev.get("endpoint_key")
            status = _STATUS.get((ev.get("status") or "").lower())
            if not ident or not ep_key or status is None:
                continue
            if ev.get("check_id"):
                check_ids = [ev["check_id"]]
            elif ev.get("confirmation"):
                check_ids = [c.id for c in self.checks if c.confirmation == ev["confirmation"]]
            else:
                continue
            conf = ev.get("confirmation")
            for cid in check_ids:
                cell = self.matrix.get(ident, ep_key, cid)
                # Only record on a cell the shape marked applicable (PENDING), or
                # upgrade an already-attempted cell to a stronger verdict. Never
                # resurrect a not_applicable cell, never fabricate a new one.
                if cell is None:
                    continue
                if cell.status != CellStatus.PENDING and not (
                        cell.status in (CellStatus.NOT_DETECTED, CellStatus.DETECTED, CellStatus.ERROR)
                        and status == CellStatus.CONFIRMED):
                    if cell.status != CellStatus.NOT_APPLICABLE:
                        # Batch 02: the verdict label stays, but a prior label
                        # (an agent's detected/confirmed) never erases the leg
                        # that actually ran here.
                        self.matrix.record(ident, ep_key, cid, status=cell.status, reason=cell.reason,
                                           severity=cell.severity, confidence=cell.confidence,
                                           validator=cell.validator, evidence=cell.evidence,
                                           executed=True, attempts=({"id": new_attempt_id(), "sent": None},))
                    continue
                self.matrix.record(
                    ident, ep_key, cid, status=status,
                    reason=ev.get("reason") or f"{conf or cid} leg executed",
                    confidence=ev.get("confidence"),
                    validator=conf or (CHECKS_BY_ID.get(cid).confirmation if cid in CHECKS_BY_ID else None),
                    evidence=(ev.get("evidence") or "")[:200] or None, executed=True,
                    attempts=({"id": new_attempt_id(), "sent": None},))
                n += 1
        return n

    def _unauthenticated(self) -> set[str]:
        """Identities with no credentials: the anonymous principal, by role or id."""
        return {i for i in {c[0] for c in self.matrix.cells()}
                if (self.identity_roles.get(i, i) or "").lower() == "anonymous"}

    def evaluate_readiness(self, resolve=None):
        """One-shot disposition before queue/budget; legacy callers omit it.

        Changed captures/prerequisites use a fresh build_coverage_* tracker and
        its existing conclusive-only checkpoint. This does not retry/re-arm
        previously dispositioned cases on the same tracker.
        """
        if resolve is None:
            return
        for key, cell in self.matrix.cells().items():
            if cell.executed or cell.status == CellStatus.NOT_APPLICABLE:
                continue
            identity, endpoint, check_id = key
            check = CHECKS_BY_ID.get(check_id)
            if check is None:
                continue
            method, _, path = endpoint.partition(" ")
            value = resolve(identity, method, path, check)
            if not isinstance(value, dict) or "status" not in value:
                value = {"status": "needs_prerequisite", "reason_code": "invalid_readiness",
                         "reason": "readiness resolver produced no usable decision"}
            self.readiness[key] = dict(value)
            if value["status"] == "ready":
                continue
            code = value.get("reason_code", "prerequisite_unmet")
            status = (CellStatus.NOT_APPLICABLE if code == "protocol_inapplicable" else
                      CellStatus.BLOCKED if value["status"] == "policy_denied" else
                      CellStatus.INCONCLUSIVE if value["status"] == "needs_prerequisite" else CellStatus.SKIPPED)
            reason = f"{code}: {value.get('reason', '')}"
            for case, child in self.matrix.cases_for_cell(*key):
                if not child.executed and child.status == CellStatus.PENDING:
                    self.matrix.record_case(*key, case, status=status, reason=reason, executed=False)
            if cell.status not in (CellStatus.CONFIRMED, CellStatus.DETECTED):
                self.matrix.record(*key, status=status, reason=reason, executed=False)

    def pending_leg_cells(self, driveable: set[str] | None = None) -> list:
        """(identity, endpoint_key, Check) for every applicable+PENDING cell whose
        check has a deterministic leg (optionally restricted to the `driveable`
        confirmation names the caller can actually run). These are the cells the
        matrix-DRIVER fires regardless of any agent label -- the I1 guarantee."""
        out = []
        for (ident, ep_key, check_id), cell in self.matrix.cells().items():
            if cell.executed or cell.status not in (CellStatus.PENDING, CellStatus.DETECTED):
                continue
            if self.readiness.get((ident, ep_key, check_id), {}).get("status", "ready") != "ready":
                continue
            check = CHECKS_BY_ID.get(check_id)
            if not check or check.confirmation not in _LEG_CONFIRMATIONS:
                continue
            if driveable is not None and check.confirmation not in driveable:
                continue
            out.append((ident, ep_key, check))
        return out

    async def drive_coverage_legs(self, run_leg, *, driveable: set[str] | None = None,
                                  budget: int = 80, deadline: float | None = None, readiness=None) -> int:
        """Actively FIRE each applicable+pending leg-backed cell via the injected
        async `run_leg(identity, method, path, check) -> result` (result exposing
        .status / .summary, or None to skip), recording the REAL outcome. This is
        what turns the matrix from an after-the-fact record into I1's work-program:
        every applicable deterministic check is attempted deterministically,
        independent of whether the LLM labelled it. Returns cells driven. Bounded
        by `budget` so a large surface can't fan out unboundedly, and by
        `deadline` (a `time.monotonic()` value) so it ends in time."""
        self.evaluate_readiness(readiness)
        n = 0
        self.driveable = set(_LEG_CONFIRMATIONS if driveable is None else driveable)
        pending = self.pending_leg_cells(driveable)
        self.queued.update((ident, ep_key, check.id) for ident, ep_key, check in pending)
        for (ident, ep_key, check) in _fair_cells(pending, self._unauthenticated()):
            if n >= budget:
                self.stopped_by = "leg budget"
                break
            if deadline is not None and time.monotonic() >= deadline:
                self.stopped_by = "time budget"
                break
            self._checkpoint_after(n)
            n += 1  # Bound attempts, including failed or declined dispatches.
            self.attempted.add((ident, ep_key, check.id))
            method, _, path = ep_key.partition(" ")
            try:
                res = await run_leg(ident, method, path, check)
            except Exception as e:  # a leg blowing up must not sink coverage
                log.debug("drive_coverage_legs: %s on %s failed: %s", check.confirmation, ep_key, e)
                self.matrix.record(ident, ep_key, check.id, status=CellStatus.ERROR,
                                   reason=f"validator dispatch failed: {type(e).__name__}",
                                   validator=check.confirmation, executed=False)
                continue
            if res is None:
                self.matrix.record(ident, ep_key, check.id, status=CellStatus.INCONCLUSIVE,
                                   reason="validator dispatch returned no result", validator=check.confirmation)
                continue
            status = _covered_status(res, _LEG_STATUS.get(getattr(res, "status", ""), _LEG_STATUS_UNKNOWN))
            executed, fresh, referenced = _attempt_facts(res, status)
            self.matrix.record(
                ident, ep_key, check.id, status=status,
                reason=(getattr(res, "summary", "") or f"{check.confirmation} leg driven off the matrix")[:180],
                confidence=getattr(res, "confidence", None),
                validator=getattr(res, "validator", None) or check.confirmation,
                evidence=(getattr(res, "evidence", "") or "")[:200],
                executed=executed, attempts=fresh, referenced_attempts=referenced)
        return n

    def expand_parameter_cases(self, endpoints: dict[str, dict], *,
                               driveable: set[str] | None = None,
                               per_cell_budget: int = 8) -> int:
        """Enumerate the concrete input cases under each applicable+pending leg cell
        (T05). A PARAMETER-phase check fans out over the endpoint template's real
        inputs (query/body/object-id); a domain/endpoint check, or a parameter check
        on an endpoint with no captured inputs, gets the single NO_PARAMETER_CASE so
        it is still exercised. Bounded per cell so a wide body cannot fan out
        unboundedly; over-budget cases stay visible (SKIPPED), never counted as
        tested. Returns the number of cases registered (added + budget-skipped)."""
        from harness.coverage_model import Phase, NO_PARAMETER_CASE, derive_input_cases_from_template
        total = 0
        for (ident, ep_key, check) in self.pending_leg_cells(driveable):
            ep = endpoints.get(ep_key) or {}
            # Always register the request-level (no-parameter) case FIRST: it is the
            # representative the leg's whole-request result binds to. A PARAMETER
            # check additionally enumerates the endpoint's concrete inputs -- for
            # VISIBILITY, not per-parameter attribution (R01): these deterministic
            # legs test the whole request, so a sibling input is left inconclusive
            # rather than credited with the request-level verdict.
            # The request-level representative is ALWAYS registered (it is the case
            # the leg is actually driven on) -- it is never starved by the budget.
            rep_res = self.matrix.expand_cases(ident, ep_key, check.id, [NO_PARAMETER_CASE])
            total += rep_res["added"]
            # The concrete parameter inputs are enumerated for visibility, bounded by
            # the per-cell budget; over-budget inputs stay visible (SKIPPED).
            if check.phase == Phase.PARAMETER:
                params = derive_input_cases_from_template(ep.get("template"))
                if params:
                    p_res = self.matrix.expand_cases(ident, ep_key, check.id, params,
                                                     budget_remaining=per_cell_budget)
                    total += p_res["added"] + p_res["budget_skipped"]
        return total

    async def drive_coverage_cases(self, run_case, *, driveable: set[str] | None = None,
                                   budget: int = 80, deadline: float | None = None, readiness=None,
                                   field_cap: int = PER_PARAMETER_FIELD_CAP) -> int:
        """Fire each PENDING child case via the injected async
        `run_case(identity, method, path, check, case_key) -> result` (result
        exposing .status/.summary/..., or None when the leg produced no send),
        recording the REAL per-case outcome (T05). This is the case-granular analogue
        of `drive_coverage_legs`: confirming one input marks only THAT case, never
        its siblings.

        A leg that cannot test one input on its own is driven ONCE PER CELL, on the
        request-level (no-parameter) representative, and the result binds to THAT
        case (R01): its verdict is NOT stamped onto each enumerated parameter. Every
        other (parameter) case in the cell is recorded INCONCLUSIVE with an explicit
        "no per-parameter attribution" reason -- visible, but never credited with the
        request-level verdict, proof, or a separate execution. A leg that can (see
        `case_target`) is driven once per parameter case instead, at most
        `field_cap` inputs per cell (`_drive_parameter_cases`).

        `budget` bounds DISPATCH ATTEMPTS -- one per `run_case` call, so a cell driven
        per parameter spends one unit per input it dispatches (R05). A callback
        that RAISES records the representative ERROR (visible, never swallowed); one
        that returns None records INCONCLUSIVE (dispatched, no usable send). An
        unknown status fails conservatively to INCONCLUSIVE, not an optimistic
        NOT_DETECTED (R06). `deadline`, a `time.monotonic()` value, stops new
        dispatches once passed. Returns the number of dispatch attempts made."""
        # group pending cases by cell so each leg is driven once, at request level
        self.evaluate_readiness(readiness)
        cells: dict[tuple[str, str, str], list] = {}
        for (ident, ep_key, check_id, ck) in self.matrix.pending_cases():
            if self.readiness.get((ident, ep_key, check_id), {}).get("status", "ready") != "ready":
                continue
            check = CHECKS_BY_ID.get(check_id)
            if not check or check.confirmation not in _LEG_CONFIRMATIONS:
                continue
            if driveable is not None and check.confirmation not in driveable:
                continue
            cells.setdefault((ident, ep_key, check_id), []).append(ck)

        attempts = 0
        self.driveable = set(_LEG_CONFIRMATIONS if driveable is None else driveable)
        self.queued.update(cells)
        for (ident, ep_key, check_id) in _fair_cells(list(cells), self._unauthenticated()):
            cks = cells[(ident, ep_key, check_id)]
            if attempts >= budget:
                self.stopped_by = "leg budget"
                break
            if deadline is not None and time.monotonic() >= deadline:
                self.stopped_by = "time budget"
                break
            self._checkpoint_after(attempts)
            check = CHECKS_BY_ID[check_id]
            # the request-level representative the whole-request result binds to
            rep = next((c for c in cks if c.is_no_parameter), cks[0])
            self.attempted.add((ident, ep_key, check_id))
            targets = ([c for c in cks if c is not rep and case_target(check.confirmation, c)]
                       if rep.is_no_parameter else [])
            if targets:
                attempts += await self._drive_parameter_cases(
                    run_case, ident, ep_key, check, cks, rep, targets, deadline,
                    budget - attempts, field_cap)
            else:
                attempts += 1
                await self._drive_request_level(run_case, ident, ep_key, check, cks, rep)
        return attempts

    async def _drive_request_level(self, run_case, ident, ep_key, check, cks, rep) -> None:
        """Drive the leg once on the request-level representative; its verdict
        binds to that case only, and every other case in `cks` is recorded
        INCONCLUSIVE (R01: no per-parameter attribution)."""
        check_id = check.id
        method, _, path = ep_key.partition(" ")
        no_attr_reason = (f"{check.confirmation} ran at request level; this leg does not "
                          f"attribute per-parameter evidence, so this input is untested")

        def _mark_siblings_inconclusive(reason):
            for c in cks:
                if c.coord_id() != rep.coord_id():
                    self.matrix.record_case(ident, ep_key, check_id, c,
                                            status=CellStatus.INCONCLUSIVE, reason=reason)

        try:
            res = await run_case(ident, method, path, check, rep)
        except Exception as e:  # a leg blowing up is recorded, never swallowed
            log.debug("drive_coverage_cases: %s on %s failed: %s", check.confirmation, ep_key, e)
            # An attempt was actually dispatched (run_case was invoked and
            # failed mid-flight) -- executed=True distinguishes this from
            # the "no send at all" branch below (R07).
            self.matrix.record_case(
                ident, ep_key, check_id, rep, status=CellStatus.ERROR,
                reason=f"{check.confirmation} attempt errored: {type(e).__name__}: {e}"[:180],
                validator=check.confirmation, executed=False)
            _mark_siblings_inconclusive(f"{check.confirmation} attempt errored at request level")
            return
        if res is None:
            # No request was ever sent (declined/unsupported) -- NOT an
            # execution, however loudly the validator name is attached.
            self.matrix.record_case(
                ident, ep_key, check_id, rep, status=CellStatus.INCONCLUSIVE,
                reason=f"{check.confirmation} produced no send (declined/unsupported)",
                validator=check.confirmation, executed=False)
            _mark_siblings_inconclusive(no_attr_reason)
            return
        self._record_case_result(ident, ep_key, check, rep, res,
                                 f"{check.confirmation} driven at request level")
        _mark_siblings_inconclusive(no_attr_reason)

    def _record_case_result(self, ident, ep_key, check, case, res, default_reason) -> None:
        status = _covered_status(res, _CASE_STATUS.get(getattr(res, "status", ""), CellStatus.INCONCLUSIVE))
        if status in (CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE) and (
                getattr(res, "control_outcome", "") or "") not in ("", "control_held"):
            # The leg itself says this negative does not cover the case (a
            # named parameter it never reached, or inputs it left untested).
            status = CellStatus.INCONCLUSIVE
        executed, fresh, referenced = _attempt_facts(res, status)
        self.matrix.record_case(
            ident, ep_key, check.id, case, status=status,
            reason=(getattr(res, "summary", "") or default_reason)[:180],
            confidence=getattr(res, "confidence", None),
            validator=getattr(res, "validator", None) or check.confirmation,
            evidence=(getattr(res, "evidence", "") or "")[:200], executed=executed,
            attempts=fresh, referenced_attempts=referenced)

    async def _drive_parameter_cases(self, run_case, ident, ep_key, check, cks, rep,
                                     targets, deadline, remaining, field_cap) -> int:
        """Per-parameter dispatch (owner option b): drive the leg once per input it
        can test alone, so each parameter's verdict binds to that parameter's case
        and concludes nothing else. At most `field_cap` inputs per cell; inputs over
        the cap, the case budget, the leg budget (`remaining` dispatches) or the
        deadline stay inconclusive. When any input was not tested on its own, the
        request-level representative is ALSO driven as before (detection
        unchanged, one more dispatch), bound to itself only. Returns the number of
        dispatches made."""
        check_id = check.id
        method, _, path = ep_key.partition(" ")
        tested: set[str] = set()
        timed_out = out_of_budget = False
        used = 0
        for n, case in enumerate(targets):
            if n >= field_cap:
                self.matrix.record_case(
                    ident, ep_key, check_id, case, status=CellStatus.INCONCLUSIVE,
                    reason=f"{check.confirmation}: per-parameter field cap "
                           f"({field_cap}) reached before this input; untested")
                continue
            if used >= remaining:
                out_of_budget = True
                self.stopped_by = "leg budget"
                self.matrix.record_case(
                    ident, ep_key, check_id, case, status=CellStatus.INCONCLUSIVE,
                    reason=f"{check.confirmation}: leg budget reached before this input; untested")
                continue
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                self.stopped_by = "time budget"
                self.matrix.record_case(
                    ident, ep_key, check_id, case, status=CellStatus.INCONCLUSIVE,
                    reason=f"{check.confirmation}: time budget reached before this input; untested")
                continue
            tested.add(case.coord_id())
            used += 1
            try:
                res = await run_case(ident, method, path, check, case)
            except Exception as e:  # recorded on this input only
                log.debug("drive_coverage_cases: %s on %s %s failed: %s",
                          check.confirmation, ep_key, case.label(), e)
                self.matrix.record_case(
                    ident, ep_key, check_id, case, status=CellStatus.ERROR,
                    reason=f"{check.confirmation} attempt errored: {type(e).__name__}: {e}"[:180],
                    validator=check.confirmation, executed=False)
                continue
            if res is None:
                self.matrix.record_case(
                    ident, ep_key, check_id, case, status=CellStatus.INCONCLUSIVE,
                    reason=f"{check.confirmation} produced no send for {case.label()}",
                    validator=check.confirmation, executed=False)
                continue
            self._record_case_result(ident, ep_key, check, case, res,
                                     f"{check.confirmation} driven on {case.label()}")
        others = [(c, r) for c, r in self.matrix.cases_for_cell(ident, ep_key, check_id)
                  if c.coord_id() != rep.coord_id()]
        if (not timed_out and not out_of_budget
                and any(c.coord_id() not in tested for c, _r in others)):
            # Some input was not tested alone (a location this leg cannot target,
            # the field cap, the case budget): keep today's request-level attempt
            # while the leg budget allows one more dispatch. Inputs tested alone
            # keep their own verdicts.
            if used < remaining:
                rest = [c for c in cks if c.coord_id() not in tested]
                await self._drive_request_level(run_case, ident, ep_key, check, rest, rep)
                return used + 1
            out_of_budget = True
            self.stopped_by = "leg budget"
        negatives = (CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE)
        if (not timed_out and not out_of_budget and others
                and all(r.status in negatives for _c, r in others)):
            self.matrix.record_case(
                ident, ep_key, check_id, rep, status=CellStatus.NOT_DETECTED,
                reason=f"{check.confirmation}: every input ({len(others)}) tested on its own, "
                       f"none detected",
                validator=check.confirmation, executed=True,
                referenced_attempts=tuple(a.get("id") if isinstance(a, dict) else a
                                          for _c, r in others for a in r.attempts))
        else:
            self.matrix.record_case(
                ident, ep_key, check_id, rep, status=CellStatus.INCONCLUSIVE,
                reason=f"{check.confirmation} ran per parameter; the request as a whole is "
                       f"concluded only when every input is", validator=check.confirmation)
        return used

    def finalize_pending_reasons(self, investigated_keys: set[str] | None = None) -> int:
        """Give remaining applicable-pending cells an explicit reason so the
        'not tested + why' audit is complete (I5). A leg-backed check on an
        endpoint the worklist DID investigate, but for which no execution was
        recorded, is skipped with an honest "attempt not tracked" reason -- it is
        NEVER inferred as tested (R01). Everything else is either "endpoint not
        reached" or "needs agent/manual review"."""
        investigated_keys = investigated_keys or set()
        n = 0
        for (ident, ep_key, check_id), cell in list(self.matrix.cells().items()):
            if cell.status != CellStatus.PENDING:
                continue
            # A cell whose detail lives in child cases (T05) is left to aggregate
            # from them; the honest per-case reasons are in `cases_not_tested`.
            if self.matrix.has_cases(ident, ep_key, check_id):
                continue
            check = CHECKS_BY_ID.get(check_id)
            if check and check.confirmation in _LEG_CONFIRMATIONS:
                if self.driveable is not None and check.confirmation not in self.driveable:
                    reason = f"validator unavailable or disabled for this run: {check.confirmation}"
                elif ep_key in investigated_keys:
                    reason = (f"endpoint investigated but no {check.confirmation} execution was recorded "
                              f"for identity {ident!r} (attempt not tracked -- not inferred as tested)")
                else:
                    reason = "endpoint not reached in this run's node budget (leg available, not attempted)"
            else:
                reason = ("manual verification required" if check and check.confirmation == "manual"
                          else f"no check-specific coverage adapter (confirmation={getattr(check, 'confirmation', '?')})")
            self.matrix.record(ident, ep_key, check_id, status=CellStatus.SKIPPED, reason=reason)
            n += 1
        return n

    def restore_checkpoint(self, checkpoint, context_key=""):
        self.context_key = context_key
        payload = [self.endpoints, sorted(self.matrix.cells()), context_key]
        self.checkpoint_signature = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        if not checkpoint or checkpoint.get("signature") != self.checkpoint_signature:
            return
        prior = CoverageMatrix.from_dict(checkpoint.get("matrix") or {})
        conclusive = {CellStatus.CONFIRMED, CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE}
        for key, cell in prior.cells().items():
            if key in self.matrix.cells() and cell.executed and cell.status in conclusive:
                # A resumed verdict references the prior run's attempts; nothing is
                # re-sent, so it gains no fresh attempt. A legacy (pre-v2) cell has
                # no ids to reference and is marked as such, never invented.
                refs = tuple(a["id"] for a in cell.attempts) + tuple(cell.referenced_attempts)
                self.matrix.record(*key, status=cell.status, reason=cell.reason,
                                   severity=cell.severity, confidence=cell.confidence,
                                   validator=cell.validator, evidence=cell.evidence, executed=True,
                                   referenced_attempts=refs or ("checkpoint:legacy",))
                self.reused.add(key)

    def phase_ledger(self, *, compact: bool = True):
        """Stage counts over EVERY cell, plus the per-cell rows. `compact` (the
        job-result form, E11) lists a row only for a cell that is shape-applicable
        or has a non-default state (queued, attempted, sent, resumed); the rest are
        counted in `not_applicable` and listed in checkpoint.matrix."""
        rows = []
        for key, cell in self.matrix.cells().items():
            ident, ep, cid = key
            check = CHECKS_BY_ID.get(cid)
            captured = bool(self.endpoints.get(ep, {}).get("template"))
            supported = bool(check and check.confirmation in _LEG_CONFIRMATIONS)
            capability = supported and (self.driveable is None or check.confirmation in self.driveable)
            applicable = cell.status != CellStatus.NOT_APPLICABLE
            conclusive = cell.executed and cell.status in {
                CellStatus.CONFIRMED, CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE}
            # Child aggregation intentionally leaves incomplete cells pending.
            # Preserve a representative's refusal instead of hiding it behind
            # that aggregate status (parameter siblings have no separate send).
            representative = next((result for case, result in self.matrix.cases_for_cell(*key)
                                   if case.is_no_parameter), cell)
            disposition = self.readiness.get(key, {})
            ready = disposition.get("status", "ready") == "ready"
            if disposition.get("status") in {"unsupported", "disabled"}:
                capability = False
            if conclusive:
                reason = "conclusive"
            elif disposition and not ready:
                code = disposition.get("reason_code", "prerequisite_unmet")
                reason = ("validator_unavailable" if disposition.get("status") == "disabled" else
                          code if code in {"manual_required", "check_adapter_missing", "protocol_inapplicable",
                                          "validator_unavailable", "missing_principal", "missing_body", "scope_rejected"}
                          else "policy_blocked" if disposition.get("status") == "policy_denied"
                          else "prerequisite_unmet")
            elif not applicable:
                reason = "not_applicable"
            elif representative.status == CellStatus.BLOCKED:
                reason = "policy_blocked"
            elif any(marker in cell.reason for marker in ("missing_principal", "missing_body", "scope_rejected")):
                reason = next(marker for marker in ("missing_principal", "missing_body", "scope_rejected") if marker in cell.reason)
            elif "did not reach this endpoint" in cell.reason:
                reason = "unreachable_identity"
            elif key in self.attempted and representative.status == CellStatus.SKIPPED:
                # The leg ran and declined on its own precondition (no JWT, no
                # object id, ...): not an unfinished dispatch, and never a negative.
                reason = "leg_precondition_unmet"
            elif key in self.attempted:
                reason = "incomplete_attempt"
            elif check and check.confirmation == "manual":
                reason = "manual_required"
            elif not supported:
                reason = "check_adapter_missing"
            elif not capability:
                reason = "validator_unavailable"
            elif key in self.queued:
                reason = "budget_exhausted"
            elif not captured:
                reason = "missing_capture"
            else:
                reason = "prerequisite_unmet"
            rows.append({"identity": ident, "endpoint": ep, "check": cid,
                         "discovered": True, "captured": captured,
                         "confirmation": getattr(check, "confirmation", None),
                         "observation_status": cell.status.value,
                         "shape_applicable": applicable, "implemented": capability,
                         "eligible": applicable and capability and ready,
                         "readiness": disposition,
                         "queued": key in self.queued,
                         "policy": "allowed" if cell.executed else ("denied" if reason == "policy_blocked" else "not_established"),
                         "attempted": key in self.attempted, "sent": bool(cell.executed),
                         # Batch 02: fresh sends in this run vs referenced prior execution.
                         "fresh_sent": bool(cell.attempts),
                         "fresh_sends": sum(a.get("sent") or 0 for a in cell.attempts),
                         "referenced": bool(cell.referenced_attempts),
                         "conclusive": bool(conclusive), "resumed": key in self.reused,
                         "terminal_reason": reason, "detail": cell.reason})
        ledger = {"counts": {stage: sum(bool(row[stage]) for row in rows) for stage in
                             ("discovered", "captured", "shape_applicable", "implemented", "eligible",
                              "queued", "attempted", "sent", "fresh_sent", "referenced", "conclusive",
                              "resumed")}, "cells": rows}
        ledger["drive"] = _drive_volume(self.matrix, rows)
        if not compact:
            return ledger
        kept, omitted = [], {}
        for row in rows:
            if _listed_in_compact_ledger(row):
                kept.append(row)
            else:
                omitted[row["check"]] = omitted.get(row["check"], 0) + 1
        ledger["cells"] = kept
        ledger["not_applicable"] = {"total": sum(omitted.values()), "by_check": dict(sorted(omitted.items()))}
        ledger["cells_omitted_note"] = ("not-applicable cells are counted in not_applicable "
                                        "and listed in checkpoint.matrix")
        return ledger

    def report(self, *, compact: bool = True) -> dict:
        s = self.matrix.summary()
        s["not_tested"] = self.matrix.not_tested()
        if compact:
            # E11: a not-applicable cell is not a gap, so it is counted per check and
            # reason instead of listed row by row (the full matrix is in the checkpoint).
            # Done here, not in CoverageMatrix.not_tested(), so that method is unchanged.
            na_value = CellStatus.NOT_APPLICABLE.value
            aggregated: dict[str, dict[str, int]] = {}
            for row in s["not_tested"]:
                if row["status"] == na_value:
                    reasons = aggregated.setdefault(row["check"], {})
                    reasons[row["reason"]] = reasons.get(row["reason"], 0) + 1
            s["not_tested"] = [row for row in s["not_tested"] if row["status"] != na_value]
            s["not_tested_not_applicable"] = aggregated
        # T05: the case-granular "not tested + why" (pending/budget-skipped/blocked
        # child cases). Empty when no case layer was populated -- fully additive.
        s["cases_not_tested"] = self.matrix.cases_not_tested()
        # R01/R07: the auditable executed-vs-inferred breakdown, additive
        # alongside the matrix's own (coarser) summary -- coverage_summary.py's
        # real production consumer, reached by every live investigate_engagement
        # run through build_coverage/build_coverage_driven/build_coverage_cases_driven.
        from harness.coverage_summary import summarize_coverage
        s["audited"] = summarize_coverage(self.matrix)
        s["phase_ledger"] = self.phase_ledger(compact=compact)
        s["capability_schema_version"] = 1
        s["attempt_schema_version"] = ATTEMPT_SCHEMA_VERSION
        s["capability_dispositions"] = [{"identity":k[0], "endpoint":k[1], "check":k[2], **v}
                                        for k,v in self.readiness.items()]
        s["checkpoint"] = self.checkpoint()
        return s

    def checkpoint(self) -> dict:
        """What a later run restores completed cells from (restore_checkpoint)."""
        return {"signature": self.checkpoint_signature, "context_key": self.context_key,
                "matrix": self.matrix.to_dict()}

    def _checkpoint_after(self, completed: int) -> None:
        """Hand the checkpoint to on_checkpoint once `completed` legs are done, at each
        multiple of CHECKPOINT_EVERY_LEGS. A failing callback never stops the drive."""
        if self.on_checkpoint is None or completed <= 0 or completed % CHECKPOINT_EVERY_LEGS:
            return
        try:
            self.on_checkpoint(self.checkpoint())
        except Exception as e:
            log.warning("coverage checkpoint callback failed: %s", e)


def endpoint_view(state) -> dict[str, dict]:
    """Project an EngagementState's endpoints to the dict shape the check
    predicates + tracker read (methods as a tuple, findings/access/reachability)."""
    out: dict[str, dict] = {}
    for key, ep in state.endpoints.items():
        out[key] = {
            "path": ep.path,
            "methods": (ep.method,),
            "access": ep.access,
            "reachable_roles": ep.reachable_roles,
            # WL-02 principal cells: reachability is decided per principal.
            "access_by_principal": getattr(ep, "access_by_principal", None) or {},
            "object_scoped": ep.object_scoped,
            "findings": ep.findings,
            # T05: the captured request template, so the case layer can derive the
            # endpoint's concrete inputs (query/body/object-id) rather than invent them.
            "template": getattr(ep, "template", None),
            "capture_variants": getattr(ep, "capture_variants", []),
        }
    return out


def _reaches(ident: str, ep: dict, identity_roles: dict[str, str]) -> bool:
    """Whether coverage identity `ident` (a principal id) reached endpoint `ep`:
    its own access cell decides, so a principal denied with 403 is not counted
    as reaching because another principal of its role did (or one NAMED like
    its role); without a cell, its role in the role view (engagement.principal_reached)."""
    from harness.engagement import principal_reached
    return principal_reached(ep.get("access_by_principal"), ep.get("reachable_roles"),
                             ident, identity_roles.get(ident, ident))


def _identities_of(roles) -> tuple[list[str], dict[str, str]]:
    """Durable principal identities + their role map for coverage (R02). Two
    same-role accounts stay distinct coverage identities via their principal id;
    role is retained (as metadata) only for reachability and trust ordering."""
    identity_roles: dict[str, str] = {}
    for r in (roles or []):
        identity_roles[_principal_of(r)] = _role_of(r)
    identities = sorted(identity_roles) or ["anonymous"]
    return identities, identity_roles


def build_coverage(state, roles, investigated_keys: set[str] | None = None,
                   execution_events=None) -> dict:
    """One call: build + fill + record the coverage matrix for a finished
    engagement and return the auditable report. `roles` is the list of
    role_crawl.RoleSession; `investigated_keys` are the endpoint keys the worklist
    actually probed this run (used only to phrase the skip reason for a leg that
    was never recorded as executed -- NOT to infer a not_detected, R01);
    `execution_events` are real per-cell leg executions to record (see
    `record_execution_events`)."""
    tracker = CoverageTracker()
    endpoints = endpoint_view(state)
    identities, identity_roles = _identities_of(roles)
    tracker.build(endpoints, identities, identity_roles)
    tracker.record_findings_from_state(endpoints, identities, identity_roles)
    if execution_events:
        tracker.record_execution_events(execution_events)
    tracker.finalize_pending_reasons(investigated_keys=set(investigated_keys or ()))
    return tracker.report()


async def build_coverage_driven(state, roles, run_leg, *, driveable: set[str] | None = None,
                                budget: int = 80, investigated_keys: set[str] | None = None,
                                checkpoint=None, context_key="",
                                deadline: float | None = None, on_checkpoint=None, readiness=None) -> dict:
    """Like build_coverage, but ACTIVELY DRIVES the deterministic legs (I1): after
    recording the findings the run already produced, it fires every applicable
    leg-backed cell via `run_leg` (regardless of any agent label) and records the
    real outcome, THEN reasons over what is still pending. Async because the
    driving sends live traffic through the injected `run_leg` seam."""
    tracker = CoverageTracker()
    endpoints = endpoint_view(state)
    identities, identity_roles = _identities_of(roles)
    tracker.build(endpoints, identities, identity_roles)
    tracker.record_findings_from_state(endpoints, identities, identity_roles)
    # The driver records REAL leg outcomes cell-by-cell; there is no inference to
    # add afterwards. Cells the driver did not reach stay pending and are given an
    # honest skip reason below (R01: never fabricate a not_detected).
    tracker.restore_checkpoint(checkpoint, context_key)
    tracker.on_checkpoint = on_checkpoint
    driven = await tracker.drive_coverage_legs(run_leg, driveable=driveable, budget=budget,
                                               deadline=deadline, readiness=readiness)
    tracker.finalize_pending_reasons(investigated_keys=set(investigated_keys or ()))
    report = tracker.report()
    report["legs_driven"] = driven
    report["drive_stopped_by"] = tracker.stopped_by
    report["queued_not_attempted"] = len(tracker.queued - tracker.attempted)
    return report


async def build_coverage_cases_driven(state, roles, run_case, *, driveable: set[str] | None = None,
                                      budget: int = 80, per_cell_case_budget: int = 8,
                                      parameter_field_cap: int = PER_PARAMETER_FIELD_CAP,
                                      investigated_keys: set[str] | None = None,
                                      checkpoint=None, context_key="",
                                      deadline: float | None = None, on_checkpoint=None, readiness=None) -> dict:
    """Case-granular coverage driving (T05/R26): enumerate each applicable leg
    cell's concrete input cases from the endpoint template, then fire a leg PER
    CASE via `run_case(identity, method, path, check, case_key)` and record the
    real per-case outcome. Confirming one input marks only that case; siblings the
    driver did not reach stay visible and honestly pending (never read as tested).

    Distinct from `build_coverage_driven` (which drives once per cell): this is the
    finer-grained path the orchestrator uses when parameter-level coverage is
    enabled. Async because driving sends live traffic through `run_case`."""
    tracker = CoverageTracker()
    endpoints = endpoint_view(state)
    identities, identity_roles = _identities_of(roles)
    tracker.build(endpoints, identities, identity_roles)
    tracker.record_findings_from_state(endpoints, identities, identity_roles)
    tracker.restore_checkpoint(checkpoint, context_key)
    tracker.on_checkpoint = on_checkpoint
    tracker.evaluate_readiness(readiness)
    enumerated = tracker.expand_parameter_cases(
        endpoints, driveable=driveable, per_cell_budget=per_cell_case_budget)
    driven = await tracker.drive_coverage_cases(run_case, driveable=driveable, budget=budget,
                                                deadline=deadline, readiness=None,
                                                field_cap=parameter_field_cap)
    tracker.finalize_pending_reasons(investigated_keys=set(investigated_keys or ()))
    report = tracker.report()
    report["cases_enumerated"] = enumerated
    report["cases_driven"] = driven
    report["drive_stopped_by"] = tracker.stopped_by
    report["queued_not_attempted"] = len(tracker.queued - tracker.attempted)
    return report
