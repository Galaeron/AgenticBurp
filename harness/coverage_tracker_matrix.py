"""The matrix-building methods of CoverageTracker: resolving a finding's class to catalog rows,
filling cells from the engagement state and execution events, readiness and pending legs.

Part of the ARC-9 split of harness.coverage_tracker. Import these names from
harness.coverage_tracker, the facade, not from this module.
"""
from __future__ import annotations

from harness.categories import canonicalize
from harness.coverage_model import (
    CHECKS_BY_ID, CHECK_ID_SCHEME, CellResult, CellStatus, check_id_scheme_of, is_legacy_check_id,
    resolve_check_id, specific_class_token,
)
from harness.coverage_tracker_tables import _LEG_CONFIRMATIONS, _reaches, _trust, new_attempt_id


class _MatrixMixin:
    """Methods of CoverageTracker moved verbatim; see harness.coverage_tracker."""

    def _specific_check(self, text: str) -> str | None:
        return self._specific_to_check.get(specific_class_token(text))

    def resolve_class(self, vuln_class: str, validator: str | None = None) -> tuple[list[str], bool]:
        """Catalog check ids a finding of `vuln_class` bears on, and whether that
        result is AMBIGUOUS (more than one row left). Order (WG-2 (4)):

        (a) the raw/snake class is one of a row's `specific_classes` -> that row only;
        (b) the canonical/raw class match; when several rows share it and `validator`
            (the finding's validator / confirmed_by_leg) is given, narrow to the rows
            whose `confirmation` equals it, when that leaves at least one;
        (c) the access-control free-text words (resolved through (a)), then a
            whole-word fallback against each check's class token -- whole-word so a
            short token like 'auth' does not match inside 'authorization'."""
        import re as _re
        raw = (vuln_class or "").lower().strip()
        if not raw:
            return [], False
        # (a) a token that names one row of a shared class.
        hit = self._specific_check(raw)
        if hit:
            return [hit], False
        # (b) exact canonical / raw token match.
        canon = canonicalize(vuln_class)
        ids: list[str] = []
        for key in (canon, raw):
            if key and key in self._class_to_checks:
                ids.extend(self._class_to_checks[key])
        ids = sorted(set(ids))
        if ids:
            if len(ids) > 1 and validator:
                v = str(validator).lower().strip()
                v = v[:-len("_validator")] if v.endswith("_validator") else v
                by_id = {c.id: c for c in self.checks}
                narrowed = [i for i in ids if i in by_id and by_id[i].confirmation == v]
                if narrowed:
                    ids = narrowed
            if len(ids) > 1:
                # A compound class ("IDOR/BOLA") canonicalizes to a shared class but
                # names one row through its access-control words.
                for words in self._ACCESS_CONTROL_WORDS:
                    for w in words:
                        if w in raw:
                            hit = self._specific_check(w)
                            if hit in ids:
                                return [hit], False
            return ids, len(ids) > 1
        # (c) access-control free text, through the specific-token table.
        for words in self._ACCESS_CONTROL_WORDS:
            for w in words:
                if w in raw:
                    hit = self._specific_check(w)
                    if hit:
                        return [hit], False
        for c in self.checks:
            ct = c.vulnerability_class.lower()
            if len(ct) >= 4 and _re.search(r"\b" + _re.escape(ct) + r"\b", raw):
                ids.append(c.id)
        ids = sorted(set(ids))
        return ids, len(ids) > 1

    def checks_for_class(self, vuln_class: str, validator: str | None = None) -> list[str]:
        """Catalog check ids a finding of `vuln_class` bears on (see `resolve_class`;
        `class_is_ambiguous` says whether more than one row is left)."""
        return self.resolve_class(vuln_class, validator)[0]

    def class_is_ambiguous(self, vuln_class: str, validator: str | None = None) -> bool:
        """True when `vuln_class` (narrowed by `validator`) still names several rows,
        so a confirmation cannot say which cell it proves."""
        return self.resolve_class(vuln_class, validator)[1]

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
                                   identity_roles: dict[str, str] | None = None, *,
                                   late: bool = False) -> int:
        """Record CONFIRMED/DETECTED cells from the findings attached to each
        endpoint, attributed to the endpoint's probe identity. Returns cells set.

        `late` records findings produced after the matrix was driven (retry rounds)
        into the cells it already has, and counts only the cells it changes: a
        confirmed finding is recorded anywhere (a confirmation outranks a driven
        negative, and `record` never overwrites a confirmed cell); a detected one
        only fills a cell no leg executed, so a driven verdict is never overturned
        by an agent label. A cell the matrix does not have is left out: a late
        finding does not grow the denominator after the drive."""
        n = 0
        for ep_key, ep in endpoints.items():
            findings = ep.get("findings") or []
            if not findings:
                continue
            ident = self._probe_identity(ep, identities, identity_roles)
            for f in findings:
                vc = f.get("vulnerability_class", "")
                confirmed = bool(f.get("confirmed"))
                check_ids, ambiguous = self.resolve_class(
                    vc, f.get("validator") or f.get("confirmed_by_leg"))
                status = CellStatus.CONFIRMED if confirmed else CellStatus.DETECTED
                reason = f"{'confirmed' if confirmed else 'detected'} {vc}"
                if confirmed and ambiguous:
                    # WG-2 (4): one confirmation proves ONE cell; when the class is
                    # shared and the finding names no specific row, every candidate is
                    # DETECTED (still visible, still drivable), never CONFIRMED.
                    status = CellStatus.DETECTED
                    reason = (f"confirmed {vc}, but the class is shared by {len(check_ids)} "
                              f"rows and the finding names no specific one")
                for check_id in check_ids:
                    if late:
                        cell = self.matrix.get(ident, ep_key, check_id)
                        # A late DETECTED (an agent label, or an ambiguous confirmation)
                        # only fills a cell no leg executed.
                        if (cell is None or cell.status in (status, CellStatus.CONFIRMED)
                                or (status != CellStatus.CONFIRMED and cell.executed)):
                            continue
                    self.matrix.record(
                        ident, ep_key, check_id, status=status,
                        reason=reason,
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
                # WG-1: an event naming a legacy (pre-WG-1) id lands on its current
                # cell; an unknown id matches no cell and is skipped below. Events
                # come from this run's legs (no persisted ledger is replayed), so an
                # unmarked event uses the current id scheme; one stamped
                # `check_id_scheme: 1` reads as pre-WG-1 data.
                cid = ev["check_id"]
                try:
                    scheme = check_id_scheme_of(ev.get("check_id_scheme", CHECK_ID_SCHEME))
                except ValueError:
                    continue
                check_ids = [resolve_check_id(cid, scheme=scheme)
                             if is_legacy_check_id(cid, scheme) else cid]
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
