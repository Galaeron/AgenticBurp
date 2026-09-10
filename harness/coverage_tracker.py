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

from categories import canonicalize
from coverage_model import (
    CHECK_CATALOG, CHECKS_BY_ID, Check, CellStatus, CellResult, CoverageMatrix,
)

log = logging.getLogger("harness.coverage_tracker")

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
}


class CoverageTracker:
    """Reconciles a finished engagement into a filled CoverageMatrix."""

    def __init__(self, checks: tuple[Check, ...] = CHECK_CATALOG):
        self.matrix = CoverageMatrix()
        self.checks = checks
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
        na = self.matrix.fill_applicability(identities, endpoints, self.checks)
        skipped = 0
        for ep_key, ep in endpoints.items():
            reach = [str(r) for r in (ep.get("reachable_roles") or [])]
            if not reach:
                continue  # reachability unknown -> leave applicable cells pending
            for ident in identities:
                if identity_roles.get(ident, ident) in reach:
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
        reach = [str(r) for r in (ep.get("reachable_roles") or [])]
        pool = [i for i in identities if identity_roles.get(i, i) in reach] or list(identities)
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
                    continue
                self.matrix.record(
                    ident, ep_key, cid, status=status,
                    reason=ev.get("reason") or f"{conf or cid} leg executed",
                    confidence=ev.get("confidence"),
                    validator=conf or (CHECKS_BY_ID.get(cid).confirmation if cid in CHECKS_BY_ID else None),
                    evidence=(ev.get("evidence") or "")[:200] or None)
                n += 1
        return n

    def pending_leg_cells(self, driveable: set[str] | None = None) -> list:
        """(identity, endpoint_key, Check) for every applicable+PENDING cell whose
        check has a deterministic leg (optionally restricted to the `driveable`
        confirmation names the caller can actually run). These are the cells the
        matrix-DRIVER fires regardless of any agent label -- the I1 guarantee."""
        out = []
        for (ident, ep_key, check_id), cell in self.matrix.cells().items():
            if cell.status != CellStatus.PENDING:
                continue
            check = CHECKS_BY_ID.get(check_id)
            if not check or check.confirmation not in _LEG_CONFIRMATIONS:
                continue
            if driveable is not None and check.confirmation not in driveable:
                continue
            out.append((ident, ep_key, check))
        return out

    async def drive_coverage_legs(self, run_leg, *, driveable: set[str] | None = None,
                                  budget: int = 80) -> int:
        """Actively FIRE each applicable+pending leg-backed cell via the injected
        async `run_leg(identity, method, path, check) -> result` (result exposing
        .status / .summary, or None to skip), recording the REAL outcome. This is
        what turns the matrix from an after-the-fact record into I1's work-program:
        every applicable deterministic check is attempted deterministically,
        independent of whether the LLM labelled it. Returns cells driven. Bounded
        by `budget` so a large surface can't fan out unboundedly."""
        _STATUS = {"confirmed": CellStatus.CONFIRMED, "not_confirmed": CellStatus.NOT_DETECTED,
                   "skipped": CellStatus.SKIPPED, "error": CellStatus.ERROR}
        n = 0
        for (ident, ep_key, check) in self.pending_leg_cells(driveable):
            if n >= budget:
                break
            method, _, path = ep_key.partition(" ")
            try:
                res = await run_leg(ident, method, path, check)
            except Exception as e:  # a leg blowing up must not sink coverage
                log.debug("drive_coverage_legs: %s on %s failed: %s", check.confirmation, ep_key, e)
                continue
            if res is None:
                continue
            n += 1
            status = _STATUS.get(getattr(res, "status", ""), CellStatus.NOT_DETECTED)
            self.matrix.record(
                ident, ep_key, check.id, status=status,
                reason=(getattr(res, "summary", "") or f"{check.confirmation} leg driven off the matrix")[:180],
                confidence=getattr(res, "confidence", None),
                validator=getattr(res, "validator", None) or check.confirmation,
                evidence=(getattr(res, "evidence", "") or "")[:200])
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
        from coverage_model import Phase, NO_PARAMETER_CASE, derive_input_cases_from_template
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
                                   budget: int = 80) -> int:
        """Fire each PENDING child case via the injected async
        `run_case(identity, method, path, check, case_key) -> result` (result
        exposing .status/.summary/..., or None when the leg produced no send),
        recording the REAL per-case outcome (T05). This is the case-granular analogue
        of `drive_coverage_legs`: confirming one input marks only THAT case, never
        its siblings.

        The leg is driven ONCE PER CELL, on the request-level (no-parameter)
        representative, and the result binds to THAT case (R01): a deterministic leg
        tests the whole request, so its verdict is NOT stamped onto each enumerated
        parameter. Every other (parameter) case in the cell is recorded INCONCLUSIVE
        with an explicit "no per-parameter attribution" reason -- visible, but never
        credited with the request-level verdict, proof, or a separate execution.

        `budget` bounds DISPATCH ATTEMPTS -- one per driven cell (R05). A callback
        that RAISES records the representative ERROR (visible, never swallowed); one
        that returns None records INCONCLUSIVE (dispatched, no usable send). An
        unknown status fails conservatively to INCONCLUSIVE, not an optimistic
        NOT_DETECTED (R06). Returns the number of dispatch attempts made."""
        _STATUS = {"confirmed": CellStatus.CONFIRMED, "not_confirmed": CellStatus.NOT_DETECTED,
                   "controlled_negative": CellStatus.CONTROLLED_NEGATIVE,
                   "blocked": CellStatus.BLOCKED, "inconclusive": CellStatus.INCONCLUSIVE,
                   "skipped": CellStatus.SKIPPED, "error": CellStatus.ERROR}
        # group pending cases by cell so each leg is driven once, at request level
        cells: dict[tuple[str, str, str], list] = {}
        for (ident, ep_key, check_id, ck) in self.matrix.pending_cases():
            check = CHECKS_BY_ID.get(check_id)
            if not check or check.confirmation not in _LEG_CONFIRMATIONS:
                continue
            if driveable is not None and check.confirmation not in driveable:
                continue
            cells.setdefault((ident, ep_key, check_id), []).append(ck)

        def _mark_siblings_inconclusive(ident, ep_key, check_id, cks, target, reason):
            for c in cks:
                if c.coord_id() == target.coord_id():
                    continue
                self.matrix.record_case(ident, ep_key, check_id, c,
                                        status=CellStatus.INCONCLUSIVE, reason=reason)

        attempts = 0
        for (ident, ep_key, check_id), cks in cells.items():
            if attempts >= budget:
                break
            check = CHECKS_BY_ID[check_id]
            method, _, path = ep_key.partition(" ")
            # the request-level representative the whole-request result binds to
            rep = next((c for c in cks if c.is_no_parameter), cks[0])
            no_attr_reason = (f"{check.confirmation} ran at request level; this leg does not "
                              f"attribute per-parameter evidence, so this input is untested")
            attempts += 1
            try:
                res = await run_case(ident, method, path, check, rep)
            except Exception as e:  # a leg blowing up is recorded, never swallowed
                log.debug("drive_coverage_cases: %s on %s failed: %s", check.confirmation, ep_key, e)
                self.matrix.record_case(
                    ident, ep_key, check_id, rep, status=CellStatus.ERROR,
                    reason=f"{check.confirmation} attempt errored: {type(e).__name__}: {e}"[:180],
                    validator=check.confirmation)
                _mark_siblings_inconclusive(ident, ep_key, check_id, cks, rep,
                                            f"{check.confirmation} attempt errored at request level")
                continue
            if res is None:
                self.matrix.record_case(
                    ident, ep_key, check_id, rep, status=CellStatus.INCONCLUSIVE,
                    reason=f"{check.confirmation} produced no send (declined/unsupported)",
                    validator=check.confirmation)
                _mark_siblings_inconclusive(ident, ep_key, check_id, cks, rep, no_attr_reason)
                continue
            status = _STATUS.get(getattr(res, "status", ""), CellStatus.INCONCLUSIVE)
            self.matrix.record_case(
                ident, ep_key, check_id, rep, status=status,
                reason=(getattr(res, "summary", "") or f"{check.confirmation} driven at request level")[:180],
                confidence=getattr(res, "confidence", None),
                validator=getattr(res, "validator", None) or check.confirmation,
                evidence=(getattr(res, "evidence", "") or "")[:200])
            _mark_siblings_inconclusive(ident, ep_key, check_id, cks, rep, no_attr_reason)
        return attempts

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
                if ep_key in investigated_keys:
                    reason = (f"endpoint investigated but no {check.confirmation} execution was recorded "
                              f"for identity {ident!r} (attempt not tracked -- not inferred as tested)")
                else:
                    reason = "endpoint not reached in this run's node budget (leg available, not attempted)"
            else:
                reason = f"no deterministic leg (confirmation={getattr(check, 'confirmation', '?')}); needs agent/manual review"
            self.matrix.record(ident, ep_key, check_id, status=CellStatus.SKIPPED, reason=reason)
            n += 1
        return n

    def report(self) -> dict:
        s = self.matrix.summary()
        s["not_tested"] = self.matrix.not_tested()
        # T05: the case-granular "not tested + why" (pending/budget-skipped/blocked
        # child cases). Empty when no case layer was populated -- fully additive.
        s["cases_not_tested"] = self.matrix.cases_not_tested()
        return s


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
            "object_scoped": ep.object_scoped,
            "findings": ep.findings,
            # T05: the captured request template, so the case layer can derive the
            # endpoint's concrete inputs (query/body/object-id) rather than invent them.
            "template": getattr(ep, "template", None),
        }
    return out


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
                                budget: int = 80, investigated_keys: set[str] | None = None) -> dict:
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
    driven = await tracker.drive_coverage_legs(run_leg, driveable=driveable, budget=budget)
    tracker.finalize_pending_reasons(investigated_keys=set(investigated_keys or ()))
    report = tracker.report()
    report["legs_driven"] = driven
    return report


async def build_coverage_cases_driven(state, roles, run_case, *, driveable: set[str] | None = None,
                                      budget: int = 80, per_cell_case_budget: int = 8,
                                      investigated_keys: set[str] | None = None) -> dict:
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
    enumerated = tracker.expand_parameter_cases(
        endpoints, driveable=driveable, per_cell_budget=per_cell_case_budget)
    driven = await tracker.drive_coverage_cases(run_case, driveable=driveable, budget=budget)
    tracker.finalize_pending_reasons(investigated_keys=set(investigated_keys or ()))
    report = tracker.report()
    report["cases_enumerated"] = enumerated
    report["cases_driven"] = driven
    return report
