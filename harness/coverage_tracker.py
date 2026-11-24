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

The module is split by seam (ARC-9). This module stays the import path and owns the state
tests patch (`time`, `REQUEST_LEVEL_INPUTS`, the logger); it re-exports every name below,
and CoverageTracker is composed of three mixins whose code reads those names back through
this module at call time:

    coverage_tracker_tables  status maps, confirmation tables, fair-share scheduling, helpers
    coverage_tracker_matrix  class resolution, build, recording, readiness
    coverage_tracker_drive   the leg and case drive loops
    coverage_tracker_report  finalize, credit, checkpoint, phase ledger, report
"""
from __future__ import annotations

import logging
import time

from harness.categories import canonicalize
from harness.coverage_model import CHECK_CATALOG, Check, CoverageMatrix, specific_class_token
from harness.validators.injection_targets import PER_PARAMETER_FIELD_CAP, REQUEST_LEVEL_INPUTS
from harness.coverage_tracker_drive import _DriveMixin, _drive_order  # noqa: F401
from harness.coverage_tracker_matrix import _MatrixMixin  # noqa: F401
from harness.coverage_tracker_report import _ReportMixin  # noqa: F401
from harness.coverage_tracker_tables import (  # noqa: F401
    CHECKPOINT_EVERY_LEGS, DRIVE_LABELS, UNDRIVEN_ROW_CONFIRMATIONS, _CASE_STATUS, _CONCLUSIVE,
    _LEG_CONFIRMATIONS, _LEG_EXECUTED, _LEG_STATUS, _LEG_STATUS_UNKNOWN, _NO_CAPTURE_CODES,
    _PASSIVE_LEG_CONFIRMATIONS, _PEER_ORDER, _PHASE_TURN, _TRUST, _WRITE_METHODS, _attempt_facts,
    _check_of, _check_queues, _covered_status, _drive_volume, _executed, _fair_cells,
    _listed_in_compact_ledger, _passive_first, _peer_rank, _principal_of, _reaches, _role_of,
    _spread_cells, _time_fair_cells, _trust, leg_table_problems, new_attempt_id,
    resume_context_key,
)


log = logging.getLogger("harness.coverage_tracker")


class CoverageTracker(_MatrixMixin, _DriveMixin, _ReportMixin):
    """Reconciles a finished engagement into a filled CoverageMatrix."""

    def __init__(self, checks: tuple[Check, ...] = CHECK_CATALOG):
        self.matrix = CoverageMatrix()
        self.checks = checks
        self.attempted = set()
        self.queued = set()
        self.reused = set()
        self.readiness: dict[tuple, dict] = {}
        # R11-10: cell key -> {"identity", "outcome", "peer_status"} for a cell of an
        # identity with no capture of the endpoint, on a caller-independent check that
        # another identity holds a capture for (credit_caller_independent).
        self.credited: dict[tuple, dict] = {}
        self.endpoints = {}
        self.identity_roles: dict[str, str] = {}
        self.driveable = None  # None means no driver supplied; an empty set means none available.
        self.checkpoint_signature = ""
        self.context_key = ""
        # E7: called with checkpoint() every CHECKPOINT_EVERY_LEGS completed legs.
        self.on_checkpoint = None
        # Why a drive stopped with queued cells left: "leg budget" or "time budget".
        self.stopped_by = None
        # Passive legs judged (no send, no budget); the drivers return only budgeted dispatches.
        self.passive_judged = 0
        # canonical vulnerability_class -> [check_id]; plus the raw class token so
        # a check class canonicalize() returns None for (e.g. "misconfig") still maps.
        self._class_to_checks: dict[str, list[str]] = {}
        for c in checks:
            for token in {c.vulnerability_class, canonicalize(c.vulnerability_class) or c.vulnerability_class}:
                self._class_to_checks.setdefault(token, []).append(c.id)
        # WG-2 (4): snake token -> the ONE row whose specific_classes names it (the
        # catalog guard keeps tokens unique; on an injected clash the first row wins).
        self._specific_to_check: dict[str, str] = {}
        for c in checks:
            for tok in c.specific_classes:
                self._specific_to_check.setdefault(specific_class_token(tok), c.id)

    # --- mapping a finding's class to catalog checks ---

    # Access-control free-text words (canonicalize misses most of these). Each one is
    # in a row's specific_classes, so it resolves to that ONE row (WG-2: "idor" no
    # longer also fills ATHZ-02). BFLA wording is tried first, as before.
    _ACCESS_CONTROL_WORDS = (
        ("bfla", "function-level", "function level", "broken function"),
        ("idor", "bola", "object-level", "object level", "insecure direct object"),
    )


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
    _add_client_routes(out, getattr(state, "client_routes", None))
    return out


def _add_client_routes(out: dict[str, dict], routes) -> None:
    """Give each client-side route input (client_routes.py) its coverage cells.
    A history route that is also a captured endpoint carries its page-query
    parameters on that endpoint's template; any other route becomes an endpoint of
    its own, `GET /doc#/route` or `GET /doc`, that only the browser XSS legs load
    (Check.applies)."""
    if routes is None:
        return
    try:
        inputs = routes.inputs()
    except Exception as e:  # a malformed restored map must not stop coverage
        log.warning("client routes unreadable for coverage: %s", e)
        return
    for route in inputs:
        key = route.endpoint_key
        tmpl = route.template()
        if key in out:
            base = dict(out[key].get("template") or {})
            base["client_route"] = tmpl["client_route"]
            out[key] = {**out[key], "template": base}
            continue
        out[key] = {
            "path": route.path, "methods": ("GET",), "access": {}, "reachable_roles": [],
            "access_by_principal": {}, "object_scoped": False, "findings": [],
            "template": tmpl, "capture_variants": [], "client_route_only": True,
        }


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
                                deadline: float | None = None, on_checkpoint=None, readiness=None,
                                tracker_out: list | None = None) -> dict:
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
    report["passive_legs_judged"] = tracker.passive_judged
    report["drive_stopped_by"] = tracker.stopped_by
    report["queued_not_attempted"] = len(tracker.queued - tracker.attempted)
    if tracker_out is not None:
        tracker_out.append(tracker)
    return report


async def build_coverage_cases_driven(state, roles, run_case, *, driveable: set[str] | None = None,
                                      budget: int = 80, per_cell_case_budget: int = 8,
                                      parameter_field_cap: int = PER_PARAMETER_FIELD_CAP,
                                      investigated_keys: set[str] | None = None,
                                      checkpoint=None, context_key="",
                                      deadline: float | None = None, on_checkpoint=None, readiness=None,
                                      tracker_out: list | None = None) -> dict:
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
    report["passive_legs_judged"] = tracker.passive_judged
    report["drive_stopped_by"] = tracker.stopped_by
    report["queued_not_attempted"] = len(tracker.queued - tracker.attempted)
    if tracker_out is not None:
        tracker_out.append(tracker)
    return report


def report_after_final_pass(tracker, previous: dict, investigated_keys: set[str] | None = None,
                            final_pass: dict | None = None) -> dict:
    """Re-issue a driven coverage report once the final pass (R11-4) has driven more
    cells on `tracker`. The first drive's statistics in `previous` are kept, and
    the pass's own counts go under `final_pass`."""
    tracker.finalize_pending_reasons(investigated_keys=set(investigated_keys or ()))
    report = tracker.report()
    for key, value in previous.items():
        report.setdefault(key, value)
    report["queued_not_attempted"] = len(tracker.queued - tracker.attempted)
    if final_pass is not None:
        report["final_pass"] = final_pass
    return report


def refresh_after_retry_rounds(tracker, previous: dict, state, roles,
                               investigated_keys: set[str] | None = None) -> dict:
    """Re-issue a driven coverage report once retry rounds have run.

    The matrix is built and driven before the retry rounds, so findings those rounds
    produce would otherwise be missing from it. This records them into the same
    tracker (`record_findings_from_state(late=True)`: no driven verdict overturned,
    no new cells) and returns a fresh report that keeps the drive's statistics from
    `previous`. Returns `previous` unchanged when the rounds changed no cell."""
    endpoints = endpoint_view(state)
    identities, identity_roles = _identities_of(roles)
    changed = tracker.record_findings_from_state(endpoints, identities, identity_roles, late=True)
    if not changed:
        return previous
    tracker.finalize_pending_reasons(investigated_keys=set(investigated_keys or ()))
    report = tracker.report()
    for key, value in previous.items():
        report.setdefault(key, value)
    report["refreshed_after_retry_rounds"] = changed
    return report
