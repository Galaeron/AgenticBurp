"""The drive loops of CoverageTracker: running the queued legs and the per-parameter cases within
the leg and time budgets, and recording each result into the matrix.

Part of the ARC-9 split of harness.coverage_tracker. Import these names from
harness.coverage_tracker, the facade, not from this module.

A name the facade owns and tests patch (`time`, `REQUEST_LEVEL_INPUTS`, `_LEG_STATUS`,
`_fair_cells`, ...) is read as `_ct.<name>` at call time, so a patch on harness.coverage_tracker
reaches this code exactly as when it was one module.
"""
from __future__ import annotations

from itertools import chain

from harness.client_routes import CLIENT_ROUTE_LEGS, CLIENT_ROUTE_LOCATIONS
from harness.coverage_model import CHECKS_BY_ID, CellStatus
from harness.coverage_tracker_tables import (
    _CASE_STATUS, _LEG_CONFIRMATIONS, _PASSIVE_LEG_CONFIRMATIONS, _attempt_facts, _check_of,
    _covered_status, _passive_first,
)
from harness.validators.injection_targets import (
    PER_PARAMETER_FIELD_CAP, PER_PARAMETER_LOCATIONS, case_target,
)


def _drive_order(items, unauthenticated, spent=None):
    """The order a drive dispatches `items` in: passive legs first. Without a
    time bound (`spent` None) the rest share the dispatch budget by count
    (`_fair_cells`); with one, they share the drive's time (`_time_fair_cells`),
    the driver adding each dispatch's seconds to `spent` as it goes."""
    if spent is None:
        return iter(_passive_first(_ct._fair_cells(items, unauthenticated)))
    passive = [item for item in items
               if getattr(_check_of(item), "confirmation", "") in _PASSIVE_LEG_CONFIRMATIONS]
    sending = [item for item in items
               if getattr(_check_of(item), "confirmation", "") not in _PASSIVE_LEG_CONFIRMATIONS]
    return chain(_ct._fair_cells(passive, unauthenticated),
                 _ct._time_fair_cells(sending, unauthenticated, spent))


class _DriveMixin:
    """Methods of CoverageTracker moved verbatim; see harness.coverage_tracker."""

    async def drive_coverage_legs(self, run_leg, *, driveable: set[str] | None = None,
                                  budget: int = 80, deadline: float | None = None, readiness=None) -> int:
        """Actively FIRE each applicable+pending leg-backed cell via the injected
        async `run_leg(identity, method, path, check) -> result` (result exposing
        .status / .summary, or None to skip), recording the REAL outcome. This is
        what turns the matrix from an after-the-fact record into I1's work-program:
        every applicable deterministic check is attempted deterministically,
        independent of whether the LLM labelled it. Returns the budgeted (sending)
        cells driven; passive judgements are counted in `passive_judged`. Bounded
        by `budget` (a passive leg spends none) so a large surface can't fan out unboundedly, and by
        `deadline` (a `time.monotonic()` value) so it ends in time."""
        self.evaluate_readiness(readiness)
        n = 0
        self.driveable = set(_LEG_CONFIRMATIONS if driveable is None else driveable)
        pending = self.pending_leg_cells(driveable)
        self.queued.update((ident, ep_key, check.id) for ident, ep_key, check in pending)
        spent = 0
        # Under a deadline each check's dispatch seconds steer the order (_drive_order).
        seconds: dict[str, float] | None = {} if deadline is not None else None
        for (ident, ep_key, check) in _drive_order(pending, self._unauthenticated(), seconds):
            passive = check.confirmation in _PASSIVE_LEG_CONFIRMATIONS
            if not passive and spent >= budget:
                self.stopped_by = "leg budget"
                break
            if deadline is not None and _ct.time.monotonic() >= deadline:
                self.stopped_by = "time budget"
                break
            self._checkpoint_after(n)
            n += 1
            spent += not passive  # Bound attempts, including failed or declined dispatches.
            self.passive_judged += passive
            self.attempted.add((ident, ep_key, check.id))
            method, _, path = ep_key.partition(" ")
            started = _ct.time.monotonic()
            try:
                res = await run_leg(ident, method, path, check)
            except Exception as e:  # a leg blowing up must not sink coverage
                _ct.log.debug("drive_coverage_legs: %s on %s failed: %s", check.confirmation, ep_key, e)
                self.matrix.record(ident, ep_key, check.id, status=CellStatus.ERROR,
                                   reason=f"validator dispatch failed: {type(e).__name__}",
                                   validator=check.confirmation, executed=False)
                continue
            finally:
                if seconds is not None:
                    seconds[check.id] = seconds.get(check.id, 0.0) + _ct.time.monotonic() - started
            if res is None:
                self.matrix.record(ident, ep_key, check.id, status=CellStatus.INCONCLUSIVE,
                                   reason="validator dispatch returned no result", validator=check.confirmation)
                continue
            self._record_leg_result(ident, ep_key, check, res)
        return spent

    def _record_leg_result(self, ident, ep_key, check, res) -> None:
        status = _covered_status(res, _ct._LEG_STATUS.get(getattr(res, "status", ""), _ct._LEG_STATUS_UNKNOWN))
        executed, fresh, referenced = _attempt_facts(res, status)
        self.matrix.record(
            ident, ep_key, check.id, status=status,
            reason=(getattr(res, "summary", "") or f"{check.confirmation} leg driven off the matrix")[:180],
            confidence=getattr(res, "confidence", None),
            validator=getattr(res, "validator", None) or check.confirmation,
            evidence=(getattr(res, "evidence", "") or "")[:200],
            executed=executed, attempts=fresh, referenced_attempts=referenced)

    # --- R11-4 final pass (harness/final_pass.py): the drive goes on, same tracker ---

    def reopen_unattempted(self) -> int:
        """Put back to PENDING each queued cell the drive never attempted, which
        finalize_pending_reasons had closed as SKIPPED with nothing sent. A cell
        with child cases needs nothing: its unrun cases are still PENDING. Returns
        how many cells were reopened."""
        n = 0
        for key in sorted(self.queued - self.attempted):
            cell = self.matrix.cells().get(key)
            if (cell is None or cell.executed or cell.status != CellStatus.SKIPPED
                    or self.matrix.has_cases(*key)):
                continue
            self.matrix.record(*key, status=CellStatus.PENDING, reason="")
            n += 1
        return n

    async def drive_remaining(self, run_leg, *, case_mode: bool, budget: int,
                              deadline: float | None,
                              field_cap: int = PER_PARAMETER_FIELD_CAP) -> dict:
        """Drive what the first drive left (queued, never attempted), with the
        dispatches its leg budget has left, until `deadline`. The drive's own
        stop reason and counters are kept; this returns this pass's."""
        first_stop = self.stopped_by
        self.stopped_by = None
        reopened = 0 if case_mode else self.reopen_unattempted()
        before = len(self.attempted)
        passive_before = self.passive_judged
        if case_mode:
            driven = await self.drive_coverage_cases(run_leg, driveable=self.driveable, budget=budget,
                                                     deadline=deadline, field_cap=field_cap)
        else:
            driven = await self.drive_coverage_legs(run_leg, driveable=self.driveable, budget=budget,
                                                    deadline=deadline)
        out = {"reopened": reopened, "cells_attempted": len(self.attempted) - before,
               "dispatches": driven, "passive_judged": self.passive_judged - passive_before,
               "stopped_by": self.stopped_by,
               "queued_not_attempted": len(self.queued - self.attempted)}
        self.stopped_by = first_stop
        return out

    def record_held_result(self, ident, ep_key, check, case_key, res) -> None:
        """Record the verdict of a cell (or case, with `case_key`) whose held
        replays the final pass ran, the same way the drive records one."""
        if res is None:
            return
        if case_key is None:
            self._record_leg_result(ident, ep_key, check, res)
        else:
            self._record_case_result(ident, ep_key, check, case_key, res,
                                     f"{check.confirmation} driven with its held replays")

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
            # check additionally enumerates the endpoint's concrete inputs: a leg
            # that can test one input alone (`case_target`) is driven on each, and
            # for any other leg they are VISIBILITY, not per-parameter attribution
            # (R01): a sibling input is left inconclusive rather than credited
            # with the request-level verdict.
            # The request-level representative is ALWAYS registered (it is the case
            # the leg is actually driven on) -- it is never starved by the budget.
            rep_res = self.matrix.expand_cases(ident, ep_key, check.id, [NO_PARAMETER_CASE])
            total += rep_res["added"]
            # The concrete parameter inputs are enumerated for visibility, bounded by
            # the per-cell budget; over-budget inputs stay visible (SKIPPED).
            params = []
            if check.phase == Phase.PARAMETER:
                params = derive_input_cases_from_template(ep.get("template"))
                if check.confirmation not in CLIENT_ROUTE_LEGS:
                    # A client-side route input is loaded in a browser; no other
                    # leg reaches it, so it is no input of that leg's cell.
                    params = [c for c in params
                              if c.parameter_location not in CLIENT_ROUTE_LOCATIONS]
            elif check.confirmation in PER_PARAMETER_LOCATIONS:
                # An endpoint check whose leg can test one parameter alone (path
                # traversal) fans out over the inputs at the locations that leg
                # injects into; what only its request-level attempt reaches (see
                # REQUEST_LEVEL_INPUTS: the path) stays on the representative. An
                # empty body's root container ("/") names no input.
                locations = PER_PARAMETER_LOCATIONS.get(check.confirmation, ())
                params = [c for c in derive_input_cases_from_template(ep.get("template"))
                          if c.parameter_location in locations and c.parameter_name != "/"]
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
        `field_cap` inputs per cell (`_drive_parameter_cases`), and its verdict
        binds to that case only when the leg reports testing exactly that input.

        `budget` bounds DISPATCH ATTEMPTS -- one per `run_case` call, so a cell driven
        per parameter spends one unit per input it dispatches (R05). A passive leg
        (`_PASSIVE_LEG_CONFIRMATIONS`) runs first and spends none. A callback
        that RAISES records the representative ERROR (visible, never swallowed); one
        that returns None records INCONCLUSIVE (dispatched, no usable send). An
        unknown status fails conservatively to INCONCLUSIVE, not an optimistic
        NOT_DETECTED (R06). `deadline`, a `time.monotonic()` value, stops new
        dispatches once passed. Returns the number of budgeted dispatch attempts
        made; passive judgements are counted in `passive_judged`."""
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

        attempts = passive_attempts = 0
        self.driveable = set(_LEG_CONFIRMATIONS if driveable is None else driveable)
        self.queued.update(cells)
        # Under a deadline each check's dispatch seconds steer the order (_drive_order).
        seconds: dict[str, float] | None = {} if deadline is not None else None
        for (ident, ep_key, check_id) in _drive_order(list(cells), self._unauthenticated(), seconds):
            cks = cells[(ident, ep_key, check_id)]
            passive = CHECKS_BY_ID[check_id].confirmation in _PASSIVE_LEG_CONFIRMATIONS
            if not passive and attempts - passive_attempts >= budget:
                self.stopped_by = "leg budget"
                break
            if deadline is not None and _ct.time.monotonic() >= deadline:
                self.stopped_by = "time budget"
                break
            self._checkpoint_after(attempts)
            check = CHECKS_BY_ID[check_id]
            # the request-level representative the whole-request result binds to
            rep = next((c for c in cks if c.is_no_parameter), cks[0])
            self.attempted.add((ident, ep_key, check_id))
            targets = ([c for c in cks if c is not rep and case_target(check.confirmation, c)]
                       if rep.is_no_parameter else [])
            started = _ct.time.monotonic()
            if targets:
                attempts += await self._drive_parameter_cases(
                    run_case, ident, ep_key, check, cks, rep, targets, deadline,
                    budget - (attempts - passive_attempts), field_cap)
            else:
                attempts += 1
                passive_attempts += passive
                await self._drive_request_level(run_case, ident, ep_key, check, cks, rep)
            if seconds is not None:
                seconds[check_id] = seconds.get(check_id, 0.0) + _ct.time.monotonic() - started
        self.passive_judged += passive_attempts
        return attempts - passive_attempts

    async def _drive_request_level(self, run_case, ident, ep_key, check, cks, rep, *,
                                   remainder_only: bool = False) -> None:
        """Drive the leg once on the request-level representative; its verdict
        binds to that case only, and every other case in `cks` is recorded
        INCONCLUSIVE (R01: no per-parameter attribution). `remainder_only` (a leg
        in REQUEST_LEVEL_INPUTS, every parameter case already tested alone) asks
        the leg to test only the input no parameter case names."""
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
            res = await (run_case(ident, method, path, check, rep, remainder_only=True)
                         if remainder_only else run_case(ident, method, path, check, rep))
        except Exception as e:  # a leg blowing up is recorded, never swallowed
            _ct.log.debug("drive_coverage_cases: %s on %s failed: %s", check.confirmation, ep_key, e)
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
                                 f"{check.confirmation} driven at request level"
                                 + (f" on the {_ct.REQUEST_LEVEL_INPUTS.get(check.confirmation)} only"
                                    if remainder_only else ""))
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

    def _record_parameter_result(self, ident, ep_key, check, case, rep, res) -> None:
        """Bind one per-parameter dispatch's result to `case`. A verdict binds only
        when the leg reports it tested exactly that input
        (ValidationResult.tested_parameters); a leg that does not say keeps the
        R01 rule: the case stays INCONCLUSIVE, never tested, and a confirmation
        it cannot place marks the request-level case instead. A result with no
        verdict (skipped, blocked, error, inconclusive) is recorded as it is."""
        status = _CASE_STATUS.get(getattr(res, "status", ""), CellStatus.INCONCLUSIVE)
        tested = tuple(tuple(t) for t in (getattr(res, "tested_parameters", ()) or ()))
        if (status not in (CellStatus.CONFIRMED, CellStatus.NOT_DETECTED,
                           CellStatus.CONTROLLED_NEGATIVE)
                or tested == (case_target(check.confirmation, case),)):
            self._record_case_result(ident, ep_key, check, case, res,
                                     f"{check.confirmation} driven on {case.label()}")
            return
        if status == CellStatus.CONFIRMED:
            self._record_case_result(ident, ep_key, check, rep, res,
                                     f"{check.confirmation} confirmed on the request")
        _, fresh, referenced = _attempt_facts(res, CellStatus.INCONCLUSIVE)
        self.matrix.record_case(
            ident, ep_key, check.id, case, status=CellStatus.INCONCLUSIVE,
            reason=f"{check.confirmation} did not report testing {case.label()} on its own, "
                   f"so its {getattr(res, 'status', '')} result is not attributed to this input",
            validator=check.confirmation, executed=False,
            attempts=fresh, referenced_attempts=referenced)

    async def _drive_parameter_cases(self, run_case, ident, ep_key, check, cks, rep,
                                     targets, deadline, remaining, field_cap) -> int:
        """Per-parameter dispatch (owner option b): drive the leg once per input it
        can test alone, so each parameter's verdict binds to that parameter's case
        and concludes nothing else. At most `field_cap` inputs per cell; inputs over
        the cap, the case budget, the leg budget (`remaining` dispatches) or the
        deadline stay inconclusive. When any input was not tested on its own, the
        request-level representative is ALSO driven as before (detection
        unchanged, one more dispatch), bound to itself only. A leg in
        REQUEST_LEVEL_INPUTS drives it even when every input was tested alone,
        bound to the input no parameter case names (`remainder_only`). Returns the
        number of dispatches made."""
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
            if deadline is not None and _ct.time.monotonic() >= deadline:
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
                _ct.log.debug("drive_coverage_cases: %s on %s %s failed: %s",
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
            self._record_parameter_result(ident, ep_key, check, case, rep, res)
        others = [(c, r) for c, r in self.matrix.cases_for_cell(ident, ep_key, check_id)
                  if c.coord_id() != rep.coord_id()]
        untested = any(c.coord_id() not in tested for c, _r in others)
        # A leg whose request-level attempt also reaches an input no parameter
        # case names (path traversal's path segment) runs it even when every
        # parameter was tested alone, on that input only: skipping it would leave
        # the input untested under a clean cell.
        remainder_only = not untested and check.confirmation in _ct.REQUEST_LEVEL_INPUTS
        if not timed_out and not out_of_budget and (untested or remainder_only):
            # Some input was not tested alone (a location this leg cannot target,
            # the field cap, the case budget): keep today's request-level attempt
            # while the leg budget allows one more dispatch. Inputs tested alone
            # keep their own verdicts.
            if used < remaining:
                rest = [c for c in cks if c.coord_id() not in tested]
                await self._drive_request_level(run_case, ident, ep_key, check, rest, rep,
                                                remainder_only=remainder_only)
                return used + 1
            out_of_budget = True
            self.stopped_by = "leg budget"
        negatives = (CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE)
        declined = [r for c, r in others if c.coord_id() in tested and r.status == CellStatus.SKIPPED
                    and not r.executed and not r.attempts]
        if not timed_out and not out_of_budget and others and len(declined) == len(others):
            # The leg ran on every input and declined each on its own precondition
            # (r10: 226 cells whose replayed request lacked the inputs the endpoint
            # template named), sending nothing. Like a request-level refusal, the
            # representative says so, so the cell is not read as an unfinished drive.
            self.matrix.record_case(
                ident, ep_key, check_id, rep, status=CellStatus.SKIPPED,
                reason=f"{check.confirmation} declined every input it was dispatched on "
                       f"({len(declined)}), sending nothing: {declined[0].reason}"[:180],
                validator=check.confirmation)
        elif (not timed_out and not out_of_budget and others
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


from harness import coverage_tracker as _ct  # noqa: E402
