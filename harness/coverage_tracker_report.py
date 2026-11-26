"""The finishing methods of CoverageTracker: pending reasons, caller-independent credit,
checkpoint and restore, the phase ledger and the report.

Part of the ARC-9 split of harness.coverage_tracker. Import these names from
harness.coverage_tracker, the facade, not from this module.

`_listed_in_compact_ledger` and the logger are read as `_ct.<name>` at call time (a test patches
the former on harness.coverage_tracker).
"""
from __future__ import annotations

import hashlib
import json

from harness.coverage_model import (
    ATTEMPT_SCHEMA_VERSION, CHECKS_BY_ID, CellStatus, CoverageMatrix,
)
from harness.coverage_tracker_tables import (
    CHECKPOINT_EVERY_LEGS, _CONCLUSIVE, _LEG_CONFIRMATIONS, _NO_CAPTURE_CODES, _drive_volume,
    _peer_rank,
)


class _ReportMixin:
    """Methods of CoverageTracker moved verbatim; see harness.coverage_tracker."""

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

    # --- R11-10: identity-independent checks are not one gap per identity ---

    def _lacks_capture(self, key, cell) -> bool:
        """The cell's identity holds no capture of the endpoint: the drive's readiness
        said so (missing_principal, or covered_by_identity from the orchestrator), or
        a restored cell kept that reason."""
        if key in self.credited or (cell.reason or "").startswith(_NO_CAPTURE_CODES):
            return True
        return self.readiness.get(key, {}).get("reason_code") in _NO_CAPTURE_CODES

    def credit_caller_independent(self) -> int:
        """For a check whose verdict does not depend on the caller
        (`Check.caller_independent`), the cell of an identity with no capture of the
        endpoint is credited to another identity's cell for the same endpoint and
        check, instead of standing as a missing-principal gap. Nothing is sent and
        the cell gains no execution: it stays INCONCLUSIVE for its own identity, and
        the report lists it under `credited_by_identity`, apart from the gaps.
        - `covered_by_identity`: the other identity's cell has a conclusive verdict;
        - `open_on_identity`: it has none yet; the gap is counted once, on that cell;
        - `not_applicable_on_identity`: the check does not apply to its capture.
        Identity-bound checks keep `missing_principal`. Idempotent; returns how
        many cells are credited."""
        previous, self.credited = self.credited, {}
        cells = self.matrix.cells()
        by_pair: dict[tuple, list] = {}
        for key in cells:
            by_pair.setdefault((key[1], key[2]), []).append(key)
        for (ep_key, check_id), keys in by_pair.items():
            check = CHECKS_BY_ID.get(check_id)
            if check is None or not check.caller_independent or len(keys) < 2:
                continue
            lacking, peers = [], []
            for key in keys:
                cell = cells[key]
                no_capture = (key in previous or self._lacks_capture(key, cell))
                if no_capture and not cell.executed and cell.status not in _CONCLUSIVE:
                    lacking.append(key)
                elif not no_capture and (cell.status != CellStatus.NOT_APPLICABLE
                                         or (cell.reason or "").startswith("protocol_inapplicable")):
                    # A not-applicable peer counts only when its capture was judged
                    # (readiness: protocol_inapplicable). A shape or origin-scoped
                    # not-applicable cell says nothing about holding a capture.
                    peers.append(key)
            if not lacking or not peers:
                continue
            peer = min(peers, key=lambda k: (_peer_rank(cells[k]), k[0]))
            peer_cell = cells[peer]
            outcome = ("covered_by_identity" if peer_cell.status in _CONCLUSIVE else
                       "not_applicable_on_identity" if peer_cell.status == CellStatus.NOT_APPLICABLE
                       else "open_on_identity")
            reason = (f"{outcome}:{peer[0]}: {peer[0]}'s cell for this check on the same "
                      f"endpoint is {peer_cell.status.value}; this identity holds no capture "
                      "of the endpoint and the check does not depend on the caller")
            for key in lacking:
                self.credited[key] = {"identity": peer[0], "outcome": outcome,
                                      "peer_status": peer_cell.status.value}
                for case, child in self.matrix.cases_for_cell(*key):
                    if not child.executed and child.status not in _CONCLUSIVE:
                        self.matrix.record_case(*key, case, status=CellStatus.INCONCLUSIVE,
                                                reason=reason, executed=False)
                self.matrix.record(*key, status=CellStatus.INCONCLUSIVE, reason=reason[:180],
                                   executed=False)
        return len(self.credited)

    def credited_summary(self) -> dict:
        """Counts of the credited cells: by outcome, by check, by the cell's own identity
        and by the identity whose cell stands for it."""
        by_outcome: dict[str, int] = {}
        by_check: dict[str, int] = {}
        by_identity: dict[str, int] = {}
        by_covering: dict[str, int] = {}
        for (ident, _ep, cid), entry in self.credited.items():
            by_outcome[entry["outcome"]] = by_outcome.get(entry["outcome"], 0) + 1
            by_check[cid] = by_check.get(cid, 0) + 1
            by_identity[ident] = by_identity.get(ident, 0) + 1
            by_covering[entry["identity"]] = by_covering.get(entry["identity"], 0) + 1
        return {"cells": len(self.credited), "by_outcome": dict(sorted(by_outcome.items())),
                "by_check": dict(sorted(by_check.items())),
                "by_cell_identity": dict(sorted(by_identity.items())),
                "by_covering_identity": dict(sorted(by_covering.items())),
                "note": ("cells of an identity with no capture of the endpoint, on a check "
                         "whose verdict does not depend on the caller: counted on the "
                         "identity that holds the capture, neither as a gap nor as a send "
                         "of this identity")}

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
            credit = self.credited.get(key)
            if conclusive:
                reason = "conclusive"
            elif credit is not None:
                # R11-10: not this identity's gap and not its send (see credit_caller_independent).
                reason = credit["outcome"]
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
                         "terminal_reason": reason, "detail": cell.reason,
                         **({"covered_by": credit["identity"]} if credit is not None else {})})
        ledger = {"counts": {stage: sum(bool(row[stage]) for row in rows) for stage in
                             ("discovered", "captured", "shape_applicable", "implemented", "eligible",
                              "queued", "attempted", "sent", "fresh_sent", "referenced", "conclusive",
                              "resumed")}, "cells": rows}
        ledger["drive"] = _drive_volume(self.matrix, rows)
        if not compact:
            return ledger
        kept, omitted = [], {}
        for row in rows:
            if _ct._listed_in_compact_ledger(row):
                kept.append(row)
            else:
                omitted[row["check"]] = omitted.get(row["check"], 0) + 1
        ledger["cells"] = kept
        ledger["not_applicable"] = {"total": sum(omitted.values()), "by_check": dict(sorted(omitted.items()))}
        ledger["cells_omitted_note"] = ("not-applicable cells are counted in not_applicable "
                                        "and listed in checkpoint.matrix")
        return ledger

    def report(self, *, compact: bool = True) -> dict:
        self.credit_caller_independent()
        s = self.matrix.summary()
        # R11-10: a credited cell is listed under credited_by_identity, not as a gap.
        s["not_tested"] = [row for row in self.matrix.not_tested()
                           if (row["identity"], row["endpoint"], row["check"]) not in self.credited]
        s["credited_by_identity"] = self.credited_summary()
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
        s["cases_not_tested"] = [row for row in self.matrix.cases_not_tested()
                                 if (row["identity"], row["endpoint"], row["check"])
                                 not in self.credited]
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
            _ct.log.warning("coverage checkpoint callback failed: %s", e)


from harness import coverage_tracker as _ct  # noqa: E402
