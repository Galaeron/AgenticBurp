"""Batch 02: attempt facts are separate from verdict projections.

Every case drives the production coverage builders through the run's real
_ConfirmationCache, ExecutionRegistry and RunContext transport against a
loopback target. Only the validator is a fixture: it makes one real GET
through the run's executor and reports the status it is told to.
"""
from __future__ import annotations

import asyncio
import json
import threading
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harness import coverage_tracker, engagement
from harness.assessment_health import assessment_health
from harness.coverage_model import CellStatus, CoverageMatrix
from harness.coverage_tracker import (CoverageTracker, build_coverage,
                                      build_coverage_cases_driven, build_coverage_driven)
from harness.models import Finding, HttpExchange
from harness.orchestrator_chain import _ConfirmationCache
from harness.role_crawl import RoleSession
from harness.run_context import RunContext, TypedRequest
from harness.validators.base import ValidationResult
from harness.validators.injection_targets import case_target

ROLES = [RoleSession("anonymous", {})]
CHECK = "WSTG-INPV-05"          # SQL injection, a parameter (case-driven) check


class _Target:
    def __init__(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.server.requests += 1
                data = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.requests = 0
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def requests(self):
        return self.server.requests

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class _OneSend:
    """Fixture validator: one real send through the run, then a fixed status."""
    name = "sqlmap"

    def __init__(self, ctx, status="not_confirmed"):
        self.run_context, self.status = ctx, status

    async def validate(self, finding, exchange):
        outcome = await self.run_context.executor().execute(
            TypedRequest("GET", exchange.url), capability="sqlmap")
        return ValidationResult(self.name, self.status if outcome.ok else "inconclusive",
                                finding.vulnerability_class, summary="fixture leg")


def _state(base, *paths):
    state = engagement.EngagementState(host="127.0.0.1")
    for path in paths:
        url = f"{base}{path}"
        state.record_template(url, "GET", HttpExchange(
            method="GET", url=url, request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body='{"ok": true}'))
    for ep in state.endpoints.values():
        ep.reachable_roles = ["anonymous"]
    return state


class _Run:
    """A run context plus the production confirmation cache over it."""

    def __init__(self, target, status="not_confirmed", bind_cases=False):
        self.target, self.status, self.bind_cases = target, status, bind_cases
        self.ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=50,
                                     gate_config={"active_enabled": True})
        self.cache = _ConfirmationCache(self.ctx, lambda *args: "case:shared")
        self.dispatched = 0

    async def run_case(self, identity, method, path, check, case_key=None):
        self.dispatched += 1
        exchange = HttpExchange(method=method, url=f"{self.target.base}{path.replace('{id}', '1')}?q=1",
                                request_headers={}, request_body="", response_status=200,
                                response_headers={}, response_body="")
        finding = Finding(vulnerability_class=check.vulnerability_class, confidence=0.5,
                          summary="coverage", evidence="", suggested_test="", basis="derived")
        target = case_target(check.confirmation, case_key) if self.bind_cases and case_key else None
        if target is not None:
            # As the production case leg does: bind the leg to the parameter case.
            finding = finding.model_copy(update={"parameter_location": target[0],
                                                 "parameter_name": target[1], "parameter_only": True})
        return await self.cache.validate(_OneSend(self.ctx, self.status), finding, exchange,
                                         case_ref="case:shared")

    def drive(self, builder, state, **kwargs):
        async def go():
            async with self.ctx:
                return await builder(state, ROLES, self.run_case, driveable={"sqlmap"}, **kwargs)
        return asyncio.run(go())


ITEMS = "GET /items/{id}"


def _cell(report, path=ITEMS):
    matrix = CoverageMatrix.from_dict(report["checkpoint"]["matrix"])
    return matrix, matrix.get("anonymous", path, CHECK)


def _row(report, path=ITEMS):
    return next(r for r in report["phase_ledger"]["cells"]
                if r["endpoint"] == path and r["check"] == CHECK)


class AttemptFactTests(unittest.TestCase):
    def setUp(self):
        self.target = _Target()
        self.addCleanup(self.target.close)

    def test_sqlmap_per_parameter_dispatch_records_one_fresh_attempt_per_input(self):
        """Per-parameter dispatch: sqlmap is sent once for `q`, once for `sort` and
        once at request level for the path id it cannot target alone. Each send is
        a fresh attempt on its own case; the untargetable sibling keeps the cell
        executed but incomplete."""
        run = _Run(self.target, bind_cases=True)
        report = run.drive(build_coverage_cases_driven, _state(self.target.base, "/items/1?q=1&sort=a"))
        matrix, parent = _cell(report)
        self.assertEqual(self.target.requests, 3)
        self.assertEqual(parent.status, CellStatus.PENDING)       # not endpoint-complete
        self.assertTrue(parent.executed)
        self.assertEqual(len(parent.attempts), 3)
        cases = {ck.parameter_name: r for ck, r in matrix.cases_for_cell("anonymous", ITEMS, CHECK)}
        for name in ("q", "sort", ""):
            self.assertEqual(cases[name].status, CellStatus.NOT_DETECTED, name)
            self.assertEqual(len(cases[name].attempts), 1, name)
            self.assertEqual(cases[name].attempts[0]["sent"], 1, name)
        self.assertEqual(len({cases[n].attempts[0]["id"] for n in ("q", "sort", "")}), 3)
        self.assertEqual(cases["object_id"].status, CellStatus.INCONCLUSIVE)
        self.assertFalse(cases["object_id"].attempts or cases["object_id"].executed)
        row = _row(report)
        self.assertTrue(row["fresh_sent"])
        self.assertFalse(row["conclusive"])

    def test_control_request_level_representative_with_pending_sibling_is_executed_but_incomplete(self):
        """Control: with no parameter case pending (a case budget of 0 leaves both
        inputs budget-skipped) sqlmap keeps its single request-level dispatch."""
        run = _Run(self.target)
        report = run.drive(build_coverage_cases_driven, _state(self.target.base, "/items/1?q=1&sort=a"),
                           per_cell_case_budget=0)
        matrix, parent = _cell(report)
        self.assertEqual(self.target.requests, 1)
        self.assertEqual(parent.status, CellStatus.PENDING)       # not endpoint-complete
        self.assertTrue(parent.executed)
        self.assertEqual(len(parent.attempts), 1)
        self.assertEqual(parent.attempts[0]["sent"], 1)
        cases = matrix.cases_for_cell("anonymous", ITEMS, CHECK)
        rep = [r for ck, r in cases if ck.is_no_parameter]
        siblings = [r for ck, r in cases if not ck.is_no_parameter]
        self.assertEqual(rep[0].attempts, parent.attempts)
        self.assertTrue(siblings and all(not s.attempts and not s.executed for s in siblings))
        row = _row(report)
        self.assertTrue(row["fresh_sent"])
        self.assertFalse(row["conclusive"])

    def test_executed_negative_beside_errored_sibling_is_not_a_clean_negative(self):
        run = _Run(self.target)
        state = _state(self.target.base, "/items/1?q=1&sort=a")
        tracker = CoverageTracker()
        endpoints = coverage_tracker.endpoint_view(state)
        tracker.build(endpoints, ["anonymous"], {"anonymous": "anonymous"})
        tracker.expand_parameter_cases(endpoints, driveable={"sqlmap"})

        async def go():
            async with run.ctx:
                await tracker.drive_coverage_cases(run.run_case, driveable={"sqlmap"})
        asyncio.run(go())
        sibling = next(ck for ck, _r in tracker.matrix.cases_for_cell("anonymous", ITEMS, CHECK)
                       if not ck.is_no_parameter)
        tracker.matrix.record_case("anonymous", ITEMS, CHECK, sibling,
                                   status=CellStatus.ERROR, reason="sibling errored")
        parent = tracker.matrix.get("anonymous", ITEMS, CHECK)
        self.assertNotIn(parent.status, {CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE})
        self.assertEqual(len(parent.attempts), 1)
        report = tracker.report()
        self.assertGreaterEqual(report["audited"]["not_a_clean_negative"]["total"], 0)
        self.assertEqual(report["audited"]["attempts"]["fresh"], 1)

    def test_cached_proof_reference_creates_zero_new_sends(self):
        state = _state(self.target.base, "/items/1?q=1")
        first = _Run(self.target)
        report = first.drive(build_coverage_driven, state)
        _m, original = _cell(report)
        self.assertEqual(self.target.requests, 1)
        (attempt,) = original.attempts
        # Same run, second dispatch of the same check: an ExecutionRegistry hit.
        again = _Run(self.target)
        again.ctx, again.cache = first.ctx, first.cache
        tracker = CoverageTracker()
        endpoints = coverage_tracker.endpoint_view(state)
        tracker.build(endpoints, ["anonymous"], {"anonymous": "anonymous"})
        asyncio.run(tracker.drive_coverage_legs(again.run_case, driveable={"sqlmap"}))
        hit = tracker.matrix.get("anonymous", ITEMS, CHECK)
        self.assertEqual(self.target.requests, 1)                  # no new send
        self.assertEqual(hit.attempts, ())
        self.assertEqual(hit.referenced_attempts, (attempt["id"],))
        # A later run resumed from the checkpoint references, never re-sends.
        resumed = _Run(self.target)
        report2 = resumed.drive(build_coverage_driven, state, checkpoint=report["checkpoint"],
                                context_key=report["checkpoint"]["context_key"])
        _m2, cell2 = _cell(report2)
        self.assertEqual(self.target.requests, 1)
        self.assertEqual(resumed.dispatched, 0)
        self.assertEqual(cell2.attempts, ())
        self.assertEqual(cell2.referenced_attempts, (attempt["id"],))
        row = _row(report2)
        self.assertFalse(row["fresh_sent"])
        self.assertTrue(row["referenced"] and row["resumed"] and row["conclusive"])

    def test_prior_detected_label_cannot_erase_an_actual_attempt(self):
        for label in ("detected", "confirmed"):
            with self.subTest(label=label):
                state = _state(self.target.base, "/items/1?q=1")
                state.endpoints[ITEMS].findings = [{
                    "vulnerability_class": "sql injection", "confirmed": label == "confirmed",
                    "summary": "agent label"}]
                report = build_coverage(state, ROLES, execution_events=[{
                    "identity": "anonymous", "endpoint_key": ITEMS, "check_id": CHECK,
                    "status": "not_detected", "confirmation": "sqlmap"}])
                _m, cell = _cell(report)
                self.assertEqual(cell.status.value, label)       # label kept, never downgraded
                self.assertTrue(cell.executed)
                self.assertEqual(len(cell.attempts), 1)
                self.assertTrue(_row(report)["fresh_sent"])

    def test_declined_check_creates_no_send(self):
        state = _state(self.target.base, "/items/1?q=1&sort=a")
        for builder in (build_coverage_driven, build_coverage_cases_driven):
            with self.subTest(builder=builder.__name__, decline="readiness"):
                run = _Run(self.target)
                report = run.drive(builder, state, readiness=lambda *a: {
                    "status": "policy_denied", "reason_code": "policy", "reason": "declined"})
                _m, cell = _cell(report)
                self.assertEqual((run.dispatched, self.target.requests), (0, 0))
                self.assertEqual(cell.attempts, ())
                self.assertFalse(_row(report)["fresh_sent"])
            with self.subTest(builder=builder.__name__, decline="no result"):
                run = _Run(self.target)

                async def declined(*args):
                    run.dispatched += 1
                    return None
                run.run_case = declined
                report = run.drive(builder, state)
                _m, cell = _cell(report)
                self.assertEqual(self.target.requests, 0)
                self.assertGreater(run.dispatched, 0)
                self.assertEqual((cell.attempts, cell.executed), ((), False))
                self.assertFalse(_row(report)["fresh_sent"])

    def test_export_coverage_and_ledger_agree(self):
        run = _Run(self.target)
        state = _state(self.target.base, "/items/1?q=1&sort=a", "/other/2?q=2")
        report = json.loads(json.dumps(run.drive(build_coverage_cases_driven, state)))
        self.assertEqual(report["attempt_schema_version"], 2)
        matrix = CoverageMatrix.from_dict(report["checkpoint"]["matrix"])
        ids = {a["id"] for c in matrix.cells().values() for a in c.attempts}
        sends = sum(a["sent"] for c in matrix.cells().values() for a in c.attempts)
        self.assertEqual(len(ids), 2)
        self.assertEqual(sends, self.target.requests)
        self.assertEqual(sends, run.ctx.budget.used)
        self.assertEqual(report["phase_ledger"]["counts"]["fresh_sent"], len(ids))
        self.assertEqual(report["audited"]["attempts"]["fresh"], len(ids))
        self.assertEqual(report["audited"]["attempts"]["fresh_sends"], sends)


class DriveVolumeFunnelTests(unittest.TestCase):
    """The funnel shows requests driven next to conclusive cells: a leg that sent
    but ended inconclusive is drive effort, never a conclusive answer."""

    def setUp(self):
        self.target = _Target()
        self.addCleanup(self.target.close)

    def _report(self, status):
        state = _state(self.target.base, "/items/1?q=1")
        run = _Run(self.target, status)
        return json.loads(json.dumps(run.drive(build_coverage_driven, state), default=str)), run

    def test_inconclusive_send_is_driven_but_not_conclusive(self):
        report, run = self._report("inconclusive")
        self.assertEqual(self.target.requests, 1)
        _m, cell = _cell(report)
        self.assertFalse(cell.executed)                    # still not counted as tested
        row = _row(report)
        self.assertEqual((row["fresh_sends"], row["conclusive"], row["sent"]), (1, False, False))
        drive = report["phase_ledger"]["drive"]
        self.assertEqual(drive["requests_driven"], run.ctx.budget.used)
        self.assertGreater(drive["requests_driven"], drive["conclusive"])
        self.assertEqual(drive["conclusive"], report["phase_ledger"]["counts"]["conclusive"])
        self.assertEqual(drive["driven_not_conclusive"], 1)
        self.assertIn("not a request count", drive["labels"]["sent"])
        self.assertEqual(report["audited"]["drive"],
                         {"requests_driven": 1, "conclusive": drive["conclusive"]})
        health = assessment_health(report)
        self.assertGreater(health["requests_driven"], health["conclusive"])

    def test_control_every_send_conclusive(self):
        report, run = self._report("not_confirmed")
        self.assertEqual(self.target.requests, 1)
        row = _row(report)
        self.assertEqual((row["fresh_sends"], row["conclusive"], row["sent"]), (1, True, True))
        drive = report["phase_ledger"]["drive"]
        self.assertEqual(drive["requests_driven"], run.ctx.budget.used)
        self.assertEqual(drive["driven_not_conclusive"], 0)
        self.assertEqual(drive["conclusive"], report["phase_ledger"]["counts"]["conclusive"])
        self.assertEqual(report["audited"]["drive"],
                         {"requests_driven": 1, "conclusive": drive["conclusive"]})


class EngagementExportAgreementTests(unittest.TestCase):
    """investigate_engagement itself: the API result's coverage, its phase ledger
    and the run's request budget agree on fresh versus referenced execution."""

    def test_worklist_reuse_is_referenced_not_resent_in_the_export(self):
        from harness import test_execution_registry as reg
        case = reg.EngagementCallerTests("test_the_coverage_drive_is_covered_by_the_worklist_run")
        case.setUp()
        self.addCleanup(case.tearDown)

        def drive_config(*, mutating):
            cfg = reg._config(mutating=mutating)
            cfg["engagement"]["coverage_drive_legs"] = True
            return cfg
        with unittest.mock.patch("harness.test_engagement_transport_callers._config", drive_config):
            result, rc, _model, launches, _target = case._investigate(
                [case._items("/api/items/1", "q=a"), case._items("/api/items/6", "q=b")])
        exported = json.loads(json.dumps(result["coverage"], default=str))
        self.assertEqual(exported["attempt_schema_version"], 2)
        matrix = CoverageMatrix.from_dict(exported["checkpoint"]["matrix"])
        cells = matrix.cells()
        fresh = {a["id"]: a for c in cells.values() for a in c.attempts}
        referenced = [k for k, c in cells.items() if c.referenced_attempts]
        ledger = exported["phase_ledger"]
        self.assertEqual(ledger["counts"]["fresh_sent"], sum(bool(c.attempts) for c in cells.values()))
        self.assertEqual(ledger["counts"]["referenced"], len(referenced))
        self.assertEqual(exported["audited"]["attempts"]["fresh"], len(fresh))
        self.assertLessEqual(sum(a["sent"] or 0 for a in fresh.values()), rc.budget.used)
        # The worklist's sqlmap run is reused by the drive: referenced, never a fresh send.
        self.assertEqual(len(launches.on("/api/items/")), 1)
        sqlmap_rows = [r for r in ledger["cells"] if r["confirmation"] == "sqlmap" and r["attempted"]]
        self.assertTrue(sqlmap_rows)
        for row in sqlmap_rows:
            self.assertTrue(row["referenced"], row)
            self.assertFalse(row["fresh_sent"], row)


class MalformedCompressionOutcomeTests(unittest.TestCase):
    """Batch 01 follow-up: undecodable responses end the three migrated validators
    with a visible incomplete outcome, never a clean negative."""

    def _serve(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.server.requests += 1
                self.send_response(200)
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", "8")
                self.end_headers()
                self.wfile.write(b"not gzip")
            do_POST = do_GET

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.requests = 0
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, f"http://127.0.0.1:{server.server_address[1]}/r"

    def test_each_validator_reports_the_failed_decode(self):
        from harness.validators.http_request_smuggling_validator import HttpRequestSmugglingValidator
        from harness.validators.recon_validator import ReconValidator
        from harness.validators.web_cache_poisoning_validator import WebCachePoisoningValidator
        for cls, vc in ((HttpRequestSmugglingValidator, "http request smuggling"),
                        (ReconValidator, "technology disclosure"),
                        (WebCachePoisoningValidator, "web_cache_poisoning")):
            with self.subTest(validator=cls.__name__):
                server, url = self._serve()
                exchange = HttpExchange(method="GET", url=url, request_headers={}, request_body="",
                                        response_status=200, response_headers={}, response_body="x")
                finding = Finding(vulnerability_class=vc, confidence=0.5, summary="c",
                                  evidence="", suggested_test="", basis="derived")

                async def go():
                    ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=40,
                                            gate_config={"active_enabled": True,
                                                         "allow_mutating_replay": True})
                    async with ctx:
                        return await cls(run_context=ctx, allowed_hosts=["127.0.0.1"]).validate(
                            finding, exchange)
                result = asyncio.run(go())
                self.assertGreater(server.requests, 0)
                self.assertEqual(result.status, "inconclusive", result.summary)
                self.assertFalse(result.confirmed)
                self.assertIn("not a negative result", result.summary)


class LegacyReadTests(unittest.TestCase):
    def test_legacy_executed_cell_reads_without_attempt_facts(self):
        legacy = {"cells": {f"anonymous|GET /x|{CHECK}": {"status": "not_detected", "reason": "",
                                                         "executed": True}}}
        cell = CoverageMatrix.from_dict(legacy).get("anonymous", "GET /x", CHECK)
        self.assertTrue(cell.executed)
        self.assertEqual((cell.attempts, cell.referenced_attempts), ((), ()))
        self.assertNotIn("attempt_schema_version", CoverageMatrix.from_dict(legacy).to_dict())

    def test_legacy_checkpoint_resume_references_without_inventing_an_attempt(self):
        target = _Target()
        self.addCleanup(target.close)
        state = _state(target.base, "/items/1?q=1")
        tracker = CoverageTracker()
        tracker.build(coverage_tracker.endpoint_view(state), ["anonymous"], {"anonymous": "anonymous"})
        tracker.restore_checkpoint(None, "")
        legacy = {"signature": tracker.checkpoint_signature, "context_key": "", "matrix": {
            "cells": {f"anonymous|{ITEMS}|{CHECK}": {"status": "not_detected", "reason": "old",
                                                       "executed": True}}}}
        report = _Run(target).drive(build_coverage_driven, state, checkpoint=legacy)
        _m, cell = _cell(report)
        self.assertEqual(target.requests, 0)
        self.assertEqual(cell.attempts, ())
        self.assertEqual(cell.referenced_attempts, ("checkpoint:legacy",))


if __name__ == "__main__":
    unittest.main()
