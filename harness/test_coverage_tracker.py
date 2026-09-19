"""Tests for coverage_tracker: turning a finished engagement into the auditable
identity × endpoint × check matrix (I1/I2/I5)."""
import unittest

from harness import engagement
from harness.coverage_tracker import CoverageTracker, build_coverage, endpoint_view
from harness.coverage_model import CellStatus


class ClassMappingTests(unittest.TestCase):
    def setUp(self):
        self.t = CoverageTracker()

    def test_maps_canonical_and_freetext_classes(self):
        self.assertIn("WSTG-INPV-05", self.t.checks_for_class("sqli"))
        self.assertIn("WSTG-INPV-05", self.t.checks_for_class("SQL Injection"))
        # free-text access-control the canonicaliser returns None for
        self.assertIn("WSTG-ATHZ-04", self.t.checks_for_class("IDOR/BOLA"))
        self.assertTrue(self.t.checks_for_class("Broken Function-Level Authorization"))
        # mass assignment -> api_security check (internal id; WSTG-CONF-09 is a
        # different requirement -- "Test File Permission")
        self.assertIn("AV-MASSASSIGN-01", self.t.checks_for_class("mass_assignment"))

    def test_unknown_class_maps_to_nothing(self):
        self.assertEqual(self.t.checks_for_class("totally-made-up-class"), [])


def _state_with(endpoints):
    st = engagement.EngagementState(host="t.test")
    for method, path, kw in endpoints:
        ep = st._ep(method, path)
        ep.reachable_roles = kw.get("reachable_roles", [])
        ep.object_scoped = kw.get("object_scoped", "{id}" in path)
        for f in kw.get("findings", []):
            ep.add_finding(f)
    return st


class BuildTests(unittest.TestCase):
    def test_applicability_and_reachability(self):
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        counts = t.build(eps, ["anonymous", "user", "admin"])
        # object-scoped -> IDOR check applicable
        cell = t.matrix.get("user", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(cell.status, CellStatus.PENDING)
        # anonymous never reached it -> skipped with a reachability reason
        cell_anon = t.matrix.get("anonymous", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(cell_anon.status, CellStatus.SKIPPED)
        self.assertIn("did not reach", cell_anon.reason)
        self.assertGreater(counts["not_applicable"], 0)

    def test_confirmed_finding_recorded(self):
        st = _state_with([
            ("GET", "/api/tickets/{id}", {
                "reachable_roles": ["user", "admin"],
                "findings": [{"vulnerability_class": "idor", "confirmed": True,
                              "confirmed_by_leg": "cross_identity",
                              "severity": "high", "confidence": 0.9}]}),
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user", "admin"])
        t.record_findings_from_state(eps, ["user", "admin"])
        # attributed to the lowest-trust reacher (user)
        cell = t.matrix.get("user", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(cell.status, CellStatus.CONFIRMED)
        self.assertEqual(cell.severity, "high")

    def test_detected_but_unconfirmed_recorded(self):
        st = _state_with([
            ("GET", "/api/admin/users", {
                "reachable_roles": ["user"],
                "findings": [{"vulnerability_class": "Broken Function-Level Authorization",
                              "confirmed": False, "severity": "medium", "confidence": 0.5}]}),
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.record_findings_from_state(eps, ["user"])
        cell = t.matrix.get("user", "GET /api/admin/users", "WSTG-ATHZ-02")
        self.assertEqual(cell.status, CellStatus.DETECTED)

    def test_reviewer_repro_report_audited_distinguishes_executed_from_attributed(self):
        """R01/R07: CoverageTracker.report()["audited"] is coverage_summary.py's
        real production consumer -- an agent-attributed CONFIRMED (no leg ran)
        counts as inferred there, while a real recorded leg execution counts
        as executed, even though both show CONFIRMED in the coarser top-level
        matrix summary."""
        st = _state_with([
            ("GET", "/api/tickets/{id}", {
                "reachable_roles": ["user"],
                "findings": [{"vulnerability_class": "idor", "confirmed": True,
                              "severity": "high", "confidence": 0.9}]}),
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.record_findings_from_state(eps, ["user"])
        audited = t.report()["audited"]
        self.assertGreaterEqual(audited["inferred"]["numerator"], 1)
        self.assertEqual(audited["executed"]["numerator"], 0)

    def test_execution_event_marks_not_detected(self):
        """A REAL recorded leg execution with a not_detected outcome marks the
        cell not_detected (R01: only actual executions, never inference)."""
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.record_execution_events([{
            "identity": "user", "endpoint_key": "GET /api/tickets/{id}",
            "confirmation": "cross_identity", "status": "not_detected"}])
        cell = t.matrix.get("user", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(cell.status, CellStatus.NOT_DETECTED)

    def test_execution_event_can_confirm(self):
        st = _state_with([("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]})])
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.record_execution_events([{
            "identity": "user", "endpoint_key": "GET /api/tickets/{id}",
            "check_id": "WSTG-ATHZ-04", "status": "confirmed", "evidence": "cross-id 200"}])
        cell = t.matrix.get("user", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(cell.status, CellStatus.CONFIRMED)

    def test_no_execution_events_never_invents_not_detected(self):
        """R01 NEGATIVE CONTROL: an endpoint the worklist investigated, with NO
        recorded leg execution, must NOT be marked not_detected. It is skipped
        with an explicit "attempt not tracked" reason -- never inferred as tested."""
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),
        ])
        report = build_coverage(st, [type("R", (), {"role": "user"})()],
                                investigated_keys={"GET /api/tickets/{id}"})
        # no cell may be not_detected -- nothing actually ran
        self.assertEqual(report.get("not_detected", 0), 0)
        # the applicable leg cells are skipped, and the reason says WHY (not tested)
        skipped_reasons = [nt["reason"] for nt in report["not_tested"]
                           if nt["status"] == "skipped"]
        self.assertTrue(any("attempt not tracked" in r for r in skipped_reasons))

    def test_summary_excludes_skipped_and_error_from_tested(self):
        """R02: skipped/error/pending/running never count as tested/attempted."""
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),
            ("POST", "/api/search", {"reachable_roles": ["user"]}),
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.record_execution_events([
            {"identity": "user", "endpoint_key": "GET /api/tickets/{id}",
             "check_id": "WSTG-ATHZ-04", "status": "not_detected"},
            {"identity": "user", "endpoint_key": "POST /api/search",
             "check_id": "WSTG-INPV-05", "status": "error"},
        ])
        t.finalize_pending_reasons(investigated_keys={"GET /api/tickets/{id}", "POST /api/search"})
        s = t.matrix.summary()
        # one real verdict (not_detected) -> conclusive/tested == 1
        self.assertEqual(s["conclusive"], 1)
        self.assertEqual(s["tested"], 1)
        # attempted counts the errored execution too, but NOT skipped/pending
        self.assertEqual(s["attempted"], 2)
        self.assertGreater(s["skipped"], 0)
        self.assertEqual(s["error"], 1)
        # tested must never include skipped
        self.assertLess(s["tested"], s["skipped"] + s["tested"])

    def test_not_tested_has_reasons(self):
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),
        ])
        report = build_coverage(st, [type("R", (), {"role": "user"})()],
                                investigated_keys=set())
        # every not-tested cell must carry a reason (the I5 audit guarantee)
        self.assertTrue(report["not_tested"])
        self.assertTrue(all(nt["reason"] for nt in report["not_tested"]))
        # summary keys present
        for k in ("total_cells", "confirmed", "detected", "not_applicable"):
            self.assertIn(k, report)


class DriveLegsTests(unittest.TestCase):
    """The I1 matrix-DRIVER: fire every applicable leg-backed cell regardless of
    an agent label, recording the real leg outcome."""

    def _tracker(self):
        import asyncio
        from harness.coverage_tracker import CoverageTracker, endpoint_view
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),   # idor -> cross_identity
            ("POST", "/api/search", {"reachable_roles": ["user"]}),         # body-bearing -> sqli/xss/...
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        return t, asyncio

    def test_pending_leg_cells_are_applicable_and_leg_backed(self):
        t, _ = self._tracker()
        cells = t.pending_leg_cells()
        # every returned cell must be PENDING + have a deterministic-leg check
        from harness.coverage_model import CHECKS_BY_ID
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        self.assertTrue(cells)
        for ident, ep_key, check in cells:
            self.assertIn(check.confirmation, _LEG_CONFIRMATIONS)
        # the object-scoped endpoint's IDOR/cross_identity cell is in there
        self.assertTrue(any(c.id == "WSTG-ATHZ-04" for _, _, c in cells))

    def test_driver_records_confirmed_and_not_detected(self):
        t, asyncio = self._tracker()

        class _Res:
            def __init__(self, status): self.status = status; self.summary = "x"; self.confidence = 0.9; self.evidence = "e"; self.validator = "v"

        async def run_leg(identity, method, path, check):
            # confirm the IDOR cell, everything else not_confirmed
            if check.id == "WSTG-ATHZ-04":
                return _Res("confirmed")
            return _Res("not_confirmed")

        driven = asyncio.run(t.drive_coverage_legs(run_leg, budget=100))
        self.assertGreater(driven, 0)
        from harness.coverage_model import CellStatus
        idor_cell = t.matrix.get("user", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(idor_cell.status, CellStatus.CONFIRMED)
        # a driven-but-not-confirmed leg cell is NOT_DETECTED (attempted), not pending
        sqli_cell = t.matrix.get("user", "POST /api/search", "WSTG-INPV-05")
        self.assertEqual(sqli_cell.status, CellStatus.NOT_DETECTED)

    def test_driver_respects_budget(self):
        t, asyncio = self._tracker()
        calls = {"n": 0}

        class _Res:
            status = "not_confirmed"; summary = ""; confidence = None; evidence = ""; validator = "v"

        async def run_leg(identity, method, path, check):
            calls["n"] += 1
            return _Res()

        asyncio.run(t.drive_coverage_legs(run_leg, budget=2))
        self.assertEqual(calls["n"], 2)

    def test_build_coverage_driven_reports_legs_driven(self):
        import asyncio
        from harness.coverage_tracker import build_coverage_driven

        class _Res:
            status = "not_confirmed"; summary = ""; confidence = None; evidence = ""; validator = "v"

        async def run_leg(identity, method, path, check):
            return _Res()

        st = _state_with([("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]})])
        report = asyncio.run(build_coverage_driven(
            st, [type("R", (), {"role": "user"})()], run_leg, budget=50))
        self.assertIn("legs_driven", report)
        self.assertGreaterEqual(report["legs_driven"], 1)
        self.assertTrue(all(nt.get("reason") for nt in report["not_tested"]))


class PrincipalIdentityTests(unittest.TestCase):
    """R02: two same-role principals + anonymous stay THREE distinct coverage
    identities -- role no longer collapses Alice and Bob into one column."""

    def test_same_role_principals_are_distinct_identities(self):
        from harness.role_crawl import RoleSession
        from harness.coverage_tracker import _identities_of
        roles = [RoleSession("user", {"Authorization": "Bearer A"}, name="alice"),
                 RoleSession("user", {"Authorization": "Bearer B"}, name="bob"),
                 RoleSession("anonymous", {})]
        identities, identity_roles = _identities_of(roles)
        self.assertEqual(set(identities), {"alice", "bob", "anonymous"})
        self.assertEqual(identity_roles["alice"], "user")
        self.assertEqual(identity_roles["bob"], "user")

    def test_matrix_keeps_same_role_principals_separate(self):
        from harness.role_crawl import RoleSession
        st = _state_with([("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]})])
        t = CoverageTracker()
        eps = endpoint_view(st)
        from harness.coverage_tracker import _identities_of
        identities, identity_roles = _identities_of([
            RoleSession("user", {"Authorization": "Bearer A"}, name="alice"),
            RoleSession("user", {"Authorization": "Bearer B"}, name="bob"),
            RoleSession("anonymous", {})])
        t.build(eps, identities, identity_roles)
        # alice and bob each get their own IDOR cell (both reach as role user) ...
        self.assertEqual(t.matrix.get("alice", "GET /api/tickets/{id}", "WSTG-ATHZ-04").status,
                         CellStatus.PENDING)
        self.assertEqual(t.matrix.get("bob", "GET /api/tickets/{id}", "WSTG-ATHZ-04").status,
                         CellStatus.PENDING)
        # ... and are independent: confirming alice's does not touch bob's
        t.matrix.record("alice", "GET /api/tickets/{id}", "WSTG-ATHZ-04",
                        status=CellStatus.CONFIRMED, reason="alice only")
        self.assertEqual(t.matrix.get("bob", "GET /api/tickets/{id}", "WSTG-ATHZ-04").status,
                         CellStatus.PENDING)
        # anonymous never reached (role not in reachable_roles) -> skipped
        self.assertEqual(t.matrix.get("anonymous", "GET /api/tickets/{id}", "WSTG-ATHZ-04").status,
                         CellStatus.SKIPPED)


class CasesDrivenTests(unittest.TestCase):
    """T05: case-granular driving -- fan a parameter leg out over the endpoint's
    real inputs, drive per case, and keep un-run siblings honestly pending."""

    def _state(self):
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),  # IDOR (endpoint phase)
            ("POST", "/api/search", {"reachable_roles": ["user"]}),        # SQLi/XSS (parameter phase)
        ])
        # attach a captured template carrying two distinct query inputs
        st.endpoints["POST /api/search"].template = {
            "method": "POST", "query": "search=x&sort=y", "body": "",
            "content_type": "", "object_id": None}
        return st

    def test_expand_parameter_cases_fans_out_over_inputs(self):
        st = self._state()
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.expand_parameter_cases(eps, per_cell_budget=8)
        # SQLi (parameter phase) -> a request-level representative + one case per input
        sqli_cases = t.matrix.cases_for_cell("user", "POST /api/search", "WSTG-INPV-05")
        param_names = sorted(ck.parameter_name for ck, _ in sqli_cases if not ck.is_no_parameter)
        self.assertEqual(param_names, ["search", "sort"])
        self.assertTrue(any(ck.is_no_parameter for ck, _ in sqli_cases))  # the representative
        # IDOR (endpoint phase) -> a single explicit no-parameter case
        idor_cases = t.matrix.cases_for_cell("user", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(len(idor_cases), 1)
        self.assertTrue(idor_cases[0][0].is_no_parameter)

    def test_request_level_confirm_does_not_credit_parameter_siblings(self):
        # R01: a whole-request confirm marks the cell as RISK (via the request-level
        # case), but the enumerated parameter inputs are NOT credited with it -- they
        # stay inconclusive (untested), never inheriting the verdict.
        import asyncio
        st = self._state()
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.expand_parameter_cases(eps, per_cell_budget=8)

        class _Res:
            def __init__(self, s): self.status = s; self.summary = "x"; self.confidence = 0.9; self.evidence = "e"; self.validator = "v"

        async def run_case(identity, method, path, check, case_key):
            # a request-level confirm on the SQLi cell (the driver only calls the
            # no-parameter representative); no per-parameter attribution
            if check.id == "WSTG-INPV-05":
                self.assertTrue(case_key.is_no_parameter)   # driven at request level
                return _Res("confirmed")
            return None

        asyncio.run(t.drive_coverage_cases(run_case, budget=100))
        # the cell shows endpoint RISK ...
        self.assertEqual(t.matrix.get("user", "POST /api/search", "WSTG-INPV-05").status,
                         CellStatus.CONFIRMED)
        # ... but neither parameter input is confirmed; both stay inconclusive (untested)
        cases = {ck.parameter_name: r for ck, r in
                 t.matrix.cases_for_cell("user", "POST /api/search", "WSTG-INPV-05")}
        self.assertEqual(cases["search"].status, CellStatus.INCONCLUSIVE)
        self.assertEqual(cases["sort"].status, CellStatus.INCONCLUSIVE)
        nt_params = {c["parameter_name"] for c in t.matrix.cases_not_tested()}
        self.assertIn("search", nt_params)
        self.assertIn("sort", nt_params)

    def test_build_coverage_cases_driven_reports_pending_honestly(self):
        import asyncio
        from harness.coverage_tracker import build_coverage_cases_driven
        st = self._state()

        class _Res:
            status = "not_confirmed"; summary = ""; confidence = None; evidence = ""; validator = "v"

        async def run_case(identity, method, path, check, case_key):
            # a not_confirmed request-level result on the SQLi cell only
            if check.id == "WSTG-INPV-05":
                return _Res()
            return None

        report = asyncio.run(build_coverage_cases_driven(
            st, [type("R", (), {"role": "user"})()], run_case, budget=100))
        self.assertIn("cases_enumerated", report)
        self.assertIn("cases_driven", report)
        self.assertGreaterEqual(report["cases_enumerated"], 2)
        # cases_driven counts DISPATCH ATTEMPTS (R05), one per driven cell.
        self.assertGreaterEqual(report["cases_driven"], 1)
        # every not-tested case carries a reason (I5 at case granularity)
        self.assertTrue(all(c.get("reason") for c in report["cases_not_tested"]))
        # The SQLi leg ran at REQUEST LEVEL (not_confirmed) -> the concrete parameter
        # inputs 'search'/'sort' were NOT individually attributed, so they stay in the
        # honest not-tested list; the request-level result is not itself a gap.
        nt = {(c["endpoint"], c["check"], c["parameter_name"]) for c in report["cases_not_tested"]}
        self.assertIn(("POST /api/search", "WSTG-INPV-05", "search"), nt)
        self.assertIn(("POST /api/search", "WSTG-INPV-05", "sort"), nt)

    def test_failing_callback_is_recorded_as_error_and_consumes_budget(self):
        # R05: a raising callback must be recorded ERROR (visible) and the budget must
        # bound DISPATCH ATTEMPTS -- budget=1 permits exactly one attempt.
        import asyncio
        st = self._state()
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.expand_parameter_cases(eps, per_cell_budget=8)
        calls = {"n": 0}

        async def failing(identity, method, path, check, case_key):
            calls["n"] += 1
            raise RuntimeError("synthetic operational failure")

        attempts = asyncio.run(t.drive_coverage_cases(failing, budget=1))
        self.assertEqual(attempts, 1)
        self.assertEqual(calls["n"], 1)                       # budget bounded the calls
        self.assertEqual(t.matrix.case_summary()["error"], 1)  # the failure is visible

    def test_none_result_is_inconclusive_not_silent(self):
        # R05: a callback that returns None is recorded INCONCLUSIVE (dispatched, no
        # usable send) -- distinct from an untested case, never silently dropped.
        import asyncio
        st = self._state()
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.expand_parameter_cases(eps, per_cell_budget=8)

        async def declines(identity, method, path, check, case_key):
            return None

        asyncio.run(t.drive_coverage_cases(declines, budget=100))
        cs = t.matrix.case_summary()
        self.assertGreater(cs["inconclusive"], 0)
        self.assertEqual(cs["not_detected"], 0)   # None never becomes an optimistic negative

    def test_per_cell_budget_bounds_fanout(self):
        st = _state_with([("POST", "/api/x", {"reachable_roles": ["user"]})])
        st.endpoints["POST /api/x"].template = {
            "method": "POST", "query": "a=1&b=2&c=3&d=4", "body": "",
            "content_type": "", "object_id": None}
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.expand_parameter_cases(eps, per_cell_budget=2)
        cases = t.matrix.cases_for_cell("user", "POST /api/x", "WSTG-INPV-05")
        # parameter inputs are budgeted (2 of 4 pending, 2 budget-skipped); the
        # request-level representative is always present on top.
        param_pending = [r for ck, r in cases if not ck.is_no_parameter and r.status == CellStatus.PENDING]
        param_skipped = [r for ck, r in cases if not ck.is_no_parameter and r.status == CellStatus.SKIPPED]
        self.assertEqual(len(param_pending), 2)
        self.assertEqual(len(param_skipped), 2)
        self.assertTrue(any(ck.is_no_parameter for ck, _ in cases))  # representative kept


if __name__ == "__main__":
    unittest.main()
