"""Tests for coverage_model — the WSTG/Academy check catalog + coverage matrix."""
import unittest

from harness.coverage_model import (
    Check, Phase, CellStatus, CellResult, CoverageMatrix,
    CHECK_CATALOG, CHECKS_BY_ID, CHECKS_BY_PHASE,
    _has_params, _accepts_input, _is_object_scoped, _accepts_xml,
    _has_url_param, _has_auth_endpoint, _has_file_path_segment,
    _always_applicable, _is_authed, _has_cookie_or_session, _accepts_body,
)


# ---- Catalog integrity ----

class CatalogTests(unittest.TestCase):
    def test_all_checks_have_unique_ids(self):
        ids = [c.id for c in CHECK_CATALOG]
        self.assertEqual(len(ids), len(set(ids)), f"duplicate ids: {[x for x in ids if ids.count(x) > 1]}")

    def test_all_checks_have_required_fields(self):
        for c in CHECK_CATALOG:
            self.assertTrue(c.id, f"check missing id: {c}")
            self.assertTrue(c.name, f"check {c.id} missing name")
            self.assertIn(c.phase, Phase, f"check {c.id} has invalid phase")
            self.assertTrue(c.vulnerability_class, f"check {c.id} missing vulnerability_class")
            self.assertTrue(c.confirmation, f"check {c.id} missing confirmation")

    def test_all_checks_in_by_id_index(self):
        for c in CHECK_CATALOG:
            self.assertIs(CHECKS_BY_ID[c.id], c)

    def test_all_phases_have_checks(self):
        for phase in Phase:
            self.assertTrue(CHECKS_BY_PHASE.get(phase), f"no checks in phase {phase}")

    def test_canonical_class_resolves(self):
        for c in CHECK_CATALOG:
            canon = c.canonical_class()
            self.assertIsNotNone(canon, f"check {c.id} vulnerability_class "
                                        f"{c.vulnerability_class!r} does not canonicalize")

    def test_check_count_minimum(self):
        self.assertGreaterEqual(len(CHECK_CATALOG), 25)


# ---- Applicability predicates ----

class PredicateTests(unittest.TestCase):
    def _ep(self, **kw):
        base = {"path": "/api/test", "methods": ("GET",), "access": {},
                "reachable_roles": [], "object_scoped": False}
        base.update(kw)
        return base

    def test_has_params_query(self):
        ok, _ = _has_params(self._ep(path="/api/search?q=x"))
        self.assertTrue(ok)

    def test_has_params_template(self):
        ok, _ = _has_params(self._ep(path="/api/tickets/{id}"))
        self.assertTrue(ok)

    def test_has_params_numeric_segment(self):
        ok, _ = _has_params(self._ep(path="/api/tickets/42"))
        self.assertTrue(ok)

    def test_has_params_body_method(self):
        ok, _ = _has_params(self._ep(methods=("POST",)))
        self.assertTrue(ok)

    def test_has_params_plain_get(self):
        ok, _ = _has_params(self._ep(path="/api/health"))
        self.assertFalse(ok)

    def test_is_object_scoped_flag(self):
        ok, _ = _is_object_scoped(self._ep(object_scoped=True))
        self.assertTrue(ok)

    def test_is_object_scoped_path(self):
        ok, _ = _is_object_scoped(self._ep(path="/api/tickets/42"))
        self.assertTrue(ok)

    def test_is_object_scoped_no(self):
        ok, _ = _is_object_scoped(self._ep(path="/api/tickets"))
        self.assertFalse(ok)

    def test_accepts_xml(self):
        ok, _ = _accepts_xml(self._ep(path="/api/tickets/import", methods=("POST",)))
        self.assertTrue(ok)

    def test_accepts_xml_no(self):
        ok, _ = _accepts_xml(self._ep(path="/api/tickets", methods=("GET",)))
        self.assertFalse(ok)

    def test_has_url_param_redirect(self):
        ok, _ = _has_url_param(self._ep(path="/api/redirect"))
        self.assertTrue(ok)

    def test_has_url_param_no(self):
        ok, _ = _has_url_param(self._ep(path="/api/health"))
        self.assertFalse(ok)

    def test_has_auth_endpoint(self):
        ok, _ = _has_auth_endpoint(self._ep(path="/api/login"))
        self.assertTrue(ok)

    def test_has_auth_endpoint_no(self):
        ok, _ = _has_auth_endpoint(self._ep(path="/api/tickets"))
        self.assertFalse(ok)

    def test_has_file_path_segment(self):
        ok, _ = _has_file_path_segment(self._ep(path="/uploads/42"))
        self.assertTrue(ok)

    def test_has_file_path_segment_no(self):
        ok, _ = _has_file_path_segment(self._ep(path="/api/users"))
        self.assertFalse(ok)

    def test_always_applicable(self):
        ok, _ = _always_applicable(self._ep())
        self.assertTrue(ok)

    def test_is_authed(self):
        ok, _ = _is_authed(self._ep(access={"admin": 200}))
        self.assertTrue(ok)

    def test_is_authed_no(self):
        ok, _ = _is_authed(self._ep())
        self.assertFalse(ok)

    def test_accepts_body(self):
        ok, _ = _accepts_body(self._ep(methods=("POST", "GET")))
        self.assertTrue(ok)

    def test_accepts_body_no(self):
        ok, _ = _accepts_body(self._ep(methods=("GET",)))
        self.assertFalse(ok)


# ---- CellResult ----

class CellResultTests(unittest.TestCase):
    def test_not_applicable_factory(self):
        r = CellResult.not_applicable("no params")
        self.assertEqual(r.status, CellStatus.NOT_APPLICABLE)
        self.assertEqual(r.reason, "no params")

    def test_round_trip(self):
        r = CellResult(status=CellStatus.CONFIRMED, reason="sqlmap confirmed",
                       severity="high", confidence=0.95, validator="sqlmap",
                       evidence="payload: ' OR 1=1")
        d = r.to_dict()
        r2 = CellResult.from_dict(d)
        self.assertEqual(r2.status, CellStatus.CONFIRMED)
        self.assertEqual(r2.severity, "high")
        self.assertAlmostEqual(r2.confidence, 0.95)
        self.assertEqual(r2.validator, "sqlmap")

    def test_to_dict_minimal(self):
        r = CellResult()
        d = r.to_dict()
        self.assertEqual(d["status"], "pending")
        self.assertNotIn("severity", d)


# ---- CoverageMatrix ----

class MatrixTests(unittest.TestCase):
    def _endpoints(self):
        return {
            "GET /api/tickets/{id}": {
                "path": "/api/tickets/{id}", "methods": ("GET",),
                "access": {"user": 200}, "reachable_roles": ["user"],
                "object_scoped": True,
            },
            "POST /api/login": {
                "path": "/api/login", "methods": ("POST",),
                "access": {}, "reachable_roles": [],
                "object_scoped": False,
            },
            "GET /api/health": {
                "path": "/api/health", "methods": ("GET",),
                "access": {}, "reachable_roles": [],
                "object_scoped": False,
            },
        }

    def test_fill_applicability(self):
        m = CoverageMatrix()
        eps = self._endpoints()
        identities = ["anonymous", "user"]
        na = m.fill_applicability(identities, eps)
        self.assertGreater(na, 0)
        total = len(m.cells())
        self.assertEqual(total, len(identities) * len(eps) * len(CHECK_CATALOG))

    def test_not_applicable_cells_have_reasons(self):
        m = CoverageMatrix()
        eps = self._endpoints()
        m.fill_applicability(["user"], eps)
        for key, cell in m.cells().items():
            if cell.status == CellStatus.NOT_APPLICABLE:
                self.assertTrue(cell.reason, f"NA cell {key} has no reason")

    def test_pending_cells_have_reasons(self):
        m = CoverageMatrix()
        eps = self._endpoints()
        m.fill_applicability(["user"], eps)
        for key, cell in m.cells().items():
            if cell.status == CellStatus.PENDING:
                self.assertTrue(cell.reason, f"pending cell {key} has no reason")

    def test_object_scoped_idor_applicable(self):
        m = CoverageMatrix()
        eps = self._endpoints()
        m.fill_applicability(["user"], eps)
        idor_cell = m.get("user", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertIsNotNone(idor_cell)
        self.assertEqual(idor_cell.status, CellStatus.PENDING)

    def test_non_object_scoped_idor_not_applicable(self):
        m = CoverageMatrix()
        eps = self._endpoints()
        m.fill_applicability(["user"], eps)
        idor_cell = m.get("user", "GET /api/health", "WSTG-ATHZ-04")
        self.assertIsNotNone(idor_cell)
        self.assertEqual(idor_cell.status, CellStatus.NOT_APPLICABLE)

    def test_sqli_applicable_on_login(self):
        m = CoverageMatrix()
        eps = self._endpoints()
        m.fill_applicability(["user"], eps)
        sqli_cell = m.get("user", "POST /api/login", "WSTG-INPV-05")
        self.assertIsNotNone(sqli_cell)
        self.assertEqual(sqli_cell.status, CellStatus.PENDING)

    def test_record_confirmed(self):
        m = CoverageMatrix()
        m.record("user", "POST /api/login", "WSTG-INPV-05",
                 status=CellStatus.CONFIRMED, reason="sqlmap confirmed",
                 severity="high", confidence=0.99, validator="sqlmap")
        cell = m.get("user", "POST /api/login", "WSTG-INPV-05")
        self.assertEqual(cell.status, CellStatus.CONFIRMED)

    def test_confirmed_not_overwritten(self):
        m = CoverageMatrix()
        m.record("user", "POST /api/login", "WSTG-INPV-05",
                 status=CellStatus.CONFIRMED, reason="proven")
        m.record("user", "POST /api/login", "WSTG-INPV-05",
                 status=CellStatus.NOT_DETECTED, reason="retry")
        cell = m.get("user", "POST /api/login", "WSTG-INPV-05")
        self.assertEqual(cell.status, CellStatus.CONFIRMED)
        self.assertEqual(cell.reason, "proven")

    def test_summary(self):
        m = CoverageMatrix()
        m.fill_applicability(["user"], self._endpoints())
        m.record("user", "POST /api/login", "WSTG-INPV-05",
                 status=CellStatus.CONFIRMED, reason="test")
        s = m.summary()
        self.assertGreater(s["total_cells"], 0)
        self.assertEqual(s["confirmed"], 1)
        self.assertGreater(s["not_applicable"], 0)
        self.assertIn("by_phase", s)
        self.assertIn("by_check", s)

    def test_not_tested(self):
        m = CoverageMatrix()
        m.fill_applicability(["user"], self._endpoints())
        nt = m.not_tested()
        self.assertGreater(len(nt), 0)
        for item in nt:
            self.assertIn(item["status"], ("not_applicable", "skipped"))
            self.assertTrue(item["reason"])

    def test_for_endpoint(self):
        m = CoverageMatrix()
        m.fill_applicability(["user", "admin"], self._endpoints())
        ep_cells = m.for_endpoint("POST /api/login")
        self.assertGreater(len(ep_cells), 0)
        for (identity, check_id), cell in ep_cells.items():
            self.assertIn(identity, ("user", "admin"))

    def test_for_identity(self):
        m = CoverageMatrix()
        m.fill_applicability(["user"], self._endpoints())
        id_cells = m.for_identity("user")
        self.assertEqual(len(id_cells), len(self._endpoints()) * len(CHECK_CATALOG))

    def test_for_check(self):
        m = CoverageMatrix()
        m.fill_applicability(["user"], self._endpoints())
        chk_cells = m.for_check("WSTG-INPV-05")
        self.assertEqual(len(chk_cells), len(self._endpoints()))

    def test_round_trip(self):
        m = CoverageMatrix()
        m.fill_applicability(["user"], self._endpoints())
        m.record("user", "POST /api/login", "WSTG-INPV-05",
                 status=CellStatus.CONFIRMED, reason="test", severity="high")
        d = m.to_dict()
        m2 = CoverageMatrix.from_dict(d)
        cell = m2.get("user", "POST /api/login", "WSTG-INPV-05")
        self.assertEqual(cell.status, CellStatus.CONFIRMED)
        self.assertEqual(len(m2.cells()), len(m.cells()))

    def test_fill_does_not_overwrite_existing(self):
        m = CoverageMatrix()
        m.record("user", "POST /api/login", "WSTG-INPV-05",
                 status=CellStatus.CONFIRMED, reason="prior")
        m.fill_applicability(["user"], self._endpoints())
        cell = m.get("user", "POST /api/login", "WSTG-INPV-05")
        self.assertEqual(cell.status, CellStatus.CONFIRMED)


# ---- Negative controls ----

class NegativeControlTests(unittest.TestCase):
    """The coverage matrix must never invent findings or inflate coverage."""

    def test_empty_matrix_summary(self):
        m = CoverageMatrix()
        s = m.summary()
        self.assertEqual(s["total_cells"], 0)
        self.assertEqual(s["confirmed"], 0)

    def test_no_endpoints_no_cells(self):
        m = CoverageMatrix()
        na = m.fill_applicability(["user"], {})
        self.assertEqual(na, 0)
        self.assertEqual(len(m.cells()), 0)

    def test_no_identities_no_cells(self):
        m = CoverageMatrix()
        na = m.fill_applicability([], {"GET /x": {"path": "/x", "methods": ("GET",),
                                                   "access": {}, "reachable_roles": [],
                                                   "object_scoped": False}})
        self.assertEqual(na, 0)
        self.assertEqual(len(m.cells()), 0)

    def test_not_tested_lists_only_na_and_skipped(self):
        m = CoverageMatrix()
        m.fill_applicability(["user"], {"GET /x": {"path": "/x", "methods": ("GET",),
                                                    "access": {}, "reachable_roles": [],
                                                    "object_scoped": False}})
        m.record("user", "GET /x", "WSTG-INPV-05",
                 status=CellStatus.CONFIRMED, reason="proven")
        for item in m.not_tested():
            self.assertIn(item["status"], ("not_applicable", "skipped"))

    def test_predicate_reasons_are_never_empty(self):
        ep = {"path": "/api/test", "methods": ("GET",), "access": {},
              "reachable_roles": [], "object_scoped": False}
        for check in CHECK_CATALOG:
            _, reason = check.applies(ep)
            self.assertTrue(reason, f"check {check.id} returned empty reason")


if __name__ == "__main__":
    unittest.main()
