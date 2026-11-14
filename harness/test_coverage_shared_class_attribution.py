"""WG-2 open items (3) and (4): shared-class coverage attribution and driving.

Several catalog rows share one canonical class (five rows are ``auth``). Before this
change ``CoverageTracker.record_findings`` stamped a finding's status on EVERY row of
its class, so one confirmed ``auth`` finding confirmed enumeration, MFA, password
policy, bypass and session management at once, and ``idor`` also filled ATHZ-02.
The coverage driver handed shared rows their bare class, which auth_sequence routes
to no check.

These tests drive the real tracker (build + record_findings_from_state over an
endpoint view of slim findings) and the real driver seam, with a bare-class negative
control and a pure guard over the catalog's ``specific_classes``.
"""
import asyncio
import dataclasses
import unittest
from types import SimpleNamespace

from harness import engagement
from harness.coverage_model import (
    CHECK_CATALOG, CHECKS_BY_ID, CellStatus, shared_class_specificity_problems,
)
from harness.coverage_tracker import CoverageTracker, endpoint_view

AUTH_ROWS = ("WSTG-ATHN-04", "WSTG-ATHN-07", "WSTG-IDNT-04", "WSTG-ATHN-11", "WSTG-SESS-01")


def _state(method, path, findings, *, object_scoped=False):
    st = engagement.EngagementState(host="t.test")
    ep = st._ep(method, path)
    ep.reachable_roles = ["user"]
    ep.object_scoped = object_scoped
    for f in findings:
        ep.add_finding(f)
    return st


def _attributed(method, path, findings, *, object_scoped=False):
    """Build the matrix and record the endpoint's slim findings, as build_coverage does."""
    st = _state(method, path, findings, object_scoped=object_scoped)
    t = CoverageTracker()
    eps = endpoint_view(st)
    t.build(eps, ["user"])
    t.record_findings_from_state(eps, ["user"])
    key = f"{method} {path}"
    return {cid: t.matrix.get("user", key, cid) for cid in CHECKS_BY_ID}


def _confirmed(cells):
    return sorted(cid for cid, c in cells.items() if c is not None and c.status == CellStatus.CONFIRMED)


class SharedClassAttributionTests(unittest.TestCase):
    """A confirmation is attributed to the ONE row it names (WG-2 (4))."""

    def test_username_enumeration_confirms_idnt04_only(self):
        cells = _attributed("POST", "/login", [{
            "vulnerability_class": "username_enumeration", "confirmed": True,
            "confirmed_by_leg": "auth_sequence", "severity": "medium", "confidence": 0.8}])
        self.assertEqual(cells["WSTG-IDNT-04"].status, CellStatus.CONFIRMED)
        for cid in ("WSTG-ATHN-04", "WSTG-ATHN-07", "WSTG-ATHN-11", "WSTG-SESS-01"):
            self.assertNotEqual(cells[cid].status, CellStatus.CONFIRMED, cid)
        self.assertEqual(_confirmed(cells), ["WSTG-IDNT-04"])

    def test_xss_with_stored_validator_confirms_injt02_only(self):
        cells = _attributed("POST", "/api/comments", [{
            "vulnerability_class": "xss", "confirmed": True, "validator": "stored_xss",
            # the slim-finding honesty backstop demotes an xss confirmation naming no leg
            "confirmed_by_leg": "stored_xss", "severity": "high", "confidence": 0.9}])
        self.assertEqual(_confirmed(cells), ["WSTG-INJT-02"])
        self.assertNotEqual(cells["WSTG-INJT-01"].status, CellStatus.CONFIRMED)

    def test_idor_confirms_athz04_only(self):
        cells = _attributed("GET", "/api/tickets/{id}", [{
            "vulnerability_class": "idor", "confirmed": True,
            "confirmed_by_leg": "cross_identity", "severity": "high", "confidence": 0.9}],
            object_scoped=True)
        self.assertEqual(_confirmed(cells), ["WSTG-ATHZ-04"])

    def test_bfla_confirms_athz02_only(self):
        cells = _attributed("GET", "/api/admin/users", [{
            "vulnerability_class": "bfla", "confirmed": True,
            "confirmed_by_leg": "cross_identity", "severity": "high", "confidence": 0.9}])
        self.assertEqual(_confirmed(cells), ["WSTG-ATHZ-02"])

    def test_bare_auth_without_validator_confirms_no_auth_row(self):
        """Negative control: a bare shared class names no row, so nothing is
        CONFIRMED; every candidate is DETECTED with the ambiguity reason (still
        visible and still drivable, never dropped)."""
        cells = _attributed("POST", "/login", [{
            "vulnerability_class": "auth", "confirmed": True,
            "severity": "high", "confidence": 0.9}])
        self.assertEqual(_confirmed(cells), [])
        for cid in AUTH_ROWS:
            self.assertEqual(cells[cid].status, CellStatus.DETECTED, cid)
            self.assertIn("shared by 5 rows", cells[cid].reason)
            self.assertIn("names no specific one", cells[cid].reason)

    def test_bare_auth_with_a_shared_leg_stays_ambiguous(self):
        """auth_sequence backs four auth rows, so naming it narrows but does not pick one."""
        cells = _attributed("POST", "/login", [{
            "vulnerability_class": "auth", "confirmed": True,
            "confirmed_by_leg": "auth_sequence", "severity": "high", "confidence": 0.9}])
        self.assertEqual(_confirmed(cells), [])
        for cid in ("WSTG-ATHN-04", "WSTG-ATHN-07", "WSTG-IDNT-04", "WSTG-ATHN-11"):
            self.assertEqual(cells[cid].status, CellStatus.DETECTED, cid)
            self.assertIn("shared by 4 rows", cells[cid].reason)
        self.assertEqual(cells["WSTG-SESS-01"].status, CellStatus.PENDING)

    def test_unconfirmed_bare_class_is_still_detected_on_every_candidate(self):
        cells = _attributed("POST", "/login", [{
            "vulnerability_class": "auth", "confirmed": False, "confidence": 0.4}])
        for cid in AUTH_ROWS:
            self.assertEqual(cells[cid].status, CellStatus.DETECTED, cid)
            self.assertEqual(cells[cid].reason, "detected auth")

    def test_resolution_order_and_ambiguity_flag(self):
        t = CoverageTracker()
        self.assertEqual(t.resolve_class("Stored XSS"), (["WSTG-INJT-02"], False))
        self.assertEqual(t.resolve_class("IDOR/BOLA"), (["WSTG-ATHZ-04"], False))
        self.assertEqual(t.checks_for_class("Broken Function-Level Authorization"),
                         ["WSTG-ATHZ-02"])
        self.assertEqual(t.checks_for_class("xss", validator="browser_xss"), ["WSTG-INJT-01"])
        # a validator that matches no candidate does not narrow to nothing
        self.assertEqual(sorted(t.checks_for_class("xss", validator="sqlmap")),
                         ["WSTG-INJT-01", "WSTG-INJT-02"])
        self.assertTrue(t.class_is_ambiguous("xss"))
        self.assertFalse(t.class_is_ambiguous("xss", validator="stored_xss"))
        # "misconfig" narrows by the verb_tamper leg; "_validator"-suffixed names fold
        self.assertEqual(t.checks_for_class("misconfig", validator="verb_tamper"),
                         ["WSTG-INJT-03"])
        self.assertEqual(t.checks_for_class("csp", validator="csp_validator"), ["WSTG-CONF-12"])
        # a single-row class is never ambiguous
        self.assertEqual(t.resolve_class("sqli"), (["WSTG-INJT-05"], False))


class SpecificClassGuardTests(unittest.TestCase):
    """Every row of a shared class declares specific_classes; no token is on two rows."""

    def test_catalog_is_sound(self):
        self.assertEqual(shared_class_specificity_problems(), [])

    def test_guard_rejects_a_shared_row_without_specific_classes(self):
        rows = tuple(dataclasses.replace(c, specific_classes=()) if c.id == "WSTG-ATHN-11" else c
                     for c in CHECK_CATALOG)
        problems = shared_class_specificity_problems(rows)
        self.assertTrue(any(p.startswith("WSTG-ATHN-11:") and "no specific_classes" in p
                            for p in problems), problems)

    def test_guard_rejects_a_token_on_two_rows(self):
        stolen = CHECKS_BY_ID["WSTG-IDNT-04"].specific_classes[0]
        rows = tuple(dataclasses.replace(c, specific_classes=c.specific_classes + (stolen,))
                     if c.id == "WSTG-ATHN-07" else c for c in CHECK_CATALOG)
        problems = shared_class_specificity_problems(rows)
        self.assertTrue(any("already on" in p for p in problems), problems)

    def test_guard_rejects_a_snake_spelling_collision(self):
        rows = tuple(dataclasses.replace(c, specific_classes=c.specific_classes + ("stored-xss",))
                     if c.id == "WSTG-INJT-01" else c for c in CHECK_CATALOG)
        self.assertTrue(shared_class_specificity_problems(rows))

    def test_guard_rejects_a_token_of_another_class(self):
        rows = tuple(dataclasses.replace(c, specific_classes=c.specific_classes + ("sqli",))
                     if c.id == "WSTG-ATHN-04" else c for c in CHECK_CATALOG)
        problems = shared_class_specificity_problems(rows)
        self.assertTrue(any("canonicalizes to 'sqli'" in p for p in problems), problems)


class SharedClassDriverTests(unittest.TestCase):
    """WG-2 (3): the driver hands a shared row its leg_class."""

    def test_idnt04_cell_is_driven_with_username_enumeration(self):
        st = _state("POST", "/login", [])
        t = CoverageTracker()
        t.build(endpoint_view(st), ["user"])
        handed: dict[str, str] = {}

        async def run_leg(identity, method, path, check):
            # The class orchestrator_chain._run_leg_core hands the leg.
            handed[check.id] = check.leg_class or check.vulnerability_class
            return SimpleNamespace(status="not_confirmed", summary="stub", confidence=None,
                                   evidence="", validator=check.confirmation)

        asyncio.run(t.drive_coverage_legs(run_leg, driveable={"auth_sequence"}, budget=50))
        self.assertEqual(handed.get("WSTG-IDNT-04"), "username_enumeration")
        self.assertEqual(handed.get("WSTG-ATHN-11"), "2fa_bypass")
        self.assertEqual(handed.get("WSTG-ATHN-07"), "weak_password")
        self.assertEqual(handed.get("WSTG-ATHN-04"), "auth")  # no bypass leg exists

    def test_leg_classes_reach_their_auth_sequence_branch(self):
        from harness.models import HttpExchange
        from harness.validators.auth_sequence_validator import AuthSequenceValidator
        ex = HttpExchange(method="POST", url="http://t.test/login",
                          request_headers={"Content-Type": "application/json"},
                          request_body='{"username": "u", "password": "p"}',
                          response_status=200, response_headers={}, response_body="")
        v = AuthSequenceValidator()
        expected = {"WSTG-IDNT-04": ["enum"], "WSTG-ATHN-11": ["mfa"], "WSTG-ATHN-07": ["weak"]}
        for cid, branch in expected.items():
            self.assertEqual(v._which_checks(CHECKS_BY_ID[cid].leg_class, ex), branch, cid)
        # the bare row class routes to no check -- the gap the leg_class closes
        self.assertEqual(v._which_checks("auth", ex), [])

    def test_sess01_leg_class_is_a_reset_token_class(self):
        from harness.validators.reset_token_validator import ResetTokenValidator
        self.assertIn(CHECKS_BY_ID["WSTG-SESS-01"].leg_class, ResetTokenValidator.finding_classes)


if __name__ == "__main__":
    unittest.main()
