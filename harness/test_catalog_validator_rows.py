"""WG-2: every registered validator that confirms a WSTG test has a catalog row, and
no row names a confirmation kind that is not a registered validator.

Pins:
  - `coverage_model.catalog_kind_problems` is empty for the shipped catalog against
    the validators `validators/registry.py` really registers (cross_identity armed,
    since it is registered on opt-in);
  - negative controls: an injected row naming an unregistered validator, a
    registered validator with neither a row nor an exclusion reason, a stale
    exclusion, and an excluded row id that has a row are each reported;
  - the stale kinds WG-2 fixed (CSRF, NoSQL, SESS-01) and the MFA binding move;
  - caller level: a CoverageTracker built over an engagement marks each new row
    applicable only on the exchange shape its leg needs, and the coverage driver
    offers the new leg-backed rows (auth_sequence, verb_tamper) as pending cells;
  - WG-2 item 5: every row kind is a drive leg or undriven with a reason
    (`coverage_tracker.leg_table_problems`, with negative controls), and the
    driver offers client_trust, websocket and oauth cells only where they apply.
"""
from __future__ import annotations

import dataclasses
import unittest

import harness.coverage_manifest as cm
from harness import engagement
from harness.coverage_model import (
    CHECK_CATALOG, CHECKS_BY_ID, EXCLUDED_CATALOG_ROWS, NON_VALIDATOR_CONFIRMATIONS,
    VALIDATOR_ROW_EXCLUSIONS, CellStatus, catalog_kind_problems,
)
from harness.coverage_tracker import (
    _LEG_CONFIRMATIONS, UNDRIVEN_ROW_CONFIRMATIONS, CoverageTracker, endpoint_view,
    leg_table_problems,
)
from harness.safety_gate import reset_default_gate
from harness.validators.registry import ValidatorRegistry


def _registered_names() -> set[str]:
    try:
        reg = ValidatorRegistry({"validators": {"cross_identity": {"enabled": True}}})
        return set(reg.validators)
    finally:
        reset_default_gate()


class KindAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registered = _registered_names()

    def test_shipped_catalog_has_no_kind_problems(self):
        self.assertEqual(catalog_kind_problems(CHECK_CATALOG, self.registered), [])

    def test_every_automated_kind_names_a_registered_validator(self):
        for check in CHECK_CATALOG:
            if check.confirmation in NON_VALIDATOR_CONFIRMATIONS:
                continue
            with self.subTest(check=check.id):
                self.assertIn(check.confirmation, self.registered)

    def test_every_registered_validator_has_a_row_or_a_reason(self):
        kinds = {c.confirmation for c in CHECK_CATALOG}
        for name in sorted(self.registered):
            with self.subTest(validator=name):
                self.assertTrue(name in kinds or VALIDATOR_ROW_EXCLUSIONS.get(name, "").strip())
        # WG-3 landed the logout leg, so SESS-06 is a row, not an exclusion.
        self.assertNotIn("WSTG-SESS-06", EXCLUDED_CATALOG_ROWS)
        self.assertEqual("auth_sequence", CHECKS_BY_ID["WSTG-SESS-06"].confirmation)

    def test_row_naming_an_unregistered_validator_is_reported(self):
        # Negative control: the audit must fail on a made-up kind.
        bogus = dataclasses.replace(CHECKS_BY_ID["WSTG-INJT-05"], id="WSTG-INJT-04",
                                    confirmation="no_such_validator")
        problems = catalog_kind_problems(CHECK_CATALOG + (bogus,), self.registered)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("WSTG-INJT-04", problems[0])
        self.assertIn("no_such_validator", problems[0])

    def test_unrowed_validator_without_reason_is_reported(self):
        problems = catalog_kind_problems(CHECK_CATALOG, self.registered | {"phantom_leg"})
        self.assertEqual(problems, [
            "phantom_leg: registered validator has no catalog row and no exclusion reason"])
        blank = {**VALIDATOR_ROW_EXCLUSIONS, "phantom_leg": "  "}
        self.assertEqual(len(catalog_kind_problems(
            CHECK_CATALOG, self.registered | {"phantom_leg"}, blank)), 1)

    def test_stale_exclusions_are_reported(self):
        # An exclusion for a validator that has a row, and one for a validator that
        # is no longer registered.
        stale = {**VALIDATOR_ROW_EXCLUSIONS, "csrf": "old reason", "gone_leg": "removed"}
        problems = catalog_kind_problems(CHECK_CATALOG, self.registered, stale)
        self.assertEqual(sorted(problems), [
            "csrf: excluded but a row names it (stale exclusion)",
            "gone_leg: excluded but not registered (stale exclusion)"])
        rows = catalog_kind_problems(CHECK_CATALOG, self.registered,
                                     excluded_rows={"WSTG-INJT-05": "x"})
        self.assertEqual(rows, ["WSTG-INJT-05: on the excluded-row list but has a row"])


class DriveLegTableTests(unittest.TestCase):
    """WG-2 item 5: every row kind is either a coverage-drive leg or listed as
    undriven with the reason its verdict cannot answer the row."""

    def test_shipped_leg_table_has_no_problems(self):
        self.assertEqual(leg_table_problems(CHECK_CATALOG), [])

    def test_added_and_rejected_kinds(self):
        for name in ("client_trust", "websocket", "oauth"):
            self.assertIn(name, _LEG_CONFIRMATIONS)
        self.assertEqual(set(UNDRIVEN_ROW_CONFIRMATIONS),
                         {"crypto", "recon", "web_cache_poisoning", "subdomain_takeover"})
        for name, why in UNDRIVEN_ROW_CONFIRMATIONS.items():
            self.assertNotIn(name, _LEG_CONFIRMATIONS)
            self.assertTrue(why.strip(), name)
        # Each added leg is the confirmation of exactly the row it now drives.
        for check_id, name in (("WSTG-BUSL-02", "client_trust"), ("WSTG-CLNT-10", "websocket"),
                               ("WSTG-ATHZ-05", "oauth")):
            self.assertEqual(CHECKS_BY_ID[check_id].confirmation, name)

    def test_problems_are_reported(self):
        # Negative controls: an undocumented kind, a kind on both lists, a blank
        # reason and a stale entry are each reported.
        dropped = _LEG_CONFIRMATIONS - {"oauth"}
        self.assertEqual(leg_table_problems(CHECK_CATALOG, legs=dropped), [
            "oauth: row kind is neither a drive leg nor undriven with a reason"])
        both = _LEG_CONFIRMATIONS | {"crypto"}
        self.assertEqual(leg_table_problems(CHECK_CATALOG, legs=both), [
            "crypto: both a drive leg and undriven"])
        blank = {**UNDRIVEN_ROW_CONFIRMATIONS, "recon": " "}
        self.assertEqual(leg_table_problems(CHECK_CATALOG, undriven=blank), [
            "recon: undriven with no reason"])
        stale = _LEG_CONFIRMATIONS | {"gone_leg"}
        self.assertEqual(leg_table_problems(CHECK_CATALOG, legs=stale), [
            "gone_leg: in the leg table but no row names it (stale entry)"])


class FixedKindTests(unittest.TestCase):
    def test_stale_kinds_now_name_their_validator(self):
        self.assertEqual(CHECKS_BY_ID["WSTG-SESS-05"].confirmation, "csrf")
        self.assertEqual(CHECKS_BY_ID["WSTG-INJT-05.6"].confirmation, "nosql")
        self.assertEqual(CHECKS_BY_ID["WSTG-SESS-01"].confirmation, "reset_token")
        self.assertEqual(CHECKS_BY_ID["WSTG-BUSL-09"].confirmation, "manual")
        self.assertEqual(CHECKS_BY_ID["WSTG-BUSL-08"].confirmation, "file_upload")
        self.assertNotIn("file_upload", VALIDATOR_ROW_EXCLUSIONS)
        self.assertNotIn("agent", {c.confirmation for c in CHECK_CATALOG})

    def test_mfa_bindings_moved_to_athn_11(self):
        for key in ("mfa_confirm", "mfa_control"):
            self.assertEqual(cm.caller_evidence(key)["check_id"], "WSTG-ATHN-11")
        ids = {s.check_id for s in cm.REQUIREMENT_TESTS if "2fa" in s.test_id}
        self.assertEqual(ids, {"WSTG-ATHN-11"})


# Endpoint shapes for the caller-level applicability test.
_LOGIN = "POST /login"
_WS = "GET /ws"
_OAUTH = "GET /oauth/authorize"
_DENIED = "GET /api/admin/report"
_CART = "POST /api/cart"
_NOTES = "GET /api/notes"
_NOTE_W = "POST /api/notes"
_PLAN = "POST /api/subscription"   # a server-owned plan field, no price/amount key


def _engagement():
    st = engagement.EngagementState(host="t.test")
    for key in (_LOGIN, _WS, _OAUTH, _DENIED, _CART, _NOTES, _NOTE_W, _PLAN):
        method, _, path = key.partition(" ")
        st._ep(method, path)
    st.endpoints[_LOGIN].template = {"method": "POST", "query": "",
                                     "body": "username=a&password=b",
                                     "content_type": "application/x-www-form-urlencoded",
                                     "object_id": None}
    st.endpoints[_OAUTH].template = {"method": "GET",
                                     "query": "client_id=c&redirect_uri=https://x/cb",
                                     "body": "", "content_type": "", "object_id": None}
    st.endpoints[_DENIED].access = {"user": 403, "admin": 200}
    st.endpoints[_DENIED].reachable_roles = ["user", "admin"]
    st.endpoints[_CART].template = {"method": "POST", "query": "",
                                    "body": '{"item": 3, "price": 10}',
                                    "content_type": "application/json", "object_id": None}
    st.endpoints[_NOTE_W].template = {"method": "POST", "query": "", "body": '{"title": "t"}',
                                      "content_type": "application/json", "object_id": None}
    st.endpoints[_PLAN].template = {"method": "POST", "query": "", "body": '{"plan": "basic"}',
                                    "content_type": "application/json", "object_id": None}
    return st


# check id -> exactly the fixture endpoints whose shape that row fits (domain rows
# are asserted separately).
_EXPECTED_ONLY = {
    "WSTG-IDNT-04": {_LOGIN, _OAUTH},   # _has_auth_endpoint also matches "oauth"
    "WSTG-ATHN-11": {_LOGIN, _OAUTH},
    "WSTG-SESS-02": {_LOGIN},
    "WSTG-SESS-01": {_LOGIN, _OAUTH},
    "WSTG-CLNT-10": {_WS},
    "WSTG-ATHZ-05": {_OAUTH},
    "WSTG-INJT-03": {_DENIED},
    "WSTG-BUSL-02": {_CART, _PLAN},   # client_trust's own trust-field recogniser
    "WSTG-CONF-13": {_DENIED},
    "WSTG-INJT-17": {_WS, _OAUTH, _DENIED, _NOTES},
}


class CallerLevelCoverageTests(unittest.TestCase):
    def setUp(self):
        self.tracker = CoverageTracker()
        self.eps = endpoint_view(_engagement())
        self.tracker.build(self.eps, ["user"], {"user": "user"})

    def _applicable(self, check_id):
        return {ep for ep in self.eps
                if self.tracker.matrix.get("user", ep, check_id).status
                != CellStatus.NOT_APPLICABLE}

    def test_new_rows_apply_only_where_the_shape_fits(self):
        for check_id, expected in _EXPECTED_ONLY.items():
            with self.subTest(check=check_id):
                self.assertEqual(self._applicable(check_id), expected)
        # Domain rows follow their CONF-12 / CRYP-01 siblings: every endpoint.
        for check_id in ("WSTG-CLNT-09", "WSTG-CONF-10"):
            self.assertEqual(self._applicable(check_id), set(self.eps))

    def test_plain_endpoint_gets_no_shape_specific_row(self):
        # Negative control: an ordinary collection GET carries no login, upgrade,
        # OAuth parameter, denial or value field, so none of those rows apply.
        for check_id in ("WSTG-IDNT-04", "WSTG-ATHN-11", "WSTG-SESS-02", "WSTG-CLNT-10",
                         "WSTG-ATHZ-05", "WSTG-INJT-03", "WSTG-BUSL-02", "WSTG-CONF-13"):
            with self.subTest(check=check_id):
                cell = self.tracker.matrix.get("user", _NOTES, check_id)
                self.assertEqual(cell.status, CellStatus.NOT_APPLICABLE)
                self.assertTrue(cell.reason)

    def test_driver_offers_new_leg_backed_rows(self):
        cells = {(ep, c.id) for _, ep, c in
                 self.tracker.pending_leg_cells({"auth_sequence", "verb_tamper"})}
        self.assertIn((_LOGIN, "WSTG-IDNT-04"), cells)
        self.assertIn((_LOGIN, "WSTG-ATHN-11"), cells)
        self.assertIn((_DENIED, "WSTG-INJT-03"), cells)
        # Negative control: no verb-tamper cell where no role was denied.
        self.assertNotIn((_NOTES, "WSTG-INJT-03"), cells)
        # SESS-01 moved to reset_token, so the auth_sequence driver no longer offers it.
        self.assertNotIn((_LOGIN, "WSTG-SESS-01"), cells)

    def test_driver_offers_the_wg2_item5_legs(self):
        # client_trust, websocket and oauth are drive legs: their applicable cells
        # are pending for the driver with no agent label.
        cells = {(ep, c.id) for _, ep, c in
                 self.tracker.pending_leg_cells({"client_trust", "websocket", "oauth"})}
        self.assertEqual(cells, {(_CART, "WSTG-BUSL-02"), (_PLAN, "WSTG-BUSL-02"),
                                 (_WS, "WSTG-CLNT-10"), (_OAUTH, "WSTG-ATHZ-05")})
        # Negative control: a driver without those legs is offered none of the cells.
        others = {(ep, c.id) for _, ep, c in
                  self.tracker.pending_leg_cells(_LEG_CONFIRMATIONS - {"client_trust", "websocket", "oauth"})}
        self.assertFalse({c for _, c in others} & {"WSTG-BUSL-02", "WSTG-CLNT-10", "WSTG-ATHZ-05"})


if __name__ == "__main__":
    unittest.main()
