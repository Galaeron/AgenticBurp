"""WG-1: the coverage catalog cites CURRENT OWASP WSTG test IDs, and every id it
used before (WSTG v4.2 numbering, plus the internal AV-MASSASSIGN-01) still
resolves through the one alias table.

Pins:
  - every non-internal catalog id is in the vendored WSTG list
    (`harness/wstg_ids.py`, no network);
  - each corrected row's hand-checked mapping (old id -> new id -> the upstream
    test name and the row's vulnerability class), and the rows that kept their id;
  - a coverage cell, an evidence artifact and an execution event stored under an
    old id land on the new id;
  - negative controls: an id in neither the current list nor the alias table is
    rejected (never silently aliased), and a current WSTG id with no catalog row
    is not mapped onto a neighbouring row;
  - the requirement manifest still has one requirement per catalog row (64: 38 from
    WG-1, the 11 WG-2 rows, WG-3's SESS-06, WG-2's BUSL-08, the 11 internal
    rows main added before the port, and R11-7's BUSL-10 and AV-BUSL-COUPON-01).

A row added later must be added to the hand-checked tables below (WG-2's rows are in
ADDED_ROWS; internal AV-* rows are in INTERNAL_ROWS).
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import harness.coverage_manifest as cm
import harness.coverage_model as model
from harness import engagement
from harness.coverage_model import (
    CHECK_CATALOG, CHECKS_BY_ID, LEGACY_CHECK_ID_ALIASES, REUSED_LEGACY_IDS, CellStatus,
    CoverageMatrix, UnknownCheckIdError, resolve_check_id,
)
from harness.coverage_tracker import CoverageTracker, endpoint_view
from harness.wstg_ids import (
    WSTG_LATEST_SUBTESTS, WSTG_LATEST_TESTS, WSTG_RELEASE_LABEL, WSTG_SOURCE_COMMIT,
    is_current_wstg_id,
)

# Hand-checked against the WSTG checklist and document tree at WSTG_SOURCE_COMMIT and
# docs/WSTG_GAP_REVIEW_2026-11-12.md: old id -> (new id, upstream test name, row class).
REKEYED_ROWS: dict[str, tuple[str, str, str]] = {
    "WSTG-CONF-05": ("WSTG-CONF-12", "Content Security Policy", "csp"),
    "WSTG-CONF-08": ("WSTG-CLNT-07", "Cross Origin Resource Sharing", "cors"),
    "WSTG-CONF-02": ("WSTG-CONF-14", "Other HTTP Security Header Misconfigurations", "misconfig"),
    "WSTG-ATHN-01": ("WSTG-ATHN-04", "Bypassing Authentication Schema", "auth"),
    "WSTG-BUSV-04": ("WSTG-INJT-16", "HTTP Request Smuggling", "http_request_smuggling"),
    "WSTG-INPV-14": ("WSTG-INJT-15", "HTTP Response Splitting", "header_injection"),
    "WSTG-INPV-05": ("WSTG-INJT-05", "SQL Injection", "sqli"),
    "WSTG-INPV-01": ("WSTG-INJT-01", "Reflected Cross Site Scripting", "xss"),
    "WSTG-INPV-02": ("WSTG-INJT-02", "Stored Cross Site Scripting", "xss"),
    "WSTG-INPV-12": ("WSTG-INJT-12", "Command Injection", "command_injection"),
    "WSTG-INPV-18": ("WSTG-INJT-18", "Server-side Template Injection", "ssti"),
    "WSTG-INPV-07": ("WSTG-INJT-07", "XML Injection", "xxe"),
    "WSTG-INPV-19": ("WSTG-INJT-19", "Server-Side Request Forgery", "ssrf"),
    "WSTG-INPV-17": ("WSTG-CLNT-04", "Client-side URL Redirect", "open_redirect"),
    "WSTG-INPV-06": ("WSTG-INJT-05.6", "NoSQL Injection", "nosql"),
    "WSTG-CRYP-04": ("WSTG-SESS-10", "JSON Web Tokens", "jwt"),
    "WSTG-INPV-11": ("WSTG-INJT-23", "Insecure Deserialization", "deserialization"),
    "WSTG-BUSL-07": ("WSTG-BUSL-05", "Number of Times a Function Can Be Used Limits",
                     "race_condition"),
    "WSTG-BUSL-08": ("WSTG-ATHZ-03", "Privilege Escalation", "toctou"),
    "AV-MASSASSIGN-01": ("WSTG-INJT-20", "Mass Assignment", "api_security"),
}

# Rows whose v4.2 id still names the same current test: id -> (upstream name, class).
UNCHANGED_ROWS: dict[str, tuple[str, str]] = {
    "WSTG-CRYP-01": ("Weak Transport Layer Security", "crypto"),
    "WSTG-CONF-07": ("HTTP Strict Transport Security", "misconfig"),
    "WSTG-INFO-02": ("Fingerprint Web Server", "recon"),
    "WSTG-INFO-05": ("Review Web Page Content for Information Leakage", "info_disclosure"),
    "WSTG-CONF-06": ("HTTP Methods", "misconfig"),
    "WSTG-CONF-09": ("File Permissions", "misconfig"),
    "WSTG-ATHZ-04": ("Insecure Direct Object References", "idor"),
    "WSTG-ATHZ-02": ("Bypassing Authorization Schema", "idor"),
    "WSTG-ATHN-07": ("Weak Authentication Methods", "auth"),
    "WSTG-ATHN-03": ("Weak Lock Out Mechanism", "rate_limit"),
    "WSTG-ATHN-09": ("Weak Password Change or Reset Functionalities", "reset_token"),
    "WSTG-SESS-01": ("Session Management Schema", "auth"),
    "WSTG-SESS-03": ("Session Fixation", "session_fixation"),
    "WSTG-BUSL-09": ("Upload of Malicious Files", "file_upload"),
    "WSTG-ATHZ-01": ("Directory Traversal and File Include", "path_traversal"),
    "WSTG-ERRH-01": ("Improper Error Handling", "info_disclosure"),
    "WSTG-SESS-05": ("Cross Site Request Forgery", "csrf"),
    "WSTG-CLNT-01": ("DOM-Based Cross Site Scripting", "dom_xss"),
}

# WG-2: rows added for registered validators that had none.
# id -> (upstream name, row class, confirmation kind).
ADDED_ROWS: dict[str, tuple[str, str, str]] = {
    "WSTG-CLNT-09": ("Clickjacking", "clickjacking", "csp"),
    "WSTG-CONF-10": ("Subdomain Takeover", "subdomain_takeover", "subdomain_takeover"),
    "WSTG-IDNT-04": ("Account Enumeration and Guessable User Account", "auth",
                     "auth_sequence"),
    "WSTG-ATHN-11": ("Multi-Factor Authentication (MFA)", "auth", "auth_sequence"),
    "WSTG-SESS-02": ("Cookies Attributes", "crypto", "crypto"),
    "WSTG-ATHZ-05": ("OAuth Weaknesses", "oauth", "oauth"),
    "WSTG-CLNT-10": ("WebSockets", "websocket", "websocket"),
    "WSTG-INJT-03": ("HTTP Verb Tampering", "misconfig", "verb_tamper"),
    "WSTG-BUSL-02": ("Ability to Forge Requests", "business_logic", "client_trust"),
    "WSTG-INJT-17": ("Host Header Injection", "web_cache_poisoning", "web_cache_poisoning"),
    "WSTG-CONF-13": ("Path Confusion", "web_cache_poisoning", "web_cache_poisoning"),
    # WG-3: the Python logout-invalidation leg.
    "WSTG-SESS-06": ("Logout Functionality", "session_timeout", "auth_sequence"),
    # WG-2: the benign disallowed-extension upload leg. "WSTG-BUSL-08" is also a
    # scheme-1 alias (REKEYED_ROWS) and is declared in REUSED_LEGACY_IDS.
    "WSTG-BUSL-08": ("Upload of Unexpected File Types", "file_upload", "file_upload"),
    # R11-7: the business-flow legs (checkout tamper / payment skip, 2FA disable).
    "WSTG-BUSL-10": ("Payment Functionality", "payment_tamper", "business_flow"),
}


# Internal scenarios main added after WG-1 was written (exposure legs, the
# filter-bypass leg, .well-known, the write-integrity legs). They make no WSTG claim.
# id -> (row class, confirmation kind).
INTERNAL_ROWS: dict[str, tuple[str, str]] = {
    "AV-EXPOSURE-01": ("info_disclosure", "content_exposure"),
    "AV-EXPOSURE-02": ("info_disclosure", "listing_exposure"),
    "AV-EXPOSURE-03": ("info_disclosure", "metrics_exposure"),
    "AV-EXPOSURE-04": ("info_disclosure", "sensitive_file"),
    "AV-FILTER-01": ("path_filter_bypass", "filter_bypass"),
    "AV-WELLKNOWN-01": ("recon", "well_known"),
    "AV-WRITE-XID-01": ("cross_identity_write", "write_integrity"),
    "AV-WRITE-AUTHOR-01": ("forged_authorship", "write_integrity"),
    "AV-WRITE-BIZ-01": ("business_rule_tamper", "write_integrity"),
    "AV-MASSASSIGN-02": ("mass_assignment_create", "write_integrity"),
    "AV-WRITE-VALID-01": ("create_validation", "write_integrity"),
    "AV-BUSL-COUPON-01": ("coupon_misuse", "business_flow"),
}


def _upstream_name(check_id: str) -> str:
    return WSTG_LATEST_TESTS.get(check_id) or WSTG_LATEST_SUBTESTS[check_id]


class VendoredListTests(unittest.TestCase):
    def test_vendored_list_is_pinned_and_complete(self):
        self.assertEqual(WSTG_SOURCE_COMMIT, "4d58b98e50bb8462491d7fd226864352d489c979")
        self.assertEqual(len(WSTG_LATEST_TESTS), 117)
        for sub in WSTG_LATEST_SUBTESTS:
            self.assertIn(sub.rsplit(".", 1)[0], WSTG_LATEST_TESTS, sub)

    def test_every_non_internal_catalog_id_is_a_current_wstg_id(self):
        for check in CHECK_CATALOG:
            if check.id.startswith("AV-"):
                continue  # an internal scenario id makes no WSTG claim
            with self.subTest(check=check.id):
                self.assertTrue(check.is_wstg())
                self.assertTrue(is_current_wstg_id(check.id), check.id)
                self.assertEqual(check.wstg_version, WSTG_RELEASE_LABEL)
                self.assertEqual(check.reference_label(), f"{check.id} (WSTG latest)")

    def test_v42_only_and_made_up_ids_are_not_current(self):
        # Negative control for the list itself: the v4.2 INPV/BUSV numbering and a
        # sub-test number upstream never published are not current ids.
        for bad in ("WSTG-INPV-05", "WSTG-BUSV-04", "WSTG-INJT-05.9", "WSTG-FAKE-05.6",
                    "WSTG-INJT-99", ""):
            with self.subTest(bad=bad):
                self.assertFalse(is_current_wstg_id(bad))


class HandCheckedMappingTests(unittest.TestCase):
    def test_each_corrected_row_maps_to_its_hand_checked_test(self):
        for old, (new, name, vuln_class) in REKEYED_ROWS.items():
            with self.subTest(old=old):
                self.assertEqual(LEGACY_CHECK_ID_ALIASES[old], new)
                if old not in REUSED_LEGACY_IDS:
                    self.assertNotIn(old, CHECKS_BY_ID)
                self.assertIn(new, CHECKS_BY_ID)
                self.assertEqual(CHECKS_BY_ID[new].vulnerability_class, vuln_class)
                self.assertEqual(_upstream_name(new), name)

    def test_unchanged_rows_still_name_the_same_test(self):
        for check_id, (name, vuln_class) in UNCHANGED_ROWS.items():
            with self.subTest(check=check_id):
                self.assertIn(check_id, CHECKS_BY_ID)
                self.assertNotIn(check_id, LEGACY_CHECK_ID_ALIASES)
                self.assertEqual(CHECKS_BY_ID[check_id].vulnerability_class, vuln_class)
                self.assertEqual(WSTG_LATEST_TESTS[check_id], name)

    def test_added_rows_name_their_test_and_validator(self):
        for check_id, (name, vuln_class, kind) in ADDED_ROWS.items():
            with self.subTest(check=check_id):
                self.assertIn(check_id, CHECKS_BY_ID)
                if check_id not in REUSED_LEGACY_IDS:
                    self.assertNotIn(check_id, LEGACY_CHECK_ID_ALIASES)
                self.assertEqual(WSTG_LATEST_TESTS[check_id], name)
                self.assertEqual(CHECKS_BY_ID[check_id].vulnerability_class, vuln_class)
                self.assertEqual(CHECKS_BY_ID[check_id].confirmation, kind)

    def test_internal_rows_make_no_wstg_claim(self):
        for check_id, (vuln_class, kind) in INTERNAL_ROWS.items():
            with self.subTest(check=check_id):
                check = CHECKS_BY_ID[check_id]
                self.assertFalse(check.is_wstg())
                self.assertNotIn(check_id, LEGACY_CHECK_ID_ALIASES)
                self.assertEqual(check.vulnerability_class, vuln_class)
                self.assertEqual(check.confirmation, kind)
                self.assertEqual(check.reference_label(), f"{check_id} (internal scenario)")

    def test_tables_cover_the_whole_catalog(self):
        hand_checked = ({new for new, _, _ in REKEYED_ROWS.values()} | set(UNCHANGED_ROWS)
                        | set(ADDED_ROWS) | set(INTERNAL_ROWS))
        self.assertEqual(hand_checked, set(CHECKS_BY_ID))
        self.assertEqual(set(LEGACY_CHECK_ID_ALIASES), set(REKEYED_ROWS))

    def test_alias_table_never_shadows_a_current_row(self):
        # Only a declared reused id (scheme-1 meaning differs) may be both.
        self.assertEqual(set(LEGACY_CHECK_ID_ALIASES) & set(CHECKS_BY_ID), set(REUSED_LEGACY_IDS))
        self.assertEqual(REUSED_LEGACY_IDS, frozenset({"WSTG-BUSL-08"}))
        self.assertLessEqual(set(LEGACY_CHECK_ID_ALIASES.values()), set(CHECKS_BY_ID))

    def test_import_guard_rejects_a_shadowing_alias_and_a_stale_row_id(self):
        with mock.patch.dict(model.LEGACY_CHECK_ID_ALIASES, {"WSTG-INJT-05": "WSTG-INJT-01"}):
            with self.assertRaisesRegex(ValueError, "shadows"):
                model._check_catalog_ids()
        with mock.patch.object(model, "is_current_wstg_id", lambda _id: False):
            with self.assertRaisesRegex(ValueError, "not in harness/wstg_ids.py"):
                model._check_catalog_ids()
        model._check_catalog_ids()  # the shipped catalog passes


class ResolveTests(unittest.TestCase):
    def test_current_and_legacy_ids_resolve(self):
        self.assertEqual(resolve_check_id("WSTG-INJT-05"), "WSTG-INJT-05")
        for old, (new, _, _) in REKEYED_ROWS.items():
            self.assertEqual(resolve_check_id(old, scheme=1), new)
            if old not in REUSED_LEGACY_IDS:
                self.assertEqual(resolve_check_id(old), new)

    def test_unknown_id_is_rejected_not_aliased(self):
        # Neither a current catalog id nor an alias: a typo, a made-up v4.2-style id,
        # and a REAL current WSTG id with no catalog row (search-engine recon,
        # INFO-01; ATHN-11 played this part until WG-2 gave it a row). None
        # may land on a neighbouring row.
        for bad in ("WSTG-INPV-99", "WSTG-INJT-5", "wstg-injt-05", "WSTG-INFO-01", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(UnknownCheckIdError):
                    resolve_check_id(bad)


class LegacyStorageTests(unittest.TestCase):
    """Data written by r9, r10 and earlier carries the old ids."""

    def test_cell_stored_under_old_id_loads_under_new_id(self):
        stored = {
            "cells": {
                "user|GET /x|WSTG-INPV-05": {"status": "not_detected", "reason": "r9"},
                "user|GET /r|WSTG-INPV-17": {"status": "confirmed", "reason": "r10"},
                "user|POST /m|AV-MASSASSIGN-01": {"status": "pending", "reason": ""},
            },
            "cases": {
                "user|GET /x|WSTG-INPV-05": [
                    {"key": {"parameter_location": "query", "parameter_name": "q"},
                     "result": {"status": "not_detected", "reason": "r9"}}],
            },
        }
        m = CoverageMatrix.from_dict(stored)
        self.assertEqual(m.get("user", "GET /x", "WSTG-INJT-05").status, CellStatus.NOT_DETECTED)
        self.assertEqual(m.get("user", "GET /r", "WSTG-CLNT-04").status, CellStatus.CONFIRMED)
        self.assertEqual(m.get("user", "POST /m", "WSTG-INJT-20").status, CellStatus.PENDING)
        self.assertIsNone(m.get("user", "GET /x", "WSTG-INPV-05"))
        self.assertEqual(len(m.cases_for_cell("user", "GET /x", "WSTG-INJT-05")), 1)
        # Re-saving writes the current id only.
        keys = set(m.to_dict()["cells"])
        self.assertIn("user|GET /x|WSTG-INJT-05", keys)
        self.assertFalse(any("INPV" in k or "AV-MASS" in k for k in keys))

    def test_current_id_wins_over_a_legacy_duplicate(self):
        stored = {"cells": {
            "user|GET /x|WSTG-INPV-05": {"status": "not_detected", "reason": "old"},
            "user|GET /x|WSTG-INJT-05": {"status": "confirmed", "reason": "new"},
        }}
        m = CoverageMatrix.from_dict(stored)
        self.assertEqual(m.get("user", "GET /x", "WSTG-INJT-05").reason, "new")
        self.assertEqual(len(m.to_dict()["cells"]), 1)

    def test_unknown_stored_id_is_kept_verbatim_not_aliased(self):
        # Negative control: an id in neither table keeps its own key; it never
        # becomes (or overwrites) a catalog cell.
        stored = {"cells": {
            "user|GET /x|WSTG-INPV-99": {"status": "confirmed", "reason": "?"},
            "user|GET /x|WSTG-INFO-01": {"status": "confirmed", "reason": "?"},
        }}
        m = CoverageMatrix.from_dict(stored)
        self.assertEqual(set(m.to_dict()["cells"]),
                         {"user|GET /x|WSTG-INPV-99", "user|GET /x|WSTG-INFO-01"})
        for check_id in CHECKS_BY_ID:
            self.assertIsNone(m.get("user", "GET /x", check_id))


class LegacyEvidenceTests(unittest.TestCase):
    RUN = "RUN_WG1"

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="cov_wg1_"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _raw(self, check_id, aspect, name):
        (self._tmp / name).write_text(json.dumps({
            "schema_version": cm.SCHEMA_VERSION, "check_id": check_id, "aspect": aspect,
            "execution": {"status": "pass", "run_id": self.RUN, "test_id": "m.T.test_x"}}),
            encoding="utf-8")

    def test_evidence_under_old_id_counts_for_new_requirement(self):
        self._raw("WSTG-INPV-17", "redirect", "WSTG-INPV-17__redirect.json")
        loaded = cm.load_evidence(self._tmp, run_id=self.RUN)
        self.assertIn(("WSTG-CLNT-04", "redirect"), loaded)
        self.assertNotIn(("WSTG-INPV-17", "redirect"), loaded)
        spec = cm.TestSpec(check_id="WSTG-CLNT-04", test_id="m.T.test_x", aspect="redirect",
                           mode="automated", label="unit",
                           evidence_file=cm.evidence_basename("WSTG-CLNT-04", "redirect"))
        rep = cm.reconcile((spec,), evidence_dir=self._tmp, run_id=self.RUN)
        req = next(r for r in rep["requirements"] if r["check_id"] == "WSTG-CLNT-04")
        self.assertEqual(req["requirement_status"], cm.RequirementStatus.COVERED_PARTIAL.value)

    def test_write_under_old_id_lands_on_new_id_and_unknown_is_refused(self):
        path = cm.write_evidence(check_id="WSTG-CRYP-04", aspect="jwt", status="pass",
                                 test_id="m.T.test_x", run_id=self.RUN, evidence_dir=self._tmp)
        self.assertEqual(path.name, cm.evidence_basename("WSTG-SESS-10", "jwt"))
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["check_id"], "WSTG-SESS-10")
        for bad in ("WSTG-INPV-99", "WSTG-INFO-01"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    cm.write_evidence(check_id=bad, aspect="x", status="pass",
                                      test_id="m.T.test_x", run_id=self.RUN,
                                      evidence_dir=self._tmp)

    def test_unknown_evidence_id_matches_no_requirement(self):
        self._raw("WSTG-INPV-99", "x", "WSTG-INPV-99__x.json")
        loaded = cm.load_evidence(self._tmp, run_id=self.RUN)
        self.assertEqual(set(loaded), {("WSTG-INPV-99", "x")})
        rep = cm.reconcile((), evidence_dir=self._tmp, run_id=self.RUN)
        self.assertNotIn("WSTG-INPV-99", {r["check_id"] for r in rep["requirements"]})


class LegacyEventTests(unittest.TestCase):
    def _tracker(self):
        st = engagement.EngagementState(host="t.test")
        ep = st._ep("POST", "/api/search")
        ep.reachable_roles = ["user"]
        t = CoverageTracker()
        t.build(endpoint_view(st), ["user"])
        self.assertEqual(t.matrix.get("user", "POST /api/search", "WSTG-INJT-05").status,
                         CellStatus.PENDING)
        return t

    def test_event_naming_old_id_updates_the_new_cell(self):
        t = self._tracker()
        n = t.record_execution_events([
            {"identity": "user", "endpoint_key": "POST /api/search",
             "check_id": "WSTG-INPV-05", "status": "not_detected"}])
        self.assertEqual(n, 1)
        self.assertEqual(t.matrix.get("user", "POST /api/search", "WSTG-INJT-05").status,
                         CellStatus.NOT_DETECTED)

    def test_event_naming_unknown_id_updates_nothing(self):
        t = self._tracker()
        before = t.matrix.to_dict()
        n = t.record_execution_events([
            {"identity": "user", "endpoint_key": "POST /api/search",
             "check_id": "WSTG-INPV-99", "status": "confirmed"}])
        self.assertEqual(n, 0)
        self.assertEqual(t.matrix.to_dict(), before)


class ManifestCountTests(unittest.TestCase):
    def test_one_requirement_per_catalog_row(self):
        tmp = Path(tempfile.mkdtemp(prefix="cov_wg1_count_"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        rep = cm.reconcile(evidence_dir=tmp, run_id="RUN_EMPTY")
        self.assertEqual(rep["totals"]["requirements"], 64)
        self.assertEqual({r["check_id"] for r in rep["requirements"]}, set(CHECKS_BY_ID))
        for spec in cm.REQUIREMENT_TESTS:
            self.assertIn(spec.check_id, CHECKS_BY_ID)
            if spec.check_id not in REUSED_LEGACY_IDS:
                self.assertNotIn(spec.check_id, LEGACY_CHECK_ID_ALIASES)


if __name__ == "__main__":
    unittest.main()
