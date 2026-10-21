"""I04: the CSRF "NEEDS MANUAL CHECK" label survives real storage and every export.

test_csrf_reflection_control proves the validator never confirms CSRF on a
reflecting endpoint and that Orchestrator.analyze returns the unconfirmed,
low-severity candidate. This file follows that same candidate past the API
response: it is written to a temporary SQLite store by the real
persist_findings, the in-memory evidence is dropped, and the stored row, the
issue export, the SARIF document and the Markdown report are read back. The
candidate must stay unconfirmed, low severity and manual-verification on each.

What each surface can carry is asserted as it is today. The Markdown report
quotes the label and the copy-ready csrf-test.html steps; the stored row keeps
both (summary and suggested_test); the issue export quotes the label in
expected_vs_observed. The issue export and SARIF have no field for a finding's
suggested_test, so the steps are not asserted there; SARIF carries its own
"[UNVERIFIED ... manual verification]" marker instead of the label text.

Control: a SameSite=Lax capture produces no csrf row anywhere. Fault injection:
the retired reflection decision is patched in, the candidate leaves analyze
confirmed, and each export-layer assertion must fail on its own.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from harness import (cache, confirmation_gate, evidence_ledger, report_generator, safety_gate,
                     sarif_adapter, store)
from harness.orchestrator import Orchestrator
from harness.test_csrf_reflection_control import _Reflector, _RetiredDecisionDouble, _capture
from harness.test_engagement_transport_callers import _Model, _config, _install_model
from harness.validators.csrf_validator import CsrfValidator

_COOKIE_AUTH_FORM_WRITE = {"Set-Cookie": "session=s; Path=/"}
_SAMESITE_LAX = {"Set-Cookie": "session=s; Path=/; SameSite=Lax"}
# Values the capture carries that no export may repeat (see _capture).
_CAPTURED_SECRETS = ("abc123", "victim-session")


def _markdown_sections(markdown: str) -> dict[str, str]:
    """'## Heading' -> the text under it ('### ' finding headings stay inside)."""
    return {part.splitlines()[0].strip(): part for part in re.split(r"^## ", markdown, flags=re.M)[1:]}


class CsrfLabelStorageExportTests(unittest.TestCase):
    """The default shared pile (no engagement_id), the Burp default. The named-pile
    class below inherits these tests and re-runs them through the scoped readers."""

    ENGAGEMENT = ""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i04_label_")
        self._orig = (store._DB_PATH, cache._cache)
        self._runs = 0
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    # --- the caller: Orchestrator.analyze over a real store -----------------------
    def _analyze(self, response_headers, *, fault: bool = False):
        """Run one analyze() on a fresh store/cache. `fault` patches the retired
        reflection decision in place of CsrfValidator.validate."""
        self._runs += 1
        store._DB_PATH = Path(self._tmp) / f"state-{self._runs}.db"
        cache.init_cache(db_path=os.path.join(self._tmp, f"cache-{self._runs}.db"))
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()
        self.target = _Reflector()
        self.addCleanup(self.target.close)
        orch = Orchestrator(_config(mutating=False))
        orch.allowed_hosts = ["127.0.0.1"]
        _install_model(orch, _Model([]))
        exchange = _capture(self.target.base).model_copy(update={"response_headers": response_headers})
        self.url = exchange.url
        with ExitStack() as stack:
            stack.enter_context(patch("harness.browser_driver.default_driver", return_value=None))
            if fault:
                stack.enter_context(patch.object(CsrfValidator, "validate", _RetiredDecisionDouble.validate))
            self.response = asyncio.run(orch.analyze(exchange, engagement_id=self.ENGAGEMENT))

    # --- readers: everything below comes back out of SQLite -----------------------
    def _reopen(self):
        """Drop the in-memory evidence; the store opens a fresh connection per call."""
        evidence_ledger.reset_default_ledger()

    def _api(self):
        return [f for r in self.response.agent_reports for f in r.findings if f.vulnerability_class == "csrf"]

    def _stored(self):
        self._reopen()
        return [f for f in store.all_host_findings(self.url, engagement_id=self.ENGAGEMENT)
                if f["vulnerability_class"] == "csrf"]

    def _raw_rows(self):
        """The file itself, bypassing every store reader."""
        conn = sqlite3.connect(str(store._DB_PATH))
        try:
            return conn.execute(
                "SELECT confirmed, severity, confidence, summary, suggested_test FROM findings "
                "WHERE vulnerability_class = 'csrf'").fetchall()
        finally:
            conn.close()

    def _all_issues(self):
        self._reopen()
        return report_generator.export_issues_for_host(self.url, engagement_id=self.ENGAGEMENT)

    def _issues(self):
        return [i for i in self._all_issues() if i["vulnerability_class"] == "csrf"]

    def _sarif(self):
        return sarif_adapter.export_issues_to_sarif(self._all_issues())

    def _sarif_results(self):
        return [r for run in self._sarif()["runs"] for r in run["results"] if r["ruleId"] == "csrf"]

    def _markdown(self):
        self._reopen()
        return report_generator.generate_report_for_host(self.url, engagement_id=self.ENGAGEMENT)

    def _every_export(self) -> str:
        return "\n".join([json.dumps(self._stored()), json.dumps(self._all_issues()),
                          json.dumps(self._sarif()), self._markdown()])

    # --- the label contract, one assertion block per surface ----------------------
    def assert_api_label(self):
        findings = self._api()
        self.assertEqual(len(findings), 1, "the CSRF candidate disappeared")
        f = findings[0]
        self.assertFalse(f.confirmed)
        self.assertEqual(f.severity, "low")
        self.assertLessEqual(f.confidence, 0.3)
        self.assertIn("NEEDS MANUAL CHECK", f.summary)
        self.assertIn("csrf-test.html", f.suggested_test)
        self.assertTrue(f.manual_verification)
        self.assertEqual(f.triage_priority, "manual_verification")

    def assert_stored_label(self):
        rows = self._stored()
        self.assertEqual(len(rows), 1, "the CSRF candidate was not stored")
        row = rows[0]
        self.assertFalse(row["confirmed"])
        self.assertEqual(row["severity"], "low")
        self.assertLessEqual(row["confidence"], 0.3)
        self.assertEqual(row["lifecycle_state"], confirmation_gate.STATE_SUSPECTED)
        self.assertNotEqual(row["proof_status"], "resolved")
        self.assertIn("NEEDS MANUAL CHECK", row["summary"])
        self.assertIn("csrf-test.html", row["suggested_test"])
        # manual_verification is derived, not a column: the same triage the exports use.
        self.assertEqual(confirmation_gate.finding_triage(row)["triage_priority"], "manual_verification")
        raw = self._raw_rows()
        self.assertEqual(len(raw), 1)
        confirmed, severity, confidence, summary, suggested_test = raw[0]
        self.assertEqual((confirmed, severity), (0, "low"))
        self.assertLessEqual(confidence, 0.3)
        self.assertIn("NEEDS MANUAL CHECK", summary)
        self.assertIn("csrf-test.html", suggested_test)

    def assert_issue_label(self):
        issues = self._issues()
        self.assertEqual(len(issues), 1, "the CSRF candidate was not exported as an issue")
        issue = issues[0]
        self.assertFalse(issue["confirmed"])
        self.assertEqual(issue["severity"], "low")
        self.assertLessEqual(issue["confidence"], 0.3)
        self.assertEqual(issue["triage_priority"], "manual_verification")
        self.assertEqual(issue["evidence_maturity"], "unverified")
        self.assertEqual(issue["verification_state"], "candidate")
        self.assertFalse(issue["oracle_verified"])
        self.assertIn("NEEDS MANUAL CHECK", issue["expected_vs_observed"]["observed"])

    def assert_sarif_label(self):
        results = self._sarif_results()
        self.assertEqual(len(results), 1, "the CSRF candidate was not exported to SARIF")
        result = results[0]
        self.assertTrue(result["message"]["text"].startswith("[UNVERIFIED"), result["message"]["text"])
        self.assertIn("manual verification", result["message"]["text"])
        self.assertEqual(result["level"], "note")
        props = result["properties"]
        self.assertEqual(props["observation_type"], "candidate")
        self.assertEqual(props["evidence_maturity"], "unverified")
        self.assertEqual(props["triage_priority"], "manual_verification")
        self.assertEqual(props["originalSeverity"], "low")

    def assert_markdown_label(self):
        markdown = self._markdown()
        sections = _markdown_sections(markdown)
        self.assertNotIn("Confirmed Findings", sections)
        self.assertNotIn("✅ CONFIRMED", markdown)
        self.assertIn("**0 confirmed finding(s)**, **1 unconfirmed finding(s)**", markdown)
        unconfirmed = sections.get("Unconfirmed Findings", "")
        self.assertIn("### csrf --", unconfirmed, "the candidate is not in the unvalidated section")
        block = unconfirmed[unconfirmed.index("### csrf --"):]
        self.assertIn("SUSPECTED (unconfirmed)", block)
        self.assertIn("CANDIDATE (not oracle-verified)", block)
        self.assertRegex(block, r"\*\*Severity:\*\* \S+ LOW\b")
        self.assertLessEqual(float(re.search(r"\*\*Confidence:\*\* ([0-9.]+)", block).group(1)), 0.3)
        self.assertIn("**Triage priority:** manual_verification", block)
        self.assertIn("**Evidence maturity:** unverified", block)
        description = next(line for line in block.splitlines() if line.startswith("**Description:**"))
        self.assertIn("NEEDS MANUAL CHECK", description)
        self.assertIn("**Steps to reproduce:** NEEDS MANUAL CHECK", block)
        self.assertIn("csrf-test.html", block)
        self.assertIn('<form action="', block)

    def assert_no_mutation(self):
        self.assertNotIn(("POST", "/account/email"), self.target.requests)
        self.assertFalse([r for r in self.target.requests if r[0] == "POST"], self.target.requests)

    _SURFACES = ("assert_stored_label", "assert_issue_label", "assert_sarif_label", "assert_markdown_label")

    # --- positive control ---------------------------------------------------------
    def test_candidate_stays_unconfirmed_low_and_manual_on_every_surface(self):
        self._analyze(_COOKIE_AUTH_FORM_WRITE)
        self.assert_api_label()
        for surface in self._SURFACES:
            with self.subTest(surface=surface):
                getattr(self, surface)()
        self.assert_no_mutation()

    def test_exports_repeat_neither_the_captured_token_nor_the_session_cookie(self):
        self._analyze(_COOKIE_AUTH_FORM_WRITE)
        self.assert_stored_label()   # the exports below are about this candidate, not an empty store
        everything = self._every_export()
        for secret in _CAPTURED_SECRETS:
            self.assertNotIn(secret, everything)

    # --- negative control ---------------------------------------------------------
    def test_samesite_lax_capture_leaves_no_csrf_row_in_storage_or_any_export(self):
        # Paired with the identical capture minus the SameSite attribute, so an empty
        # result below cannot be a pipeline that stopped storing or exporting.
        self._analyze(_COOKIE_AUTH_FORM_WRITE)
        self.assertEqual(len(self._stored()), 1)
        self.assertEqual(len(self._issues()), 1)

        self._analyze(_SAMESITE_LAX)
        self.assertEqual(self._api(), [])
        self.assertEqual(self._stored(), [])
        self.assertEqual(self._raw_rows(), [])
        self.assertEqual(self._issues(), [])
        self.assertEqual(self._sarif_results(), [])
        markdown = self._markdown()
        self.assertNotIn("### csrf", markdown)
        self.assertNotIn("NEEDS MANUAL CHECK", markdown)
        self.assertNotIn("csrf-test.html", markdown)
        self.assert_no_mutation()

    # --- fault injection ----------------------------------------------------------
    def test_reinstated_reflection_decision_is_caught_on_each_export_surface(self):
        """The retired decision (tokenless GET, confirm when the response echoes a
        submitted value) is patched in. Against the owned reflector it confirms, so
        the candidate leaves analyze confirmed and must reach every export confirmed
        -- and each label assertion above must then fail on its own."""
        self._analyze(_COOKIE_AUTH_FORM_WRITE, fault=True)

        # The fault took effect at the caller, and what it leaks is visible on each
        # export surface -- so the assertions below fail for the right reason.
        api = self._api()
        self.assertTrue(api and api[0].confirmed, "the injected decision did not confirm at analyze")
        self.assertTrue(self._stored()[0]["confirmed"])
        self.assertTrue(self._issues()[0]["confirmed"])
        self.assertNotEqual(self._sarif_results()[0]["properties"]["observation_type"], "candidate")
        self.assertIn("**1 confirmed finding(s)**", self._markdown())

        with self.assertRaises(AssertionError):
            self.assert_api_label()
        for surface in self._SURFACES:
            with self.subTest(surface=surface), self.assertRaises(AssertionError):
                getattr(self, surface)()


class CsrfLabelNamedPileTests(CsrfLabelStorageExportTests):
    """A named engagement pile: the same label, read back through the scoped readers."""

    ENGAGEMENT = "i04-label-pile"


if __name__ == "__main__":
    unittest.main()
