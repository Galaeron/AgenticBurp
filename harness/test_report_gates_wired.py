"""
Re-analysis pass #2: honor the `reporting.*` surfacing gates on the LIVE report.

`generate_markdown_report` has always accepted `gate_uncorroborated_catchall` /
`gate_low_confidence_generic` / `generic_confidence_floor` /
`quarantine_leads`, but `generate_report_for_host` (what `GET /report` calls)
never forwarded them and no production code read `reporting.gate_*` -- so an
operator who set `reporting.gate_uncorroborated_catchall: true` in
config.local.yaml got an unchanged, noisier live report and no signal the knob
did nothing. `generate_report_for_host` now takes an optional `config` and
forwards those gates.

These tests assert:
  1. POSITIVE: with the gate ON, an uncorroborated catch-all finding
     (security_misconfiguration, unconfirmed) is demoted out of the main
     "Unconfirmed Findings" list into the "Test Suggestions (unverified leads)"
     section.
  2. NEGATIVE CONTROL (default byte-identical): no config / empty config / a
     reporting block at shipped defaults all produce the SAME report, and that
     report keeps the finding in the main list with no leads section -- so the
     default `/report` is unchanged.
  3. RECALL GUARD: even with the gate ON, a concrete-class finding (sqli) is
     never demoted.

Deterministic, offline (temp `store._DB_PATH`); no model/network,
no *ANSWER_KEY*/blind-target content.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness import store, report_generator
from harness.models import HttpExchange, Finding

_LEADS_HEADER = "## Test Suggestions (unverified leads)"
_UNCONFIRMED_HEADER = "## Unconfirmed Findings"


class ReportGatesWiredTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_report_gates.db"
        self.url = "https://gates.example.com/api/x"
        # An uncorroborated catch-all guess (unconfirmed misconfig) -- the
        # class the gate demotes -- plus a concrete sqli the gate must never
        # touch (recall guard).
        self._seed("security_misconfiguration", "misconfig guess summary", case_id="c-mis")
        self._seed("sqli", "sqli concrete summary", case_id="c-sqli")

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _seed(self, vuln_class: str, summary: str, *, case_id: str) -> None:
        exchange = HttpExchange(
            url=self.url, method="GET", request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
        )
        finding = Finding(
            vulnerability_class=vuln_class, confidence=0.9, summary=summary,
            evidence="e", suggested_test="t", basis="assumed",
            case_id=case_id, finding_id=f"{case_id}-fid", proof_id=f"{case_id}-pid",
        )
        store.persist_findings(exchange, "test_agent", [finding])

    def test_gate_on_demotes_catchall_to_leads(self):
        report = report_generator.generate_report_for_host(
            self.url, config={"reporting": {"gate_uncorroborated_catchall": True}})
        self.assertIn(_LEADS_HEADER, report)
        # The misconfig guess is under the leads section, not the main list.
        leads_part = report.split(_LEADS_HEADER, 1)[1]
        self.assertIn("misconfig guess summary", leads_part)
        # Recall guard: the concrete sqli finding is NOT demoted.
        unconfirmed_part = report.split(_UNCONFIRMED_HEADER, 1)[1].split(_LEADS_HEADER)[0]
        self.assertIn("sqli concrete summary", unconfirmed_part)
        self.assertNotIn("misconfig guess summary", unconfirmed_part)

    def test_default_is_byte_identical_across_no_empty_and_default_config(self):
        no_config = report_generator.generate_report_for_host(self.url)
        empty_config = report_generator.generate_report_for_host(self.url, config={})
        default_reporting = report_generator.generate_report_for_host(
            self.url, config={"reporting": {"gate_uncorroborated_catchall": False,
                                            "gate_low_confidence_generic": False,
                                            "generic_confidence_floor": 0.5,
                                            "quarantine_unverified_leads": False}})
        self.assertEqual(no_config, empty_config)
        self.assertEqual(no_config, default_reporting)
        # Default report: no leads section, both findings in the main list.
        self.assertNotIn(_LEADS_HEADER, no_config)
        self.assertIn("misconfig guess summary", no_config)
        self.assertIn("sqli concrete summary", no_config)

    def test_gate_on_changes_the_report_vs_default(self):
        # Non-vacuousness: the flag actually takes effect on the live report.
        default = report_generator.generate_report_for_host(self.url)
        gated = report_generator.generate_report_for_host(
            self.url, config={"reporting": {"gate_uncorroborated_catchall": True}})
        self.assertNotEqual(default, gated)


if __name__ == "__main__":
    unittest.main()
