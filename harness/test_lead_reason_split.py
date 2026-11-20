"""EFF-5: LEAD is split by why it is LEAD -- refuted (a held negative control said
no) vs untested (a live leg exists but none ran a held negative for this case),
plus rejected-on-review and environment observations.

Before this, a refuted finding and an untested one shared the one LEAD badge and
total, so a report reader could not tell "a check said no" from "nothing ran".
The unit tests pin the mapping and the counts; the caller tests run the real
suppression gate, persist through the real store, and render the real report,
with a refuted finding as the negative control for every untested assertion.
"""
import tempfile
import unittest
from pathlib import Path

import harness.confirmation_gate as cg
from harness import store
from harness.control_outcome import CONTROL_HELD
from harness.models import AgentReport, Finding, HttpExchange, ValidationReport
from harness.report_generator import generate_markdown_report

_URL = "https://target.test/api/items"


def _finding(vc="sqli", **kw):
    return Finding(vulnerability_class=vc, confidence=0.85, severity="high",
                   summary=f"{vc} on /api/items", evidence="e", suggested_test="t",
                   basis="derived", **kw)


class LeadReasonMappingTests(unittest.TestCase):
    def test_each_lead_verdict_has_its_reason(self):
        expected = {"unconfirmed_hypothesis": "refuted", "inconclusive_unverified": "untested",
                    "downgraded": "rejected", "rejected": "rejected",
                    "environment_observation": "environment"}
        for verdict, reason in expected.items():
            self.assertEqual(cg.lead_reason(False, verdict), reason, verdict)
            self.assertEqual(cg.finding_lead_reason({"confirmed": False, "review_verdict": verdict}),
                             reason, verdict)

    def test_every_lead_verdict_is_mapped(self):
        # A new LEAD verdict without a reason would KeyError in lead_reason.
        self.assertEqual(set(cg._LEAD_REASON_BY_VERDICT), set(cg._LEAD_VERDICTS))
        self.assertEqual(set(cg._LEAD_REASON_BY_VERDICT.values()), set(cg.LEAD_REASONS))

    def test_control_confirmed_and_suspected_have_no_lead_reason(self):
        self.assertEqual(cg.lead_reason(True, "unconfirmed_hypothesis"), "")
        for verdict in ("", "survived", "unproven_unverified_leg"):
            self.assertEqual(cg.lead_reason(False, verdict), "", verdict)

    def test_counts_split_lead_by_reason(self):
        findings = [
            {"confirmed": True, "review_verdict": ""},
            {"confirmed": False, "review_verdict": ""},
            {"confirmed": False, "review_verdict": "unconfirmed_hypothesis"},
            {"confirmed": False, "review_verdict": "inconclusive_unverified"},
            _finding(review_verdict="inconclusive_unverified"),
            # The findings API's own reading wins (an unresolved proof cleared it).
            {"confirmed": True, "review_verdict": "", "lifecycle_state": "LEAD",
             "lead_reason": "rejected"},
        ]
        counts = cg.lifecycle_counts(findings)
        self.assertEqual((counts["CONFIRMED"], counts["SUSPECTED"], counts["LEAD"]), (1, 1, 4))
        self.assertEqual(counts["lead_by_reason"],
                         {"refuted": 1, "untested": 2, "rejected": 1, "environment": 0})

    def test_a_lead_without_a_known_reason_counts_as_untested(self):
        counts = cg.lifecycle_counts([{"confirmed": False, "review_verdict": "",
                                       "lifecycle_state": "LEAD", "lead_reason": ""}])
        self.assertEqual(counts["LEAD"], 1)
        self.assertEqual(sum(counts["lead_by_reason"].values()), 1)
        self.assertEqual(counts["lead_by_reason"]["untested"], 1)


class LeadReasonCallerTests(unittest.TestCase):
    """Gate -> store -> findings API -> report, for a held-control negative
    (refuted) and a negative whose control was not reported (untested)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp.name) / "state.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        self._tmp.cleanup()

    def _gate_and_persist(self, outcome, path):
        finding = _finding()
        report = AgentReport(agent="sqli", model="test", findings=[finding])
        cg.apply_confirmation_suppression([report], validation_reports=[ValidationReport(
            validator="sqli", status="not_confirmed", finding_class="sqli", confirmed=False,
            control_outcome=outcome)])
        store.persist_findings(HttpExchange(url=f"{_URL}/{path}", method="GET"), "sqli", [finding])
        return finding

    def _rows(self):
        return {row["url"].rsplit("/", 1)[-1]: row for row in store.all_host_findings(_URL)}

    def test_findings_api_carries_the_lead_reason(self):
        self._gate_and_persist(CONTROL_HELD, "held")
        self._gate_and_persist("", "silent")
        rows = self._rows()
        self.assertEqual((rows["silent"]["lifecycle_state"], rows["silent"]["lead_reason"]),
                         ("LEAD", "untested"))
        # Negative control: the held negative still reads as refuted.
        self.assertEqual((rows["held"]["lifecycle_state"], rows["held"]["lead_reason"]),
                         ("LEAD", "refuted"))

    def test_report_badges_and_totals_split_refuted_from_untested(self):
        self._gate_and_persist(CONTROL_HELD, "held")
        self._gate_and_persist("", "silent")
        md = generate_markdown_report("target.test", store.all_host_findings(_URL))
        self.assertIn("**2 LEAD** (1 refuted by a held negative control, "
                      "1 untested -- no leg ran a held negative)", md)
        sections = {s.split(" -- ", 1)[1].split("\n", 1)[0].rsplit("/", 1)[-1]: s
                    for s in md.split("\n### ")[1:] if " -- " in s}
        self.assertIn("LEAD -- untested", sections["silent"])
        self.assertNotIn("refuted", sections["silent"])
        # Negative control: the refuted finding shows the refuted badge.
        self.assertIn("LEAD -- refuted", sections["held"])
        self.assertNotIn("LEAD -- untested", sections["held"])

    def test_control_report_without_leads_shows_no_split(self):
        store.persist_findings(HttpExchange(url=f"{_URL}/open", method="GET"), "sqli", [_finding()])
        md = generate_markdown_report("target.test", store.all_host_findings(_URL))
        self.assertIn("Lifecycle: **0 CONFIRMED**, **1 SUSPECTED**, **0 LEAD**.", md)

    def test_quarantined_leads_count_in_the_headline_totals(self):
        finding = self._gate_and_persist("", "silent")
        rows = store.all_host_findings(_URL)
        for row in rows:
            row["basis"] = "assumed"  # routed to the quarantined leads bucket
        md = generate_markdown_report("target.test", rows, quarantine_leads=True)
        self.assertIn("quarantined test suggestion", md)
        self.assertIn("**1 LEAD** (1 untested -- no leg ran a held negative)", md)
        self.assertEqual(finding.review_verdict, "inconclusive_unverified")


if __name__ == "__main__":
    unittest.main()
