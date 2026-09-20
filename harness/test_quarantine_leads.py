"""Tests for should_quarantine_as_lead (Item 3 — precision & blind-control sprint).

Covers:
  - The pure predicate in confirmation_gate
  - Caller-level: generate_markdown_report routes quarantined findings into the
    leads bucket and verified findings are NOT quarantined (negative control)
"""
import unittest

from harness.confirmation_gate import should_quarantine_as_lead
from harness.models import Finding


def _finding_dict(
    basis="assumed",
    confirmed=False,
    oracle_verified=False,
    vulnerability_class="idor",
):
    return {
        "vulnerability_class": vulnerability_class,
        "basis": basis,
        "confirmed": confirmed,
        "oracle_verified": oracle_verified,
        "confidence": 0.7,
        "severity": "high",
        "summary": "test",
        "evidence": "",
        "suggested_test": "",
    }


def _finding_obj(**kwargs):
    d = _finding_dict(**kwargs)
    return Finding(
        vulnerability_class=d["vulnerability_class"],
        confidence=d["confidence"],
        summary=d["summary"],
        evidence=d["evidence"],
        suggested_test=d["suggested_test"],
        basis=d["basis"],
        confirmed=d["confirmed"],
        oracle_verified=d["oracle_verified"],
    )


class TestShouldQuarantineAsLead(unittest.TestCase):
    # --- True cases ----------------------------------------------------------

    def test_assumed_live_class_unverified_is_quarantined(self):
        self.assertTrue(should_quarantine_as_lead(_finding_dict(
            basis="assumed", confirmed=False, oracle_verified=False,
            vulnerability_class="idor")))

    def test_recalled_live_class_unverified_is_quarantined(self):
        self.assertTrue(should_quarantine_as_lead(_finding_dict(
            basis="recalled", confirmed=False, oracle_verified=False,
            vulnerability_class="sqli")))

    def test_works_on_finding_object(self):
        f = _finding_obj(basis="assumed", confirmed=False, oracle_verified=False,
                         vulnerability_class="ssrf")
        self.assertTrue(should_quarantine_as_lead(f))

    # --- False cases (negative controls) ------------------------------------

    def test_confirmed_finding_is_not_quarantined(self):
        self.assertFalse(should_quarantine_as_lead(_finding_dict(
            basis="assumed", confirmed=True, oracle_verified=False,
            vulnerability_class="idor")))

    def test_oracle_verified_finding_is_not_quarantined(self):
        self.assertFalse(should_quarantine_as_lead(_finding_dict(
            basis="assumed", confirmed=False, oracle_verified=True,
            vulnerability_class="idor")))

    def test_derived_basis_is_not_quarantined(self):
        self.assertFalse(should_quarantine_as_lead(_finding_dict(
            basis="derived", confirmed=False, oracle_verified=False,
            vulnerability_class="idor")))

    def test_no_leg_class_is_not_quarantined(self):
        # "cors_misconfiguration" has no LIVE leg (leg_tier != "live")
        self.assertFalse(should_quarantine_as_lead(_finding_dict(
            basis="assumed", confirmed=False, oracle_verified=False,
            vulnerability_class="cors_misconfiguration")))

    def test_provisional_class_is_not_quarantined(self):
        # rate_limit is PROVISIONAL (not live-verified) -- should not be quarantined
        self.assertFalse(should_quarantine_as_lead(_finding_dict(
            basis="assumed", confirmed=False, oracle_verified=False,
            vulnerability_class="rate_limit")))


class TestQuarantineReportIntegration(unittest.TestCase):
    """Caller-level: generate_markdown_report splits quarantined findings."""

    def _run(self, findings, quarantine_leads=True):
        from harness.report_generator import generate_markdown_report
        return generate_markdown_report("test.host", findings, quarantine_leads=quarantine_leads)

    def test_quarantined_finding_absent_from_unconfirmed_section(self):
        findings = [_finding_dict(basis="assumed", confirmed=False, oracle_verified=False,
                                  vulnerability_class="idor")]
        report = self._run(findings, quarantine_leads=True)
        self.assertIn("Test Suggestions", report,
                      "quarantined finding should appear in Test Suggestions section")
        self.assertNotIn("## Unconfirmed Findings", report,
                         "quarantined finding should NOT appear under Unconfirmed Findings")

    def test_quarantine_off_leaves_finding_in_unconfirmed(self):
        findings = [_finding_dict(basis="assumed", confirmed=False, oracle_verified=False,
                                  vulnerability_class="idor")]
        report = self._run(findings, quarantine_leads=False)
        self.assertIn("## Unconfirmed Findings", report,
                      "with quarantine off, finding should stay under Unconfirmed Findings")
        self.assertNotIn("Test Suggestions", report)

    def test_verified_finding_not_quarantined(self):
        # Negative control: an oracle-verified finding is NOT quarantined even when quarantine_leads=True
        confirmed_finding = _finding_dict(basis="assumed", confirmed=True, oracle_verified=True,
                                          vulnerability_class="idor")
        report = self._run([confirmed_finding], quarantine_leads=True)
        self.assertNotIn("Test Suggestions", report,
                         "a confirmed+oracle-verified finding must NOT be quarantined")
        self.assertIn("## Confirmed Findings", report)

    def test_same_class_confirmed_not_quarantined_unconfirmed_quarantined(self):
        # Discrimination: two findings of the same live class, one confirmed, one not.
        confirmed = _finding_dict(basis="assumed", confirmed=True, oracle_verified=False,
                                  vulnerability_class="idor")
        unconfirmed = _finding_dict(basis="assumed", confirmed=False, oracle_verified=False,
                                    vulnerability_class="idor")
        report = self._run([confirmed, unconfirmed], quarantine_leads=True)
        self.assertIn("## Confirmed Findings", report)
        self.assertIn("Test Suggestions", report)


if __name__ == "__main__":
    unittest.main()
