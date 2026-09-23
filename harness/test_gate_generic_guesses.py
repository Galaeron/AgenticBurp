"""Tests for confirmation_gate.is_low_confidence_generic_guess (B2-5).

B2-5 gates UNCONFIRMED, low-confidence (< floor) findings in a narrow set of
generic vulnerability classes -- the scorecard's dominant FP driver -- into
the same `leads` bucket generate_markdown_report already builds for
quarantine_unverified_leads. It must NEVER suppress a confirmed finding or a
high-confidence one (hard recall guard), and it ships OFF: with the flag
False, generate_markdown_report's output must be byte-for-byte identical to
before this feature existed.

Covers:
  - The pure predicate in confirmation_gate (positive + negative controls)
  - Caller-level: generate_markdown_report routes matching findings into the
    leads bucket when gate_low_confidence_generic=True
  - Recall guard: confirmed / oracle-verified / high-confidence findings of
    the SAME generic class stay surfaced even with the flag on
  - No-op control: flag off -> output identical to the pre-B2-5 baseline
"""
import unittest

from harness.confirmation_gate import is_low_confidence_generic_guess, DEFAULT_GENERIC_CLASSES
from harness.models import Finding


def _finding_dict(
    vulnerability_class="Security misconfiguration",
    confidence=0.4,
    confirmed=False,
    oracle_verified=False,
    url="https://test.host/api/thing",
    method="GET",
):
    return {
        "url": url,
        "method": method,
        "vulnerability_class": vulnerability_class,
        "basis": "assumed",
        "confirmed": confirmed,
        "oracle_verified": oracle_verified,
        "confidence": confidence,
        "severity": "medium",
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


class TestIsLowConfidenceGenericGuess(unittest.TestCase):
    # --- True cases (positive) ------------------------------------------

    def test_low_confidence_misconfig_is_gated(self):
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.4), floor=0.5))

    def test_low_confidence_access_control_workflow_bypass_is_gated(self):
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="Broken Access Control (Workflow Bypass)", confidence=0.3),
            floor=0.5))

    def test_low_confidence_sqli_is_gated(self):
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="SQL injection", confidence=0.35), floor=0.5))

    def test_works_on_finding_object(self):
        f = _finding_obj(vulnerability_class="Security misconfiguration", confidence=0.2)
        self.assertTrue(is_low_confidence_generic_guess(f, floor=0.5))

    def test_canonical_key_form_also_matches(self):
        # canonicalize("Security misconfiguration") == "misconfig"; the
        # already-canonical spelling must match too.
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="misconfig", confidence=0.1), floor=0.5))

    # --- False cases (negative controls / recall guard) ------------------

    def test_confirmed_finding_never_gated(self):
        self.assertFalse(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.1,
                          confirmed=True),
            floor=0.5))

    def test_oracle_verified_finding_never_gated(self):
        self.assertFalse(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="SQL injection", confidence=0.1,
                          oracle_verified=True),
            floor=0.5))

    def test_high_confidence_finding_not_gated(self):
        self.assertFalse(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.9),
            floor=0.5))

    def test_confidence_at_floor_not_gated(self):
        # Strictly below the floor only -- at-or-above stays surfaced.
        self.assertFalse(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.5),
            floor=0.5))

    def test_non_generic_class_not_gated(self):
        self.assertFalse(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="idor", confidence=0.1), floor=0.5))

    def test_missing_confidence_not_gated(self):
        d = _finding_dict(vulnerability_class="Security misconfiguration")
        d["confidence"] = None
        self.assertFalse(is_low_confidence_generic_guess(d, floor=0.5))

    def test_default_generic_classes_are_narrow(self):
        # Reviewability guard: the default set stays small and explicit.
        self.assertEqual(DEFAULT_GENERIC_CLASSES, frozenset({
            "misconfig", "broken access control (workflow bypass)", "sqli",
        }))


class TestGateGenericGuessesReportIntegration(unittest.TestCase):
    """Caller-level: generate_markdown_report routes gated findings to leads."""

    def _run(self, findings, gate_low_confidence_generic=True, generic_confidence_floor=0.5,
             quarantine_leads=False):
        from harness.report_generator import generate_markdown_report
        return generate_markdown_report(
            "test.host", findings,
            quarantine_leads=quarantine_leads,
            gate_low_confidence_generic=gate_low_confidence_generic,
            generic_confidence_floor=generic_confidence_floor,
        )

    def test_positive_low_confidence_generic_routed_to_leads(self):
        findings = [_finding_dict(vulnerability_class="Security misconfiguration", confidence=0.4,
                                  confirmed=False)]
        report = self._run(findings, gate_low_confidence_generic=True)
        self.assertIn("Test Suggestions", report,
                      "low-confidence generic-class finding should be routed to leads")
        self.assertNotIn("## Unconfirmed Findings", report,
                         "gated finding must not appear under Unconfirmed Findings")

    def test_negative_control_confirmed_and_high_confidence_stay_surfaced(self):
        # Same clean exchange, same generic class: a CONFIRMED finding and a
        # HIGH-CONFIDENCE finding must both stay surfaced with the flag on --
        # the hard recall guard.
        confirmed = _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.4,
                                  confirmed=True, url="https://test.host/api/a")
        high_confidence = _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.9,
                                        confirmed=False, url="https://test.host/api/b")
        low_confidence_guess = _finding_dict(vulnerability_class="Security misconfiguration",
                                             confidence=0.2, confirmed=False,
                                             url="https://test.host/api/c")
        report = self._run([confirmed, high_confidence, low_confidence_guess],
                           gate_low_confidence_generic=True)
        self.assertIn("## Confirmed Findings", report)
        self.assertIn("## Unconfirmed Findings", report,
                      "the high-confidence unconfirmed finding must stay surfaced")
        self.assertIn("Test Suggestions", report,
                      "the low-confidence guess must be routed to leads")

    def test_flag_off_is_byte_for_byte_noop(self):
        # Mixed fixture: confirmed, high-confidence unconfirmed, and a
        # low-confidence generic-class guess that WOULD be gated if the flag
        # were on. With the flag off, output must be identical to calling
        # generate_markdown_report with none of the B2-5 params at all.
        findings = [
            _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.4,
                         confirmed=True, url="https://test.host/api/a"),
            _finding_dict(vulnerability_class="idor", confidence=0.9,
                         confirmed=False, url="https://test.host/api/b"),
            _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.2,
                         confirmed=False, url="https://test.host/api/c"),
            _finding_dict(vulnerability_class="Broken Access Control (Workflow Bypass)", confidence=0.3,
                         confirmed=False, url="https://test.host/api/d"),
        ]
        from harness.report_generator import generate_markdown_report
        baseline = generate_markdown_report("test.host", findings)
        explicit_off = generate_markdown_report(
            "test.host", findings,
            quarantine_leads=False,
            gate_low_confidence_generic=False,
            generic_confidence_floor=0.5,
        )
        gated_off_via_helper = self._run(findings, gate_low_confidence_generic=False)
        self.assertEqual(baseline, explicit_off,
                         "default call must be byte-for-byte identical to an explicit flag-off call")
        self.assertEqual(baseline, gated_off_via_helper)
        self.assertNotIn("Test Suggestions", baseline)
        self.assertIn("## Confirmed Findings", baseline)
        self.assertIn("## Unconfirmed Findings", baseline)

    def test_surfaced_fp_count_drops_with_no_tp_loss(self):
        confirmed = _finding_dict(vulnerability_class="SQL injection", confidence=0.4,
                                  confirmed=True, url="https://test.host/api/tp")
        guesses = [
            _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.1,
                         confirmed=False, url=f"https://test.host/api/fp{i}")
            for i in range(3)
        ]
        from harness.report_generator import generate_markdown_report

        off_report = generate_markdown_report("test.host", [confirmed] + guesses,
                                               gate_low_confidence_generic=False)
        on_report = generate_markdown_report("test.host", [confirmed] + guesses,
                                             gate_low_confidence_generic=True,
                                             generic_confidence_floor=0.5)

        self.assertIn("## Confirmed Findings", off_report)
        self.assertIn("## Confirmed Findings", on_report,
                      "confirmed finding (TP) must survive gating")
        self.assertIn("## Unconfirmed Findings", off_report)
        self.assertNotIn("## Unconfirmed Findings", on_report,
                         "all 3 low-confidence guesses (FPs) should be gated out of surfaced")
        self.assertIn("Test Suggestions", on_report)


if __name__ == "__main__":
    unittest.main()
