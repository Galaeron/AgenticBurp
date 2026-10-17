"""Tests for confirmation_gate.is_low_confidence_generic_guess (B2-5) and
confirmation_gate.is_uncorroborated_catchall_guess (FR-4, 2026-09-25).

B2-5 gates UNCONFIRMED, low-confidence (< floor) findings in a narrow set of
generic vulnerability classes -- the scorecard's dominant FP driver -- into
the same `leads` bucket generate_markdown_report already builds for
quarantine_unverified_leads. It must NEVER suppress a confirmed finding or a
high-confidence one (hard recall guard), and it ships OFF: with the flag
False, generate_markdown_report's output must be byte-for-byte identical to
before this feature existed.

FR-4 fixes two linked defects verified by an offline re-score of captured
benchmark findings: (a) the generic-class gate's normalization missed the
model's actual dominant spellings (snake_case `security_misconfiguration`,
and every `info_disclosure` variant) because `categories.canonicalize()`
didn't fold them and the raw-lowercase fallback didn't match either; (b)
confidence is the wrong lever for these two catch-all classes specifically
(most already sit at confidence >= 0.5) -- the measured effective lever is
requiring a confirming leg (confirmed OR oracle_verified) before a
`misconfig`/`info_disclosure` finding is surfaced, regardless of confidence.
`is_uncorroborated_catchall_guess` implements that, gated behind the
separate, OFF-by-default `gate_uncorroborated_catchall` flag.

Covers:
  - The pure predicates in confirmation_gate (positive + negative controls)
  - Normalization: snake_case/compound spelling variants now resolve to the
    same canonical key as their already-working spaced/hyphenated forms
  - Caller-level: generate_markdown_report routes matching findings into the
    leads bucket when gate_low_confidence_generic=True /
    gate_uncorroborated_catchall=True
  - Recall guard: confirmed / oracle-verified / high-confidence findings of
    the SAME generic class stay surfaced even with the flag on
  - NEGATIVE CONTROL: concrete classes (sqli/xss/path_traversal) are NEVER
    gated by is_uncorroborated_catchall_guess -- no global leg requirement
  - No-op control: flag off -> output identical to the pre-feature baseline
"""
import unittest

from harness.categories import canonicalize
from harness.confirmation_gate import (
    is_low_confidence_generic_guess, DEFAULT_GENERIC_CLASSES,
    is_uncorroborated_catchall_guess, DEFAULT_CATCHALL_CLASSES,
)
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
        # FR-4 (2026-09-25): info_disclosure joins the set now that its
        # spelling variants actually fold to one canonical key -- see
        # TestGenericClassNormalizationFR4 below.
        self.assertEqual(DEFAULT_GENERIC_CLASSES, frozenset({
            "misconfig", "broken access control (workflow bypass)", "sqli",
            "info_disclosure",
        }))

    # --- FR-4 normalization: the model's actual dominant spellings ---------

    def test_snake_case_security_misconfiguration_is_gated(self):
        # Verified defect: canonicalize("security_misconfiguration") used to
        # return None (only the space-spelled form matched), so this, the
        # SINGLE MOST COMMON FP label in the captured benchmark runs (35x),
        # fell straight through the old gate untouched.
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="security_misconfiguration", confidence=0.4), floor=0.5))

    def test_information_disclosure_snake_case_is_gated(self):
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="information_disclosure", confidence=0.4), floor=0.5))

    def test_verbose_error_disclosure_is_gated(self):
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="verbose_error_disclosure", confidence=0.2), floor=0.5))

    def test_excessive_data_exposure_is_gated(self):
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="excessive_data_exposure", confidence=0.1), floor=0.5))

    def test_exposure_of_internal_data_is_gated(self):
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="exposure_of_internal_data", confidence=0.3), floor=0.5))

    def test_exposure_of_sensitive_information_is_gated(self):
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="exposure_of_sensitive_information", confidence=0.3),
            floor=0.5))

    def test_information_disclosure_header_is_gated(self):
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="information_disclosure_header", confidence=0.3),
            floor=0.5))

    def test_title_case_information_disclosure_is_gated(self):
        self.assertTrue(is_low_confidence_generic_guess(
            _finding_dict(vulnerability_class="Information Disclosure", confidence=0.4), floor=0.5))

    def test_ambiguous_owasp_heading_still_returns_none(self):
        # MUST still hold after the FR-4 synonym additions -- canonicalize()'s
        # "return None rather than guess" guarantee for a genuinely ambiguous
        # OWASP Top 10 heading is untouched by this change.
        self.assertIsNone(canonicalize("Broken Access Control"))


class TestIsUncorroboratedCatchallGuess(unittest.TestCase):
    """Pure-predicate tests for confirmation_gate.is_uncorroborated_catchall_guess
    (FR-4): unlike is_low_confidence_generic_guess, this ignores confidence
    entirely -- the two catch-all classes sit at confidence >= 0.5 far too
    often for a confidence floor to be an effective lever (measured: 86/96
    misconfig + 65/76 info-disclosure findings in the captured benchmark runs).
    """

    def test_default_catchall_classes_are_narrow(self):
        self.assertEqual(DEFAULT_CATCHALL_CLASSES, frozenset({"misconfig", "info_disclosure"}))

    # --- True cases: HIGH confidence (0.9) proves confidence is bypassed ---

    def test_snake_case_misconfig_at_high_confidence_is_gated(self):
        self.assertTrue(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="security_misconfiguration", confidence=0.9)))

    def test_spaced_misconfig_at_high_confidence_is_gated(self):
        self.assertTrue(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.9)))

    def test_information_disclosure_at_high_confidence_is_gated(self):
        self.assertTrue(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="information_disclosure", confidence=0.9)))

    def test_verbose_error_disclosure_at_high_confidence_is_gated(self):
        self.assertTrue(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="verbose_error_disclosure", confidence=0.9)))

    def test_excessive_data_exposure_at_high_confidence_is_gated(self):
        self.assertTrue(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="excessive_data_exposure", confidence=0.9)))

    def test_works_on_finding_object(self):
        f = _finding_obj(vulnerability_class="security_misconfiguration", confidence=0.9)
        self.assertTrue(is_uncorroborated_catchall_guess(f))

    # --- False cases: corroboration survives (hard recall guard) -----------

    def test_confirmed_misconfig_survives(self):
        self.assertFalse(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="security_misconfiguration", confidence=0.9,
                          confirmed=True)))

    def test_oracle_verified_info_disclosure_survives(self):
        self.assertFalse(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="information_disclosure", confidence=0.9,
                          oracle_verified=True)))

    # --- NEGATIVE CONTROL: no global leg requirement ------------------------

    def test_unconfirmed_sqli_is_never_gated(self):
        self.assertFalse(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="sqli", confidence=0.9)))

    def test_unconfirmed_xss_is_never_gated(self):
        self.assertFalse(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="xss", confidence=0.9)))

    def test_unconfirmed_path_traversal_is_never_gated(self):
        self.assertFalse(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="path_traversal", confidence=0.9)))

    def test_unconfirmed_idor_is_never_gated(self):
        self.assertFalse(is_uncorroborated_catchall_guess(
            _finding_dict(vulnerability_class="idor", confidence=0.1)))


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


class TestGateUncorroboratedCatchallReportIntegration(unittest.TestCase):
    """Caller-level (FR-4): generate_markdown_report routes
    gate_uncorroborated_catchall-matching findings to leads -- mirrors
    TestGateGenericGuessesReportIntegration above for the new predicate."""

    def _run(self, findings, gate_uncorroborated_catchall=True, quarantine_leads=False,
             gate_low_confidence_generic=False):
        from harness.report_generator import generate_markdown_report
        return generate_markdown_report(
            "test.host", findings,
            quarantine_leads=quarantine_leads,
            gate_low_confidence_generic=gate_low_confidence_generic,
            gate_uncorroborated_catchall=gate_uncorroborated_catchall,
        )

    def test_positive_high_confidence_catchall_guesses_routed_to_leads(self):
        # Confidence 0.9 on BOTH catch-all classes, several spelling variants
        # -- proves the new gate ignores confidence entirely (the point of
        # this predicate: a confidence floor barely reaches these classes).
        findings = [
            _finding_dict(vulnerability_class="security_misconfiguration", confidence=0.9,
                         confirmed=False, url="https://test.host/api/a"),
            _finding_dict(vulnerability_class="Security misconfiguration", confidence=0.9,
                         confirmed=False, url="https://test.host/api/b"),
            _finding_dict(vulnerability_class="information_disclosure", confidence=0.9,
                         confirmed=False, url="https://test.host/api/c"),
            _finding_dict(vulnerability_class="verbose_error_disclosure", confidence=0.9,
                         confirmed=False, url="https://test.host/api/d"),
            _finding_dict(vulnerability_class="excessive_data_exposure", confidence=0.9,
                         confirmed=False, url="https://test.host/api/e"),
        ]
        report = self._run(findings, gate_uncorroborated_catchall=True)
        self.assertIn("Test Suggestions", report)
        self.assertIn("**5 quarantined test suggestion(s)**", report)
        self.assertNotIn("## Unconfirmed Findings", report,
                         "all high-confidence catch-all guesses must be routed to leads")

    def test_negative_control_confirmed_and_oracle_verified_survive(self):
        confirmed = _finding_dict(vulnerability_class="security_misconfiguration", confidence=0.9,
                                  confirmed=True, url="https://test.host/api/a")
        oracle_verified = _finding_dict(vulnerability_class="information_disclosure", confidence=0.9,
                                        oracle_verified=True, url="https://test.host/api/b")
        report = self._run([confirmed, oracle_verified], gate_uncorroborated_catchall=True)
        self.assertIn("## Confirmed Findings", report)
        self.assertIn("## Unconfirmed Findings", report,
                      "the oracle-verified finding must stay surfaced (not confirmed, but corroborated)")
        self.assertNotIn("Test Suggestions", report)

    def test_negative_control_concrete_classes_still_surfaced_no_global_leg_requirement(self):
        # CRITICAL negative control: with the flag ON, unconfirmed
        # sqli/xss/path_traversal findings on a clean exchange are STILL
        # surfaced. Only the two catch-all classes are gated -- FR-4
        # explicitly forbids a global leg requirement (measured to collapse
        # recall to 0.05).
        findings = [
            _finding_dict(vulnerability_class="sqli", confidence=0.9, confirmed=False,
                         url="https://test.host/api/sqli"),
            _finding_dict(vulnerability_class="xss", confidence=0.9, confirmed=False,
                         url="https://test.host/api/xss"),
            _finding_dict(vulnerability_class="path_traversal", confidence=0.9, confirmed=False,
                         url="https://test.host/api/pt"),
        ]
        report = self._run(findings, gate_uncorroborated_catchall=True)
        self.assertIn("## Unconfirmed Findings", report,
                      "concrete-class findings must stay surfaced -- no global leg requirement")
        self.assertNotIn("Test Suggestions", report)

    def test_flag_off_is_byte_for_byte_noop(self):
        # With the flag off (the shipped default), output must be identical
        # to a call that never mentions gate_uncorroborated_catchall at all --
        # the new predicate must gate NOTHING when its flag is False.
        findings = [
            _finding_dict(vulnerability_class="security_misconfiguration", confidence=0.9,
                         confirmed=True, url="https://test.host/api/a"),
            _finding_dict(vulnerability_class="idor", confidence=0.9,
                         confirmed=False, url="https://test.host/api/b"),
            _finding_dict(vulnerability_class="security_misconfiguration", confidence=0.9,
                         confirmed=False, url="https://test.host/api/c"),
            _finding_dict(vulnerability_class="information_disclosure", confidence=0.9,
                         confirmed=False, url="https://test.host/api/d"),
        ]
        from harness.report_generator import generate_markdown_report
        baseline = generate_markdown_report("test.host", findings)
        explicit_off = generate_markdown_report(
            "test.host", findings,
            quarantine_leads=False,
            gate_low_confidence_generic=False,
            generic_confidence_floor=0.5,
            gate_uncorroborated_catchall=False,
        )
        gated_off_via_helper = self._run(findings, gate_uncorroborated_catchall=False)
        self.assertEqual(baseline, explicit_off,
                         "default call must be byte-for-byte identical to an explicit flag-off call")
        self.assertEqual(baseline, gated_off_via_helper)
        self.assertNotIn("Test Suggestions", baseline)
        self.assertIn("## Confirmed Findings", baseline)
        self.assertIn("## Unconfirmed Findings", baseline,
                      "with the flag off, the two unconfirmed catch-all guesses must stay surfaced")


if __name__ == "__main__":
    unittest.main()
