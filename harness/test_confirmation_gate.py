import unittest
from harness.models import AgentReport, Finding, ValidationReport
from harness.confirmation_gate import is_confirmable_class, apply_confirmation_suppression, leg_tier


def _finding(vc, severity="high", confidence=0.85, confirmed=False):
    return Finding(vulnerability_class=vc, confidence=confidence, severity=severity,
                   summary=f"{vc} on /x", evidence="e", suggested_test="t",
                   basis="derived", confirmed=confirmed)


def _neg(finding_class, validator="v"):
    """A ValidationReport representing a REAL controlled negative: a leg ran and
    returned not_confirmed. This is what earns a REFUTED verdict (R08)."""
    return ValidationReport(validator=validator, status="not_confirmed",
                            finding_class=finding_class, confirmed=False)


def _apply(finding, **kw):
    apply_confirmation_suppression([AgentReport(agent="a", model="test", findings=[finding])], **kw)
    return finding


class TestConfirmationGate(unittest.TestCase):
    def test_is_confirmable_class(self):
        self.assertTrue(is_confirmable_class("idor"))
        self.assertTrue(is_confirmable_class("Insecure Direct Object Reference"))
        self.assertTrue(is_confirmable_class("SQL_INJECTION"))
        self.assertTrue(is_confirmable_class("reflected xss"))
        self.assertTrue(is_confirmable_class("ssrf"))
        self.assertTrue(is_confirmable_class("xml_external_entity"))
        self.assertTrue(is_confirmable_class("jwt algorithm confusion"))
        self.assertTrue(is_confirmable_class("command injection (rce)"))
        self.assertTrue(is_confirmable_class("ssti"))
        self.assertTrue(is_confirmable_class("path_traversal"))
        self.assertTrue(is_confirmable_class("open_redirect"))

        # Non-confirmable classes (no active validation leg)
        self.assertFalse(is_confirmable_class("business_logic"))
        self.assertFalse(is_confirmable_class("information_disclosure"))
        self.assertFalse(is_confirmable_class("missing_security_headers"))
        self.assertFalse(is_confirmable_class(None))
        self.assertFalse(is_confirmable_class(""))

    def test_unconfirmed_idor_no_execution_is_capped_but_not_refuted(self):
        """R08: with NO leg execution, an unconfirmed live-class finding is capped
        for safety (low, <=0.35 -- the precision floor) but labelled UNVERIFIED,
        NOT refuted -- there was no controlled negative to refute it."""
        f = Finding(
            vulnerability_class="idor",
            confidence=0.85,
            severity="high",
            summary="User profile IDOR on /users/2",
            evidence="id=2",
            suggested_test="try id=3",
            basis="derived",
            confirmed=False,
        )
        report = AgentReport(agent="idor", model="test", findings=[f])

        demoted = apply_confirmation_suppression([report])  # no validation_reports
        self.assertEqual(demoted, 1)
        self.assertEqual(f.severity, "low")               # precision floor preserved
        self.assertEqual(f.original_severity, "high")
        self.assertLessEqual(f.confidence, 0.35)
        self.assertEqual(f.original_confidence, 0.85)
        self.assertEqual(f.review_verdict, "inconclusive_unverified")  # not "refuted"
        self.assertTrue(f.summary.startswith("[Unverified] "))

    def test_unconfirmed_idor_with_controlled_negative_is_refuted(self):
        """R08: a REAL controlled negative (a live leg ran, not_confirmed) earns a
        REFUTED verdict."""
        f = _finding("idor", severity="high")
        report = AgentReport(agent="idor", model="test", findings=[f])
        apply_confirmation_suppression([report], validation_reports=[_neg("idor")])
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.review_verdict, "unconfirmed_hypothesis")
        self.assertTrue(f.summary.startswith("[Hypothesis] "))

    def test_leg_error_is_inconclusive_not_refuted(self):
        """R08: a leg that ERRORED (or was skipped) is not a controlled negative --
        the finding stays UNVERIFIED, never labelled a false positive."""
        for status in ("error", "skipped"):
            f = _finding("sql_injection", severity="critical")
            vr = ValidationReport(validator="sqlmap", status=status,
                                  finding_class="sql_injection", confirmed=False)
            apply_confirmation_suppression(
                [AgentReport(agent="sqli", model="test", findings=[f])],
                validation_reports=[vr])
            self.assertEqual(f.severity, "low")                     # still capped (floor)
            self.assertEqual(f.review_verdict, "inconclusive_unverified", status)
            self.assertTrue(f.summary.startswith("[Unverified] "), status)

    def test_confirmed_finding_is_not_demoted(self):
        f = Finding(
            vulnerability_class="idor",
            confidence=0.95,
            severity="high",
            summary="Confirmed user profile IDOR on /users/2",
            evidence="id=2",
            suggested_test="try id=3",
            basis="derived",
            confirmed=True,
        )
        report = AgentReport(agent="idor", model="test", findings=[f])

        demoted = apply_confirmation_suppression([report])
        self.assertEqual(demoted, 0)
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.confidence, 0.95)
        self.assertIsNone(f.original_severity)
        self.assertFalse(f.summary.startswith("[Hypothesis]"))

    def test_non_confirmable_class_is_untouched(self):
        f = Finding(
            vulnerability_class="business_logic",
            confidence=0.80,
            severity="medium",
            summary="Workflow skip on checkout",
            evidence="step=3",
            suggested_test="test",
            basis="derived",
            confirmed=False,
        )
        report = AgentReport(agent="business_logic", model="test", findings=[f])

        demoted = apply_confirmation_suppression([report])
        self.assertEqual(demoted, 0)
        self.assertEqual(f.severity, "medium")
        self.assertEqual(f.confidence, 0.80)


class TestLegAwareThreeState(unittest.TestCase):
    def test_leg_tier(self):
        # live: session-11 legs + Phase-2 live-verified ssti/open_redirect/ssrf/
        # command_injection/mass_assignment + session-15 browser_xss/csrf/verb_tamper.
        for live in ("idor", "SQL_INJECTION", "xxe", "jwt algorithm confusion",
                     "path_traversal", "ssti", "open_redirect", "ssrf",
                     "command injection", "mass_assignment", "reflected xss",
                     "cross-site scripting", "file_upload",
                     # session-16: privilege_escalation promoted (sequence leg
                     # live-verifies the write->re-read priv-esc mechanism).
                     "privilege escalation"):
            self.assertEqual(leg_tier(live), "live", live)
        # provisional: confirmable class whose leg is not yet live-verified, OR whose
        # verdict was RETIRED to an observation (review 2026-09-09): csrf + verb_tamper
        # overconfirmed and were removed from the live set (ORACLE_RETIREMENTS.md).
        for prov in ("rate_limit", "reset_token", "csrf", "verb_tamper", "misconfig"):
            self.assertEqual(leg_tier(prov), "provisional", prov)
        for none in ("business_logic", "information_disclosure", None, ""):
            self.assertEqual(leg_tier(none), "none", none)

    def test_provisional_subclass_not_promoted_by_substring_of_live_class(self):
        """R09: a provisional technique whose NAME contains a live class's name as
        a substring must stay provisional, not inherit "live"."""
        # dom_xss ⊃ "xss" (live); must NOT be promoted to live by that substring.
        self.assertEqual(leg_tier("dom_xss"), "provisional")
        self.assertEqual(leg_tier("DOM-based XSS"), "provisional")
        # "privilege escalation race" ⊃ "privilege escalation" (live) -> provisional
        self.assertEqual(leg_tier("privilege escalation race"), "provisional")
        self.assertEqual(leg_tier("toctou"), "provisional")
        # but the EXACT live classes are unaffected
        self.assertEqual(leg_tier("privilege escalation"), "live")
        self.assertEqual(leg_tier("reflected xss"), "live")
        self.assertEqual(leg_tier("stored xss"), "live")

    def test_explicit_override_still_promotes_provisional_subclass(self):
        """The Phase-2 promotion seam must still work: an explicit override that
        names dom_xss promotes it to live (R09 must not break deliberate promotion)."""
        from harness.confirmation_gate import LIVE_VERIFIED_MARKERS
        self.assertEqual(leg_tier("dom_xss"), "provisional")
        promoted = LIVE_VERIFIED_MARKERS | {"dom_xss"}
        self.assertEqual(leg_tier("dom_xss", live_verified_markers=promoted), "live")

    def test_refuted_live_class_demoted_to_low(self):
        # a live leg ran and returned a controlled negative -> REFUTED (R08)
        f = _apply(_finding("sqli", severity="critical"), validation_reports=[_neg("sqli")])
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.original_severity, "critical")
        self.assertLessEqual(f.confidence, 0.35)
        self.assertEqual(f.review_verdict, "unconfirmed_hypothesis")
        self.assertTrue(f.summary.startswith("[Hypothesis] "))

    def test_unproven_provisional_class_capped_at_medium_not_low(self):
        # A provisional-leg class (leg not live-verified) is kept visible at
        # medium, not buried to low -- recall over a not-yet-trusted silence.
        f = _apply(_finding("rate_limit", severity="high", confidence=0.9))
        self.assertEqual(f.severity, "medium")
        self.assertEqual(f.original_severity, "high")
        self.assertLessEqual(f.confidence, 0.5)
        self.assertGreater(f.confidence, 0.35)  # NOT capped as hard as REFUTED
        self.assertEqual(f.review_verdict, "unproven_unverified_leg")
        self.assertTrue(f.summary.startswith("[Unconfirmed] "))

    def test_provisional_low_severity_unchanged(self):
        f = _apply(_finding("rate_limit", severity="low", confidence=0.3))
        self.assertEqual(f.severity, "low")  # medium cap never RAISES severity

    def test_xss_now_refuted_as_live_verified(self):
        # browser_xss was live-verified in session-15 against vuln_fixture, so an
        # unconfirmed XSS finding WITH a controlled negative is REFUTED (low), not
        # UNPROVEN (medium).
        f = _apply(_finding("reflected xss", severity="high"),
                   validation_reports=[_neg("xss")])
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.review_verdict, "unconfirmed_hypothesis")

    def test_override_promotes_a_provisional_leg_to_refuted(self):
        # rate_limit is still provisional -> UNPROVEN (medium); an operator passes
        # it in the live set to promote to REFUTED (low).
        from harness.confirmation_gate import LIVE_VERIFIED_MARKERS
        base = _apply(_finding("rate_limit", severity="high"))
        self.assertEqual(base.severity, "medium")  # provisional today
        promoted = LIVE_VERIFIED_MARKERS | {"rate_limit"}
        # promoted to live AND a controlled negative present -> REFUTED (R08)
        f = _apply(_finding("rate_limit", severity="high"),
                   live_verified_markers=promoted, validation_reports=[_neg("rate_limit")])
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.review_verdict, "unconfirmed_hypothesis")

    def test_confirmed_untouched_regardless_of_tier(self):
        f = _apply(_finding("reflected xss", severity="high", confirmed=True))
        self.assertEqual(f.severity, "high")
        self.assertIsNone(f.review_verdict)


if __name__ == "__main__":
    unittest.main()
