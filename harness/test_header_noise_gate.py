"""Tests for the header/config noise gate (critique rec #4): cap CORS/CSP/
clickjacking/missing-header observer findings below the medium operating point,
recall-safe, never deleting a finding."""
import unittest

from harness.models import AgentReport, Finding
import harness.header_noise_gate as g


def _f(vc, severity="medium", confirmed=False):
    return Finding(vulnerability_class=vc, confidence=0.8, summary="s", evidence="e",
                   suggested_test="t", basis="derived", severity=severity, confirmed=confirmed)


def _reports(findings):
    return [AgentReport(agent="a", model="test", findings=findings)]


class ClassMatchTests(unittest.TestCase):
    def test_matches_header_observer_classes(self):
        for vc in ["CORS Misconfiguration", "Content Security Policy (CSP) weakness",
                   "Clickjacking", "Missing Security Headers", "HSTS not set",
                   "X-Frame-Options missing"]:
            self.assertTrue(g.is_header_noise_class(vc), vc)

    def test_does_not_match_high_value_classes(self):
        for vc in ["Insecure Direct Object Reference", "sqli", "SQL Injection",
                   "Information Disclosure", "Security Misconfiguration",
                   "Weak Cryptography", "Server-Side Request Forgery"]:
            self.assertFalse(g.is_header_noise_class(vc), vc)


class GateTests(unittest.TestCase):
    def test_medium_cors_capped_to_low(self):
        reports = _reports([_f("CORS Misconfiguration", "medium")])
        n = g.apply_header_noise_gate(None, reports)
        self.assertEqual(n, 1)
        f = reports[0].findings[0]
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.original_severity, "medium")

    def test_confirmed_cors_is_still_capped(self):
        # The 56/73 Juice Shop case: a CONFIRMED header re-read must not stay medium+.
        reports = _reports([_f("CORS Misconfiguration", "high", confirmed=True)])
        g.apply_header_noise_gate(None, reports)
        self.assertEqual(reports[0].findings[0].severity, "low")

    def test_high_value_finding_untouched(self):
        reports = _reports([_f("sqli", "high"), _f("Insecure Direct Object Reference", "critical")])
        n = g.apply_header_noise_gate(None, reports)
        self.assertEqual(n, 0)
        self.assertEqual(reports[0].findings[0].severity, "high")
        self.assertEqual(reports[0].findings[1].severity, "critical")

    def test_already_low_not_touched_and_not_counted(self):
        reports = _reports([_f("CSP weakness", "low"), _f("Clickjacking", "info")])
        n = g.apply_header_noise_gate(None, reports)
        self.assertEqual(n, 0)
        self.assertEqual(reports[0].findings[0].severity, "low")
        self.assertEqual(reports[0].findings[1].severity, "info")

    def test_recall_safe_no_finding_deleted(self):
        reports = _reports([_f("CORS Misconfiguration", "critical")])
        before = len(reports[0].findings)
        g.apply_header_noise_gate(None, reports)
        self.assertEqual(len(reports[0].findings), before)  # demoted, never removed


if __name__ == "__main__":
    unittest.main()
