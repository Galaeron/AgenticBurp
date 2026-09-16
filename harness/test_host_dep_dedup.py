"""Tests for the Phase 1.2 host-dependency policy (host_dep_dedup).

The passive-banner classification and severity cap were previously asserted with
test-local logic inside test_blind_negatives; they now live in harness code and
are exercised here by calling that code directly."""
import unittest

from harness.host_dep_dedup import is_passive_banner, cap_passive_banner_severity


class PassiveBannerClassificationTests(unittest.TestCase):
    def test_response_banner_sources_are_passive(self):
        for src in ("Server header", "response headers", "X-Powered-By",
                    "Via header", "Server"):
            self.assertTrue(is_passive_banner(src), src)

    def test_active_sources_are_not_passive(self):
        for src in ("package.json body", "exposed lockfile", "composer.json",
                    "fetched /package.json", ""):
            self.assertFalse(is_passive_banner(src), src)

    def test_none_source_is_not_passive(self):
        self.assertFalse(is_passive_banner(None))


class SeverityCapTests(unittest.TestCase):
    def test_passive_medium_and_high_capped_to_low(self):
        self.assertEqual(cap_passive_banner_severity("medium", True), "low")
        self.assertEqual(cap_passive_banner_severity("high", True), "low")

    def test_passive_critical_not_capped(self):
        # Matches pre-extraction behavior: a disclosed critical is not silently
        # demoted; KEV escalation is a separate, caller-applied path.
        self.assertEqual(cap_passive_banner_severity("critical", True), "critical")

    def test_passive_low_unchanged(self):
        self.assertEqual(cap_passive_banner_severity("low", True), "low")
        self.assertEqual(cap_passive_banner_severity("info", True), "info")

    def test_active_component_severity_untouched(self):
        # A served-manifest (non-passive) component keeps its advisory severity.
        self.assertEqual(cap_passive_banner_severity("high", False), "high")
        self.assertEqual(cap_passive_banner_severity("medium", False), "medium")

    def test_werkzeug_server_banner_high_advisory_caps_to_low(self):
        # The exact case the blind-negative test used to assert inline: a
        # Werkzeug version from a Server banner with a "high" advisory ships low.
        passive = is_passive_banner("Server header")
        self.assertTrue(passive)
        self.assertEqual(cap_passive_banner_severity("high", passive), "low")


if __name__ == "__main__":
    unittest.main()
