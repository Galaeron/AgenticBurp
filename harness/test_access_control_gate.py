"""Tests for the deterministic access-control response gate."""
import unittest

from harness.models import HttpExchange, AgentReport, Finding
from harness.access_control_gate import apply_access_control_response_gate, _CAPPED_CONFIDENCE


def _ex(status):
    return HttpExchange(url="http://t/api/tickets/1", method="GET", response_status=status)


def _rep(vuln_class, conf):
    return AgentReport(agent="idor", model="m", findings=[Finding(
        vulnerability_class=vuln_class, confidence=conf, severity="medium",
        summary="s", evidence="e", suggested_test="t", basis="derived")])


class AccessControlGateTests(unittest.TestCase):
    def test_idor_capped_on_403(self):
        reps = [_rep("insecure_direct_object_reference", 0.9)]
        n = apply_access_control_response_gate(_ex(403), reps)
        self.assertEqual(n, 1)
        f = reps[0].findings[0]
        self.assertEqual(f.confidence, _CAPPED_CONFIDENCE)
        self.assertEqual(f.original_confidence, 0.9)
        self.assertEqual(f.review_verdict, "downgraded")
        self.assertIn("403", f.review_note)

    def test_prose_class_and_405_capped(self):
        reps = [_rep("function-level authorization at the api layer", 0.8)]
        self.assertEqual(apply_access_control_response_gate(_ex(405), reps), 1)
        self.assertEqual(reps[0].findings[0].confidence, _CAPPED_CONFIDENCE)

    def test_401_capped(self):
        reps = [_rep("Broken Access Control", 0.7)]
        self.assertEqual(apply_access_control_response_gate(_ex(401), reps), 1)

    def test_200_not_touched(self):
        # The real IDOR case: cross-user request that SUCCEEDED -> untouched.
        reps = [_rep("insecure_direct_object_reference", 0.85)]
        self.assertEqual(apply_access_control_response_gate(_ex(200), reps), 0)
        self.assertEqual(reps[0].findings[0].confidence, 0.85)

    def test_404_is_ambiguous_not_gated(self):
        reps = [_rep("idor", 0.8)]
        self.assertEqual(apply_access_control_response_gate(_ex(404), reps), 0)

    def test_non_access_control_class_untouched_on_denial(self):
        # An XSS or misconfig finding on a 403 is unrelated to this gate.
        reps = [_rep("Cross-site scripting (reflected)", 0.9)]
        self.assertEqual(apply_access_control_response_gate(_ex(403), reps), 0)
        self.assertEqual(reps[0].findings[0].confidence, 0.9)

    def test_already_low_confidence_not_re_annotated(self):
        reps = [_rep("idor", 0.1)]
        self.assertEqual(apply_access_control_response_gate(_ex(403), reps), 0)
        self.assertIsNone(reps[0].findings[0].original_confidence)


if __name__ == "__main__":
    unittest.main()
