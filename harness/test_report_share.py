"""SC-15: evidence-first report polish + retest classification.

Covers the four acceptance criteria, each with a positive case AND a negative
control:

  1. all formats agree on reportable issues (SC-5 parity)   (FormatParityTests)
  2. unproved prose never changes verification state        (VerificationStateTests)
  3. secret-canary fixtures stay redacted                   (RedactionTests)
  4. stable issue IDs survive export and a patched-fixture retest
                                                             (RetestClassificationTests)
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from harness import issues, report_generator, report_share
from harness.report_share import RetestOutcome


def _finding(*, vc="sqli", url="http://shop.test/orders", method="POST",
             confirmed=False, oracle_verified=False, verification_state="candidate",
             case_id="c1", proof_id="p1", severity="high", confidence=0.9,
             evidence="parameter id altered the query result", summary="",
             finding_id="f1", parameter_name="id", parameter_location="body_json",
             basis="observed"):
    return {
        "vulnerability_class": vc, "url": url, "method": method,
        "confirmed": confirmed, "oracle_verified": oracle_verified,
        "verification_state": verification_state, "case_id": case_id, "proof_id": proof_id,
        "severity": severity, "confidence": confidence, "evidence": evidence,
        "summary": summary or evidence, "finding_id": finding_id,
        "parameter_name": parameter_name, "parameter_location": parameter_location,
        "basis": basis,
    }


def _issue_id(finding):
    return issues.issue_id_for(issues.issue_key(finding))


# --------------------------------------------------------------------------
# Criterion 1: all formats agree on reportable issues (SC-5 parity)
# --------------------------------------------------------------------------
class FormatParityTests(unittest.TestCase):
    def test_html_and_http_render_exactly_the_exported_issue_ids(self):
        findings = [
            _finding(vc="sqli", finding_id="f1"),
            _finding(vc="xss", url="http://shop.test/search", method="GET",
                     parameter_name="q", parameter_location="query", finding_id="f2"),
        ]
        exports = report_generator.issue_exports(findings)
        ids = report_share.reportable_issue_ids(exports)
        html = report_share.render_offline_html(exports, host="shop.test")
        http = report_share.render_http_exports(exports, host="shop.test")
        for iid in ids:
            self.assertIn(iid, html)
            self.assertIn(iid, http)
        # Exactly len(exports) issues rendered -- no extras, none dropped.
        self.assertEqual(html.count('<section class="issue">'), len(exports))
        self.assertEqual(http.count("### issue "), len(exports))

    def test_sc5_gate_omits_the_same_lead_from_every_format(self):
        solid = _finding(vc="sqli", confirmed=True, confidence=0.9, finding_id="fsolid",
                         url="http://shop.test/orders")
        lead = _finding(vc="Security misconfiguration", confirmed=False, oracle_verified=False,
                        confidence=0.2, finding_id="flead", url="http://shop.test/x",
                        method="GET", parameter_name="", parameter_location="")
        gate_cfg = {"reporting": {"gate_low_confidence_generic": True,
                                  "generic_confidence_floor": 0.9}}
        with patch("harness.store.all_host_findings", return_value=[solid, lead]), \
                patch("harness.store.proofs_for_case", return_value=[]), \
                patch("harness.store.all_issue_merges", return_value={}), \
                patch("harness.store.host_of", return_value="shop.test"):
            ungated = report_generator.export_issues_for_host("http://shop.test/")
            gated = report_generator.export_issues_for_host("http://shop.test/", config=gate_cfg)

        ungated_ids = set(report_share.reportable_issue_ids(ungated))
        gated_ids = set(report_share.reportable_issue_ids(gated))
        self.assertIn(_issue_id(solid), gated_ids)          # solid finding survives the gate
        self.assertNotIn(_issue_id(lead), gated_ids)        # low-confidence generic lead demoted
        self.assertTrue(gated_ids < ungated_ids)            # strict subset -> the gate removed one

        html = report_share.render_offline_html(gated)
        http = report_share.render_http_exports(gated)
        self.assertIn(_issue_id(solid), html)
        self.assertIn(_issue_id(solid), http)
        self.assertNotIn(_issue_id(lead), html)             # gated lead absent from every format
        self.assertNotIn(_issue_id(lead), http)


# --------------------------------------------------------------------------
# Criterion 2: unproved prose never changes verification state
# --------------------------------------------------------------------------
class VerificationStateTests(unittest.TestCase):
    def test_self_claimed_verified_without_proof_renders_as_candidate(self):
        # A finding that CLAIMS verified with assertive prose but has no backing
        # proof must export -- and render -- as candidate (audited, not trusted).
        claimed = _finding(vc="sqli", oracle_verified=True, verification_state="verified",
                           confirmed=False,
                           evidence="CONFIRMED CRITICAL: definitely a verified RCE, trust me",
                           summary="VERIFIED CRITICAL")
        exports = report_generator.issue_exports([claimed])  # no proofs supplied
        self.assertEqual(exports[0]["verification_state"], "candidate")
        self.assertFalse(exports[0]["oracle_verified"])
        html = report_share.render_offline_html(exports)
        # The rendered badge is candidate, not verified (CSS class defs, which
        # always list both, are '.b-verified{' -- distinct from a badge span).
        self.assertIn('badge b-candidate">candidate', html)
        self.assertNotIn('badge b-verified', html)  # no "verified" badge span is rendered

    def test_html_escapes_finding_text(self):
        exports = report_generator.issue_exports([_finding(
            vc="xss", evidence="<script>alert('pwn')</script>")])
        html = report_share.render_offline_html(exports)
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)


# --------------------------------------------------------------------------
# Criterion 3: secret-canary fixtures stay redacted
# --------------------------------------------------------------------------
class RedactionTests(unittest.TestCase):
    def test_secret_canary_never_appears_in_any_format(self):
        canary = "CANARYSECRET7f3a9deadbeef"
        finding = _finding(
            vc="sqli", url=f"http://shop.test/orders?token={canary}",
            evidence=f"escalated using Authorization: Bearer {canary} on the request",
            summary=f"leaked Cookie: session={canary}")
        exports = report_generator.issue_exports([finding])
        html = report_share.render_offline_html(exports)
        http = report_share.render_http_exports(exports)
        self.assertNotIn(canary, html)
        self.assertNotIn(canary, http)
        # Sanity: the issue itself is still present (redaction, not omission).
        self.assertIn(exports[0]["issue_id"], html)


# --------------------------------------------------------------------------
# .http shape
# --------------------------------------------------------------------------
class HttpExportShapeTests(unittest.TestCase):
    def test_http_block_is_importable_shape(self):
        exports = report_generator.issue_exports([_finding(vc="sqli", method="POST")])
        http = report_share.render_http_exports(exports, host="shop.test")
        self.assertIn(f"### issue {exports[0]['issue_id']}", http)
        self.assertRegex(http, r"(?m)^POST https?://")
        self.assertIn("Authorization: <<SESSION:", http)  # placeholder, never a real secret

    def test_empty_exports_render_cleanly(self):
        self.assertIn("No reportable issues", report_share.render_offline_html([]))
        self.assertIn("No reportable issues", report_share.render_http_exports([]))


# --------------------------------------------------------------------------
# Criterion 4: stable issue IDs survive export + a patched-fixture retest
# --------------------------------------------------------------------------
class RetestClassificationTests(unittest.TestCase):
    def _export(self, finding, verdict=None):
        proofs = {finding["case_id"]: [{"proof_id": finding["proof_id"], "verdict": verdict}]} \
            if verdict is not None else None
        return report_generator.issue_exports([finding], proofs_by_case=proofs)[0]

    def test_issue_id_is_stable_across_a_patched_retest(self):
        original = self._export(_finding(case_id="c1", finding_id="f1", confirmed=True), "confirmed")
        # Patched retest: SAME coordinates, NEW case/proof/finding ids.
        retest = self._export(_finding(case_id="c2", proof_id="p2", finding_id="f2",
                                       confirmed=False), "controlled_negative")
        self.assertEqual(original["issue_id"], retest["issue_id"])  # stable id survives retest

    def test_patched_retest_classifies_fixed(self):
        original = self._export(_finding(case_id="c1", confirmed=True), "confirmed")
        retest = self._export(_finding(case_id="c2", proof_id="p2", confirmed=False),
                              "controlled_negative")
        [result] = report_share.classify_retests([original], [retest])
        self.assertEqual(result.outcome, RetestOutcome.FIXED)
        self.assertEqual(result.issue_id, original["issue_id"])
        self.assertTrue(result.covered)

    def test_still_vulnerable_retest_classifies_still_vulnerable(self):
        original = self._export(_finding(case_id="c1", confirmed=True), "confirmed")
        retest = self._export(_finding(case_id="c2", proof_id="p2", confirmed=True), "confirmed")
        [result] = report_share.classify_retests([original], [retest])
        self.assertEqual(result.outcome, RetestOutcome.STILL_VULNERABLE)

    def test_blocked_or_error_retest_is_inconclusive_not_fixed(self):
        original = self._export(_finding(case_id="c1", confirmed=True), "confirmed")
        retest = self._export(_finding(case_id="c2", proof_id="p2", confirmed=False), "blocked")
        [result] = report_share.classify_retests([original], [retest])
        self.assertEqual(result.outcome, RetestOutcome.INCONCLUSIVE)  # never "fixed" on a blocked control

    def test_uncovered_issue_classifies_not_run(self):
        original = self._export(_finding(case_id="c1", confirmed=True), "confirmed")
        [result] = report_share.classify_retests([original], [])  # retest run covered nothing
        self.assertEqual(result.outcome, RetestOutcome.NOT_RUN)
        self.assertFalse(result.covered)
        self.assertEqual(result.issue_id, original["issue_id"])


if __name__ == "__main__":
    unittest.main()
