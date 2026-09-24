"""Per-sink secret-canary tests (NC-4, R09 residual).

PR-9 wired secret redaction into the model-prompt path and made audit sanitization
recursive. NC-4 asserts the SAME guarantee holds at every other place engagement
data can egress or persist -- headers, URL, body (incl. nested), the audit event
sink, and the Markdown report export -- by driving a synthetic secret CANARY through
each real sink function and asserting it is gone, while a NEGATIVE-control injection
PAYLOAD in a non-secret field (q=/search=) survives verbatim (redaction is
secret-NAME-scoped, not blanket, so it must never eat a SQLi/XSS payload).

This run also covers the report chains section, whose evidence/suggested_test reached
the export unredacted before this change (the individual-finding path already masked
the same fields) -- see report_generator._render_finding vs the chains loop.

Offline, deterministic. No model, target, or network.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from harness import security, issues
from harness.audit_logger import AuditLogger
from harness.report_generator import generate_markdown_report

# One canary per surface, and one injection payload used as the negative control.
CANARY = "CANARY_SECRET_9f3a"
PAYLOAD = "<script>alert(1)</script>"       # a non-secret-field injection payload


class HeaderSinkTests(unittest.TestCase):
    def test_authorization_and_cookie_redacted_custom_header_kept(self):
        out = security.redact_headers({
            "Authorization": f"Bearer {CANARY}",
            "Cookie": f"session={CANARY}",
            "X-Trace-Id": "keep-this-non-secret",
        })
        blob = json.dumps(out)
        self.assertNotIn(CANARY, blob)
        self.assertIn("keep-this-non-secret", blob)


class UrlSinkTests(unittest.TestCase):
    def test_secret_param_redacted_query_payload_survives(self):
        url = f"http://target.invalid/x?api_key={CANARY}&q={PAYLOAD}"
        out = security.redact_secrets_in_url(url)
        self.assertNotIn(CANARY, out)
        # the q= payload survives (URL-encoded but structurally intact).
        self.assertTrue("alert" in out and "script" in out,
                        f"injection payload was mangled/removed: {out!r}")


class BodySinkTests(unittest.TestCase):
    def test_json_secret_field_redacted_payload_field_survives(self):
        body = json.dumps({"password": CANARY, "q": PAYLOAD})
        out = security.redact_secrets_in_body(body)
        self.assertNotIn(CANARY, out)
        self.assertIn(PAYLOAD, out)

    def test_nested_secret_field_redacted(self):
        body = json.dumps({"outer": {"token": CANARY}, "data": {"search": PAYLOAD}})
        out = security.redact_secrets_in_body(body)
        self.assertNotIn(CANARY, out)
        self.assertIn(PAYLOAD, out)


class AuditSinkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.logger = AuditLogger(name="nc4-canary",
                                  log_file=os.path.join(self.tmp, "audit.log"),
                                  enable_console=False, enable_file=False)

    def test_recursive_sanitize_removes_nested_secret_keeps_note(self):
        data = {"level1": {"password": CANARY, "note": PAYLOAD,
                           "level2": {"api_key": CANARY}}}
        out = self.logger._sanitize_data(data)
        blob = json.dumps(out)
        self.assertNotIn(CANARY, blob)
        self.assertIn(PAYLOAD, blob)


def _finding(vc, evidence, suggested_test="", url="http://target.invalid/x"):
    return {
        "vulnerability_class": vc, "summary": "s", "severity": "medium",
        "confidence": 0.7, "url": url, "method": "GET",
        "evidence": evidence, "suggested_test": suggested_test, "basis": "observed",
    }


class ReportExportSinkTests(unittest.TestCase):
    def test_individual_finding_evidence_and_url_redacted(self):
        md = generate_markdown_report("target.invalid", [
            _finding("info_disclosure",
                     evidence=f"response leaked token={CANARY}; reflected q={PAYLOAD}",
                     url=f"http://target.invalid/x?api_key={CANARY}&q=abc")])
        self.assertNotIn(CANARY, md)
        self.assertTrue("alert" in md and "script" in md)  # payload survives

    def test_chain_finding_evidence_and_suggested_test_redacted(self):
        # The NC-4 fix: the chains render path previously emitted evidence and
        # suggested_test unredacted.
        md = generate_markdown_report("target.invalid", [
            _finding("potential-attack-chain:sqli+idor",
                     evidence=f"chain quotes captured token={CANARY} and payload q={PAYLOAD}",
                     suggested_test=f"replay with api_key={CANARY} to verify")])
        self.assertIn("Potential Attack Chains", md)   # it really rendered the chain
        self.assertNotIn(CANARY, md)
        self.assertIn(PAYLOAD, md)                     # payload preserved


if __name__ == "__main__":
    unittest.main()
