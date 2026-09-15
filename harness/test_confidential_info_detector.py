"""Tests for the A4 confidential-info response detector."""
import unittest

import confidential_info_detector as cid
from models import HttpExchange


def _ex(body="", headers=None):
    return HttpExchange(url="https://shop.test/api/x", method="GET", request_headers={},
                        request_body="", response_status=200,
                        response_headers=headers or {}, response_body=body)


class ScanTests(unittest.TestCase):
    def _cats(self, body="", headers=None):
        return {m.category for m in cid.scan_response(_ex(body, headers))}

    def test_aws_key_detected(self):
        self.assertIn("secret", self._cats("id=AKIAIOSFODNN7EXAMPLE more"))

    def test_private_key_block_critical(self):
        ms = cid.scan_response(_ex("-----BEGIN RSA PRIVATE KEY-----\nMIIabc"))
        self.assertTrue(any(m.severity == "critical" for m in ms))

    def test_jwt_detected(self):
        body = '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEFghiJKL"}'
        self.assertIn("secret", self._cats(body))

    def test_connection_string_creds(self):
        self.assertIn("secret", self._cats("mongodb://admin:s3cretpw@10.0.0.5:27017/db"))

    def test_private_ip_low(self):
        ms = cid.scan_response(_ex("host is 192.168.1.50 internally"))
        self.assertTrue(any(m.category == "internal_host" and m.severity == "low" for m in ms))

    def test_internal_hostname(self):
        self.assertIn("internal_host", self._cats("proxy: db01.internal:5432"))

    def test_filesystem_path(self):
        self.assertIn("internal_path", self._cats("stack trace at /var/www/app/config.php line 3"))

    def test_credit_card_luhn_valid_matches(self):
        # 4111 1111 1111 1111 is a Luhn-valid test Visa.
        self.assertIn("pii", self._cats("card 4111 1111 1111 1111 on file"))

    def test_credit_card_luhn_invalid_rejected(self):
        # 16 digits but not Luhn-valid -> not a card (avoids matching random ids).
        self.assertNotIn("pii", self._cats("order 1234567812345678 shipped"))

    def test_ssn(self):
        self.assertIn("pii", self._cats("ssn 123-45-6789"))

    def test_clean_response_no_matches(self):
        self.assertEqual(cid.scan_response(_ex('{"status":"ok","items":[1,2,3]}')), [])

    def test_header_scanned(self):
        ms = cid.scan_response(_ex("", {"X-Debug-Path": "/etc/passwd loaded"}))
        self.assertTrue(any(m.location.startswith("header:") for m in ms))

    def test_set_cookie_header_skipped(self):
        # a token in Set-Cookie isn't treated as a server-side leak here
        ms = cid.scan_response(_ex("", {"Set-Cookie": "session=eyJhbGciOi.eyJzdWIi.abcdefgh"}))
        self.assertEqual(ms, [])


class RedactionTests(unittest.TestCase):
    def test_secret_value_never_echoed(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        ms = cid.scan_response(_ex(f"key={secret}"))
        for m in ms:
            self.assertNotIn(secret, m.redacted)
        self.assertTrue(any("…" in m.redacted for m in ms))

    def test_findings_evidence_is_redacted(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        findings = cid.findings_from_exchange(_ex(f"key={secret}"))
        self.assertTrue(findings)
        for f in findings:
            self.assertNotIn(secret, f.evidence)


class FindingTests(unittest.TestCase):
    def test_findings_grouped_by_category(self):
        body = "AKIAIOSFODNN7EXAMPLE and host 10.1.2.3"
        findings = cid.findings_from_exchange(_ex(body))
        classes = {f.severity for f in findings}
        # a high-severity secret finding and a low-severity internal_host finding
        self.assertIn("high", classes)
        self.assertIn("low", classes)
        self.assertTrue(all(f.vulnerability_class == "info_disclosure" for f in findings))

    def test_no_findings_on_clean(self):
        self.assertEqual(cid.findings_from_exchange(_ex('{"ok":true}')), [])

    def test_findings_not_confirmed(self):
        findings = cid.findings_from_exchange(_ex("AKIAIOSFODNN7EXAMPLE"))
        self.assertTrue(all(not f.confirmed for f in findings))


class ScanEndpointTests(unittest.TestCase):
    def setUp(self):
        import server as server_module
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def test_scan_confidential_endpoint_redacts(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        r = self.client.post("/scan/confidential", json={
            "url": "https://t.test/x", "method": "GET", "request_headers": {}, "request_body": "",
            "response_status": 200, "response_headers": {}, "response_body": f"key={secret}"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertGreaterEqual(body["match_count"], 1)
        self.assertNotIn(secret, r.text)  # redacted everywhere in the response

    def test_scan_clean_response(self):
        r = self.client.post("/scan/confidential", json={
            "url": "https://t.test/x", "method": "GET", "request_headers": {}, "request_body": "",
            "response_status": 200, "response_headers": {}, "response_body": '{"ok":true}'})
        self.assertEqual(r.json()["match_count"], 0)


if __name__ == "__main__":
    unittest.main()
