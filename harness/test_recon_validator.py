"""
Tests for the recon_validator.py hardening from this session's audit
follow-up: sensitive header VALUES (Authorization, Cookie, Set-Cookie,
X-API-Key, X-Auth-Token) are now redacted at collection time, before
being stored into EndpointInfo.headers -- not because a leak into any
Finding/ValidationResult field was ever found (traced every consumer
during the audit; none serialize endpoint.headers), but so a future
change can't accidentally start exposing what's already sitting there
unnecessarily.
"""
import unittest

from harness.models import HttpExchange
from harness.validators.recon_validator import ReconResult, ReconValidator


class SensitiveHeaderValueRedactionTests(unittest.TestCase):
    def setUp(self):
        self.validator = ReconValidator()

    def test_authorization_header_value_is_redacted(self):
        exchange = HttpExchange(
            url="https://example.com/api/x", method="GET",
            request_headers={"Authorization": "Bearer super-secret-token-value"},
            response_headers={},
        )
        result = ReconResult()
        self.validator._analyze_exchange(exchange, result)

        endpoint = result.endpoints[exchange.url]
        self.assertIn("authorization", endpoint.headers)
        self.assertNotIn("super-secret-token-value", endpoint.headers["authorization"])
        self.assertIn("REDACTED", endpoint.headers["authorization"])

    def test_cookie_header_value_is_redacted(self):
        exchange = HttpExchange(
            url="https://example.com/api/x", method="GET",
            request_headers={"Cookie": "session=abc123realtoken"},
            response_headers={},
        )
        result = ReconResult()
        self.validator._analyze_exchange(exchange, result)

        endpoint = result.endpoints[exchange.url]
        self.assertNotIn("abc123realtoken", endpoint.headers["cookie"])

    def test_set_cookie_response_header_value_is_redacted(self):
        exchange = HttpExchange(
            url="https://example.com/api/x", method="GET",
            request_headers={},
            response_headers={"Set-Cookie": "session=newrealtoken; HttpOnly"},
        )
        result = ReconResult()
        self.validator._analyze_exchange(exchange, result)

        endpoint = result.endpoints[exchange.url]
        stored_value = endpoint.headers["response_set-cookie"]
        self.assertNotIn("newrealtoken", stored_value)

    def test_sensitive_classification_still_works_after_redaction(self):
        """
        The header NAME must still drive endpoint.auth_required/sensitive
        classification even though the VALUE is now redacted -- this is
        a name-based check, not a value-based one, so redacting the
        value must not silently break it.
        """
        exchange = HttpExchange(
            url="https://example.com/api/x", method="GET",
            request_headers={"Authorization": "Bearer x"},
            response_headers={},
        )
        result = ReconResult()
        self.validator._analyze_exchange(exchange, result)

        endpoint = result.endpoints[exchange.url]
        self.assertTrue(endpoint.auth_required)
        self.assertTrue(endpoint.sensitive)

    def test_non_sensitive_headers_are_unaffected(self):
        exchange = HttpExchange(
            url="https://example.com/api/x", method="GET",
            request_headers={"User-Agent": "test-agent/1.0", "Accept": "application/json"},
            response_headers={"Content-Type": "application/json"},
        )
        result = ReconResult()
        self.validator._analyze_exchange(exchange, result)

        endpoint = result.endpoints[exchange.url]
        self.assertEqual(endpoint.headers["user-agent"], "test-agent/1.0")
        self.assertEqual(endpoint.headers["response_content-type"], "application/json")

    def test_tech_fingerprinting_still_sees_real_response_header_values(self):
        """
        Redaction must only apply to genuinely sensitive header names --
        a tech-fingerprinting header like Server or X-Powered-By must
        still carry its real value through to _analyze_header_for_tech,
        since that's the whole point of collecting it.
        """
        exchange = HttpExchange(
            url="https://example.com/api/x", method="GET",
            request_headers={},
            response_headers={"X-Powered-By": "Express"},
        )
        result = ReconResult()
        self.validator._analyze_exchange(exchange, result)

        endpoint = result.endpoints[exchange.url]
        self.assertEqual(endpoint.headers["response_x-powered-by"], "Express")


if __name__ == "__main__":
    unittest.main()
