import unittest

import harness.credential_endpoint_detector as ced
from harness.models import HttpExchange


class DetectCredentialSubmissionTests(unittest.TestCase):
    def test_ordinary_login_json_flagged_despite_no_injection_syntax(self):
        """The exact real-world case this module exists for: a benign,
        ordinary-looking login (real-looking credentials, zero injection
        syntax) must still be flagged, since that's precisely what the
        reactive sqli agent misses."""
        e = HttpExchange(
            url="http://localhost:3000/rest/user/login", method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body='{"email":"bob@bob.com","password":"bobbob"}',
        )
        f = ced.detect_credential_submission(e)
        self.assertIsNotNone(f)
        self.assertEqual(f.vulnerability_class, "sqli")
        self.assertFalse(f.confirmed)
        self.assertLess(f.confidence, 0.7)  # moderate, not overclaiming

    def test_form_encoded_login_flagged(self):
        e = HttpExchange(
            url="https://example.test/login", method="POST",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="username=alice&password=hunter2",
        )
        self.assertIsNotNone(ced.detect_credential_submission(e))

    def test_password_field_alone_without_identifier_or_auth_path_not_flagged(self):
        # e.g. a settings PATCH that includes a password field for some
        # unrelated purpose, on a URL with no auth-shaped path -- avoid
        # over-flagging every endpoint that merely mentions "password".
        e = HttpExchange(
            url="https://example.test/api/widgets/42", method="PATCH",
            request_body='{"password":"x","color":"blue"}',
        )
        self.assertIsNone(ced.detect_credential_submission(e))

    def test_auth_shaped_path_without_identifier_field_still_flagged(self):
        e = HttpExchange(
            url="https://example.test/api/authenticate", method="POST",
            request_body='{"password":"x"}',
        )
        self.assertIsNotNone(ced.detect_credential_submission(e))

    def test_get_request_never_flagged(self):
        e = HttpExchange(
            url="https://example.test/login?password=x&email=a@b.com", method="GET",
        )
        self.assertIsNone(ced.detect_credential_submission(e))

    def test_no_password_field_not_flagged(self):
        e = HttpExchange(
            url="https://example.test/login", method="POST",
            request_body='{"email":"a@b.com","otp":"123456"}',
        )
        self.assertIsNone(ced.detect_credential_submission(e))

    def test_unrelated_post_endpoint_not_flagged(self):
        e = HttpExchange(
            url="https://example.test/api/cart/add", method="POST",
            request_body='{"item_id":42,"quantity":1}',
        )
        self.assertIsNone(ced.detect_credential_submission(e))


if __name__ == "__main__":
    unittest.main()
