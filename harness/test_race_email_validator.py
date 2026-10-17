"""Single-endpoint email-race proof and negative readback controls."""
import asyncio
from types import SimpleNamespace
from urllib.parse import parse_qs
import unittest

from harness.models import Finding, HttpExchange
from harness.validators.race_condition_validator import RaceConditionValidator


class _Gate:
    def authorize_burst(self, **kwargs):
        return SimpleNamespace(allowed=True, allowed_burst_size=2, reason="")


class _Sessions:
    def bind_headers(self, headers):
        return "user", {k: v for k, v in headers.items() if k.lower() != "cookie"}


class _Executor:
    def __init__(self, vulnerable):
        self.vulnerable = vulnerable
        self.controlled = ""
        self.confirmed = False

    async def execute(self, req, capability, session_ref=None):
        if req.method == "POST":
            email = parse_qs(req.body)["email"][0]
            if email.endswith("@mail.test"):
                self.controlled = email
            return SimpleNamespace(ok=True, status=200, body="pending", headers={})
        if req.url == "https://mail.test/email":
            return SimpleNamespace(
                ok=True, status=200,
                body='<a href="/email/message-1">message</a>', headers={})
        if req.url == "https://mail.test/email/message-1":
            return SimpleNamespace(
                ok=True, status=200,
                body=(f"To: {self.controlled} "
                      '<a href="https://app.test/email/change-email?token=redacted">Confirm</a>'),
                headers={})
        if "token=redacted" in req.url:
            self.confirmed = True
            return SimpleNamespace(ok=True, status=200, body="confirmed", headers={})
        if req.url == "https://app.test/my-account":
            address = "carlos@example.test" if self.vulnerable and self.confirmed else self.controlled
            return SimpleNamespace(ok=True, status=200,
                                   body=(f'<p>Your email is: {address}</p>'
                                         '<p>Please confirm carlos@example.test</p>'),
                                   headers={})
        return SimpleNamespace(ok=False, status=404, body="", headers={})


class _Context:
    def __init__(self, vulnerable):
        self.gate = _Gate()
        self.sessions = _Sessions()
        self._executor = _Executor(vulnerable)

    def executor(self):
        return self._executor


def _finding():
    return Finding(vulnerability_class="race_condition", severity="high",
                   confidence=0.3, summary="candidate", evidence="",
                   suggested_test="", basis="derived")


def _exchange():
    return HttpExchange(
        url="https://app.test/my-account/change-email", method="POST",
        request_headers={"Cookie": "session=u",
                         "Content-Type": "application/x-www-form-urlencoded"},
        request_body="email=probe%40example.com&csrf=t", response_status=200,
        response_headers={}, response_body="pending")


class EmailRaceValidatorTests(unittest.TestCase):
    def _run(self, vulnerable):
        validator = RaceConditionValidator(
            run_context=_Context(vulnerable), target_email="carlos@example.test",
            mailbox_url="https://mail.test/email", email_race_rounds=1)
        return asyncio.run(validator.validate(_finding(), _exchange()))

    def test_confirms_only_after_target_address_readback(self):
        result = self._run(True)
        self.assertTrue(result.confirmed)
        self.assertEqual(result.status, "confirmed")
        self.assertIn("account readback", result.evidence)

    def test_controlled_address_readback_is_negative_control(self):
        result = self._run(False)
        self.assertFalse(result.confirmed)
        self.assertEqual(result.status, "not_confirmed")


if __name__ == "__main__":
    unittest.main()
