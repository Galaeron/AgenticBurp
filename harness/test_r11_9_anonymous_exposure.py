"""R11-9 open point (owner decision 2026-11-19): an anonymous read is an exposure caller.

A captured GET with no credentials is replayed as the anonymous caller. An unmasked
credential secret on an account object in that read confirms excessive data
exposure. The existing policies stay as they were: the proof names no object-level
access-control break (BOLA/BFLA stays bound to authz.owners) and no missing
authentication (bound to authz.protected_paths).

Through the production caller (Orchestrator._validate_findings) against a loopback
service.
"""
import json
import unittest

from harness.models import HttpExchange
from harness.test_oracle_gaps_api_security import _BCRYPT
from harness.test_r11_6_identities_bodies import _Base, _Service, _bearer
from harness.validators.api_security_validator import ApiSecurityValidator

_USERS = {"status": "success", "data": [
    {"id": 1, "email": "alice@example.test", "role": "customer", "password": _BCRYPT},
    {"id": 3, "email": "dora@example.test", "role": "customer", "password": _BCRYPT}]}
_PRODUCTS = {"status": "success", "data": [
    {"id": 1, "name": "Apple Juice", "price": 1.99, "description": "fresh"},
    {"id": 2, "name": "Banana", "price": 0.5, "description": "ripe"}]}


class _Public(_Service):
    """Answers every GET with no credentials too."""

    def do_GET(self):
        srv = self.server
        srv.received.append(("GET", self.path, dict(self.headers), None))
        return self._send(200, _USERS if self.path.startswith("/api/users") else _PRODUCTS)


class _Recording(ApiSecurityValidator):
    """Keeps the exposure leg's own ValidationResult (its mechanism classes)."""
    results: list = []

    async def _probe_exposure(self, finding, exchange):
        res = await super()._probe_exposure(finding, exchange)
        type(self).results.append(res)
        return res


class AnonymousExposureCallerTests(_Base, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.server.RequestHandlerClass = _Public

    def exposure(self, path):
        ex = HttpExchange(url=self.origin + path, method="GET", request_headers={},
                          response_status=200, response_body="{}")
        sessions = [("a", "alice", {"Authorization": _bearer("alice@example.test", 1)})]
        _Recording.results = []
        return self.dispatch(_Recording(), ex, "excessive data exposure", sessions=sessions)

    def test_secret_in_an_anonymous_read_confirms_exposure(self):
        report = self.exposure("/api/users")
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("as anonymous", report.summary)
        self.assertIn("read with no credentials, twice", report.evidence)
        self.assertNotIn(_BCRYPT, report.evidence + report.summary)
        sent = [h for m, _, h, _ in self.server.received]
        self.assertEqual(len(sent), 2, "two anonymous reads; the caller is its own control")
        self.assertFalse(any(h.get("Authorization") for h in sent), "no credentials are added")

    def test_policy_unchanged_no_owner_or_missing_auth_claim(self):
        report = self.exposure("/api/users")
        self.assertEqual(report.status, "confirmed", report.summary)
        classes = set(_Recording.results[-1].mechanism_classes)
        self.assertEqual(classes, {"excessive data exposure", "info_disclosure"})
        self.assertFalse(classes & {"idor", "bola", "bfla", "auth_bypass",
                                    "missing_authentication", "broken_authentication"})

    def test_control_public_fields_only_is_not_confirmed(self):
        report = self.exposure("/api/products")
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertEqual(len(self.server.received), 1)

    def test_control_identified_caller_still_uses_the_anonymous_control(self):
        a = _bearer("alice@example.test", 1)
        ex = HttpExchange(url=self.origin + "/api/users", method="GET",
                          request_headers={"Authorization": a})
        sessions = [("a", "alice", {"Authorization": a})]
        report = self.dispatch(ApiSecurityValidator(), ex, "excessive data exposure",
                               sessions=sessions)
        self.assertEqual(report.status, "confirmed", report.summary)
        auth = [h.get("Authorization") for m, _, h, _ in self.server.received]
        self.assertEqual(auth, [a, a, None])
        self.assertIn("anonymous read also shows it", report.evidence)


if __name__ == "__main__":
    unittest.main()
