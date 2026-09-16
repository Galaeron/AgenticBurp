"""Hermetic tests for the Phase 3 stateful sequence leg (write -> re-read
differential). No network: httpx is stubbed with a tiny stateful fake app; the
safety gate is configured permissive (or blocking) per test."""
import asyncio
import json
import unittest
from unittest.mock import patch

import httpx

from harness import global_throttle
from harness import safety_gate
from harness.models import Finding, HttpExchange
from harness.validators.sequence_validator import SequenceValidator, _is_priv


class _Resp:
    def __init__(self, status, text):
        self.status_code, self.text = status, text


def _fake_request(state):
    """Stateful fake for httpx.AsyncClient.request. A GET reflects the current
    stored role; a write (POST/PUT/PATCH) marks the resource mutated. When
    `vulnerable`, a post-write GET shows role=admin (the write persisted);
    otherwise the GET always shows role=user (write rejected / not persisted)."""
    async def request(self, method, url, *, content=None, headers=None, **kw):
        m = (method or "").upper()
        if m in ("POST", "PUT", "PATCH"):
            state["written"] = True
            return _Resp(200, '{"ok": true}')
        role = "admin" if (state["written"] and state["vulnerable"]) else "user"
        return _Resp(200, json.dumps({"id": 1, "name": "alice", "role": role}))
    return request


_FINDING = Finding(vulnerability_class="mass_assignment", confidence=0.5, severity="high",
                   summary="mass-assignment hypothesis", evidence="", suggested_test="",
                   basis="derived")
_EXCHANGE = HttpExchange(
    url="http://target.test/api/account/profile", method="PATCH",
    request_headers={"Content-Type": "application/json", "Authorization": "Bearer u"},
    request_body='{"name": "alice", "bio": "hi"}',
    response_status=200, response_headers={}, response_body='{"name":"alice"}')


class SequenceValidatorTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)
        safety_gate.reset_default_gate()

    def tearDown(self):
        safety_gate.reset_default_gate()

    def _run(self, vulnerable, *, allow_mutating=True):
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": allow_mutating})
        state = {"written": False, "vulnerable": vulnerable}
        v = SequenceValidator(allowed_hosts=["target.test"])
        with patch.object(httpx.AsyncClient, "request", _fake_request(state)):
            return asyncio.run(v.validate(_FINDING, _EXCHANGE))

    def test_applies_only_to_writable_json(self):
        v = SequenceValidator()
        self.assertTrue(v.applies(_FINDING, _EXCHANGE))
        get_ex = HttpExchange(url="http://target.test/x", method="GET",
                              request_headers={}, request_body="")
        self.assertFalse(v.applies(_FINDING, get_ex))
        non_json = HttpExchange(url="http://target.test/x", method="POST",
                                request_headers={"Content-Type": "text/plain"}, request_body="hello")
        self.assertFalse(v.applies(_FINDING, non_json))

    def test_confirms_when_injected_field_persists(self):
        res = self._run(vulnerable=True)
        self.assertEqual(res.status, "confirmed")
        self.assertTrue(res.confirmed)
        self.assertIn("role", res.summary)  # the flipped field is named

    def test_negative_control_write_not_persisted(self):
        # Same sequence, but the app never persists the injected field: the
        # verify read still shows role=user -> must NOT confirm.
        res = self._run(vulnerable=False)
        self.assertEqual(res.status, "not_confirmed")
        self.assertFalse(res.confirmed)

    def test_skips_when_mutating_replay_not_authorized(self):
        # The write step is gated; without allow_mutating_replay it is blocked,
        # so the leg skips rather than confirming on the baseline read alone.
        res = self._run(vulnerable=True, allow_mutating=False)
        self.assertEqual(res.status, "skipped")
        self.assertFalse(res.confirmed)
        self.assertIn("mutating replay not authorized", res.summary)

    def test_out_of_scope_host_skipped(self):
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True})
        v = SequenceValidator(allowed_hosts=["other.test"])
        res = asyncio.run(v.validate(_FINDING, _EXCHANGE))
        self.assertEqual(res.status, "skipped")


class IsPrivTests(unittest.TestCase):
    def test_bool_field(self):
        self.assertTrue(_is_priv(True, True))
        self.assertTrue(_is_priv("true", True))
        self.assertFalse(_is_priv(False, True))
        self.assertFalse(_is_priv(None, True))

    def test_string_field(self):
        self.assertTrue(_is_priv("admin", "admin"))
        self.assertTrue(_is_priv("ADMIN", "admin"))
        self.assertFalse(_is_priv("user", "admin"))


if __name__ == "__main__":
    unittest.main()
