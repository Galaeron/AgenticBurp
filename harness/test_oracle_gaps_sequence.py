"""Oracle gap: the sequence leg on a create whose collection the creating session
cannot read (an anonymous signup to a listing that needs a login).

The baseline GET already carries the capture's own session; the skip reason now
says the request is a create handed to write_integrity / api_security, instead of
"not readable". An update target keeps the old reason, and nothing is written in
either case.
"""
import asyncio
import json
import unittest
from unittest.mock import patch

import httpx

from harness import global_throttle, safety_gate
from harness.models import Finding, HttpExchange
from harness.validators.sequence_validator import SequenceValidator, _names_an_item


class _Resp:
    def __init__(self, status, text):
        self.status_code, self.text = status, text


_FINDING = Finding(vulnerability_class="mass_assignment", confidence=0.5, severity="high",
                   summary="mass-assignment hypothesis", evidence="", suggested_test="",
                   basis="derived")


class SequenceCreateSkipTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                                      "allowed_hosts": ["target.test"]})

    def tearDown(self):
        safety_gate.reset_default_gate()

    def _run(self, method, path, headers, get_status=401, error_body=None):
        sent = []

        async def request(client, verb, url, *, content=None, headers=None, **kw):
            sent.append((verb.upper(), url, dict(headers or {})))
            if verb.upper() == "GET":
                return _Resp(get_status, error_body if error_body is not None
                             else "<html><title>UnauthorizedError</title></html>")
            return _Resp(201, '{"ok": true}')

        ex = HttpExchange(url="http://target.test" + path, method=method,
                          request_headers={"Content-Type": "application/json", **headers},
                          request_body=json.dumps({"email": "new@example.test", "password": "x-123456"}),
                          response_status=201, response_headers={}, response_body="{}")
        v = SequenceValidator(allowed_hosts=["target.test"])
        with patch.object(httpx.AsyncClient, "request", request):
            return asyncio.run(v.validate(_FINDING, ex)), sent

    def test_anonymous_create_to_unlistable_collection_is_handed_off(self):
        result, sent = self._run("POST", "/api/accounts/", {})
        self.assertEqual(result.status, "skipped")
        self.assertIn("create the capture's own session cannot read back", result.summary)
        self.assertIn("GET /api/accounts/ -> 401", result.summary)
        self.assertIn("write_integrity", result.summary)
        self.assertIn("nothing was written", result.summary)
        self.assertEqual([m for m, _, _ in sent], ["GET"], "a create must not be written by this leg")

    def test_baseline_read_carries_the_capture_session(self):
        _, sent = self._run("POST", "/api/accounts", {"Authorization": "Bearer creator"}, get_status=403)
        self.assertEqual(sent[0][2].get("Authorization"), "Bearer creator")

    def test_item_update_keeps_the_unreadable_reason(self):
        for method, path in (("POST", "/api/accounts/7"), ("PATCH", "/api/account/profile"),
                             ("PUT", "/api/accounts/7")):
            result, sent = self._run(method, path, {"Authorization": "Bearer u"})
            self.assertEqual(result.status, "skipped", (method, path))
            self.assertIn("resource not readable as a JSON object", result.summary, (method, path))
            self.assertEqual([m for m, _, _ in sent], ["GET"], (method, path))

    def test_json_error_document_is_not_a_baseline(self):
        # A 401 answered with a JSON error object must not be diffed as the resource
        # (and must not lead to a privileged write on a create).
        for path in ("/api/accounts", "/api/accounts/7"):
            result, sent = self._run("POST", path, {}, error_body=json.dumps({"error": "login required"}))
            self.assertEqual(result.status, "skipped", (path, result.summary))
            self.assertEqual([m for m, _, _ in sent], ["GET"], path)

    def test_item_segment_shapes(self):
        self.assertTrue(_names_an_item("http://t.test/api/things/42"))
        self.assertTrue(_names_an_item("http://t.test/api/things/5f2b9c1e8d7a6b5c"))
        self.assertTrue(_names_an_item("http://t.test/api/things/123e4567-e89b-12d3-a456-426614174000"))
        self.assertFalse(_names_an_item("http://t.test/api/things/"))
        self.assertFalse(_names_an_item("http://t.test/api/account/profile"))


if __name__ == "__main__":
    unittest.main()
