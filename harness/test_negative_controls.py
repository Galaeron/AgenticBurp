"""Hermetic tests for the negative-control builders (precision item #1)."""
from __future__ import annotations

import json
import unittest

from harness.models import HttpExchange
from harness import negative_controls as nc


def _q(url):
    return HttpExchange(url=url, method="GET")


class TestQueryNeutralisation(unittest.TestCase):
    def test_benign_literal_replaces_every_query_value(self):
        ex = _q("http://127.0.0.1/x?url=http://evil.com&next=/../../etc/passwd")
        out = nc._benign_literal(ex)
        self.assertIsNotNone(out)
        self.assertNotIn("evil.com", out.url)
        self.assertNotIn("etc/passwd", out.url)
        self.assertIn("url=benign_control_value", out.url)
        self.assertIn("next=benign_control_value", out.url)

    def test_benign_integer_replaces_with_1(self):
        ex = _q("http://127.0.0.1/i?id=1'%20OR%201=1--")
        out = nc._benign_integer(ex)
        self.assertIsNotNone(out)
        self.assertIn("id=1", out.url)
        self.assertNotIn("OR", out.url)

    def test_none_when_no_params(self):
        ex = _q("http://127.0.0.1/x")
        self.assertIsNone(nc._benign_literal(ex))


class TestBodyNeutralisation(unittest.TestCase):
    def test_json_body_values_replaced(self):
        ex = HttpExchange(
            url="http://127.0.0.1/api", method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body=json.dumps({"role": "admin", "cmd": "; rm -rf /"}))
        out = nc._benign_literal(ex)
        self.assertIsNotNone(out)
        parsed = json.loads(out.request_body)
        self.assertEqual(parsed, {"role": "benign_control_value", "cmd": "benign_control_value"})

    def test_form_body_values_replaced(self):
        ex = HttpExchange(
            url="http://127.0.0.1/login", method="POST",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="user=admin&next=http://evil")
        out = nc._benign_literal(ex)
        self.assertIsNotNone(out)
        self.assertIn("user=benign_control_value", out.request_body)
        self.assertIn("next=benign_control_value", out.request_body)
        self.assertNotIn("evil", out.request_body)

    def test_query_and_body_both_neutralised(self):
        ex = HttpExchange(
            url="http://127.0.0.1/api?debug=1", method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body=json.dumps({"x": "y"}))
        out = nc._benign_integer(ex)
        self.assertIn("debug=1", out.url)
        self.assertEqual(json.loads(out.request_body), {"x": "1"})


class TestBuilderTable(unittest.TestCase):
    def test_self_controlling_legs_have_no_builder(self):
        # OOB collaborator legs are self-controlling; giving them a benign-variant
        # builder would be a category error. Guard against a future edit re-adding one.
        for leg in nc.SELF_CONTROLLING:
            self.assertNotIn(leg, nc.BUILDERS,
                             f"{leg} is self-controlling and must not have a negative-control builder")

    def test_known_injection_legs_have_builders(self):
        for leg in ("sqlmap", "path_traversal", "open_redirect", "ssti"):
            self.assertIn(leg, nc.BUILDERS)


if __name__ == "__main__":
    unittest.main()
