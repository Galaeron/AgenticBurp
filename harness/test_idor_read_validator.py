"""Tests for the single-principal IDOR read-differential validator: it must
confirm a cross-object read (own vs foreign vs absent all differ), stay quiet when
the endpoint returns the same page for every id, and never send a mutating request."""
import asyncio
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs

from harness import safety_gate
from harness.models import Finding, HttpExchange
from harness.validators.idor_read_validator import (
    IdorReadValidator, _locate_id, _foreign_ids, _with_id,
)


def _f():
    return Finding(vulnerability_class="idor", confidence=0.5, summary="s", evidence="e",
                   suggested_test="t", basis="derived")


class _Gate(unittest.TestCase):
    def setUp(self):
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                                      "allowed_hosts": ["t.test"]})

    def tearDown(self):
        safety_gate.reset_default_gate()


class HelperTests(unittest.TestCase):
    def test_locate_query_id(self):
        ex = HttpExchange(url="http://t.test/my-account?id=wiener", method="GET",
                          request_headers={}, response_status=200)
        self.assertEqual(_locate_id(ex), ("query", "id", "wiener"))

    def test_locate_path_id(self):
        ex = HttpExchange(url="http://t.test/api/orders/123", method="GET",
                          request_headers={}, response_status=200)
        self.assertEqual(_locate_id(ex), ("path", 3, "123"))

    def test_numeric_neighbours(self):
        self.assertEqual(set(_foreign_ids("10", [])), {"11", "9", "12"})

    def test_with_id_replaces_query(self):
        ex = HttpExchange(url="http://t.test/a?id=wiener&x=1", method="GET",
                          request_headers={}, response_status=200)
        self.assertEqual(_with_id(ex, "query", "id", "carlos"),
                         "http://t.test/a?id=carlos&x=1")


class ReadDifferentialTests(_Gate):
    def _run(self, app, exchange, candidate_ids=None):
        v = IdorReadValidator(allowed_hosts=["t.test"], candidate_ids=candidate_ids)
        with patch("httpx.AsyncClient.request", app):
            return asyncio.run(v.validate(_f(), exchange))

    def test_confirms_username_idor_with_supplied_candidate(self):
        # Distinct account page per id; absent id -> not found. carlos supplied.
        async def app(self, method, url, headers=None, content=None):
            idv = parse_qs(urlsplit(url).query).get("id", [""])[0]
            class _R: pass
            r = _R(); r.status_code = 200
            if idv == "wiener":
                r.text = "Your username: wiener. Your API key: KEY-WIENER-" + "x" * 40
            elif idv == "carlos":
                r.text = "Your username: carlos. Your API key: KEY-CARLOS-" + "y" * 40
            else:
                r.status_code = 404; r.text = "Not found"
            return r
        ex = HttpExchange(url="http://t.test/my-account?id=wiener", method="GET",
                          request_headers={"Cookie": "session=wiener"}, response_status=200)
        res = self._run(app, ex, candidate_ids=["carlos"])
        self.assertEqual(res.status, "confirmed")
        self.assertTrue(res.confirmed)
        self.assertNotIn("KEY-CARLOS", res.evidence)  # other object's data redacted

    def test_confirms_numeric_idor_via_neighbour(self):
        async def app(self, method, url, headers=None, content=None):
            seg = urlsplit(url).path.rsplit("/", 1)[-1]
            class _R: pass
            r = _R(); r.status_code = 200
            if seg == "123":
                r.text = "Order 123 for wiener total $10 " + "a" * 40
            elif seg in ("124", "122", "125"):
                r.text = f"Order {seg} for someone-else total $99 " + "b" * 40
            else:
                r.status_code = 404; r.text = "No such order"
            return r
        ex = HttpExchange(url="http://t.test/api/orders/123", method="GET",
                          request_headers={"Cookie": "session=wiener"}, response_status=200)
        res = self._run(app, ex)
        self.assertEqual(res.status, "confirmed")

    def test_same_page_for_every_id_is_not_confirmed(self):
        # No real object behind the id: identical page for own, foreign, absent.
        async def app(self, method, url, headers=None, content=None):
            class _R: pass
            r = _R(); r.status_code = 200
            r.text = "Welcome to the dashboard " + "z" * 80
            return r
        ex = HttpExchange(url="http://t.test/my-account?id=5", method="GET",
                          request_headers={}, response_status=200)
        res = self._run(app, ex)
        self.assertEqual(res.status, "not_confirmed")

    def test_foreign_id_denied_is_not_confirmed(self):
        async def app(self, method, url, headers=None, content=None):
            idv = parse_qs(urlsplit(url).query).get("id", [""])[0]
            class _R: pass
            r = _R()
            if idv == "wiener":
                r.status_code = 200; r.text = "Your account wiener " + "a" * 60
            else:
                r.status_code = 403; r.text = "Access denied"
            return r
        ex = HttpExchange(url="http://t.test/my-account?id=wiener", method="GET",
                          request_headers={}, response_status=200)
        res = self._run(app, ex, candidate_ids=["carlos"])
        self.assertEqual(res.status, "not_confirmed")

    def test_non_get_is_skipped(self):
        v = IdorReadValidator(allowed_hosts=["t.test"])
        ex = HttpExchange(url="http://t.test/my-account?id=1", method="POST",
                          request_headers={}, request_body="x=1", response_status=200)
        self.assertFalse(v.applies(_f(), ex))


if __name__ == "__main__":
    unittest.main()
