"""Oracle gaps (nosql): two misses the leg had on a real NoSQL backend.

1. A route parameter fed into a server-side JavaScript filter (`$where`) was never
   probed: a GET whose only input is an id-like path segment was skipped unsent.
   The leg now sends equal-length JavaScript boolean suffixes on the segment and
   confirms only when true and false split (true wider, false like a missing id),
   the neutral suffixes answer like the captured id, and both repeat.
2. A write whose backend rejects `$eq` ("unrecognised operator") read as "plain
   strings", although `$ne` widened the update to every object. `{"$in": [t]}` now
   stands in for the equality control, and an operator that matched more objects
   than the captured value did confirms when no equality control works.

Every probe goes through the run transport to a loopback fixture; controls: a
plain-string route, a punctuation-stripping echo route, a write backend that
rejects any object value, and the mutating ceiling.
"""
import asyncio
import json
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators.nosql_validator import NosqlValidator, path_id_segments

_REVIEWS = [{"shop": "s1001", "product": 1, "text": "fine"},
            {"shop": "s1001", "product": 1, "text": "good"},
            {"shop": "s2002", "product": 2, "text": "meh"}]
_NOTES = [{"id": "n-1", "message": "a"}, {"id": "n-2", "message": "b"},
          {"id": "n-3", "message": "c"}]
_QUOTED = re.compile(r"^(.*)' (\|\||&&) '(\w+)'=='(\w+)$")
_BARE = re.compile(r"^(\d+) (\|\||&&) (\d+)==(\d+)$")


def _bool(left: bool, op: str, a: str, b: str) -> bool:
    return (left or a == b) if op == "||" else (left and a == b)


class _Backend(BaseHTTPRequestHandler):
    sent: list = []

    def _reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).sent.append(("GET", self.path, ""))
        path = urlsplit(self.path).path
        parts = path.split("/")
        raw = unquote(parts[3]) if len(parts) > 3 else ""
        if path.startswith("/q/shops/"):
            # $where: "this.shop == '" + raw + "'"
            if "'" not in raw:
                rows = [r for r in _REVIEWS if r["shop"] == raw]
            else:
                m = _QUOTED.match(raw)
                if not m:
                    return self._reply(500, {"error": "SyntaxError: unexpected string"})
                rows = [r for r in _REVIEWS if _bool(r["shop"] == m[1], m[2], m[3], m[4])]
            return self._reply(200, {"data": rows})
        if path.startswith("/n/products/"):
            # $where: "this.product == " + raw
            if raw.isdigit():
                rows = [r for r in _REVIEWS if r["product"] == int(raw)]
            else:
                m = _BARE.match(raw)
                if not m:
                    return self._reply(500, {"error": "ReferenceError"})
                rows = [r for r in _REVIEWS
                        if _bool(r["product"] == int(m[1]), m[2], m[3], m[4])]
            return self._reply(200, {"data": rows})
        if path.startswith("/plain/shops/"):
            return self._reply(200, {"data": [r for r in _REVIEWS if r["shop"] == raw]})
        if path.startswith("/strip/orders/"):
            clean = re.sub(r"[^\w-]", "", raw)
            return self._reply(200, {"orderId": clean, "data": [
                r for r in _REVIEWS if r["shop"] == clean]})
        return self._reply(404, {"error": "not found"})

    def do_PATCH(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode() if length else ""
        type(self).sent.append(("PATCH", self.path, raw))
        doc = json.loads(raw or "{}")
        key, message = doc.get("id"), doc.get("message")
        path = urlsplit(self.path).path
        if isinstance(key, dict):
            if path == "/api/rejecting":
                return self._reply(500, {"error": "Cast to string failed"})
            op = next(iter(key), "")
            if op == "$ne":
                hits = [n for n in _NOTES if n["id"] != key["$ne"]]
            elif op == "$in" and path == "/api/notes":
                hits = [n for n in _NOTES if n["id"] in key["$in"]]
            else:
                return self._reply(500, {"error": f"Unrecognized operator: {op}"})
        else:
            hits = [n for n in _NOTES if n["id"] == key]
        updated = [dict(n, message=message) for n in hits]
        return self._reply(200, {"modified": len(hits), "original": hits, "updated": updated})

    def log_message(self, *args):
        pass


class OracleGapNosqlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global_throttle.configure(0)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Backend)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def run_leg(self, method, path, *, body="", response="{}", ceiling=15, mutating=True):
        finding = Finding(vulnerability_class="NoSQL Injection", confidence=0.5,
                          severity="high", summary="s", evidence="e", suggested_test="t",
                          basis="derived", finding_id="f-nosql-gap")
        exchange = HttpExchange(
            url=self.base + path, method=method,
            request_headers={"Content-Type": "application/json"} if body else {},
            request_body=body, response_status=200, response_body=response)
        gate = {"active_enabled": True, "allow_mutating_replay": mutating,
                "mutating_ceiling_by_check": {"nosql": ceiling} if ceiling else {}}
        config = {"server": {"allowed_hosts": ["127.0.0.1"]},
                  "validators": {"enabled": True, "active_enabled": True}}

        async def run():
            _Backend.sent = []
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=config,
                                         gate_config=gate) as ctx:
                leg = NosqlValidator(allowed_hosts=["127.0.0.1"], run_context=ctx)
                return await leg.validate(finding, exchange), list(_Backend.sent)
        return asyncio.run(run())

    # -- path segments ------------------------------------------------------------

    def test_id_like_segments_are_found_and_versions_are_not(self):
        def segs(path):
            return path_id_segments(HttpExchange(url="http://h" + path, method="GET"))
        self.assertEqual(segs("/rest/products/1/reviews"), [3])
        self.assertEqual(segs("/rest/track/c208-5ba28e7db5120c47"), [3])
        self.assertEqual(segs("/api/v1/users"), [])
        self.assertEqual(segs("/api/users/profile"), [])
        self.assertEqual(path_id_segments(HttpExchange(url="http://h/a/1", method="POST")), [])

    def test_quoted_where_on_a_string_path_id_is_confirmed(self):
        result, sent = self.run_leg("GET", "/q/shops/s1001/reviews",
                                    response=json.dumps({"data": _REVIEWS[:2]}))
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("single-quoted", result.summary)
        self.assertGreaterEqual(result.confidence, 0.9)
        self.assertTrue(all(m == "GET" and p.startswith("/q/shops/") for m, p, _ in sent))
        self.assertLessEqual(len(sent), 20)

    def test_unquoted_where_on_a_numeric_path_id_is_confirmed(self):
        result, _ = self.run_leg("GET", "/n/products/2/reviews")
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("unquoted", result.summary)

    def test_control_plain_string_route_is_a_negative(self):
        result, sent = self.run_leg("GET", "/plain/shops/s1001/reviews")
        self.assertTrue(sent)
        self.assertEqual((result.status, result.control_outcome), ("not_confirmed", ""),
                         result.summary)
        self.assertIn("did not split", result.summary)

    def test_control_punctuation_stripping_echo_is_not_confirmed(self):
        result, _ = self.run_leg("GET", "/strip/orders/s1001-0042abc")
        self.assertFalse(result.confirmed, result.summary)
        self.assertEqual(result.status, "not_confirmed")

    # -- writes whose backend rejects $eq ----------------------------------------

    def test_patch_with_eq_rejected_confirms_through_in_control(self):
        body = json.dumps({"id": "n-2", "message": "mine"})
        captured = json.dumps({"modified": 1, "original": [_NOTES[1]], "updated": []})
        result, sent = self.run_leg("PATCH", "/api/notes", body=body, response=captured)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("{'$in': [t]}", result.summary)
        self.assertIn("matched 3 objects", result.summary)
        self.assertTrue(all(m == "PATCH" for m, _, _ in sent))
        self.assertLessEqual(len(sent), 6)

    def test_patch_widening_confirms_when_no_equality_operator_works(self):
        body = json.dumps({"id": "n-2", "message": "mine"})
        captured = json.dumps({"modified": 1, "original": [_NOTES[1]], "updated": []})
        result, _ = self.run_leg("PATCH", "/api/widen-only", body=body, response=captured)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("matched 3 objects", result.summary)
        self.assertEqual(result.confidence, 0.85)

    def test_control_backend_rejecting_every_object_is_a_negative(self):
        body = json.dumps({"id": "n-2", "message": "mine"})
        captured = json.dumps({"modified": 1, "original": [_NOTES[1]], "updated": []})
        result, sent = self.run_leg("PATCH", "/api/rejecting", body=body, response=captured)
        self.assertTrue(sent)
        self.assertEqual((result.status, result.control_outcome), ("not_confirmed", ""),
                         result.summary)

    def test_control_write_ceiling_below_one_verdict_sends_nothing(self):
        body = json.dumps({"id": "n-2", "message": "mine"})
        result, sent = self.run_leg("PATCH", "/api/notes", body=body, ceiling=5)
        self.assertEqual(sent, [])
        self.assertEqual(result.status, "skipped")
        self.assertIn("mutating_ceiling_by_check.nosql", result.summary)

    def test_control_mutating_replay_off_sends_no_write(self):
        body = json.dumps({"id": "n-2", "message": "mine"})
        result, sent = self.run_leg("PATCH", "/api/notes", body=body, mutating=False)
        self.assertEqual([s for s in sent if s[0] == "PATCH"], [])
        self.assertFalse(result.confirmed)


if __name__ == "__main__":
    unittest.main()
