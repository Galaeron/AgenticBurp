"""Oracle gap (race_condition, SKL-1): a once-only operation raced past its own
check (a review "like" the app refuses to repeat) was only ever a lead, because
the generic burst had no state read-back.

The leg now reads the object the request names back -- a GET the run captured
whose answer carries the id, else a URL derived from the request -- twice before
the burst (volatile fields dropped), once after it, and once after one
sequential repeat kept inside the gate's burst allowance. It confirms when the
object recorded the effect 2..N times and the app refused the sequential repeat.

Every request goes through the real RunContext transport to a loopback app whose
check-then-act window is opened by a sleep. Controls: an operation that holds its
limit under the burst, a repeatable operation, no reader, a burst allowance with
no room for the repeat, and mutating replay off.
"""
import asyncio
import ast
import json
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import harness.coverage_manifest as cm
from harness.coverage_evidence_case import EvidenceCase, evidence_for
from harness.testing_fixtures.leg_fault import bound_test_names, outcomes_with_leg_severed
from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext, ScopePolicy
from harness.validators.race_condition_validator import (
    RaceConditionValidator, object_refs, reader_candidates)

_TOKEN = "Bearer racer-fixture-token"
_WINDOW = 0.25   # seconds between the app's check and its update


class _Shop(BaseHTTPRequestHandler):
    reviews: dict = {}
    items: dict = {}
    lock = threading.Lock()
    posts: list = []
    gets: list = []
    views = 0

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        type(self).gets.append(path)
        if path == "/api/products/7/reviews":
            data = [{"_id": rid, "product": 7, "message": "fine", **state}
                    for rid, state in self.reviews.items()]
            return self._json(200, {"status": "success", "data": data})
        if path.startswith("/api/items/") and path.count("/") == 3:
            item = self.items.get(path.rsplit("/", 1)[1])
            if item is not None:
                type(self).views += 1
                # Only the counter is exposed (claimers are private): no duplicate entries.
                return self._json(200, {"data": {"id": item["id"], "claims": item["claims"],
                                                 "views": type(self).views}})
        return self._json(404, {"error": "no such route"})

    def do_POST(self):
        path = urlsplit(self.path).path
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        type(self).posts.append(path)
        user = self.headers.get("Authorization", "")
        if path.startswith("/api/items/") and path.endswith("/claim"):
            item = self.items[path.split("/")[3]]
            if user in item["claimedBy"]:
                return self._json(409, {"error": "already claimed"})
            time.sleep(_WINDOW)                           # the check-then-act window
            item["claimedBy"].append(user)
            item["claims"] += 1
            return self._json(200, {"ok": True})
        review = self.reviews.get(json.loads(raw or b"{}").get("id"))
        if review is None:
            return self._json(404, {"error": "no such review"})
        if path == "/api/reviews/like":                   # once per user, check not atomic
            if user in review["likedBy"]:
                return self._json(403, {"error": "Not allowed"})
            time.sleep(_WINDOW)
        elif path == "/api/locked/like":                  # once per user, check atomic
            with self.lock:
                if user not in review["likedBy"]:
                    review["likedBy"].append(user)
                    review["likesCount"] += 1
            return self._json(200, {"likesCount": review["likesCount"]})
        elif path != "/api/repeat/like":                  # /api/repeat/like: no limit
            return self._json(404, {"error": "no such route"})
        review["likedBy"].append(user)
        review["likesCount"] += 1
        return self._json(200, {"likesCount": review["likesCount"]})

    def log_message(self, *args):
        pass


def _finding():
    return Finding(vulnerability_class="race_condition", severity="medium", confidence=0.5,
                   summary="race", evidence="candidate", suggested_test="burst", basis="derived")


class OracleGapRaceTests(EvidenceCase):
    @classmethod
    def setUpClass(cls):
        global_throttle.configure(0)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Shop)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def setUp(self):
        _Shop.reviews = {rid: {"likesCount": 2, "likedBy": ["someone", "other"]}
                         for rid in ("rev7a", "rev7b", "rev7c", "rev7d", "rev7e", "rev7f")}
        _Shop.items = {"4242": {"id": 4242, "claims": 0, "claimedBy": []}}
        _Shop.views = 0
        _Shop.posts, _Shop.gets = [], []

    def _captured(self):
        with urllib.request.urlopen(self.base + "/api/products/7/reviews") as resp:
            body = resp.read().decode()
        _Shop.gets = []
        return [HttpExchange(url=self.base + "/api/products/7/reviews", method="GET",
                             response_status=200, response_body=body).model_dump()]

    def run_leg(self, path, body, *, captured=None, burst=6, mutating=True):
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=80,
            gate_config={"active_enabled": True, "allow_mutating_replay": mutating,
                         "max_burst_size": burst})
        ctx.sessions.register("user", "user", {"Authorization": _TOKEN},
                              allowed_origins=[ScopePolicy.origin_of(self.base)])
        if captured is not None:
            ctx.experiment_context = {"captured": captured}
        exchange = HttpExchange(url=self.base + path, method="POST",
                                request_headers={"Authorization": _TOKEN,
                                                 "Content-Type": "application/json"},
                                request_body=json.dumps(body), response_status=200,
                                response_body='{"likesCount":1}')
        leg = RaceConditionValidator(burst_size=6, run_context=ctx)

        async def scenario():
            try:
                return await leg.validate(_finding(), exchange)
            finally:
                await ctx.aclose()
        return asyncio.run(scenario())

    def test_refs_and_reader_candidates_are_generic(self):
        ex = HttpExchange(url="http://h.test/api/v2/baskets/77/items", method="POST",
                          request_body=json.dumps({"BasketId": "12", "paid": 5, "quantity": 1}))
        self.assertEqual(object_refs(ex), [("BasketId", "12"), ("#4", "77")])
        captured = [
            {"url": "http://h.test/api/v2/baskets/12", "method": "GET", "response_status": 200,
             "response_body": '{"data":{"id":12}}'},
            {"url": "http://h.test/other/12", "method": "GET", "response_status": 200,
             "response_body": '{"id":12}'},
            {"url": "http://h.test/api/logout", "method": "GET", "response_status": 200,
             "response_body": '{"id":12}'},
            {"url": "http://evil.test/api/v2/baskets/12", "method": "GET", "response_status": 200,
             "response_body": '{"id":12}'},
            {"url": "http://h.test/api/v2/baskets/12", "method": "POST", "response_status": 200,
             "response_body": '{"id":12}'},
            HttpExchange(url="http://h.test/api/v2/big", method="GET", response_status=500,
                         response_body='{"id":12}'),
        ]
        urls = reader_candidates(ex, object_refs(ex), captured)
        self.assertEqual(urls[:2], ["http://h.test/api/v2/baskets/12", "http://h.test/other/12"])
        self.assertIn("http://h.test/api/v2/baskets/77", urls)        # the path up to the id
        self.assertIn("http://h.test/api/v2/baskets/77/items", urls)  # the collection itself
        self.assertFalse(any("logout" in u or "evil" in u or "/big" in u for u in urls))

    @evidence_for(**cm.caller_evidence("race_confirm"))
    def test_once_only_like_raced_past_its_check_confirms_by_read_back(self):
        result = self.run_leg("/api/reviews/like", {"id": "rev7a"}, captured=self._captured())
        self.record_observation({"status": result.status, "posts": len(_Shop.posts)})
        self.assertEqual(result.status, "confirmed", result.summary + " | " + result.limitation)
        self.assertTrue(result.confirmed)
        self.assertEqual(result.confidence, 0.9)          # duplicate likedBy entries
        self.assertIn("recorded the effect 5 times", result.summary)
        self.assertIn("refused (HTTP 403)", result.summary)
        self.assertIn("/api/products/7/reviews", result.summary)
        self.assertNotIn("racer-fixture-token", result.summary + result.evidence + result.raw_output)
        self.assertEqual(_Shop.reviews["rev7a"]["likedBy"].count(_TOKEN), 5)
        # Five concurrent copies plus the one sequential repeat: the gate's allowance of 6.
        self.assertEqual(_Shop.posts, ["/api/reviews/like"] * 6)
        self.assertEqual(_Shop.gets, ["/api/products/7/reviews"] * 4)
        raw = ast.literal_eval(result.raw_output)
        self.assertEqual((raw["burst_size"], raw["effects"], raw["control_refused"]), (5, 5, True))

    def test_url_derived_reader_drops_a_volatile_counter(self):
        result = self.run_leg("/api/items/4242/claim", {"note": "x"})
        self.assertEqual(result.status, "confirmed", result.summary + " | " + result.limitation)
        self.assertEqual(result.confidence, 0.8)          # growth, no duplicate entries
        self.assertIn("/api/items/4242", result.summary)
        self.assertIn("refused (HTTP 409)", result.summary)
        self.assertIn("Volatile fields ignored: views", result.evidence)
        self.assertNotIn("`views`", result.summary)

    @evidence_for(**cm.caller_evidence("race_control"))
    def test_control_operation_holding_its_limit_is_a_negative(self):
        result = self.run_leg("/api/locked/like", {"id": "rev7b"}, captured=self._captured())
        self.record_observation({"status": result.status, "posts": len(_Shop.posts)})
        self.assertEqual((result.status, result.control_outcome), ("not_confirmed", ""))
        self.assertFalse(result.confirmed)
        self.assertIn("recorded the effect once", result.summary)
        self.assertEqual(len(_Shop.posts), 5)             # no sequential repeat needed

    def test_control_repeatable_operation_stays_a_lead(self):
        result = self.run_leg("/api/repeat/like", {"id": "rev7c"}, captured=self._captured())
        self.assertEqual(result.status, "not_confirmed")
        self.assertFalse(result.confirmed)
        self.assertTrue(result.summary.startswith(
            "Lead, not confirmed (state read-back not decisive)"), result.summary)
        self.assertIn("repeatable", result.limitation)
        self.assertEqual(len(_Shop.posts), 6)

    def test_control_no_reader_keeps_the_lead_unchanged(self):
        result = self.run_leg("/api/reviews/like", {"id": "rev7d"})
        self.assertEqual(result.status, "not_confirmed")
        self.assertTrue(result.summary.startswith("Lead, not confirmed (no state read-back)"),
                        result.summary)
        self.assertIn("No state read-back", result.limitation)
        raw = ast.literal_eval(result.raw_output)
        self.assertNotIn("readback", raw)
        self.assertEqual(raw["burst_size"], 6)            # nothing kept back for a repeat
        self.assertEqual(len(_Shop.posts), 6)
        self.assertEqual(len(_Shop.gets), 3)              # the URL-derived candidates, all 404

    def test_control_allowance_without_room_for_the_repeat_stays_a_lead(self):
        result = self.run_leg("/api/reviews/like", {"id": "rev7e"}, captured=self._captured(),
                              burst=2)
        self.assertEqual(result.status, "not_confirmed")
        self.assertIn("left no sequential repeat", result.limitation)
        self.assertEqual(len(_Shop.posts), 2)

    def test_control_mutating_replay_off_sends_nothing(self):
        result = self.run_leg("/api/reviews/like", {"id": "rev7f"}, captured=self._captured(),
                              mutating=False)
        self.assertEqual(result.status, "blocked")
        self.assertEqual((_Shop.posts, _Shop.gets), ([], []))

    # --- Fault injection: a bound aspect must notice a disconnected leg ---------
    def test_bound_aspects_fail_when_the_leg_is_disconnected(self):
        names = bound_test_names(type(self))
        self.assertEqual(len(names), 2, f"bound tests went missing: {names}")
        for name, outcome in outcomes_with_leg_severed(type(self), names).items():
            with self.subTest(test=name):
                self.assertNotEqual(outcome, "passed",
                                    f"{name} still passes with the leg disconnected: not evidence")


if __name__ == "__main__":
    unittest.main()
