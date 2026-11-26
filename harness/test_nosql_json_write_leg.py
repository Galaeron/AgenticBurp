"""R11-8 (a): the nosql leg mutated the crawler's guessed `name`/`value` body on the
review writes and never the request's own `id`, and shape opened the leg only for
a login.

Now a captured JSON PUT/PATCH with scalar fields of its own gets a nosql leg with
no agent label, when the run's write gates admit its replays (active_enabled,
allow_mutating_replay and a nosql write ceiling that pays for one verdict), and
the leg tries the body's own id-like field first. A guessed body is never a
target.

The caller tests drive Orchestrator.investigate_engagement (discovery canned,
model silent) against a loopback review store whose PATCH matches `id` as a
Mongo-style filter; a sibling route casts `id` to a string first. Controls: the
cast route, write gates closed, the default write ceiling, a body with no scalar
field, a POST create, a guessed body, and the login leg.
"""
from __future__ import annotations

import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.orchestrator_helpers import shape_precondition_legs
from harness.role_crawl import RoleSession, _GENERIC_JSON_BODY
from harness.run_context import RunContext
from harness.safety_gate import SafetyGate, SafetyGateConfig
from harness.test_engagement_transport_callers import (
    _EngagementCallerBase, _Model, _canned, _config, _install_model)
from harness.validators.nosql_validator import (
    NosqlValidator, guessed_body, json_write_fields, operator_targets)

_REVIEWS = [{"id": "r-1", "message": "a"}, {"id": "r-2", "message": "b"},
            {"id": "r-3", "message": "c"}]


class _Store(BaseHTTPRequestHandler):
    """PATCH /api/reviews: `{"id": <filter>, "message": m}` updates every review the
    filter matches. /api/cast-reviews casts the filter to a string first."""
    sent: list = []

    def _reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length).decode() if length else ""

    def do_PATCH(self):
        raw = self._body()
        type(self).sent.append(("PATCH", self.path, raw))
        try:
            doc = json.loads(raw or "{}")
        except ValueError:
            return self._reply(400, {"error": "bad json"})
        key = doc.get("id")
        if self.path.startswith("/api/cast-reviews"):
            key = str(key)
        if isinstance(key, dict) and "$ne" in key:
            hits = [r for r in _REVIEWS if r["id"] != key["$ne"]]
        elif isinstance(key, dict) and "$eq" in key:
            hits = [r for r in _REVIEWS if r["id"] == key["$eq"]]
        elif isinstance(key, dict) and "$in" in key:
            hits = [r for r in _REVIEWS if r["id"] in key["$in"]]
        else:
            hits = [r for r in _REVIEWS if r["id"] == key]
        return self._reply(200, {"modified": len(hits), "original": hits})

    def _other(self):
        raw = self._body()
        type(self).sent.append((self.command, self.path, raw))
        self._reply(200, {})

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = _other

    def log_message(self, *args):
        pass


def _review_patch(base, path="/api/reviews", body='{"id": "r-2", "message": "mine"}',
                  method="PATCH"):
    return HttpExchange(url=base + path, method=method,
                        request_headers={"Content-Type": "application/json"},
                        request_body=body, response_status=200,
                        response_headers={"Content-Type": "application/json"},
                        response_body=json.dumps({"modified": 1, "original": [_REVIEWS[1]]}))


def _node(path="/api/reviews", method="PATCH"):
    return {"method": method, "path": path, "by_role": {"anonymous": 200},
            "reachable_roles": ["anonymous"], "object_scoped": False}


def _operator_on_id(raw: str) -> bool:
    try:
        return isinstance(json.loads(raw or "{}").get("id"), dict)
    except (ValueError, AttributeError):
        return False


class NosqlJsonWriteDispatchTests(_EngagementCallerBase, unittest.TestCase):
    """investigate_engagement -> shape precondition -> _confirm -> nosql leg."""

    @classmethod
    def setUpClass(cls):
        global_throttle.configure(0)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Store)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def _engage(self, *, path="/api/reviews", method="PATCH", body=None,
                mutating=True, ceiling=15):
        """One engagement over the captured write; returns (nosql results, sends)."""
        cfg = _config(mutating=mutating)
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _install_model(orch, _Model([]))
        gate = {"active_enabled": True, "allow_mutating_replay": mutating}
        if ceiling:
            gate["mutating_ceiling_by_check"] = {"nosql": ceiling}
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=400, config=cfg,
                               gate_config=gate)
        captured = (lambda base: _review_patch(
            base, path, method=method,
            **({"body": body} if body is not None else {})).model_dump(),)
        results: list = []
        real_validate = NosqlValidator.validate

        async def recording(validator, finding, exchange):
            result = await real_validate(validator, finding, exchange)
            results.append((exchange.method, exchange.url, result))
            return result

        async def go():
            try:
                async with rc:
                    return await orch.investigate_engagement(
                        self.base, [RoleSession("anonymous", {})], max_nodes=2,
                        step_budget=1, max_chain_rounds=0, run_context=rc,
                        objective_class="nosql")
            finally:
                await rc.aclose()

        patches = [patch("harness.engagement_builder.build_engagement",
                         side_effect=_canned([_node(path, method)], captured)),
                   patch("harness.browser_driver.default_driver", return_value=None),
                   patch.object(NosqlValidator, "validate", recording)]
        _Store.sent = []
        for p in patches:
            p.start()
        try:
            asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        return results, list(_Store.sent)

    def test_id_operator_that_widens_the_match_confirms_with_no_label(self):
        results, sent = self._engage()
        self.assertTrue(results, "no nosql leg reached the captured JSON PATCH")
        confirmed = [r for _, _, r in results if r.status == "confirmed"]
        self.assertTrue(confirmed, [r.summary for _, _, r in results])
        self.assertIn("'id'", confirmed[0].summary)
        ops = [b for m, p, b in sent if m == "PATCH" and _operator_on_id(b)]
        self.assertTrue(ops, "no operator was put into the body's own id")
        # The other field keeps its captured value: only `id` carried the operator.
        self.assertTrue(all(json.loads(b)["message"] == "mine" for b in ops))

    def test_control_server_that_casts_id_to_a_string_does_not_confirm(self):
        results, sent = self._engage(path="/api/cast-reviews")
        self.assertTrue(results, "no nosql leg reached the captured JSON PATCH")
        self.assertTrue([b for m, p, b in sent if m == "PATCH" and _operator_on_id(b)])
        self.assertFalse([r for _, _, r in results if r.confirmed],
                         [r.summary for _, _, r in results])

    def test_control_mutating_replay_off_opens_no_leg_and_sends_no_operator(self):
        results, sent = self._engage(mutating=False)
        self.assertEqual(results, [])
        self.assertFalse([b for _, _, b in sent if _operator_on_id(b)])

    def test_control_default_write_ceiling_opens_no_leg(self):
        results, sent = self._engage(ceiling=0)
        self.assertEqual(results, [])
        self.assertFalse([b for _, _, b in sent if _operator_on_id(b)])

    def test_control_body_without_scalar_fields_opens_no_leg(self):
        results, _ = self._engage(body='{"items": [{"id": "r-2"}], "meta": {"id": "r-2"}}')
        self.assertEqual(results, [])

    def test_control_guessed_body_opens_no_leg(self):
        results, sent = self._engage(body=_GENERIC_JSON_BODY)
        self.assertEqual(results, [])
        self.assertFalse([b for _, _, b in sent if "$ne" in b])

    def test_removing_the_json_write_precondition_loses_the_dispatch(self):
        """Defect injection: without the JSON-write shape the leg needs a model
        label, the silent model gives none, so the positive must fail."""
        with patch("harness.orchestrator_helpers._nosql_json_write_candidate",
                   return_value=False):
            results, _ = self._engage()
        self.assertEqual(results, [], "dispatch survived -- the positive test is vacuous")


def _gate(*, active=True, mutating=True, ceiling=15):
    by_check = {"nosql": ceiling} if ceiling else {}
    return SafetyGate(SafetyGateConfig(active_enabled=active, allow_mutating_replay=mutating,
                                       mutating_ceiling_by_check=by_check))


class NosqlJsonWriteShapeTests(unittest.TestCase):
    ROLES = [RoleSession("anonymous", {})]

    def legs(self, exchange, gate, node=None):
        node = node or _node(method=exchange.method)
        return [c for c, _ in shape_precondition_legs(node, exchange, self.ROLES, "http://t",
                                                      gate=gate)]

    def test_json_update_gets_one_nosql_leg_when_gates_admit_it(self):
        for method in ("PUT", "PATCH"):
            legs = self.legs(_review_patch("http://t", method=method), _gate())
            self.assertEqual(legs.count("nosql"), 1, (method, legs))

    def test_each_write_gate_alone_closes_the_leg(self):
        ex = _review_patch("http://t")
        for gate in (_gate(active=False), _gate(mutating=False), _gate(ceiling=0),
                     _gate(ceiling=5)):
            self.assertNotIn("nosql", self.legs(ex, gate))

    def test_post_create_gets_no_shape_leg(self):
        ex = _review_patch("http://t", method="POST")
        self.assertNotIn("nosql", self.legs(ex, _gate()))

    def test_body_without_scalar_fields_gets_no_leg(self):
        ex = _review_patch("http://t", body='{"items": [1, 2], "meta": {"id": "x"}}')
        self.assertEqual(json_write_fields(ex), [])
        self.assertNotIn("nosql", self.legs(ex, _gate()))

    def test_login_candidate_keeps_its_leg_with_write_gates_closed(self):
        ex = HttpExchange(url="http://t/login", method="POST",
                          request_headers={"Content-Type": "application/x-www-form-urlencoded"},
                          request_body="csrf=x&username=u&password=p")
        closed = _gate(active=False, mutating=False, ceiling=0)
        legs = self.legs(ex, closed, node={"method": "POST", "path": "/login"})
        self.assertEqual(legs.count("nosql"), 1, legs)

    def test_json_login_update_is_still_one_leg(self):
        ex = HttpExchange(url="http://t/login", method="POST",
                          request_headers={"Content-Type": "application/json"},
                          request_body='{"username": "u", "password": "p"}')
        legs = self.legs(ex, _gate(), node={"method": "POST", "path": "/login"})
        self.assertEqual(legs.count("nosql"), 1, legs)


class NosqlTargetChoiceTests(unittest.TestCase):
    def test_id_like_body_fields_come_first(self):
        ex = _review_patch("http://t", body=json.dumps(
            {"message": "m", "note": "n", "author": "a", "reviewId": "r-2", "id": "r-2"}))
        names = [p for _, p in operator_targets(ex)]
        self.assertEqual(names[:2], ["reviewId", "id"])
        self.assertEqual(set(names), {"message", "note", "author", "reviewId", "id"})

    def test_guessed_body_and_a_leg_variant_of_it_are_not_targets(self):
        variant = json.dumps({**json.loads(_GENERIC_JSON_BODY), "role": "admin",
                              "isAdmin": True})
        for body in (_GENERIC_JSON_BODY, variant):
            ex = _review_patch("http://t", body=body)
            self.assertTrue(guessed_body(ex), body)
            self.assertEqual(operator_targets(ex), [])
        self.assertFalse(guessed_body(_review_patch("http://t")))

    def test_guessed_body_is_skipped_unsent_and_is_not_a_negative(self):
        sent = []

        class _Never(BaseHTTPRequestHandler):
            def do_PATCH(self):
                sent.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Never)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        finding = Finding(vulnerability_class="NoSQL Injection", confidence=0.5,
                          severity="high", summary="s", evidence="e", suggested_test="t",
                          basis="derived", finding_id="f-guess")
        exchange = _review_patch(base, body=_GENERIC_JSON_BODY)
        config = {"server": {"allowed_hosts": ["127.0.0.1"]},
                  "validators": {"enabled": True, "active_enabled": True}}

        async def run():
            async with RunContext.create(
                    allowed_hosts=["127.0.0.1"], config=config,
                    gate_config={"active_enabled": True, "allow_mutating_replay": True,
                                 "mutating_ceiling_by_check": {"nosql": 15}}) as ctx:
                return await NosqlValidator(["127.0.0.1"], run_context=ctx).validate(
                    finding, exchange)
        result = asyncio.run(run())
        self.assertEqual(sent, [])
        self.assertEqual(result.status, "skipped")
        self.assertIn("crawler's guess", result.summary)


if __name__ == "__main__":
    unittest.main()
