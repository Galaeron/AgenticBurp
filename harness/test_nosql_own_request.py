"""r7: two NoSQL-injection findings, on a JSON-body POST and a PUT, never reached
their own requests. The nosql leg only knew a login-form differential: any other
request was skipped unsent, and the run's only nosql traffic was that leg GETting
a login URL for an HTML form. The leg now runs an operator differential on the
finding's own request (method, URL, headers and body), through the run transport
and its active/mutating gates.

The caller tests drive the real confirmation caller (_validate_findings), the
real registry and the real suppression gate over a loopback JSON API; only
persistence is stubbed. Controls: an endpoint that treats operator objects as
plain values refutes, and with mutating replay off nothing is sent.
"""
import asyncio
import json
import threading
import unittest
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, patch

from harness import global_throttle
from harness.confirmation_gate import apply_confirmation_suppression
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator_confirm import ConfirmMixin
from harness.run_context import RunContext
from harness.validators.registry import ValidatorRegistry

_ROWS = [{"id": 1, "city": "Springfield", "owner": "a"}, {"id": 2, "city": "Shelbyville", "owner": "b"}]


class _Api(BaseHTTPRequestHandler):
    """/api/items/search (POST/PUT JSON) evaluates a Mongo-style filter on `city`;
    /api/items/plain stores every value as given and answers the same way."""
    sent: list = []

    def _reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode() if length else ""
        type(self).sent.append((self.command, self.path, raw))
        try:
            doc = json.loads(raw or "{}")
        except ValueError:
            return self._reply(400, {"error": "bad json"})
        city = doc.get("city")
        if self.path.startswith("/api/items/search"):
            if isinstance(city, dict) and "$ne" in city:
                rows = [r for r in _ROWS if r["city"] != city["$ne"]]
            elif isinstance(city, dict) and "$eq" in city:
                rows = [r for r in _ROWS if r["city"] == city["$eq"]]
            else:
                rows = [r for r in _ROWS if r["city"] == city]
            return self._reply(200, {"data": rows})
        return self._reply(201, {"status": "success", "data": {"id": 9, "city": str(city)}})

    do_POST = do_PUT = _handle

    def do_GET(self):
        type(self).sent.append((self.command, self.path, ""))
        self._reply(500, {"error": "no form here"})

    def log_message(self, *args):
        pass


class NosqlOwnRequestCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global_throttle.configure(0)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Api)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def run_caller(self, method, path, *, mutating=True, name="", ceiling=15):
        finding = Finding(vulnerability_class="NoSQL Injection", confidence=0.6, severity="high",
                          summary="JSON body parameters may reach a MongoDB query",
                          evidence="synthetic", suggested_test="{\"$ne\": null}", basis="derived",
                          finding_id="f-nosql", parameter_location="body" if name else "",
                          parameter_name=name)

        async def run():
            hosts = ["127.0.0.1"]
            gate = {"active_enabled": True, "allow_mutating_replay": mutating,
                    "mutating_ceiling_by_check": {"nosql": ceiling} if ceiling else {}}
            config = {"server": {"allowed_hosts": hosts},
                      "validators": {"enabled": True, "active_enabled": True}}
            caller = ConfirmMixin()
            caller.config = config
            caller.allowed_hosts = hosts
            caller.validator_registry = ValidatorRegistry(config)
            caller.validator_registry.validators = {
                "nosql": caller.validator_registry.validators["nosql"]}
            exchange = HttpExchange(url=self.base + path, method=method,
                                    request_headers={"Content-Type": "application/json"},
                                    request_body='{"city": "Springfield", "note": "x"}',
                                    response_status=200, response_body='{"data": []}')
            report = AgentReport(agent="nosql", model="synthetic", findings=[finding])
            context = RunContext.create(allowed_hosts=hosts, config=config, gate_config=gate)
            _Api.sent = []
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.object(caller, "_persist_confirmation_proof", AsyncMock(
                        return_value=(True, {"proof_id": "synthetic"}, ""))))
                    stack.enter_context(patch("harness.store.persist_test_plans"))
                    stack.enter_context(patch("harness.store.persist_validation_submission",
                                              return_value=(True, "")))
                    stack.enter_context(patch("harness.evidence_ledger.emit"))
                    validations, _ = await caller._validate_findings(
                        exchange, [report], run_context=context)
            finally:
                await context.aclose()
            apply_confirmation_suppression([report], validations)
            nosql = [v for v in validations if v.validator == "nosql"]
            self.assertEqual(len(nosql), 1, validations)
            return nosql[0], finding, list(_Api.sent)
        return asyncio.run(run())

    def test_post_finding_is_confirmed_on_its_own_request(self):
        v, f, sent = self.run_caller("POST", "/api/items/search")
        self.assertEqual(v.status, "confirmed", v.summary)
        self.assertTrue(f.confirmed)
        self.assertIn("'city'", v.summary)
        # Every send is the finding's own method and path, never a GET elsewhere.
        self.assertTrue(sent)
        self.assertEqual({(m, p) for m, p, _ in sent}, {("POST", "/api/items/search")})
        self.assertIn({"$ne": json.loads(sent[0][2])["city"]["$ne"]}, [json.loads(b)["city"] for _, _, b in sent])
        self.assertTrue(all(json.loads(b)["note"] == "x" for _, _, b in sent))

    def test_put_finding_keeps_its_method(self):
        v, _, sent = self.run_caller("PUT", "/api/items/search/1")
        self.assertEqual(v.status, "confirmed", v.summary)
        self.assertEqual({m for m, _, _ in sent}, {"PUT"})

    def test_named_parameter_absent_tests_the_real_ones_and_is_marked(self):
        v, f, sent = self.run_caller("POST", "/api/items/plain", name="value")
        self.assertTrue(sent)
        self.assertEqual(v.status, "not_confirmed")
        self.assertEqual(v.control_outcome, "named_parameter_untested")
        self.assertEqual(f.review_verdict, "inconclusive_unverified")

    def test_control_plain_value_endpoint_is_not_confirmed(self):
        v, f, sent = self.run_caller("POST", "/api/items/plain")
        self.assertTrue(sent)
        self.assertEqual({(m, p) for m, p, _ in sent}, {("POST", "/api/items/plain")})
        self.assertEqual((v.status, v.control_outcome), ("not_confirmed", ""))
        self.assertFalse(f.confirmed)

    def test_default_write_ceiling_refuses_unsent_and_is_not_a_negative(self):
        v, f, sent = self.run_caller("POST", "/api/items/search", ceiling=0)
        self.assertEqual(sent, [])
        self.assertEqual(v.status, "skipped")
        self.assertIn("mutating_ceiling_by_check.nosql", v.summary)
        self.assertNotEqual(f.review_verdict, "unconfirmed_hypothesis")

    def test_control_mutating_replay_off_sends_nothing(self):
        v, f, sent = self.run_caller("POST", "/api/items/search", mutating=False)
        self.assertEqual(sent, [])
        self.assertNotEqual(v.status, "confirmed")
        self.assertFalse(f.confirmed)


if __name__ == "__main__":
    unittest.main()
