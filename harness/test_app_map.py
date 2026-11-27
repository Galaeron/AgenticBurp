"""HU-3: the application map, caller level.

A real ThreadingHTTPServer on 127.0.0.1 plays a generic two-role application:
orders are private to their creator, items are a catalogue only the admin may
change, and the profile update accepts a client-sent role. Each exchange is sent
for real, then captured through the production path -- Orchestrator.analyze with
the analyst's attribution, which retains it via store.record_observation --
with every model client replaced by a silent, counting stub. The creator's
ownership fact is stored the way a run leaves it. The map is then read through
the FastAPI route and the report.

  map        objects, owners, id patterns, role outcomes, value fields, workflow
  traffic    building the map sends nothing to the app and calls no model
  proposed   a stored semantic model's items are all `proposed`; the observed part
             of the map is identical with and without it (negative control)
  report     the section is absent by default and present with the key on
"""
from __future__ import annotations

import asyncio
import json
import re
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

from harness import app_map, store
from harness.application_semantic_model import (ApplicationSemanticModel, BusinessObject,
                                                ChainingHypothesis, Role, SensitiveSink,
                                                ValueFlow, Workflow)
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.principals import OwnershipFact, object_reference
from harness.test_cross_request_prior_context import _IsolatedStateCase
from harness.test_smoke_detection import _test_config

_TOKENS = {"tok-alice": "alice", "tok-bob": "bob", "tok-root": "root"}
_ROLES = {"alice": "user", "bob": "user", "root": "admin"}
_ORDER = 7


class _App:
    """Orders: owner-only. Items: every signed-in user lists them; only the admin
    updates one. Profile: accepts whatever the client sends."""

    def __init__(self):
        self.requests: list = []
        self.orders: dict = {}
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _begin(self):
                user = _TOKENS.get(self.headers.get("Authorization", "").replace("Bearer ", "", 1))
                length = int(self.headers.get("Content-Length") or 0)
                text = self.rfile.read(length).decode() if length else ""
                app.requests.append((self.command, self.path, user))
                return user, (json.loads(text) if text else {})

            def _route(self):
                user, body = self._begin()
                if user is None:
                    return self._send(401, {"error": "login required"})
                path, method = self.path, self.command
                if method == "GET" and path == "/api/items":
                    return self._send(200, {"data": [{"id": 1, "name": "widget", "price": 5}]})
                if method == "PUT" and re.fullmatch(r"/api/items/\d+", path):
                    if _ROLES[user] != "admin":
                        return self._send(403, {"error": "admins only"})
                    return self._send(200, {"data": {"id": 1, **body}})
                if method == "POST" and path == "/api/orders":
                    app.orders[_ORDER] = user
                    return self._send(201, {"data": {"id": _ORDER, "owner": user}})
                order = re.fullmatch(r"/api/orders/(\d+)", path)
                if method == "GET" and order:
                    if app.orders.get(int(order.group(1))) != user:
                        return self._send(403, {"error": "forbidden"})
                    return self._send(200, {"data": {"id": _ORDER, "owner": user, "total": 10}})
                if method == "PATCH" and path == "/api/profile":
                    return self._send(200, {"data": {"name": user, **body}})
                return self._send(404, {"error": "not found"})

            do_GET = do_POST = do_PUT = do_PATCH = _route

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.host = self.base.split("://", 1)[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def exchange(self, method, path, user, body=None, *, captured_at):
        """Send one request for real and return it as a captured HttpExchange."""
        token = next(t for t, u in _TOKENS.items() if u == user)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        data = json.dumps(body) if body is not None else ""
        req = urllib.request.Request(self.base + path, data=data.encode() if data else None,
                                     method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status, text = resp.status, resp.read().decode()
        except urllib.error.HTTPError as err:
            status, text = err.code, err.read().decode()
        return HttpExchange(url=self.base + path, method=method, request_headers=headers,
                            request_body=data, response_status=status,
                            response_headers={"Content-Type": "application/json"},
                            response_body=text, captured_at=captured_at)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


class _SilentModel:
    """Every model client: no findings, and every call is counted."""

    def __init__(self):
        self.calls = 0

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1, **kw):
        self.calls += 1
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1, **kw):
        self.calls += 1
        return OllamaResult(data={"findings": [], "components": []}, prompt_tokens=1,
                            completion_tokens=1)


def _orchestrator(model) -> Orchestrator:
    orch = Orchestrator(_test_config())
    orch.ollama = model
    for agent in orch.agent_manager.agents.values():
        agent.ollama = model
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = model
    coordinator = getattr(orch, "coordinator", None)
    if coordinator is not None and hasattr(coordinator, "ollama"):
        coordinator.ollama = model
    return orch


# (captured_at, user, method, path, body) -- ingested OUT of capture order below.
_CAPTURES = [
    (100.0, "alice", "GET", "/api/items", None),
    (110.0, "alice", "POST", "/api/orders", {"item_id": 1, "quantity": 2, "unit_price": 5,
                                             "note": "gift"}),
    (120.0, "alice", "GET", f"/api/orders/{_ORDER}", None),
    (130.0, "alice", "PATCH", "/api/profile", {"display_name": "Alice", "role": "admin",
                                               "is_admin": True}),
    (140.0, "alice", "PUT", "/api/items/1", {"name": "widget", "price": 1}),
    (200.0, "bob", "GET", f"/api/orders/{_ORDER}", None),
    (300.0, "root", "PUT", "/api/items/1", {"name": "widget", "price": 9}),
]


def _asm() -> ApplicationSemanticModel:
    return ApplicationSemanticModel(
        host="127.0.0.1",
        roles=[Role(name="auditor", privilege_rank=2, source="surface"),
               Role(name="user", privilege_rank=1, source="surface")],
        business_objects=[
            BusinessObject(name="Order", id_params=["id"], object_scoped=True,
                           read_endpoints=["GET /api/orders/{id}"],
                           write_endpoints=["POST /api/orders"]),
            BusinessObject(name="Coupon", id_params=["code"],
                           write_endpoints=["POST /api/coupons"])],
        workflows=[Workflow(name="checkout", category="commerce",
                            steps=["POST /api/orders", "POST /api/payments"],
                            stages=["order", "pay"])],
        value_flows=[ValueFlow(param="quantity", kind="quantity", endpoints=["POST /api/orders"]),
                     ValueFlow(param="coupon_code", kind="price", endpoints=["POST /api/coupons"])],
        sensitive_sinks=[SensitiveSink(name="payments", category="payment",
                                       endpoints=["POST /api/payments"])],
        chaining_hypotheses=[ChainingHypothesis(
            id="bch:order-idor", source="IDOR on Order", target="payment sink",
            rationale="orders are addressed by id", rank=0.7, classes=["idor"],
            endpoints=["GET /api/orders/{id}"])])


def _observed_only(doc: dict) -> dict:
    return {k: [i for i in doc[k] if i["basis"] == "observed"]
            for k in ("roles", "objects", "endpoints", "value_fields", "workflows")}


class AppMapCallerTests(_IsolatedStateCase, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.app = _App()
        self.addCleanup(self.app.close)
        self.model = _SilentModel()
        orch = _orchestrator(self.model)
        exchanges = [(user, self.app.exchange(method, path, user, body, captured_at=at))
                     for at, user, method, path, body in _CAPTURES]
        for user, exchange in reversed(exchanges):            # ingest order != capture order
            result = asyncio.run(orch.analyze(
                exchange, force_agents=["idor"], bypass_cache=True,
                observation_attribution={"principal_ref": user, "role": _ROLES[user]}))
            self.assertEqual(result.observation_context["write"]["status"], "stored", result)
            self.assertFalse(any(r.findings for r in result.agent_reports))   # silent model
        store.save_ownership_fact(OwnershipFact(
            object_ref=object_reference(f"{self.app.base}/api/orders/{_ORDER}", run_id="run-1"),
            owner_principal_id="alice", provenance="created-as:alice"))
        self.app.requests.clear()
        self.model.calls = 0

    def _client(self):
        from fastapi.testclient import TestClient
        import harness.server as server
        return TestClient(server.app, base_url="http://localhost",
                          headers={"Authorization": f"Bearer {server._mutation_token()}"})

    def _get_map(self):
        response = self._client().get(f"/engagement/{self.app.host}/map")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _seed_asm(self):
        import time
        import harness.server as server
        server._job_store().create({
            "job_id": "job-map-1", "host": self.app.host, "base_url": self.app.base,
            "status": "done", "started_at": time.time(), "finished_at": time.time(),
            "result": {"application_semantic_model": _asm().to_dict()}})

    def test_the_map_lists_objects_owners_role_outcomes_and_value_fields(self):
        doc = self._get_map()
        self.assertEqual((doc["sends_traffic"], doc["model_calls"]), (False, 0))
        self.assertEqual(doc["sources"]["observations"], len(_CAPTURES))
        self.assertIsNone(doc["sources"]["semantic_model"])
        self.assertEqual({r["name"] for r in doc["roles"]}, {"user", "admin"})
        self.assertTrue(all(r["basis"] == "observed" for r in doc["roles"]))
        user = next(r for r in doc["roles"] if r["name"] == "user")
        self.assertEqual(user["principals"], ["alice", "bob"])

        objects = {o["object_type"]: o for o in doc["objects"]}
        self.assertEqual(set(objects), {"Item", "Order", "Profile"})
        order = objects["Order"]
        self.assertEqual(order["owners"], [{"principal": "alice", "objects_owned": 1,
                                            "basis": "observed"}])
        self.assertEqual([(p["route"], p["pattern"]) for p in order["id_patterns"]],
                         [("/api/orders/{id}", "integer")])
        self.assertEqual(order["actions"], ["read", "create"])
        self.assertEqual(objects["Item"]["owners"], [])

        endpoints = {e["key"]: e for e in doc["endpoints"]}
        outcomes = {k: {r["role"]: (r["outcome"], r["statuses"], r["principals"])
                        for r in e["role_outcomes"]} for k, e in endpoints.items()}
        self.assertEqual(outcomes["GET /api/orders/{id}"]["user"],
                         ("mixed", [200, 403], ["alice", "bob"]))
        self.assertEqual(outcomes["PUT /api/items/{id}"],
                         {"user": ("denied", [403], ["alice"]),
                          "admin": ("allowed", [200], ["root"])})
        self.assertEqual(outcomes["POST /api/orders"]["user"][0], "allowed")
        self.assertEqual(endpoints["PUT /api/items/{id}"]["object_type"], "Item")

        fields = {(f["field"], f["kind"]) for f in doc["value_fields"]}
        self.assertTrue({("quantity", "quantity"), ("unit_price", "price"), ("role", "role"),
                         ("is_admin", "role"), ("price", "price")} <= fields, fields)
        self.assertNotIn("note", {f["field"] for f in doc["value_fields"]})       # not value-bearing
        self.assertNotIn("display_name", {f["field"] for f in doc["value_fields"]})
        price = next(f for f in doc["value_fields"] if f["field"] == "price")
        self.assertEqual(price["endpoints"], ["PUT /api/items/{id}"])
        self.assertTrue(all(f["basis"] == "observed" for f in doc["value_fields"]))

        flows = {w["principal"]: w for w in doc["workflows"]}
        self.assertEqual(set(flows), {"alice"})                    # bob and root: one step each
        self.assertEqual(flows["alice"]["order_basis"], "capture")
        self.assertEqual([s["endpoint"] for s in flows["alice"]["steps"]], [
            "GET /api/items", "POST /api/orders", "GET /api/orders/{id}", "PATCH /api/profile",
            "PUT /api/items/{id}"])
        self.assertEqual(doc, self._get_map())                      # deterministic

    def test_a_corrupted_capture_gives_no_fields_and_is_named_unresolved(self):
        """Evidence integrity (2026-11-26): the map reads capture bytes through the
        verified reader. An intact store lists no unresolved capture (control); a
        capture whose blob no longer hashes to its sha256 contributes no fields
        and is named in sources.evidence_unresolved."""
        doc = self._get_map()
        self.assertEqual(doc["sources"]["evidence_unresolved"], [])
        self.assertIn("is_admin", {f["field"] for f in doc["value_fields"]})
        conn = store._connect()
        try:
            oid, sha = conn.execute("SELECT observation_id, evidence_sha256 FROM exchange_observations "
                                    "WHERE method = 'PATCH'").fetchone()
            conn.execute("UPDATE evidence_blobs SET data = ? WHERE sha256 = ?",
                         (b'{"request_body": {"is_superuser": true}}', sha))
            conn.commit()
        finally:
            conn.close()
        doc = self._get_map()
        self.assertEqual(doc["sources"]["evidence_unresolved"], [oid])
        fields = {f["field"] for f in doc["value_fields"]}
        self.assertNotIn("is_admin", fields)        # the capture's real bytes are gone
        self.assertNotIn("is_superuser", fields)    # and the rewritten bytes are not served
        self.assertIn("quantity", fields)           # intact captures still feed the map

    def test_building_the_map_sends_no_traffic_and_calls_no_model(self):
        self._seed_asm()
        self._get_map()
        app_map.build_map(self.app.host)
        app_map.report_section(self.app.host, config={"app_map": {"report_section": True}})
        self.assertEqual(self.app.requests, [])
        self.assertEqual(self.model.calls, 0)

    def test_a_model_hypothesis_is_always_proposed_never_observed(self):
        without = self._get_map()
        self._seed_asm()
        doc = self._get_map()
        self.assertEqual(doc["sources"]["semantic_model"], "job:job-map-1")
        # Negative control: the overlay adds proposed items and changes no observed one.
        self.assertEqual(_observed_only(doc), _observed_only(without))
        self.assertEqual(without["hypotheses"], [])
        proposed = {k: [i for i in doc[k] if i["basis"] == "proposed"]
                    for k in ("roles", "objects", "value_fields", "workflows", "hypotheses")}
        self.assertEqual({r["name"] for r in proposed["roles"]}, {"auditor", "user"})
        self.assertEqual({o["object_type"]: o["also_observed"] for o in proposed["objects"]},
                         {"Order": True, "Coupon": False})
        self.assertEqual({f["field"] for f in proposed["value_fields"]}, {"quantity", "coupon_code"})
        self.assertEqual([w["name"] for w in proposed["workflows"]], ["checkout"])
        self.assertEqual({h["kind"] for h in proposed["hypotheses"]},
                         {"sensitive_sink", "chaining_hypothesis"})
        self.assertTrue(all(h["basis"] == "proposed" for h in doc["hypotheses"]))
        # Nothing the model alone said is labelled observed.
        observed = _observed_only(doc)
        self.assertNotIn("auditor", {r["name"] for r in observed["roles"]})
        self.assertNotIn("Coupon", {o["object_type"] for o in observed["objects"]})
        self.assertNotIn("coupon_code", {f["field"] for f in observed["value_fields"]})
        self.assertNotIn("checkout", {w["name"] for w in observed["workflows"]})
        every = [i for k in ("roles", "objects", "endpoints", "value_fields", "workflows",
                             "hypotheses") for i in doc[k]]
        self.assertTrue(all(i["basis"] in ("observed", "proposed") for i in every))

    def test_report_section_is_absent_by_default_and_present_with_the_key_on(self):
        from harness.report_generator import generate_report_for_host
        shipped = yaml.safe_load((Path(app_map.__file__).parent / "config.yaml").read_text())
        self.assertIs(shipped["app_map"]["report_section"], False)
        url = self.app.base + "/"
        self.assertNotIn("## Application Map", generate_report_for_host(url, config=shipped))
        self.assertNotIn("## Application Map", generate_report_for_host(url))
        self._seed_asm()
        on = dict(shipped, app_map={"report_section": True})
        report = generate_report_for_host(url, config=on)
        self.assertIn("## Application Map", report)
        self.assertIn("| Order | read, create | /api/orders/{id}: integer | alice (1) |", report)
        self.assertIn("admin: allowed [200]; user: denied [403]", report)       # PUT /api/items
        self.assertIn("`unit_price` (price, body)", report)
        self.assertIn("### Proposed by the model (hypotheses, not observed)", report)
        self.assertIn("proposed object: Coupon", report)
        self.assertEqual(self.app.requests, [])


if __name__ == "__main__":
    unittest.main()
