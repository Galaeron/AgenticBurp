"""client_trust beyond a price: server-owned fields recognised by key semantics
and value shape (a payment source, a quantity, a role), each against an owned
loopback JSON store with its negative control on the same store.

The store is generic (nothing application-specific): sessions are bearer tokens
shaped like JWTs, an upgrade endpoint takes a payment method, a cart-item
collection takes a quantity, a profile takes a role. Each vulnerable mode has a
matching safe mode (payment method validated, quantity range-checked or clamped,
role ignored), and every test checks what was left behind.
"""
import asyncio
import base64
import json
import secrets
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harness import global_throttle, safety_gate
from harness.models import Finding, HttpExchange
from harness.orchestrator_helpers import _has_client_trust_shape
from harness.validators.client_trust_validator import ClientTrustValidator, has_trust_shape, trust_fields


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _token(uid: int, role: str) -> str:
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'status': 'success', 'data': {'id': uid, 'role': role}})}.sig{secrets.token_hex(6)}"


class _Store(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def user(self):
        auth = self.headers.get("Authorization") or ""
        return self.server.tokens.get(auth.removeprefix("Bearer "))

    def parts(self):
        return [p for p in self.path.split("?")[0].split("/") if p]

    def body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}")

    def do_GET(self):
        self.server.received.append(("GET", self.path))
        p, srv = self.parts(), self.server
        if p == ["api", "upgrade"]:
            return self.reply(200, {"status": "success", "data": {"cost": 49}})
        if len(p) == 3 and p[:2] == ["api", "cart-items"] and p[2].isdigit():
            item = srv.items.get(int(p[2]))
            return self.reply(200, {"status": "success", "data": item}) if item else \
                self.reply(404, {"error": "not found"})
        if len(p) == 3 and p[:2] == ["api", "profiles"] and int(p[2]) in srv.profiles:
            return self.reply(200, {"status": "success", "data": srv.profiles[int(p[2])]})
        return self.reply(404, {"error": "no route"})

    def do_POST(self):
        self.server.received.append(("POST", self.path))
        p, srv, data, modes = self.parts(), self.server, self.body(), self.server.modes
        uid = self.user()
        if uid is None:
            return self.reply(401, {"error": "unauthenticated"})
        if p == ["api", "upgrade"]:
            method = data.get("paymentMethod")
            if method == "card":
                return self.reply(402, {"error": "card declined"})   # the legitimate payment fails
            if "validate_payment" in modes and method not in ("card", "wallet"):
                return self.reply(400, {"error": "unknown payment method"})
            if method == "wallet":
                return self.reply(402, {"error": "insufficient balance"})
            srv.roles[uid] = "premium"
            return self.reply(200, {"status": "success",
                                    "data": {"confirmation": "upgraded", "token": _token(uid, "premium")}})
        if p == ["api", "cart-items"]:
            q = data.get("quantity")
            if "check_range" in modes and (not isinstance(q, int) or not 0 < q <= 50):
                return self.reply(400, {"error": "quantity out of range"})
            if "clamp" in modes and isinstance(q, int):
                q = max(1, min(q, 50))
            key = (data.get("cartId"), data.get("productId"))
            if any((i["cartId"], i["productId"]) == key for i in srv.items.values()):
                return self.reply(409, {"error": "already in cart"})
            new = srv.next_id
            srv.next_id += 1
            srv.items[new] = {"id": new, "cartId": data.get("cartId"), "productId": data.get("productId"),
                              "quantity": q}
            return self.reply(201, {"status": "success", "data": srv.items[new]})
        return self.reply(404, {"error": "no route"})

    def do_PUT(self):
        self.server.received.append(("PUT", self.path))
        p, srv, data = self.parts(), self.server, self.body()
        if self.user() is None:
            return self.reply(401, {"error": "unauthenticated"})
        if len(p) == 3 and p[:2] == ["api", "profiles"] and int(p[2]) in srv.profiles:
            prof = srv.profiles[int(p[2])]
            if "ignore_role" in srv.modes:
                data = {k: v for k, v in data.items() if k != "role"}
            prof.update(data)
            return self.reply(200, {"status": "success", "data": prof})
        return self.reply(404, {"error": "no route"})

    def do_DELETE(self):
        self.server.received.append(("DELETE", self.path))
        p, srv = self.parts(), self.server
        if len(p) == 3 and p[:2] == ["api", "cart-items"] and int(p[2]) in srv.items:
            del srv.items[int(p[2])]
            return self.reply(200, {"status": "success"})
        return self.reply(404, {"error": "not found"})


class _Fixture(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Store)
        self.token = _token(7, "member")
        srv = self.server
        srv.tokens, srv.roles, srv.items, srv.next_id = {self.token: 7}, {7: "member"}, {}, 100
        srv.profiles = {7: {"id": 7, "name": "Ann", "role": "member"}}
        srv.modes, srv.received = set(), []
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{srv.server_port}"
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                                      "allowed_hosts": ["127.0.0.1"]})

    def tearDown(self):
        safety_gate.reset_default_gate()
        self.server.shutdown()
        self.server.server_close()

    def run_leg(self, method, path, body, status=None):
        ex = HttpExchange(url=self.origin + path, method=method, request_body=json.dumps(body),
                          request_headers={"Authorization": "Bearer " + self.token,
                                           "Content-Type": "application/json"},
                          response_status=status)
        finding = Finding(vulnerability_class="client-side controls", confidence=0.5, summary="x",
                          evidence="capture", suggested_test="tamper", basis="derived")
        leg = ClientTrustValidator(allowed_hosts=["127.0.0.1"])
        self.assertTrue(leg.applies(finding, ex))
        result = asyncio.run(leg.validate(finding, ex))
        text = result.summary + result.evidence
        self.assertNotIn(self.token, text)
        self.assertNotIn("eyJ", text, "a token leaked into the verdict")
        return result

    def writes(self):
        return [(m, p) for m, p in self.server.received if m != "GET"]


class PaymentSourceTests(_Fixture):
    def test_unpaid_payment_method_is_confirmed_by_the_reissued_token(self):
        result = self.run_leg("POST", "/api/upgrade", {"paymentMethod": "card"}, status=402)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("'member' -> 'premium'", result.summary)
        self.assertIn("refused (HTTP 402)", result.summary)
        self.assertIn("no route to undo", result.summary)
        # The control, then one tamper: a standing change stops at the first accepted.
        self.assertEqual([m for m, _ in self.writes()], ["POST", "POST"])

    def test_validated_payment_method_is_not_confirmed(self):
        self.server.modes.add("validate_payment")
        result = self.run_leg("POST", "/api/upgrade", {"paymentMethod": "card"}, status=402)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertFalse(result.confirmed)
        self.assertEqual(self.server.roles[7], "member")

    def test_a_captured_payment_that_went_through_is_never_replayed(self):
        result = self.run_leg("POST", "/api/upgrade", {"paymentMethod": "card"}, status=200)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("would pay again", result.summary)
        self.assertEqual(self.server.received, [])


class QuantityTests(_Fixture):
    _ITEM = {"productId": 2, "cartId": 1, "quantity": 1}

    def test_negative_quantity_is_confirmed_by_read_back_and_every_item_deleted(self):
        result = self.run_leg("POST", "/api/cart-items", self._ITEM, status=201)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertRegex(result.summary, r"read-back stores quantity=-\d+")
        self.assertIn("deleted and its removal verified", result.summary)
        self.assertEqual(self.server.items, {}, "a probe's cart item was left behind")

    def test_range_checked_quantity_is_not_confirmed(self):
        self.server.modes.add("check_range")
        result = self.run_leg("POST", "/api/cart-items", self._ITEM, status=201)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(self.server.items, {})

    def test_clamped_quantity_is_not_confirmed(self):
        self.server.modes.add("clamp")
        result = self.run_leg("POST", "/api/cart-items", self._ITEM, status=201)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(self.server.items, {})


class RoleUpdateTests(_Fixture):
    def test_client_set_role_is_confirmed_and_written_back(self):
        result = self.run_leg("PUT", "/api/profiles/7", {"name": "Ann", "role": "member"}, status=200)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("role='admin'", result.summary)
        self.assertIn("written back", result.summary)
        self.assertEqual(self.server.profiles[7]["role"], "member")

    def test_ignored_role_is_not_confirmed(self):
        self.server.modes.add("ignore_role")
        result = self.run_leg("PUT", "/api/profiles/7", {"name": "Ann", "role": "member"}, status=200)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(self.server.profiles[7]["role"], "member")


class TargetingTests(unittest.TestCase):
    def ex(self, method, body):
        return HttpExchange(url="http://127.0.0.1:1/api/x", method=method, request_body=body)

    def test_server_owned_fields_route_and_free_text_does_not(self):
        for body in ('{"paymentMode": "wallet"}', '{"payment": {"method": "card"}}',
                     '{"productId": 2, "quantity": 1}', '{"plan": "basic"}', '{"currency": "EUR"}',
                     '{"couponCode": "SPRING"}', '{"role": "user"}', '{"isVerified": false}',
                     '{"status": "pending"}', "price=100&item=1"):
            self.assertTrue(has_trust_shape(self.ex("POST", body)), body)
            self.assertTrue(_has_client_trust_shape(self.ex("POST", body)), body)
        for body in ('{"comment": "hi"}', "comment=hi", '{"status": "shipped"}',
                     '{"quantity": 0}', '{"cardNumber": "4111 1111 1111 1111"}'):
            self.assertFalse(has_trust_shape(self.ex("POST", body)), body)
        self.assertFalse(has_trust_shape(self.ex("GET", '{"quantity": 1}')))

    def test_tamper_values_keep_the_captured_type(self):
        (field,) = trust_fields({"quantity": "1"}, "json")
        self.assertTrue(all(isinstance(v, str) for v in field.tampers))
        self.assertTrue(any(int(v) < 0 for v in field.tampers))


if __name__ == "__main__":
    unittest.main()
