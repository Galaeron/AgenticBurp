"""business_flow (R11-7): checkout tamper, payment skip, coupon misuse and 2FA
disable without step-up, each against an owned loopback shop.

Every case runs through the real registry (for_finding + bind_run_context) over
real HTTP, with a RunContext whose gate admits the writes and the run's captured
flow in `experiment_context["captured"]`. The shop is generic: a basket, a
checkout, an order history, a wallet-free membership upgrade, a basket coupon and
a 2FA setting per bearer token. Each positive has a matched negative on the same
shop with the matching rule switched on (server-side prices, payment required,
codes checked, step-up required). The tests also pin: a default config sends
nothing, an unrestorable step is named in the finding, and no DELETE is ever sent.
"""
import json
import logging
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

from harness.coverage_model import CHECKS_BY_ID
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators import business_flow_validator as bf
from harness.validators.registry import ValidatorRegistry

_PRICE = 10
_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"     # the loopback shop's own test seed
_PASSWORD = {"Bearer a": "pw-a", "Bearer b": "pw-b"}
_CODES = {"WELCOME10": ("Bearer a", 10, False), "OLD5": ("Bearer a", 5, True),
          "BOB20": ("Bearer b", 20, False)}


def _user():
    return {"basket": [], "orders": [], "coupon": None, "tier": "free", "mfa": True}


class _Shop(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, doc):
        raw = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def caller(self):
        return self.headers.get("Authorization", "")

    def user(self):
        return self.server.users.setdefault(self.caller(), _user())

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            return {}

    def basket_doc(self, u):
        subtotal = sum(i["price"] * i["quantity"] for i in u["basket"])
        discount = _CODES.get(u["coupon"], (None, 0, False))[1] if u["coupon"] else 0
        if u["coupon"] and u["coupon"] not in _CODES:      # accept_any applied a forged code
            discount = 10
        return {"items": u["basket"], "coupon": u["coupon"], "discount": discount,
                "total": subtotal - discount}

    def do_GET(self):
        self.server.received.append(("GET", self.path, self.caller()))
        if self.caller() not in _PASSWORD:
            return self.reply(401, {"error": "auth"})
        u = self.user()
        if self.path == "/api/orders":
            return self.reply(200, {"status": "success", "data": u["orders"]})
        if self.path == "/api/basket":
            return self.reply(200, {"status": "success", "data": self.basket_doc(u)})
        if self.path == "/api/whoami":
            return self.reply(200, {"data": {"email": self.caller()[-1] + "@shop.test",
                                             "tier": u["tier"]}})
        if self.path == "/api/2fa/status":
            return self.reply(200, {"setup": u["mfa"]})
        return self.reply(404, {"error": "not found"})

    def do_DELETE(self):
        self.server.received.append(("DELETE", self.path, self.caller()))
        return self.reply(405, {"error": "no"})

    def write(self):
        data = self.body()
        self.server.received.append((self.command, self.path, self.caller()))
        if self.caller() not in _PASSWORD:
            return self.reply(401, {"error": "auth"})
        u, modes = self.user(), self.server.modes
        if self.path == "/api/profile":
            u["nickname"] = data.get("nickname")
            return self.reply(200, {"status": "success"})
        if self.path in ("/api/basket/items", "/api/selections"):
            qty = data.get("quantity", 1)
            if qty < 1 and "trust_qty" not in modes:
                return self.reply(400, {"error": "quantity must be positive"})
            price = data.get("price", _PRICE) if "trust_price" in modes else _PRICE
            u["basket"].append({"productId": data.get("productId"), "quantity": qty, "price": price})
            return self.reply(201, {"status": "success"})
        if self.path == "/api/checkout":
            if "racy" in modes:            # check-then-act with a window and no lock
                return self.checkout(u, data, window=0.3)
            with self.server.lock:
                return self.checkout(u, data)
        if self.path == "/api/membership":
            if data.get("paymentId") != 1 and "no_payment_check" not in modes:
                return self.reply(400, {"error": "payment required"})
            u["tier"] = "deluxe"
            return self.reply(200, {"status": "success"})
        if self.path == "/api/basket/coupon":
            code = data.get("couponCode") or ""
            if not code:
                u["coupon"] = None
                return self.reply(200, {"status": "success"})
            if "accept_any" not in modes:
                owner, _value, expired = _CODES.get(code, (None, 0, False))
                if owner is None:
                    return self.reply(400, {"error": "invalid coupon"})
                if expired:
                    return self.reply(400, {"error": "coupon expired"})
                if owner != self.caller():
                    return self.reply(400, {"error": "coupon belongs to another account"})
            u["coupon"] = code
            return self.reply(200, {"status": "success", "data": self.basket_doc(u)})
        if self.path == "/api/2fa/disable":
            if data.get("password") != _PASSWORD[self.caller()] and "no_stepup" not in modes:
                return self.reply(403, {"error": "password required"})
            u["mfa"] = False
            return self.reply(200, {"status": "success"})
        if self.path == "/api/2fa/setup":
            if data.get("password") != _PASSWORD[self.caller()]:
                return self.reply(403, {"error": "password required"})
            if "totp" in modes and str(data.get("initialToken")) not in {
                    bf.totp_code(_TOTP_SECRET, time.time() + d) for d in (-30, 0)}:
                return self.reply(401, {"error": "wrong one-time code"})
            u["mfa"] = True
            return self.reply(200, {"status": "success"})
        return self.reply(404, {"error": "not found"})

    def checkout(self, u, data, window=0.0):
        if data.get("deliveryId") not in (1, 2):
            return self.reply(400, {"error": "unknown delivery"})
        if not u["basket"]:
            return self.reply(400, {"error": "empty basket"})
        doc = self.basket_doc(u)
        code = data.get("couponCode") or ""
        if code:
            owner, value, expired = _CODES.get(code, (None, 10, False))
            if "accept_any" not in self.server.modes:
                if owner is None:
                    return self.reply(400, {"error": "invalid coupon"})
                if expired:
                    return self.reply(400, {"error": "coupon expired"})
                if owner != self.caller():
                    return self.reply(400, {"error": "coupon belongs to another account"})
            doc["total"] -= value
        if window:
            time.sleep(window)
        self.server.next_id += 1
        u["orders"].append({"id": self.server.next_id, "total": doc["total"]})
        u["basket"], u["coupon"] = [], None
        return self.reply(200, {"status": "success", "orderId": self.server.next_id})

    do_POST = do_PUT = do_PATCH = write


def _cap(origin, method, path, *, body=None, status=200, answer=None, who="Bearer a"):
    return {"url": origin + path, "method": method,
            "request_headers": {"Authorization": who, "Content-Type": "application/json"},
            "request_body": json.dumps(body) if body is not None else "",
            "response_status": status, "response_body": json.dumps(answer) if answer is not None else ""}


class _Fixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Shop)
        self.server.users, self.server.modes, self.server.received = {}, set(), []
        self.server.next_id = 100
        self.server.lock = threading.Lock()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.runs = []

    async def asyncTearDown(self):
        for run in self.runs:
            await run.aclose()
        self.server.shutdown()
        self.server.server_close()
        self.assertNotIn("DELETE", [m for m, _p, _c in self.server.received],
                         "business_flow sent a DELETE")

    def user(self, who="Bearer a"):
        return self.server.users.setdefault(who, _user())

    def build(self, *, ceiling=8, writes=True, active=True, captured=(), bf_cfg=None, burst=1,
              login=None):
        cfg = {"validators": {"active_enabled": active, "allow_mutating_replay": writes,
                              "business_flow": {"enabled": True, **(bf_cfg or {})}},
               "server": {"allowed_hosts": ["127.0.0.1"]}}
        gate = {"active_enabled": active, "allow_mutating_replay": writes, "max_burst_size": burst}
        if ceiling is not None:
            gate["mutating_ceiling_by_check"] = {"business_flow": ceiling}
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=120, config=cfg,
                                gate_config=gate)
        self.runs.append(run)
        run.sessions.register("a", "alice", {"Authorization": "Bearer a"}, allowed_origins=[self.origin])
        run.sessions.register("b", "bob", {"Authorization": "Bearer b"}, allowed_origins=[self.origin])
        if login is not None:
            run.sessions.set_login("a", login, self.origin)
        run.experiment_context = {"captured": list(captured)}
        return ValidatorRegistry(cfg), run

    def finding(self, cls, method, path, body):
        finding = Finding(vulnerability_class=cls, confidence=0.6, summary="flow check",
                          evidence="capture", suggested_test="replay the flow", basis="derived")
        ex = HttpExchange(url=self.origin + path, method=method, request_body=json.dumps(body),
                          request_headers={"Authorization": "Bearer a",
                                           "Content-Type": "application/json"})
        return finding, ex

    async def dispatch(self, cls, method, path, body, *, captured, **kw):
        reg, run = self.build(captured=captured, **kw)
        finding, ex = self.finding(cls, method, path, body)
        legs = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
                if v.name == "business_flow"]
        self.assertTrue(legs, f"registry did not route {cls} to business_flow")
        async with run:
            result = await legs[0].validate(finding, ex)
        return result, run

    def writes(self):
        return [(m, p) for m, p, _c in self.server.received if m != "GET"]


class CheckoutTamperTests(_Fixture):
    def flow(self):
        o = self.origin
        return [
            _cap(o, "GET", "/api/orders", answer={"data": [{"id": 1, "total": 20}]}),
            _cap(o, "POST", "/api/basket/items", body={"productId": 7, "quantity": 2, "price": 10},
                 status=201),
            _cap(o, "POST", "/api/checkout", body={"paymentId": 1, "deliveryId": 1}),
        ]

    async def test_client_price_settles_for_less(self):
        self.server.modes.add("trust_price")
        result, run = await self.dispatch("payment_tamper", "POST", "/api/checkout",
                                          {"paymentId": 1, "deliveryId": 1}, captured=self.flow())
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertEqual(result.mechanism_classes, ("payment_tamper",))
        self.assertIn("price", result.summary)
        totals = [o["total"] for o in self.user()["orders"]]
        self.assertIn(20, totals)          # the untampered control
        self.assertIn(2, totals)           # the tampered flow: 2 x 1
        self.assertIn("LEFT IN PLACE", result.summary)
        self.assertTrue(run.change_log.failed_restores(), "the placed orders were not named")

    async def test_server_price_holds(self):
        result, _run = await self.dispatch("payment_tamper", "POST", "/api/checkout",
                                           {"paymentId": 1, "deliveryId": 1}, captured=self.flow())
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual({o["total"] for o in self.user()["orders"]}, {20})

    async def test_no_read_back_sends_nothing(self):
        flow = [c for c in self.flow() if c["method"] != "GET"]
        result, _run = await self.dispatch("payment_tamper", "POST", "/api/checkout",
                                           {"paymentId": 1, "deliveryId": 1}, captured=flow)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertEqual(self.writes(), [])

    async def test_capability_needs_explicit_ceiling(self):
        finding, ex = self.finding("payment_tamper", "POST", "/api/checkout",
                                   {"paymentId": 1, "deliveryId": 1})
        check = CHECKS_BY_ID["WSTG-BUSL-10"]
        reg, run = self.build()
        self.assertEqual(reg.capability_for_check(check, ex, run_context=run)["status"], "ready")
        reg, run = self.build(ceiling=None)
        got = reg.capability_for_check(check, ex, run_context=run)
        self.assertEqual((got["status"], got["reason_code"]), ("policy_denied", "mutating_ceiling_missing"))
        reg, run = self.build(writes=False)
        self.assertEqual(reg.capability_for_check(check, ex, run_context=run)["status"], "policy_denied")


class PaymentSkipTests(_Fixture):
    def flow(self):
        o = self.origin
        return [_cap(o, "GET", "/api/whoami", answer={"data": {"email": "a@shop.test", "tier": "free"}}),
                _cap(o, "POST", "/api/membership", body={"paymentId": 1})]

    async def test_unpaid_upgrade_confirms(self):
        self.server.modes.add("no_payment_check")
        result, _run = await self.dispatch("payment_tamper", "POST", "/api/membership",
                                           {"paymentId": 1}, captured=self.flow())
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("Payment skip", result.summary)
        self.assertIn("LEFT IN PLACE", result.summary)
        self.assertEqual(self.user()["tier"], "deluxe")

    async def test_payment_required_holds(self):
        result, _run = await self.dispatch("payment_tamper", "POST", "/api/membership",
                                           {"paymentId": 1}, captured=self.flow())
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(self.user()["tier"], "free")


class CouponMisuseTests(_Fixture):
    def flow(self):
        o = self.origin
        return [
            _cap(o, "GET", "/api/basket", answer={"data": {"items": [], "coupon": None,
                                                           "discount": 0, "total": 10}}),
            _cap(o, "PUT", "/api/basket/coupon", body={"couponCode": "OLD5"}, status=400,
                 answer={"error": "coupon expired"}),
            _cap(o, "PUT", "/api/basket/coupon", body={"couponCode": "BOB20"}, who="Bearer b"),
            _cap(o, "PUT", "/api/basket/coupon", body={"couponCode": "WELCOME10"}),
        ]

    def seed(self):
        self.user()["basket"] = [{"productId": 7, "quantity": 1, "price": 10}]
        self.user("Bearer b")

    async def test_forged_code_discount_confirmed_and_removed(self):
        self.seed()
        self.server.modes.add("accept_any")
        result, run = await self.dispatch("coupon_misuse", "PUT", "/api/basket/coupon",
                                          {"couponCode": "WELCOME10"}, captured=self.flow())
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("a forged code", result.summary)
        self.assertEqual(result.mechanism_classes, ("coupon_misuse",))
        self.assertIsNone(self.user()["coupon"], "the forged code was not removed")
        self.assertNotIn("LEFT IN PLACE", result.summary)
        self.assertFalse(run.change_log.failed_restores())

    async def test_checked_codes_hold(self):
        self.seed()
        result, _run = await self.dispatch("coupon_misuse", "PUT", "/api/basket/coupon",
                                           {"couponCode": "WELCOME10"}, captured=self.flow())
        self.assertEqual(result.status, "not_confirmed", result.summary)
        coupon_writes = [p for m, p in self.writes() if p == "/api/basket/coupon"]
        self.assertEqual(len(coupon_writes), 3, "forged, expired and another identity's code")
        self.assertIsNone(self.user()["coupon"])


class MfaDisableTests(_Fixture):
    def flow(self, *, enable=True):
        o = self.origin
        caps = [_cap(o, "GET", "/api/2fa/status", answer={"setup": True}),
                _cap(o, "POST", "/api/2fa/disable", body={"password": "pw-a"})]
        if enable:
            caps.insert(1, _cap(o, "POST", "/api/2fa/setup",
                                body={"password": "pw-a", "setupToken": "t"}))
        return caps

    async def test_disable_without_password_confirmed_and_reenabled(self):
        self.server.modes.add("no_stepup")
        result, run = await self.dispatch("mfa_disable_stepup", "POST", "/api/2fa/disable",
                                          {"password": "pw-a"}, captured=self.flow())
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertEqual(result.mechanism_classes, ("mfa_disable_stepup",))
        self.assertIn("re-enabled", result.summary)
        self.assertTrue(self.user()["mfa"])
        self.assertFalse(run.change_log.failed_restores())

    async def test_unrestorable_disable_is_named(self):
        self.server.modes.add("no_stepup")
        result, run = await self.dispatch("mfa_disable_stepup", "POST", "/api/2fa/disable",
                                          {"password": "pw-a"}, captured=self.flow(enable=False))
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("2FA LEFT DISABLED", result.summary)
        self.assertIn("alice", result.summary)
        self.assertFalse(self.user()["mfa"])
        self.assertTrue(run.change_log.failed_restores(), "the residue was not in the change log")

    async def test_step_up_required_holds(self):
        result, _run = await self.dispatch("mfa_disable_stepup", "POST", "/api/2fa/disable",
                                           {"password": "pw-a"}, captured=self.flow())
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertTrue(self.user()["mfa"])
        self.assertEqual(len(self.writes()), 2, "dropped and wrong step-up, no re-enable needed")


class DefaultsSendNothingTests(_Fixture):
    async def test_committed_config_sends_nothing(self):
        cfg = yaml.safe_load((Path(__file__).parent / "config.yaml").read_text(encoding="utf-8"))
        v = cfg["validators"]
        self.assertFalse(v.get("active_enabled"))
        self.assertFalse(v.get("allow_mutating_replay"))
        self.assertNotIn("business_flow", v.get("mutating_ceiling_by_check") or {})
        self.assertIs(v["business_flow"].get("settlement_race"), False)     # R11-7c switch
        self.assertFalse(ValidatorRegistry(cfg).validators["business_flow"].settlement_race)
        reg = ValidatorRegistry(cfg)
        self.assertIn("business_flow", reg.validators)
        finding, ex = self.finding("payment_tamper", "POST", "/api/checkout",
                                   {"paymentId": 1, "deliveryId": 1})
        self.assertFalse([l for l in reg.for_finding(finding, ex) if l.name == "business_flow"])
        # Even handed straight to the leg, a default run sends nothing.
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=20,
                                config={"server": {"allowed_hosts": ["127.0.0.1"]}},
                                gate_config={"active_enabled": False, "allow_mutating_replay": False})
        self.runs.append(run)
        run.sessions.register("a", "alice", {"Authorization": "Bearer a"}, allowed_origins=[self.origin])
        leg = reg.validators["business_flow"]
        leg.run_context = run
        async with run:
            result = await leg.validate(finding, ex)
        self.assertEqual(result.status, "skipped")
        self.assertEqual(self.server.received, [])

    async def test_writes_on_but_no_ceiling_sends_nothing(self):
        self.server.modes.add("trust_price")
        result, _run = await self.dispatch("payment_tamper", "POST", "/api/checkout",
                                           {"paymentId": 1, "deliveryId": 1}, ceiling=None,
                                           captured=CheckoutTamperTests.flow(self))
        self.assertEqual(result.status, "skipped")
        self.assertIn("mutating_ceiling_by_check", result.summary)
        self.assertEqual(self.server.received, [])

    async def test_foreign_credentials_send_nothing(self):
        reg, run = self.build(captured=CheckoutTamperTests.flow(self))
        finding, ex = self.finding("payment_tamper", "POST", "/api/checkout",
                                   {"paymentId": 1, "deliveryId": 1})
        ex.request_headers = {"Authorization": "Bearer stranger"}
        leg = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
               if v.name == "business_flow"][0]
        async with run:
            result = await leg.validate(finding, ex)
        self.assertEqual(result.status, "skipped")
        self.assertIn("run registered", result.summary)
        self.assertEqual(self.server.received, [])


class SettlementCouponTests(_Fixture):
    """R11-7c gap 1: a code carried by the settlement body goes through the
    control (code emptied) vs misuse-flow comparison."""
    BODY = {"paymentId": 1, "deliveryId": 1, "couponCode": "WELCOME10"}

    def flow(self):
        o = self.origin
        return [
            _cap(o, "GET", "/api/orders", answer={"data": [{"id": 1, "total": 20}]}),
            _cap(o, "POST", "/api/basket/items", body={"productId": 7, "quantity": 2}, status=201),
            _cap(o, "POST", "/api/checkout", body=self.BODY),
            _cap(o, "POST", "/api/checkout", body={**self.BODY, "couponCode": "OLD5"}, status=400,
                 answer={"error": "coupon expired"}),
        ]

    async def test_forged_code_at_settlement_confirmed(self):
        self.server.modes.add("accept_any")
        result, run = await self.dispatch("coupon_misuse", "POST", "/api/checkout", self.BODY,
                                          captured=self.flow())
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertEqual(result.mechanism_classes, ("coupon_misuse",))
        self.assertIn("coupon", result.summary)
        totals = [o["total"] for o in self.user()["orders"]]
        self.assertEqual(totals, [20, 10], "the control (code emptied) then the forged code")
        self.assertIn("LEFT IN PLACE", result.summary)
        self.assertTrue(run.change_log.failed_restores())

    async def test_checked_codes_at_settlement_hold_and_basket_named(self):
        result, run = await self.dispatch("coupon_misuse", "POST", "/api/checkout", self.BODY,
                                          captured=self.flow())
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual([o["total"] for o in self.user()["orders"]], [20], "only the control settled")
        checkouts = [p for m, p in self.writes() if p == "/api/checkout"]
        fills = [p for m, p in self.writes() if p == "/api/basket/items"]
        self.assertEqual(len(checkouts), 3, "control, forged and expired code")
        # The expired-code flow settles the basket the refused forged flow left, so
        # the basket is filled only twice and never fuller than the control's.
        self.assertEqual(len(fills), 2)
        self.assertEqual(len(self.user()["basket"]), 1)
        self.assertIn("stay in the basket", result.summary)
        self.assertTrue(run.change_log.failed_restores())


class SettlementRaceTests(_Fixture):
    """R11-7c gap 2: concurrent settlements of one filled basket, judged on the
    order-history read-back against a sequential control."""

    def flow(self):
        return CheckoutTamperTests.flow(self)

    async def race(self, *, on=True, burst=2, ceiling=16):
        return await self.dispatch("payment_tamper", "POST", "/api/checkout",
                                   {"paymentId": 1, "deliveryId": 1}, captured=self.flow(),
                                   ceiling=ceiling, burst=burst,
                                   bf_cfg={"settlement_race": on, "race_copies": 2})

    async def test_racy_settlement_confirmed(self):
        self.server.modes.add("racy")
        result, run = await self.race()
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("Settlement race confirmed", result.summary)
        self.assertIn("new entries from one filled basket", result.summary)
        self.assertIn("LEFT IN PLACE", result.summary)
        self.assertTrue(run.change_log.failed_restores())
        self.assertNotIn("DELETE", [m for m, _p in self.writes()])

    async def test_serialized_settlement_holds(self):
        result, _run = await self.race()
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertIn("Settlement race: held", result.summary)
        # the race's sequential control and one of the concurrent copies
        self.assertEqual(sum(1 for o in self.user()["orders"]), 2 + 1 + 1)

    async def test_switch_off_sends_no_race(self):
        self.server.modes.add("racy")
        result, _run = await self.race(on=False)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertNotIn("Settlement race", result.summary)
        self.assertEqual(len(self.user()["orders"]), 2, "the control and the price tamper only")

    async def test_burst_ceiling_one_sends_no_race(self):
        self.server.modes.add("racy")
        result, _run = await self.race(burst=1)
        self.assertIn("max_burst_size", result.summary)
        self.assertEqual(len(self.user()["orders"]), 2)

    async def test_ceiling_too_small_sends_no_race(self):
        self.server.modes.add("racy")
        result, _run = await self.race(ceiling=8)
        self.assertIn("does not pay for the sequential control", result.summary)
        self.assertEqual(len(self.user()["orders"]), 2)


class FlowDiscoveryTests(_Fixture):
    """R11-7c gap 4: a basket filled through a path that is not cart-shaped is found
    by its effect on the captured read-back; an unrelated write is not replayed."""

    def flow(self, *, traced=True):
        o = self.origin
        item = {"productId": 7, "quantity": 2, "price": 10}
        return [
            _cap(o, "GET", "/api/orders", answer={"data": [{"id": 1, "total": 20}]}),
            _cap(o, "GET", "/api/basket", answer={"data": {"items": [], "total": 0}}),
            _cap(o, "POST", "/api/profile", body={"nickname": "al"}),
            _cap(o, "POST", "/api/selections", body=item, status=201),
            _cap(o, "GET", "/api/basket",
                 answer={"data": {"items": [item] if traced else [], "total": 20 if traced else 0}}),
            _cap(o, "POST", "/api/checkout", body={"paymentId": 1, "deliveryId": 1}),
        ]

    async def test_non_cart_path_found_by_read_back(self):
        self.server.modes.add("trust_price")
        result, _run = await self.dispatch("payment_tamper", "POST", "/api/checkout",
                                           {"paymentId": 1, "deliveryId": 1}, captured=self.flow())
        self.assertEqual(result.status, "confirmed", result.summary)
        paths = [p for _m, p in self.writes()]
        self.assertIn("/api/selections", paths)
        self.assertNotIn("/api/profile", paths, "an unrelated write was replayed")

    async def test_untraced_write_is_not_a_cart_step(self):
        self.server.modes.add("trust_price")
        result, _run = await self.dispatch("payment_tamper", "POST", "/api/checkout",
                                           {"paymentId": 1, "deliveryId": 1},
                                           captured=self.flow(traced=False))
        self.assertNotEqual(result.status, "confirmed", result.summary)
        paths = [p for _m, p in self.writes()]
        self.assertNotIn("/api/selections", paths)
        self.assertNotIn("/api/profile", paths)


class VariantTests(unittest.TestCase):
    def tampers(self):
        T = bf._Tamper
        return [T(-1, ("deliveryId",), "delivery", 1, 9), T(0, ("price",), "amount", 10, 1),
                T(0, ("fee",), "amount", 3, 1), T(0, ("quantity",), "quantity", 2, -1)]

    def test_families_first_and_bounded(self):
        got = bf.BusinessFlowValidator(max_variants=3)._pick_variants(self.tampers())
        self.assertEqual([t.family for t in got], ["amount", "quantity", "delivery"])
        got = bf.BusinessFlowValidator()._pick_variants(self.tampers())
        self.assertEqual([t.family for t in got], ["amount", "quantity"])
        self.assertEqual(bf.BusinessFlowValidator(max_variants=50).max_variants, 4)
        self.assertEqual(len(bf.BusinessFlowValidator(max_variants=50)._pick_variants(self.tampers())), 4)


class TotpRestoreTests(_Fixture):
    """R11-7c gap 3: re-enable 2FA with a fresh code from the identity's declared
    TOTP secret; without one (or with a wrong one) the residue is named."""

    def flow(self):
        o = self.origin
        return [_cap(o, "GET", "/api/2fa/status", answer={"setup": True}),
                _cap(o, "POST", "/api/2fa/setup",
                     body={"password": "pw-a", "setupToken": "t", "initialToken": "000000"}),
                _cap(o, "POST", "/api/2fa/disable", body={"password": "pw-a"})]

    async def run_disable(self, login):
        self.server.modes.update({"no_stepup", "totp"})
        records = []

        class _Keep(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())
        handler = _Keep(level=logging.DEBUG)
        root = logging.getLogger()
        old = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            result, run = await self.dispatch("mfa_disable_stepup", "POST", "/api/2fa/disable",
                                              {"password": "pw-a"}, captured=self.flow(), login=login)
        finally:
            root.removeHandler(handler)
            root.setLevel(old)
        text = result.summary + (result.evidence or "") + (result.limitation or "") + "\n".join(records)
        self.assertNotIn(_TOTP_SECRET, text, "the TOTP secret was printed")
        for d in (-30, 0, 30):
            self.assertNotIn(bf.totp_code(_TOTP_SECRET, time.time() + d), result.summary + (result.evidence or ""))
        return result, run

    async def test_declared_secret_restores(self):
        result, run = await self.run_disable({"totp_secret": _TOTP_SECRET})
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("fresh one-time code", result.summary)
        self.assertNotIn("LEFT DISABLED", result.summary)
        self.assertTrue(self.user()["mfa"])
        self.assertFalse(run.change_log.failed_restores())

    async def test_no_secret_names_residue(self):
        result, run = await self.run_disable(None)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("2FA LEFT DISABLED", result.summary)
        self.assertIn("totp_secret", result.summary)
        self.assertFalse(self.user()["mfa"])
        self.assertTrue(run.change_log.failed_restores())

    async def test_wrong_secret_names_residue(self):
        result, _run = await self.run_disable({"totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})
        self.assertIn("2FA LEFT DISABLED", result.summary)
        self.assertFalse(self.user()["mfa"])

    def test_rfc6238_vector(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"      # RFC 6238 SHA1 seed "1234567890" x2
        self.assertEqual(bf.totp_code(secret, 59, digits=8), "94287082")
        self.assertEqual(bf.totp_code(secret, 1111111109, digits=8), "07081804")


class ShapeTests(unittest.TestCase):
    def test_shapes(self):
        self.assertEqual(bf.flow_kind("POST", "http://x/api/checkout", '{"deliveryId": 1}'),
                         bf.PAYMENT_TAMPER)
        self.assertEqual(bf.flow_kind("PUT", "http://x/rest/basket/1/coupon/ABC", ""), bf.COUPON_MISUSE)
        self.assertEqual(bf.flow_kind("POST", "http://x/rest/2fa/disable", '{"password": "x"}'),
                         bf.MFA_DISABLE)
        self.assertIsNone(bf.flow_kind("POST", "http://x/rest/2fa/disable", '{}'))
        self.assertIsNone(bf.flow_kind("GET", "http://x/api/checkout", ""))
        self.assertIsNone(bf.flow_kind("POST", "http://x/rest/user/login", '{"coupon": "x"}'))
        self.assertIsNone(bf.flow_kind("POST", "http://x/api/basket/items", '{"quantity": 1}'))

    def test_class_gate(self):
        leg = bf.BusinessFlowValidator(allow_writes=True)
        ex = HttpExchange(url="http://x/api/checkout", method="POST", request_body='{"deliveryId": 1}')
        mk = lambda c: Finding(vulnerability_class=c, confidence=0.5, summary="s", evidence="e",
                               suggested_test="t", basis="derived")
        self.assertTrue(leg.applies(mk("payment_tamper"), ex))
        self.assertFalse(leg.applies(mk("coupon_misuse"), ex))       # wrong shape for the class
        self.assertFalse(leg.applies(mk("sqli"), ex))
        self.assertTrue(leg.claims_class(mk("payment_tamper"), ex))
        self.assertFalse(bf.BusinessFlowValidator(allow_writes=False).applies(mk("payment_tamper"), ex))


if __name__ == "__main__":
    unittest.main()
