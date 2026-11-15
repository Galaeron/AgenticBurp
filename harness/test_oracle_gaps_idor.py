"""Oracle gap (2026-11-14): idor_read with two run identities.

The run held two identities and the reader's session read the other identity's
protected object, yet the leg stayed a single-principal lead: the ownership
ledger had no fact for that object (nothing observed the second identity
receive it) and the leg never consulted the second identity at all. With the
self-observed ownership opt-in (authz.self_observed_ownership) the leg now
shows the owner itself: an owner field (userId, ownerId, email ...) of the
foreign object holds identity B's account key from B's own credentials, the
reader's own object carries the reader's different key at that same field, and
B's own session reads the same object. Each test drives
Orchestrator._validate_findings inside an entered RunContext against an owned
loopback app.

  (i)   confirm: B's object read by A, owner field names B, B reads it;
  (ii)  negative control: the opt-in off -> the labelled lead, naming the
        config that would let it confirm;
  (iii) negative control: the owner field names an account no identity holds;
  (iv)  negative control: B's own session is denied the object;
  (v)   negative control: the "second identity" is a second session of the
        reader's own account;
  (vi)  negative control: the reader's own object does not carry its own key at
        the field, so the field is not shown to name an owner.
"""
import asyncio
import base64
import json
import secrets
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from harness.models import AgentReport, HttpExchange
from harness.test_confirmation_soundness_rve import _CallerBase, _finding
from harness.validators.idor_read_validator import IdorReadValidator


def _jwt(uid, email):
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    payload = {"status": "success", "data": {"id": uid, "email": email}, "iat": 1731600000}
    return f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part(payload)}.{secrets.token_urlsafe(16)}"


class _BasketApp:
    """GET /api/carts/{n} for any live bearer token (the BOLA under test), 401
    without one. `owners`: cart id -> owning account id. `deny`: (token, cart)
    pairs refused with 403."""

    def __init__(self, owners, tokens, *, deny=(), owner_key="UserId"):
        app = self
        self.received: list[tuple[str, str]] = []
        lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, doc):
                data = json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                auth = self.headers.get("Authorization") or ""
                token = auth[7:] if auth.lower().startswith("bearer ") else ""
                path = urlsplit(self.path).path
                with lock:
                    app.received.append((path, token))
                if not path.startswith("/api/carts/"):
                    return self._send(404, {"error": "not found"})
                if token not in tokens:
                    return self._send(401, {"error": "No Authorization header was found"})
                cart = path.rsplit("/", 1)[1]
                if not cart.isdigit() or int(cart) not in owners:
                    return self._send(404, {"error": "not found"})
                if (token, int(cart)) in deny:
                    return self._send(403, {"error": "forbidden"})
                n = int(cart)
                return self._send(200, {"status": "success", "data": {
                    "id": n, "coupon": None, owner_key: owners[n],
                    "Products": [{"name": f"item-{n}-{secrets.token_hex(3)}", "quantity": n}]}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TwoPrincipalIdorTests(_CallerBase, unittest.TestCase):   # base named for the static checks
    def run_leg(self, *, owners, b_account=12, opt_in=True, deny_b=False, owner_key="UserId"):
        from harness.run_context import RunContext
        alice, bob = _jwt(11, "alice@example.test"), _jwt(b_account, "bob@example.test")
        app = _BasketApp(owners, {alice, bob}, owner_key=owner_key,
                         deny={(bob, 2)} if deny_b else ())
        self.addCleanup(app.close)
        orch = self._orch(hosts=("127.0.0.1",))
        orch.validator_registry.validators = {
            "idor_read": IdorReadValidator(allowed_hosts=["127.0.0.1"])}
        exchange = HttpExchange(url=app.origin + "/api/carts/1", method="GET",
                                request_headers={"Authorization": "Bearer " + alice},
                                response_status=200,
                                response_headers={"Content-Type": "application/json"},
                                response_body="{}")
        config = {"authz": {"self_observed_ownership": True}} if opt_in else {}

        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=100, config=config,
                                    gate_config={"active_enabled": True})
            run.sessions.register("a", "alice", {"Authorization": "Bearer " + alice},
                                  allowed_origins=[app.origin])
            run.sessions.register("b", "bob", {"Authorization": "Bearer " + bob},
                                  allowed_origins=[app.origin])
            async with run:
                reports, _proofs = await orch._validate_findings(
                    exchange, [AgentReport(agent="access_control", model="fake",
                                           findings=[_finding("idor")])], run_context=run)
            await run.aclose()
            return reports

        reports = [r for r in asyncio.run(go()) if r.validator == "idor_read"]
        self.assertTrue(reports, "idor_read was not dispatched")
        return reports[0], app, (alice, bob)

    def test_second_identity_owning_the_object_confirms(self):
        report, app, (_alice, bob) = self.run_leg(owners={1: 11, 2: 12})
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("(two principals)", report.summary)
        self.assertIn("Self-observed ownership, two principals", report.evidence)
        self.assertIn("/data/UserId", report.evidence)
        self.assertIn("run identity bob", report.evidence)
        self.assertIn(("/api/carts/2", bob), app.received)
        self.assertNotIn("item-2-", report.evidence + report.summary)

    def test_opt_in_off_stays_a_lead_naming_what_would_confirm(self):
        report, app, (_alice, bob) = self.run_leg(owners={1: 11, 2: 12}, opt_in=False)
        self.assertEqual(report.status, "inconclusive", report.summary)
        self.assertIn("a second identity is needed to confirm", report.summary)
        self.assertIn("Missing evidence: a second identity", report.evidence)
        self.assertIn("authz.self_observed_ownership is off", report.evidence)
        self.assertIn("authz.owners", report.evidence)
        self.assertFalse([p for p, t in app.received if t == bob])

    def test_owner_field_naming_no_identity_is_a_lead(self):
        report, _app, _ = self.run_leg(owners={1: 11, 2: 99})
        self.assertEqual(report.status, "inconclusive", report.summary)
        self.assertIn("names an account no run identity holds", report.evidence)
        self.assertNotIn("99", report.evidence.split("Missing evidence")[1])

    def test_second_identity_denied_the_object_is_a_lead(self):
        report, _app, _ = self.run_leg(owners={1: 11, 2: 12}, deny_b=True)
        self.assertEqual(report.status, "inconclusive", report.summary)
        self.assertIn("did not read the same object (HTTP 403)", report.evidence)

    def test_second_session_of_the_same_account_never_confirms(self):
        report, _app, _ = self.run_leg(owners={1: 11, 2: 11}, b_account=11)
        self.assertNotEqual(report.status, "confirmed", report.summary)
        self.assertIn("names this principal's own account", report.evidence)

    def test_field_not_shown_to_name_the_owner_is_a_lead(self):
        # "customerId" holds B's id on B's cart but A's own cart carries 0 there.
        report, _app, _ = self.run_leg(owners={1: 0, 2: 12}, owner_key="customerId")
        self.assertEqual(report.status, "inconclusive", report.summary)
        self.assertIn("does not carry its own account at the owner field", report.evidence)


if __name__ == "__main__":
    import unittest
    unittest.main()
