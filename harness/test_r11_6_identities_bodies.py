"""R11-6: captured principals mapped to run identities, and mass-assignment bodies
built from an object's read.

(a) A capture whose credentials hold a token this run issued (with server cookies
    riding along, or a token from before a sign-in refresh) reaches the
    api_security exposure leg, replayed with the session's current credentials.
    A foreign token stays unregistered and nothing is sent.
(b) A PUT/PATCH of one object with no captured body (or only the crawler's guess)
    gets a mass-assignment leg whose body is built from the object's GET:
    settable fields only, snapshot restored and verified. A real captured body
    keeps the captured-body path and the guess is never sent.

Every case goes through the production caller (Orchestrator._validate_findings,
and shape_precondition_legs for the graph routing) against a loopback service.
"""
import asyncio
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from harness import cache, global_throttle, run_tokens, safety_gate, store
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.orchestrator_helpers import shape_precondition_legs
from harness.role_crawl import _GENERIC_JSON_BODY
from harness.run_context import RunContext
from harness.test_default_history_caller import _config, _RecordingModel
from harness.test_oracle_gaps_api_security import _LISTING, _MD5, _token
from harness.validators import read_body
from harness.validators.api_security_validator import ApiSecurityValidator
from harness.validators.sequence_validator import SequenceValidator

_OBJECT = {"id": 7, "email": "carol@example.test", "name": "Carol", "role": "customer",
           "isAdmin": False, "createdAt": "2026-11-01T10:00:00Z", "updated_at": "2026-11-02",
           "passwordHash": _MD5, "orderCount": 3, "avatarUrl": "/img/7.png",
           "address": {"city": "Lyon"}, "tags": ["a"]}
_READ_ONLY = ("id", "createdAt", "updated_at", "passwordHash", "orderCount", "avatarUrl",
              "address", "tags")


class _Service(BaseHTTPRequestHandler):
    """GET/PUT/POST of one stored object; `vulnerable` applies every sent field."""

    def log_message(self, *args):
        pass

    def _send(self, status, doc):
        body = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        srv = self.server
        srv.received.append(("GET", self.path, dict(self.headers), None))
        if not self.headers.get("Authorization"):
            return self._send(401, {"error": "login required"})
        if self.path.startswith("/api/accounts"):
            return self._send(200, srv.listing)
        return self._send(200, {"status": "success", "data": dict(srv.obj)})

    def _write(self):
        srv = self.server
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        srv.received.append((self.command, self.path, dict(self.headers), raw))
        srv.writes += 1
        if srv.fail_write_at and srv.writes == srv.fail_write_at:
            return self._send(500, {"error": "write failed"})
        try:
            body = json.loads(raw or "{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        for key, value in body.items():
            if key in ("id", "createdAt"):
                continue
            if key in ("role", "isAdmin") and not srv.vulnerable:
                continue
            if key in srv.obj or srv.vulnerable:
                srv.obj[key] = value
        return self._send(200, {"status": "success"})

    do_PUT = do_PATCH = do_POST = _write


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="r11_6_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        st = global_throttle.throttle.stats()
        prev = (st["rate_per_second"] if st["enabled"] else 0.0, st["burst"] if st["enabled"] else None)
        self.addCleanup(lambda: global_throttle.configure(*prev))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Service)
        srv = self.server
        srv.received, srv.listing, srv.obj = [], _LISTING, dict(_OBJECT)
        srv.vulnerable, srv.writes, srv.fail_write_at = True, 0, 0
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{srv.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def dispatch(self, validator, ex, vclass, *, sessions=(), before=None, mutating=True):
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["127.0.0.1"]
        writes = {"allow_mutating_replay": True, "mutating_ceiling_by_check": {"sequence": 2}}
        cfg["validators"].update(active_enabled=True, **(writes if mutating else {}))
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        global_throttle.configure(0)
        orch.validator_registry.validators = {validator.name: validator}

        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=50, config=cfg,
                                    gate_config={"active_enabled": True, **(writes if mutating else {})})
            for sid, principal, headers in sessions:
                run.sessions.register(sid, principal, headers, allowed_origins=[self.origin])
            if before is not None:
                before(run)
            finding = Finding(vulnerability_class=vclass, confidence=0.7, summary=vclass,
                              evidence="capture", suggested_test="replay", basis="derived")
            async with run:
                reports, _ = await orch._validate_findings(
                    ex, [AgentReport(agent="api_security", model="fake", findings=[finding])],
                    run_context=run)
            await run.aclose()
            return reports

        reports = asyncio.run(go())
        mine = [r for r in reports if r.validator == validator.name]
        self.assertEqual(len(mine), 1, [(r.validator, r.status, r.summary) for r in reports])
        return mine[0]

    def sent_bodies(self):
        return [json.loads(raw) for method, _, _, raw in self.server.received
                if method in ("PUT", "PATCH", "POST") and raw]


# -- (a) run-issued tokens -------------------------------------------------------------

def _bearer(email, uid, **kw):
    return "Bearer " + _token(email, uid, **kw)


class RunIssuedTokenTests(_Base):
    def exposure(self, capture_headers, *, before=None, a=None):
        a = a or _bearer("alice@example.test", 1, password=_MD5)
        ex = HttpExchange(url=self.origin + "/api/accounts", method="GET",
                          request_headers=capture_headers)
        sessions = [("a", "alice", {"Authorization": a}),
                    ("b", "bob", {"Authorization": _bearer("bob@example.test", 2)})]
        return self.dispatch(ApiSecurityValidator(), ex, "excessive data exposure",
                             sessions=sessions, before=before)

    def test_run_token_with_server_cookies_reaches_the_exposure_leg(self):
        a = _bearer("alice@example.test", 1, password=_MD5)
        report = self.exposure({"Authorization": a, "Cookie": "language=en; banner=1"}, a=a)
        self.assertEqual(report.status, "confirmed", report.summary)
        sent = [h for m, _, h, _ in self.server.received]
        self.assertEqual([h.get("Authorization") for h in sent], [a, a, None])
        self.assertFalse(any(h.get("Cookie") for h in sent), "capture cookies are not replayed")
        self.assertNotIn(a.split()[1], report.evidence + report.summary)

    def test_token_from_before_a_refresh_is_replayed_with_the_current_one(self):
        old = _bearer("alice@example.test", 1)
        new = _bearer("alice@example.test", 1, password=_MD5)

        def refresh(run):
            run.sessions.replace_headers("a", {"Authorization": new})
        report = self.exposure({"Authorization": old}, a=old, before=refresh)
        self.assertEqual(report.status, "confirmed", report.summary)
        auth = [h.get("Authorization") for m, _, h, _ in self.server.received]
        self.assertEqual(auth, [new, new, None])
        self.assertNotIn(old, auth)

    def test_foreign_token_stays_unregistered(self):
        foreign = _bearer("mallory@example.test", 9, password=_MD5)
        report = self.exposure({"Authorization": foreign, "Cookie": "language=en"})
        self.assertEqual(report.status, "skipped", report.summary)
        self.assertIn("not a registered session", report.summary)
        self.assertEqual(self.server.received, [], "nothing is sent for a foreign principal")

    def test_anonymous_capture_is_read_as_the_anonymous_caller(self):
        # R11-9 (owner decision 2026-11-19): no longer skipped. This service
        # refuses anonymous reads, so nothing is exposed.
        report = self.exposure({})
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertEqual([h.get("Authorization") for _, _, h, _ in self.server.received], [None])

    def test_matching_rules(self):
        ids = [{"name": "a", "headers": {"Authorization": "Bearer t1", "Cookie": "sid=s1"}},
               {"name": "b", "headers": {"Authorization": "Bearer t2"}}]
        match = run_tokens.issued_identity
        self.assertEqual(match(ids, {"Authorization": "Bearer t1", "Cookie": "x=1"})["name"], "a")
        self.assertEqual(match(ids, {"Cookie": "sid=s1; lang=en"})["name"], "a")
        self.assertIsNone(match(ids, {"Authorization": "Bearer t3"}))
        self.assertIsNone(match(ids, {"Authorization": "Bearer t1", "Cookie": "sid=other"}))
        self.assertIsNone(match(ids, {"Authorization": "Bearer t1", "X-Api-Key": "foreign"}))
        self.assertIsNone(match(ids, {"Cookie": "lang=en"}), "server cookies alone prove nothing")
        shared = ids + [{"name": "c", "headers": {"Authorization": "Bearer t2"}}]
        self.assertIsNone(match(shared, {"Authorization": "Bearer t2"}), "a shared token is no principal")


# -- (b) a body built from the read ----------------------------------------------------

class ReadBuiltBodyTests(_Base):
    AUTH = {"Authorization": "Bearer carol"}

    def put(self, body="", note=""):
        return HttpExchange(url=self.origin + "/api/users/7", method="PUT",
                            request_headers=dict(self.AUTH), request_body=body,
                            analyst_note=note)

    def assert_read_only_never_sent(self):
        bodies = self.sent_bodies()
        self.assertTrue(bodies)
        for body in bodies:
            for key in _READ_ONLY:
                self.assertNotIn(key, body)

    def test_shape_routing_gives_a_bodyless_put_a_mass_assignment_leg(self):
        node = {"method": "PUT", "path": "/api/users/7"}
        for ex in (self.put(), self.put(_GENERIC_JSON_BODY)):
            legs = [v for v, _ in shape_precondition_legs(node, ex, [], self.origin)]
            self.assertEqual(legs.count("mass_assignment"), 1, legs)
        collection = HttpExchange(url=self.origin + "/api/users", method="PUT",
                                  request_headers=dict(self.AUTH))
        self.assertNotIn("mass_assignment", [v for v, _ in shape_precondition_legs(
            {"method": "PUT", "path": "/api/users"}, collection, [], self.origin)])

    def test_sequence_leg_confirms_with_a_body_from_the_read_and_restores(self):
        node = {"method": "PUT", "path": "/api/users/7"}
        ex = dict(shape_precondition_legs(node, self.put(), [], self.origin))["mass_assignment"]
        report = self.dispatch(SequenceValidator(allowed_hosts=["127.0.0.1"]), ex, "mass_assignment")
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("body_source=read of GET", report.evidence)
        self.assertIn("restore_succeeded=true", report.evidence)
        attack, restore = self.sent_bodies()
        self.assertEqual(attack["isAdmin"], True)
        self.assertEqual(attack["role"], "admin")
        self.assertEqual(attack["email"], _OBJECT["email"])
        self.assertEqual(restore, {k: _OBJECT[k] for k in ("email", "name", "role", "isAdmin")})
        self.assertEqual(self.server.obj, _OBJECT, "the object is back to its snapshot")
        self.assert_read_only_never_sent()

    def test_api_security_guessed_body_is_replaced_by_the_read(self):
        report = self.dispatch(ApiSecurityValidator(), self.put(_GENERIC_JSON_BODY), "mass_assignment")
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("body_source=read of GET", report.evidence)
        for body in self.sent_bodies():
            self.assertNotIn("value", body, "the guessed body is never sent")
        self.assert_read_only_never_sent()

    def test_patched_service_is_not_confirmed_and_is_restored(self):
        self.server.vulnerable = False
        report = self.dispatch(ApiSecurityValidator(), self.put(), "mass_assignment")
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertEqual(self.server.obj, _OBJECT)
        self.assert_read_only_never_sent()

    def test_default_ceiling_sends_nothing(self):
        report = self.dispatch(ApiSecurityValidator(), self.put(), "mass_assignment", mutating=False)
        self.assertEqual(report.status, "skipped", report.summary)
        self.assertEqual(self.sent_bodies(), [], "no default widens: nothing is written")

    def test_failed_restore_is_an_error_not_a_pass(self):
        self.server.fail_write_at = 2
        report = self.dispatch(ApiSecurityValidator(), self.put(), "mass_assignment")
        self.assertEqual(report.status, "error", report.summary)
        self.assertIn("RESTORE FAILED", report.summary)

    def test_real_captured_body_never_uses_the_read_or_the_guess(self):
        report = self.dispatch(ApiSecurityValidator(), self.put('{"name": "Carol B"}'),
                               "mass_assignment")
        self.assertNotIn("body_source=read", report.evidence or "")
        bodies = self.sent_bodies()
        self.assertTrue(bodies)
        for body in bodies:
            self.assertEqual(body.get("name"), "Carol B")
            self.assertNotIn("value", body)
            self.assertNotIn("email", body, "no read-built field rides on a captured body")

    def test_guessed_post_body_is_never_sent(self):
        ex = HttpExchange(url=self.origin + "/api/users", method="POST",
                          request_headers=dict(self.AUTH), request_body=_GENERIC_JSON_BODY)
        self.dispatch(ApiSecurityValidator(), ex, "mass_assignment")
        self.assertEqual(self.sent_bodies(), [])

    def test_read_only_fields(self):
        fields, why = read_body.body_from_read({"data": _OBJECT})
        self.assertEqual(sorted(fields), ["email", "isAdmin", "name", "role"], why)
        for key in ("accountType", "footprint", "totalPrice"):
            self.assertFalse(read_body.read_only_field(key, "x"), key)
        self.assertIsNone(read_body.body_from_read({"data": [_OBJECT, _OBJECT]})[0])
        self.assertIsNone(read_body.body_from_read({"email": "a", "card": "****1234"})[0])

    def test_defect_injection_routing_is_load_bearing(self):
        """Without the R11-6 routing a bodyless PUT gets no mass-assignment leg."""
        import harness.validators.sequence_validator as seq_mod
        node = {"method": "PUT", "path": "/api/users/7"}
        with patch.object(seq_mod, "needs_read_body", lambda ex: False):
            legs = [v for v, _ in shape_precondition_legs(node, self.put(), [], self.origin)]
        self.assertNotIn("mass_assignment", legs)

    def test_defect_injection_read_only_filter_is_load_bearing(self):
        """With the read-only filter disabled the read-only fields WOULD be sent:
        the assertion above depends on the new code, not on the fixture."""
        with patch.object(read_body, "read_only_field", lambda k, v: False):
            self.dispatch(ApiSecurityValidator(), self.put(), "mass_assignment")
        with self.assertRaises(AssertionError):
            self.assert_read_only_never_sent()


class DefectInjectionTests(RunIssuedTokenTests):
    """Without the run-token mapping, the extra-cookie capture is skipped again."""

    def test_run_token_with_server_cookies_reaches_the_exposure_leg(self):
        with patch.object(run_tokens, "issued_identity", lambda *a, **k: None):
            a = _bearer("alice@example.test", 1, password=_MD5)
            report = self.exposure({"Authorization": a, "Cookie": "language=en"}, a=a)
        self.assertEqual(report.status, "skipped", report.summary)

    test_token_from_before_a_refresh_is_replayed_with_the_current_one = None
    test_foreign_token_stays_unregistered = None
    test_anonymous_capture_gets_its_own_skip = None
    test_matching_rules = None


if __name__ == "__main__":
    unittest.main()
