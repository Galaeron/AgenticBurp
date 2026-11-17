"""Oracle gaps in api_security: credential material by shape, credential secrets in
the caller's own session token (JWT claims), account objects of accounts no
session is registered for, and a captured create handed to write_integrity.

Shape rules are checked directly; every confirmation goes through the production
caller (Orchestrator._validate_findings) against an owned loopback service, with a
negative control next to it. The create hand-off runs the real write_integrity
engine against the generic store of test_write_integrity, and checks what was
left behind.
"""
import asyncio
import base64
import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from harness import cache, global_throttle, safety_gate, store
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext
from harness.test_default_history_caller import _config, _RecordingModel
from harness.test_write_integrity import _Store, _seed
from harness.validators.api_security_validator import (
    ApiSecurityValidator, _credential_material, _jwt_claims, exposure_fields)

_MD5 = hashlib.md5(b"oracle-gap").hexdigest()
_SHA1 = hashlib.sha1(b"oracle-gap").hexdigest()
_SHA256 = hashlib.sha256(b"oracle-gap").hexdigest()
_SHA512 = hashlib.sha512(b"oracle-gap").hexdigest()
_B64 = base64.b64encode(hashlib.sha256(b"oracle-gap-b64").digest()).decode()
_BCRYPT = "$2b$12$" + "R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
_ARGON2 = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA"
_PBKDF2_DJANGO = "pbkdf2_sha256$600000$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2g="
_PBKDF2_PHC = "$pbkdf2-sha256$29000$N2bsXSuFkPI$Zl7BQ7c2r4m8nT0pYcV1aW3eF5gH6jK8"
_TOTP = "JBSWY3DPEHPK3PXPJBSWY3DP"


def _jwt(claims: dict) -> str:
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part(claims)}.c2lnbmF0dXJl"


def _token(email, uid, password="", totp=""):
    return _jwt({"status": "success", "data": {"id": uid, "email": email, "role": "customer",
                                               "password": password, "totpSecret": totp},
                 "iat": 1700000000})


class CredentialMaterialShapeTests(unittest.TestCase):
    def test_password_hashes_and_digests(self):
        self.assertEqual(_B64 != "" and any(c.isdigit() or c in "+/" for c in _B64), True)
        cases = [("password", _MD5, "password digest"), ("passwordHash", _SHA1, "password digest"),
                 ("pwd", _SHA256, "password digest"), ("user_password", _SHA512, "password digest"),
                 ("password", _B64, "password digest"), ("hash", _BCRYPT, "password hash"),
                 ("credential", _ARGON2, "password hash"),
                 ("passwordDigest", _PBKDF2_DJANGO, "password hash"),
                 ("secretHash", _PBKDF2_PHC, "password hash"),
                 ("totpSecret", _TOTP, "TOTP secret"), ("mfa_seed", _TOTP, "TOTP secret"),
                 ("twoFactorKey", _TOTP, "TOTP secret")]
        for key, value, kind in cases:
            self.assertEqual(_credential_material(key, value), kind, key)

    def test_checksums_ids_and_attributes_are_not_material(self):
        for key, value in [("checksum", _MD5), ("etag", _SHA1), ("sha256", _SHA256),
                           ("fileHash", _SHA256), ("contentMd5", _MD5), ("id", _MD5),
                           ("uuid", _MD5), ("userId", _MD5), ("passwordId", _MD5),
                           ("passwordHint", _BCRYPT), ("passwordResetAt", _SHA1),
                           ("integrity", "sha384-" + _B64), ("fingerprint", _SHA256),
                           ("password", "hunter2"), ("password", "********************************"),
                           ("otpCode", _TOTP), ("secret", _TOTP), ("totpSecret", "123456"),
                           ("password", True), ("password", 12345678)]:
            self.assertEqual(_credential_material(key, value), "", key)

    def test_jwt_claims_and_routing_signal(self):
        tok = _token("alice@example.test", 1, password=_MD5)
        self.assertEqual(_jwt_claims(tok)["data"]["password"], _MD5)
        self.assertIsNone(_jwt_claims("not.a.jwt"))
        self.assertIsNone(_jwt_claims("eyJhbGciOi.eyJzdWIi"))
        doc = {"items": [{"checksum": _MD5, "id": _SHA1}, {"hash": _BCRYPT}],
               "session": _token("alice@example.test", 1, password=_MD5)}
        found = exposure_fields(json.dumps(doc))
        self.assertIn("$.items[1].hash", found)
        self.assertIn("$.session<jwt>.data.password", found)
        self.assertFalse([p for p in found if "checksum" in p or p.endswith(".id")], found)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.received.append(dict(self.headers))
        if not self.headers.get("Authorization"):
            status, doc = 401, {"error": "login required"}
        else:
            status = self.server.statuses.pop(0) if self.server.statuses else 200
            doc = self.server.doc if status == 200 else {"error": "refused"}
        body = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_LISTING = {"status": "success", "data": [
    {"id": 1, "email": "alice@example.test", "role": "customer"},
    {"id": 2, "email": "bob@example.test", "role": "customer"}]}


class ExposureCallerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="oracle_gaps_api_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        st = global_throttle.throttle.stats()
        prev = (st["rate_per_second"] if st["enabled"] else 0.0, st["burst"] if st["enabled"] else None)
        self.addCleanup(lambda: global_throttle.configure(*prev))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.received, self.server.statuses, self.server.doc = [], [], {}
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def dispatch(self, doc, *, a="Bearer a", b="Bearer b", statuses=()):
        self.server.doc, self.server.statuses = doc, list(statuses)
        self.server.received.clear()
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["127.0.0.1"]
        cfg["validators"].update(active_enabled=True)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        global_throttle.configure(0)
        orch.validator_registry.validators = {"api_security": ApiSecurityValidator()}

        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=50, config=cfg,
                                    gate_config={"active_enabled": True})
            run.sessions.register("a", "alice", {"Authorization": a}, allowed_origins=[self.origin])
            run.sessions.register("b", "bob", {"Authorization": b}, allowed_origins=[self.origin])
            ex = HttpExchange(url=self.origin + "/api/accounts", method="GET",
                              request_headers={"Authorization": a})
            finding = Finding(vulnerability_class="excessive data exposure", confidence=0.7,
                              summary="secret exposed", evidence="capture", suggested_test="replay",
                              basis="derived")
            async with run:
                reports, proofs = await orch._validate_findings(
                    ex, [AgentReport(agent="api_security", model="fake", findings=[finding])],
                    run_context=run)
            await run.aclose()
            return reports, proofs

        reports, proofs = asyncio.run(go())
        mine = [r for r in reports if r.validator == "api_security_validator"]
        self.assertEqual(len(mine), 1, [(r.validator, r.status) for r in reports])
        return mine[0], proofs

    def bearer(self, email, uid, **kw):
        return "Bearer " + _token(email, uid, **kw)

    # -- the caller's own session token -------------------------------------------
    def test_password_digest_in_own_session_token_confirms_after_two_accepted_reads(self):
        a = self.bearer("alice@example.test", 1, password=_MD5)
        report, proofs = self.dispatch(_LISTING, a=a, b=self.bearer("bob@example.test", 2))
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("session token", report.summary)
        self.assertIn("claim=request.Authorization<jwt>.data.password; password digest", report.evidence)
        self.assertNotIn(_MD5, report.evidence + report.summary)
        self.assertNotIn("totpSecret", report.evidence)   # empty claim: not a secret
        auth = [h.get("Authorization") for h in self.server.received]
        self.assertEqual(auth, [a, a, None])   # baseline, repeat, anonymous control
        proof = [p for p in proofs if p.get("validator") == "api_security_validator"
                 and p.get("attack_artifact_id")]
        self.assertEqual(len(proof), 1, proofs)

    def test_token_without_credential_claims_is_not_confirmed(self):
        report, _ = self.dispatch(_LISTING, a=self.bearer("alice@example.test", 1),
                                  b=self.bearer("bob@example.test", 2))
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertEqual(len(self.server.received), 1)

    def test_token_refused_on_the_baseline_is_not_confirmed(self):
        a = self.bearer("alice@example.test", 1, password=_MD5)
        report, _ = self.dispatch(_LISTING, a=a, statuses=[401])
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertEqual(len(self.server.received), 1, "a refused token earns no repeat read")

    def test_token_refused_on_the_repeat_is_not_confirmed(self):
        a = self.bearer("alice@example.test", 1, password=_MD5)
        report, _ = self.dispatch(_LISTING, a=a, statuses=[200, 403])
        self.assertNotEqual(report.status, "confirmed", report.summary)
        self.assertEqual(len(self.server.received), 2)

    # -- accounts no session is registered for --------------------------------------
    def test_hash_on_an_account_shown_not_to_be_the_callers_confirms(self):
        doc = {"data": [{"id": 1, "email": "alice@example.test"},
                        {"id": 9, "email": "carol@example.test", "password": _BCRYPT}]}
        report, _ = self.dispatch(doc, a=self.bearer("alice@example.test", 1),
                                  b=self.bearer("bob@example.test", 2))
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("field=$.data[1].password", report.evidence)
        self.assertIn("owner=unregistered-account:", report.evidence)
        self.assertNotIn("carol", report.evidence)
        self.assertNotIn(_BCRYPT, report.evidence)

    def test_unknown_caller_email_names_no_owner(self):
        # Without the caller's own account keys, a foreign-looking object might be
        # the caller's: nothing is attributed.
        doc = {"data": [{"id": 9, "email": "carol@example.test", "password": _BCRYPT}]}
        report, _ = self.dispatch(doc)
        self.assertEqual(report.status, "not_confirmed", report.summary)

    def test_checksum_and_compound_token_on_unregistered_account_stay_silent(self):
        doc = {"data": [{"id": 9, "email": "carol@example.test", "checksum": _MD5, "etag": _SHA1,
                         "uuid": _MD5, "membershipToken": "opaque-member-credential-0001"}]}
        report, _ = self.dispatch(doc, a=self.bearer("alice@example.test", 1),
                                  b=self.bearer("bob@example.test", 2))
        self.assertEqual(report.status, "not_confirmed", report.summary)

    def test_registered_other_account_found_by_its_token_email(self):
        doc = {"data": [{"id": 1, "email": "alice@example.test"},
                        {"id": 2, "email": "bob@example.test", "apiToken": "opaque-bob-credential"}]}
        report, _ = self.dispatch(doc, a=self.bearer("alice@example.test", 1),
                                  b=self.bearer("bob@example.test", 2))
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("owner=bob", report.evidence)


_ACCOUNT = {"email": "new@example.test", "password": "pw-123456", "name": "Newcomer"}


class CreateHandOffTests(unittest.IsolatedAsyncioTestCase):
    """A captured create (201) of api_security's mass-assignment check runs in
    write_integrity's create engine: never a verbatim replay, never an object
    left behind, nothing sent when no restore route is known."""

    async def asyncSetUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Store)
        self.server.data, self.server.next_id = _seed(), 100
        self.server.owners = {("lists", 1): "Bearer a", ("lists", 2): "Bearer b",
                              ("items", 10): "Bearer a"}
        self.server.modes, self.server.received, self.server.bodies = set(), [], []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    async def asyncTearDown(self):
        self.server.shutdown()
        self.server.server_close()

    async def probe(self, restore_routes, *, status=201):
        cfg = {"validators": {"active_enabled": True, "allow_mutating_replay": True,
                              "write_integrity": {"enabled": True, "restore_routes": list(restore_routes)}},
               "server": {"allowed_hosts": ["127.0.0.1"]}}
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=80, config=cfg,
                                gate_config={"active_enabled": True, "allow_mutating_replay": True,
                                             "mutating_ceiling_by_check": {"write_integrity": 8}})
        run.sessions.register("a", "alice", {"Authorization": "Bearer a"}, allowed_origins=[self.origin])
        run.sessions.register("b", "bob", {"Authorization": "Bearer b"}, allowed_origins=[self.origin])
        v = ApiSecurityValidator()
        v.run_context = run
        ex = HttpExchange(url=self.origin + "/api/accounts", method="POST",
                          request_headers={"Authorization": "Bearer a", "Content-Type": "application/json"},
                          request_body=json.dumps(_ACCOUNT), response_status=status,
                          response_headers={}, response_body='{"data": {"id": 99}}')
        finding = Finding(vulnerability_class="mass assignment", confidence=0.6, summary="ma",
                          evidence="capture", suggested_test="replay", basis="derived")
        try:
            async with run:
                return await v.validate(finding, ex), run
        finally:
            await run.aclose()

    def posts(self):
        return [p for m, p, _ in self.server.received if m == "POST"]

    async def test_privileged_field_stored_at_create_confirms_and_is_deleted(self):
        result, _ = await self.probe(["DELETE /api/accounts/{id}"])
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("Mass assignment at create", result.summary)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertEqual(self.server.data, _seed())
        # Never the captured email verbatim: every create was uniquified.
        self.assertNotIn(_ACCOUNT["email"], [b.get("email") for b in self.server.bodies])

    async def test_ignored_privileged_fields_are_not_confirmed(self):
        self.server.modes.add("ignore_roles")
        result, _ = await self.probe(["DELETE /api/accounts/{id}"])
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertIn("ignored the privileged fields", result.summary)
        self.assertEqual(self.server.data, _seed())

    async def test_no_restore_route_sends_nothing(self):
        result, _ = await self.probe([])
        self.assertIn(result.status, ("blocked", "inconclusive"), result.summary)
        self.assertFalse(result.confirmed)
        self.assertIn("did not complete", result.summary)
        self.assertIn("no restore path known", result.summary)
        self.assertEqual(self.posts(), [], "an unrestorable create must not be sent")
        self.assertEqual(self.server.data, _seed())


if __name__ == "__main__":
    unittest.main()
