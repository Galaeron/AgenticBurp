"""RS256 -> HS256 key confusion with a public key the run already captured, through
investigate_engagement (the production caller of the JWT forge leg).

The forge leg used to look for the verification key only at the two standard JWKS
paths. A key the run captured anywhere in scope (a PEM file a capture or one of the
run's own GETs answered with) is now reused for the same HS256 forgery: its bytes
as served, and its standard PEM serialisations, are the HMAC secret. Nothing new is
fetched for it.

The loopback target is generic: GET /api/profile takes an RS256 bearer token, and
GET /assets/keys/signing.pub serves the verification key.
  - confused verifier (it verifies HS256 with that same PEM as the secret): the
    forgery with the captured key is accepted, so the leg confirms; the forge leg
    never requests the key's path.
  - control, a verifier that pins RS256: the same forgery is sent and refused; the
    leg concludes not_confirmed with the existing garbage/no-token controls.
  - control, no key captured: no captured-key forgery is sent, so the confused
    verifier stays undetected (the JWKS paths answer 404).
  - same, with the key known only from one of the run's own earlier GETs.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from harness import cache, evidence_ledger, global_throttle, identity_headers, safety_gate, store
from harness.models import HttpExchange
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.run_context import RunContext, TypedRequest
from harness.test_engagement_transport_callers import _Model, _canned, _config, _install_model
from harness.validators.jwt_forge_validator import JwtForgeValidator

_KEY_PATH = "/assets/keys/signing.pub"
_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _PRIVATE.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _rs256(payload: dict) -> str:
    head = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps(payload).encode())
    sig = _PRIVATE.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{_b64(sig)}"


_TOKEN = _rs256({"sub": "user7", "role": "customer"})


def _pem_hmac(token: str) -> bool:
    """True for an HS256 token signed with the PEM file's bytes as the secret."""
    try:
        head, body, sig = token.split(".")
        alg = json.loads(_unb64(head)).get("alg")
    except ValueError:
        return False
    expected = hmac.new(_PEM, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return alg == "HS256" and hmac.compare_digest(expected, _unb64(sig))


class _JwtTarget:
    """mode "confused" verifies HS256 with the PEM as the secret; "pinned" accepts
    RS256 only. Records (method, path, token, status) for every request."""

    def __init__(self, mode: str):
        self.mode, self.requests, self._lock = mode, [], threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body: bytes, ctype="application/json"):
                auth = self.headers.get("Authorization", "")
                with outer._lock:
                    outer.requests.append((self.command, self.path.split("?")[0],
                                           auth[7:] if auth.startswith("Bearer ") else "", status))
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == _KEY_PATH:
                    return self._send(200, _PEM, "text/plain")
                if path != "/api/profile":
                    return self._send(404, b'{"error": "not found"}')
                auth = self.headers.get("Authorization", "")
                claims = outer.verify(auth[7:]) if auth.startswith("Bearer ") else None
                if claims is None:
                    return self._send(401, b'{"error": "unauthorized"}')
                return self._send(200, json.dumps({
                    "id": 7, "user": claims.get("sub"), "role": claims.get("role"),
                    "email": "user7@example.test", "orders": [101, 102]}).encode())

            def _other(self):
                self._send(405, b'{"error": "method not allowed"}')

            do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _other

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def verify(self, token: str):
        try:
            head, body, sig = token.split(".")
            header, claims = json.loads(_unb64(head)), json.loads(_unb64(body))
        except ValueError:
            return None
        signing_input = f"{head}.{body}".encode()
        if header.get("alg") == "RS256":
            try:
                _PRIVATE.public_key().verify(_unb64(sig), signing_input, padding.PKCS1v15(),
                                             hashes.SHA256())
                return claims
            except (InvalidSignature, ValueError):
                return None
        if header.get("alg") == "HS256" and self.mode == "confused" and _pem_hmac(token):
            return claims
        return None

    def close(self):
        self._server.shutdown()
        self._server.server_close()


_NODE = {"method": "GET", "path": "/api/profile", "by_role": {"user": 200, "anonymous": 401},
         "reachable_roles": ["user"], "object_scoped": False}
_ROLES = [RoleSession("anonymous", {}), RoleSession("user", {"Authorization": f"Bearer {_TOKEN}"})]


def _key_capture(base):
    return HttpExchange(url=f"{base}{_KEY_PATH}", method="GET", response_status=200,
                        response_headers={"Content-Type": "text/plain"},
                        response_body=_PEM.decode()).model_dump()


class JwtCapturedKeyCallerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="jwt_captured_key_")
        orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        stats = global_throttle.throttle.stats()
        throttle = (stats["rate_per_second"] if stats["enabled"] else 0.0,
                    stats["burst"] if stats["enabled"] else None)
        global_throttle.configure(0)
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()

        def restore():
            global_throttle.configure(*throttle)
            safety_gate.reset_default_gate()
            store._DB_PATH, cache._cache = orig
            identity_headers.clear()
            shutil.rmtree(self._tmp, ignore_errors=True)
        self.addCleanup(restore)

    def _run(self, mode, *, captured=(), prime_key_fetch=False):
        target = _JwtTarget(mode)
        self.addCleanup(target.close)
        cfg = _config(mutating=False)
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _install_model(orch, _Model([]))
        results, probed = [], []
        real_validate, real_probe = JwtForgeValidator.validate, JwtForgeValidator._probe

        async def spy(validator, finding, exchange, *a, **kw):
            result = await real_validate(validator, finding, exchange, *a, **kw)
            results.append((exchange.url, result))
            return result

        async def probe_spy(validator, url, headers):
            probed.append(url.split("?")[0])
            return await real_probe(validator, url, headers)

        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=3000, config=cfg,
                               gate_config={"active_enabled": True, "allow_mutating_replay": False})

        async def go():
            try:
                async with rc:
                    if prime_key_fetch:
                        # One of the run's own earlier GETs answered with the key.
                        await rc.executor().execute(TypedRequest("GET", target.base + _KEY_PATH),
                                                    capability="crawl")
                    return await orch.investigate_engagement(
                        target.base, _ROLES, max_nodes=2, step_budget=2, max_chain_rounds=0,
                        run_context=rc)
            finally:
                await rc.aclose()

        patches = [patch("harness.engagement_builder.build_engagement",
                         side_effect=_canned([_NODE], captured)),
                   patch("harness.browser_driver.default_driver", return_value=None),
                   patch.object(JwtForgeValidator, "validate", new=spy),
                   patch.object(JwtForgeValidator, "_probe", new=probe_spy)]
        for p in patches:
            p.start()
        try:
            asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        on_profile = [r for url, r in results if url.split("?")[0].endswith("/api/profile")]
        self.assertTrue(on_profile, "the JWT forge leg never ran on the token-gated route")
        forged = [(m, s) for m, p, tok, s in target.requests if tok and _pem_hmac(tok)]
        self.forge_probed = probed
        return on_profile, forged, target

    def test_confused_verifier_is_confirmed_with_the_captured_key(self):
        results, forged, target = self._run("confused", captured=(_key_capture,))
        confirmed = [r for r in results if r.confirmed]
        self.assertTrue(confirmed, [r.summary for r in results])
        self.assertIn("a public key the run captured", confirmed[0].summary)
        self.assertIn(("GET", 200), forged)
        self.assertEqual({m for m, _s in forged}, {"GET"})
        # Reused, not fetched: the forge leg never requested the key's path.
        self.assertTrue(self.forge_probed)
        self.assertEqual([u for u in self.forge_probed if u.endswith(_KEY_PATH)], [])

    def test_control_rs256_pinned_verifier_refuses_the_captured_key_forgery(self):
        results, forged, _target = self._run("pinned", captured=(_key_capture,))
        self.assertFalse([r for r in results if r.confirmed], [r.summary for r in results])
        # The forgery was sent and refused, beside the existing controls.
        self.assertTrue(forged)
        self.assertEqual({s for _m, s in forged}, {401})
        self.assertTrue(any(r.status == "not_confirmed" and "public keys the run captured" in r.evidence
                            for r in results), [r.evidence for r in results])

    def test_control_without_a_captured_key_no_key_forgery_is_sent(self):
        results, forged, _target = self._run("confused")
        self.assertEqual(forged, [])
        self.assertFalse([r for r in results if r.confirmed], [r.summary for r in results])

    def test_a_key_seen_only_in_one_of_the_runs_own_answers_is_reused(self):
        results, forged, target = self._run("confused", prime_key_fetch=True)
        self.assertTrue([r for r in results if r.confirmed], [r.summary for r in results])
        self.assertIn(("GET", 200), forged)
        self.assertEqual([u for u in self.forge_probed if u.endswith(_KEY_PATH)], [])


if __name__ == "__main__":
    unittest.main()
