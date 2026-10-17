"""Tests for the Phase 1.1 account-registration helper (identity_registration).

A stdlib loopback server mimics crAPI's auth contract (signup/login) and the
harness's own /identities/session-headers endpoint, so both the in-process and
server registration paths are exercised over real HTTP without a live target.

Rule 4: the helper sends signup/login traffic, so these tests assert it actually
arrived (per-path request counts), not merely that the call returned.
"""
from __future__ import annotations

import json
import sys
import threading
import unittest
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Robust whether run via `unittest discover -s testing` (testing/ on path) or
# `cd testing && python -m unittest ...` (needs the repo root for `harness`).
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent))

import identity_registration as idreg  # noqa: E402
from harness import identity_headers  # noqa: E402

_HOST = "127.0.0.1"


def _make_handler(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _read(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                return json.loads(raw or b"{}")
            except ValueError:
                return {}

        def _send(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            state["counts"][self.path] += 1
            body = self._read()
            if self.path == "/identity/api/auth/signup":
                email = body.get("email")
                if email in state["signed_up"]:
                    self._send(409, {"message": "already registered"})
                    return
                state["signed_up"].add(email)
                self._send(200, {"ok": True})
                return
            if self.path == "/identity/api/auth/login":
                email = body.get("email") or ""
                if "fail" in email or body.get("password") == "wrongpw":
                    self._send(401, {"message": "bad credentials"})
                    return
                self._send(200, {"token": f"jwt-for-{email}", "type": "Bearer"})
                return
            if self.path == "/identities/session-headers":
                state["server_posts"].append(body)
                self._send(200, {"ok": True})
                return
            self._send(404, {"message": "not found"})

    return H


class IdentityRegistrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = {"counts": Counter(), "signed_up": set(), "server_posts": []}
        cls.server = ThreadingHTTPServer((_HOST, 0), _make_handler(cls.state))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://{_HOST}:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        identity_headers.clear(_HOST)
        self.state["counts"].clear()
        self.state["signed_up"].clear()
        self.state["server_posts"].clear()

    def tearDown(self):
        identity_headers.clear(_HOST)

    def _accounts(self):
        return [idreg.Account("victimA", "a@test", "pwA",
                              signup_fields={"name": "A", "number": "1111111111"}),
                idreg.Account("victimB", "b@test", "pwB",
                              signup_fields={"name": "B", "number": "2222222222"})]

    def test_in_process_registers_both_and_arms_cross_user(self):
        self.assertFalse(identity_headers.has_identities(_HOST))
        run = idreg.register_identities(self.base, self._accounts())
        # host derived from base_url is the BARE hostname (no port) -- the spelling
        # registry.py:436 / cross_identity_validator.py:390 look up.
        self.assertEqual(run["host"], _HOST)
        self.assertTrue(identity_headers.has_identities(_HOST),
                        "cross-user validator would still sit out: no identities armed")
        got = {i["name"]: i for i in identity_headers.identities_for_host(_HOST)}
        self.assertEqual(set(got), {"victimA", "victimB"})
        self.assertEqual(got["victimA"]["headers"]["Authorization"], "Bearer jwt-for-a@test")
        self.assertEqual(got["victimB"]["role"], "user")
        # Rule 4: the helper genuinely signed up + logged in each account.
        self.assertEqual(self.state["counts"]["/identity/api/auth/login"], 2)
        self.assertEqual(self.state["counts"]["/identity/api/auth/signup"], 2)
        # The run log proves both were registered, each with a timestamp -- the
        # Phase 1.1 "done when" (a log shows both accounts registered before the
        # first exchange).
        self.assertEqual([r["name"] for r in run["registered"]], ["victimA", "victimB"])
        self.assertTrue(all(r["at"] for r in run["registered"]))

    def test_signup_already_exists_is_idempotent(self):
        idreg.register_identities(self.base, self._accounts())
        identity_headers.clear(_HOST)
        # Second run: signup now returns 409, but login still succeeds and the
        # identities are re-registered -- a re-run must not abort.
        run = idreg.register_identities(self.base, self._accounts())
        self.assertTrue(identity_headers.has_identities(_HOST))
        self.assertEqual(len(run["registered"]), 2)

    def test_login_failure_raises_not_silent(self):
        # A partial identity set silently skips the cross-user checks -- the exact
        # bug being fixed -- so a login failure must fail LOUD.
        accounts = [idreg.Account("ok", "a@test", "pwA"),
                    idreg.Account("broken", "fail@test", "pw")]
        with self.assertRaises(idreg.RegistrationError):
            idreg.register_identities(self.base, accounts)

    def test_wrong_password_raises(self):
        accounts = [idreg.Account("victimA", "a@test", "wrongpw"),
                    idreg.Account("victimB", "b@test", "wrongpw")]
        with self.assertRaises(idreg.RegistrationError):
            idreg.register_identities(self.base, accounts)

    def test_requires_two_accounts(self):
        with self.assertRaises(ValueError):
            idreg.register_identities(self.base, [idreg.Account("solo", "s@test", "pw")])

    def test_bad_via_and_server_requires_url(self):
        with self.assertRaises(ValueError):
            idreg.register_identities(self.base, self._accounts(), via="nope")
        with self.assertRaises(ValueError):
            idreg.register_identities(self.base, self._accounts(), via="server")
        # No network happened for either argument error.
        self.assertEqual(sum(self.state["counts"].values()), 0)

    def test_server_path_posts_session_headers(self):
        run = idreg.register_identities(self.base, self._accounts(), via="server",
                                        server_url=self.base, server_token="tkn")
        self.assertEqual(run["via"], "server")
        # Two session-header POSTs reached the server, each carrying the bearer
        # header for the right host.
        self.assertEqual(self.state["counts"]["/identities/session-headers"], 2)
        posts = {p["name"]: p for p in self.state["server_posts"]}
        self.assertEqual(set(posts), {"victimA", "victimB"})
        self.assertEqual(posts["victimA"]["headers"]["Authorization"], "Bearer jwt-for-a@test")
        self.assertEqual(posts["victimA"]["host"], _HOST)
        # via='server' must NOT also touch the in-process store.
        self.assertFalse(identity_headers.has_identities(_HOST))


if __name__ == "__main__":
    unittest.main()
