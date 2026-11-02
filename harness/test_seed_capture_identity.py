"""AR-ID: a supplied capture that carries a cookie session binds to the declared
identity that owns that session, or is reported as unbound with a reason.

Run 7d6b115acbec dropped six cookie-bearing captures as "no matching supplied
identity": `build_engagement` compared the identity-header maps exactly, so a
capture whose Cookie header held the declared session cookie next to browser- or
server-set cookies (or in another order) matched nobody. These tests drive the
production caller (`engagement_builder.build_engagement`, through an owning
RunContext, against an owned loopback app) and check:

  - a cookie-session capture with extra/reordered cookies binds to its identity;
  - a capture whose session cookie value differs stays unbound (control);
  - the anonymous and Authorization-header cases bind as before;
  - an Authorization identity is not widened to a capture with an undeclared cookie;
  - no cookie or token value reaches the run's errors or diagnostics.

No live target, no model.
"""
from __future__ import annotations

import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harness import engagement_builder, global_throttle
from harness.models import HttpExchange
from harness.role_crawl import RoleSession
from harness.run_context import RunContext

CAROL_SID = "carol-sid-5b1e9c"
MALLORY_SID = "mallory-sid-77aa01"
ALICE_TOKEN = "alice-token-3f2d"

ANON = RoleSession("anonymous", {})
ALICE = RoleSession("user", {"Authorization": f"Bearer {ALICE_TOKEN}"}, name="alice")
CAROL = RoleSession("user", {"Cookie": f"sid={CAROL_SID}"}, name="carol")
ROLES = [ANON, ALICE, CAROL]
SECRETS = (CAROL_SID, MALLORY_SID, ALICE_TOKEN)


class _App:
    """Owned loopback app: `/` links nothing; every other path answers 200."""

    def __init__(self):
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self):
                data = (b"<html><body>home</body></html>" if self.path == "/"
                        else json.dumps({"ok": True}).encode())
                self.send_response(200)
                self.send_header("Content-Type", "text/html" if self.path == "/" else "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class SeedCaptureIdentityTests(unittest.TestCase):
    def setUp(self):
        stats = global_throttle.throttle.stats()
        prior = (stats["rate_per_second"] if stats["enabled"] else 0.0,
                 stats["burst"] if stats["enabled"] else None)
        global_throttle.configure(0)
        self.addCleanup(global_throttle.configure, *prior)
        self.app = _App()
        self.addCleanup(self.app.close)

    def _capture(self, path, headers):
        return HttpExchange(url=self.app.base + path, method="GET",
                            request_headers=headers, response_status=200,
                            response_body='{"ok": true}')

    def _build(self, captures):
        async def go():
            rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200,
                                   gate_config={"active_enabled": True})
            try:
                async with rc:
                    return await engagement_builder.build_engagement(
                        self.app.base, ROLES, allowed_hosts=["127.0.0.1"],
                        active_discovery=False, run_context=rc, seed_exchanges=captures)
            finally:
                await rc.aclose()
        return asyncio.run(go())

    def _seeded(self, result, path):
        row = next((e for e in result.endpoints if e.path == path), None)
        if row is None:
            return set()
        return {pid for pid, cell in row.by_principal.items()
                if cell.get("source") == "seed_capture"}

    def _assert_no_secret(self, result):
        text = json.dumps({"errors": result.errors}, default=str)
        for secret in SECRETS:
            self.assertNotIn(secret, text, "a credential value reached the run's errors")

    def test_cookie_session_capture_binds_despite_extra_and_reordered_cookies(self):
        _, result = self._build([
            self._capture("/api/carol/profile",
                          {"Cookie": f"theme=dark; sid={CAROL_SID}; _ga=GA1.1.42"}),
            self._capture("/api/carol/settings", {"cookie": f"sid={CAROL_SID}"}),
        ])
        self.assertEqual(self._seeded(result, "/api/carol/profile"), {"carol"}, result.errors)
        self.assertEqual(self._seeded(result, "/api/carol/settings"), {"carol"}, result.errors)
        self.assertFalse([e for e in result.errors if "capture" in e and "unbound" in e])
        self._assert_no_secret(result)

    def test_mismatched_session_cookie_stays_unbound_and_is_reported(self):
        _, result = self._build([
            self._capture("/api/mallory/profile",
                          {"Cookie": f"theme=dark; sid={MALLORY_SID}"}),
        ])
        self.assertEqual(self._seeded(result, "/api/mallory/profile"), set())
        reasons = [e for e in result.errors if e.startswith("capture unbound")]
        self.assertEqual(len(reasons), 1, result.errors)
        self.assertIn("cookie", reasons[0])
        self._assert_no_secret(result)

    def test_anonymous_and_authorization_captures_bind_as_before(self):
        _, result = self._build([
            self._capture("/api/public", {"Accept": "application/json"}),
            self._capture("/api/alice/orders", {"Authorization": f"Bearer {ALICE_TOKEN}"}),
            self._capture("/api/alice/wrong", {"Authorization": "Bearer someone-else"}),
        ])
        self.assertEqual(self._seeded(result, "/api/public"), {"anonymous"}, result.errors)
        self.assertEqual(self._seeded(result, "/api/alice/orders"), {"alice"}, result.errors)
        self.assertEqual(self._seeded(result, "/api/alice/wrong"), set())
        self._assert_no_secret(result)

    def test_undeclared_cookie_does_not_widen_an_authorization_identity(self):
        """A capture carrying alice's bearer AND a session cookie alice never declared
        is not silently relabelled as alice (the cookie could be another session)."""
        _, result = self._build([
            self._capture("/api/alice/mixed", {"Authorization": f"Bearer {ALICE_TOKEN}",
                                               "Cookie": f"sid={MALLORY_SID}"}),
            self._capture("/api/anon/cookie", {"Cookie": "theme=dark"}),
        ])
        self.assertEqual(self._seeded(result, "/api/alice/mixed"), set())
        self.assertEqual(self._seeded(result, "/api/anon/cookie"), set())
        reasons = [e for e in result.errors if e.startswith("capture unbound")]
        self.assertEqual(len(reasons), 2, result.errors)
        self._assert_no_secret(result)


if __name__ == "__main__":
    unittest.main()
