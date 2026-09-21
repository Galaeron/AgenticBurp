"""
RB-1: HTTP-level tests for server.py's local-API origin/CSRF defense.

Before this, a page the tester's browser visited could `fetch()` this
loopback server directly: on the default deploy (loopback, no
server.auth_token/HARNESS_BEARER_TOKEN configured), `_require_auth`'s
loopback bypass meant every route -- including every state-changing one --
was reachable with no proof the caller was the tester's own Burp extension
or curl session (server.py's own prior comment conceded the JSON endpoints
were "protected only by accidental CORS-preflight").

Two independent, additive controls now close that gap (see
`_csrf_defense_middleware` in server.py for the implementation):
  1. PRIMARY -- an ephemeral bearer token, generated at startup whenever no
     operator token is configured, required on every state-changing
     (POST/PUT/PATCH/DELETE) route even from loopback.
  2. DEFENSE-IN-DEPTH -- an Origin/Sec-Fetch-Site check that rejects any
     request a browser itself has labeled cross-site, on every route
     (including GET, the "simple request" class control 1 does not cover).

Same isolated-DB + fresh-module-reload pattern as test_server.py, so every
test gets its own freshly-generated ephemeral token; no operator
auth_token/HARNESS_BEARER_TOKEN is configured in this test environment, so
server.py always takes the ephemeral-generation branch RB-1 added.
"""
import tempfile
import unittest
from pathlib import Path

from harness import store


class LocalApiCsrfDefenseTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        # Imported/reloaded after the DB path is patched and inside setUp,
        # same reasoning as test_server.py: server.py's module-level
        # Orchestrator construction (and, now, its ephemeral-token
        # generation) must not happen before the test DB is in place, and a
        # fresh reload per test avoids state (including the token) bleeding
        # across tests.
        import importlib
        import harness.server as server_module
        importlib.reload(server_module)
        self.server = server_module

        # This whole test class exercises the ephemeral-generation branch,
        # not the pre-existing operator-configured-token branch (that one is
        # covered by test_hardening.py::test_non_loopback_auth_guard). Make
        # the assumption explicit rather than silently testing the wrong
        # branch if some future change starts configuring a token here.
        self.assertIsNone(self.server._BEARER_TOKEN,
                          "test env must have no operator auth_token/HARNESS_BEARER_TOKEN set")
        self.token = self.server._mutation_token()
        self.assertTrue(self.token, "an ephemeral token must always be generated when no operator token is set")

        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    # --- Control 1 (primary): the ephemeral bearer token on state-changing routes ---

    def test_state_changing_route_without_token_is_401(self):
        resp = self.client.post("/cache/clear")
        self.assertEqual(resp.status_code, 401)

    def test_state_changing_route_with_wrong_token_is_401(self):
        resp = self.client.post("/cache/clear", headers={"Authorization": "Bearer not-the-real-token"})
        self.assertEqual(resp.status_code, 401)

    def test_loopback_call_with_token_and_no_origin_succeeds(self):
        resp = self.client.post("/cache/clear", headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")

    def test_get_routes_remain_ungated_behind_the_mutation_token(self):
        # GET/read routes are deliberately NOT gated behind _mutation_token()
        # (see _csrf_defense_middleware's docstring) -- only the pre-existing
        # _require_auth loopback convenience governs them, same as before
        # RB-1. The Origin/Sec-Fetch-Site check (below) is what defends
        # those instead. No Authorization header at all here.
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)

    # --- Control 2 (defense-in-depth): reject cross-site requests outright ---

    def test_cross_site_origin_is_rejected_even_with_a_valid_token(self):
        resp = self.client.post("/cache/clear", headers={
            "Authorization": f"Bearer {self.token}", "Origin": "http://evil.test"})
        self.assertEqual(resp.status_code, 403)

    def test_sec_fetch_site_cross_site_is_rejected_on_a_get_route(self):
        # A browser sets Sec-Fetch-Site itself (a page cannot forge it) --
        # this must reject on its own signal, with no Origin header present
        # at all, and on a GET route too (the "simple request" class control
        # 1 does not cover -- this is exactly the gap the backlog item calls
        # out: "GET routes ... are reachable cross-origin").
        resp = self.client.get("/health", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(resp.status_code, 403)

    def test_same_origin_origin_header_is_allowed(self):
        # POSITIVE control: an Origin header that DOES match the request's
        # own host (a genuine same-origin fetch()) must not be rejected --
        # the middleware rejects a MISMATCHED/cross-site Origin, never the
        # mere presence of an Origin header.
        resp = self.client.post("/cache/clear", headers={
            "Authorization": f"Bearer {self.token}", "Origin": "http://localhost"})
        self.assertEqual(resp.status_code, 200)

    def test_no_origin_request_with_valid_token_is_not_rejected_by_origin_middleware(self):
        # NEGATIVE CONTROL (regression guard), matching the RB-1 acceptance
        # criteria verbatim: curl and the Burp extension send NO Origin
        # header and NO Sec-Fetch-Site header at all today. A missing Origin
        # must never be treated as cross-site by the middleware -- only an
        # ACTUALLY cross-site Origin/Sec-Fetch-Site value is rejected. This
        # is what keeps every existing same-origin/no-Origin caller working.
        resp = self.client.post("/cache/clear", headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
