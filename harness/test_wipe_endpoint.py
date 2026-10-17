"""
P3-1 (partial): HTTP-level tests for DELETE /engagement/{host}/evidence --
the opt-in, auth-gated endpoint that calls the already-landed, callable-only
store.wipe_engagement(host) (see harness/test_store.py::WipeEngagementTests
for the store-layer coverage of wipe_engagement itself; this file covers the
HTTP wiring on top of it: the opt-in flag, and that the existing auth/CSRF
gates apply to this route exactly like every other mutating route).

Ships OFF by default (server.enable_wipe_endpoint: false) -- no scheduler,
no retention-apply endpoint here; those are separate follow-ons. This suite
asserts, offline:
  1. POSITIVE: flag ON + valid mutation token -> 200, per-table counts, and
     the seeded finding for the wiped host is gone.
  2. NEGATIVE (auth): flag ON + missing/invalid token -> 401, store untouched.
     This is the pre-existing CSRF middleware gate (_csrf_defense_middleware),
     unchanged by this slice -- it runs before the route handler at all.
  3. NEGATIVE (opt-in): flag OFF (the shipped default) + valid token -> 403,
     store untouched.
  4. ISOLATION: wiping host A never touches host B's stored findings.

Same isolated-DB + fresh-module-reload pattern as test_local_api_csrf.py, so
every test gets its own freshly-generated ephemeral mutation token and a
freshly-initialized _WIPE_ENDPOINT_ENABLED (read from the committed
config.yaml default, i.e. False, on every reload).
"""
import importlib
import tempfile
import unittest
from pathlib import Path

from harness import store
from harness.models import HttpExchange, Finding


class WipeEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_wipe_endpoint.db"

        # Reloaded after the DB path is patched, same reasoning as
        # test_local_api_csrf.py: server.py's module-level Orchestrator
        # construction and ephemeral-token generation must not happen before
        # the test DB is in place, and a fresh reload per test avoids state
        # (including both the token and _WIPE_ENDPOINT_ENABLED) bleeding
        # across tests.
        import harness.server as server_module
        importlib.reload(server_module)
        self.server = server_module

        self.assertIsNone(self.server._BEARER_TOKEN,
                          "test env must have no operator auth_token/HARNESS_BEARER_TOKEN set")
        self.token = self.server._mutation_token()
        self.assertTrue(self.token, "an ephemeral token must always be generated when no operator token is set")

        # Ship-default sanity check: a fresh reload from the committed
        # config.yaml must come up with the endpoint OFF. If this ever
        # fails, config.yaml's server.enable_wipe_endpoint has drifted off
        # its safe default (config_manifest.py's NC-3 guard also covers
        # this independently).
        self.assertFalse(self.server._WIPE_ENDPOINT_ENABLED,
                         "server.enable_wipe_endpoint must ship false")
        self._original_wipe_enabled = self.server._WIPE_ENDPOINT_ENABLED

        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def tearDown(self):
        self.server._WIPE_ENDPOINT_ENABLED = self._original_wipe_enabled
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _seed_finding(self, host: str, url: str, *, case_id: str) -> None:
        """Minimal seed: one persisted finding for `host`, via the
        production persist path (store.persist_findings), so presence/
        absence can be asserted with store.all_host_findings(url) -- the
        same reader the store-layer WipeEngagementTests use."""
        exchange = HttpExchange(
            url=url, method="GET", request_headers={}, request_body="",
            response_status=200, response_headers={}, response_body="",
        )
        finding = Finding(
            vulnerability_class="sqli", confidence=0.9, summary=f"finding for {host}",
            evidence="e", suggested_test="t", basis="derived",
            case_id=case_id, finding_id=f"{case_id}-finding", proof_id=f"{case_id}-proof",
        )
        store.persist_findings(exchange, "test_agent", [finding])
        self.assertEqual(len(store.all_host_findings(url)), 1,
                         f"seed failed: expected exactly one finding for {host}")

    # --- POSITIVE: flag ON + valid token -----------------------------------

    def test_wipe_with_flag_on_and_valid_token_succeeds_and_deletes_findings(self):
        url_a = "https://a.example.com/api/x"
        self._seed_finding("a.example.com", url_a, case_id="case-A-1")
        self.server._WIPE_ENDPOINT_ENABLED = True

        resp = self.client.delete(
            "/engagement/a.example.com/evidence",
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["host"], "a.example.com")
        self.assertIn("wiped", body)
        self.assertIsInstance(body["wiped"], dict)
        self.assertGreater(body["wiped"].get("findings", 0), 0)

        # The seeded finding for the wiped host is gone from the store.
        self.assertEqual(store.all_host_findings(url_a, include_suppressed=True), [])

    # --- NEGATIVE: auth (missing/invalid token) -----------------------------

    def test_wipe_with_flag_on_and_missing_token_is_401_and_store_untouched(self):
        url_a = "https://a.example.com/api/x"
        self._seed_finding("a.example.com", url_a, case_id="case-A-2")
        self.server._WIPE_ENDPOINT_ENABLED = True

        resp = self.client.delete("/engagement/a.example.com/evidence")

        self.assertEqual(resp.status_code, 401)
        self.assertEqual(len(store.all_host_findings(url_a)), 1)

    def test_wipe_with_flag_on_and_invalid_token_is_401_and_store_untouched(self):
        url_a = "https://a.example.com/api/x"
        self._seed_finding("a.example.com", url_a, case_id="case-A-3")
        self.server._WIPE_ENDPOINT_ENABLED = True

        resp = self.client.delete(
            "/engagement/a.example.com/evidence",
            headers={"Authorization": "Bearer not-the-real-token"},
        )

        self.assertEqual(resp.status_code, 401)
        self.assertEqual(len(store.all_host_findings(url_a)), 1)

    # --- NEGATIVE: opt-in (flag OFF, the shipped default) -------------------

    def test_wipe_with_flag_off_and_valid_token_is_403_and_store_untouched(self):
        url_a = "https://a.example.com/api/x"
        self._seed_finding("a.example.com", url_a, case_id="case-A-4")
        # Flag left at its reloaded (shipped-default) value: False.
        self.assertFalse(self.server._WIPE_ENDPOINT_ENABLED)

        resp = self.client.delete(
            "/engagement/a.example.com/evidence",
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.assertEqual(resp.status_code, 403)
        self.assertIn("disabled", resp.json().get("detail", ""))
        self.assertEqual(len(store.all_host_findings(url_a)), 1)

    # --- ISOLATION -----------------------------------------------------------

    def test_wiping_host_a_leaves_host_b_findings_intact(self):
        url_a = "https://a.example.com/api/x"
        url_b = "https://b.example.com/api/y"
        self._seed_finding("a.example.com", url_a, case_id="case-A-5")
        self._seed_finding("b.example.com", url_b, case_id="case-B-1")
        self.server._WIPE_ENDPOINT_ENABLED = True

        resp = self.client.delete(
            "/engagement/a.example.com/evidence",
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(store.all_host_findings(url_a, include_suppressed=True), [])
        self.assertEqual(len(store.all_host_findings(url_b)), 1)


if __name__ == "__main__":
    unittest.main()
