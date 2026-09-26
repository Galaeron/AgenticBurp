"""
RA-3: HTTP-level tests for server.py's GET /report/sarif endpoint --
sarif_adapter.py (export_issues_to_sarif/validate_sarif_shape) was fully
built and tested (test_sarif_adapter.py) but had no production caller
anywhere. This wires it up as a read-only offline export, same
FastAPI TestClient + isolated temp DB + module-reload pattern as
test_server.py/test_local_api_csrf.py.

Covers: a positive round trip (seeded finding -> schema-valid SARIF doc
whose result carries the issue's rule/title), the empty-host control
(no findings -> schema-valid doc with zero results, not a 500), the
read-auth gate (server._READ_AUTH_ENABLED True/False, mirroring
test_server.py::ReadAuthTests' own per-route tests), and that /report's
existing Markdown contract is untouched by this change.
"""
import tempfile
import unittest
from pathlib import Path

from harness import sarif_adapter
from harness import store
from harness.models import HttpExchange, Finding


class SarifReportEndpointTests(unittest.TestCase):
    def setUp(self):
        # Isolated temp DB, never touch the real harness_state.db.
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        # Imported/reloaded after the DB path is patched and inside setUp,
        # same reasoning as test_server.py: server.py's module-level
        # Orchestrator construction must not happen before the test DB is
        # in place, and reloading avoids state bleed across tests.
        import importlib
        import harness.server as server_module
        importlib.reload(server_module)
        self.server = server_module
        from fastapi.testclient import TestClient
        # No default Authorization header (unlike SuppressionEndpointTests)
        # -- this endpoint is GET-only, unaffected by the RB-1 CSRF gate,
        # and the auth-control tests below need to toggle the header
        # per-request.
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _auth_header(self):
        return {"Authorization": f"Bearer {self.server._mutation_token()}"}

    def _seed_finding(self, url="https://example.com/api/items"):
        exchange = HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                                 response_status=200, response_headers={}, response_body="")
        finding = Finding(vulnerability_class="sqli", confidence=0.9,
                           summary="Boolean-blind SQL injection in id",
                           evidence="db error surfaced", suggested_test="t",
                           basis="derived", severity="high", confirmed=True)
        store.persist_findings(exchange, "sqli_agent", [finding])
        return url

    # --- Positive: seeded finding round-trips into a schema-valid doc -----

    def test_seeded_finding_produces_schema_valid_sarif_with_result(self):
        url = self._seed_finding()
        resp = self.client.get("/report/sarif", params={"url": url})
        self.assertEqual(resp.status_code, 200)
        doc = resp.json()
        self.assertEqual(sarif_adapter.validate_sarif_shape(doc), [])
        results = doc["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "sqli")
        rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("sqli", rule_ids)

    # --- Empty-host control: zero findings, not a 500 ---------------------

    def test_host_with_no_findings_returns_zero_result_schema_valid_doc(self):
        resp = self.client.get("/report/sarif", params={"url": "https://nothing-here.example.com/x"})
        self.assertEqual(resp.status_code, 200)
        doc = resp.json()
        self.assertEqual(sarif_adapter.validate_sarif_shape(doc), [])
        self.assertEqual(doc["runs"][0]["results"], [])

    # --- Auth control -------------------------------------------------------

    def test_requires_token_when_read_auth_enabled(self):
        self.server._READ_AUTH_ENABLED = True
        resp = self.client.get("/report/sarif", params={"url": "https://example.com/x"})
        self.assertEqual(resp.status_code, 401)
        resp = self.client.get("/report/sarif", params={"url": "https://example.com/x"},
                               headers=self._auth_header())
        self.assertEqual(resp.status_code, 200)

    def test_reachable_without_token_when_read_auth_disabled_by_default(self):
        self.assertFalse(self.server._READ_AUTH_ENABLED,
                         "server.require_read_auth must default to false")
        resp = self.client.get("/report/sarif", params={"url": "https://example.com/x"})
        self.assertNotEqual(resp.status_code, 401)
        self.assertEqual(resp.status_code, 200)

    # --- /report's own Markdown contract is untouched ----------------------

    def test_existing_markdown_report_endpoint_is_unchanged(self):
        url = self._seed_finding()
        resp = self.client.get("/report", params={"url": url})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["content-type"].split(";")[0], "text/markdown")
        self.assertIn("sqli", resp.text)


if __name__ == "__main__":
    unittest.main()
