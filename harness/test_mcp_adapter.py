"""Hermetic tests for the read-only MCP adapter (P2.1). No network, no live
target, no MCP SDK dependency -- exercises the adapter against real
store.py/report_generator.py data in an isolated temp DB."""
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from harness import store
from harness.models import HttpExchange, Finding
from harness.mcp_adapter import (
    ReadOnlyMcpAdapter, McpAuthError, McpTenantError, latest_provenance_for_host,
)


class _IsolatedDbTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _persist(self, host: str, *, param="id", secret_query=""):
        url = f"https://{host}/api/items" + (f"?token={secret_query}" if secret_query else "")
        exchange = HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                                response_status=200, response_headers={}, response_body="")
        finding = Finding(vulnerability_class="sqli", confidence=0.8, summary="s",
                          evidence="e", suggested_test="t", basis="derived",
                          parameter_location="query", parameter_name=param)
        store.persist_findings(exchange, "sqli_agent", [finding])


class TestNoExecutionSurface(unittest.TestCase):
    """Negative control: this adapter must expose NOTHING that starts a scan,
    sends an active probe, or executes anything against a target."""

    def test_no_tool_or_execution_methods_exist(self):
        adapter = ReadOnlyMcpAdapter()
        for banned in ("call_tool", "start_scan", "analyze", "active_probe",
                       "run_active_probe", "investigate", "execute"):
            self.assertFalse(
                hasattr(adapter, banned),
                f"ReadOnlyMcpAdapter must not expose {banned!r} -- it is a read-only surface")

    def test_only_list_and_read_resource_are_public(self):
        adapter = ReadOnlyMcpAdapter()
        public_methods = [m for m in dir(adapter) if not m.startswith("_") and callable(getattr(adapter, m))]
        self.assertEqual(set(public_methods), {"list_resources", "read_resource"})


class TestAuthAndTenantIsolation(_IsolatedDbTest):
    def test_no_tokens_configured_is_open_by_default(self):
        """Matches server.py's own _require_auth default: a loopback
        deployment with no configured bearer token is open."""
        self._persist("a.example.com")
        adapter = ReadOnlyMcpAdapter()
        resources = adapter.list_resources("a.example.com")
        self.assertEqual(len(resources), 3)

    def test_unauthorized_request_is_refused(self):
        adapter = ReadOnlyMcpAdapter(tokens_by_tenant={"tok-a": "a.example.com"})
        with self.assertRaises(McpAuthError):
            adapter.list_resources("a.example.com", token="not-a-real-token")
        with self.assertRaises(McpAuthError):
            adapter.list_resources("a.example.com")  # no token at all

    def test_tenant_a_cannot_read_tenant_b(self):
        """Negative control: a token scoped to tenant A must be refused for
        tenant B's data, even though the token itself is valid."""
        self._persist("a.example.com")
        self._persist("b.example.com")
        adapter = ReadOnlyMcpAdapter(tokens_by_tenant={
            "tok-a": "a.example.com", "tok-b": "b.example.com"})
        # Token A can read its own tenant.
        resources_a = adapter.list_resources("a.example.com", token="tok-a")
        self.assertEqual(len(resources_a), 3)
        # Token A CANNOT read tenant B.
        with self.assertRaises(McpTenantError):
            adapter.list_resources("b.example.com", token="tok-a")
        with self.assertRaises(McpTenantError):
            adapter.read_resource("mcp://harness/b.example.com/issues", token="tok-a")


class TestReadResourceMatchesNormalExport(_IsolatedDbTest):
    def test_issues_resource_matches_export_issues_for_host(self):
        self._persist("a.example.com")
        from harness import report_generator
        expected = report_generator.export_issues_for_host("a.example.com")
        adapter = ReadOnlyMcpAdapter()
        result = adapter.read_resource("mcp://harness/a.example.com/issues")
        self.assertEqual(result["data"], expected)
        self.assertEqual(result["total"], len(expected))

    def test_redaction_hides_secrets(self):
        self._persist("a.example.com", secret_query="SUPERSECRETTOKEN123")
        adapter = ReadOnlyMcpAdapter()
        result = adapter.read_resource("mcp://harness/a.example.com/issues")
        serialized = json.dumps(result)
        self.assertNotIn("SUPERSECRETTOKEN123", serialized)

    def test_pagination_splits_across_pages(self):
        for i in range(3):
            self._persist("a.example.com", param=f"param{i}")
        adapter = ReadOnlyMcpAdapter(page_size=1)
        page0 = adapter.read_resource("mcp://harness/a.example.com/issues", page=0)
        page1 = adapter.read_resource("mcp://harness/a.example.com/issues", page=1)
        self.assertEqual(page0["total"], 3)
        self.assertEqual(len(page0["data"]), 1)
        self.assertEqual(len(page1["data"]), 1)
        self.assertNotEqual(page0["data"][0]["issue_id"], page1["data"][0]["issue_id"])

    def test_coverage_resource_absent_is_honest_none_not_fabricated(self):
        adapter = ReadOnlyMcpAdapter()
        result = adapter.read_resource("mcp://harness/never-scanned.example.com/coverage")
        self.assertIsNone(result["data"])
        self.assertEqual(result["total"], 0)

    def test_provenance_resource_absent_is_honest_none(self):
        with tempfile.TemporaryDirectory() as empty_dir:
            adapter = ReadOnlyMcpAdapter(run_output_dir=empty_dir)
            result = adapter.read_resource("mcp://harness/a.example.com/provenance")
            self.assertIsNone(result["data"])


class TestLatestProvenanceForHost(unittest.TestCase):
    def test_picks_the_most_recent_manifest_for_the_host(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            (out / "run1.json").write_text(json.dumps(
                {"run_id": "run1", "target_identifier": "a.example.com", "started_at": 100}))
            (out / "run2.json").write_text(json.dumps(
                {"run_id": "run2", "target_identifier": "a.example.com", "started_at": 200}))
            (out / "run3.json").write_text(json.dumps(
                {"run_id": "run3", "target_identifier": "other.example.com", "started_at": 300}))
            result = latest_provenance_for_host("a.example.com", out)
            self.assertEqual(result["run_id"], "run2")

    def test_no_matching_manifest_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            result = latest_provenance_for_host("nobody.example.com", d)
            self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
