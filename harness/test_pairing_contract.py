"""Benign HTTP caller controls for R02; no provider or target network calls.

The endpoint boundary uses a fake passive orchestrator and real temporary
SQLite persistence. This is not Java integration or inference validation.
The separate Java caller tests require a real JDK/Gradle execution.
"""
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient
from harness import store
from harness.models import AnalysisResponse, Finding


class FakePassiveOrchestrator:
    def __init__(self, config, **kwargs):
        self.calls = 0
        self.coordinator_model = "synthetic-provider"
        self.agent_manager = SimpleNamespace(get_enabled_agents=lambda: ["synthetic-passive"], agents={})
        async def synthetic_health():
            return {"reachable": True, "models": [self.coordinator_model], "error": None}
        self.ollama = SimpleNamespace(base_url="http://synthetic.invalid", health_check=synthetic_health)
        self.effort_budget = SimpleNamespace(ledger=None)

    async def analyze(self, exchange, force_agents, attempt_rediscovery, engagement_id=""):
        self.calls += 1
        store.persist_findings(exchange, "synthetic-passive", [Finding(
            vulnerability_class="passive_observation", confidence=0.7,
            summary="Benign captured response observation", severity="info",
            evidence="Ordinary captured text", suggested_test="", basis="derived")], engagement_id=engagement_id)
        return AnalysisResponse(coordinator_model=self.coordinator_model, engagement_id=engagement_id,
                                dispatched_agents=["synthetic-passive"],
                                agent_reports=[], summary="Benign passive analysis completed")


class PairingCallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db_patch = patch.object(store, "_DB_PATH", Path(self.tmp.name) / "synthetic.db")
        db_patch.start()
        self.addCleanup(db_patch.stop)
        config = {"server": {"host": "127.0.0.1", "auth_token": "synthetic-r02-token",
                             "require_read_auth": True}}
        original_open = open

        def synthetic_config(file, *args, **kwargs):
            if Path(file).name in {"config.yaml", "config.local.yaml"}:
                return io.StringIO(yaml.safe_dump(config))
            return original_open(file, *args, **kwargs)

        # Avoid constructing providers, using local overrides, or writing the
        # live ephemeral-token lockfile when loading the real route module.
        name = "harness._r02_test_server"
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name("server.py"))
        self.server = importlib.util.module_from_spec(spec)
        sys.modules[name] = self.server
        self.addCleanup(lambda: sys.modules.pop(name, None))
        with patch("builtins.open", side_effect=synthetic_config), \
                patch("harness.orchestrator.Orchestrator", FakePassiveOrchestrator):
            spec.loader.exec_module(self.server)
        self.client = TestClient(self.server.app, base_url="http://localhost")
        self.addCleanup(self.client.close)
        self.auth = {"Authorization": "Bearer synthetic-r02-token"}
        self.request = {"exchange": {"url": "https://captured.example/ordinary",
                                    "method": "GET", "response_status": 200,
                                    "response_body": "Ordinary captured text"}}

    def test_health_is_liveness_and_pairing_requires_credential(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        for headers in ({}, {"Authorization": "Bearer synthetic-wrong-token"}):
            with self.subTest(headers_present=bool(headers)):
                denied = self.client.get("/pairing/check", headers=headers)
                self.assertEqual(denied.status_code, 401)
                self.assertNotIn("synthetic-r02-token", denied.text)
        paired = self.client.get("/pairing/check", headers=self.auth)
        self.assertEqual(paired.status_code, 200)
        self.assertEqual(paired.json(), {"status": "authenticated"})
        self.assertEqual(self.server.orchestrator.calls, 0)

    def test_authenticated_analyze_persists_and_authenticated_report_reads(self):
        accepted = self.client.post("/analyze", json=self.request, headers=self.auth)
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(self.server.orchestrator.calls, 1)
        engagement_id = accepted.json()["engagement_id"]
        self.assertEqual(engagement_id, "", "unnamed analysis uses shared site history")
        stored = store.all_host_findings(self.request["exchange"]["url"], engagement_id=engagement_id)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["summary"], "Benign captured response observation")
        denied = self.client.get("/report", params={"url": self.request["exchange"]["url"]})
        self.assertEqual(denied.status_code, 401)
        report = self.client.get("/report", params={"url": self.request["exchange"]["url"], "engagement_id": engagement_id},
                                 headers=self.auth)
        self.assertEqual(report.status_code, 200)
        self.assertIn("Benign captured response observation", report.text)

    def test_missing_wrong_or_rotated_token_never_reaches_analyze(self):
        for headers in ({}, {"Authorization": "Bearer synthetic-wrong-token"}):
            self.assertEqual(self.client.post("/analyze", json=self.request,
                                              headers=headers).status_code, 401)
        self.server._BEARER_TOKEN = "synthetic-restarted-token"
        self.assertEqual(self.client.get("/pairing/check", headers=self.auth).status_code, 401)
        self.assertEqual(self.client.post("/analyze", json=self.request,
                                          headers=self.auth).status_code, 401)
        self.assertEqual(self.server.orchestrator.calls, 0)
        self.assertEqual(store.all_host_findings(self.request["exchange"]["url"]), [])
        reconnect = {"Authorization": "Bearer synthetic-restarted-token"}
        self.assertEqual(self.client.get("/pairing/check", headers=reconnect).status_code, 200)

    def test_ephemeral_effective_token_also_pairs(self):
        self.server._BEARER_TOKEN = None
        self.server._EPHEMERAL_TOKEN = "synthetic-ephemeral-token"
        self.assertEqual(self.client.get("/pairing/check", headers=self.auth).status_code, 401)
        accepted = self.client.get("/pairing/check", headers={
            "Authorization": "Bearer synthetic-ephemeral-token"})
        self.assertEqual(accepted.status_code, 200)

    def test_browser_cross_site_rejected_even_with_valid_credential(self):
        headers = {**self.auth, "Sec-Fetch-Site": "cross-site"}
        self.assertEqual(self.client.get("/pairing/check", headers=headers).status_code, 403)
        self.assertEqual(self.client.post("/analyze", json=self.request,
                                          headers=headers).status_code, 403)
        self.assertEqual(self.server.orchestrator.calls, 0)


if __name__ == "__main__":
    unittest.main()
