import copy
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from harness.runtime_provenance import describe
from harness.source_identity import SourceSnapshot


class RuntimeProvenanceTests(unittest.TestCase):
    def test_runtime_controls_and_hash_change_without_secret_disclosure(self):
        config = {"server": {"auth_token": "synthetic-private"},
                  "validators": {"active_enabled": False, "allow_mutating_replay": False},
                  "critique": {"temperature": 0},
                  "agents": {"idor": {"custom_prompt": "synthetic-private-prompt"}}}
        original = copy.deepcopy(config)
        orch = NS(validator_registry=NS(active_enabled=True), allowed_hosts=["test.invalid"],
                  ollama=NS(seed=0), coordinator_model="m", coordinator=NS(temperature=0, seed=None),
                  agent_manager=NS(agents={"idor": NS(model="m", temperature=0)}))
        snapshot = SourceSnapshot(content_id="sha256:source", head="commit", status="captured")
        with patch("harness.runtime_provenance.capture_source_snapshot", return_value=snapshot):
            first = describe(config, orch, snapshot)
            orch.ollama.seed = 1
            second = describe(config, orch, snapshot)
            config["agents"]["idor"]["custom_prompt"] = "changed"
            third = describe(config, orch, snapshot)
            config["agents"]["idor"]["custom_prompt"] = "synthetic-private-prompt"
        self.assertNotEqual(first["config_hash"], second["config_hash"])
        self.assertNotEqual(second["config_hash"], third["config_hash"])
        self.assertEqual(first["controls"]["ollama"]["seed"], 0)
        self.assertTrue(first["controls"]["validators"]["active_enabled"])
        self.assertNotIn("synthetic-private", str(first))
        self.assertEqual(config, original)

    def test_route_requires_auth_and_returns_server_identity(self):
        # Load the production routes with an inert orchestrator. Keep this
        # fixture independent of optional/uncommitted test modules.
        import importlib.util
        import io
        from pathlib import Path
        import sys
        from fastapi.testclient import TestClient

        original_open = open
        def synthetic_config(file, *args, **kwargs):
            if Path(file).name in {"config.yaml", "config.local.yaml"}:
                return io.StringIO('server:\n  auth_token: synthetic-provenance-token\n  require_read_auth: true\n')
            return original_open(file, *args, **kwargs)

        name = "harness._provenance_test_server"
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name("server.py"))
        server = importlib.util.module_from_spec(spec)
        sys.modules[name] = server
        self.addCleanup(lambda: sys.modules.pop(name, None))
        with patch("builtins.open", side_effect=synthetic_config), \
                patch("harness.orchestrator.Orchestrator", return_value=NS()):
            spec.loader.exec_module(server)
        client = TestClient(server.app, base_url="http://localhost")
        self.addCleanup(client.close)
        with patch("harness.runtime_provenance.describe", return_value={"server": "identity"}) as describe_mock:
            self.assertEqual(client.get("/run-provenance").status_code, 401)
            describe_mock.assert_not_called()
            response = client.get("/run-provenance", headers={"Authorization": "Bearer synthetic-provenance-token"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"server": "identity"})
