"""Tests for model listing/selection (cloud-31B-as-agent + UI dropdowns)."""
import asyncio
import unittest
from unittest.mock import patch

from ollama_client import OllamaClient


class ListModelsClientTests(unittest.TestCase):
    def _list(self, *, json_data=None, raise_exc=None, status=200):
        client = OllamaClient(base_url="http://ollama.test")

        class _Resp:
            def __init__(self):
                self.status_code = status
            def raise_for_status(self):
                if status >= 400:
                    import httpx
                    raise httpx.HTTPStatusError("bad", request=None, response=None)
            def json(self):
                return json_data

        async def fake_get(self, url, **kw):
            if raise_exc is not None:
                raise raise_exc
            return _Resp()

        with patch("httpx.AsyncClient.get", fake_get):
            return asyncio.run(client.list_models())

    def test_parses_and_sorts_tag_names(self):
        data = {"models": [{"name": "qwen3:8b"}, {"name": "gemma2:9b"}, {"name": "qwen3:8b"}]}
        self.assertEqual(self._list(json_data=data), ["gemma2:9b", "qwen3:8b"])

    def test_unreachable_returns_empty(self):
        import httpx
        self.assertEqual(self._list(raise_exc=httpx.ConnectError("no")), [])

    def test_malformed_returns_empty(self):
        self.assertEqual(self._list(json_data=["not", "a", "dict"]), [])


class OrchestratorModelSelectionTests(unittest.TestCase):
    """Uses the server module's real orchestrator (built once), no network."""

    @classmethod
    def setUpClass(cls):
        import server as server_module
        cls.orch = server_module.orchestrator

    def test_set_coordinator_model(self):
        original = self.orch.coordinator_model
        try:
            out = self.orch.set_coordinator_model("gemma4:31b-cloud")
            self.assertEqual(out["coordinator_model"], "gemma4:31b-cloud")
            self.assertEqual(self.orch.coordinator.model, "gemma4:31b-cloud")
        finally:
            self.orch.set_coordinator_model(original)

    def test_set_all_agents_model(self):
        originals = {n: a.model for n, a in self.orch.agent_manager.agents.items()}
        try:
            out = self.orch.set_agents_model("gemma4:31b-cloud")
            self.assertEqual(len(out["agents_changed"]), len(originals))
            self.assertTrue(all(a.model == "gemma4:31b-cloud"
                                for a in self.orch.agent_manager.agents.values()))
        finally:
            for n, m in originals.items():
                self.orch.agent_manager.agents[n].model = m

    def test_set_single_agent_model(self):
        name = next(iter(self.orch.agent_manager.agents))
        original = self.orch.agent_manager.agents[name].model
        try:
            self.orch.set_agents_model("gemma4:31b-cloud", agent=name)
            self.assertEqual(self.orch.agent_manager.agents[name].model, "gemma4:31b-cloud")
        finally:
            self.orch.agent_manager.agents[name].model = original

    def test_unknown_agent_raises(self):
        with self.assertRaises(ValueError):
            self.orch.set_agents_model("m", agent="no_such_agent")

    def test_empty_model_raises(self):
        with self.assertRaises(ValueError):
            self.orch.set_coordinator_model("")


class ModelEndpointTests(unittest.TestCase):
    def setUp(self):
        import server as server_module
        self.server_module = server_module
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def test_get_models_merges_cloud(self):
        from unittest.mock import AsyncMock, patch
        with patch.object(self.server_module.orchestrator.ollama, "list_models",
                          AsyncMock(return_value=["qwen3:8b"])):
            resp = self.client.get("/models")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("qwen3:8b", body["local"])
        self.assertIn("gemma4:31b-cloud", body["cloud"])  # from config, not tags
        self.assertIn("gemma4:31b-cloud", body["all"])

    def test_select_nothing_is_400(self):
        resp = self.client.post("/models/select", json={})
        self.assertEqual(resp.status_code, 400)

    def test_select_coordinator(self):
        orig = self.server_module.orchestrator.coordinator_model
        try:
            resp = self.client.post("/models/select", json={"coordinator": "gemma4:31b-cloud"})
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["coordinator_model"], "gemma4:31b-cloud")
        finally:
            self.server_module.orchestrator.set_coordinator_model(orig)

    def test_get_settings(self):
        r = self.client.get("/settings")
        self.assertEqual(r.status_code, 200)
        self.assertIn("throttle", r.json())
        self.assertIn("retry_budget", r.json())

    def test_update_settings_throttle_and_retry(self):
        import global_throttle
        orig_policy = self.server_module.orchestrator.retry_budget_policy
        try:
            r = self.client.post("/settings", json={"throttle_rps": 5.0,
                                                    "retry_budget": {"max_retries": 7}})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(self.server_module.orchestrator.retry_budget_policy.max_retries, 7)
            self.assertTrue(global_throttle.throttle.enabled)
        finally:
            self.server_module.orchestrator.retry_budget_policy = orig_policy
            global_throttle.configure(0)

    def test_update_settings_empty_is_400(self):
        self.assertEqual(self.client.post("/settings", json={}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
