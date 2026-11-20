"""SEC-1: a -cloud/:cloud model is refused in every slot unless
ollama.allow_cloud_models opts in, before any model call, and the run manifest
records the egress state.

Negative controls: the opt-in path (the same config with
allow_cloud_models: true) reaches the model / the analysis, and a local model
is never refused.
"""
import asyncio
import copy
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from harness import model_egress
from harness.models import HttpExchange
from harness.ollama_client import OllamaClient, OllamaCloudModelRefusedError, backend_options
from harness.run_manifest import RunManifest
from harness.test_ollama_context_window import FakeOllama, _FreshBreaker, _install

_HARNESS = Path(__file__).resolve().parent
CLOUD = "gpt-oss:120b-cloud"


def _default_config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        return yaml.safe_load(f) or {}


def _with(cfg: dict, *, allow=None, **sections) -> dict:
    cfg = copy.deepcopy(cfg)
    for section, values in sections.items():
        cfg.setdefault(section, {}).update(values)
    if allow is not None:
        cfg.setdefault("ollama", {})["allow_cloud_models"] = allow
    return cfg


class DefaultConfigTests(unittest.TestCase):
    def test_default_config_ships_the_refusal_on(self):
        cfg = _default_config()
        self.assertIs(cfg["ollama"]["allow_cloud_models"], False)
        self.assertFalse(model_egress.allow_cloud_models(cfg))

    def test_default_config_is_not_refused(self):
        # The default coordinator.cloud_model is a cloud model but inactive
        # (cloud_primary and cloud_reasoning off): not a slot, not refused.
        state = model_egress.refuse_cloud_models(_default_config())
        self.assertEqual((state["cloud_slots"], state["refused"], state["egress"]), ([], False, False))

    def test_every_slot_is_checked(self):
        cfg = _default_config()
        for section, values in (("coordinator", {"model": CLOUD}),
                                ("coordinator", {"cloud_primary": True}),
                                ("coordinator", {"cloud_reasoning": True}),
                                ("agent_defaults", {"model": CLOUD}),
                                ("critique", {"model": CLOUD}),
                                ("surface_prioritization", {"model": CLOUD}),
                                ("writeups", {"model": CLOUD})):
            with self.subTest(section=section, values=values):
                with self.assertRaises(OllamaCloudModelRefusedError) as ctx:
                    model_egress.refuse_cloud_models(_with(cfg, **{section: values}))
                self.assertTrue(ctx.exception.slots)
                self.assertIn("allow_cloud_models", str(ctx.exception))
        agents = copy.deepcopy(cfg)
        agents.setdefault("agents", {})["sqli"] = {"model": "qwen3:cloud"}
        with self.assertRaises(OllamaCloudModelRefusedError) as ctx:
            model_egress.refuse_cloud_models(agents)
        self.assertEqual(ctx.exception.slots, [{"slot": "agents.sqli.model", "model": "qwen3:cloud"}])
        # A live agent's resolved model is a slot too.
        with self.assertRaises(OllamaCloudModelRefusedError):
            model_egress.refuse_cloud_models(cfg, {"xss": CLOUD})

    def test_a_role_on_another_provider_is_not_an_ollama_slot(self):
        cfg = _with(_default_config(), critique={"model": CLOUD, "provider": "anthropic"})
        state = model_egress.refuse_cloud_models(cfg)
        self.assertFalse(state["refused"])
        self.assertIn("critique", state["remote_providers"])

    def test_opt_in_accepts_and_records_egress(self):
        # NEGATIVE CONTROL for the refusals above: the same slot with the opt-in.
        state = model_egress.refuse_cloud_models(
            _with(_default_config(), allow=True, agent_defaults={"model": CLOUD}))
        self.assertEqual((state["egress"], state["refused"], state["allow_cloud_models"]),
                         (True, False, True))
        self.assertEqual(state["cloud_slots"], [{"slot": "agent_defaults.model", "model": CLOUD}])

    def test_a_quoted_opt_in_is_invalid_not_true(self):
        cfg = _with(_default_config(), allow="true", agent_defaults={"model": CLOUD})
        with self.assertRaises(ValueError):
            model_egress.refuse_cloud_models(cfg)
        with self.assertRaises(ValueError):
            OllamaClient(base_url="http://fake-ollama:11434", **backend_options(cfg["ollama"]))
        state = model_egress.egress_state(cfg)
        self.assertEqual((state["refused"], state.get("allow_cloud_models_invalid")), (True, True))


class ClientGuardTests(_FreshBreaker, unittest.IsolatedAsyncioTestCase):
    """OllamaClient._chat, the chokepoint every model call goes through."""

    async def test_cloud_model_is_refused_unsent(self):
        fake = FakeOllama(prompt_eval_count=10)
        _install(self, fake)
        client = OllamaClient(base_url="http://fake-ollama:11434")
        with self.assertRaises(OllamaCloudModelRefusedError) as ctx:
            await client.chat_json(model=CLOUD, system_prompt="s", user_prompt="u")
        self.assertEqual(fake.paths, [], "nothing is sent to a refused model")
        self.assertFalse(ctx.exception.inference_usage["attempted"])
        snap = client.metrics_snapshot()
        self.assertEqual(snap["client"]["cloud_refused"], 1)
        self.assertIs(snap["backend"]["allow_cloud_models"], False)

    async def test_refusal_does_not_open_the_breaker(self):
        fake = FakeOllama(prompt_eval_count=10)
        _install(self, fake)
        client = OllamaClient(base_url="http://fake-ollama:11434")
        for _ in range(8):
            with self.assertRaises(OllamaCloudModelRefusedError):
                await client.chat_json(model=CLOUD, system_prompt="s", user_prompt="u")
        await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt="u")
        self.assertEqual(fake.count("/api/chat"), 1)

    async def test_opt_in_sends(self):
        # NEGATIVE CONTROL: the same call with the opt-in is sent.
        fake = FakeOllama(prompt_eval_count=10)
        _install(self, fake)
        client = OllamaClient(base_url="http://fake-ollama:11434", allow_cloud_models=True)
        await client.chat_json(model=CLOUD, system_prompt="s", user_prompt="u")
        self.assertEqual(fake.count("/api/chat"), 1)
        self.assertEqual(client.model_cloud_refused_count, 0)

    async def test_local_model_is_never_refused(self):
        fake = FakeOllama(prompt_eval_count=10)
        _install(self, fake)
        client = OllamaClient(base_url="http://fake-ollama:11434")
        await client.chat_json(model="qwen3:8b", system_prompt="s", user_prompt="u")
        self.assertEqual(fake.count("/api/chat"), 1)


class RunStartRefusalTests(_FreshBreaker, unittest.TestCase):
    """The orchestrator entry points refuse a run with a cloud slot before its
    first model call (caller level)."""

    @classmethod
    def setUpClass(cls):
        import os
        from harness import cache, store
        cls._tmp = tempfile.mkdtemp(prefix="model_egress_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        from harness import cache, store
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _orchestrator(self, *, allow):
        from harness import test_smoke_investigate as smoke
        from harness.orchestrator import Orchestrator
        fake = FakeOllama(prompt_eval_count=10)
        _install(self, fake)
        cfg = smoke._test_config()
        cfg["agent_defaults"]["model"] = CLOUD
        if allow:
            cfg["ollama"]["allow_cloud_models"] = True
        return Orchestrator(cfg), fake

    def _exchange(self):
        return HttpExchange(url="http://localhost/api/items?id=1", method="GET",
                            response_status=200, response_body='{"id": 1}')

    def test_analyze_is_refused_before_any_model_call(self):
        orch, fake = self._orchestrator(allow=False)
        inner = AsyncMock(side_effect=AssertionError("the analysis must not start"))
        with patch.object(orch, "_analyze_inner", inner),                 self.assertLogs("harness.model_egress", "WARNING") as logs:
            with self.assertRaises(OllamaCloudModelRefusedError) as ctx:
                asyncio.run(orch.analyze(self._exchange()))
        # Review fix: /analyze withholds exception text, so the operator-facing
        # reason (with the slot) is logged where the run is refused.
        self.assertTrue(any("agent_defaults.model" in line for line in logs.output), logs.output)
        self.assertEqual(fake.paths, [], "no request reaches the model server")
        self.assertEqual(orch.ollama.model_cloud_refused_count, 0,
                         "refused at run start, not call by call")
        inner.assert_not_called()
        self.assertIn("agent_defaults.model", str(ctx.exception))

    def test_analyze_with_opt_in_starts(self):
        # NEGATIVE CONTROL: the opt-in lets the same analysis start.
        orch, _fake = self._orchestrator(allow=True)
        inner = AsyncMock(return_value="analysed")
        with patch.object(orch, "_analyze_inner", inner):
            self.assertEqual(asyncio.run(orch.analyze(self._exchange())), "analysed")
        inner.assert_called_once()

    def test_investigate_engagement_is_refused_before_discovery_or_model_call(self):
        from harness import test_smoke_investigate as smoke
        orch, fake = self._orchestrator(allow=False)
        build = AsyncMock(side_effect=AssertionError("discovery must not start"))
        with patch("harness.engagement_builder.build_engagement", build):
            with self.assertRaises(OllamaCloudModelRefusedError):
                asyncio.run(orch.investigate_engagement(
                    smoke.BASE_URL, smoke.ROLES, max_nodes=1, step_budget=1, max_chain_rounds=0))
        self.assertEqual(fake.paths, [])
        build.assert_not_called()


class ServerRefusalTests(_FreshBreaker, unittest.TestCase):
    """SEC-1 at the API: the default config with a cloud model in a slot gets
    409 with the refusal reason from /analyze and /engagement/{host}/investigate,
    never a generic 500, and no request reaches the model server."""

    def setUp(self):
        super().setUp()
        import importlib
        from fastapi.testclient import TestClient
        from harness import store
        import harness.server as server_module
        tmp = tempfile.mkdtemp(prefix="model_egress_server_")
        self.addCleanup(shutil.rmtree, tmp, True)
        self.addCleanup(setattr, store, "_DB_PATH", store._DB_PATH)
        store._DB_PATH = Path(tmp) / "state.db"
        importlib.reload(server_module)
        self.server = server_module
        server_module.config["runs"] = {"output_dir": tmp, "cache_namespace": "test-isolated"}
        server_module.orchestrator.allowed_hosts = ["shop.test"]
        self.fake = FakeOllama(prompt_eval_count=10)
        _install(self, self.fake)
        self.client = TestClient(server_module.app, base_url="http://localhost",
                                 headers={"Authorization": f"Bearer {server_module._mutation_token()}"})
        self.assertFalse(server_module.orchestrator.config["ollama"].get("allow_cloud_models"),
                         "the shipped default refuses cloud models")

    def _cloud_slot(self):
        return patch.dict(self.server.orchestrator.config["agent_defaults"], {"model": CLOUD})

    def _arm_active(self):
        # /engagement/{host}/investigate sends target traffic, so ARC-1 admission
        # (403 while validators.active_enabled is off) runs before the SEC-1 check.
        # Arm it so these tests reach the cloud-slot refusal they exercise.
        registry = self.server.orchestrator.validator_registry
        self.addCleanup(registry.set_active_enabled, registry.active_enabled)
        registry.set_active_enabled(True)

    def _assert_refused(self, resp):
        self.assertEqual(resp.status_code, 409, resp.text)
        detail = resp.json()["detail"]
        self.assertIn("agent_defaults.model", detail)
        self.assertIn(CLOUD, detail)
        self.assertEqual(self.fake.paths, [], "no request reaches the model server")

    def test_analyze_cloud_slot_is_409_with_the_reason(self):
        # Negative control: before this mapping the route returned 500 with
        # only the exception type name.
        orch = self.server.orchestrator
        inner = AsyncMock(side_effect=AssertionError("the analysis must not start"))
        exchange = HttpExchange(url="http://shop.test/api/items?id=1", method="GET",
                                response_status=200, response_body='{"id": 1}')
        with self._cloud_slot(), patch.object(orch, "_analyze_inner", inner):
            resp = self.client.post("/analyze", json={"exchange": exchange.model_dump()})
        self._assert_refused(resp)
        inner.assert_not_called()

    def test_investigate_cloud_slot_is_409_before_a_job_exists(self):
        orch = self.server.orchestrator
        run = AsyncMock(return_value={"summary": {}})
        body = {"base_url": "http://shop.test:5002", "roles": []}
        self._arm_active()
        with self._cloud_slot(), patch.object(orch, "investigate_engagement", run):
            resp = self.client.post("/engagement/shop.test/investigate", json=body)
        self._assert_refused(resp)
        run.assert_not_called()
        self.assertEqual(self.client.get("/engagement/shop.test/investigate").json().get("jobs", []), [])

    def test_control_local_slots_are_admitted(self):
        # Control: without a cloud slot the same request is admitted (200).
        run = AsyncMock(return_value={"summary": {}})
        self._arm_active()
        with patch.object(self.server.orchestrator, "investigate_engagement", run):
            resp = self.client.post("/engagement/shop.test/investigate",
                                    json={"base_url": "http://shop.test:5002", "roles": []})
        self.assertEqual(resp.status_code, 200, resp.text)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="model_egress_manifest_")
        self.addCleanup(shutil.rmtree, self._tmp, True)

    def _start(self, cfg, agents=None):
        return RunManifest.start(run_id="r1", target_identifier="t", config=cfg,
                                 output_dir=self._tmp,
                                 model_versions={"agents": agents or []})

    def test_opt_in_run_records_egress(self):
        cfg = _with(_default_config(), allow=True, critique={"model": CLOUD})
        egress = self._start(cfg, ["qwen3:8b"]).data["model_egress"]
        self.assertEqual((egress["egress"], egress["allow_cloud_models"], egress["refused"]),
                         (True, True, False))
        self.assertEqual(egress["cloud_slots"], [{"slot": "critique.model", "model": CLOUD}])

    def test_local_run_records_no_egress(self):
        # NEGATIVE CONTROL.
        egress = self._start(_default_config(), ["qwen3:8b"]).data["model_egress"]
        self.assertEqual((egress["egress"], egress["cloud_slots"], egress["allow_cloud_models"]),
                         (False, [], False))

    def test_resolved_agent_model_list_is_a_slot(self):
        egress = self._start(_with(_default_config(), allow=True), [CLOUD]).data["model_egress"]
        self.assertEqual(egress["cloud_slots"], [{"slot": "agent:resolved[0]", "model": CLOUD}])


if __name__ == "__main__":
    unittest.main()
