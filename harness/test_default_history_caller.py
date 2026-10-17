"""I02 batch B: default-history continuity through the real analyze() caller.

Owner decision 2026-10-17: by default every analysis of a site shares ONE pile
(the host-wide partition); an explicit engagement_id is an optional named pile
for separation. Within a pile, the captured principal still isolates history.

Two benign analyses run back to back through Orchestrator.analyze with real
persistence and the real prior-findings reader. The model is canned: analysis
A reports a finding carrying a unique marker; every prompt is recorded. The
question is whether analysis B's model input contains A's marker. Passive
configuration only -- the test also asserts that nothing is sent to the target.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
import yaml

from harness import cache, safety_gate, store
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator

_HARNESS = Path(__file__).resolve().parent
_MARKER = "I02B-PRIOR-MARKER-7f3c1a"
_A_URL = "http://shop.invalid/api/orders/1001"
_B_URL = "http://shop.invalid/api/orders/1002"


class _RecordingModel:
    """Canned model: a marker finding for analysis A's URL, nothing else."""

    def __init__(self):
        self.prompts: list[str] = []

    def _reply(self, user_prompt: str) -> dict:
        self.prompts.append(user_prompt)
        if f"\nURL: {_A_URL}\n" in user_prompt:   # analysis A's own exchange
            return {"findings": [{
                "vulnerability_class": "idor", "severity": "low", "confidence": 0.4,
                "summary": f"Order object reachable by id ({_MARKER})",
                "evidence": "benign fixture", "suggested_test": "compare two owners",
                "basis": "assumed"}], "components": []}
        return {"findings": [], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._reply(user_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data=self._reply(user_prompt), prompt_tokens=1, completion_tokens=1)


def _config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = False   # passive: nothing sent
    for k in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    return cfg


def _exchange(url: str, headers: dict | None = None) -> HttpExchange:
    return HttpExchange(url=url, method="GET", request_headers=dict(headers or {}),
                        response_status=200, response_headers={"Content-Type": "application/json"},
                        response_body='{"id": 1, "total": 10}')


class DefaultHistoryCallerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i02b_history_")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        self.sent: list[str] = []

    def tearDown(self):
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, *, a_headers=None, b_headers=None, a_engagement="", b_engagement="",
             extra_patches=()) -> bool:
        """Analyse A then B; return whether B's model input contained A's marker."""
        model = _RecordingModel()
        orch = Orchestrator(_config())
        orch.ollama = model
        for agent in getattr(orch.agent_manager, "agents", {}).values():
            agent.ollama = model
        if getattr(orch, "analysis_pipeline", None) is not None:
            orch.analysis_pipeline.ollama_client = model
        if getattr(orch, "coordinator", None) is not None and hasattr(orch.coordinator, "ollama"):
            orch.coordinator.ollama = model

        real_send = httpx.AsyncClient.send

        async def record_send(client, request, *a, **kw):
            self.sent.append(str(request.url))
            return await real_send(client, request, *a, **kw)

        async def go():
            await orch.analyze(_exchange(_A_URL, a_headers), force_agents=["idor"],
                               engagement_id=a_engagement)
            start = len(model.prompts)
            await orch.analyze(_exchange(_B_URL, b_headers), force_agents=["idor"],
                               engagement_id=b_engagement)
            return any(_MARKER in p for p in model.prompts[start:])

        patches = [patch.object(httpx.AsyncClient, "send", record_send), *extra_patches]
        for p in patches:
            p.start()
        try:
            seen = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        self.assertEqual([u for u in self.sent if "shop.invalid" in u], [],
                         "advisory analysis sent traffic to the target")
        return seen

    def test_default_pile_same_identity_sees_earlier_finding(self):
        self.assertTrue(self._run(), "B's model input lost A's finding in the default pile")

    def test_default_pile_different_identity_does_not_see_it(self):
        self.assertFalse(self._run(b_headers={"Authorization": "Bearer other-user"}))

    def test_named_pile_shared_sees_it(self):
        self.assertTrue(self._run(a_engagement="review-1", b_engagement="review-1"))

    def test_different_named_piles_are_separate(self):
        self.assertFalse(self._run(a_engagement="review-1", b_engagement="review-2"))

    def test_named_pile_is_separate_from_the_default_pile(self):
        self.assertFalse(self._run(a_engagement="review-1", b_engagement=""))

    def test_severed_reader_is_detected(self):
        """Fault injection: without the prior-findings reader the default-pile
        continuity must disappear, so the positive case depends on it."""
        self.assertFalse(self._run(extra_patches=[
            patch("harness.store.prior_findings_summary", return_value="")]))


if __name__ == "__main__":
    unittest.main()
