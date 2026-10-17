"""Caller-level regression proving `investigate_engagement` reaches the
objective-completion stage (harness/objective_completion.py) only when a
caller supplies an explicit `objective_task`, strictly after deterministic
confirmation -- and never otherwise. Same harness pattern as
test_deterministic_first.py, extended with an SSTI objective."""
from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from harness import engagement_builder, role_crawl, worklist_investigator
from harness import objective_completion as objective_completion_mod
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.objective_completion import CompletionResult, COMPLETED
from harness.objective_profiles import ObjectiveTask, SSTI_FILE_DELETE
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.validators.base import ValidationResult
from harness.validators.ssti_validator import SstiValidator


_HARNESS = Path(__file__).resolve().parent
BASE = "http://shop.test/"
CAPTURE = HttpExchange(
    method="GET",
    url=f"{BASE}render?message=hello",
    request_headers={},
    response_status=200,
    response_headers={"Content-Type": "text/html"},
    response_body="hello",
)


def _config() -> dict:
    cfg = yaml.safe_load((_HARNESS / "config.yaml").read_text(encoding="utf-8")) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = True
    cfg["validators"]["allow_mutating_replay"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    eng = cfg.setdefault("engagement", {})
    eng["auto_escalate"] = False
    eng["feature_crawl"] = False
    eng["coverage_drive_legs"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["shop.test"]
    return cfg


async def _build(base_url, roles, **kwargs):
    state = EngagementState(host="shop.test")
    state._ep("GET", "/render")
    rc = role_crawl.RoleCrawlResult(base_url=base_url)
    rc.captured.append(CAPTURE)
    return state, rc


class ObjectiveCompletionWiringTest(unittest.TestCase):
    def _run(self, *, objective_task=None, validator_confirms: bool = True,
             completion_side_effect=None):
        async def review(*args, **kwargs):
            return 0

        confirmed = ValidationResult(
            validator="ssti", status="confirmed" if validator_confirms else "not_confirmed",
            finding_class="ssti", confidence=0.95, confirmed=validator_confirms,
            summary="arithmetic canary evaluated", evidence="8633 appeared between nonces",
        )
        completion_calls: list = []

        async def _fake_completion(task, finding, exchange, confirmation, **kw):
            completion_calls.append((task, finding, exchange, confirmation, kw))
            if completion_side_effect:
                return completion_side_effect
            return CompletionResult(COMPLETED, action_class="file_delete",
                                    summary="deleted", requests_used=2)

        orch = Orchestrator(_config())
        orch.allowed_hosts = ["shop.test"]
        with patch.object(engagement_builder, "build_engagement", new=_build), \
             patch.object(worklist_investigator, "investigate_worklist",
                          new=AsyncMock(return_value=[])), \
             patch("harness.orchestrator_chain.review_captured_exchanges", new=review), \
             patch("harness.orchestrator_chain.universal_header_audit",
                   new=AsyncMock(return_value=0)), \
             patch.object(SstiValidator, "validate", new=AsyncMock(return_value=confirmed)), \
             patch.object(objective_completion_mod, "attempt_completion",
                          new=_fake_completion), \
             patch.object(orch, "_persist_confirmation_proof",
                          new=AsyncMock(return_value=(False, None, "test"))):
            result = asyncio.run(orch.investigate_engagement(
                BASE, [RoleSession("anonymous", {})], max_nodes=1,
                max_chain_rounds=0, discovery_max_probes=1,
                stop_on_confirm=True, objective_class="ssti",
                objective_task=objective_task))
        return result, completion_calls

    def test_declared_task_invokes_completion_after_confirmation(self):
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt",
                             oracle_url="http://shop.test/status?file=/tmp/disposable.txt")
        result, calls = self._run(objective_task=task)
        self.assertEqual(len(calls), 1)
        # Completion only ever receives an already-CONFIRMED result.
        self.assertTrue(calls[0][3].confirmed)
        entry = result["outcomes"][0]["objective_completion"]
        self.assertEqual(entry["status"], COMPLETED)
        self.assertEqual(entry["action_class"], "file_delete")

    def test_no_task_never_calls_completion(self):
        # Regression for the existing SSTI record: arithmetic-only confirmation
        # with no declared objective must not invoke completion at all, and
        # the outcome must carry no objective_completion entry.
        result, calls = self._run(objective_task=None)
        self.assertEqual(calls, [])
        self.assertNotIn("objective_completion", result["outcomes"][0])
        self.assertTrue(result["stopped_on_confirmation"])

    def test_unconfirmed_finding_never_reaches_completion(self):
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt")
        result, calls = self._run(objective_task=task, validator_confirms=False)
        self.assertEqual(calls, [])
        self.assertFalse(result["stopped_on_confirmation"])

    def test_completion_failure_never_downgrades_confirmation(self):
        task = ObjectiveTask(profile=SSTI_FILE_DELETE, target_path="/tmp/disposable.txt")

        async def _boom(*a, **kw):
            raise RuntimeError("transport exploded")

        with patch.object(objective_completion_mod, "attempt_completion", new=_boom):
            result, _ = self._run_with_patched_completion(task, _boom)
        findings = result["outcomes"][0]["findings_detail"]
        self.assertTrue(findings[0]["confirmed"])
        self.assertEqual(result["outcomes"][0]["objective_completion"]["status"], "error")

    def _run_with_patched_completion(self, task, fake):
        confirmed = ValidationResult(
            validator="ssti", status="confirmed", finding_class="ssti", confidence=0.95,
            confirmed=True, summary="arithmetic canary evaluated")

        async def review(*args, **kwargs):
            return 0

        orch = Orchestrator(_config())
        orch.allowed_hosts = ["shop.test"]
        with patch.object(engagement_builder, "build_engagement", new=_build), \
             patch.object(worklist_investigator, "investigate_worklist",
                          new=AsyncMock(return_value=[])), \
             patch("harness.orchestrator_chain.review_captured_exchanges", new=review), \
             patch("harness.orchestrator_chain.universal_header_audit",
                   new=AsyncMock(return_value=0)), \
             patch.object(SstiValidator, "validate", new=AsyncMock(return_value=confirmed)), \
             patch.object(objective_completion_mod, "attempt_completion", new=fake), \
             patch.object(orch, "_persist_confirmation_proof",
                          new=AsyncMock(return_value=(False, None, "test"))):
            result = asyncio.run(orch.investigate_engagement(
                BASE, [RoleSession("anonymous", {})], max_nodes=1,
                max_chain_rounds=0, discovery_max_probes=1,
                stop_on_confirm=True, objective_class="ssti",
                objective_task=task))
        return result, None


if __name__ == "__main__":
    unittest.main()
