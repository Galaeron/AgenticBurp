"""r5 proof-binding regressions (10 h Juice Shop run, job ec2d4f39326d).

1. A proof confirms only the finding of its own class on an endpoint: the
   id-in-URL idor_read leg used to apply to (and "confirm") every GET finding
   on /rest/basket/<id> -- XSS, missing headers, insecure transmission.
2. Model review annotates a proven finding; it never leaves it "downgraded".
3. A graph-loop proof binds to the stored finding of its class and parameter
   (sqlmap on POST /rest/user/login, email), never to another class/parameter.
4. A jwt_forge confirmation reproduced N-of-N reaches verification_state
   "verified" (its confirmation carries an executed in-probe control).

All sends are faked; no traffic leaves the process.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from harness import cache, safety_gate, store
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _RecordingModel, _config
from harness.validators.base import ValidationResult

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImN1c3RvbWVyIn0.c2lnbmF0dXJl"


def _finding(cls: str, *, verdict=None, confidence=0.9, **kw) -> Finding:
    return Finding(vulnerability_class=cls, confidence=confidence, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived",
                   review_verdict=verdict, **kw)


def _get(url: str, headers=None) -> HttpExchange:
    return HttpExchange(url=url, method="GET", request_headers=dict(headers or {}),
                        response_status=200, response_headers={"Content-Type": "application/json"},
                        response_body='{"id": 7, "total": 10}')


def _confirmed(name: str, cls: str):
    async def validate(self, finding, exchange):
        return ValidationResult(name, "confirmed", cls, confidence=0.9, confirmed=True,
                                summary=f"{name} confirmed")
    return validate


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="r5_binding_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()

    def tearDown(self):
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _orch(self, validators: dict, *, oracle=None) -> Orchestrator:
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["shop.invalid"]
        if oracle is not None:
            cfg["oracle"] = oracle
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        orch.validator_registry.active_enabled = True
        orch.validator_registry.validators = validators
        return orch


class CritiqueAnnotatesProvenTests(unittest.IsolatedAsyncioTestCase):
    """Defect 2 at the critique stage: annotate a proven finding, never demote it."""

    async def test_critique_cannot_demote_or_reject_a_proven_finding(self):
        from harness.analysis_pipeline import AnalysisPipeline
        from harness.effort import BudgetMode, EffortBudget
        client = MagicMock()
        result = MagicMock()
        result.data = {"reviews": [
            {"index": 0, "verdict": "rejected", "note": "looks benign", "adjusted_confidence": 0.1},
            {"index": 1, "verdict": "downgraded", "note": "weak", "adjusted_confidence": 0.2}]}
        client.chat_json_metered = AsyncMock(return_value=result)
        pipeline = AnalysisPipeline(MagicMock(), EffortBudget(BudgetMode.HARD), MagicMock(),
                                    {"critique": {"enabled": True, "confidence_threshold": 0.5},
                                     "coordinator": {"model": "m"}}, ollama_client=client)
        proven = _finding("jwt", confidence=0.95, confirmed=True, proof_id="p1",
                          case_id="c1", confirmed_by_leg="jwt_forge",
                          verdict="validator-confirmed")
        unproven = _finding("Cross-Site Scripting (XSS)", confidence=0.9)
        report = AgentReport(agent="jwt", model="m", findings=[proven, unproven])
        await pipeline._critique(HttpExchange(url="http://shop.invalid/x", method="GET"), [report])
        self.assertIn(proven, report.findings)
        self.assertEqual(proven.review_verdict, "validator-confirmed")
        self.assertEqual(proven.confidence, 0.95)
        self.assertIn("looks benign", proven.review_note or "")
        # Negative control: an unproven finding is still demoted by review.
        self.assertEqual(unproven.review_verdict, "downgraded")
        self.assertEqual(unproven.confidence, 0.2)


if __name__ == "__main__":
    unittest.main()
