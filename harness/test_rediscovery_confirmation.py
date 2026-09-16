"""W-7/W-24: _attempt_rediscovery's prompt literally says "ALREADY CONFIRMED",
which makes a model echoing "confirmed": true into its own JSON output more
likely, not less. That must never become a persisted, proof-less
confirmation -- only the deterministic validator pipeline
(orchestrator_confirm.py) may set confirmed=True, always alongside a linked
proof_id/case_id.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock

from harness.models import Finding, HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator


def _config():
    return {
        "ollama": {"base_url": "http://localhost:11434"},
        "coordinator": {"model": "llama3.1:8b"},
        "agent_defaults": {"model": "gemma2:9b"},
        "agents": {},
        "server": {"allowed_hosts": []},
    }


class RediscoveryConfirmationTests(unittest.TestCase):
    def test_llm_supplied_confirmed_true_is_stripped(self):
        orchestrator = Orchestrator(_config())
        orchestrator.ollama.chat_json_metered = AsyncMock(return_value=OllamaResult(
            data={"findings": [{
                "vulnerability_class": "sqli",
                "confidence": 0.9,
                "summary": "self-reported as confirmed by the model",
                "evidence": "e",
                "suggested_test": "t",
                "basis": "derived",
                "confirmed": True,
                "proof_id": "model-supplied-id",
                "case_id": "model-supplied-case",
            }]},
            prompt_tokens=10, completion_tokens=10,
        ))
        exchange = HttpExchange(url="https://a.test/x", method="GET")
        known = [Finding(vulnerability_class="sqli", confidence=0.5, summary="prior",
                          evidence="e", suggested_test="t", basis="derived")]

        report = asyncio.run(orchestrator._attempt_rediscovery(exchange, known))

        self.assertIsNotNone(report)
        self.assertEqual(len(report.findings), 1)
        f = report.findings[0]
        self.assertFalse(f.confirmed, "rediscovery must discard an LLM's self-reported 'confirmed'")
        self.assertEqual(f.proof_id, "", "rediscovery must discard an LLM's self-reported 'proof_id' (R02)")
        self.assertEqual(f.case_id, "", "rediscovery must discard an LLM's self-reported 'case_id' (R02)")


if __name__ == "__main__":
    unittest.main()
