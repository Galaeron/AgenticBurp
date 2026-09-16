"""
Coordinator fail-open telemetry -- SESSION_4_PLAN.md T4.1.

The coordinator fails open to ALL agents when routing returns nothing or errors.
That is safe for recall but was historically SILENT. These tests prove the
fail-open path is now counted, so a routing layer that has quietly started
firing every agent on every exchange is observable.
"""
import asyncio
import unittest

from harness import coordinator
from harness.coordinator import Coordinator
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult

_EXCHANGE = HttpExchange(
    url="http://localhost/x",
    method="GET",
    request_headers={},
    request_body="",
    response_status=200,
    response_headers={},
    response_body="{}",
)
_AVAILABLE = ["sqli", "xss", "idor"]


class _EmptyRoutingStub:
    """Returns a well-formed but empty dispatch -- the 'no valid targets' path."""
    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data={"dispatch": [], "reason": ""}, prompt_tokens=1, completion_tokens=1)


class _RaisingRoutingStub:
    """Raises -- the 'coordinator error' path."""
    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        raise RuntimeError("boom")


class FailOpenTelemetryTest(unittest.TestCase):
    def setUp(self):
        coordinator.reset_fail_open_stats()

    def test_empty_routing_counts_fail_open(self):
        c = Coordinator(_EmptyRoutingStub(), {"model": "m"})
        dispatch, _reason = asyncio.run(c.choose_agents(_EXCHANGE, list(_AVAILABLE)))
        self.assertEqual(set(dispatch), set(_AVAILABLE), "should fail open to all agents")
        stats = coordinator.fail_open_stats()
        self.assertEqual(stats["count"], 1)
        self.assertIn("local:no-valid-targets", stats["by_reason"])

    def test_routing_error_counts_fail_open(self):
        c = Coordinator(_RaisingRoutingStub(), {"model": "m"})
        dispatch, _reason = asyncio.run(c.choose_agents(_EXCHANGE, list(_AVAILABLE)))
        self.assertEqual(set(dispatch), set(_AVAILABLE), "should fail open to all agents")
        stats = coordinator.fail_open_stats()
        self.assertEqual(stats["count"], 1)
        self.assertTrue(
            any(k.startswith("local:error:") for k in stats["by_reason"]),
            f"expected an error-keyed fail-open reason; got {stats['by_reason']}",
        )


if __name__ == "__main__":
    unittest.main()
