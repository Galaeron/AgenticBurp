"""Contract tests for testing_fixtures.sent_probe (review 2026-10).

The sent-count hardening across the leg tests depends on two subtle properties,
so they are pinned here rather than left implicit in every caller:

1. CountingResponder must behave as a drop-in for the plain async function the
   tests patch onto httpx.AsyncClient.request -- i.e. attribute access on the
   class must bind the client as the first positional arg (descriptor protocol).
2. The counter must sit BELOW the gate: a send the gate REFUSES must leave the
   count at 0, so a seeded scope can never make a leg pass having sent nothing.
"""
import asyncio
import unittest
from unittest.mock import patch

from harness.safety_gate import (
    SafetyGate, SafetyGateConfig, GatedAsyncClient, SafetyGateBlocked,
)
from harness.testing_fixtures.sent_probe import CountingResponder, seed_gate_scope


class _Resp:
    status_code = 200
    text = "ok"
    headers: dict = {}


async def _responder(client, method, url, content=None, headers=None, **kw):
    return _Resp()


class CountingResponderContract(unittest.TestCase):
    def tearDown(self):
        from harness import safety_gate
        safety_gate.reset_default_gate()

    def test_binds_client_and_counts_allowed_send(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True,
                                           allowed_hosts={"t.test"}))
        responder = CountingResponder(_responder)

        async def scenario():
            async with GatedAsyncClient(gate, "v") as client:
                return await client.request("POST", "http://t.test/x")

        with patch("httpx.AsyncClient.request", responder):
            resp = asyncio.run(scenario())
        self.assertEqual(resp.status_code, 200)   # proves the client bound and the call went through
        self.assertEqual(responder.count, 1)
        self.assertEqual(responder.calls, [("POST", "http://t.test/x")])

    def test_refused_send_leaves_count_at_zero(self):
        # out-of-scope host -> the gate refuses before the parent request() runs
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True,
                                           allowed_hosts={"t.test"}))
        responder = CountingResponder(_responder)

        async def scenario():
            async with GatedAsyncClient(gate, "v") as client:
                with self.assertRaises(SafetyGateBlocked):
                    await client.request("POST", "http://evil.test/x")

        with patch("httpx.AsyncClient.request", responder):
            asyncio.run(scenario())
        self.assertEqual(responder.count, 0, responder.why())

    def test_seed_gate_scope_arms_the_process_gate(self):
        from harness.safety_gate import get_default_gate
        seed_gate_scope(["t.test"])
        gate = get_default_gate()
        self.assertTrue(gate.config.active_enabled)
        self.assertIn("t.test", gate.config.allowed_hosts)
        self.assertFalse(gate.authorize(validator_name="v", method="POST",
                                        url="http://evil.test/x").allowed)
        self.assertTrue(gate.authorize(validator_name="v", method="POST",
                                       url="http://t.test/x").allowed)


if __name__ == "__main__":
    unittest.main()
