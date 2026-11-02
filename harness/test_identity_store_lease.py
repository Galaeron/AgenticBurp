"""investigate_engagement registers each role's headers as a cross-identity replay
identity in the process-global identity_headers store. Those registrations belong
to the engagement: they must be gone once it ends (returned, raised or cancelled),
so a later engagement on the same host never sees an earlier one's roles as "other
identities", and an overlapping engagement never loses (or sees) another's.

Caller-level: the real Orchestrator.investigate_engagement, with the model
silenced and discovery/worklist replaced by in-memory fixtures (the
test_engagement_chain_relink pattern). The fake worklist runs inside the
engagement, after registration, and records what a store reader there sees --
the same `identities_for_host` call the cross-identity leg makes. Tokens are
synthetic; no header value is ever printed.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from harness import engagement_builder
from harness import identity_headers
from harness import safety_gate
from harness import worklist_investigator
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.test_engagement_chain_relink import (
    BASE_URL, HOST, _config, _fake_build_engagement, _install_silent_model)


def _roles(name: str) -> list:
    return [RoleSession("anonymous", {}),
            RoleSession("user", {"Authorization": f"Bearer synthetic-{name}"}, name=name)]


def _names() -> list:
    return sorted(i["name"] for i in identity_headers.identities_for_host(HOST))


class IdentityStoreLeaseTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        identity_headers.clear()
        self.seen: dict[str, list] = {}
        self.hooks: dict = {}
        cfg = _config()
        cfg["validators"]["allow_mutating_replay"] = False
        self.cfg = cfg
        safety_gate.reset_default_gate()
        patches = [
            patch.object(engagement_builder, "build_engagement", new=_fake_build_engagement),
            patch.object(worklist_investigator, "investigate_worklist", new=self._worklist),
            patch("harness.second_order.auto_confirm_candidates", new=AsyncMock(return_value=[])),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        identity_headers.clear()
        safety_gate.reset_default_gate()

    async def _worklist(self, probe, state, base_url, roles, **kwargs):
        who = roles[-1].principal_id()
        record = lambda: self.seen.setdefault(who, []).append(_names())
        record()
        hook = self.hooks.get(who)
        if hook is not None:
            await hook(record)
        return []

    async def _engage(self, name: str) -> dict:
        orch = Orchestrator(self.cfg)
        orch.allowed_hosts = [HOST]
        _install_silent_model(orch)
        return await orch.investigate_engagement(
            BASE_URL, _roles(name), max_nodes=2, step_budget=2,
            max_chain_rounds=1, discovery_max_probes=10)

    async def test_sequential_engagement_sees_only_its_own_roles(self):
        await self._engage("alice")
        await self._engage("bob")
        self.assertEqual(self.seen["alice"], [["alice"]])
        self.assertEqual(self.seen["bob"], [["bob"]],
                         "the earlier engagement's role leaked into the later one")
        self.assertEqual(_names(), [])
        self.assertFalse(identity_headers.has_identities(HOST))

    async def test_registrations_released_when_engagement_raises(self):
        async def boom(record):
            raise RuntimeError("synthetic worklist failure")
        self.hooks["alice"] = boom
        with self.assertRaises(RuntimeError):
            await self._engage("alice")
        self.assertEqual(self.seen["alice"], [["alice"]])
        self.assertEqual(_names(), [])

    async def test_registrations_released_when_engagement_cancelled(self):
        entered = asyncio.Event()

        async def hang(record):
            entered.set()
            await asyncio.Event().wait()
        self.hooks["alice"] = hang
        task = asyncio.create_task(self._engage("alice"))
        await asyncio.wait_for(entered.wait(), 30)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.seen["alice"], [["alice"]])
        self.assertEqual(_names(), [])

    async def test_overlapping_engagements_keep_their_own_live_registrations(self):
        bob_registered, alice_done = asyncio.Event(), asyncio.Event()

        async def alice_hook(record):
            await bob_registered.wait()
            record()

        async def bob_hook(record):
            bob_registered.set()
            await alice_done.wait()
            record()   # alice's engagement has ended and released its lease
        self.hooks.update(alice=alice_hook, bob=bob_hook)

        async def alice_then_signal():
            try:
                return await self._engage("alice")
            finally:
                alice_done.set()
        await asyncio.wait_for(asyncio.gather(alice_then_signal(), self._engage("bob")), 60)
        self.assertEqual(self.seen["alice"], [["alice"], ["alice"]])
        self.assertEqual(self.seen["bob"], [["bob"], ["bob"]],
                         "alice's release removed bob's live registration, or they saw each other")
        self.assertEqual(_names(), [])

    async def test_single_engagement_and_operator_identities_unchanged(self):
        """Control: the engagement's role is visible inside it; operator-fed
        identities (registered outside any engagement) stay visible throughout and
        survive it, and one the engagement shadows by name is restored after."""
        identity_headers.set_identity(HOST, "carol", {"Authorization": "Bearer synthetic-op-carol"}, "user")
        identity_headers.set_identity(HOST, "alice", {"Authorization": "Bearer synthetic-op-alice"}, "admin")

        async def check_shadow(record):
            alice = [i for i in identity_headers.identities_for_host(HOST) if i["name"] == "alice"]
            self.assertEqual(alice[0]["role"], "user")
        self.hooks["alice"] = check_shadow
        result = await self._engage("alice")
        self.assertIn("assessment", result)
        self.assertEqual(self.seen["alice"], [["alice", "carol"]])
        self.assertEqual(_names(), ["alice", "carol"])
        alice = [i for i in identity_headers.identities_for_host(HOST) if i["name"] == "alice"]
        self.assertEqual(alice[0]["role"], "admin")


if __name__ == "__main__":
    unittest.main()
