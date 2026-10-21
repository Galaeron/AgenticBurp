"""Connect-time address pinning (P1-10, superseded by I05-B's per-run pin).

P1-10 pinned each request hop to a fresh resolution by rewriting the URL; the next
request or redirect hop resolved again, so a rebinding name could still move
later traffic. I05-B pins at the socket instead: every client a run builds
connects through `AddressPins`, which resolves a name ONCE per run and refuses
special-purpose addresses. These are the unit-level properties; the real-socket
and real-TLS caller tests are in test_destination_policy_callers.py.
"""
from __future__ import annotations

import asyncio
import unittest

from harness import run_context
from harness.run_context import AddressPins, DestinationBlocked, RunContext


class _Resolver:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = 0

    def __call__(self, host):
        self.calls += 1
        if isinstance(self.answers[0], Exception):
            raise self.answers[0]
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]


class AddressPinTests(unittest.TestCase):
    def test_first_answer_holds_for_the_run(self):
        resolver = _Resolver("10.0.0.5", "10.0.0.9")
        pins = AddressPins(resolver)

        async def go():
            return [await pins.address_for("App.Test") for _ in range(3)]

        self.assertEqual(asyncio.run(go()), ["10.0.0.5"] * 3)
        self.assertEqual(resolver.calls, 1)
        self.assertEqual(pins.pinned(), {"app.test": "10.0.0.5"})

    def test_ip_literal_is_not_resolved(self):
        resolver = _Resolver("10.0.0.5")
        pins = AddressPins(resolver)
        self.assertEqual(asyncio.run(pins.address_for("127.0.0.1")), "127.0.0.1")
        self.assertEqual(resolver.calls, 0)

    def test_resolver_failure_raises_and_pins_nothing(self):
        pins = AddressPins(_Resolver(OSError("no such name")))
        with self.assertRaises(OSError):
            asyncio.run(pins.address_for("nx.test"))
        self.assertEqual(pins.pinned(), {})

    def test_special_purpose_addresses_are_refused_through_a_name(self):
        for ip in ("169.254.169.254", "fe80::1", "224.0.0.1", "0.0.0.0", "::",
                   "::ffff:169.254.169.254", "240.0.0.1"):
            with self.subTest(ip=ip):
                with self.assertRaises(DestinationBlocked):
                    asyncio.run(AddressPins(_Resolver(ip)).address_for("meta.test"))
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.20", "8.8.8.8", "::1"):
            with self.subTest(ip=ip):
                self.assertEqual(asyncio.run(AddressPins(_Resolver(ip)).address_for("lab.test")), ip)


class RunClientPinTests(unittest.TestCase):
    def _backend(self, client):
        return client._transport._pool._network_backend

    def test_run_clients_connect_through_the_pin_by_default(self):
        ctx = RunContext.create(allowed_hosts=["app.test"])
        session = ctx.sessions.register("s", "s", allowed_origins=["https://app.test"])
        default = ctx.default_client(destination="https://app.test/a")
        scoped = session.client(ctx.timeout, trust_policy=ctx.tls_policy,
                                destination="https://app.test/a", address_pins=ctx.address_pins)
        self.assertIsInstance(self._backend(default), run_context._PinnedBackend)
        self.assertIsInstance(self._backend(scoped), run_context._PinnedBackend)
        asyncio.run(ctx.aclose())

    def test_explicit_opt_out_connects_by_name(self):
        ctx = RunContext.create(allowed_hosts=["app.test"],
                                config={"security": {"pin_connect_address": False}})
        self.assertIsNone(ctx.address_pins)
        client = ctx.default_client(destination="https://app.test/a")
        self.assertNotIsInstance(self._backend(client), run_context._PinnedBackend)
        asyncio.run(ctx.aclose())

    def test_resolver_failure_is_an_honest_error_not_a_send(self):
        ctx = RunContext.create(allowed_hosts=["nx.test"], max_requests=5)
        ctx.address_pins.resolver = _Resolver(OSError("no such name"))

        async def go():
            try:
                return await ctx.target_transport().send("GET", "http://nx.test:9/a", capability="t")
            finally:
                await ctx.aclose()

        out = asyncio.run(go())
        self.assertEqual(out.outcome, "error")
        self.assertIn("no such name", out.error)

    def test_special_purpose_answer_is_blocked_not_sent(self):
        ctx = RunContext.create(allowed_hosts=["meta.test"], max_requests=5)
        ctx.address_pins.resolver = _Resolver("169.254.169.254")

        async def go():
            try:
                return await ctx.target_transport().send("GET", "http://meta.test/latest", capability="t")
            finally:
                await ctx.aclose()

        out = asyncio.run(go())
        self.assertEqual(out.outcome, "blocked")
        self.assertFalse(out.executed)
        self.assertIn("special-purpose", out.error)


if __name__ == "__main__":
    unittest.main()
