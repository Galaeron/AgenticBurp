"""P1-9: allowed-host DNS/address-resolution boundary -- characterization, not a
new defense.

Scope authorization in this codebase (`ScopePolicy.in_scope` in run_context.py,
`scope_lock.host_in_scope`) is a HOSTNAME-STRING membership check. httpx performs
its own DNS resolution later, at connect time, entirely outside that check -- the
scope check does not resolve the hostname and does not pin the address the
request actually reaches. This module decides and documents that contract
honestly and characterizes it with tests. It deliberately does NOT build
address-level rebinding enforcement (connect-time IP pinning); that is out of
scope for this unit and is proposed below as a follow-up.

Three things are demonstrated, all OFFLINE (mocked `socket.getaddrinfo`, the
owned 127.0.0.1 `_Fixture` loopback server from test_run_context.py -- no real
DNS lookup, no off-host connection):

  1. POSITIVE CONTROL -- an authorized hostname with STABLE resolution to the
     loopback fixture reaches it. Legitimate authorized use still works.
  2. CHANGING-RESOLUTION CHARACTERIZATION -- an in-scope hostname's resolved
     address changes between calls (classic DNS-rebinding shape). Because scope
     is decided on the hostname string alone, the send is still allowed to
     proceed to whatever address it resolves to at connect time. This test
     asserts that TRUE, current behaviour -- it does NOT assert a protection
     that does not exist. Address-level rebinding enforcement is NOT built
     here; it is tracked as the P1-9 follow-up (see module docstring below).
  3. NEGATIVE CONTROL -- an UNLISTED hostname is still refused (out_of_scope).
     This shows ordinary scope enforcement is intact; per the backlog's
     explicit warning, it must NOT be read as rebinding protection -- it only
     shows an unlisted name is refused, not that an already-allowed name is
     pinned to one address.

Follow-up proposed (not implemented here): a connect-time resolution pin in
`TargetTransport.execute` (harness/run_context.py) that resolves the hostname
once per hop, verifies the address is used for that hop's actual connection
(preserving the original Host/SNI so TLS and virtual hosting still work), and
rejects the send if the resolution changes between the check and the connect
(check/use race explicitly designed out, e.g. by resolving and connecting to
the pinned address in one atomic step rather than resolve-then-separately-
connect-by-name). Its own zero-request negative control would assert that a
hostname whose resolution changes between pin and use is refused with NO
request ever reaching the new address.
"""
from __future__ import annotations

import asyncio
import socket
import unittest
from unittest import mock

from harness.run_context import RunContext, TypedRequest
from harness.test_run_context import _Fixture

IN_SCOPE_IP = "127.0.0.1"


def _ctx(allowed_hosts, **over):
    kw = dict(allowed_hosts=allowed_hosts,
              gate_config={"active_enabled": True, "allow_mutating_replay": True})
    kw.update(over)
    return RunContext.create(**kw)


class DnsResolutionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.srv = _Fixture()
        self.addCleanup(self.srv.close)

    # -- 1. positive control: authorized hostname, stable resolution ---------

    def test_authorized_hostname_stable_resolution_reaches_fixture(self):
        # authorized.example is in allowed_hosts and resolves, every call, to
        # the loopback fixture. Proves legitimate authorized use still works
        # under the mocked-resolver seam used by the other tests here.
        authorized_host = "authorized.example"
        ctx = _ctx([authorized_host])

        def stable_getaddrinfo(host, *a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     (IN_SCOPE_IP, self.srv.port))]

        async def scenario():
            with mock.patch("socket.getaddrinfo", side_effect=stable_getaddrinfo):
                out = await ctx.executor().execute(
                    TypedRequest("GET", f"http://{authorized_host}:{self.srv.port}/ok"),
                    capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "ok")
        self.assertIn("/ok", self.srv.paths())

    # -- 2. changing-resolution characterization (TRUE behaviour, not a claim) -

    def test_allowed_hostname_changing_resolution_is_not_pinned_by_scope(self):
        # allowed.example IS in allowed_hosts. Its mocked resolution changes
        # between calls -- first to an off-fixture loopback port (nothing
        # listening), then to the fixture. This is the DNS-rebinding SHAPE
        # applied to an already-authorized hostname, which test_scope_escape's
        # rebinding test does not cover (that one uses an UNLISTED hostname).
        #
        # DOCUMENTED CONTRACT (P1-9): ScopePolicy.in_scope is a hostname-string
        # check. It does not resolve the hostname and does not pin the address.
        # So this send is NOT blocked by scope on account of the changing
        # resolution -- it proceeds and connects to whatever address the
        # (mocked) resolver hands back at connect time. That is the honest,
        # current behaviour asserted below. This is NOT a claim that address-
        # level rebinding is prevented -- it explicitly is not, here. Enforcing
        # that is the proposed follow-up (connect-time address pinning),
        # deliberately not built in this characterization unit.
        allowed_host = "allowed.example"
        ctx = _ctx([allowed_host])

        # A loopback port nothing is listening on, to stand in for "resolves
        # somewhere else" without making any real off-host connection.
        unbound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        unbound.bind((IN_SCOPE_IP, 0))
        off_fixture_port = unbound.getsockname()[1]
        unbound.close()  # closed immediately -- nothing listens there

        calls = {"n": 0}

        def rebinding_getaddrinfo(host, *a, **k):
            calls["n"] += 1
            port = off_fixture_port if calls["n"] == 1 else self.srv.port
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (IN_SCOPE_IP, port))]

        async def scenario():
            with mock.patch("socket.getaddrinfo", side_effect=rebinding_getaddrinfo):
                first = await ctx.executor().execute(
                    TypedRequest("GET", f"http://{allowed_host}:{off_fixture_port}/first"),
                    capability="probe")
                second = await ctx.executor().execute(
                    TypedRequest("GET", f"http://{allowed_host}:{self.srv.port}/second"),
                    capability="probe")
            await ctx.aclose()
            return first, second

        first, second = asyncio.run(scenario())
        # First hop: scope allowed the hostname (in allowed_hosts); the actual
        # connect failed only because nothing listens on that port -- a
        # transport-level error, never a scope refusal. Scope did not notice
        # or object to the "rebind".
        self.assertEqual(first.outcome, "error")
        # Second hop: same hostname, scope check identical (still True) --
        # this time the mocked resolution happens to land on the fixture, and
        # the request is sent and succeeds. Nothing about the scope decision
        # changed between the two calls; only the resolved address did.
        self.assertEqual(second.outcome, "ok")
        self.assertIn("/second", self.srv.paths())

    # -- 3. negative control: unlisted hostname still refused -----------------

    def test_unlisted_hostname_still_refused_not_rebinding_protection(self):
        # unlisted.example is NOT in allowed_hosts. This shows ordinary scope
        # enforcement is intact -- it must NOT be read as rebinding protection
        # (per IMPROVEMENT_BACKLOG.md P1-9's explicit warning): it only shows
        # an unlisted hostname is refused, regardless of what it resolves to,
        # not that an ALREADY-allowed hostname is pinned to one address (test 2
        # above shows it is not).
        ctx = _ctx([IN_SCOPE_IP])
        unlisted_host = "unlisted.example"

        def fake_getaddrinfo(host, *a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (IN_SCOPE_IP, self.srv.port))]

        async def scenario():
            with mock.patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
                out = await ctx.executor().execute(
                    TypedRequest("GET", f"http://{unlisted_host}:{self.srv.port}/secret"),
                    capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertEqual(self.srv.paths(), [])

    # -- preserve authorized loopback/private targets (do not assert blocked) -

    def test_authorized_loopback_target_not_blocked(self):
        ctx = _ctx([IN_SCOPE_IP])

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", f"{self.srv.base}/allowed"), capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "ok")
        self.assertIn("/allowed", self.srv.paths())


if __name__ == "__main__":
    unittest.main()
