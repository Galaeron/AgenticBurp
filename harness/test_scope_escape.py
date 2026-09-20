"""P1-2: scope-escape adversarial coverage.

Vectors an attacker-controlled target could use to trick the scoped transport
into contacting a host outside the engagement's allow-list:

  (a) a raw IP literal that is not itself in `allowed_hosts`.
  (b) DNS-rebinding style: a hostname NOT in `allowed_hosts` that a (mocked)
      DNS resolver maps onto an address belonging to an in-scope host. Proves
      the scope decision is made on the request's HOSTNAME STRING, never on a
      resolved address, so rebinding the name after the scope check cannot
      smuggle a request past it.
  (c) alternate URL schemes (file://, gopher://) that bypass HTTP semantics.
  (d) a mid-hop redirect that tries to leave scope, via the transport's own
      manual redirect loop (real loopback fixture, not a mock).

Every negative case here asserts `out_of_scope` (or a pre-send `blocked`) AND
that nothing was ever sent to the disallowed destination -- the positive
control (an in-scope loopback request) proves the harness is not just
vacuously refusing everything.
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


class ScopeEscapeTests(unittest.TestCase):
    def setUp(self):
        self.srv = _Fixture()
        self.addCleanup(self.srv.close)

    # -- (a) raw IP literal not in scope -----------------------------------

    def test_offscope_ip_literal_refused(self):
        # Scope only allows the fixture's own loopback address; a different,
        # unroutable IP literal must be refused before any send.
        ctx = _ctx([IN_SCOPE_IP])

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", "http://198.51.100.7/secret"), capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertEqual(self.srv.paths(), [])

    # -- (b) DNS-rebinding style ---------------------------------------------

    def test_rebinding_hostname_not_itself_scoped_is_refused(self):
        # attacker-controlled.example is NOT in allowed_hosts. Mock DNS so it
        # resolves to the in-scope loopback address -- if scope were decided
        # on the RESOLVED address instead of the request's hostname string,
        # this would wrongly be let through. No real DNS lookup happens here.
        ctx = _ctx([IN_SCOPE_IP])
        rebinding_host = "attacker-controlled.example"

        def fake_getaddrinfo(host, *a, **k):
            self.assertNotEqual(host, "198.51.100.7")  # sanity: this is our mock, not a real query
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     (IN_SCOPE_IP, self.srv.port))]

        async def scenario():
            with mock.patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
                out = await ctx.executor().execute(
                    TypedRequest("GET", f"http://{rebinding_host}:{self.srv.port}/secret"),
                    capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertEqual(self.srv.paths(), [])  # never reached the fixture, despite the DNS mock

    # -- (c) alternate schemes ------------------------------------------------

    def test_file_scheme_refused(self):
        ctx = _ctx([IN_SCOPE_IP])

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", "file:///etc/passwd"), capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "out_of_scope")

    def test_gopher_scheme_refused_even_against_inscope_host(self):
        # Host is the in-scope loopback address; only the scheme is hostile.
        # Proves the scheme check applies independently of the host check.
        ctx = _ctx([IN_SCOPE_IP])

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", f"gopher://{IN_SCOPE_IP}:{self.srv.port}/x"), capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertEqual(self.srv.paths(), [])

    # -- (d) mid-hop redirect leaving scope -----------------------------------

    def test_mid_hop_redirect_to_offscope_ip_literal_stopped(self):
        # First hop is in-scope and IS contacted; its 302 tries to send the
        # walk to an off-scope raw IP literal. The manual redirect loop must
        # re-check scope before following it, so the second hop is never sent.
        self.srv.httpd.redirect_location = "http://198.51.100.7/collect"
        ctx = _ctx([IN_SCOPE_IP])

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", f"{self.srv.base}/redirect"), capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertIn("/redirect", self.srv.paths())   # first hop WAS contacted (in scope)
        self.assertNotIn("/collect", self.srv.paths())  # off-scope destination never reached

    def test_mid_hop_redirect_to_alternate_scheme_stopped(self):
        self.srv.httpd.redirect_location = "gopher://127.0.0.1/x"
        ctx = _ctx([IN_SCOPE_IP])

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", f"{self.srv.base}/redirect"), capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertIn("/redirect", self.srv.paths())

    # -- positive control: proves the tests above are not vacuous ------------

    def test_inscope_loopback_request_still_succeeds(self):
        ctx = _ctx([IN_SCOPE_IP])

        async def scenario():
            out = await ctx.executor().execute(
                TypedRequest("GET", f"{self.srv.base}/ok"), capability="probe")
            await ctx.aclose()
            return out

        out = asyncio.run(scenario())
        self.assertEqual(out.outcome, "ok")
        self.assertEqual(out.status, 200)
        self.assertIn("/ok", self.srv.paths())


if __name__ == "__main__":
    unittest.main()
