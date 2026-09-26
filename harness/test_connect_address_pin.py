"""Caller-level tests for connect-time address pinning (P1-10, DNS-rebinding).

OFF by default. When `security.pin_connect_address` is set, TargetTransport.execute
resolves each hop's host ONCE and directs the connection to that pinned address
while preserving the Host header and TLS SNI, so a later/alternate resolution can
never redirect the connect. A MockTransport records the address each request was
actually sent to; an injected resolver drives the rebinding scenarios without DNS.

The live two-origin/real-HTTPS proof stays OWNER; these tests prove the pin logic:
the connect targets the resolved IP (not the hostname, not a second resolution),
redirects are re-pinned, IP literals are left alone, and default-off is unchanged.
"""
from __future__ import annotations

import unittest

import httpx

from harness.run_context import RunContext


def _recording_transport(record: list, *, redirect_from: str | None = None,
                         redirect_to: str = ""):
    def handler(request: httpx.Request) -> httpx.Response:
        record.append({
            "connect_host": request.url.host,
            "host_header": request.headers.get("host"),
            "sni": request.extensions.get("sni_hostname"),
        })
        if redirect_from and request.headers.get("host", "").split(":")[0] == redirect_from:
            return httpx.Response(302, headers={"location": redirect_to})
        return httpx.Response(200, text="ok")
    return httpx.MockTransport(handler)


class _ResolverSpy:
    """Maps host -> ip; records every call. `sequence` (if given) is returned in
    order regardless of host, to model a resolution that changes over time."""
    def __init__(self, mapping=None, sequence=None):
        self.mapping = dict(mapping or {})
        self.sequence = list(sequence or [])
        self.calls: list[str] = []

    def __call__(self, host: str) -> str:
        self.calls.append(host)
        if self.sequence:
            return self.sequence.pop(0)
        return self.mapping[host]


def _ctx(pin: bool, hosts, record, **kw):
    cfg = {"security": {"pin_connect_address": True}} if pin else {}
    rc = RunContext.create(allowed_hosts=hosts, config=cfg)
    rc._default_client = httpx.AsyncClient(transport=_recording_transport(record, **kw),
                                           follow_redirects=False, verify=False)
    return rc


class ConnectPinTests(unittest.IsolatedAsyncioTestCase):
    async def _send(self, rc, resolver, method="GET", url="http://app.test/x"):
        t = rc.target_transport()
        if resolver is not None:
            t._resolver = resolver
        try:
            return await t.send(method, url, capability="test")
        finally:
            await rc.aclose()

    async def test_pin_directs_connect_to_resolved_ip_preserving_host(self):
        rec = []
        rc = _ctx(True, ["app.test"], rec)
        r = _ResolverSpy({"app.test": "10.0.0.1"})
        out = await self._send(rc, r)
        self.assertEqual(out.outcome, "ok")
        self.assertEqual(rec[0]["connect_host"], "10.0.0.1")   # connected to the IP
        self.assertEqual(rec[0]["host_header"], "app.test")    # Host preserved
        self.assertEqual(r.calls, ["app.test"])                # resolved exactly once

    async def test_uses_pinned_ip_not_a_later_resolution(self):
        # resolver would return A then B; the connect must use A, never B.
        rec = []
        rc = _ctx(True, ["app.test"], rec)
        r = _ResolverSpy(sequence=["10.0.0.1", "10.9.9.9"])
        await self._send(rc, r)
        connects = [e["connect_host"] for e in rec]
        self.assertIn("10.0.0.1", connects)
        self.assertNotIn("10.9.9.9", connects, "a later resolution's address was contacted")

    async def test_https_sets_sni_hostname_extension(self):
        rec = []
        rc = _ctx(True, ["app.test"], rec)
        out = await self._send(rc, _ResolverSpy({"app.test": "10.0.0.1"}),
                               url="https://app.test/x")
        self.assertEqual(out.outcome, "ok")
        self.assertEqual(rec[0]["connect_host"], "10.0.0.1")
        self.assertEqual(rec[0]["sni"], "app.test")            # TLS SNI preserved

    async def test_ip_literal_host_is_not_resolved(self):
        rec = []
        rc = _ctx(True, ["127.0.0.1"], rec)
        r = _ResolverSpy({})
        out = await self._send(rc, r, url="http://127.0.0.1/x")
        self.assertEqual(out.outcome, "ok")
        self.assertEqual(r.calls, [], "an IP literal must not be resolved")
        self.assertEqual(rec[0]["connect_host"], "127.0.0.1")

    async def test_redirect_hop_is_repinned(self):
        rec = []
        rc = _ctx(True, ["app.test", "app2.test"], rec,
                  redirect_from="app.test", redirect_to="http://app2.test/y")
        r = _ResolverSpy({"app.test": "10.0.0.1", "app2.test": "10.0.0.2"})
        out = await self._send(rc, r)
        self.assertEqual(out.outcome, "ok")
        self.assertEqual([e["connect_host"] for e in rec], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual([e["host_header"] for e in rec], ["app.test", "app2.test"])

    async def test_resolver_failure_is_an_honest_error_not_a_send(self):
        rec = []
        rc = _ctx(True, ["app.test"], rec)
        def boom(host):
            raise OSError("no such host")
        out = await self._send(rc, boom)
        self.assertEqual(out.outcome, "error")
        self.assertEqual(rec, [], "nothing may be sent when resolution fails")


class DefaultOffTests(unittest.IsolatedAsyncioTestCase):
    async def test_off_by_default_connects_to_hostname_and_never_resolves(self):
        rec = []
        rc = _ctx(False, ["app.test"], rec)            # no pin toggle
        r = _ResolverSpy({"app.test": "10.0.0.1"})
        t = rc.target_transport()
        t._resolver = r
        try:
            out = await t.send("GET", "http://app.test/x", capability="test")
        finally:
            await rc.aclose()
        self.assertEqual(out.outcome, "ok")
        self.assertEqual(rec[0]["connect_host"], "app.test")   # unchanged default path
        self.assertEqual(r.calls, [], "resolver must not run when pinning is off")


if __name__ == "__main__":
    unittest.main()
