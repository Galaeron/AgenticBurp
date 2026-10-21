"""I05 batch B: redirects and DNS rebinding cannot move a run's sends elsewhere.

Scope is an exact-hostname check made before DNS (P1-9). These tests use real
sockets: owned HTTP(S) servers on 127.0.0.1 and 127.0.0.2 (same port), each
counting the requests it actually receives, and a resolver controlled for `.test`
names only (socket.getaddrinfo is patched for those names; everything else
resolves normally). The second address stands in for an internal service an
in-scope name could be rebound to.

Checks: a run pins each name to its first answer for the whole run -- across
requests and redirect hops, over plain HTTP and real TLS (certificate verified
against the NAME while connecting to the pinned address) -- and refuses a name
that resolves to a special-purpose address such as cloud metadata. An
out-of-scope redirect target receives nothing; a cross-origin redirect inside
scope carries no credentials. Removing the pin from the run's clients must be
detected.
"""
from __future__ import annotations

import asyncio
import shutil
import socket
import socketserver
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from harness import safety_gate
from harness.run_context import RunContext

_REAL_GETADDRINFO = socket.getaddrinfo


class _Server:
    """Owned loopback server bound to one address; records path and headers."""

    def __init__(self, ip: str, port: int = 0, *, tls: ssl.SSLContext | None = None,
                 redirect_to: str = ""):
        self.ip = ip
        self.requests: list[tuple[str, dict]] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                with outer._lock:
                    outer.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
                if self.path.startswith("/redir") and redirect_to:
                    self.send_response(302)
                    self.send_header("Location", redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                data = f"served by {outer.ip}".encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def server_bind(self):
                # HTTPServer.server_bind reverse-resolves the bind address (getfqdn);
                # for 127.0.0.2 that lookup times out after ~5 s. No name is needed.
                socketserver.TCPServer.server_bind(self)
                self.server_name, self.server_port = self.server_address[:2]

            def get_request(self):
                sock, addr = self.socket.accept()
                if tls is not None:
                    sock = tls.wrap_socket(sock, server_side=True)
                return sock, addr

        self._server = Server((ip, port), Handler)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class _Resolver:
    """Answers for `.test` names: each call returns the next listed address (the
    last one repeats). Every other name resolves for real."""

    def __init__(self, answers: dict[str, list[str]]):
        self.answers = {name: list(ips) for name, ips in answers.items()}
        self.calls: list[str] = []

    def __call__(self, host, port, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else host
        if name in self.answers:
            self.calls.append(name)
            seq = self.answers[name]
            ip = seq.pop(0) if len(seq) > 1 else seq[0]
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                     (ip, int(port or 0)))]
        return _REAL_GETADDRINFO(host, port, *args, **kwargs)


class _DestinationFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i05b_dest_")
        safety_gate.reset_default_gate()

    def tearDown(self):
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _server(self, ip, port=0, **kw) -> _Server:
        server = _Server(ip, port, **kw)
        self.addCleanup(server.close)
        return server

    def _pair(self, **kw) -> tuple[_Server, _Server]:
        """The in-scope server and the 'internal' one, on the same port."""
        first = self._server("127.0.0.1", **kw)
        return first, self._server("127.0.0.2", first.port, **kw)

    def _sends(self, urls, *, hosts, resolver, config=None, creds=None, timeout=5.0,
               extra_patches=()):
        run = RunContext.create(allowed_hosts=list(hosts), max_requests=50, config=config or {},
                                timeout=timeout, gate_config={"active_enabled": True})

        async def go():
            async with run:
                transport = run.target_transport()
                outs = []
                for url in urls:
                    if creds:
                        outs.append(await transport.send_creds("GET", url, capability="i05b",
                                                               headers=creds, max_redirects=5))
                    else:
                        outs.append(await transport.send("GET", url, capability="i05b"))
                return outs

        patches = [patch("socket.getaddrinfo", side_effect=resolver), *extra_patches]
        for p in patches:
            p.start()
        try:
            return asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()


class DnsRebindingTests(_DestinationFixture, unittest.TestCase):
    def test_stable_name_reaches_its_server(self):
        server = self._server("127.0.0.1")
        outs = self._sends([f"http://app.test:{server.port}/a"] * 2, hosts=["app.test"],
                           resolver=_Resolver({"app.test": ["127.0.0.1"]}))
        self.assertEqual([o.outcome for o in outs], ["ok", "ok"], outs)
        self.assertEqual(len(server.requests), 2)

    def test_rebinding_between_requests_stays_on_the_first_address(self):
        first, internal = self._pair()
        outs = self._sends([f"http://app.test:{first.port}/a"] * 3, hosts=["app.test"],
                           resolver=_Resolver({"app.test": ["127.0.0.1", "127.0.0.2"]}))
        self.assertEqual(internal.requests, [], "a rebound name reached the second address")
        self.assertEqual(len(first.requests), 3, outs)

    def test_rebinding_on_a_redirect_hop_stays_on_the_first_address(self):
        first = self._server("127.0.0.1")
        first_port = first.port
        first.close()
        first = self._server("127.0.0.1", first_port,
                             redirect_to=f"http://app.test:{first_port}/after")
        internal = self._server("127.0.0.2", first_port)
        outs = self._sends([f"http://app.test:{first_port}/redir"], hosts=["app.test"],
                           resolver=_Resolver({"app.test": ["127.0.0.1", "127.0.0.2"]}))
        self.assertEqual(internal.requests, [], "the redirect hop reached the second address")
        self.assertEqual([p for p, _ in first.requests], ["/redir", "/after"], outs)

    def test_opt_in_per_hop_pin_setting_also_holds_across_requests(self):
        first, internal = self._pair()
        self._sends([f"http://app.test:{first.port}/a"] * 2, hosts=["app.test"],
                    resolver=_Resolver({"app.test": ["127.0.0.1", "127.0.0.2"]}),
                    config={"security": {"pin_connect_address": True}})
        self.assertEqual(internal.requests, [])

    def test_special_purpose_address_is_refused_without_a_connect(self):
        outs = self._sends(["http://meta.test:80/latest/meta-data/"], hosts=["meta.test"],
                           resolver=_Resolver({"meta.test": ["169.254.169.254"]}), timeout=2.0)
        self.assertEqual(outs[0].outcome, "blocked", outs[0])
        self.assertIn("special-purpose", outs[0].error)

    def test_gated_validator_sends_are_pinned_too(self):
        """A caller: GatedAsyncClient routes through the enclosing run (I03)."""
        first, internal = self._pair()
        resolver = _Resolver({"app.test": ["127.0.0.1", "127.0.0.2"]})
        run = RunContext.create(allowed_hosts=["app.test"], max_requests=50,
                                gate_config={"active_enabled": True})

        async def go():
            async with run:
                async with safety_gate.GatedAsyncClient(run.gate, "i05b_caller") as client:
                    for _ in range(2):
                        await client.get(f"http://app.test:{first.port}/a")

        with patch("socket.getaddrinfo", side_effect=resolver):
            asyncio.run(go())
        self.assertEqual(internal.requests, [])
        self.assertEqual(len(first.requests), 2)

    def test_removing_the_pin_from_the_run_clients_is_detected(self):
        """Fault injection: the run's clients connect by name again."""
        first, internal = self._pair()
        self._sends([f"http://app.test:{first.port}/a"] * 2, hosts=["app.test"],
                    resolver=_Resolver({"app.test": ["127.0.0.1", "127.0.0.2"]}),
                    extra_patches=[patch("harness.run_context._pinned_backend",
                                         return_value=None)])
        self.assertTrue(internal.requests,
                        "unpinned clients no longer reach the rebound address -- vacuous")


class RealTlsPinningTests(_DestinationFixture, unittest.TestCase):
    def test_https_verifies_the_name_while_connecting_to_the_pinned_address(self):
        from harness.test_remediation_tls import _LEAF_CERT, _LEAF_KEY, _TRUSTED_CA
        cert, key, ca = (Path(self._tmp) / n for n in ("leaf.pem", "key.pem", "ca.pem"))
        cert.write_text(_LEAF_CERT, encoding="ascii")
        key.write_text(_LEAF_KEY, encoding="ascii")
        ca.write_text(_TRUSTED_CA, encoding="ascii")
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(str(cert), str(key))
        first, internal = self._pair(tls=server_tls)
        outs = self._sends([f"https://fixture.test:{first.port}/a"] * 2, hosts=["fixture.test"],
                           resolver=_Resolver({"fixture.test": ["127.0.0.1", "127.0.0.2"]}),
                           config={"transport": {"tls": {"ca_bundle": str(ca.resolve())}}})
        self.assertEqual([o.outcome for o in outs], ["ok", "ok"], outs)
        self.assertEqual(len(first.requests), 2)
        self.assertEqual(internal.requests, [])


class RedirectDestinationTests(_DestinationFixture, unittest.TestCase):
    def test_redirect_to_an_out_of_scope_origin_sends_nothing_there(self):
        denied = self._server("127.0.0.1")
        start = self._server("127.0.0.1", redirect_to=f"http://denied.test:{denied.port}/x")
        outs = self._sends([f"http://app.test:{start.port}/redir"], hosts=["app.test"],
                           resolver=_Resolver({"app.test": ["127.0.0.1"],
                                               "denied.test": ["127.0.0.1"]}))
        self.assertEqual(outs[0].outcome, "out_of_scope", outs[0])
        self.assertEqual(denied.requests, [])

    def test_cross_origin_redirect_inside_scope_drops_credentials(self):
        landing = self._server("127.0.0.1")
        start = self._server("127.0.0.1", redirect_to=f"http://other.test:{landing.port}/landing")
        self._sends([f"http://app.test:{start.port}/redir"], hosts=["app.test", "other.test"],
                    resolver=_Resolver({"app.test": ["127.0.0.1"], "other.test": ["127.0.0.1"]}),
                    creds={"Authorization": "Bearer i05b-secret"})
        self.assertEqual(start.requests[0][1].get("authorization"), "Bearer i05b-secret")
        self.assertEqual(len(landing.requests), 1)
        self.assertNotIn("authorization", landing.requests[0][1])


if __name__ == "__main__":
    unittest.main()
