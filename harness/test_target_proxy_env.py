"""ARC-14: target traffic never follows an HTTP(S)_PROXY / ALL_PROXY from the environment.

Real sockets: an owned loopback target and an owned loopback "proxy" that
records whatever reaches it. The environment points HTTP_PROXY, HTTPS_PROXY and
ALL_PROXY at the proxy (NO_PROXY cleared), and `target.test` resolves to the
target through a controlled resolver. A run's TargetTransport send must reach the
target directly, its name resolved by the run's own pin, with the proxy seeing
nothing; the run's client is built with trust_env=False.

Negative control: the same run with a target client that trusts the environment
(no pinned transport, trust_env left on) is carried by the proxy, so the target
and the pin never see it -- the test detects a proxy taking over the send.
"""
from __future__ import annotations

import asyncio
import os
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import httpx

from harness import run_context as run_context_mod
from harness import safety_gate
from harness.run_context import RunContext

_REAL_GETADDRINFO = socket.getaddrinfo


class _Recording:
    """Owned loopback HTTP server: records the request line target it is sent."""

    def __init__(self, label: str):
        self.seen: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.seen.append(self.path)
                data = label.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        class Server(ThreadingHTTPServer):
            daemon_threads = True

        self._server = Server(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class TargetProxyEnvTests(unittest.TestCase):
    def setUp(self):
        safety_gate.reset_default_gate()
        self.addCleanup(safety_gate.reset_default_gate)
        self.target = _Recording("target")
        self.proxy = _Recording("proxy")
        self.addCleanup(self.target.close)
        self.addCleanup(self.proxy.close)
        proxy_url = f"http://127.0.0.1:{self.proxy.port}"
        env = patch.dict(os.environ, {"HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url,
                                      "ALL_PROXY": proxy_url, "NO_PROXY": ""})
        env.start()
        self.addCleanup(env.stop)
        self.resolved: list[str] = []

        def resolve(host, port, *args, **kwargs):
            name = host.decode() if isinstance(host, bytes) else host
            if name == "target.test":
                self.resolved.append(name)
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                         ("127.0.0.1", int(port or 0)))]
            return _REAL_GETADDRINFO(host, port, *args, **kwargs)
        resolver = patch("socket.getaddrinfo", side_effect=resolve)
        resolver.start()
        self.addCleanup(resolver.stop)
        self.url = f"http://target.test:{self.target.port}/item"

    def _send(self) -> str:
        run = RunContext.create(allowed_hosts=["target.test"], max_requests=10,
                                gate_config={"active_enabled": True}, timeout=5.0)

        async def go():
            async with run:
                out = await run.target_transport().send("GET", self.url, capability="arc14",
                                                        max_redirects=0)
                return out.outcome
        return asyncio.run(go())

    def test_environment_proxy_is_ignored_and_the_pin_applies(self):
        self.assertEqual(urllib_env_proxies().get("http"), f"http://127.0.0.1:{self.proxy.port}")
        self.assertEqual(self._send(), "ok")
        self.assertEqual(self.target.seen, ["/item"])
        self.assertEqual(self.proxy.seen, [])
        self.assertIn("target.test", self.resolved)     # resolved by the run's pin

    def test_target_client_is_built_without_trust_env(self):
        client = run_context_mod._target_client(verify=True, timeout=1.0, http2=False, pins=None)
        try:
            self.assertFalse(client.trust_env)
            self.assertEqual(client._mounts, {})
        finally:
            asyncio.run(client.aclose())

    def test_negative_control_an_env_trusting_client_is_carried_by_the_proxy(self):
        def env_trusting_client(*, verify, timeout, http2, pins):
            return httpx.AsyncClient(follow_redirects=False, verify=verify, timeout=timeout,
                                     cookies=httpx.Cookies(), http2=http2)

        with patch.object(run_context_mod, "_target_client", env_trusting_client):
            self.assertEqual(self._send(), "ok")
        self.assertEqual(self.target.seen, [])
        self.assertEqual(self.proxy.seen, [self.url])
        self.assertNotIn("target.test", self.resolved)  # the pin never saw the name


def urllib_env_proxies() -> dict:
    """What an environment-trusting client would read (sanity: the env is live)."""
    import urllib.request
    return urllib.request.getproxies_environment()


if __name__ == "__main__":
    unittest.main()
