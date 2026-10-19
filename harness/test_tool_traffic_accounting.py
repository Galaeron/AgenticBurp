"""I05: an external tool's own requests spend the owning run, through a counting proxy.

sqlmap is launched through the real validator, but the launched program is an
owned stand-in "tool": it makes I05D_REQUESTS GET requests to the -u URL it was
given (with the -H headers it was given) and exits. The swap happens inside
subprocess.Popen, so the real launch path runs. An owned loopback target counts
what it actually receives, independently of the harness.

Checks: every request the tool makes is counted by the run (target count ==
budget.used); a small budget stops the tool after exactly that many requests and
leaves no process behind; credentials reach only the target origin; an
off-origin redirect is refused at the proxy. Handing the tool the real target URL
(forwarding loss) must be detected by the same accounting assertion.

Code review 02: a same-origin redirect stays reachable from a container (R34), and
a stalled or half-open client can neither hold the validator in the proxy's
close() nor a handler open forever (R35). Both fixes have a fault injection.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from harness import tool_proxy, tool_runner
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.test_engagement_transport_callers import _Target
from harness.validators.sqlmap import SqlmapValidator

_FAKE_SQLMAP = "i05d-fake-sqlmap"
_REAL_POPEN = subprocess.Popen

_TOOL = r'''
import os, sys, urllib.error, urllib.request
args = sys.argv[1:]
url = args[args.index("-u") + 1]
# A container reaches the host through host.docker.internal; this stand-in runs
# on the host, so it resolves that alias to loopback the way Docker Desktop does.
url = url.replace("host.docker.internal", "127.0.0.1")
headers = {}
for i, a in enumerate(args):
    if a == "-H":
        k, _, v = args[i + 1].partition(":")
        headers[k.strip()] = v.strip()
import time
ok = refused = 0
for i in range(int(os.environ.get("I05D_REQUESTS", "0"))):
    time.sleep(float(os.environ.get("I05D_DELAY", "0")))
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(f"{url}{sep}i05d={i}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
            ok += 1
    except urllib.error.HTTPError as e:
        refused += 1
    except Exception:
        refused += 1
print(f"tool done ok={ok} refused={refused}", flush=True)
'''


def _sqli() -> Finding:
    return Finding(vulnerability_class="sqli", severity="high", confidence=0.6,
                   summary="id reaches SQL", evidence="", suggested_test="", basis="derived")


class _AccountingFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i05d_tool_")
        self.tool = os.path.join(self._tmp, "tool.py")
        Path(self.tool).write_text(_TOOL, encoding="utf-8")
        self.env = {"I05D_REQUESTS": "12"}
        self.launched: list[list[str]] = []
        fixture = self

        class _SwapPopen(_REAL_POPEN):
            def __init__(self, args, *a, **kw):
                if isinstance(args, (list, tuple)) and args:
                    head = str(args[0])
                    if head == _FAKE_SQLMAP or (head == tool_runner.DOCKER and args[1:2] == ["run"]):
                        fixture.launched.append([str(x) for x in args])
                        args = [sys.executable, fixture.tool, *args[1:]]
                        kw["env"] = {**(kw.get("env") or os.environ), **fixture.env}
                super().__init__(args, *a, **kw)

        self._popen = patch("subprocess.Popen", _SwapPopen)
        self._popen.start()
        self.target = _Target()

    def tearDown(self):
        self._popen.stop()
        self.target.close()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _validate(self, *, max_requests=100, headers=None, extra_patches=(), bound=None,
                  **validator_kw):
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=max_requests)
        exchange = HttpExchange(url=f"{self.target.base}/api/items/7", method="GET",
                                request_headers=dict(headers or {}), response_status=200,
                                response_body='{"id": 7}')
        validator = SqlmapValidator(binary=_FAKE_SQLMAP, timeout_seconds=30,
                                    allowed_hosts=["127.0.0.1"], run_context=run, **validator_kw)

        async def go():
            try:
                async with run:
                    # `bound`: the test's own limit, so a hang fails instead of blocking.
                    return await asyncio.wait_for(validator.validate(_sqli(), exchange), bound)
            finally:
                await run.aclose()

        for p in extra_patches:
            p.start()
        try:
            result = asyncio.run(go())
        finally:
            for p in reversed(extra_patches):
                p.stop()
        return result, run

    def _tool_requests(self):
        return [r for r in self.target.requests if "i05d=" in r[1]]


class ToolTrafficAccountingTests(_AccountingFixture, unittest.TestCase):
    def test_every_tool_request_is_counted_by_the_run(self):
        result, run = self._validate()
        self.assertEqual(len(self._tool_requests()), 12, self.target.requests)
        self.assertEqual(len(self.target.requests), run.budget.used)
        url = self.launched[0][self.launched[0].index("-u") + 1]
        self.assertNotEqual(urlsplit(url).port, urlsplit(self.target.base).port,
                            "the tool was given the real target")

    def test_small_budget_stops_the_tool_after_exactly_that_many(self):
        result, run = self._validate(max_requests=5)
        self.assertEqual(len(self.target.requests), 5)
        self.assertEqual(run.budget.used, 5)
        self.assertIn("budget", result.summary)

    def test_exhausted_budget_stops_a_long_running_tool(self):
        self.env.update(I05D_REQUESTS="40", I05D_DELAY="0.25")    # ~10 s if not stopped
        start = time.monotonic()
        result, run = self._validate(max_requests=3)
        took = time.monotonic() - start
        self.assertEqual(len(self.target.requests), 3)
        self.assertIn("budget", result.summary)
        self.assertLess(took, 6.0, "the tool kept running after the run's budget ran out")

    def test_disabled_stop_signal_is_detected(self):
        """Fault injection: without the proxy's stop signal the tool runs to its end."""
        self.env.update(I05D_REQUESTS="40", I05D_DELAY="0.25")
        start = time.monotonic()
        with patch.object(tool_proxy.ToolProxy, "stop_requested", property(lambda self: False)):
            self._validate(max_requests=3)
        self.assertGreater(time.monotonic() - start, 6.0,
                           "ignoring the stop signal no longer matters -- the control is vacuous")
        self.assertEqual(len(self.target.requests), 3, "the budget itself still holds")

    def test_credentials_reach_the_target_through_the_run(self):
        self._validate(headers={"Authorization": "Bearer i05d-tool"})
        seen = {r[2].get("authorization") for r in self._tool_requests()}
        self.assertEqual(seen, {"Bearer i05d-tool"})

    def test_container_tool_traffic_is_counted_by_the_run(self):
        with patch.object(tool_runner, "available", return_value=(True, "")), \
                patch.object(tool_runner, "_force_remove", return_value=True):
            result, run = self._validate(container_image="harness/sqlmap:test")
        self.assertEqual(len(self._tool_requests()), 12, self.target.requests)
        self.assertEqual(len(self.target.requests), run.budget.used)

    def test_forwarding_loss_is_detected(self):
        """Fault injection: the tool is handed the real target URL, bypassing the proxy."""
        with patch.object(tool_proxy.ToolProxy, "url_for", lambda self, url: url):
            result, run = self._validate()
        self.assertGreater(len(self.target.requests), run.budget.used,
                           "bypassing the proxy is no longer visible -- the control is vacuous")


# --- R34: a redirect is followed on the address the tool can reach -----------------------
_REDIRECT_TOOL = r'''
import http.client, json, os, sys
from urllib.parse import urljoin, urlsplit
args = sys.argv[1:]
url = args[args.index("-u") + 1]
in_container = urlsplit(url).hostname == "host.docker.internal"

def get(u):
    # Inside a container, host.docker.internal reaches the host (Docker Desktop maps it
    # to the host's loopback, emulated here) and 127.0.0.1 is the container itself.
    p = urlsplit(u)
    conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
    conn.request("GET", p.path + (f"?{p.query}" if p.query else ""), headers={"Host": p.netloc})
    r = conn.getresponse()
    r.read()
    conn.close()
    return r.status, r.getheader("Location")

status, location = get(url)
seen = {"first": status, "location": location}
if location:
    nxt = urljoin(url, location)      # resolved against what the tool requested
    seen["resolved"] = nxt
    if in_container and urlsplit(nxt).hostname in ("127.0.0.1", "localhost"):
        seen["followed"] = "unreachable: container loopback"
    else:
        seen["followed"] = get(nxt)[0]
with open(os.environ["I05D_OUT"], "w", encoding="utf-8") as f:
    json.dump(seen, f)
'''


class _RedirectTarget:
    """Owned loopback target: the scanned URL answers 302 with an ABSOLUTE same-origin
    Location; /landed answers 200. Records each request it receives."""

    def __init__(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        self.requests: list[tuple[str, str, dict, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.requests.append((self.command, self.path, {}, ""))
                if self.path.startswith("/landed"):
                    self.send_response(200)
                else:
                    self.send_response(302)
                    self.send_header("Location", f"{outer.base}/landed?from=302")
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(5)


class ToolProxyRedirectCallerTests(_AccountingFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        Path(self.tool).write_text(_REDIRECT_TOOL, encoding="utf-8")
        self.target.close()
        self.target = _RedirectTarget()
        self.env["I05D_OUT"] = os.path.join(self._tmp, "seen.json")

    def _seen(self) -> dict:
        import json
        return json.loads(Path(self.env["I05D_OUT"]).read_text(encoding="utf-8"))

    def _container_validate(self):
        with patch.object(tool_runner, "available", return_value=(True, "")), \
                patch.object(tool_runner, "_force_remove", return_value=True):
            return self._validate(container_image="harness/sqlmap:test")

    def test_container_follows_a_same_origin_redirect_through_the_proxy(self):
        _, run = self._container_validate()
        seen = self._seen()
        self.assertEqual(urlsplit(seen["resolved"]).hostname, "host.docker.internal", seen)
        self.assertEqual(seen["followed"], 200, seen)
        self.assertEqual([r[1] for r in self.target.requests if r[1].startswith("/landed")],
                         ["/landed?from=302"])
        self.assertEqual(len(self.target.requests), run.budget.used)

    def test_host_tool_keeps_loopback(self):
        """Control: on the host the redirect resolves to the proxy on 127.0.0.1."""
        _, run = self._validate()
        seen = self._seen()
        self.assertEqual(urlsplit(seen["resolved"]).hostname, "127.0.0.1", seen)
        self.assertEqual(seen["followed"], 200, seen)
        self.assertEqual(len(self.target.requests), 2)
        self.assertEqual(run.budget.used, 2)

    def test_absolute_loopback_rewrite_is_detected(self):
        """Fault injection: the pre-R34 rewrite to http://127.0.0.1:<port> strands a container."""
        def absolute(proxy, request_url, location):
            p = urlsplit(location)
            return f"http://{proxy.bind_host}:{proxy.port}{p.path}?{p.query}"

        with patch.object(tool_proxy.ToolProxy, "_rewrite_location", absolute):
            self._container_validate()
        seen = self._seen()
        self.assertEqual(seen["followed"], "unreachable: container loopback",
                         "the loopback rewrite no longer strands the container -- the control is vacuous")
        self.assertFalse([r for r in self.target.requests if r[1].startswith("/landed")])


# --- R35: a stalled client cannot hold the proxy or its caller --------------------------
async def _pre_r35_close(proxy):
    """The close() before R35: stop listening, then wait for every client to finish."""
    server, proxy._server = proxy._server, None
    if server is not None:
        server.close()
        await server.wait_closed()


class ToolProxyStalledClientCallerTests(_AccountingFixture, unittest.TestCase):
    """A client that half-opens a proxy connection and never finishes its request --
    a stray local process, or a forwarder that keeps the host side open -- while the
    validator's own tool runs normally."""

    def setUp(self):
        super().setUp()
        self.env["I05D_REQUESTS"] = "3"
        self.stalled: list[socket.socket] = []
        self.replies: list[bytes] = []
        real_start = tool_proxy.ToolProxy.start
        fixture = self

        async def start_with_stalled_client(proxy):
            await real_start(proxy)
            sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            sock.sendall(b"GET /api/items/7?stalled=1 HTTP/1.1\r\n")   # never finished
            fixture.stalled.append(sock)
            threading.Thread(target=fixture._read_reply, args=(sock,), daemon=True).start()
            return proxy

        self.stall = patch.object(tool_proxy.ToolProxy, "start", start_with_stalled_client)

    def _read_reply(self, sock: socket.socket) -> None:
        data = b""
        try:
            while chunk := sock.recv(4096):
                data += chunk
        except OSError:
            pass
        self.replies.append(data)

    def tearDown(self):
        for sock in self.stalled:
            sock.close()
        super().tearDown()

    def test_validator_returns_while_a_client_is_stalled(self):
        start = time.monotonic()
        result, run = self._validate(extra_patches=(self.stall,), bound=15)
        self.assertLess(time.monotonic() - start, 12.0)
        self.assertEqual(len(self._tool_requests()), 3, "control: the tool's requests are served")
        self.assertEqual(len(self.target.requests), run.budget.used)
        self.assertFalse([r for r in self.target.requests if "stalled=1" in r[1]],
                         "an unfinished request was forwarded")

    def test_stalled_client_gets_408_within_the_deadline_while_open(self):
        self.env.update(I05D_REQUESTS="2", I05D_DELAY="1.0")   # the proxy stays open ~2 s
        with patch.object(tool_proxy, "_CLIENT_TIMEOUT_SECONDS", 0.5):
            result, run = self._validate(extra_patches=(self.stall,), bound=15)
        end = time.monotonic() + 3
        while not self.replies and time.monotonic() < end:
            time.sleep(0.02)
        # Only the deadline answers 408; close() would abort the connection without a reply.
        self.assertTrue(self.replies and self.replies[0].startswith(b"HTTP/1.1 408"), self.replies)
        self.assertEqual(len(self._tool_requests()), 2, "control: the tool's requests are served")

    def test_unbounded_close_is_detected(self):
        """Fault injection: the pre-R35 close() waits on the stalled client, so the
        validator does not return within the test's own bound (and does not hang)."""
        with patch.object(tool_proxy, "_CLIENT_TIMEOUT_SECONDS", 3600.0), \
                patch.object(tool_proxy.ToolProxy, "close", _pre_r35_close):
            with self.assertRaises(asyncio.TimeoutError,
                                   msg="an unbounded close() no longer hangs -- the control is vacuous"):
                self._validate(extra_patches=(self.stall,), bound=5)


class ToolProxyBoundaryTests(unittest.TestCase):
    """The proxy itself: off-origin redirects and refusals never reach anything."""

    def test_off_origin_redirect_is_rewritten_to_a_refusal(self):
        proxy = tool_proxy.ToolProxy(None, "http://127.0.0.1:1/", capability="t")
        proxy.port = 4242
        self.assertEqual(proxy._rewrite_location("http://127.0.0.1:1/a", "/next"), "/next")
        self.assertEqual(proxy._rewrite_location("http://127.0.0.1:1/a/b", "c"), "/a/c")
        # Same origin: origin-relative, so the tool keeps the proxy address it used (R34).
        self.assertEqual(proxy._rewrite_location("http://127.0.0.1:1/a", "http://127.0.0.1:1/b?c=1"),
                         "/b?c=1")
        for off in ("http://evil.test/x", "//evil.test/x", "http://127.0.0.1:1//evil.test/x"):
            self.assertEqual(proxy._rewrite_location("http://127.0.0.1:1/a", off),
                             tool_proxy._OFF_ORIGIN_PATH, off)

    def test_proxy_serves_exactly_one_origin(self):
        proxy = tool_proxy.ToolProxy(None, "http://127.0.0.1:1/", capability="t")
        proxy.port = 4242
        with self.assertRaises(ValueError):
            proxy.url_for("http://other.test/x")


if __name__ == "__main__":
    unittest.main()
