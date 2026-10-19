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
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
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

    def _validate(self, *, max_requests=100, headers=None, extra_patches=(), **validator_kw):
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=max_requests)
        exchange = HttpExchange(url=f"{self.target.base}/api/items/7", method="GET",
                                request_headers=dict(headers or {}), response_status=200,
                                response_body='{"id": 7}')
        validator = SqlmapValidator(binary=_FAKE_SQLMAP, timeout_seconds=30,
                                    allowed_hosts=["127.0.0.1"], run_context=run, **validator_kw)

        async def go():
            try:
                async with run:
                    return await validator.validate(_sqli(), exchange)
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


class ToolProxyBoundaryTests(unittest.TestCase):
    """The proxy itself: off-origin redirects and refusals never reach anything."""

    def test_off_origin_redirect_is_rewritten_to_a_refusal(self):
        proxy = tool_proxy.ToolProxy(None, "http://127.0.0.1:1/", capability="t")
        proxy.port = 4242
        self.assertEqual(proxy._rewrite_location("http://127.0.0.1:1/a", "/next"), "/next")
        self.assertEqual(proxy._rewrite_location("http://127.0.0.1:1/a", "http://127.0.0.1:1/b?c=1"),
                         "http://127.0.0.1:4242/b?c=1")
        self.assertTrue(proxy._rewrite_location("http://127.0.0.1:1/a", "http://evil.test/x")
                        .endswith(tool_proxy._OFF_ORIGIN_PATH))

    def test_proxy_serves_exactly_one_origin(self):
        proxy = tool_proxy.ToolProxy(None, "http://127.0.0.1:1/", capability="t")
        proxy.port = 4242
        with self.assertRaises(ValueError):
            proxy.url_for("http://other.test/x")


if __name__ == "__main__":
    unittest.main()
