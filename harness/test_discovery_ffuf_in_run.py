"""ffuf inside a pipeline run: its requests spend the run, through the tool proxy.

engagement.discovery_ffuf (default off) lets SurfaceDiscovery launch ffuf while a
RunContext owns the traffic. The launched program is an owned stand-in "ffuf"
(the swap happens inside subprocess.Popen, so the real ffuf_runner -> ToolBroker
-> tool_runner.run launch path runs): it reads the -u FUZZ URL, a wordlist file
and the -fs / -fc filters, sends one GET per word and prints ffuf's -json lines.
An owned SPA catch-all target counts what it actually receives.

Checks: every ffuf request is charged to the run budget (target count ==
budget.used); a share cap stops sending past discovery's own budget without
killing the scan; the Python sweep does not resend paths ffuf already sent; the
harness's soft-404 byte length reaches ffuf as -fs, and an ffuf hit the harness
fingerprint calls soft-404 is dropped and counted; with the flag off nothing is
launched. Docker is never run.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import tool_runner
from harness.api_surface_discovery import SurfaceDiscovery
from harness.run_context import RunContext
from harness.test_discovery_spa_wildcards import _SpaCatchAll

_REAL_POPEN = subprocess.Popen

_FAKE_FFUF = r'''
import base64, json, os, sys, urllib.error, urllib.request
args = sys.argv[1:]
url = args[args.index("-u") + 1].replace("host.docker.internal", "127.0.0.1")
headers = {}
for i, a in enumerate(args):
    if a == "-H":
        k, _, v = args[i + 1].partition(":")
        headers[k.strip()] = v.strip()
fs = None
if "-fs" in args and not os.environ.get("FAKE_FFUF_IGNORE_FS"):
    fs = int(args[args.index("-fs") + 1])
words = open(os.environ["FAKE_FFUF_WORDLIST"], encoding="utf-8").read().split()
for word in words:
    req = urllib.request.Request(url.replace("FUZZ", word), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    except Exception:
        continue
    if status == 404 or (fs is not None and len(body) == fs):
        continue
    print(json.dumps({"input": {"FUZZ": base64.b64encode(word.encode()).decode()},
                      "status": status, "length": len(body)}), flush=True)
'''


class FfufInRunTests(unittest.TestCase):
    WORDS = ["api/items", "api/nothing", "v1/nothing", "v1/ghost", "admin/real-panel"]

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ffuf_in_run_")
        self.tool = os.path.join(self._tmp, "ffuf.py")
        Path(self.tool).write_text(_FAKE_FFUF, encoding="utf-8")
        self.wordlist = os.path.join(self._tmp, "words.txt")
        Path(self.wordlist).write_text("\n".join(self.WORDS), encoding="utf-8")
        self.env = {"FAKE_FFUF_WORDLIST": self.wordlist}
        self.launched: list[list[str]] = []
        fixture = self

        class _SwapPopen(_REAL_POPEN):
            def __init__(self, args, *a, **kw):
                if (isinstance(args, (list, tuple)) and args
                        and str(args[0]) == tool_runner.DOCKER and list(args[1:2]) == ["run"]):
                    fixture.launched.append([str(x) for x in args])
                    args = [sys.executable, fixture.tool, *args[1:]]
                    kw["env"] = {**(kw.get("env") or os.environ), **fixture.env}
                super().__init__(args, *a, **kw)

        self._patches = [patch("subprocess.Popen", _SwapPopen),
                         patch.object(tool_runner, "available", return_value=(True, "")),
                         patch.object(tool_runner, "image_present", return_value=True),
                         patch.object(tool_runner, "_force_remove", return_value=True)]
        for p in self._patches:
            p.start()
        self.target = _SpaCatchAll()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        self.target.close()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _discover(self, *, ffuf_in_runs=True, max_probes=400, max_requests=5000, **kw):
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=max_requests)
        disc = SurfaceDiscovery(self.target.base, allowed_hosts=["127.0.0.1"],
                                nouns=["items", "nothing", "ghost"], prefixes=["/api/", "/v1/"],
                                collections=[], actions=[], sensitive_files=[],
                                max_probes=max_probes, run_context=run,
                                ffuf_in_runs=ffuf_in_runs, **kw)

        async def go():
            try:
                async with run:
                    return await asyncio.wait_for(disc.discover(), 60)
            finally:
                await run.aclose()
        return asyncio.run(go()), run

    def _sent(self, path):
        return sum(r == path for r in self.target.requests)

    def assertChargedToTheRun(self, result, run):
        # Every probe -- ffuf's included -- spends the run once; the target saw
        # every GET (it does not record the OPTIONS probes, hence <=).
        self.assertEqual(run.budget.used, result.probes_sent)
        self.assertLessEqual(len(self.target.requests), run.budget.used)

    def test_every_ffuf_request_is_charged_to_the_run(self):
        result, run = self._discover()
        self.assertEqual(len(self.launched), 1)
        url = self.launched[0][self.launched[0].index("-u") + 1]
        self.assertNotIn(self.target.base.rsplit(":", 1)[1], url, "ffuf was given the real target")
        self.assertEqual(result.ffuf_requests, len(self.WORDS))
        self.assertChargedToTheRun(result, run)
        for word in self.WORDS:
            self.assertGreaterEqual(self._sent("/" + word), 1, word)
        paths = {r.path for r in result.routes}
        self.assertIn("/api/items", paths)
        self.assertIn("/admin/real-panel", paths)

    def test_the_python_sweep_does_not_resend_what_ffuf_sent(self):
        result, _ = self._discover()
        for path in ("/api/nothing", "/v1/nothing", "/v1/ghost"):
            self.assertEqual(self._sent(path), 1, path)
        # The hit costs ffuf's request plus the harness re-check (the agreement
        # check) on top of what the sweep alone sends it -- no more.
        with_ffuf = self._sent("/api/items")
        self.target.requests.clear()
        self._discover(ffuf_in_runs=False)
        self.assertEqual(with_ffuf, self._sent("/api/items") + 1)
        self.assertTrue(any("ffuf covered" in e for e in result.errors), result.errors)

    def test_the_harness_soft404_length_reaches_ffuf_as_its_size_filter(self):
        self._discover()
        args = self.launched[0]
        self.assertIn("-ac", args)
        shell = len(('<!doctype html><html><head><script nonce="%s"></script></head>'
                     '<body><app-root></app-root></body></html>' % ("0" * 16)).encode())
        self.assertEqual(args[args.index("-fs") + 1], str(shell))

    def test_ffuf_hits_the_harness_calls_soft404_are_dropped_and_counted(self):
        self.env["FAKE_FFUF_IGNORE_FS"] = "1"      # ffuf's filter disagrees
        result, _ = self._discover()
        paths = {r.path for r in result.routes}
        self.assertNotIn("/v1/ghost", paths)
        self.assertNotIn("/api/nothing", paths)
        self.assertEqual(result.ffuf_soft404_disagreements, 3)

    def test_ffuf_share_is_capped_without_killing_the_scan(self):
        # Budget 40: the calibration and spec probes leave ffuf a share below the
        # wordlist, so the rest is answered 404 and never sent.
        self.WORDS = ["api/items"] + [f"api/word{i}" for i in range(60)]
        Path(self.wordlist).write_text("\n".join(self.WORDS), encoding="utf-8")
        result, run = self._discover(max_probes=40)
        self.assertLess(result.ffuf_requests, len(self.WORDS))
        self.assertGreater(result.ffuf_requests, 0)
        self.assertLessEqual(result.probes_sent, 40)
        self.assertChargedToTheRun(result, run)
        self.assertEqual(sum(r.startswith("/api/word") for r in self.target.requests),
                         result.ffuf_requests - 1)
        self.assertTrue(any("past its share were not sent" in e for e in result.errors),
                        result.errors)

    def test_forwarding_loss_is_detected(self):
        """Fault injection: ffuf handed the real target bypasses the run's budget."""
        from harness import tool_proxy
        with patch.object(tool_proxy.ToolProxy, "url_for", lambda self, url: url):
            result, run = self._discover()
        self.assertEqual(result.ffuf_requests, 0)
        self.assertGreater(len(self.target.requests), run.budget.used,
                           "bypassing the proxy is no longer visible -- the control is vacuous")

    def test_wordlist_choice_reaches_ffuf(self):
        self._discover()
        args = self.launched[0]
        self.assertEqual(args[args.index("-w") + 1], "/wordlist.txt")   # default: harness list
        self.launched.clear()
        self.target.requests.clear()
        result, run = self._discover(ffuf_wordlist="seclists")
        args = self.launched[0]
        self.assertEqual(args[args.index("-w") + 1], "/wordlist-seclists.txt")
        self.assertChargedToTheRun(result, run)

    def test_unknown_wordlist_is_refused_before_anything_runs(self):
        with self.assertRaises(ValueError):
            SurfaceDiscovery(self.target.base, allowed_hosts=["127.0.0.1"],
                             ffuf_wordlist="/etc/passwd")
        self.assertEqual(self.launched, [])

    def test_negative_control_ffuf_stays_off_in_runs_by_default(self):
        result, run = self._discover(ffuf_in_runs=False)
        self.assertEqual(self.launched, [])
        self.assertIn("ffuf skipped: external requests cannot spend the owning run budget",
                      result.errors)
        self.assertEqual(result.ffuf_requests, 0)
        self.assertChargedToTheRun(result, run)


class DiscoveryFfufConfigTests(unittest.TestCase):
    """engagement.discovery_ffuf / discovery_ffuf_wordlist -> build_engagement kwargs."""

    def _kw(self, engagement):
        from types import SimpleNamespace
        from harness.orchestrator_chain import ChainMixin
        return ChainMixin._discovery_ffuf_kw(SimpleNamespace(config={"engagement": engagement}))

    def test_off_passes_nothing_even_with_a_wordlist(self):
        self.assertEqual(self._kw({}), {})
        self.assertEqual(self._kw({"discovery_ffuf": False, "discovery_ffuf_wordlist": "seclists"}), {})

    def test_on_with_default_and_seclists_wordlist(self):
        self.assertEqual(self._kw({"discovery_ffuf": True}), {"discovery_ffuf": True})
        self.assertEqual(self._kw({"discovery_ffuf": True, "discovery_ffuf_wordlist": "harness"}),
                         {"discovery_ffuf": True})
        self.assertEqual(self._kw({"discovery_ffuf": True, "discovery_ffuf_wordlist": "seclists"}),
                         {"discovery_ffuf": True, "discovery_ffuf_wordlist": "seclists"})

    def test_committed_config_keeps_the_current_behaviour(self):
        import yaml
        cfg = yaml.safe_load((Path(__file__).resolve().parent / "config.yaml").read_text(encoding="utf-8"))
        self.assertIs(cfg["engagement"]["discovery_ffuf"], False)
        self.assertEqual(cfg["engagement"]["discovery_ffuf_wordlist"], "harness")


if __name__ == "__main__":
    unittest.main()
