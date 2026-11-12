"""Bounded recursive content discovery, through investigate_engagement (the
production caller: config -> build_engagement -> crawl_roles -> SurfaceDiscovery).

Discovery used to stop at the first level: a directory it found (/static
redirecting to /static/) was never looked inside. engagement.discovery_recursion_depth
(default 0: off) and engagement.discovery_recursion_max_requests now let it probe
the wordlist under each directory it found, then under the directories that turns
up, to the configured depth and within the request cap.

The loopback target is a generic directory tree:
  /static -> /static/ (403), /static/reports -> /static/reports/ (403),
  /static/reports/export (200), /static/reports/archive -> .../archive/ (403),
  /static/reports/archive/backup (200, three levels down),
  /static/mirror -> 302 to a second server on 127.0.0.2 (out of scope),
  /files -> /files/ (a directory index linking to the 127.0.0.2 server),
  /files/config (200).
  - on, depth 2: the second-level routes are found; nothing at the third level is
    requested, and the depth-cap note names the directory left unexpanded.
  - on, small request cap: recursion spends at most the cap and says so.
  - off (the committed config): nothing below the first level is probed.
  - in-run ffuf on: each expanded directory is scanned by ffuf through the run.
  - every case: the out-of-scope server receives nothing, and recursion sends GETs.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch

from harness import api_surface_discovery, cache, store, tool_runner
from harness.api_surface_discovery import SurfaceDiscovery
from harness.orchestrator import Orchestrator
from harness.test_discovery_ffuf_in_run import _FAKE_FFUF, _IMAGE_ID, _REPO_DIGEST
from harness.test_engagement_transport_callers import _Model, _install_model
from harness.test_param_dispatch_caller import ROLES, _config

_REAL_POPEN = subprocess.Popen
_WORDS = ("static", "files", "reports", "export", "archive", "backup", "mirror", "config")
_DIRS = ("/static/", "/files/")


class _Recorder(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, host, handler):
        super().__init__((host, 0), handler)
        self.seen: list[tuple[str, str]] = []
        self.base = f"http://{host}:{self.server_address[1]}"
        threading.Thread(target=self.serve_forever, daemon=True).start()


class _Outside(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append((self.command, self.path))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = do_GET

    def log_message(self, *args):
        pass


class _Tree(BaseHTTPRequestHandler):
    def _route(self, path):
        outside = self.server.outside
        if path == "/":
            return 200, {}, b"<html><body><h1>home</h1></body></html>"
        if path in ("/static", "/static/reports", "/static/reports/archive", "/files"):
            return 301, {"Location": path + "/"}, b""
        if path in ("/static/", "/static/reports/", "/static/reports/archive/"):
            return 403, {}, b"<html><body>Forbidden: directory browsing is off</body></html>"
        if path == "/files/":
            return 200, {}, (f'<html><head><title>Index of /files/</title></head><body>'
                             f'<a href="config">config</a> '
                             f'<a href="{outside}/files/outside/">mirror</a></body></html>').encode()
        if path == "/static/mirror":
            return 302, {"Location": f"{outside}/static/mirror/"}, b""
        if path in ("/static/reports/export", "/static/reports/archive/backup", "/files/config"):
            return 200, {}, f"<html><body>contents of {path}</body></html>".encode()
        return 404, {}, b"<html><body>Not Found</body></html>"

    def do_GET(self):
        self.server.seen.append((self.command, self.path))
        status, headers, body = self._route(self.path.split("?")[0])
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.server.seen.append((self.command, self.path))
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _refuse(self):
        self.server.seen.append((self.command, self.path))
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _refuse

    def log_message(self, *args):
        pass


def _below_first_level(path: str) -> bool:
    """A path under one of the tree's directories, beyond the first-level sweep's
    own id-scoped guess (/static/1)."""
    path = path.split("?")[0]
    return path.startswith(_DIRS) and path not in ("/static/1", "/files/1")


class DiscoveryRecursionCallerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="discovery_recursion_")
        orig_db, orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))

        def restore():
            store._DB_PATH, cache._cache = orig_db, orig_cache
            shutil.rmtree(self._tmp, ignore_errors=True)
        self.addCleanup(restore)
        self.outside = _Recorder("127.0.0.2", _Outside)
        self.target = _Recorder("127.0.0.1", _Tree)
        self.target.outside = self.outside.base
        for server in (self.target, self.outside):
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)

    def _investigate(self, engagement_cfg=None, *, extra_patches=()):
        cfg = _config()
        cfg["validators"]["allow_mutating_replay"] = False
        cfg["engagement"].update(engagement_cfg or {})
        orch = Orchestrator(cfg)
        _install_model(orch, _Model([]))        # no model server is ever called
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        probes: list[tuple[str, str]] = []
        real_probe = SurfaceDiscovery._probe

        async def probe_spy(disc, method, path):
            probes.append((method, path))
            return await real_probe(disc, method, path)

        async def investigate():
            from harness.orchestrator_helpers import per_run_gate_config
            from harness.run_context import RunContext
            async with RunContext.create(
                    allowed_hosts=["127.0.0.1"], config=cfg, max_requests=5000,
                    gate_config=per_run_gate_config(cfg, orch.validator_registry)) as ctx:
                return await orch.investigate_engagement(
                    self.target.base, ROLES, max_nodes=0, step_budget=1, max_chain_rounds=0,
                    discovery_max_probes=600, run_context=ctx)

        patches = [patch.object(api_surface_discovery, "DEFAULT_NOUNS", _WORDS),
                   patch.object(api_surface_discovery, "DEFAULT_PREFIXES", ("/",)),
                   patch.object(api_surface_discovery, "DEFAULT_COLLECTIONS", ()),
                   patch.object(api_surface_discovery, "DEFAULT_ACTIONS", ()),
                   patch.object(api_surface_discovery, "DEFAULT_SENSITIVE_FILES", ()),
                   patch.object(SurfaceDiscovery, "_probe", new=probe_spy),
                   patch("harness.browser_driver.default_driver", return_value=None),
                   patch("harness.orchestrator_chain.shape_precondition_legs", return_value=[]),
                   *extra_patches]
        for p in patches:
            p.start()
        try:
            result = asyncio.run(investigate())
        finally:
            for p in reversed(patches):
                p.stop()
        self.assertEqual(self.outside.seen, [], "the out-of-scope server was requested")
        recursion_notes = [n for n in result.get("discovery_bounds") or []
                           if n.startswith("recursive discovery")]
        return probes, recursion_notes

    def assertGetOnlyBelowFirstLevel(self, probes):
        # Recursion sends GETs; the only other verb is the existing OPTIONS method
        # mining, and only on routes discovery already found.
        sent = {(m, p) for m, p in probes if _below_first_level(p)}
        self.assertEqual({m for m, _p in sent} - {"GET", "OPTIONS"}, set())
        got = {p for m, p in sent if m == "GET"}
        self.assertEqual({p for m, p in sent if m == "OPTIONS"} - got, set())
        self.assertEqual({m for m, p in self.target.seen if _below_first_level(p)} - {"GET", "OPTIONS"},
                         set())

    def test_depth_two_finds_second_level_routes_and_stops_at_the_depth_cap(self):
        probes, notes = self._investigate({"discovery_recursion_depth": 2,
                                           "discovery_recursion_max_requests": 400})
        probed = {p for m, p in probes if m == "GET"}
        for path in ("/static/reports", "/static/reports/export", "/static/reports/archive",
                     "/files/config"):
            self.assertIn(path, probed)
        # Third level: never requested by anything.
        self.assertFalse([p for _m, p in self.target.seen if p.startswith("/static/reports/archive/")
                          and p != "/static/reports/archive/"], self.target.seen)
        # The out-of-scope redirect was probed, and its follow refused (setUp's check).
        self.assertIn("/static/mirror", probed)
        self.assertEqual(len(notes), 1, notes)
        self.assertIn("2 of 2 level(s)", notes[0])
        self.assertIn("1 director(ies) found at the depth cap were not expanded", notes[0])
        self.assertGetOnlyBelowFirstLevel(probes)

    def test_the_request_cap_bounds_the_recursion(self):
        cap = 9
        probes, notes = self._investigate({"discovery_recursion_depth": 3,
                                           "discovery_recursion_max_requests": cap})
        below = {p for m, p in probes if m == "GET" and _below_first_level(p) and "?" not in p}
        self.assertLessEqual(len(below), cap, sorted(below))
        self.assertTrue(below)
        self.assertNotIn("/static/reports/archive/backup", {p for _m, p in self.target.seen})
        self.assertEqual(len(notes), 1, notes)
        self.assertIn(f" of {cap} request(s)", notes[0])
        self.assertIn("unexpanded at its request cap", notes[0])
        self.assertGetOnlyBelowFirstLevel(probes)

    def test_control_committed_config_probes_nothing_below_the_first_level(self):
        probes, notes = self._investigate()
        self.assertEqual(notes, [])
        self.assertEqual(sorted({p for _m, p in probes if _below_first_level(p)}), [])
        # The directories themselves were found, so only recursion was missing.
        self.assertIn("/static", {p for _m, p in probes})
        self.assertNotIn("/static/reports", {p for _m, p in self.target.seen})

    def test_in_run_ffuf_scans_each_expanded_directory_through_the_run(self):
        tmp = Path(self._tmp)
        tool, wordlist = tmp / "ffuf.py", tmp / "words.txt"
        tool.write_text(_FAKE_FFUF, encoding="utf-8")
        wordlist.write_text("\n".join(_WORDS), encoding="utf-8")
        launched: list[list[str]] = []

        class _SwapPopen(_REAL_POPEN):
            def __init__(self, args, *a, **kw):
                if (isinstance(args, (list, tuple)) and args
                        and str(args[0]) == tool_runner.DOCKER and list(args[1:2]) == ["run"]):
                    launched.append([str(x) for x in args])
                    args = [sys.executable, str(tool), *args[1:]]
                    kw["env"] = {**(kw.get("env") or os.environ),
                                 "FAKE_FFUF_WORDLIST": str(wordlist)}
                super().__init__(args, *a, **kw)

        ffuf_patches = (
            patch("subprocess.Popen", _SwapPopen),
            patch.object(tool_runner, "available", return_value=(True, "")),
            patch.object(tool_runner, "image_present", return_value=True),
            patch.object(tool_runner, "local_image_digests",
                         side_effect=lambda image, timeout=10.0: (
                             _IMAGE_ID, [f"harness/ffuf@{_REPO_DIGEST}"])),
            patch.object(tool_runner, "_force_remove", return_value=True))
        probes, notes = self._investigate({"discovery_ffuf": True,
                                           "discovery_recursion_depth": 2,
                                           "discovery_recursion_max_requests": 400},
                                          extra_patches=ffuf_patches)
        targets = [args[args.index("-u") + 1] for args in launched]
        # The root scan, then one per directory: /files/ and /static/, then
        # /static/reports/ at the second level.
        self.assertEqual(len(targets), 4, targets)
        for directory in ("/files/", "/static/", "/static/reports/"):
            self.assertTrue([t for t in targets if t.endswith(directory + "FUZZ")], (directory, targets))
        self.assertTrue(all(self.target.base.rsplit(":", 1)[1] not in t for t in targets),
                        "ffuf was handed the real target")
        # ffuf's hits under each directory are re-checked by the harness.
        self.assertIn("/static/reports/export", {p for m, p in probes if m == "GET"})
        self.assertEqual(len(notes), 1, notes)
        self.assertGetOnlyBelowFirstLevel(probes)


class DiscoveryRecursionConfigTests(unittest.TestCase):
    """engagement.discovery_recursion_depth / _max_requests -> build_engagement kwargs."""

    def _kw(self, engagement):
        from types import SimpleNamespace
        from harness.orchestrator_chain import ChainMixin
        return ChainMixin._discovery_recursion_kw(SimpleNamespace(config={"engagement": engagement}))

    def test_off_unless_both_the_depth_and_the_cap_are_positive(self):
        self.assertEqual(self._kw({}), {})
        for engagement in ({"discovery_recursion_depth": 0, "discovery_recursion_max_requests": 900},
                           {"discovery_recursion_depth": 2, "discovery_recursion_max_requests": 0},
                           {"discovery_recursion_depth": -1, "discovery_recursion_max_requests": 900},
                           {"discovery_recursion_depth": "deep", "discovery_recursion_max_requests": 9},
                           # passive-only forces the depth knob to False
                           {"discovery_recursion_depth": False, "discovery_recursion_max_requests": 9},
                           {"discovery_recursion_depth": True, "discovery_recursion_max_requests": 9}):
            with self.subTest(engagement=engagement):
                self.assertEqual(self._kw(engagement), {})

    def test_on_passes_the_depth_and_the_cap(self):
        self.assertEqual(self._kw({"discovery_recursion_depth": 2,
                                   "discovery_recursion_max_requests": 900}),
                         {"discovery_recursion_depth": 2, "discovery_recursion_max_requests": 900})

    def test_the_depth_is_capped_by_discovery(self):
        disc = SurfaceDiscovery("http://127.0.0.1:1", recursion_depth=50, recursion_max_requests=10)
        self.assertEqual(disc.recursion_depth, api_surface_discovery._MAX_RECURSION_DEPTH)

    def test_committed_config_keeps_the_current_behaviour(self):
        import yaml
        cfg = yaml.safe_load((Path(__file__).resolve().parent / "config.yaml").read_text(encoding="utf-8"))
        self.assertEqual(cfg["engagement"]["discovery_recursion_depth"], 0)
        self.assertEqual(self._kw(cfg["engagement"]), {})

    def test_passive_only_forces_recursion_off(self):
        import yaml
        from harness import config_schema
        cfg = yaml.safe_load((Path(__file__).resolve().parent / "config.yaml").read_text(encoding="utf-8"))
        cfg["engagement"]["discovery_recursion_depth"] = 3
        effective = config_schema.resolve_operating_profile(cfg, "passive-only")
        self.assertEqual(self._kw(effective["engagement"]), {})


if __name__ == "__main__":
    unittest.main()
