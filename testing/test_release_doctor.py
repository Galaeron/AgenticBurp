"""Tests for the SC-14 release doctor (offline tiers).

Each tier's check has a positive and a negative-control case; the aggregate
``report`` is ready only when required checks pass, and a runtime-gated check is
never counted as passing.
"""
from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from testing import release_doctor as rd


class CheckFunctionTests(unittest.TestCase):
    def test_dependency_present_and_absent(self):
        self.assertEqual(rd.check_dependency("json")["status"], "ok")          # positive
        self.assertEqual(rd.check_dependency("no_such_pkg_xyz")["status"], "missing")  # neg

    def test_file_present_and_absent(self):
        self.assertEqual(rd.check_file("harness/config.yaml")["status"], "ok")  # positive
        self.assertEqual(rd.check_file("nope/does-not-exist.txt")["status"], "missing")  # neg

    def test_executable_present_and_absent(self):
        with patch("shutil.which", return_value="/usr/bin/thing"):
            self.assertEqual(rd.check_executable("thing")["status"], "ok")      # positive
        with patch("shutil.which", return_value=None):
            self.assertEqual(rd.check_executable("thing")["status"], "missing")  # neg control

    def test_service_reachable_and_unreachable(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            port = srv.getsockname()[1]
            self.assertEqual(  # positive: a bound loopback listener is reachable
                rd.check_service("t", "127.0.0.1", port)["status"], "ok")
        finally:
            srv.close()
        # negative control: nothing listening on that just-closed port
        self.assertEqual(rd.check_service("t", "127.0.0.1", port)["status"], "unreachable")


class ReportTests(unittest.TestCase):
    def test_ready_only_when_required_pass(self):  # positive
        results = [rd.check_dependency("json"), rd.check_file("harness/config.yaml")]
        self.assertTrue(rd.report(results)["ready"])

    def test_required_failure_blocks_ready(self):  # negative control
        results = [rd.check_dependency("json"),
                   rd.check_dependency("no_such_pkg_xyz")]  # required, missing
        rep = rd.report(results)
        self.assertFalse(rep["ready"])
        self.assertEqual(len(rep["required_failures"]), 1)

    def test_runtime_placeholder_never_blocks_or_passes(self):  # negative control
        # A runtime-gated tier is surfaced but not counted as an OK, and (being
        # non-required) does not falsely block readiness.
        placeholder = rd.runtime_placeholder("ollama", rd.TIER_MODEL, "start it")
        self.assertEqual(placeholder["status"], "requires_runtime")
        self.assertFalse(placeholder["required"])
        rep = rd.report([rd.check_dependency("json"), placeholder])
        self.assertTrue(rep["ready"])                       # not blocked by the placeholder
        self.assertEqual(rep["counts"].get("ok"), 1)        # placeholder is not an ok

    def test_default_checks_shape_is_tiered(self):
        rep = rd.report(rd.default_checks(runtime=False))
        # The full readiness taxonomy is represented, not a single verdict.
        for tier in (rd.TIER_DEPENDENCY, rd.TIER_FILE, rd.TIER_EXECUTABLE,
                     rd.TIER_MODEL, rd.TIER_AUTH, rd.TIER_BROWSER, rd.TIER_TOOL_SCOPE):
            self.assertIn(tier, rep["tiers"])


if __name__ == "__main__":
    unittest.main()
