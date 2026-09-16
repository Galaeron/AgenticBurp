"""Tests for the container tool-runner (docker seam mocked -- no real Docker)."""
import subprocess
import unittest
from unittest.mock import patch

import tool_runner as tr


class LocalhostRewriteTests(unittest.TestCase):
    def test_loopback_hosts_rewritten_to_host_alias(self):
        self.assertEqual(tr.localhost_url("http://127.0.0.1:5002/api/x?q=1"),
                         "http://host.docker.internal:5002/api/x?q=1")
        self.assertEqual(tr.localhost_url("http://localhost/a"),
                         "http://host.docker.internal/a")

    def test_non_loopback_left_alone(self):
        self.assertEqual(tr.localhost_url("http://shop.test:8080/x"),
                         "http://shop.test:8080/x")

    def test_port_and_path_preserved(self):
        self.assertEqual(tr.localhost_url("https://127.0.0.1:8443/p/q?a=b"),
                         "https://host.docker.internal:8443/p/q?a=b")


class DockerCmdTests(unittest.TestCase):
    def test_cmd_is_ephemeral_and_adds_host_gateway(self):
        cmd = tr.docker_cmd("img:1", ["-u", "http://host.docker.internal/x", "--batch"])
        self.assertIn("run", cmd)
        self.assertIn("--rm", cmd)
        self.assertIn("--add-host", cmd)
        self.assertIn("host.docker.internal:host-gateway", cmd)
        # image precedes tool args, args preserved in order
        i = cmd.index("img:1")
        self.assertEqual(cmd[i + 1:], ["-u", "http://host.docker.internal/x", "--batch"])

    def test_add_host_can_be_disabled(self):
        cmd = tr.docker_cmd("img:1", ["x"], add_host=False)
        self.assertNotIn("--add-host", cmd)

    def test_sandbox_hardening_flags_present_by_default(self):
        # W-26: drop caps, block privilege escalation, cap pids/cpu/memory.
        cmd = tr.docker_cmd("img:1", ["x"])
        self.assertIn("--cap-drop", cmd)
        self.assertIn("ALL", cmd)
        self.assertIn("--pids-limit", cmd)
        self.assertIn("--memory", cmd)
        self.assertIn("--cpus", cmd)
        # --security-opt no-new-privileges pairs correctly
        j = cmd.index("--security-opt")
        self.assertEqual(cmd[j + 1], "no-new-privileges")
        # hardening precedes the image and never intrudes on the tool args
        self.assertLess(cmd.index("--cap-drop"), cmd.index("img:1"))

    def test_sandbox_hardening_can_be_disabled(self):
        cmd = tr.docker_cmd("img:1", ["x"], harden=False)
        self.assertNotIn("--cap-drop", cmd)
        self.assertNotIn("no-new-privileges", cmd)
        # still ephemeral even without the extra hardening
        self.assertIn("--rm", cmd)


class AvailableTests(unittest.TestCase):
    def test_available_true_when_daemon_answers(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "27.0.3\n", "")):
            ok, reason = tr.available()
        self.assertTrue(ok)
        self.assertEqual(reason, "27.0.3")

    def test_unavailable_when_daemon_silent(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "cannot connect")):
            ok, reason = tr.available()
        self.assertFalse(ok)
        self.assertIn("start docker", reason.lower())

    def test_unavailable_on_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 8)):
            ok, reason = tr.available()
        self.assertFalse(ok)
        self.assertIn("did not respond", reason)


class RunTests(unittest.TestCase):
    def test_run_invokes_docker_and_returns_streams(self):
        captured = {}
        def fake_run(cmd, capture_output, text, timeout):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, "found injectable", "")
        with patch("subprocess.run", fake_run):
            rc, out, err = tr.run("harness/sqlmap:1.10.9", ["-u", "http://host.docker.internal/x"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "found injectable")
        self.assertEqual(captured["cmd"][:3], [tr.DOCKER, "run", "--rm"])
        self.assertIn("harness/sqlmap:1.10.9", captured["cmd"])


class ContainerCleanupTests(unittest.TestCase):
    """#11: a timed-out container is verifiably force-removed, not just abandoned."""

    def test_timeout_force_removes_named_container(self):
        runs = []

        def fake_run(cmd, **kw):
            runs.append(cmd)
            if cmd[:3] == [tr.DOCKER, "run", "--rm"] or (len(cmd) > 1 and cmd[1] == "run"):
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
            class _R: returncode = 0; stdout = ""; stderr = ""
            return _R()

        with patch("subprocess.run", side_effect=fake_run):
            with self.assertRaises(subprocess.TimeoutExpired):
                tr.run("img", ["-x"], timeout=1)
        # the run cmd carried a unique --name, and a `docker rm -f <name>` followed
        run_cmd = runs[0]
        self.assertIn("--name", run_cmd)
        name = run_cmd[run_cmd.index("--name") + 1]
        self.assertTrue(any(c[:2] == [tr.DOCKER, "rm"] and name in c for c in runs[1:]))


if __name__ == "__main__":
    unittest.main()
