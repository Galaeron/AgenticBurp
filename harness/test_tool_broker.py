"""SC-9: the per-tool bounded execution broker, driven through its callers.

Every run uses the real launch path (ToolBroker.run -> tool_runner.run ->
run_process) with the docker CLI swapped, inside subprocess.Popen, for the
harmless I05-C worker: it logs its PID, starts one child and sleeps, and never
touches the network. A fake docker CLI records `docker rm -f <name>`. Nothing
runs docker. Temp files stay inside the repository tree.

Checks: a cancel mid-run kills the owned tree and removes the exact container;
the output cap truncates; a timeout cleans up; an unboundable spec is rejected
before any launch; the receipt never claims that egress metadata confines the
tool. Fault injections (no tree cleanup, no container removal, no output cap)
must make the same checks fail.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import ffuf_runner, tool_runner
from harness.run_context import CancelToken
from harness.test_tool_process_lifecycle import _root_only_tree, _ToolFixture

_REPO_TMP = Path(__file__).resolve().parent.parent / ".test-work" / "_tmp"
_IMAGE = "harness/tool:test"
_DIGEST = "sha256:" + "ab" * 32


class _BrokerFixture(_ToolFixture):
    """The I05-C fixture, with its temp dir inside the repo (not %TEMP%)."""

    def setUp(self):
        _REPO_TMP.mkdir(parents=True, exist_ok=True)
        self._tmpdir_patch = patch.object(tempfile, "tempdir", str(_REPO_TMP))
        self._tmpdir_patch.start()
        super().setUp()

    def tearDown(self):
        try:
            super().tearDown()
        finally:
            self._tmpdir_patch.stop()
            try:
                _REPO_TMP.rmdir()
            except OSError:
                pass

    def _run_in_thread(self, broker, args=("-u", "http://x/"), **kw):
        box: dict = {"receipt": {}}

        def target():
            try:
                box["value"] = broker.run(list(args), receipt=box["receipt"], **kw)
            except BaseException as exc:          # noqa: BLE001 -- recorded for the test
                box["error"] = exc
            box["finished"] = time.monotonic()

        t = threading.Thread(target=target, daemon=True)
        t.start()
        return t, box

    # --- the checks, shared by the real tests and their fault injections -------------
    def cancel_mid_run(self, broker) -> dict:
        token = CancelToken()
        t, box = self._run_in_thread(broker, cancel=token)
        self.wait_started()
        cancelled_at = time.monotonic()
        token.cancel()
        t.join(15)
        box["joined"] = not t.is_alive()
        box["took"] = box.get("finished", float("inf")) - cancelled_at
        box["survivors"] = self.survivors()
        box["docker"] = self.docker_calls()
        t.join(15)
        return box

    def assert_cancel_cleaned(self, box: dict) -> None:
        self.assertTrue(box["joined"], "the broker kept waiting on a cancelled tool")
        self.assertIsInstance(box.get("error"), tool_runner.ToolRunCancelled, box)
        self.assertLess(box["took"], 5.0)
        self.assertEqual(box["survivors"], [], "a cancelled tool process survived")
        owned = box["receipt"]["broker"]["owned"]
        self.assertIn(["rm", "-f", owned["container_name"]], box["docker"],
                      "the exact owned container was not removed")
        self.assertEqual(owned["process_cleanup"], "terminated")
        self.assertEqual(owned["container_cleanup"], "force_removed")

    def timeout_run(self, broker) -> dict:
        box: dict = {"receipt": {}}
        try:
            broker.run(["-u", "http://x/"], receipt=box["receipt"])
        except BaseException as exc:              # noqa: BLE001 -- recorded for the test
            box["error"] = exc
        box["survivors"] = self.wait_gone()
        box["docker"] = self.docker_calls()
        return box

    def assert_timeout_cleaned(self, box: dict) -> None:
        self.assertIsInstance(box.get("error"), subprocess.TimeoutExpired, box)
        self.assertEqual(box["survivors"], [], "a timed-out tool's process survived")
        self.assertIn(["rm", "-f", box["receipt"]["container_name"]], box["docker"])
        self.assertEqual(box["receipt"]["broker"]["outcome"], "timeout")

    def capped_run(self, cap: int) -> tuple[str, dict]:
        self.env.update(I05C_SLEEP="0", I05C_CHILD="0", I05C_NOISE=str(1024 * 1024))
        receipt: dict = {}
        broker = tool_runner.ToolBroker(image=_IMAGE, timeout=60, max_output=cap)
        rc, out, _ = broker.run(["-x"], receipt=receipt)
        self.assertEqual(rc, 0)
        return out, receipt

    def assert_capped(self, out: str, receipt: dict, cap: int) -> None:
        marker = 64   # the "...[N bytes of output dropped]..." line
        self.assertLessEqual(len(out.encode("utf-8")), cap + marker, "output was not capped")
        self.assertTrue(out.rstrip().endswith("worker ready"), "the tail of the output was lost")
        self.assertGreater(receipt["stdout_dropped"], 1024 * 1024 - cap - 4096)


class BrokerLifecycleTests(_BrokerFixture, unittest.TestCase):
    def test_cancel_mid_run_kills_the_owned_tree_and_removes_the_exact_container(self):
        box = self.cancel_mid_run(tool_runner.ToolBroker(image=_IMAGE, timeout=60))
        self.assert_cancel_cleaned(box)
        self.assertIs(box["error"].receipt, box["receipt"])
        owned = box["receipt"]["broker"]["owned"]
        self.assertTrue(owned["container_name"].startswith("harness_"))
        self.assertIsInstance(owned["cli_pid"], int)
        # only the exact owned name was ever force-removed
        removed = [c[2] for c in box["docker"] if c[:2] == ["rm", "-f"]]
        self.assertEqual(removed, [owned["container_name"]])

    def test_timeout_cleans_up_the_tree_and_the_container(self):
        box = self.timeout_run(tool_runner.ToolBroker(image=_IMAGE, timeout=2))
        self.assert_timeout_cleaned(box)
        self.assertEqual(box["receipt"]["broker"]["timeout_seconds"], 2.0)

    def test_output_cap_truncates_while_read(self):
        cap = 64 * 1024
        out, receipt = self.capped_run(cap)
        self.assert_capped(out, receipt, cap)
        self.assertEqual(receipt["broker"]["max_output_bytes"], cap)

    def test_clean_exit_records_identity_and_removes_nothing(self):
        self.env.update(I05C_SLEEP="0", I05C_CHILD="0")
        receipt: dict = {}
        broker = tool_runner.ToolBroker(image=f"harness/tool@{_DIGEST}", timeout=20)
        rc, out, _ = broker.run(["--version"], receipt=receipt)
        self.assertEqual(rc, 0)
        self.assertIn("worker ready", out)
        self.assertEqual([c for c in self.docker_calls() if c[:1] == ["rm"]], [])
        block = receipt["broker"]
        self.assertEqual(block["image_digest"], _DIGEST)
        self.assertTrue(block["pinned"])
        self.assertEqual(block["outcome"], "exit=0")
        self.assertEqual(block["owned"]["container_cleanup"], "rm_on_exit_unverified")
        self.assertIn("--name", receipt["argv"])
        self.assertEqual(receipt["argv"][receipt["argv"].index("--name") + 1],
                         block["owned"]["container_name"])

    def test_ffuf_caller_cancel_stops_the_brokered_tool(self):
        token, box = CancelToken(), {}

        def target():
            box["result"] = ffuf_runner.run_sync("http://localhost:5002", cancel=token,
                                                 timeout=60)

        t = threading.Thread(target=target, daemon=True)
        t.start()
        self.wait_started()
        token.cancel()
        t.join(15)
        self.assertFalse(t.is_alive())
        self.assertIn("cancelled", box["result"].error or "")
        self.assertEqual(self.survivors(), [])
        self.assertTrue(any(c[:2] == ["rm", "-f"] for c in self.docker_calls()))

    def test_ffuf_caller_unboundable_timeout_launches_nothing(self):
        result = ffuf_runner.run_sync("http://localhost:5002", timeout=0)
        self.assertIn("timeout", result.error or "")
        self.assertEqual(self.events(), [])


class BrokerRejectionTests(_BrokerFixture, unittest.TestCase):
    """An unboundable spec is refused at construction: nothing is launched."""

    def assert_rejected(self, exc_type, **spec):
        with self.assertRaises(exc_type):
            tool_runner.ToolBroker(**{"image": _IMAGE, "timeout": 10, **spec})
        self.assertEqual(self.events(), [], "a rejected tool was launched")

    def test_unbounded_timeouts(self):
        for timeout in (0, -1, float("inf"), float("nan"), tool_runner.MAX_BROKER_TIMEOUT + 1,
                        True, "10"):
            with self.subTest(timeout=timeout):
                self.assert_rejected(tool_runner.ToolBrokerRejected, timeout=timeout)

    def test_unbounded_output_caps(self):
        for cap in (0, -5, tool_runner.MAX_BROKER_OUTPUT + 1, 1.5, True):
            with self.subTest(cap=cap):
                self.assert_rejected(tool_runner.ToolBrokerRejected, max_output=cap)

    def test_shared_namespace_networks(self):
        for network in ("host", "container:other", ""):
            with self.subTest(network=network):
                self.assert_rejected(tool_runner.ToolBrokerRejected,
                                     egress=tool_runner.EgressPolicy(network=network))

    def test_sandbox_widening_or_identity_flags(self):
        for extra in (["--privileged"], ["--network", "host"], ["--net=host"],
                      ["-v", "/:/host"], ["--mount", "type=bind,src=/,dst=/h"],
                      ["--cap-add", "NET_RAW"], ["--name", "other"], ["--pid=host"],
                      ["-e", "HTTP_PROXY="], ["--security-opt", "seccomp=unconfined"],
                      ["--tmpfs"]):
            with self.subTest(extra=extra):
                self.assert_rejected(tool_runner.ToolBrokerRejected, extra=extra)

    def test_image_and_egress_requirements(self):
        self.assert_rejected(tool_runner.ImageReferenceError, image="tool@sha256:abc")
        self.assert_rejected(tool_runner.ImageReferenceError, require_digest=True)
        self.assert_rejected(tool_runner.EgressPolicyRequired, enforce_egress=True)

    def test_control_narrowing_flags_are_accepted(self):
        broker = tool_runner.ToolBroker(image=_IMAGE, timeout=10,
                                        extra=["--read-only", "--tmpfs", "/tmp", "--user=1000"])
        self.assertEqual(broker.extra, ("--read-only", "--tmpfs", "/tmp", "--user=1000"))


class BrokerReceiptHonestyTests(unittest.TestCase):
    """Egress metadata is recorded, never reported as confinement."""

    def test_modes(self):
        cases = [
            (None, "unconfined", "none"),
            (tool_runner.EgressPolicy(), "unconfined", "none"),
            (tool_runner.EgressPolicy(allowed_hosts=("host.docker.internal",)),
             "unconfined", "declared_only"),
            (tool_runner.EgressPolicy(proxy_url="http://proxy:8080",
                                      allowed_hosts=("host.docker.internal",)),
             "advisory_proxy_env", "no_proxy_bypass"),
            (tool_runner.EgressPolicy(network="none"), "no_network", "none"),
        ]
        for egress, mode, hosts_role in cases:
            with self.subTest(egress=egress):
                block = tool_runner.ToolBroker(image=_IMAGE, timeout=5, egress=egress).describe()
                conf = block["confinement"]
                self.assertEqual(conf["mode"], mode)
                self.assertEqual(conf["allowed_hosts_role"], hosts_role)
                self.assertIs(conf["destinations_enforced"], False)
                self.assertIs(conf["proven"], False)

    def test_run_receipt_carries_the_same_record(self):
        egress = tool_runner.EgressPolicy(proxy_url="http://proxy:8080",
                                          allowed_hosts=("host.docker.internal",))
        receipt: dict = {}
        with patch.object(tool_runner, "run_process",
                          return_value=tool_runner.ProcessResult(
                              args=[], returncode=0, stdout="", stderr="", outcome="exit",
                              cleanup="not_needed", containment="job")):
            tool_runner.run(_IMAGE, [], egress=egress, receipt=receipt)
        self.assertEqual(receipt["egress_confinement"]["mode"], "advisory_proxy_env")
        self.assertIs(receipt["egress_confinement"]["destinations_enforced"], False)


class BrokerFaultInjectionTests(_BrokerFixture, unittest.TestCase):
    """With each cleanup removed, the lifecycle checks above must fail."""

    def test_no_tree_cleanup_on_cancel_is_detected(self):
        with patch.object(tool_runner, "_OwnedTree", _root_only_tree()):
            box = self.cancel_mid_run(tool_runner.ToolBroker(image=_IMAGE, timeout=60))
        with self.assertRaises(AssertionError):
            self.assert_cancel_cleaned(box)
        self.assertTrue(box["survivors"], "root-only cleanup no longer leaks -- vacuous control")

    def test_no_container_removal_on_cancel_is_detected(self):
        with patch.object(tool_runner, "_force_remove", return_value=True):
            box = self.cancel_mid_run(tool_runner.ToolBroker(image=_IMAGE, timeout=60))
        with self.assertRaises(AssertionError):
            self.assert_cancel_cleaned(box)

    def test_no_tree_cleanup_on_timeout_is_detected(self):
        with patch.object(tool_runner, "_OwnedTree", _root_only_tree()):
            box = self.timeout_run(tool_runner.ToolBroker(image=_IMAGE, timeout=2))
        with self.assertRaises(AssertionError):
            self.assert_timeout_cleaned(box)

    def test_no_output_cap_is_detected(self):
        cap = 64 * 1024
        real_sink = tool_runner._BoundedSink
        with patch.object(tool_runner, "_BoundedSink", lambda limit: real_sink(1 << 40)):
            out, receipt = self.capped_run(cap)
        with self.assertRaises(AssertionError):
            self.assert_capped(out, receipt, cap)


if __name__ == "__main__":
    unittest.main()
