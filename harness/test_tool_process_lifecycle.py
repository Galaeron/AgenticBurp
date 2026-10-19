"""I05 batch C: external-tool processes stop when their work is cancelled or times out.

Every external tool (sqlmap on the host or in a container, ffuf in a container)
is launched through the real launch path, but the launched program is replaced by
a harmless owned worker: it records its PID, starts one child, can print a large
amount of synthetic output, then sleeps. It never touches the network. The swap
happens inside subprocess.Popen, so whatever launches the tool -- the old
subprocess.run or the owned runner -- is exercised for real. A fake docker CLI
records `docker rm -f <name>` / `docker container inspect <name>` calls.

Checks: cancellation after launch stops the whole process tree (and removes the
exact container) before the caller -- validator, server job -- may finish; a
timeout leaves no surviving child; output is bounded while it is read; a cancelled
or out-of-budget run launches nothing. Fault injections remove the tree
containment and the cancel poll and must be detected.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import store, tool_runner
from harness.models import Finding, HttpExchange
from harness.run_context import CancelToken, RunContext
from harness.validators.sqlmap import SqlmapValidator

_FAKE_SQLMAP = "i05c-fake-sqlmap"
_REAL_POPEN = subprocess.Popen

_WORKER = r'''
import json, os, subprocess, sys, time
log = os.environ["I05C_LOG"]
role = os.environ.get("I05C_ROLE", "root")
def note(**kw):
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(kw) + "\n")
note(role=role, pid=os.getpid(), event="start")
if role == "root" and os.environ.get("I05C_CHILD") == "1":
    subprocess.Popen([sys.executable, __file__], env=dict(os.environ, I05C_ROLE="child"),
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if role == "root":
    noise = int(os.environ.get("I05C_NOISE", "0"))
    line = "x" * 1023 + "\n"
    for _ in range(noise // 1024):
        sys.stdout.write(line)
    print("worker ready", flush=True)
time.sleep(float(os.environ.get("I05C_SLEEP" if role == "root" else "I05C_CHILD_SLEEP", "0")))
note(role=role, pid=os.getpid(), event="exit")
sys.exit(int(os.environ.get("I05C_RC", "0")) if role == "root" else 0)
'''

_FAKE_DOCKER_CTL = r'''
import json, sys
log, args = sys.argv[1], sys.argv[2:]
with open(log, "a", encoding="utf-8") as f:
    f.write(json.dumps({"docker": args}) + "\n")
if args[:2] == ["container", "inspect"]:
    sys.stderr.write("Error: No such container: %s\n" % args[-1])
    sys.exit(1)
'''


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = ctypes.c_void_p
        handle = k32.OpenProcess(0x00100000 | 0x1000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED
        if not handle:
            return False
        try:
            return k32.WaitForSingleObject(ctypes.c_void_p(handle), 0) == 0x102  # WAIT_TIMEOUT
        finally:
            k32.CloseHandle(ctypes.c_void_p(handle))
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _kill_pid(pid: int) -> None:
    """Test cleanup only: terminate one exact PID this test's worker logged."""
    if os.name == "nt":
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = ctypes.c_void_p
        handle = k32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
        if handle:
            k32.TerminateProcess(ctypes.c_void_p(handle), 1)
            k32.CloseHandle(ctypes.c_void_p(handle))
    else:
        import signal
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


class _ToolFixture(unittest.TestCase):
    """Temp dir, worker script, Popen swap, and exact-PID cleanup."""

    worker_env: dict = {}

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i05c_tool_")
        self.log = os.path.join(self._tmp, "events.jsonl")
        self.worker = os.path.join(self._tmp, "worker.py")
        Path(self.worker).write_text(_WORKER, encoding="utf-8")
        self.docker_ctl = os.path.join(self._tmp, "docker_ctl.py")
        Path(self.docker_ctl).write_text(_FAKE_DOCKER_CTL, encoding="utf-8")
        self.env = {"I05C_LOG": self.log, "I05C_SLEEP": "30", "I05C_CHILD": "1",
                    "I05C_CHILD_SLEEP": "60"}
        fixture = self

        class _SwapPopen(_REAL_POPEN):
            def __init__(self, args, *a, **kw):
                if isinstance(args, (list, tuple)) and args:
                    head = str(args[0])
                    if head == _FAKE_SQLMAP or (head == tool_runner.DOCKER and args[1:2] == ["run"]):
                        args = [sys.executable, fixture.worker, *args[1:]]
                        kw["env"] = {**(kw.get("env") or os.environ), **fixture.env}
                    elif head == tool_runner.DOCKER:
                        args = [sys.executable, fixture.docker_ctl, fixture.log, *args[1:]]
                super().__init__(args, *a, **kw)

        self._popen_patch = patch("subprocess.Popen", _SwapPopen)
        self._popen_patch.start()

    def tearDown(self):
        self._popen_patch.stop()
        for pid in self.pids():
            if _pid_alive(pid):
                _kill_pid(pid)
        shutil.rmtree(self._tmp, ignore_errors=True)

    # --- worker observations -------------------------------------------------------
    def events(self) -> list[dict]:
        try:
            with open(self.log, encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def pids(self, role: str | None = None) -> list[int]:
        return [e["pid"] for e in self.events()
                if e.get("event") == "start" and (role is None or e["role"] == role)]

    def docker_calls(self) -> list[list[str]]:
        return [e["docker"] for e in self.events() if "docker" in e]

    def wait_started(self, timeout=15.0) -> None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.pids("root") and self.pids("child"):
                return
            time.sleep(0.05)
        self.fail(f"worker tree never started: {self.events()}")

    def survivors(self) -> list[int]:
        return [pid for pid in self.pids() if _pid_alive(pid)]

    def wait_gone(self, timeout=5.0) -> list[int]:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            alive = self.survivors()
            if not alive:
                return []
            time.sleep(0.05)
        return self.survivors()


def _sqli() -> Finding:
    return Finding(vulnerability_class="sqli", severity="high", confidence=0.6,
                   summary="id reaches SQL", evidence="", suggested_test="", basis="derived")


def _exchange() -> HttpExchange:
    # No query or body parameters: the bounded boolean preflight has nothing to
    # send, so the validator goes straight to launching the tool.
    return HttpExchange(url="http://shop.test/api/items/7", method="GET",
                        response_status=200, response_body='{"id": 7}')


# --- the container runner (sqlmap container, ffuf) ---------------------------------
class ContainerRunnerLifecycleTests(_ToolFixture, unittest.TestCase):
    def _run_in_thread(self, **kw):
        box: dict = {}

        def target():
            try:
                box["value"] = tool_runner.run("harness/sqlmap:test", ["-u", "http://x/"], **kw)
            except BaseException as exc:          # noqa: BLE001 -- recorded for the test
                box["error"] = exc
            box["finished"] = time.monotonic()

        t = threading.Thread(target=target, daemon=True)
        t.start()
        return t, box

    def test_clean_exit_returns_output_and_removes_nothing(self):
        self.env.update(I05C_SLEEP="0", I05C_CHILD="0")
        rc, out, err = tool_runner.run("harness/sqlmap:test", ["--version"], timeout=20)
        self.assertEqual(rc, 0)
        self.assertIn("worker ready", out)
        self.assertEqual([c for c in self.docker_calls() if c[:1] == ["rm"]], [])

    def test_cancel_after_launch_stops_the_tree_and_removes_the_exact_container(self):
        token, receipt = CancelToken(), {}
        t, box = self._run_in_thread(timeout=60, cancel=token, receipt=receipt)
        self.wait_started()
        cancelled_at = time.monotonic()
        token.cancel()
        t.join(10)
        self.assertFalse(t.is_alive(), "the runner kept waiting on a cancelled tool")
        self.assertIsInstance(box.get("error"), tool_runner.ToolRunCancelled, box)
        self.assertLess(box["finished"] - cancelled_at, 5.0)
        self.assertEqual(self.survivors(), [], "a cancelled tool process survived")
        name = receipt["container_name"]
        self.assertIn(["rm", "-f", name], self.docker_calls())

    def test_timeout_stops_the_whole_tree(self):
        receipt: dict = {}
        with self.assertRaises(subprocess.TimeoutExpired):
            tool_runner.run("harness/sqlmap:test", ["-u", "http://x/"], timeout=2,
                            receipt=receipt)
        self.assertEqual(self.wait_gone(), [], "a timed-out tool's child survived")
        self.assertIn(["rm", "-f", receipt["container_name"]], self.docker_calls())

    def test_noisy_output_is_bounded_while_read(self):
        self.env.update(I05C_SLEEP="0", I05C_CHILD="0", I05C_NOISE=str(4 * 1024 * 1024))
        receipt: dict = {}
        rc, out, err = tool_runner.run("harness/sqlmap:test", ["-x"], timeout=60, receipt=receipt)
        self.assertEqual(rc, 0)
        self.assertLessEqual(len(out.encode("utf-8")), 512 * 1024, "output was held without bound")
        self.assertTrue(out.rstrip().endswith("worker ready"), "the tail of the output was lost")
        self.assertGreater(receipt.get("stdout_dropped", 0), 3 * 1024 * 1024)


# --- sqlmap on the host ----------------------------------------------------------------
class SqlmapHostLifecycleTests(_ToolFixture, unittest.TestCase):
    def _validator(self, **kw):
        return SqlmapValidator(binary=_FAKE_SQLMAP, allowed_hosts=["shop.test"], **kw)

    def test_timeout_leaves_no_survivor(self):
        result = asyncio.run(self._validator(timeout_seconds=2).validate(_sqli(), _exchange()))
        self.assertIn("timed out", result.summary)
        self.assertEqual(self.wait_gone(), [], "a timed-out sqlmap child survived")

    def test_cancelled_run_launches_nothing(self):
        run = RunContext.create(allowed_hosts=["shop.test"], max_requests=50)
        run.cancel.cancel()
        result = asyncio.run(self._validator(run_context=run).validate(_sqli(), _exchange()))
        self.assertEqual(self.pids(), [], "sqlmap was launched for a cancelled run")
        self.assertFalse(result.confirmed)

    def test_exhausted_run_budget_launches_nothing(self):
        run = RunContext.create(allowed_hosts=["shop.test"], max_requests=0)
        asyncio.run(self._validator(run_context=run).validate(_sqli(), _exchange()))
        self.assertEqual(self.pids(), [], "sqlmap was launched past an exhausted run budget")

    def test_run_scope_excluding_the_url_launches_nothing(self):
        run = RunContext.create(allowed_hosts=["other.test"], max_requests=50)
        asyncio.run(self._validator(run_context=run).validate(_sqli(), _exchange()))
        self.assertEqual(self.pids(), [], "sqlmap was launched outside the run's scope")

    def test_task_cancellation_waits_for_the_tool_to_stop(self):
        """asyncio cancellation of the awaiting task must not abandon the tool."""
        async def go():
            task = asyncio.ensure_future(
                self._validator(timeout_seconds=60).validate(_sqli(), _exchange()))
            await asyncio.to_thread(self.wait_started)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            return self.survivors()

        self.assertEqual(asyncio.run(go()), [], "the task ended while the tool still ran")


# --- the server job: terminal only after cleanup -------------------------------------
class JobCancelLifecycleTests(_ToolFixture, unittest.TestCase):
    """POST .../investigate/{job}/cancel while the job's sqlmap runs."""

    def setUp(self):
        super().setUp()
        self._jobdir = tempfile.TemporaryDirectory()
        self._orig_db = store._DB_PATH
        store._DB_PATH = Path(self._jobdir.name) / "state.db"
        import importlib
        import harness.server as server_module
        importlib.reload(server_module)
        self.server = server_module
        self.server.config["runs"] = {"output_dir": self._jobdir.name,
                                      "cache_namespace": "i05c-isolated"}
        self.server.orchestrator.allowed_hosts = ["shop.test"]
        from fastapi.testclient import TestClient
        # One event loop for every request: outside the context manager each request
        # runs on its own loop, whose teardown cancels the job's background task.
        self.client = TestClient(server_module.app, base_url="http://localhost",
                                 headers={"Authorization": f"Bearer {server_module._mutation_token()}"})
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        store._DB_PATH = self._orig_db
        self._jobdir.cleanup()
        super().tearDown()

    def _cancel_while_tool_runs(self, **validator_kw):
        async def investigate(*args, **kwargs):
            validator = SqlmapValidator(binary=_FAKE_SQLMAP, timeout_seconds=60,
                                        allowed_hosts=["shop.test"],
                                        run_context=kwargs["run_context"], **validator_kw)
            await validator.validate(_sqli(), _exchange())
            return {"summary": {}}

        with patch.object(self.server.orchestrator, "investigate_engagement", new=investigate):
            start = self.client.post("/engagement/shop.test/investigate",
                                     json={"base_url": "http://shop.test"})
            self.assertEqual(start.status_code, 200, start.text)
            job_id = start.json()["job_id"]
            self.wait_started()
            cancelled_at = time.monotonic()
            self.client.post(f"/engagement/shop.test/investigate/{job_id}/cancel")
            status, alive_at_terminal = None, None
            end = time.monotonic() + 15
            while time.monotonic() < end:
                status = self.client.get(f"/engagement/shop.test/investigate/{job_id}").json()
                if status["status"] not in ("running", "cancelling"):
                    alive_at_terminal = self.survivors()
                    break
                time.sleep(0.05)
            took = time.monotonic() - cancelled_at
        return status, alive_at_terminal, took

    def test_host_tool_job_is_terminal_only_after_the_tree_stopped(self):
        status, alive, took = self._cancel_while_tool_runs()
        self.assertEqual(status["status"], "cancelled", status)
        self.assertEqual(alive, [], "the job reported cancelled while sqlmap still ran")
        self.assertLess(took, 8.0)

    def test_container_tool_job_removes_the_exact_container_first(self):
        with patch.object(tool_runner, "available", return_value=(True, "")):
            status, alive, _ = self._cancel_while_tool_runs(container_image="harness/sqlmap:test")
        self.assertEqual(status["status"], "cancelled", status)
        self.assertEqual(alive, [], "the job reported cancelled while the docker CLI still ran")
        removed = [c for c in self.docker_calls() if c[:2] == ["rm", "-f"]]
        self.assertEqual(len(removed), 1, self.docker_calls())
        self.assertTrue(removed[0][2].startswith("harness_"))


# --- fault injection --------------------------------------------------------------------
def _root_only_tree():
    class _RootOnlyTree(tool_runner._OwnedTree):
        """Fault: contain and stop only the launched process, never its descendants."""

        @staticmethod
        def popen_kwargs() -> dict:
            return {}

        def attach(self, proc) -> None:
            self._proc, self.kind = proc, "pid"

        def terminate(self) -> None:
            self._proc.kill()

        def alive(self) -> int:
            return 0 if self._proc.poll() is not None else 1

    return _RootOnlyTree


class LifecycleFaultInjectionTests(_ToolFixture, unittest.TestCase):
    def test_root_only_containment_is_detected(self):
        """Without tree containment, a timeout kills only the root: the child survives."""
        with patch.object(tool_runner, "_OwnedTree", _root_only_tree()):
            with self.assertRaises(subprocess.TimeoutExpired):
                tool_runner.run("harness/sqlmap:test", ["-u", "http://x/"], timeout=2)
        self.assertTrue(self.pids("child") and self.survivors(),
                        "root-only containment no longer leaks -- the control is vacuous")

    def test_disabled_cancel_poll_is_detected(self):
        token = CancelToken()
        with patch.object(tool_runner, "_is_cancelled", return_value=False):
            box: dict = {}

            def target():
                try:
                    tool_runner.run("harness/sqlmap:test", ["-u", "http://x/"], timeout=6,
                                    cancel=token)
                except BaseException as exc:      # noqa: BLE001
                    box["error"] = exc

            t = threading.Thread(target=target, daemon=True)
            t.start()
            self.wait_started()
            token.cancel()
            t.join(3)
            still_running = t.is_alive()
            t.join(15)
        self.assertTrue(still_running, "ignoring the cancel signal no longer matters")


if __name__ == "__main__":
    unittest.main()
