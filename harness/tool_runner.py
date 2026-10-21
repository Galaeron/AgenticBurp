"""
Container tool-runner -- run external security tools in ephemeral Docker
containers instead of on the host.

Why: host installs of offensive tools (sqlmap, nikto, nuclei, ...) are exactly
what endpoint protection quarantines -- Windows Defender removed a host-installed
sqlmap on this machine -- and they pollute the host with tool versions that drift.
A tool run in a throwaway Linux container is isolated from the host AV, pinned to
an image digest, and leaves nothing behind (`--rm`).

This module is the seam every containerised validator goes through. It does NOT
decide policy (which tools, whether to use containers) -- callers do, from config.

Networking note (Docker Desktop on Windows/macOS): a container cannot reach the
host's 127.0.0.1 directly. The host is `host.docker.internal`; `localhost_url`
rewrites a loopback target URL to it, and `--add-host host.docker.internal:
host-gateway` makes that name resolve on plain Linux Docker too. A container tool
therefore tests the SAME target the host means by localhost, transparently.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


def _resolve_docker() -> str:
    """Resolve the docker CLI cross-platform: PATH first, then the OS-specific
    default install location so this works from a shell whose PATH doesn't
    include it (previously this hardcoded the Windows Docker Desktop path, which
    does not exist on macOS/Linux). Falls back to the bare name "docker" so
    available() reports a clear "not found" rather than importing a Windows path
    on every platform."""
    found = shutil.which("docker")
    if found:
        return found
    if sys.platform == "win32":
        candidates = [r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"]
    elif sys.platform == "darwin":
        candidates = ["/usr/local/bin/docker", "/opt/homebrew/bin/docker",
                      os.path.expanduser("~/.docker/bin/docker")]
    else:
        candidates = ["/usr/bin/docker", "/usr/local/bin/docker", "/snap/bin/docker"]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return "docker"


DOCKER = _resolve_docker()

_LOOPBACK = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}
_HOST_ALIAS = "host.docker.internal"


def available(timeout: float = 8.0) -> tuple[bool, str]:
    """(usable, reason). Usable only when the docker daemon actually answers --
    an installed CLI with a stopped Docker Desktop is NOT usable."""
    if not DOCKER:
        return False, "docker CLI not found -- install Docker Desktop"
    try:
        r = subprocess.run([DOCKER, "version", "--format", "{{.Server.Version}}"],
                           capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return False, f"docker CLI not found at {DOCKER!r}"
    except subprocess.TimeoutExpired:
        return False, "docker daemon did not respond (is Docker Desktop running?)"
    except Exception as e:
        return False, f"docker check failed: {e.__class__.__name__}"
    if r.returncode == 0 and (r.stdout or "").strip():
        return True, (r.stdout or "").strip()
    return False, "docker daemon not reachable -- start Docker Desktop"


def image_present(image: str, timeout: float = 10.0) -> bool:
    """True iff the image already exists locally (no pull attempted)."""
    try:
        r = subprocess.run([DOCKER, "image", "inspect", image],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


def localhost_url(url: str) -> str:
    """Rewrite a loopback target URL to the in-container host alias, so a tool in
    a container reaches the host's service. Non-loopback URLs are returned as-is."""
    p = urlsplit(url)
    if (p.hostname or "").lower() not in _LOOPBACK:
        return url
    netloc = _HOST_ALIAS + (f":{p.port}" if p.port else "")
    if p.username:  # preserve any userinfo (rare for these tools)
        cred = p.username + (f":{p.password}" if p.password else "")
        netloc = f"{cred}@{netloc}"
    return urlunsplit((p.scheme, netloc, p.path, p.query, p.fragment))


# W-26: sandbox hardening applied to every container run. These constrain a
# compromised or misbehaving tool WITHOUT restricting what an HTTP-making scanner
# (sqlmap/ffuf) actually needs: drop every Linux capability and block privilege
# escalation (an HTTP client needs neither), cap the process count and CPU/memory
# so a fork bomb or runaway can't exhaust the host, and -- because docker_cmd
# mounts nothing -- keep the mount surface empty. A read-only root filesystem is
# deliberately NOT default here: sqlmap/ffuf write session/output files whose
# paths must be tmpfs-mapped and verified per image on a live run first, so
# enabling it blindly would silently break confirmation (green argv test, dead
# tool). Pass harden=False to opt a specific run out.
_HARDENING_FLAGS = [
    "--security-opt", "no-new-privileges",
    "--cap-drop", "ALL",
    "--pids-limit", "256",
    "--memory", "1g",
    "--cpus", "2",
]


# PR-11 / R02: per-run egress control for a containerised tool. A scanner
# (sqlmap/ffuf) makes its OWN outbound requests; the Python-side timeout and the
# sandbox caps above bound host resources but NOT where those requests go, so a
# tool-followed redirect or an out-of-scope probe can leave the intended target.
# EgressPolicy is the seam that constrains that egress at `docker run`
# construction time and is recorded in the run receipt. The CONCRETE network/
# proxy containment is finalized+proven on the OWNER/live half (a real container
# against two owned origins); here the offline guarantees are: the seam exists and
# is threaded into the argv, a run that must enforce egress but has no policy FAILS
# CLOSED, and the run goes through the force-clean wrapper below.
class EgressPolicyRequired(RuntimeError):
    """Raised when a run sets ``enforce_egress`` but supplies no EgressPolicy --
    an uncontrolled-egress tool launch is refused rather than run (fail closed)."""


class ToolRunCancelled(RuntimeError):
    """Raised when a tool run is cancelled at/ before launch."""


@dataclass(frozen=True)
class EgressPolicy:
    """Declares how a containerised tool's outbound network is constrained.

    ``network`` is the docker network the container may use; ``proxy_url`` (when
    set) forces the tool's HTTP(S) egress through a controlled proxy; and
    ``allowed_hosts`` is the set of destinations the run is meant to reach (e.g.
    the in-container host alias). ``docker_flags`` renders this to argv so a test
    can assert the seam without running docker."""
    network: str = "bridge"
    proxy_url: str | None = None
    allowed_hosts: tuple[str, ...] = ()

    def docker_flags(self) -> list[str]:
        flags: list[str] = ["--network", self.network]
        if self.proxy_url:
            for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                flags += ["-e", f"{var}={self.proxy_url}"]
            if self.allowed_hosts:
                no_proxy = ",".join(self.allowed_hosts)
                for var in ("NO_PROXY", "no_proxy"):
                    flags += ["-e", f"{var}={no_proxy}"]
        return flags

    def describe(self) -> dict:
        return {"network": self.network, "proxy": self.proxy_url,
                "allowed_hosts": list(self.allowed_hosts)}


def _is_cancelled(cancel) -> bool:
    """Normalise the accepted cancel-signal shapes -- an ``asyncio.Event``, a
    run_context.CancelToken (a bool ``cancelled``), a zero-arg callable, or
    ``None`` (never cancelled). Stdlib-only."""
    if cancel is None:
        return False
    try:
        import asyncio
        if isinstance(cancel, asyncio.Event):
            return cancel.is_set()
    except Exception:
        pass
    flag = getattr(cancel, "cancelled", None)
    if isinstance(flag, bool):
        return flag
    if callable(cancel):
        try:
            return bool(cancel())
        except Exception:
            return False
    return False


def docker_cmd(image: str, args: list[str], *, add_host: bool = True,
               extra: list[str] | None = None, harden: bool = True,
               egress: "EgressPolicy | None" = None) -> list[str]:
    """The full `docker run` argv for `image` + `args`. Always ephemeral (--rm)
    and, by default, sandbox-hardened (W-26; see _HARDENING_FLAGS). When an
    `egress` policy is given, its network/proxy flags are added before the image
    (PR-11/R02). Pure/inspectable so callers (and tests) can assert on it without
    running it."""
    cmd = [DOCKER, "run", "--rm"]
    if harden:
        cmd += _HARDENING_FLAGS
    if add_host:
        cmd += ["--add-host", f"{_HOST_ALIAS}:host-gateway"]
    if egress is not None:
        cmd += egress.docker_flags()
    if extra:
        cmd += list(extra)
    cmd.append(image)
    cmd += list(args)
    return cmd


def _force_remove(name: str) -> bool:
    """Force-stop and remove a named container (#11). `docker run --rm` only cleans
    up on the container's OWN exit; if we time out and kill the docker CLI client,
    the container can keep running. `docker rm -f` verifiably terminates it.
    I05-C: returns True only when docker then reports that exact name as absent."""
    try:
        subprocess.run([DOCKER, "rm", "-f", name], capture_output=True, text=True, timeout=15)
        r = subprocess.run([DOCKER, "container", "inspect", "--format", "{{.Id}}", name],
                           capture_output=True, text=True, timeout=15)
    except Exception:
        return False
    return r.returncode != 0 and "no such" in ((r.stderr or "") + (r.stdout or "")).lower()


# ---------------------------------------------------------------------------
# I05-C: owned external processes
# ---------------------------------------------------------------------------
# Every external tool runs through run_process: the whole process tree is
# contained (a kill-on-close Job Object on Windows, a fresh session/process group
# on POSIX), stdout/stderr are drained concurrently into bounded buffers, and a
# monitor polls the cancel signal and the deadline. On cancel or timeout the tree
# is terminated and run_process returns or raises only once no member is left --
# or raises ToolCleanupFailed when that cannot be proved.

DEFAULT_MAX_OUTPUT = 256 * 1024     # bytes kept per stream (head + tail)
_POLL_SECONDS = 0.05
_KILL_WAIT_SECONDS = 5.0
_CREATE_SUSPENDED = 0x00000004


class ToolCleanupFailed(RuntimeError):
    """A stopped tool could not be proved gone: a process (or its container) may
    still be running. Distinct from cancellation, so a job never reports a clean
    stop while owned work may continue."""


class ToolContainmentUnavailable(RuntimeError):
    """The tool's process tree could not be contained (Windows: no Job Object), so
    the tool was never started. A PID alone cannot find or prove gone a descendant
    whose parent has exited (R36), so there is no unproven fallback."""


@dataclass
class ProcessResult:
    args: list
    returncode: int | None
    stdout: str
    stderr: str
    outcome: str            # exit | timeout | cancelled
    cleanup: str            # not_needed | terminated | cleanup_failed
    containment: str        # job | process-group
    pid: int | None = None
    stdout_dropped: int = 0
    stderr_dropped: int = 0
    elapsed: float = 0.0

    def receipt_fields(self) -> dict:
        return {"pid": self.pid, "containment": self.containment, "cleanup": self.cleanup,
                "stdout_dropped": self.stdout_dropped, "stderr_dropped": self.stderr_dropped,
                "elapsed_seconds": round(self.elapsed, 3)}


class _BoundedSink:
    """Keeps the first quarter and the last three quarters of `limit` bytes and
    counts what was dropped in between; fed while the pipe is read."""

    def __init__(self, limit: int):
        self.head_limit = max(0, limit // 4)
        self.tail_limit = max(0, limit - self.head_limit)
        self.head = bytearray()
        self.tail = bytearray()
        self.dropped = 0

    def feed(self, data: bytes) -> None:
        if len(self.head) < self.head_limit:
            take = self.head_limit - len(self.head)
            self.head += data[:take]
            data = data[take:]
        if data:
            self.tail += data
            over = len(self.tail) - self.tail_limit
            if over > 0:
                del self.tail[:over]
                self.dropped += over

    def text(self) -> str:
        marker = (f"\n...[{self.dropped} bytes of output dropped]...\n".encode()
                  if self.dropped else b"")
        return (bytes(self.head) + marker + bytes(self.tail)).decode("utf-8", errors="replace")


def _drain(stream, sink: _BoundedSink) -> None:
    try:
        fd = stream.fileno()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            sink.feed(chunk)
    except OSError:
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


class _Win:
    """kernel32/ntdll calls for Job Object containment (Windows only)."""

    _k32 = None
    _ntdll = None

    @classmethod
    def _load(cls):
        if cls._k32 is None:
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateJobObjectW.restype = wintypes.HANDLE
            k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            k32.SetInformationJobObject.restype = wintypes.BOOL
            k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                    ctypes.c_void_p, wintypes.DWORD]
            k32.AssignProcessToJobObject.restype = wintypes.BOOL
            k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            k32.TerminateJobObject.restype = wintypes.BOOL
            k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            k32.QueryInformationJobObject.restype = wintypes.BOOL
            k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                      ctypes.c_void_p, wintypes.DWORD,
                                                      ctypes.c_void_p]
            k32.CloseHandle.restype = wintypes.BOOL
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            ntdll = ctypes.WinDLL("ntdll")
            ntdll.NtResumeProcess.restype = ctypes.c_long
            ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
            cls._k32, cls._ntdll = k32, ntdll
        return cls._k32

    @classmethod
    def create_kill_on_close_job(cls):
        import ctypes
        from ctypes import wintypes
        k32 = cls._load()

        class _Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                        ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class _Io(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class _Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", _Basic), ("IoInfo", _Io),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        job = k32.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        info = _Extended()
        info.BasicLimitInformation.LimitFlags = 0x2000   # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            err = ctypes.get_last_error()
            k32.CloseHandle(job)
            raise ctypes.WinError(err)
        return job

    @classmethod
    def assign(cls, job, proc) -> None:
        import ctypes
        if not cls._load().AssignProcessToJobObject(job, int(proc._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    @classmethod
    def resume(cls, proc) -> None:
        cls._load()
        status = cls._ntdll.NtResumeProcess(int(proc._handle))
        if status != 0:
            raise OSError(f"NtResumeProcess failed (0x{status & 0xFFFFFFFF:08x})")

    @classmethod
    def terminate_job(cls, job) -> None:
        cls._load().TerminateJobObject(job, 1)

    @classmethod
    def active_processes(cls, job) -> int:
        import ctypes
        from ctypes import wintypes

        class _Accounting(ctypes.Structure):
            _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
                        ("ThisPeriodTotalUserTime", ctypes.c_int64),
                        ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                        ("TotalPageFaultCount", wintypes.DWORD),
                        ("TotalProcesses", wintypes.DWORD),
                        ("ActiveProcesses", wintypes.DWORD),
                        ("TotalTerminatedProcesses", wintypes.DWORD)]

        info = _Accounting()
        if not cls._load().QueryInformationJobObject(job, 1, ctypes.byref(info),
                                                     ctypes.sizeof(info), None):
            return 1    # cannot query: never claim the tree is empty
        return int(info.ActiveProcesses)

    @classmethod
    def close(cls, job) -> None:
        cls._load().CloseHandle(job)


class _OwnedTree:
    """Every process a launched tool starts. Windows: the tool starts suspended, is
    placed in a kill-on-close Job Object and only then resumed, so no descendant can
    escape; the job's ActiveProcesses proves emptiness. Without a job the tool is
    never resumed (ToolContainmentUnavailable). POSIX: a fresh session, so the
    process group holds every descendant that does not create its own."""

    def __init__(self):
        self._proc = None
        self._job = None
        self.kind = ""

    @staticmethod
    def popen_kwargs() -> dict:
        if os.name == "nt":
            return {"creationflags": _CREATE_SUSPENDED}
        return {"start_new_session": True}

    def attach(self, proc) -> None:
        self._proc = proc
        if os.name != "nt":
            self.kind = "process-group"
            return
        try:
            self._job = _Win.create_kill_on_close_job()
            _Win.assign(self._job, proc)
        except OSError as exc:
            self.close()
            # Fail closed: the old PID-only fallback reported cleanup not_needed once
            # the root exited, while a child it started kept running (R36).
            raise ToolContainmentUnavailable(
                f"no Job Object for pid {proc.pid}; the tool was not started: {exc}") from exc
        self.kind = "job"
        _Win.resume(proc)

    def terminate(self) -> None:
        if os.name == "nt":
            _Win.terminate_job(self._job)
            return
        import signal
        try:
            os.killpg(self._proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def alive(self) -> int:
        """Members still running; 0 means none is left."""
        if os.name == "nt":
            return _Win.active_processes(self._job)
        try:
            os.killpg(self._proc.pid, 0)
        except ProcessLookupError:
            return 0
        except PermissionError:
            return 1
        return 1

    def close(self) -> None:
        if self._job is not None:
            _Win.close(self._job)
            self._job = None


def _wait_empty(tree: _OwnedTree, seconds: float) -> bool:
    end = time.monotonic() + seconds
    while True:
        if tree.alive() == 0:
            return True
        if time.monotonic() >= end:
            return False
        time.sleep(_POLL_SECONDS)


def run_process(argv, *, timeout: float, cancel=None, env=None,
                max_output: int = DEFAULT_MAX_OUTPUT) -> ProcessResult:
    """Run one external tool as an owned process tree (I05-C).

    Returns a ProcessResult (returncode/stdout/stderr like CompletedProcess) after a
    normal exit. Raises ToolRunCancelled when `cancel` fires (before or after launch)
    and subprocess.TimeoutExpired when `timeout` elapses -- in both cases only after
    the whole tree has been terminated; the exception carries `.result`. Raises
    ToolCleanupFailed when that termination cannot be proved, and
    ToolContainmentUnavailable (the tool never ran) when its tree cannot be
    contained. FileNotFoundError from a missing executable propagates unchanged."""
    argv = [str(a) for a in argv]
    if _is_cancelled(cancel):
        raise ToolRunCancelled(f"tool run cancelled before launch: {argv[0]!r}")
    tree = _OwnedTree()
    start = time.monotonic()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, **tree.popen_kwargs())
    try:
        tree.attach(proc)
    except BaseException:
        # Not resumed yet (Windows), so nothing of the tool has run.
        try:
            proc.kill()
            proc.wait(_KILL_WAIT_SECONDS)
        except Exception:
            pass
        tree.close()
        for stream in (proc.stdout, proc.stderr):
            stream.close()
        raise
    sinks = (_BoundedSink(max_output), _BoundedSink(max_output))
    readers = [threading.Thread(target=_drain, args=(stream, sink), daemon=True)
               for stream, sink in ((proc.stdout, sinks[0]), (proc.stderr, sinks[1]))]
    for reader in readers:
        reader.start()
    outcome = "exit"
    stopped = False
    proved = True
    try:
        deadline = start + timeout
        while True:
            try:
                proc.wait(timeout=_POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                pass
            if _is_cancelled(cancel):
                outcome = "cancelled"
                break
            if time.monotonic() >= deadline:
                outcome = "timeout"
                break
    finally:
        # Stop whatever still runs: the tool itself after a cancel/timeout, and any
        # descendant it left behind even after a normal exit.
        if outcome != "exit" or tree.alive():
            stopped = True
            tree.terminate()
        try:
            proc.wait(timeout=_KILL_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        if stopped:
            proved = _wait_empty(tree, _KILL_WAIT_SECONDS)
        tree.close()
        for reader in readers:
            reader.join(_KILL_WAIT_SECONDS)
    result = ProcessResult(
        args=argv, returncode=proc.returncode, stdout=sinks[0].text(), stderr=sinks[1].text(),
        outcome=outcome,
        cleanup=("not_needed" if not stopped else "terminated" if proved else "cleanup_failed"),
        containment=tree.kind, pid=proc.pid, stdout_dropped=sinks[0].dropped,
        stderr_dropped=sinks[1].dropped, elapsed=time.monotonic() - start)
    if not proved:
        exc = ToolCleanupFailed(f"{argv[0]!r} (pid {proc.pid}) could not be proved stopped "
                                f"after {outcome}")
    elif outcome == "cancelled":
        exc = ToolRunCancelled(f"tool run cancelled after launch: {argv[0]!r}")
    elif outcome == "timeout":
        exc = subprocess.TimeoutExpired(argv, timeout, output=result.stdout, stderr=result.stderr)
    else:
        return result
    exc.result = result
    raise exc


async def call_cancellable(fn, *args, cancel=None, **kwargs):
    """Run the blocking `fn(*args, cancel=<poll>, **kwargs)` in a worker thread.

    `fn` must poll its `cancel` argument (run_process and run do). If the awaiting
    task is cancelled, the poll fires and this waits for `fn` to finish its own
    cleanup before re-raising -- asyncio.to_thread alone would abandon a still
    running tool. A ToolCleanupFailed from that cleanup replaces the cancellation,
    so the caller cannot report a clean stop."""
    import asyncio
    stop = threading.Event()

    def poll() -> bool:
        return stop.is_set() or _is_cancelled(cancel)

    fut = asyncio.ensure_future(asyncio.to_thread(fn, *args, cancel=poll, **kwargs))
    try:
        await asyncio.wait({fut})   # unlike shield/wait_for, never cancels `fut`
    except asyncio.CancelledError:
        stop.set()
        while not fut.done():
            try:
                await asyncio.wait({fut})
            except asyncio.CancelledError:
                continue
        exc = None if fut.cancelled() else fut.exception()   # always retrieved
        if isinstance(exc, ToolCleanupFailed):
            raise exc
        raise
    return fut.result()


def run(image: str, args: list[str], *, timeout: float = 120.0,
        add_host: bool = True, extra: list[str] | None = None,
        egress: "EgressPolicy | None" = None, enforce_egress: bool = False,
        cancel=None, receipt: dict | None = None,
        max_output: int = DEFAULT_MAX_OUTPUT) -> tuple[int, str, str]:
    """Run `image` with `args` in a throwaway container. Returns
    (returncode, stdout, stderr). Raises subprocess.TimeoutExpired on timeout so
    the caller can treat a hung tool distinctly from a clean non-zero exit.

    The container is given a unique `--name` so that on TIMEOUT (or any other
    non-clean exit) we can verifiably terminate it (#11) -- killing the CLI client
    alone does not stop the container. `docker run --rm` only cleans up on the
    container's OWN clean exit, so every path that is not a clean return removes it.

    PR-11/R02: `egress` threads a per-run egress policy into the argv; with
    `enforce_egress=True` a run that has NO policy is refused (EgressPolicyRequired,
    fail closed). `cancel` (an asyncio.Event, CancelToken or zero-arg callable)
    aborts before launch and, I05-C, stops a running tool: its CLI process tree is
    terminated and the exact container removed before ToolRunCancelled is raised.
    Output is bounded to `max_output` bytes per stream while it is read. When the
    container cannot be proved removed, ToolCleanupFailed is raised. `receipt`, when
    supplied, is populated with tool/image/argv/egress/outcome/cleanup fields."""
    if enforce_egress and egress is None:
        raise EgressPolicyRequired(
            f"refusing to launch {image!r}: no egress policy configured for this run "
            "(PR-11/R02 fail-closed -- an uncontrolled-egress tool run is not allowed)")
    import uuid
    name = f"harness_{uuid.uuid4().hex[:12]}"
    cmd = docker_cmd(image, args, add_host=add_host,
                     extra=["--name", name] + list(extra or []), egress=egress)
    if receipt is not None:
        receipt.update({
            "tool_image": image,
            "container_name": name,
            "argv": list(cmd),
            "egress_applied": egress is not None,
            "egress": (egress.describe() if egress is not None else None),
            "outcome": "launching",
        })
    if _is_cancelled(cancel):
        _force_remove(name)   # nothing launched, but stay safe if a race left one
        if receipt is not None:
            receipt["outcome"] = "cancelled_before_launch"
        raise ToolRunCancelled(f"tool run cancelled before launch: {image!r}")
    try:
        result = run_process(cmd, timeout=timeout, cancel=cancel, max_output=max_output)
    except Exception as exc:
        outcome = ("timeout" if isinstance(exc, subprocess.TimeoutExpired)
                   else "cancelled" if isinstance(exc, ToolRunCancelled)
                   else "cleanup_failed" if isinstance(exc, ToolCleanupFailed)
                   else "containment_unavailable" if isinstance(exc, ToolContainmentUnavailable)
                   else "error")
        if receipt is not None:
            receipt["outcome"] = outcome
            partial = getattr(exc, "result", None)
            if partial is not None:
                receipt.update(partial.receipt_fields())
        # the hung/killed workload must not outlive its client
        if not _force_remove(name):
            if receipt is not None:
                receipt["cleanup"] = "cleanup_failed"
            raise ToolCleanupFailed(
                f"container {name} could not be proved removed after {outcome}") from exc
        raise
    if receipt is not None:
        receipt["outcome"] = f"exit={result.returncode}"
        receipt.update(result.receipt_fields())
    return result.returncode, (result.stdout or ""), (result.stderr or "")
