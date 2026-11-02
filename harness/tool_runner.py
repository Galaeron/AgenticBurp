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
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
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


# E9 tool lifecycle. Measured on job 383f0ebff8e8: `docker version` ran before
# every container launch and no tool run had a recorded duration, so sqlmap
# startup could not be measured. Both stores are bounded and hold only counts
# and timings (never argv, output or URLs).
_LIFECYCLE: deque = deque(maxlen=500)     # one record per run()
_CHECKS: deque = deque(maxlen=500)        # one record per available() call
_STATE_LOCK = threading.Lock()
# A positive docker check is reused for this long. A negative one is never kept,
# so a stopped Docker Desktop is noticed on the very next call.
AVAILABLE_TTL_SECONDS = 60.0
_available_ok: tuple | None = None        # (docker path, monotonic stamp, reason)


def _reset_available_cache() -> None:
    """Forget the cached positive docker check (test seam)."""
    global _available_ok
    with _STATE_LOCK:
        _available_ok = None


def _remember_available(ok: bool, reason: str) -> None:
    """Keep a positive docker check for AVAILABLE_TTL_SECONDS; forget a negative."""
    global _available_ok
    with _STATE_LOCK:
        _available_ok = (DOCKER, time.monotonic(), reason) if ok else None


def available(timeout: float = 8.0) -> tuple[bool, str]:
    """(usable, reason). Usable only when the docker daemon actually answers --
    an installed CLI with a stopped Docker Desktop is NOT usable. A positive
    answer is cached for AVAILABLE_TTL_SECONDS; a negative one never is."""
    started_wall, started = time.time(), time.monotonic()
    cached = _available_ok
    if cached and cached[0] == DOCKER and started - cached[1] < AVAILABLE_TTL_SECONDS:
        _CHECKS.append({"at": started_wall, "ms": 0.0, "ok": True, "cached": True})
        return True, cached[2]
    ok, reason = _probe_docker(timeout)
    _remember_available(ok, reason)
    _CHECKS.append({"at": started_wall, "ms": round((time.monotonic() - started) * 1000.0, 3),
                    "ok": ok, "cached": False})
    return ok, reason


def _probe_docker(timeout: float) -> tuple[bool, str]:
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


# P3-2: image references pinned by content digest. `name[:tag]@sha256:<64 hex>`
# makes docker run exactly that content (a moved tag cannot swap the tool), and a
# bare `sha256:<64 hex>` is a local image ID -- the only way to pin a locally BUILT
# image such as harness/sqlmap, which has no registry RepoDigest. A reference that
# claims a digest but does not carry a well-formed one is refused before launch
# rather than handed to docker to interpret.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ImageReferenceError(ValueError):
    """Raised for a malformed digest, or a missing one when a digest is required."""


@dataclass(frozen=True)
class ImageRef:
    name: str              # "" for a bare image ID
    tag: str | None
    digest: str | None     # "sha256:<64 hex>" when pinned

    @property
    def pinned(self) -> bool:
        return self.digest is not None

    @property
    def is_image_id(self) -> bool:
        return self.pinned and not self.name


def parse_image_ref(ref: str) -> ImageRef:
    """Split an image reference into name/tag/digest. Pure; raises
    ImageReferenceError for an empty reference or a malformed digest."""
    ref = (ref or "").strip()
    if not ref:
        raise ImageReferenceError("empty image reference")
    if _DIGEST_RE.match(ref):
        return ImageRef(name="", tag=None, digest=ref)
    name, sep, digest = ref.partition("@")
    if sep:
        if not _DIGEST_RE.match(digest):
            raise ImageReferenceError(
                f"image reference {ref!r} has a malformed digest "
                "(expected @sha256:<64 lowercase hex>)")
        if not name:
            raise ImageReferenceError(f"image reference {ref!r} has no name")
    if ref.startswith("sha256:"):
        raise ImageReferenceError(f"image ID {ref!r} is not sha256:<64 lowercase hex>")
    # a ':' after the last '/' is a tag; one before it is a registry port
    tag = None
    slash = name.rfind("/")
    colon = name.rfind(":")
    if colon > slash:
        name, tag = name[:colon], name[colon + 1:]
        if not tag:
            raise ImageReferenceError(f"image reference {ref!r} has an empty tag")
    return ImageRef(name=name, tag=tag, digest=digest if sep else None)


def validate_image_ref(ref: str, *, require_digest: bool = False) -> ImageRef:
    """parse_image_ref, plus (when `require_digest`) refuse an unpinned reference."""
    parsed = parse_image_ref(ref)
    if require_digest and not parsed.pinned:
        raise ImageReferenceError(
            f"image reference {ref!r} is not pinned by digest "
            "(use name@sha256:<digest>, or sha256:<image id> for a local build)")
    return parsed


def local_image_digests(image: str, timeout: float = 10.0) -> tuple[str, list[str]] | None:
    """(image ID, RepoDigests) of a LOCAL image via `docker image inspect` (no pull),
    or None when it is absent or docker cannot answer."""
    try:
        r = subprocess.run([DOCKER, "image", "inspect", "--format",
                            "{{json .Id}} {{json .RepoDigests}}", image],
                           capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    import json
    try:
        id_part, _, digests_part = (r.stdout or "").strip().partition(" ")
        image_id = json.loads(id_part)
        repo_digests = json.loads(digests_part) if digests_part else []
    except ValueError:
        return None
    return str(image_id or ""), [str(d) for d in (repo_digests or [])]


def verify_pinned_digest(image: str, timeout: float = 10.0) -> tuple[bool, str]:
    """(ok, reason): does the local image the pinned reference names carry that
    digest? An unpinned reference is reported, not checked. Never pulls."""
    try:
        parsed = parse_image_ref(image)
    except ImageReferenceError as exc:
        return False, str(exc)
    if not parsed.pinned:
        return False, f"{image!r} is not pinned by digest"
    found = local_image_digests(image, timeout=timeout)
    if found is None:
        return False, f"{image!r} is not present locally (no pull attempted)"
    image_id, repo_digests = found
    if parsed.is_image_id:
        ok = image_id == parsed.digest
    else:
        ok = any(d.rpartition("@")[2] == parsed.digest and d.rpartition("@")[0] == parsed.name
                 for d in repo_digests)
    return (True, "digest matches") if ok else (False, f"local image does not carry {parsed.digest}")


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
            k32.OpenProcess.restype = wintypes.HANDLE
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            k32.IsProcessInJob.restype = wintypes.BOOL
            k32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                           ctypes.POINTER(wintypes.BOOL)]
            k32.WaitForSingleObject.restype = wintypes.DWORD
            k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
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
    def _accounting(cls, job):
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
            return None
        return info

    @classmethod
    def active_processes(cls, job) -> int:
        info = cls._accounting(job)
        return 1 if info is None else int(info.ActiveProcesses)   # cannot query: never empty

    @classmethod
    def total_processes(cls, job) -> int | None:
        """Processes ever associated with the job (nested jobs included)."""
        info = cls._accounting(job)
        return None if info is None else int(info.TotalProcesses)

    @classmethod
    def member_pids(cls, job) -> list[int] | None:
        """PIDs of the job's active members; None when the list cannot be read."""
        import ctypes
        from ctypes import wintypes
        size = 64
        while size <= 65536:
            class _IdList(ctypes.Structure):
                _fields_ = [("NumberOfAssignedProcesses", wintypes.DWORD),
                            ("NumberOfProcessIdsInList", wintypes.DWORD),
                            ("ProcessIdList", ctypes.c_size_t * size)]

            info = _IdList()
            if cls._load().QueryInformationJobObject(job, 3, ctypes.byref(info),
                                                     ctypes.sizeof(info), None):
                return [int(info.ProcessIdList[i]) for i in range(info.NumberOfProcessIdsInList)]
            if ctypes.get_last_error() != 234:    # not ERROR_MORE_DATA
                return None
            size *= 4
        return None

    @classmethod
    def hold_member(cls, job, pid: int):
        """A SYNCHRONIZE handle to `pid` while it is still this job's member; 0 when that
        member is already gone; None when this cannot be established."""
        import ctypes
        from ctypes import wintypes
        k32 = cls._load()
        handle = k32.OpenProcess(0x00100000 | 0x1000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED
        if not handle:
            # ERROR_INVALID_PARAMETER: no such process, so its object is already freed.
            return 0 if ctypes.get_last_error() == 87 else None
        member = wintypes.BOOL()
        if not k32.IsProcessInJob(handle, job, ctypes.byref(member)):
            k32.CloseHandle(handle)
            return None
        if not member.value:    # the PID was reused: the member it named is gone
            k32.CloseHandle(handle)
            return 0
        return handle

    @classmethod
    def exited(cls, handle) -> bool:
        return cls._load().WaitForSingleObject(handle, 0) == 0    # WAIT_OBJECT_0

    @classmethod
    def close(cls, job) -> None:
        cls._load().CloseHandle(job)


class _OwnedTree:
    """Every process a launched tool starts. Windows: the tool starts suspended, is
    placed in a kill-on-close Job Object and only then resumed, so no descendant can
    escape; the job's ActiveProcesses and the stopped members' own handles prove
    emptiness. Without a job the tool is never resumed (ToolContainmentUnavailable).
    POSIX: a fresh session, so the process group holds every descendant that does
    not create its own."""

    def __init__(self):
        self._proc = None
        self._job = None
        self._held = []           # Windows: handles to the members a terminate stopped
        self._unproved = False    # Windows: a stopped member could not be held
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
            # ActiveProcesses drops to 0 as soon as the job is terminated, while its
            # members are still exiting, and the launched process may be only a
            # launcher (a venv python.exe, a console-script shim) whose exit says
            # nothing about the tool. Hold every member first, so emptiness is
            # proved by the members' own exit.
            total = _Win.total_processes(self._job)
            pids = _Win.member_pids(self._job)
            for pid in pids or ():
                handle = _Win.hold_member(self._job, pid)
                if handle is None:
                    self._unproved = True
                elif handle:
                    self._held.append(handle)
            _Win.terminate_job(self._job)
            # A member that joined after the snapshot is stopped too, but its exit
            # cannot be awaited: never prove such a tree empty.
            if pids is None or total is None or _Win.total_processes(self._job) != total:
                self._unproved = True
            return
        import signal
        try:
            os.killpg(self._proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def alive(self) -> int:
        """Members still running; 0 means none is left."""
        if os.name == "nt":
            return (_Win.active_processes(self._job) + int(self._unproved)
                    + sum(not _Win.exited(handle) for handle in self._held))
        try:
            os.killpg(self._proc.pid, 0)
        except ProcessLookupError:
            return 0
        except PermissionError:
            return 1
        return 1

    def close(self) -> None:
        for handle in self._held:
            _Win.close(handle)
        self._held = []
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

    # Keep the worker completion as a Future, not a Task: loop shutdown cancels
    # every Task, which would mark a to_thread bridge done while its thread and
    # process still run. Preserve to_thread's task-local context propagation.
    import contextvars
    import functools
    context = contextvars.copy_context()
    invoke = functools.partial(fn, *args, cancel=poll, **kwargs)
    fut = asyncio.get_running_loop().run_in_executor(None, context.run, invoke)
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


def _record_lifecycle(image: str, outcome: str, started_wall: float, started: float,
                      returncode, receipt: dict | None) -> None:
    """Stamp the receipt with start/finish/duration and append the bounded
    lifecycle record (image, outcome, duration, return code)."""
    duration_ms = round((time.monotonic() - started) * 1000.0, 3)
    finished_wall = started_wall + duration_ms / 1000.0
    if receipt is not None:
        receipt.update(started_at=started_wall, finished_at=finished_wall, duration_ms=duration_ms)
    _LIFECYCLE.append({"image": image, "outcome": outcome, "duration_ms": duration_ms,
                       "returncode": returncode, "started_at": started_wall})


def lifecycle_snapshot(since: float | None = None) -> dict:
    """Plain-data view of the tool lifecycle: the recent run records, per-image
    counts and total milliseconds, and the docker availability checks (how many
    ran, how many were served from the cache, and their total ms). `since` (a
    time.time() stamp) limits it to records from that moment on."""
    runs = [dict(r) for r in list(_LIFECYCLE) if since is None or r["started_at"] >= since]
    checks = [c for c in list(_CHECKS) if since is None or c["at"] >= since]
    by_image: dict[str, dict] = {}
    for r in runs:
        row = by_image.setdefault(r["image"], {"runs": 0, "total_ms": 0.0})
        row["runs"] += 1
        row["total_ms"] = round(row["total_ms"] + r["duration_ms"], 3)
    return {"runs": runs, "by_image": by_image,
            "total_ms": round(sum(r["duration_ms"] for r in runs), 3),
            "availability_checks": {"checks": len(checks),
                                    "cached": sum(1 for c in checks if c["cached"]),
                                    "failed": sum(1 for c in checks if not c["ok"]),
                                    "total_ms": round(sum(c["ms"] for c in checks), 3)}}


def run(image: str, args: list[str], *, timeout: float = 120.0,
        add_host: bool = True, extra: list[str] | None = None,
        egress: "EgressPolicy | None" = None, enforce_egress: bool = False,
        cancel=None, receipt: dict | None = None,
        max_output: int = DEFAULT_MAX_OUTPUT,
        require_digest: bool = False) -> tuple[int, str, str]:
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
    supplied, is populated with tool/image/argv/egress/outcome/cleanup fields.

    P3-2: the image reference is validated before launch. A malformed
    `@sha256:` digest is refused (ImageReferenceError), as is an unpinned one when
    `require_digest`; a pinned digest is passed to docker unchanged, so docker
    runs exactly that content, and the receipt records it."""
    image_ref = validate_image_ref(image, require_digest=require_digest)
    if enforce_egress and egress is None:
        raise EgressPolicyRequired(
            f"refusing to launch {image!r}: no egress policy configured for this run "
            "(PR-11/R02 fail-closed -- an uncontrolled-egress tool run is not allowed)")
    import uuid
    started_wall, started = time.time(), time.monotonic()
    name = f"harness_{uuid.uuid4().hex[:12]}"
    cmd = docker_cmd(image, args, add_host=add_host,
                     extra=["--name", name] + list(extra or []), egress=egress)
    if receipt is not None:
        receipt.update({
            "tool_image": image,
            "tool_image_digest": image_ref.digest,
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
        _record_lifecycle(image, "cancelled_before_launch", started_wall, started, None, receipt)
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
        removed = _force_remove(name)
        _record_lifecycle(image, outcome if removed else "cleanup_failed", started_wall, started,
                          None, receipt)
        if not removed:
            if receipt is not None:
                receipt["cleanup"] = "cleanup_failed"
            raise ToolCleanupFailed(
                f"container {name} could not be proved removed after {outcome}") from exc
        raise
    if result.returncode == 125:
        # docker itself failed (daemon gone, image missing): the cached positive
        # check is stale, so the next caller re-checks and can fall back.
        _reset_available_cache()
    if receipt is not None:
        receipt["outcome"] = f"exit={result.returncode}"
        receipt.update(result.receipt_fields())
    _record_lifecycle(image, f"exit={result.returncode}", started_wall, started,
                      result.returncode, receipt)
    return result.returncode, (result.stdout or ""), (result.stderr or "")
