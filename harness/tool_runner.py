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

import shutil
import subprocess
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

# Resolve the docker CLI: PATH first, then the Docker Desktop default location so
# this works from a shell whose PATH doesn't include it.
DOCKER = shutil.which("docker") or r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"

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
    zero-arg callable, or ``None`` (never cancelled). Stdlib-only."""
    if cancel is None:
        return False
    try:
        import asyncio
        if isinstance(cancel, asyncio.Event):
            return cancel.is_set()
    except Exception:
        pass
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


def _force_remove(name: str) -> None:
    """Force-stop and remove a named container (#11). `docker run --rm` only cleans
    up on the container's OWN exit; if we time out and kill the docker CLI client,
    the container can keep running. `docker rm -f` verifiably terminates it."""
    try:
        subprocess.run([DOCKER, "rm", "-f", name], capture_output=True, text=True, timeout=15)
    except Exception:
        pass


def run(image: str, args: list[str], *, timeout: float = 120.0,
        add_host: bool = True, extra: list[str] | None = None,
        egress: "EgressPolicy | None" = None, enforce_egress: bool = False,
        cancel=None, receipt: dict | None = None) -> tuple[int, str, str]:
    """Run `image` with `args` in a throwaway container. Returns
    (returncode, stdout, stderr). Raises subprocess.TimeoutExpired on timeout so
    the caller can treat a hung tool distinctly from a clean non-zero exit.

    The container is given a unique `--name` so that on TIMEOUT (or any other
    non-clean exit) we can verifiably terminate it (#11) -- killing the CLI client
    alone does not stop the container. `docker run --rm` only cleans up on the
    container's OWN clean exit, so cleanup is done in a `finally` for every path
    that is not a clean return.

    PR-11/R02: `egress` threads a per-run egress policy into the argv; with
    `enforce_egress=True` a run that has NO policy is refused (EgressPolicyRequired,
    fail closed). `cancel` (an asyncio.Event or zero-arg callable) aborts before
    launch. `receipt`, when supplied, is populated with tool/image/argv/egress/
    outcome for a caller-inspectable record."""
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
    cleanup_needed = True
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        cleanup_needed = False   # clean exit -- --rm already removed it
        if receipt is not None:
            receipt["outcome"] = f"exit={r.returncode}"
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except subprocess.TimeoutExpired:
        if receipt is not None:
            receipt["outcome"] = "timeout"
        raise
    except Exception:
        if receipt is not None:
            receipt["outcome"] = "error"
        raise
    finally:
        if cleanup_needed:
            _force_remove(name)   # the hung/killed workload must not outlive its client
