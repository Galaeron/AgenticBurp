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


def docker_cmd(image: str, args: list[str], *, add_host: bool = True,
               extra: list[str] | None = None, harden: bool = True) -> list[str]:
    """The full `docker run` argv for `image` + `args`. Always ephemeral (--rm)
    and, by default, sandbox-hardened (W-26; see _HARDENING_FLAGS). Pure/
    inspectable so callers (and tests) can assert on it without running it."""
    cmd = [DOCKER, "run", "--rm"]
    if harden:
        cmd += _HARDENING_FLAGS
    if add_host:
        cmd += ["--add-host", f"{_HOST_ALIAS}:host-gateway"]
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
        add_host: bool = True, extra: list[str] | None = None) -> tuple[int, str, str]:
    """Run `image` with `args` in a throwaway container. Returns
    (returncode, stdout, stderr). Raises subprocess.TimeoutExpired on timeout so
    the caller can treat a hung tool distinctly from a clean non-zero exit.

    The container is given a unique `--name` so that on TIMEOUT we can verifiably
    terminate it (#11) -- killing the CLI client alone does not stop the container."""
    import uuid
    name = f"harness_{uuid.uuid4().hex[:12]}"
    cmd = docker_cmd(image, args, add_host=add_host,
                     extra=["--name", name] + list(extra or []))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except subprocess.TimeoutExpired:
        _force_remove(name)   # the hung workload must not outlive its client
        raise
