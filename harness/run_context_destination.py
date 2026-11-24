"""I05-B connect-time destination policy (AddressPins and the pinned network
backend), split from run_context.py (ARC-9). Import these names from
harness.run_context; this module reads run_context's names at call time,
so a patched `run_context._default_resolver` reaches AddressPins.
"""
from __future__ import annotations

import ipaddress
import socket
import threading

import httpcore


# ---------------------------------------------------------------------------
# I05-B: connect-time destination policy -- one address per name for the whole run.
#
# ScopePolicy authorizes HOSTNAMES, not resolved addresses (see its docstring). A
# name whose DNS answer changes during a run (DNS rebinding) could otherwise move a
# later request or redirect hop to another address -- an internal service, the
# tester's own loopback services, or cloud metadata. Every client a run builds
# therefore connects through AddressPins: each name is resolved ONCE per run and
# that first answer holds for every later request and redirect hop. A name that
# resolves to a special-purpose address (link-local incl. 169.254.169.254, multicast,
# unspecified, reserved) is refused before any socket opens; an IP-literal URL is
# connected as written (scope must already list that literal).
#
# The pin sits in the httpcore network backend, so the Host header, TLS SNI and
# certificate hostname checks stay on the name, and nothing changes for clients that
# never open a socket (mock transports). ON by default; `security.pin_connect_address:
# false` is an explicit opt-out. ARC-14: target clients never honour HTTP(S)_PROXY /
# ALL_PROXY from the environment (trust_env=False), so a proxy can never take over
# resolving the target and bypass the pin; the harness has no configured upstream
# proxy for target traffic. A name whose FIRST answer is private or loopback is
# accepted -- lab targets do that.
# ---------------------------------------------------------------------------

class DestinationBlocked(Exception):
    """A connect the run's destination policy refused before any socket opened."""


def _default_resolver(host: str) -> str:
    """Resolve `host` to a single IP once. Prefers IPv4; raises on failure so the
    caller records an honest error artifact rather than sending unpinned."""
    infos = socket.getaddrinfo(host, None)
    for family in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == family:
                return info[4][0]
    return infos[0][4][0]


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def special_purpose_reason(ip: str) -> str:
    """Why `ip` is never a target reached through a NAME, or "" when it may be."""
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.is_loopback:      # ::1 sits in a "reserved" block; loopback is allowed like 127/8
        return ""
    for label, hit in (("link-local", addr.is_link_local), ("multicast", addr.is_multicast),
                       ("unspecified", addr.is_unspecified), ("reserved", addr.is_reserved)):
        if hit:
            return f"resolved to a special-purpose ({label}) address {addr}"
    return ""


class AddressPins:
    """Per-run name -> address pins; the first answer for a name holds for the run."""

    def __init__(self, resolver=None):
        self.resolver = resolver or _rc._default_resolver
        self._pins: dict[str, str] = {}
        self._lock = threading.Lock()

    def pinned(self) -> dict:
        with self._lock:
            return dict(self._pins)

    async def address_for(self, host: str) -> str:
        if _is_ip_literal(host):
            return host
        key = host.lower()
        with self._lock:
            ip = self._pins.get(key)
        if ip is None:
            import asyncio
            resolved = await asyncio.to_thread(self.resolver, host)   # raises on failure
            with self._lock:
                ip = self._pins.setdefault(key, resolved)   # a racing first answer wins
        reason = special_purpose_reason(ip)
        if reason:
            raise DestinationBlocked(f"{host} {reason}; no connection was opened")
        return ip


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend that connects a name to its run-pinned address."""

    def __init__(self, pins: AddressPins):
        self._pins = pins
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None,
                          socket_options=None):
        ip = await self._pins.address_for(host)
        return await self._inner.connect_tcp(ip, port, timeout=timeout,
                                             local_address=local_address,
                                             socket_options=socket_options)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        return await self._inner.connect_unix_socket(path, timeout=timeout,
                                                     socket_options=socket_options)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _pinned_backend(pins: "AddressPins | None"):
    """The connect-time pin for a run's clients (None = connect by name)."""
    return _PinnedBackend(pins) if pins is not None else None


# Bound last (run_context imports this module): read only at call time.
from harness import run_context as _rc  # noqa: E402
