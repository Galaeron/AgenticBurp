"""
Scope lock (safety item #12) -- one shared home for the host-in-scope check that
22 validators each reimplemented inline, plus the central defense-in-depth used by
the safety gate.

The engagement is authorised against `server.allowed_hosts`. An active probe must
never send to a host outside that set -- and in particular must never FOLLOW an
off-scope link (a redirect, a URL scraped from the target's own content, an
attacker-planted webhook value) to a third party. Individual validators already
gate their own primary send, but the checks drifted (different spellings, and
`SqlmapValidator` had none at all -- it ran sqlmap straight at `exchange.url`).
This module makes the check one function so it cannot drift, and the gate calls it
so even a validator that forgets is stopped at the transport.

`allowed_hosts` empty means "no host restriction configured" -- the historical
default for a standalone caller that never set scope. It is deliberately
fail-OPEN only when unset and fail-CLOSED (deny) for any host not listed once a
non-empty scope IS configured.

P1-9 CONTRACT: `host_in_scope` (like `ScopePolicy.in_scope` in run_context.py,
the other scope authority) is a HOSTNAME-STRING membership check. It runs
before DNS resolution and does not itself resolve the hostname or pin the
address ultimately connected to -- httpx resolves and connects afterwards, on
its own, outside this check. An unlisted hostname is refused regardless of
what it would resolve to (tested); but a hostname that IS in `allowed_hosts`
and later resolves to a different address than it did at scope-check time
(DNS rebinding) is NOT caught by this function -- the string is still allowed,
so this still returns True. This is a hostname-authorization boundary, not an
address-level rebinding defense; see harness/test_dns_resolution_boundary.py
and IMPROVEMENT_BACKLOG.md P1-9 for the characterization and the proposed
(not yet built) connect-time address-pinning follow-up.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _host_name(value: str) -> str | None:
    """Canonical spelling, without authorizing aliases or dropping a final dot."""
    if not value or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        host = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = host[:-1].split(".") if host.endswith(".") else host.split(".")
    if len(host) > 254 or not all(_LABEL.fullmatch(label) for label in labels):
        return None
    return host


@dataclass(frozen=True)
class ScopeURL:
    scheme: str
    host: str
    port: int

    @property
    def origin(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = "" if self.port == _DEFAULT_PORTS[self.scheme] else f":{self.port}"
        return f"{self.scheme}://{host}{port}"


def parse_scope_url(url: str) -> ScopeURL | None:
    """Validate before every policy decision; malformed URLs return a denial."""
    if not isinstance(url, str) or not url or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url) or "\\" in url:
        return None
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in _DEFAULT_PORTS or not parsed.netloc or parsed.username is not None or parsed.password is not None:
            return None
        # urlsplit accepts an empty explicit port, which is ambiguous at clients.
        if parsed.netloc.endswith(":"):
            return None
        host = _host_name(parsed.hostname or "")
        port = parsed.port if parsed.port is not None else _DEFAULT_PORTS[scheme]
        if host is None or not 1 <= port <= 65535:
            return None
        return ScopeURL(scheme, host, port)
    except (ValueError, UnicodeError):
        return None


@dataclass(frozen=True)
class ScopeEntry:
    host: str | None = None
    scheme: str | None = None
    port: int | None = None
    network: object | None = None
    subdomains: bool = False


def parse_scope_entry(entry: str, *, extended: bool = False) -> ScopeEntry | None:
    """One parser with explicit caller profiles; strict remains exact-host only.

    Extended parsing remains available for compatibility/inspection. Production
    authorization adapters use only the strict intersection, so these richer
    forms never grant wildcard/network/origin reachability to a strict caller.
    """
    if not isinstance(entry, str) or not entry or entry != entry.strip() or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in entry) or "\\" in entry or "@" in entry:
        return None
    scheme = None
    value = entry
    if "://" in value:
        if not extended:
            return None
        scheme, value = value.split("://", 1)
        scheme = scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            return None
    if "/" in value:
        if not extended:
            return None
        try:
            network = ipaddress.ip_network(value, strict=False)
            return ScopeEntry(scheme=scheme, network=network)
        except ValueError:
            return None  # never discard a malformed path and widen the entry
    # Bare IPv6 is unambiguous as an exact address, with no port suffix.
    try:
        address = ipaddress.ip_address(value)
        return ScopeEntry(host=str(address), scheme=scheme)
    except ValueError:
        pass
    wildcard = value.startswith("*.")
    if wildcard:
        if not extended:
            return None
        value = value[2:]
    if "*" in value:
        return None
    if not extended:
        # Bare hostname only; preserve rejection of port/bracket/origin forms.
        if ":" in value or "[" in value or "]" in value:
            return None
        host = _host_name(value)
        return ScopeEntry(host=host) if host else None
    if "[" in value or "]" in value:
        # The discovery adapter never supported bracketed IPv6 allow entries;
        # recognizing URL brackets must not create new configured reachability.
        return None
    try:
        parsed = urlsplit("//" + value)
        if parsed.path or parsed.query or parsed.fragment or parsed.username is not None or not parsed.netloc or parsed.netloc.endswith(":"):
            return None
        host = _host_name(parsed.hostname or "")
        port = parsed.port
        if not host or port is not None and not 1 <= port <= 65535:
            return None
        if wildcard:
            try:
                ipaddress.ip_address(host)
                return None
            except ValueError:
                pass
        return ScopeEntry(host=host, scheme=scheme, port=port, subdomains=wildcard)
    except (ValueError, UnicodeError):
        return None


def scope_matches(url: str, allowed_hosts, *, extended: bool = False,
                  allow_unset: bool = False, allowed_schemes=None) -> bool:
    target = parse_scope_url(url)
    if target is None or allowed_schemes is not None and target.scheme not in allowed_schemes:
        return False
    entries = configured_entries(allowed_hosts)
    if not entries:
        return allow_unset
    for raw in entries:
        entry = parse_scope_entry(raw, extended=extended)
        if entry is None or entry.scheme is not None and target.scheme != entry.scheme or entry.port is not None and target.port != entry.port:
            continue
        if entry.network is not None:
            try:
                if ipaddress.ip_address(target.host) in entry.network:
                    return True
            except ValueError:
                pass
        elif target.host == entry.host or entry.subdomains and target.host.endswith("." + entry.host):
            return True
    return False


def configured_entries(values) -> frozenset:
    """Keep malformed container types invalid through caller configuration copies."""
    if values is None:
        return frozenset()
    if not isinstance(values, (list, tuple, set, frozenset)) or any(not isinstance(value, str) for value in values):
        return frozenset({None})  # nonempty invalid scope, never passive-unset
    return frozenset(values)


def host_of(url: str) -> str:
    parsed = parse_scope_url(url)
    return parsed.host if parsed else ""


def host_in_scope(url: str, allowed_hosts, *, active_mode: bool = False) -> bool:
    """Exact-host profile. Unset passive scope retains standalone admission;
    active scope and malformed URLs fail closed. Extended entries remain denied."""
    return scope_matches(url, allowed_hosts, allow_unset=not active_mode)


def out_of_scope_reason(url: str, allowed_hosts) -> str:
    entries = configured_entries(allowed_hosts)
    return (f"host {host_of(url)!r} is out of scope "
            f"(allowed_hosts={sorted(str(h).lower() for h in entries)})")
