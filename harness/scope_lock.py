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

from urllib.parse import urlsplit


def host_of(url: str) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""


def host_in_scope(url: str, allowed_hosts) -> bool:
    """True when `url`'s host is in scope. An empty/None `allowed_hosts` means no
    scope is configured -> in scope (unchanged standalone behaviour). A non-empty
    scope fails closed: a host not listed is out of scope."""
    if not allowed_hosts:
        return True
    host = host_of(url)
    if not host:
        return False  # unparseable host under a configured scope -> deny
    allowed = {str(h).lower() for h in allowed_hosts}
    return host in allowed


def out_of_scope_reason(url: str, allowed_hosts) -> str:
    return (f"host {host_of(url)!r} is out of scope "
            f"(allowed_hosts={sorted(str(h).lower() for h in allowed_hosts)})")
