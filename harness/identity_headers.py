"""
In-memory, NEVER-persisted transient credential store for tester-fed
cross-identity (Autorize-style) authorization testing.

The harness deliberately never writes session tokens to disk (see identity.py /
store.Session: a Session records a fingerprint, "not the credential itself…
without ever holding the token value"). The cross-identity validator, however,
needs another identity's real session headers at run time to replay a request as
that identity and see whether an access control actually holds.

This module holds those headers ONLY in process memory, for the lifetime of the
run -- exactly like Autorize's configured low-privilege cookie -- and provides no
persistence path whatsoever. It is cleared on restart. The tester populates it
(e.g. via POST /identities/session-headers); nothing here is ever logged, cached,
or written to a DB.

Ownership: a registration made outside any lease (the tester's endpoint) lives
until `clear`. A registration made inside a lease (`leased`, which wraps
Orchestrator.investigate_engagement) belongs to that engagement: it is visible
only to readers running in that engagement's context, and is removed when the
engagement ends -- returned, raised or cancelled -- so one engagement's roles
never become another's "other identities" on the same host.
"""
from __future__ import annotations
import contextvars
import functools
import threading

# host -> {identity_name: [{"owner": _Lease | None, "role": str, "headers": dict}, ...]}
# Each name keeps one claim per owner; the last claim visible to a reader wins.
_STORE: dict[str, dict[str, list[dict]]] = {}
_LOCK = threading.Lock()


class _Lease:
    __slots__ = ("parent",)

    def __init__(self, parent: "_Lease | None"):
        self.parent = parent


_LEASE: contextvars.ContextVar[_Lease | None] = contextvars.ContextVar(
    "identity_headers_lease", default=None)


def _visible_owners() -> list:
    owners, lease = [None], _LEASE.get()
    while lease is not None:
        owners.append(lease)
        lease = lease.parent
    return owners


def set_identity(host: str, name: str, headers: dict, role: str = "user") -> None:
    """Register (or replace) an identity's transient session headers for a host,
    owned by the current lease (if any)."""
    owner = _LEASE.get()
    with _LOCK:
        claims = _STORE.setdefault(host, {}).setdefault(name, [])
        claims[:] = [c for c in claims if c["owner"] is not owner]
        claims.append({"owner": owner, "role": role, "headers": dict(headers or {})})


def identities_for_host(host: str) -> list[dict]:
    """Identities visible to the caller for a host, each as {name, role, headers}."""
    owners = _visible_owners()
    out = []
    with _LOCK:
        for n, claims in _STORE.get(host, {}).items():
            seen = [c for c in claims if any(c["owner"] is o for o in owners)]
            if seen:
                out.append({"name": n, "role": seen[-1]["role"], "headers": dict(seen[-1]["headers"])})
    return out


def has_identities(host: str) -> bool:
    return bool(identities_for_host(host))


def _release(lease: _Lease) -> None:
    with _LOCK:
        for host in list(_STORE):
            names = _STORE[host]
            for n in list(names):
                names[n] = [c for c in names[n] if c["owner"] is not lease]
                if not names[n]:
                    del names[n]
            if not names:
                del _STORE[host]


def leased(fn):
    """Decorate an async function so identities it registers are released when it ends."""
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        lease = _Lease(_LEASE.get())
        token = _LEASE.set(lease)
        try:
            return await fn(*args, **kwargs)
        finally:
            _LEASE.reset(token)
            _release(lease)
    return wrapper


def clear(host: str | None = None) -> None:
    """Forget transient credentials -- for one host, or all of them."""
    with _LOCK:
        if host is None:
            _STORE.clear()
        else:
            _STORE.pop(host, None)
