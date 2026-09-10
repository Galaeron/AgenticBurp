"""Small validator-to-RunContext adapter helpers (T08).

Credentials remain session-owned: validators identify the matching run session
from a captured exchange, then send only non-credential request headers through
the executor.  A missing match deliberately leaves the credentials on the typed
request so Executor fails closed instead of silently replaying anonymously.
"""
from __future__ import annotations

_CREDENTIAL_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


def bind_session(run_context, headers: dict | None) -> tuple[str | None, dict]:
    return run_context.sessions.bind_headers(headers)
