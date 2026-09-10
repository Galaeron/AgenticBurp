"""Small validator-to-RunContext adapter helpers (T08).

Credentials remain session-owned: validators identify the matching run session
from a captured exchange, then send only non-credential request headers through
the executor.  A missing match deliberately leaves the credentials on the typed
request so Executor fails closed instead of silently replaying anonymously.
"""
from __future__ import annotations

_CREDENTIAL_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


def bind_session(run_context, headers: dict | None) -> tuple[str | None, dict]:
    headers = dict(headers or {})
    wanted = {k.lower(): v for k, v in headers.items() if k.lower() in _CREDENTIAL_HEADERS}
    if not wanted:
        return None, headers
    for session in run_context.sessions.all():
        actual = {k.lower(): v for k, v in session.headers.items()
                  if k.lower() in _CREDENTIAL_HEADERS}
        if actual == wanted:
            return session.session_id, {
                k: v for k, v in headers.items() if k.lower() not in _CREDENTIAL_HEADERS}
    return None, headers
