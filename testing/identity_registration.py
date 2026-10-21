"""Phase 1.1 -- register two test accounts for the target host before analysis.

The cross-user (Autorize-style) access-control checks only arm when
``identity_headers.has_identities(host)`` is true for the host derived from the
exchange URL. Both the registry and the validator key off the BARE hostname with
no port (``registry.py`` uses ``urlsplit(url).hostname``; ``cross_identity_validator``
uses ``urlparse(url).hostname``). The previous crAPI run registered no identities,
so the cross-user validator silently sat out the entire run -- the single setup gap
that made that run test the wrong thing. This helper closes it.

``register_identities()`` signs up (idempotent/best-effort) and logs in each
account against the target's auth API, reads its bearer token, and registers that
identity's real session header for the host -- in-process by default
(``identity_headers.set_identity``), or against a running harness server
(``POST /identities/session-headers``). It emits a run-log line per registration
and returns a structured log, so the eval scripts can show BOTH accounts
registered *before the first exchange* (the Phase 1.1 "done when"). It fails LOUD
(``RegistrationError``) if any account cannot be logged in: registering a partial
identity set would silently skip the cross-user checks again, which is exactly the
failure mode being fixed.

Credentials are transient. The bearer token lives only in the in-memory identity
store (never persisted, logged, or cached -- see ``harness/identity_headers.py``);
this helper writes nothing to disk.

The eval scripts (``eval-run/capture.py`` / ``eval-run/run_analysis.py``, which
live outside the repo) call this at startup, e.g.::

    import sys; sys.path.insert(0, "<repo>"); sys.path.insert(0, "<repo>/testing")
    from identity_registration import register_identities, Account
    register_identities(base_url, [Account("victimA", a_email, a_pw),
                                   Account("victimB", b_email, b_pw)])
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)


class RegistrationError(RuntimeError):
    """A target account could not be logged in -- raised instead of registering a
    partial identity set that would silently skip the cross-user checks."""


@dataclass(frozen=True)
class Account:
    """One test identity. ``name`` is the label the cross-user validator reports;
    ``role`` groups identities (two 'user' accounts suffice for BOLA/IDOR). Extra
    target-specific signup fields (crAPI wants ``name``/``number``) go in
    ``signup_fields``."""
    name: str
    email: str
    password: str
    role: str = "user"
    signup_fields: dict = field(default_factory=dict)


@dataclass(frozen=True)
class AuthApi:
    """How to reach the target's signup/login and read the token out. Defaults
    match crAPI's identity service (``POST /identity/api/auth/{signup,login}``,
    JSON response ``{"token": "<jwt>"}``, used as ``Authorization: Bearer <jwt>``)."""
    signup_path: str = "/identity/api/auth/signup"
    login_path: str = "/identity/api/auth/login"
    token_field: str = "token"
    header_name: str = "Authorization"
    header_scheme: str = "Bearer"
    login_identifier_field: str = "email"
    login_secret_field: str = "password"


def _now_iso(clock) -> str:
    return (clock or (lambda: datetime.now(timezone.utc)))().isoformat()


def register_identities(base_url, accounts, *, host=None, auth_api=None,
                        via="in_process", server_url=None, server_token=None,
                        client=None, timeout=10.0, clock=None) -> dict:
    """Authenticate each account and register its session header for ``host``.

    ``via`` selects where the identity is stored: ``"in_process"`` (default) calls
    ``identity_headers.set_identity`` directly -- correct when the eval script runs
    the harness in-process; ``"server"`` POSTs to ``{server_url}/identities/session-headers``
    (requires ``server_token``) -- correct when it drives a running harness server.

    Returns a run-log dict ``{"host", "base_url", "via", "registered": [...]}`` where
    each entry is ``{"name", "role", "at", "header"}``. Raises ``RegistrationError``
    if any account cannot be logged in, and ``ValueError`` for an unusable base_url,
    fewer than two accounts, or a bad ``via``.
    """
    auth_api = auth_api or AuthApi()
    host = host or (urlsplit(base_url).hostname or "")
    if not host:
        raise ValueError(f"could not derive a host from base_url={base_url!r}")
    accounts = list(accounts)
    if len(accounts) < 2:
        raise ValueError(
            f"cross-user checks need at least two accounts; got {len(accounts)}")
    if via not in ("in_process", "server"):
        raise ValueError(f"unknown via={via!r} (expected 'in_process' or 'server')")
    if via == "server" and not server_url:
        raise ValueError("via='server' requires server_url")

    owns_client = client is None
    client = client or httpx.Client(timeout=timeout)
    registered: list[dict] = []
    try:
        for acct in accounts:
            token = _authenticate(client, base_url, acct, auth_api)
            header = {auth_api.header_name: f"{auth_api.header_scheme} {token}".strip()}
            _store_identity(host, acct.name, header, acct.role, via=via,
                            server_url=server_url, server_token=server_token, client=client)
            at = _now_iso(clock)
            registered.append({"name": acct.name, "role": acct.role,
                               "at": at, "header": auth_api.header_name})
            log.info("identity registered before analysis: host=%s name=%s role=%s at=%s",
                     host, acct.name, acct.role, at)
    finally:
        if owns_client:
            client.close()
    return {"host": host, "base_url": base_url, "via": via, "registered": registered}


def _authenticate(client, base_url, acct: Account, auth_api: AuthApi) -> str:
    """Sign up (best-effort) then log in; return the bearer token or raise."""
    base = base_url.rstrip("/")
    # Signup is idempotent: an already-registered account is fine, we only need a
    # working login. Never let a signup 4xx ("already registered") abort the run.
    signup_body = {"email": acct.email, "password": acct.password, **acct.signup_fields}
    try:
        r = client.post(base + auth_api.signup_path, json=signup_body)
        log.info("signup %s -> %s", acct.email, getattr(r, "status_code", "?"))
    except httpx.HTTPError as e:
        log.info("signup %s raised %s (continuing to login)", acct.email, e)

    login_body = {auth_api.login_identifier_field: acct.email,
                  auth_api.login_secret_field: acct.password}
    try:
        r = client.post(base + auth_api.login_path, json=login_body)
    except httpx.HTTPError as e:
        raise RegistrationError(f"login request for {acct.email} failed: {e}") from e
    if r.status_code // 100 != 2:
        raise RegistrationError(
            f"login for {acct.email} returned {r.status_code}; cannot register a "
            f"cross-user identity without a session token")
    try:
        body = r.json()
    except ValueError as e:
        raise RegistrationError(f"login for {acct.email} returned a non-JSON body") from e
    token = body.get(auth_api.token_field) if isinstance(body, dict) else None
    if not token:
        raise RegistrationError(
            f"login for {acct.email} returned no {auth_api.token_field!r} token "
            f"(response keys: {sorted(body) if isinstance(body, dict) else type(body).__name__})")
    return token


def _store_identity(host, name, headers, role, *, via, server_url, server_token, client) -> None:
    if via == "in_process":
        from harness import identity_headers
        identity_headers.set_identity(host, name, headers, role)
        return
    # via == "server"
    hdrs = {"Authorization": f"Bearer {server_token}"} if server_token else {}
    resp = client.post(server_url.rstrip("/") + "/identities/session-headers",
                       json={"host": host, "name": name, "headers": headers, "role": role},
                       headers=hdrs)
    if resp.status_code // 100 != 2:
        raise RegistrationError(
            f"server refused identity {name!r} for {host}: {resp.status_code}")
