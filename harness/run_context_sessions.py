"""Run-context sessions and route health, split from run_context.py (ARC-9).

One persistent client and cookie jar per principal (SessionManager) and the
per-route 5xx circuit (TransportHealth). Import these names from
harness.run_context; this module reads run_context's names at call time.
"""
from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field

import httpx

from harness.tls_policy import TLSPolicy


# ---------------------------------------------------------------------------
# Sessions -- one persistent client + cookie jar per principal (no cross-talk)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HealthProbe:
    """A request that tells a rejected session from a route that merely refuses it."""
    method: str
    url: str
    expect_status: tuple = (200,)


@dataclass
class ManagedSession:
    """A principal's authenticated session: its auth headers plus its OWN persistent
    httpx client (with an isolated cookie jar). Reusing one client per session keeps
    connections warm (fixes the per-request-client waste) while guaranteeing cookies
    never cross principals."""
    session_id: str
    principal_id: str
    headers: dict = field(default_factory=dict)   # Authorization/etc.; the credential, kept out of findings
    allowed_origins: frozenset = frozenset()
    role: str = "user"
    name: str = ""
    principal: object | None = None
    # A one-request credential (send_creds): headers a check or the agent supplied
    # for its own send, which no configured identity owns. It carries that send's
    # credentials and cookie jar; it is never one of the run's identities.
    ephemeral: bool = False
    # Bumped each time the session's credentials are replaced (a refresh or
    # SessionManager.replace_headers). A caller that caches anything derived from
    # the credentials -- a token, decoded claims, a cache key -- must key it on
    # (session_id, generation) so a refreshed session never serves stale state.
    generation: int = 0
    # R11-6: digests (never values) of the credentials this session held before a
    # replace_headers. A capture made with an earlier token is still this
    # identity's request (run_tokens.issued_identity).
    retired_credentials: set = field(default_factory=set, repr=False)
    # E5a health: "unverified" until a send is accepted, then "healthy"; "suspect"
    # after a 401 the run could not explain; "expired" once the health probe rejected
    # the credentials and no refresh restored them (sends are then refused unsent).
    health: str = "unverified"
    last_ok_at: float = 0.0          # wall clock of the last send the target accepted
    auth_failures: int = 0           # 401s seen on sends that carried this session's credentials
    _probe: "HealthProbe | None" = field(default=None, repr=False)
    _refresh_fn: object = field(default=None, repr=False)
    # R11-8 (b): the operator-declared login of this identity (its credentials,
    # kept in memory only and never logged) and the base URL it resolves against.
    # Only an identity the run owns has one; legs that log in act only on it.
    login: dict | None = field(default=None, repr=False)
    login_base: str = field(default="", repr=False)
    _refreshes: int = field(default=0, repr=False)
    _checked_at: "float | None" = field(default=None, repr=False)   # _clock() of the last probe
    _expiry_reported: bool = field(default=False, repr=False)
    _lock: object = field(default=None, repr=False)
    _lock_loop: object = field(default=None, repr=False)
    _client: httpx.AsyncClient | None = None
    _fixture_clients: dict = field(default_factory=dict, repr=False)

    def health_lock(self) -> asyncio.Lock:
        """Serialises one session's health checks so a burst of 401s probes once.
        Bound to the running loop; a new loop gets a fresh lock."""
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock, self._lock_loop = asyncio.Lock(), loop
        return self._lock

    def client(self, timeout: float, *, http2: bool = False,
               trust_policy: TLSPolicy | None = None, destination: str | None = None,
               address_pins: "AddressPins | None" = None) -> httpx.AsyncClient:
        policy = trust_policy or TLSPolicy.from_config()
        profile = policy.profile_for(destination)
        if profile.pool_key:
            if profile.pool_key not in self._fixture_clients:
                self._fixture_clients[profile.pool_key] = _rc._target_client(
                    verify=profile.context, timeout=timeout, http2=http2, pins=address_pins)
            return self._fixture_clients[profile.pool_key]
        if self._client is None:
            self._client = _rc._target_client(verify=profile.context, timeout=timeout,
                                          http2=http2, pins=address_pins)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        for client in self._fixture_clients.values():
            await client.aclose()
        self._fixture_clients.clear()


class SessionManager:
    def __init__(self):
        self._by_id: dict[str, ManagedSession] = {}

    def register(self, session_id: str, principal_id: str, headers: dict | None = None, *,
                 allowed_origins=None, role: str = "user", name: str = "",
                 principal=None, ephemeral: bool = False) -> ManagedSession:
        normalized = frozenset(_rc.ScopePolicy.origin_of(o) for o in (allowed_origins or []))
        if "" in normalized:
            raise ValueError("sessions require valid HTTP(S) allowed origins")
        if headers and not normalized:
            raise ValueError("credential-bearing sessions require an explicit allowed origin")
        s = ManagedSession(session_id=session_id, principal_id=principal_id,
                           headers=dict(headers or {}), allowed_origins=normalized,
                           role=role, name=name or principal_id, principal=principal,
                           ephemeral=ephemeral)
        self._by_id[session_id] = s
        return s

    async def unregister(self, session_id: str) -> None:
        """Drop and close one session (I05: a learned credential's ephemeral
        re-crawl session must not outlive that re-crawl inside the run)."""
        s = self._by_id.pop(session_id, None)
        if s is not None:
            await s.aclose()

    def get(self, session_id: str | None) -> ManagedSession | None:
        return self._by_id.get(session_id) if session_id else None

    def all(self) -> list[ManagedSession]:
        return list(self._by_id.values())

    def identities(self) -> list[ManagedSession]:
        """The run's identities: every session except the ephemeral ones send_creds
        registers for one check's own credentials. A check that replays "as each
        identity" reads this. r9: the agent's empty `Bearer ` header and other
        one-off credentials had become identities, and cross_identity re-sent
        each later check as them (355 refused sends)."""
        return [s for s in self._by_id.values() if not s.ephemeral]

    # -- E5a: session health -------------------------------------------------

    def register_health_probe(self, session_id: str, method: str, url: str,
                              expect_status=(200,)) -> HealthProbe:
        """Set the request that checks `session_id` after one of its sends got a 401.
        It is sent through that same session, so `url` must be on one of its allowed
        origins. Without a probe (and without `transport.session_probe`) a session is
        never rechecked and never expires."""
        session = self._by_id.get(session_id)
        if session is None:
            raise ValueError(f"unknown session reference: {session_id}")
        statuses = (expect_status,) if isinstance(expect_status, int) else tuple(expect_status)
        session._probe = HealthProbe((method or "GET").upper(), url, statuses)
        return session._probe

    def set_refresh(self, session_id: str, fn) -> None:
        """Register `async fn() -> dict | None` that re-authenticates this identity and
        returns its new headers (None when it could not). It runs only after the health
        probe rejected the credentials, at most `transport.max_session_refreshes` times
        per session per run."""
        session = self._by_id.get(session_id)
        if session is None:
            raise ValueError(f"unknown session reference: {session_id}")
        session._refresh_fn = fn

    def set_login(self, session_id: str, login: dict, base_url: str) -> None:
        """Keep this identity's declared login (role.login) for legs that must log
        in as a run-owned identity (R11-8 b). In memory only; never logged."""
        session = self._by_id.get(session_id)
        if session is None:
            raise ValueError(f"unknown session reference: {session_id}")
        session.login, session.login_base = dict(login or {}), str(base_url or "")

    def replace_headers(self, session_id: str, headers: dict) -> ManagedSession:
        """Install new credentials for a session: bumps `generation`, marks it
        healthy, and drops the cookie jar (its cookies belonged to the old login)."""
        session = self._by_id.get(session_id)
        if session is None:
            raise ValueError(f"unknown session reference: {session_id}")
        from harness import run_tokens
        old, _ = run_tokens.issued_digests(session.headers)
        session.retired_credentials |= old
        session.headers = dict(headers or {})
        session.generation += 1
        session.health = "healthy"
        session.last_ok_at = time.time()
        session._expiry_reported = False
        for client in [session._client, *session._fixture_clients.values()]:
            if client is not None:
                client.cookies.clear()
        return session

    def bind_headers(self, headers: dict | None) -> tuple[str | None, dict]:
        """Resolve credential headers to their owning session.

        Returns the session reference plus non-credential request headers. If no
        registered session owns supplied credentials, leaves them in place so
        Executor's credential-without-session rule fails closed.
        """
        supplied = dict(headers or {})
        # Identity credentials only: a CSRF/XSRF token or Idempotency-Key that a
        # capture carries (or a role was configured with) changes per page and
        # does not say who is calling, so it neither blocks the match nor is
        # removed -- it stays in the returned headers and is sent as captured.
        wanted = {k.lower(): v for k, v in supplied.items()
                  if _rc.is_identity_credential_header(k)}
        if not wanted:
            return None, supplied
        for session in self._by_id.values():
            actual = {k.lower(): v for k, v in session.headers.items()
                      if _rc.is_identity_credential_header(k)}
            if actual == wanted:
                return session.session_id, {
                    k: v for k, v in supplied.items()
                    if not _rc.is_identity_credential_header(k)}
        return None, supplied

    def identity_principal(self, headers: dict | None) -> str:
        """The principal of the run identity whose credentials `headers` carry, else "".

        A capture made with a configured user's token is that user's request. r9
        filed its proofs under "captured" and the same user's role-session proofs
        under the user's name, so one forged-JWT root cause was two issues. Only a
        named identity answers: not the capture's own credential alias ("captured",
        registered when no identity owns the credentials) nor a one-send session."""
        ref, _ = self.bind_headers(headers)
        session = self._by_id.get(ref) if ref else None
        if session is None or session.ephemeral or session.session_id == "captured":
            return ""
        return session.principal_id or ""

    async def aclose(self) -> None:
        for s in self._by_id.values():
            await s.aclose()


# ---------------------------------------------------------------------------
# Route circuit + health events -- what the run learned about its own transport
# ---------------------------------------------------------------------------

@dataclass
class _RouteState:
    errors_5xx: int = 0
    saw_non_5xx: bool = False         # once true the route answers: never paused again
    open: bool = False
    opened_at: float = 0.0
    reported: bool = False


class TransportHealth:
    """Per-run record of routes that answer 5xx to everything and of the one-time
    health events (session expired, route paused). Shared by every TargetTransport
    built from the run, so the state is the run's, not one transport's.

    A route is keyed (method, origin, route template). It opens only when it has
    NEVER answered with a non-5xx and has returned `threshold` 5xx responses, so a
    payload-induced 5xx on a route that normally answers never pauses it. Once
    open, one send is let through per cooldown (half-open); any non-5xx closes it
    for good."""

    def __init__(self):
        self._routes: dict[tuple, _RouteState] = {}
        self._events: list[dict] = []
        self._lock = threading.Lock()

    @staticmethod
    def route_key(method: str, url: str) -> tuple:
        from harness import engagement   # lazy: the one route-template normalizer
        return ((method or "GET").upper(), _rc.ScopePolicy.origin_of(url),
                engagement.normalize_path(url))

    @staticmethod
    def route_key_for(method: str, url: str, session) -> tuple:
        """route_key plus the calling principal: a route that answers 5xx to
        anonymous can still answer an authenticated user (and an IDOR leg needs
        that answer), so each identity's circuit is its own."""
        principal = (session.principal_id if session is not None
                     and _rc.ScopePolicy.origin_of(url) in session.allowed_origins else "")
        return TransportHealth.route_key(method, url) + (principal,)

    def record_event(self, kind: str, message: str, **detail) -> None:
        with self._lock:
            self._events.append({"kind": kind, "message": message, "at": time.time(), **detail})

    def events(self) -> list[dict]:
        with self._lock:
            return [dict(e) for e in self._events]

    def route_blocked(self, key: tuple, cooldown: float) -> bool:
        """True when `key`'s circuit is open and this send must not go out. After the
        cooldown it admits ONE send (and restarts the cooldown) as the half-open probe."""
        with self._lock:
            state = self._routes.get(key)
            if state is None or not state.open:
                return False
            now = _rc._clock()
            if now - state.opened_at >= cooldown:
                state.opened_at = now
                return False
            return True

    def route_observed(self, key: tuple, status: int, threshold: int) -> None:
        with self._lock:
            state = self._routes.setdefault(key, _RouteState())
            if 500 <= status <= 599:
                state.errors_5xx += 1
                if (not state.saw_non_5xx and not state.open
                        and state.errors_5xx >= max(1, threshold)):
                    state.open, state.opened_at = True, _rc._clock()
                    if not state.reported:
                        state.reported = True
                        self._events.append({
                            "kind": "route_paused", "at": time.time(),
                            "route": f"{key[0]} {key[2]}", "origin": key[1],
                            "message": f"route {key[0]} {key[2]} returned 5xx on all "
                                       f"{state.errors_5xx} requests; further probes skipped"})
                return
            state.saw_non_5xx = True
            state.open = False

    def paused_routes(self) -> list[dict]:
        with self._lock:
            return [{"route": f"{k[0]} {k[2]}", "origin": k[1], "errors_5xx": s.errors_5xx}
                    for k, s in self._routes.items() if s.open]


# Bound last (run_context imports this module): read only at call time.
from harness import run_context as _rc  # noqa: E402
