"""
run_context.py -- run-scoped policy executor + scoped transport (Astra T03; #3/R15/R17).

Three defects this closes, together:

  - **#3 (run isolation):** authorization and evidence state were process-global (a
    single default SafetyGate, hostname-indexed transient headers). Two runs could
    contaminate each other. A `RunContext` bundles the per-run state -- its OWN gate,
    scope, budget, cancellation, and session manager -- so nothing authoritative is
    shared between runs (shared *resource* limits like the global throttle may stay
    global; authorization/evidence may not).

  - **R17 (fragmented scope/transport):** the gate had no host policy, its wrapper
    authorized only the FIRST request (httpx followed redirects internally, so a
    redirect hop bypassed scope and credential rules), and bytes/multipart bodies
    skipped inspection. `ScopedGatedClient` runs with `follow_redirects=False` and a
    MANUAL redirect loop, so scope is enforced before every hop, off-scope redirects
    are blocked before the destination is ever contacted, and credentials are not
    forwarded across an origin boundary.

  - **R15 (settings not authoritative):** one `TargetTransport` (the class formerly
    named `Executor`; that name is kept as an alias) routes every migrated send
    through the SAME gate decision, scope check, and budget -- scripts, API, and the
    graph all get identical allowed actions instead of each constructing validators
    and clients their own way. As of W-16 the orchestrator's second-order /
    discovery-confirm reads and the iterative agent are on it too, and callers with
    no run of their own reach it via `standalone_context()` / `transport_for()`.

Backward compatible: nothing here runs unless a caller builds a RunContext and uses
its executor. Browser/container adapters are T08, not claimed here. Cookie jars are
per session, never shared across principals.
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import ipaddress
import json
import socket
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpcore
import httpx

from harness import evidence
from harness import scope_lock
from harness.safety_gate import SafetyGate, SafetyGateConfig
from harness.security import is_credential_header, is_identity_credential_header
from harness.tls_policy import TLSPolicy
from harness.target_request_policy import TargetRequestPolicy

# Redirect status codes and the ones that rewrite the method to GET.
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_REDIRECT_TO_GET = frozenset({301, 302, 303})
# Request headers that carry credentials and must NOT cross an origin boundary are
# decided by security.is_credential_header (H1). This three-name set is the old,
# narrower rule, kept only as a deprecated alias for tests that import it; nothing in
# this module consults it.
_CREDENTIAL_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})
# Interval clock for session rechecks and route-circuit cooldowns (a name, so tests
# can advance it without sleeping).
_clock = time.monotonic
# E5a: a session that already answered a health probe is not probed again for this long.
_SESSION_RECHECK_SECONDS = 30.0
_HEALTH_CAPABILITY = "session_health"


def _response_size(resp) -> int:
    """Body bytes of a response; a stub client's response may carry only `.text`."""
    content = getattr(resp, "content", None)
    return len(content if content is not None else str(getattr(resp, "text", "")).encode("utf-8"))


def _session_expired_message(session) -> str:
    return (f"session {session.name} is expired: its credentials were rejected by the health "
            "probe; refresh or re-authenticate this identity to resume its tests")


# ---------------------------------------------------------------------------
# Scope policy -- the single origin/host authority (R17)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScopePolicy:
    """Which origins a run may contact. FAIL CLOSED: an empty allow-list permits
    nothing, so a misconfigured scope never silently allows the whole internet.

    P1-9 CONTRACT (read before relying on this for DNS-rebinding protection):
    `in_scope` is a HOSTNAME-STRING membership check against `allowed_hosts`. It
    does NOT resolve the hostname and does NOT pin the address httpx ultimately
    connects to -- DNS resolution happens later, inside httpx's own connect path,
    entirely outside this check. Consequently: (1) an unlisted hostname is always
    refused, regardless of what it resolves to -- that is real and tested; but
    (2) an ALREADY-ALLOWED hostname whose resolution changes between the scope
    check and the actual connect (classic DNS rebinding) is NOT caught here --
    the hostname string is still in `allowed_hosts`, so `in_scope` still returns
    True, and the request proceeds to whatever address it resolves to at connect
    time. This policy authorizes hostnames, not resolved addresses; it is not an
    address-level rebinding defense. See harness/test_dns_resolution_boundary.py
    for the characterization tests. I05-B: the address defense lives at the
    connect instead -- every client a run builds pins each name to its first
    answer for the whole run and refuses special-purpose addresses (AddressPins)."""
    allowed_hosts: frozenset = frozenset()
    allowed_schemes: frozenset = frozenset({"http", "https"})

    @staticmethod
    def origin_of(url: str) -> str:
        parsed = scope_lock.parse_scope_url(url)
        return parsed.origin if parsed else ""

    @staticmethod
    def host_of(url: str) -> str:
        return scope_lock.host_of(url)

    def in_scope(self, url: str) -> bool:
        return scope_lock.scope_matches(url, self.allowed_hosts,
                                        allowed_schemes=self.allowed_schemes)

    def same_origin(self, a: str, b: str) -> bool:
        origin = self.origin_of(a)
        return bool(origin) and origin == self.origin_of(b)


@dataclass(frozen=True)
class HostAllowScope(ScopePolicy):
    """Discovery compatibility adapter using the shared strict intersection.

    Bare hosts match exactly. Wildcard/CIDR/scheme/port forms grant no authority,
    preserving strict ScopePolicy/gate denials across every adapter. Empty passive
    admission remains compatible; active admission is closed. See SCOPE_POLICY.md.

    `hosts` is the ORIGINAL list (kept as a tuple so the dataclass stays hashable);
    the base `allowed_hosts` frozenset is left empty and unused by this subclass.
    """
    hosts: tuple = ()
    active_mode: bool = False

    def in_scope(self, url: str) -> bool:
        return scope_lock.scope_matches(url, self.hosts,
                                        allow_unset=not self.active_mode,
                                        allowed_schemes=self.allowed_schemes)


# ---------------------------------------------------------------------------
# Budget + cancellation -- atomic, per run
# ---------------------------------------------------------------------------

class RequestBudget:
    """A per-run ceiling on real network sends. `reserve` is atomic and reserves
    BEFORE the send; a denied reservation does NOT count as an executed request."""

    def __init__(self, max_requests: int | None = None):
        self._max = max_requests
        self._used = 0
        self._held = 0
        self._by_label: dict[str, int] = {}
        self._lock = threading.Lock()

    def reserve(self, n: int = 1, label: str = "") -> bool:
        """`label` names who spent the reservation (the transport passes the
        capability), so the count can be attributed afterwards; callers that do
        not know theirs leave it blank and are counted as "unlabelled"."""
        with self._lock:
            if self._max is not None and self._used + n > self._max - self._held:
                return False
            self._used += n
            key = label or "unlabelled"
            self._by_label[key] = self._by_label.get(key, 0) + n
            return True

    def hold(self, n: int) -> int:
        """Withhold up to `n` unspent requests from every reservation until
        `release_hold`, so a later stage keeps a share of the ceiling. Returns
        the amount actually held (0 for an unbounded budget)."""
        with self._lock:
            if self._max is None or n <= 0:
                return 0
            self._held = min(self._held + n, self._max - self._used)
            return self._held

    def release_hold(self) -> int:
        with self._lock:
            released, self._held = self._held, 0
            return released

    @property
    def used(self) -> int:
        return self._used

    @property
    def by_label(self) -> dict:
        """Reservations granted so far, per label (sums to `used`)."""
        with self._lock:
            return dict(self._by_label)

    @property
    def remaining(self) -> int | None:
        return None if self._max is None else max(0, self._max - self._used - self._held)


class CancelToken:
    """A cooperative cancellation flag. Thread-safe so a sync caller can cancel a
    run whose executor is awaiting."""

    def __init__(self):
        self._e = threading.Event()

    def cancel(self) -> None:
        self._e.set()

    @property
    def cancelled(self) -> bool:
        return self._e.is_set()


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
    # Bumped each time the session's credentials are replaced (a refresh or
    # SessionManager.replace_headers). A caller that caches anything derived from
    # the credentials -- a token, decoded claims, a cache key -- must key it on
    # (session_id, generation) so a refreshed session never serves stale state.
    generation: int = 0
    # E5a health: "unverified" until a send is accepted, then "healthy"; "suspect"
    # after a 401 the run could not explain; "expired" once the health probe rejected
    # the credentials and no refresh restored them (sends are then refused unsent).
    health: str = "unverified"
    last_ok_at: float = 0.0          # wall clock of the last send the target accepted
    auth_failures: int = 0           # 401s seen on sends that carried this session's credentials
    _probe: "HealthProbe | None" = field(default=None, repr=False)
    _refresh_fn: object = field(default=None, repr=False)
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
                self._fixture_clients[profile.pool_key] = _target_client(
                    verify=profile.context, timeout=timeout, http2=http2, pins=address_pins)
            return self._fixture_clients[profile.pool_key]
        if self._client is None:
            self._client = _target_client(verify=profile.context, timeout=timeout,
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
                 principal=None) -> ManagedSession:
        normalized = frozenset(ScopePolicy.origin_of(o) for o in (allowed_origins or []))
        if "" in normalized:
            raise ValueError("sessions require valid HTTP(S) allowed origins")
        if headers and not normalized:
            raise ValueError("credential-bearing sessions require an explicit allowed origin")
        s = ManagedSession(session_id=session_id, principal_id=principal_id,
                           headers=dict(headers or {}), allowed_origins=normalized,
                           role=role, name=name or principal_id, principal=principal)
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

    def replace_headers(self, session_id: str, headers: dict) -> ManagedSession:
        """Install new credentials for a session: bumps `generation`, marks it
        healthy, and drops the cookie jar (its cookies belonged to the old login)."""
        session = self._by_id.get(session_id)
        if session is None:
            raise ValueError(f"unknown session reference: {session_id}")
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
                  if is_identity_credential_header(k)}
        if not wanted:
            return None, supplied
        for session in self._by_id.values():
            actual = {k.lower(): v for k, v in session.headers.items()
                      if is_identity_credential_header(k)}
            if actual == wanted:
                return session.session_id, {
                    k: v for k, v in supplied.items()
                    if not is_identity_credential_header(k)}
        return None, supplied

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
        return ((method or "GET").upper(), ScopePolicy.origin_of(url),
                engagement.normalize_path(url))

    @staticmethod
    def route_key_for(method: str, url: str, session) -> tuple:
        """route_key plus the calling principal: a route that answers 5xx to
        anonymous can still answer an authenticated user (and an IDOR leg needs
        that answer), so each identity's circuit is its own."""
        principal = (session.principal_id if session is not None
                     and ScopePolicy.origin_of(url) in session.allowed_origins else "")
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
            now = _clock()
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
                    state.open, state.opened_at = True, _clock()
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


# ---------------------------------------------------------------------------
# Typed request + outcome
# ---------------------------------------------------------------------------

@dataclass
class TypedRequest:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str | None = None


@dataclass
class ExecutionOutcome:
    # ok | out_of_scope | blocked | budget_exhausted | cancelled | error, plus
    # session_expired | route_unavailable (E5a): refused unsent, like blocked.
    outcome: str
    status: int | None = None
    body: str = ""
    headers: dict = field(default_factory=dict)
    final_url: str = ""
    error: str = ""
    artifact: "evidence.ExchangeArtifact | None" = None

    @property
    def ok(self) -> bool:
        return self.outcome == "ok"

    @property
    def executed(self) -> bool:
        """A real network send happened. A denied/blocked/out-of-scope attempt did
        NOT execute (and did not consume budget)."""
        return self.outcome in ("ok", "error")

    @property
    def artifact_id(self) -> str:
        """The exchange artifact this send recorded ("" when none was built)."""
        return getattr(self.artifact, "artifact_id", "") or ""


# Ticket 6 follow-up: the confirmation case a validator job runs for. The
# orchestrator enters it around one validator dispatch, so every send that job
# makes is recorded as a case-bound EXECUTION event (artifact id + redacted
# request/response blobs) without each validator threading a case_ref. Inside
# a scope it is the record's case (a validator's finding id is not a case). It
# binds that field only: the record's finding_ref and the gate's per-finding
# mutating ceiling (R16) stay keyed on the caller's own case_ref, as before, so
# per-finding reconstruction is unchanged; a caller with none files under the case.
_ambient_case_ref: "contextvars.ContextVar[str]" = contextvars.ContextVar(
    "harness_case_ref_ambient", default="")


def current_case_ref() -> str:
    """The case id of the enclosing `case_scope`, or "" outside one."""
    return _ambient_case_ref.get()


@contextlib.contextmanager
def case_scope(case_ref: str):
    """Bind sends made in this block (and in tasks it starts) to `case_ref`."""
    token = _ambient_case_ref.set(case_ref or "")
    try:
        yield
    finally:
        _ambient_case_ref.reset(token)


# ---------------------------------------------------------------------------
# Executor -- the single policy-bearing send path (R15/R17)
# ---------------------------------------------------------------------------

class TargetTransport:
    """The single policy-bearing send path for target-directed traffic (R15/R17,
    W-16). Every target send -- scripts, API, the graph loop, discovery, the
    confirmation legs, and (W-16) the orchestrator's second-order/discovery-confirm
    reads and the iterative agent -- goes through `execute()`/`send()` so scope, the
    safety gate, the request budget, credential-forwarding, manual redirects, and
    evidence capture are applied in ONE place. Constructed from a RunContext;
    `RunContext.target_transport()` (alias `.executor()`) is the usual entry, and
    `standalone_context()` builds a minimal RunContext for callers that have no run
    of their own so they can still take this one path instead of a raw client.
    """

    def __init__(self, ctx: "RunContext"):
        self.ctx = ctx
        self._sent_count = contextvars.ContextVar("transport_observed_sends", default=0)

    @property
    def sent_count(self):
        return self._sent_count.get()

    @sent_count.setter
    def sent_count(self, value):
        self._sent_count.set(value)

    async def send(self, method: str, url: str, *, capability: str,
                   session_ref: str | None = None, headers: dict | None = None,
                   body: str | None = None, case_ref: str = "",
                   max_redirects: int = 5,
                   allow_cancelled_cleanup: bool = False) -> "ExecutionOutcome":
        """Convenience wrapper over execute() for a single (method, url) send, so a
        raw `httpx` call site can migrate to the transport in one line. Pass
        max_redirects=0 to match a raw client's follow_redirects=False."""
        return await self.execute(
            TypedRequest(method=(method or "GET").upper(), url=url,
                         headers=dict(headers or {}), body=body),
            capability=capability, session_ref=session_ref, case_ref=case_ref,
            max_redirects=max_redirects, allow_cancelled_cleanup=allow_cancelled_cleanup)

    async def send_creds(self, method: str, url: str, *, capability: str,
                         headers: dict | None = None, body: str | None = None,
                         case_ref: str = "", max_redirects: int = 0) -> "ExecutionOutcome":
        """Send while forwarding any credential headers (Authorization/Cookie/...).

        The transport fails closed on a credential-bearing send with no session
        reference. This resolves the supplied credentials to an already-registered
        session (SessionManager.bind_headers); if none owns them, it registers an
        EPHEMERAL session scoped to the URL's origin. Net behaviour matches a raw
        client that simply sent the credentials to `url` -- but now the send still
        takes the one policy path (scope + gate + budget + evidence). Defaults to
        max_redirects=0 to match a raw client's follow_redirects=False.
        """
        hdrs = dict(headers or {})
        cred = {k: v for k, v in hdrs.items() if is_identity_credential_header(k)}
        session_ref = None
        if cred:
            session_ref, non_cred = self.ctx.sessions.bind_headers(hdrs)
            if session_ref is None:
                sid = f"w16-ephemeral-{uuid.uuid4().hex[:8]}"
                self.ctx.sessions.register(sid, sid, headers=cred, allowed_origins=[url])
                session_ref = sid
                non_cred = {k: v for k, v in hdrs.items()
                            if not is_identity_credential_header(k)}
            hdrs = non_cred
        return await self.send(method, url, capability=capability, session_ref=session_ref,
                               headers=hdrs, body=body, case_ref=case_ref,
                               max_redirects=max_redirects)

    def _artifact(self, url: str, outcome: str, session_ref: str | None,
                  status: int | None = None, case_ref: str = "", *,
                  finding_ref: str = "", method: str | None = None, req_headers: dict | None = None,
                  req_body: str | None = None, resp_headers: dict | None = None,
                  resp_body: str | None = None, capability: str = "",
                  elapsed_ms: float | None = None,
                  size_bytes: int | None = None) -> "evidence.ExchangeArtifact":
        artifact = evidence.ExchangeArtifact.make(
            request_ref=url, response_ref="" if status is None else f"HTTP {status}",
            actual_destination=ScopePolicy.origin_of(url), transport_outcome=outcome,
            session_ref=session_ref or "")
        # P0-1: AUTHORIZATION_DECISION for every non-executed outcome (scope/gate/
        # budget/session denials -- nothing was sent) and EXECUTION for every
        # outcome that actually reached the network (real send or a transport
        # error), attached at the exact point the artifact is already built.
        # Read-only bookkeeping keyed on the caller-supplied case_ref (empty for
        # sends not tied to a finding, e.g. discovery/scripts -- those emit
        # nothing, same as evidence_ledger.emit's own no-op-on-empty-ref guard).
        # Never raises: a ledger/store hiccup here must never surface as a
        # transport failure.
        if case_ref:
            try:
                from harness import evidence_ledger
                prov = evidence_ledger.Provenance.capture(config=self.ctx.config)
                executed = outcome == "ok" or outcome.startswith("error:") or outcome == "redirect_limit"
                data = {"request": artifact.request_ref, "response": artifact.response_ref,
                        "outcome": outcome, "artifact_id": artifact.artifact_id,
                        "destination": artifact.actual_destination}
                data['tls_trust'] = {**self.ctx.tls_policy.provenance(url),
                                     'client_profile_applied': executed and not outcome.startswith('error:resolve:')}
                # FR-2 (F03): a REAL, content-addressed, hash-verified evidence
                # blob -- not just the human-readable "request"/"response"
                # strings above -- so the P0-6 resolver can tell "we have a URL
                # and a status code" from "a tester can actually replay this".
                # `method` is only ever passed by the successful-send call site
                # in execute(); every non-executed outcome (scope/gate/budget/
                # session denial) and every transport error/cancel path never
                # supplies it, so those correctly store no blob and stay
                # unresolvable. MANDATORY redaction (safety requirement): the
                # request URL and BOTH request/response headers/bodies are run
                # through the existing harness.security redactors before
                # anything is hashed or written -- this is a NEW persistence
                # sink for bodies/headers that today are never durably stored
                # at all, so it must never leak a secret. A blob-store failure
                # here is swallowed and recorded as a degraded marker; it must
                # never turn a good send into a transport failure.
                if method is not None:
                    # R01: the EXECUTION event's own `data` dict must carry
                    # `method` too, not just the redacted request blob's
                    # `req_record["method"]` below -- otherwise reproduction_
                    # recipe's `e.data.get("method")` is always None even for
                    # a real send, since a recipe reads the event data, not
                    # the blob contents.
                    data["method"] = method
                    # E5a: who sent it, how long the target took, how much it returned.
                    if capability:
                        data["capability"] = capability
                    if elapsed_ms is not None:
                        data["elapsed_ms"] = round(elapsed_ms, 1)
                    if size_bytes is not None:
                        data["bytes"] = size_bytes
                    try:
                        from harness import security, store
                        req_record = {
                            "method": method,
                            "url": security.redact_secrets_in_url(url),
                            "headers": security.redact_headers(req_headers or {}),
                            "body": (security.redact_secrets_in_body(req_body)
                                     if req_body is not None else None),
                        }
                        resp_record = {
                            "status": status,
                            "headers": security.redact_headers(resp_headers or {}),
                            "body": (security.redact_secrets_in_body(resp_body)
                                     if resp_body is not None else None),
                        }
                        req_bytes = json.dumps(req_record, sort_keys=True).encode("utf-8")
                        resp_bytes = json.dumps(resp_record, sort_keys=True).encode("utf-8")
                        data["request_blob"] = store.put_evidence_blob(req_bytes)
                        data["response_blob"] = store.put_evidence_blob(resp_bytes)
                    except Exception:
                        # Durable blob write failed: never break the send (this
                        # is a best-effort evidence enrichment). Mark the
                        # EXECUTION event degraded so evidence health -- never
                        # the send outcome itself -- reflects that reproducible
                        # evidence was expected but not durably stored.
                        data["evidence_blob_degraded"] = True
                evidence_ledger.emit(
                    evidence_ledger.EventType.EXECUTION if executed
                    else evidence_ledger.EventType.AUTHORIZATION_DECISION,
                    finding_ref or case_ref, f"{outcome}: {url}"[:500], data=data,
                    provenance=prov, case_ref=case_ref)
            except Exception:
                pass
        return artifact

    async def execute(self, request: TypedRequest, *, capability: str,
                      session_ref: str | None = None, case_ref: str = "",
                      max_redirects: int = 5,
                      allow_cancelled_cleanup: bool = False) -> ExecutionOutcome:
        """Send one request through scope + gate + budget, following redirects
        MANUALLY so every hop is re-checked. Captures an artifact on every path,
        including blocks and errors."""
        ctx = self.ctx
        # R16 accounting and the record's finding_ref: the caller's own case_ref,
        # never ambient. The record's case: the enclosing case_scope, if any.
        mutation_key = case_ref
        case_ref = current_case_ref() or case_ref
        finding_ref = mutation_key or case_ref
        session = ctx.sessions.get(session_ref)
        if session_ref and session is None:
            return ExecutionOutcome(
                outcome="unknown_session", final_url=request.url,
                error=f"unknown session reference: {session_ref}",
                artifact=self._artifact(request.url, "unknown_session", session_ref, case_ref=case_ref, finding_ref=finding_ref))
        if not session_ref and any(is_identity_credential_header(k) for k in (request.headers or {})):
            return ExecutionOutcome(
                outcome="blocked", final_url=request.url,
                error="credential-bearing request requires an explicit session reference",
                artifact=self._artifact(request.url, "credentials_require_session", None, case_ref=case_ref, finding_ref=finding_ref))
        origin0 = ScopePolicy.origin_of(request.url)
        if session and origin0 not in session.allowed_origins:
            return ExecutionOutcome(
                outcome="blocked", final_url=request.url,
                error="session is not authorized for the requested destination",
                artifact=self._artifact(request.url, "credential_destination_blocked", session_ref, case_ref=case_ref, finding_ref=finding_ref))
        if session and session.health == "expired":
            # E5a: the health probe rejected this identity's credentials; nothing is sent.
            return ExecutionOutcome(
                outcome="session_expired", final_url=request.url,
                error=_session_expired_message(session),
                artifact=self._artifact(request.url, "session_expired", session_ref, case_ref=case_ref, finding_ref=finding_ref))
        transport_cfg = ctx.config.get("transport", {}) or {}
        method = (request.method or "GET").upper()
        url = request.url
        headers = dict(request.headers or {})
        body = request.body

        # P0-1: PLANNED_ACTION -- the "what we intend to send" half of a finding's
        # audit trail, recorded once per execute() call before any scope/gate/
        # budget decision. Read-only (case_ref-gated no-op otherwise); never
        # affects what is actually sent below.
        if case_ref:
            try:
                from harness import evidence_ledger
                evidence_ledger.emit(
                    evidence_ledger.EventType.PLANNED_ACTION, finding_ref,
                    f"{method} {url}"[:500], data={"request": f"{method} {url}", "capability": capability},
                    provenance=evidence_ledger.Provenance.capture(config=ctx.config), case_ref=case_ref)
            except Exception:
                pass

        for _hop in range(max_redirects + 1):
            if ctx.cancel.cancelled and not allow_cancelled_cleanup:
                return ExecutionOutcome(outcome="cancelled", final_url=url,
                                        artifact=self._artifact(url, "cancelled", session_ref, case_ref=case_ref, finding_ref=finding_ref))
            # 1. Scope -- BEFORE any send, so an off-scope (redirect) target is never contacted.
            if not ctx.scope.in_scope(url):
                return ExecutionOutcome(outcome="out_of_scope", final_url=url,
                                        artifact=self._artifact(url, "out_of_scope", session_ref, case_ref=case_ref, finding_ref=finding_ref))
            reason = ctx.target_policy.denial_reason(url)
            if reason:
                return ExecutionOutcome(outcome="blocked", final_url=url, error=reason,
                                        artifact=self._artifact(url, "blocked", session_ref, case_ref=case_ref, finding_ref=finding_ref))
            # 1b. E5a route circuit -- a route that has only ever answered 5xx is not
            #     probed further (after the gate-free checks above so an unsent request
            #     spends neither gate nor budget). One send per cooldown is let through.
            route_key = TransportHealth.route_key_for(method, url, session)
            if ctx.health.route_blocked(route_key, float(
                    transport_cfg.get("route_circuit_cooldown_seconds", 300))):
                return ExecutionOutcome(
                    outcome="route_unavailable", final_url=url,
                    error=f"route {route_key[0]} {route_key[2]} answered 5xx to every request; "
                          "paused until its cooldown ends",
                    artifact=self._artifact(url, "route_unavailable", session_ref, case_ref=case_ref, finding_ref=finding_ref))
            # 2. Gate -- reuse the SafetyGate decision (no contradictory rules). GET is
            #    not treated as universally harmless: scope + budget still bind it, and a
            #    mutating method is gated exactly as the validators' sends are.
            decision = ctx.gate.authorize(validator_name=capability, method=method, url=url,
                                          body=body if isinstance(body, str) else None,
                                          finding_id=mutation_key or None)
            if not decision.allowed:
                return ExecutionOutcome(outcome="blocked", final_url=url, error=decision.reason,
                                        artifact=self._artifact(url, "blocked", session_ref, case_ref=case_ref, finding_ref=finding_ref))
            # 3. Budget -- reserve atomically before sending; a denial does not count as executed.
            # Only RequestBudget (and the driver child budget forwarding to it) takes a label.
            if not (ctx.budget.reserve(1, label=capability) if hasattr(ctx.budget, "by_label")
                    else ctx.budget.reserve(1)):
                return ExecutionOutcome(outcome="budget_exhausted", final_url=url,
                                        artifact=self._artifact(url, "budget_exhausted", session_ref, case_ref=case_ref, finding_ref=finding_ref))
            # 3b. I05-B: the CONNECT target is pinned by the run's clients themselves
            #     (AddressPins, at the socket): one address per name for the whole
            #     run, special-purpose addresses refused. Scope, gate and credential
            #     forwarding keep keying on the name.
            # 4. Credential-forwarding rule: attach the session's auth headers ONLY
            #    when this hop is the session's own origin. Cross-origin -> no creds.
            credential_destination = bool(
                session and ScopePolicy.origin_of(url) in session.allowed_origins)
            # Without a session only identity credentials are withheld (and those
            # were refused above); a CSRF/idempotency header goes out as before H1.
            # A session's hop off its own origin drops every credential header.
            withheld = is_identity_credential_header if session is None else is_credential_header
            send_headers = {k: v for k, v in headers.items()
                            if credential_destination or not withheld(k)}
            if session and credential_destination:
                for k, v in session.headers.items():
                    send_headers.setdefault(k, v)
            use_http2 = bool((ctx.config.get("transport", {}) or {}).get("http2", False))
            client = (session.client(ctx.timeout, http2=use_http2,
                                     trust_policy=ctx.tls_policy, destination=url,
                                     address_pins=ctx.address_pins)
                      if session and credential_destination else ctx.default_client(destination=url))
            request_kwargs: dict = {"headers": send_headers or None,
                                    "content": body if isinstance(body, str) else None}
            started = time.perf_counter()
            try:
                resp = await client.request(method, url, **request_kwargs)
            except DestinationBlocked as e:   # refused at connect: nothing was sent
                return ExecutionOutcome(outcome="blocked", final_url=url, error=str(e),
                                        artifact=self._artifact(url, "destination_blocked", session_ref,
                                                                case_ref=case_ref, finding_ref=finding_ref))
            except Exception as e:  # transport error -> honest error artifact, never a crash
                return ExecutionOutcome(outcome="error", final_url=url, error=str(e),
                                        artifact=self._artifact(url, f"error:{type(e).__name__}", session_ref, case_ref=case_ref, finding_ref=finding_ref))

            elapsed_ms = (time.perf_counter() - started) * 1000.0
            self.sent_count += 1
            ctx.health.route_observed(route_key, resp.status_code,
                                      int(transport_cfg.get("route_5xx_threshold", 8)))
            if session and credential_destination and capability != _HEALTH_CAPABILITY:
                await self._session_feedback(session, resp.status_code, url)

            if resp.status_code in _REDIRECT_CODES and resp.headers.get("location") and _hop < max_redirects:
                nxt = urljoin(url, resp.headers["location"])
                if not ctx.scope.same_origin(url, nxt):
                    body = None
                if resp.status_code in _REDIRECT_TO_GET:
                    method, body = "GET", None
                headers = {}          # drop one-shot headers; creds re-decided by same-origin next hop
                url = nxt
                continue
            return ExecutionOutcome(outcome="ok", status=resp.status_code, body=resp.text,
                                    headers=dict(resp.headers), final_url=url,
                                    artifact=self._artifact(
                                        url, "ok", session_ref, status=resp.status_code, case_ref=case_ref, finding_ref=finding_ref,
                                        method=method, req_headers=send_headers,
                                        req_body=body if isinstance(body, str) else None,
                                        resp_headers=dict(resp.headers), resp_body=resp.text,
                                        capability=capability, elapsed_ms=elapsed_ms,
                                        size_bytes=_response_size(resp)))
        # Redirect budget exhausted -> return the last hop as ok-ish (no further follow).
        return ExecutionOutcome(outcome="ok", status=None, final_url=url,
                                artifact=self._artifact(url, "redirect_limit", session_ref, case_ref=case_ref, finding_ref=finding_ref))

    # -- E5a: session health ----------------------------------------------------

    async def _session_feedback(self, session: ManagedSession, status: int, url: str) -> None:
        """What a send that carried `session`'s credentials says about the session."""
        if status < 400:
            session.last_ok_at = time.time()
            if session.health in ("unverified", "suspect"):
                session.health = "healthy"
            return
        if status == 401:
            session.auth_failures += 1
            await self._recheck_session(session, url)

    def _probe_for(self, session: ManagedSession, url: str) -> "HealthProbe | None":
        """The session's registered probe, else the one `transport.session_probe.path`
        names on the origin the 401 came from; None means nothing can be checked."""
        if session._probe is not None:
            return session._probe
        cfg = (self.ctx.config.get("transport", {}) or {}).get("session_probe") or {}
        path = cfg.get("path") if isinstance(cfg, dict) else None
        origin = ScopePolicy.origin_of(url)
        if not path or not origin:
            return None
        expect = cfg.get("expect_status", (200,))
        return HealthProbe(str(cfg.get("method") or "GET").upper(), origin + str(path),
                           (expect,) if isinstance(expect, int) else tuple(expect))

    async def _recheck_session(self, session: ManagedSession, url: str) -> None:
        """A 401 on a send with `session`'s credentials: ask the probe whether the
        session or only that route refuses it. No probe -> the session is only marked
        suspect and nothing extra is sent."""
        probe = self._probe_for(session, url)
        if probe is None:
            if session.health != "expired":
                session.health = "suspect"
            return
        async with session.health_lock():
            now = _clock()
            if session.health == "expired" or (
                    session._checked_at is not None
                    and now - session._checked_at < _SESSION_RECHECK_SECONDS):
                return
            session._checked_at = now
            verdict = await self._run_health_probe(session, probe)
            if verdict == "ok":              # the 401 was route-specific
                session.health = "healthy"
                session.last_ok_at = time.time()
                return
            if verdict == "inconclusive":    # the probe never got an answer: do not expire on a guess
                session.health = "suspect"
                return
            cfg = self.ctx.config.get("transport", {}) or {}
            limit = int(cfg.get("max_session_refreshes", 2))
            if session._refresh_fn is not None and session._refreshes < limit:
                session._refreshes += 1
                try:
                    fresh = await session._refresh_fn()
                except Exception:
                    fresh = None
                if isinstance(fresh, dict) and fresh:
                    self.ctx.sessions.replace_headers(session.session_id, fresh)
                    session._checked_at = _clock()
                    return
                if session._refreshes < limit:   # a failed attempt: re-check on the next 401
                    session.health, session._checked_at = "suspect", None
                    return
            session.health = "expired"
            if not session._expiry_reported:
                session._expiry_reported = True
                self.ctx.health.record_event(
                    "session_expired",
                    f"session {session.name} expired: its credentials were rejected by the "
                    "health probe; refresh or re-authenticate this identity to resume its tests",
                    session=session.name, session_id=session.session_id)

    async def _run_health_probe(self, session: ManagedSession, probe: "HealthProbe") -> str:
        """Send the probe once through `session`: "ok", "rejected" (the target answered
        with a status the probe does not expect) or "inconclusive" (unsent, a transport
        error, or a 5xx -- the target's trouble, not proof the credentials are bad)."""
        with case_scope(""):    # a health check belongs to no case
            out = await self.execute(TypedRequest(probe.method, probe.url),
                                     capability=_HEALTH_CAPABILITY,
                                     session_ref=session.session_id, max_redirects=0)
        if not out.ok or out.status is None or out.status >= 500:
            return "inconclusive"
        return "ok" if out.status in probe.expect_status else "rejected"


# Back-compat alias: TargetTransport was named Executor through Astra T03-T08. The
# 37 `.executor()` call sites and the existing `Executor(...)` references keep working.
Executor = TargetTransport


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
# false` is an explicit opt-out. Behind an HTTP(S) proxy (trust_env) the proxy
# resolves the target, so only the connection to the proxy is pinned. A name whose
# FIRST answer is private or loopback is accepted -- lab targets do that.
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
        self.resolver = resolver or _default_resolver
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


def _target_client(*, verify, timeout: float, http2: bool,
                   pins: "AddressPins | None") -> httpx.AsyncClient:
    """An httpx client for target traffic whose connections honour the run's pins."""
    transport = httpx.AsyncHTTPTransport(verify=verify, http2=http2)
    backend = _pinned_backend(pins)
    if backend is not None:
        transport._pool._network_backend = backend
    # verify/http2 are passed to the client too, so environment-proxy mounts use the
    # same trust as the pinned transport.
    return httpx.AsyncClient(follow_redirects=False, verify=verify, timeout=timeout,
                             cookies=httpx.Cookies(), http2=http2, transport=transport)


def _address_pins_from_config(config: dict | None) -> "AddressPins | None":
    security = (config or {}).get("security", {}) or {}
    return AddressPins() if security.get("pin_connect_address", True) is not False else None


def standalone_context(allowed_hosts, *, config: dict | None = None, gate=None,
                       active_mode: bool = False, timeout: float = 15.0,
                       max_requests: int | None = None) -> "RunContext":
    """A minimal RunContext for a caller that has no run of its own but still wants
    the ONE TargetTransport path instead of a raw httpx client (W-16 full closure).

    Its scope is a HostAllowScope, so a send previously guarded by
    `scope_discovery.is_host_allowed(url, allowed_hosts)` uses the same strict
    exact-host intersection as the gate. Pass `gate` to
    reuse the caller's existing SafetyGate (e.g. the
    iterative agent's) so mutating-method decisions are unchanged; otherwise a fresh
    per-context gate is used. The caller owns the returned context and must aclose()
    it (or use `transport_for`, which reports ownership)."""
    rc = RunContext.create(allowed_hosts=allowed_hosts, config=config, timeout=timeout,
                           max_requests=max_requests, gate=gate)
    rc.scope = HostAllowScope(hosts=tuple(scope_lock.configured_entries(allowed_hosts)),
                              active_mode=active_mode)
    return rc


def transport_for(run_context, *, allowed_hosts, config: dict | None = None, gate=None,
                  active_mode: bool = False, timeout: float = 15.0):
    """Return (transport, owned_context) for a call site that may or may not have a
    run of its own. If `run_context` is provided, its TargetTransport is used and
    owned_context is None (the caller must NOT close the shared run). Otherwise a
    `standalone_context` is built and returned as owned_context, which the caller
    must aclose() when done. I05: inside an entered run, a call site that passed no
    run uses the enclosing one (not owned) instead of a throwaway context that
    would escape the run's budget and cancellation."""
    if run_context is None:
        run_context = current_run_context()
    if run_context is not None:
        return run_context.target_transport(), None
    rc = standalone_context(allowed_hosts, config=config, gate=gate,
                            active_mode=active_mode, timeout=timeout)
    return rc.target_transport(), rc


# ---------------------------------------------------------------------------
# RunContext -- the per-run bundle
# ---------------------------------------------------------------------------

# I03: the run whose `async with` block is active, so a send site with no
# run_context wiring of its own (safety_gate.GatedAsyncClient) still spends THIS
# run's budget under its scope, cancellation and TLS trust instead of a private
# client. Same plain get/set discipline as safety_gate.push_gate (a run may be
# entered in one task and closed in another).
_ambient_run: "contextvars.ContextVar[RunContext | None]" = contextvars.ContextVar(
    "harness_run_context_ambient", default=None)


def current_run_context() -> "RunContext | None":
    """The RunContext whose `async with` block encloses this call, if any."""
    return _ambient_run.get()


@dataclass
class RunContext:
    run_id: str
    scope: ScopePolicy
    gate: SafetyGate
    budget: RequestBudget
    cancel: CancelToken
    sessions: SessionManager
    config: dict = field(default_factory=dict)
    cache_namespace: str = ""
    timeout: float = 15.0
    _default_client: httpx.AsyncClient | None = None
    _fixture_clients: dict = field(default_factory=dict, repr=False)
    tls_policy: TLSPolicy = field(default_factory=TLSPolicy.from_config, repr=False)
    # I05-B: one connect address per name for the whole run (None = opted out).
    address_pins: "AddressPins | None" = field(default_factory=AddressPins, repr=False)
    target_policy: TargetRequestPolicy = field(default_factory=TargetRequestPolicy, repr=False)
    # E5a: the run's route circuits and one-time health events (see health_report).
    health: TransportHealth = field(default_factory=TransportHealth, repr=False)
    # What safety_gate.push_gate returned when this run installed its gate as
    # ambient -- the gate (or None) that was ambient before it, to restore on
    # aclose(). Not a contextvars.Token: see push_gate's docstring for why.
    _gate_restore: object = field(default=None, repr=False, compare=False)
    _gate_pushed: bool = field(default=False, repr=False, compare=False)
    # I03: the run that was ambient before this one entered (restored on aclose).
    _run_restore: object = field(default=None, repr=False, compare=False)
    _run_pushed: bool = field(default=False, repr=False, compare=False)
    # AR-2 (LOOP half): a per-run Ollama circuit breaker + fail-open counter,
    # pushed ambient alongside the gate in __aenter__ and popped in aclose(),
    # so concurrent/sequential runs cannot poison each other's model-backend
    # state. Lazily constructed ONLY inside __aenter__ (never at plain
    # create()/field-default time) so the ~70 existing tests that build a
    # RunContext directly and never `async with` it see no new object at all,
    # matching the same guard the gate push already relies on.
    _ollama_breaker: object = field(default=None, repr=False, compare=False)
    _ollama_breaker_restore: object = field(default=None, repr=False, compare=False)
    _ollama_breaker_pushed: bool = field(default=False, repr=False, compare=False)
    fail_open_counters: object = field(default=None, repr=False, compare=False)
    _fail_open_restore: object = field(default=None, repr=False, compare=False)
    _fail_open_pushed: bool = field(default=False, repr=False, compare=False)
    # E4: the run's one validator-execution registry (execution_registry.py), set
    # by the engagement that owns the run; None means every path runs its own checks.
    execution_registry: object = field(default=None, repr=False, compare=False)

    @classmethod
    def create(cls, *, run_id: str | None = None, allowed_hosts=None, gate_config: dict | None = None,
               gate: "SafetyGate | None" = None, max_requests: int | None = None,
               config: dict | None = None, timeout: float = 15.0) -> "RunContext":
        # A FRESH gate per run (never the process-global default) -- the #3 isolation
        # fix: authorization state is per run, so two runs cannot contaminate each
        # other's mutation budgets or audit log. Pass `gate` to reuse an existing
        # gate (e.g. the caller's own) instead of building one from gate_config.
        resolved_run_id = run_id or uuid.uuid4().hex
        config_snapshot = deepcopy(config or {})
        target_policy = TargetRequestPolicy.from_config(config_snapshot)
        tls_policy = TLSPolicy.from_config(config_snapshot)
        config_snapshot['transport_tls_provenance'] = tls_policy.provenance()
        configured_namespace = str(
            ((config_snapshot.get("runs", {}) or {}).get("cache_namespace") or "")
        )
        # Safety item #12: fold this run's scope into the gate config so the gate
        # itself refuses any off-scope send (central defense-in-depth), matching
        # the ScopePolicy the transport already enforces.
        entries = scope_lock.configured_entries(allowed_hosts)
        _gate_cfg = {**(gate_config or {}), "allowed_hosts": list(entries)}
        _gate_cfg['target_policy'] = target_policy
        resolved_gate = gate if gate is not None else SafetyGate(SafetyGateConfig.from_dict(_gate_cfg))
        return cls(
            run_id=resolved_run_id,
            scope=ScopePolicy(allowed_hosts=entries),
            gate=resolved_gate,
            budget=RequestBudget(max_requests), cancel=CancelToken(),
            sessions=SessionManager(), config=config_snapshot,
            tls_policy=tls_policy,
            address_pins=_address_pins_from_config(config_snapshot),
            target_policy=target_policy,
            cache_namespace=(f"{configured_namespace}:{resolved_run_id}"
                             if configured_namespace else resolved_run_id), timeout=timeout)

    def default_client(self, *, destination: str | None = None) -> httpx.AsyncClient:
        profile = self.tls_policy.profile_for(destination)
        use_http2 = bool((self.config.get("transport", {}) or {}).get("http2", False))
        if profile.pool_key:
            if profile.pool_key not in self._fixture_clients:
                self._fixture_clients[profile.pool_key] = _target_client(
                    verify=profile.context, timeout=self.timeout, http2=use_http2,
                    pins=self.address_pins)
            return self._fixture_clients[profile.pool_key]
        if self._default_client is None:
            self._default_client = _target_client(verify=profile.context, timeout=self.timeout,
                                                  http2=use_http2, pins=self.address_pins)
        return self._default_client

    def target_transport(self) -> "TargetTransport":
        return TargetTransport(self)

    def health_report(self) -> dict:
        """What the run learned about its own transport: each session's health, the
        routes currently paused, the one-time health events, and the request budget
        spent per label (capability). Plain data, safe to serialise."""
        return {
            "sessions": [{"name": s.name, "principal": s.principal_id, "health": s.health,
                          "generation": s.generation, "auth_failures": s.auth_failures}
                         for s in self.sessions.all()],
            "routes_paused": self.health.paused_routes(),
            "events": self.health.events(),
            "budget_by_label": dict(getattr(self.budget, "by_label", {}) or {}),
        }

    def executor(self) -> "TargetTransport":   # back-compat name for target_transport()
        return self.target_transport()

    async def aclose(self) -> None:
        if self._default_client is not None:
            await self._default_client.aclose()
            self._default_client = None
        for client in self._fixture_clients.values():
            await client.aclose()
        self._fixture_clients.clear()
        await self.sessions.aclose()
        if self._gate_pushed:
            from harness.safety_gate import pop_gate
            pop_gate(self._gate_restore)
            self._gate_pushed = False
            self._gate_restore = None
        if self._run_pushed:
            _ambient_run.set(self._run_restore)
            self._run_pushed = False
            self._run_restore = None
        if self._ollama_breaker_pushed:
            from harness.circuit_breaker import pop_ollama_breaker
            pop_ollama_breaker(self._ollama_breaker_restore)
            self._ollama_breaker_pushed = False
            self._ollama_breaker_restore = None
        if self._fail_open_pushed:
            from harness.coordinator import pop_fail_open_counters
            pop_fail_open_counters(self._fail_open_restore)
            self._fail_open_pushed = False
            self._fail_open_restore = None

    def publish(self) -> "RunContext":
        """Make this run the enclosing one for target sends (current_run_context) and
        its gate the ambient default gate (get_default_gate), task-locally, until
        aclose(). `async with` does this plus the per-run model-plane state; a caller
        that owns a run but keeps the shared Ollama breaker and fail-open counters --
        a standalone analyze (I05) -- publishes only."""
        if not self._gate_pushed:
            from harness.safety_gate import push_gate
            self._gate_restore = push_gate(self.gate)
            self._gate_pushed = True
        if not self._run_pushed:
            self._run_restore = _ambient_run.get()
            _ambient_run.set(self)
            self._run_pushed = True
        return self

    async def __aenter__(self) -> "RunContext":
        # Install this run's gate as the AMBIENT one (safety_gate.get_default_gate)
        # for the `async with` block's lifetime, so a validator with no run_context
        # wiring at its own send site (calls get_default_gate() bare -- CSRF's,
        # SQLMap's fallback) still sees THIS invocation's policy, not a stale
        # process-wide default from server startup or an unrelated earlier run
        # (2026-09-17 coverage-recovery plan, Step 1). Deliberately scoped to
        # `async with`, not to bare create()/aclose(): every real call site that
        # needs this (server.py's engagement/probe endpoints) already uses
        # `async with`, and the ~70 existing tests that construct a RunContext
        # directly and read `.gate` themselves (never through get_default_gate())
        # stay exactly as they were -- no eager global side effect at construction
        # time that a test forgetting to call aclose() could leak into another.
        self.publish()

        # AR-2 (LOOP half): install this run's OWN Ollama circuit breaker and
        # fail-open counters as ambient, alongside the gate above, so model-
        # backend state cannot leak between concurrent/sequential runs.
        # Constructed here (not at create()/field-default time) so a
        # RunContext that is never `async with`-entered -- the ~70 existing
        # tests that build one directly -- never allocates these at all,
        # matching the gate's own lazy-push guard.
        from harness.circuit_breaker import (
            CircuitBreakerConfig,
            OllamaCircuitBreaker,
            push_ollama_breaker,
        )
        if self._ollama_breaker is None:
            # Same config OllamaClient.__init__ uses (ollama_client.py:130-137),
            # so a per-run breaker trips/heals identically to the shared
            # singleton, including which exceptions don't count as failures.
            from harness.ollama_client import (
                OllamaInvalidJSONError,
                OllamaModelNotFoundError,
            )
            self._ollama_breaker = OllamaCircuitBreaker(
                "ollama",
                CircuitBreakerConfig(
                    failure_threshold=3,
                    success_threshold=2,
                    timeout_seconds=60.0,
                    half_open_max_requests=1,
                    excluded_exceptions=(OllamaModelNotFoundError, OllamaInvalidJSONError),
                    enabled=True,
                ),
            )
        self._ollama_breaker_restore = push_ollama_breaker(self._ollama_breaker)
        self._ollama_breaker_pushed = True

        from harness.coordinator import push_fail_open_counters
        if self.fail_open_counters is None:
            self.fail_open_counters = {"count": 0, "by_reason": {}}
        self._fail_open_restore = push_fail_open_counters(self.fail_open_counters)
        self._fail_open_pushed = True

        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()
