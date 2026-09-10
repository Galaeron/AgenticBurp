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

  - **R15 (settings not authoritative):** one `Executor` routes every migrated send
    through the SAME gate decision, scope check, and budget -- scripts, API, and the
    graph all get identical allowed actions instead of each constructing validators
    and clients their own way.

Backward compatible: nothing here runs unless a caller builds a RunContext and uses
its executor. Browser/container adapters are T08, not claimed here. Cookie jars are
per session, never shared across principals.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

import evidence
from safety_gate import SafetyGate, SafetyGateConfig

# Redirect status codes and the ones that rewrite the method to GET.
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_REDIRECT_TO_GET = frozenset({301, 302, 303})
# Request headers that carry credentials and must NOT cross an origin boundary.
_CREDENTIAL_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


# ---------------------------------------------------------------------------
# Scope policy -- the single origin/host authority (R17)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScopePolicy:
    """Which origins a run may contact. FAIL CLOSED: an empty allow-list permits
    nothing, so a misconfigured scope never silently allows the whole internet."""
    allowed_hosts: frozenset = frozenset()
    allowed_schemes: frozenset = frozenset({"http", "https"})

    @staticmethod
    def origin_of(url: str) -> str:
        p = urlsplit(url)
        host = (p.hostname or "").lower()
        port = f":{p.port}" if p.port else ""
        return f"{(p.scheme or '').lower()}://{host}{port}"

    @staticmethod
    def host_of(url: str) -> str:
        return (urlsplit(url).hostname or "").lower()

    def in_scope(self, url: str) -> bool:
        p = urlsplit(url)
        if (p.scheme or "").lower() not in self.allowed_schemes:
            return False
        host = (p.hostname or "").lower()
        if not host or not self.allowed_hosts:
            return False
        return host in self.allowed_hosts

    def same_origin(self, a: str, b: str) -> bool:
        return self.origin_of(a) == self.origin_of(b)


# ---------------------------------------------------------------------------
# Budget + cancellation -- atomic, per run
# ---------------------------------------------------------------------------

class RequestBudget:
    """A per-run ceiling on real network sends. `reserve` is atomic and reserves
    BEFORE the send; a denied reservation does NOT count as an executed request."""

    def __init__(self, max_requests: int | None = None):
        self._max = max_requests
        self._used = 0
        self._lock = threading.Lock()

    def reserve(self, n: int = 1) -> bool:
        with self._lock:
            if self._max is not None and self._used + n > self._max:
                return False
            self._used += n
            return True

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int | None:
        return None if self._max is None else max(0, self._max - self._used)


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

@dataclass
class ManagedSession:
    """A principal's authenticated session: its auth headers plus its OWN persistent
    httpx client (with an isolated cookie jar). Reusing one client per session keeps
    connections warm (fixes the per-request-client waste) while guaranteeing cookies
    never cross principals."""
    session_id: str
    principal_id: str
    headers: dict = field(default_factory=dict)   # Authorization/etc.; the credential, kept out of findings
    generation: int = 0
    _client: httpx.AsyncClient | None = None

    def client(self, timeout: float) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(follow_redirects=False, verify=False,
                                             timeout=timeout, cookies=httpx.Cookies())
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class SessionManager:
    def __init__(self):
        self._by_id: dict[str, ManagedSession] = {}

    def register(self, session_id: str, principal_id: str, headers: dict | None = None) -> ManagedSession:
        s = ManagedSession(session_id=session_id, principal_id=principal_id, headers=dict(headers or {}))
        self._by_id[session_id] = s
        return s

    def get(self, session_id: str | None) -> ManagedSession | None:
        return self._by_id.get(session_id) if session_id else None

    async def aclose(self) -> None:
        for s in self._by_id.values():
            await s.aclose()


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
    outcome: str                      # ok | out_of_scope | blocked | budget_exhausted | cancelled | error
    status: int | None = None
    body: str = ""
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


# ---------------------------------------------------------------------------
# Executor -- the single policy-bearing send path (R15/R17)
# ---------------------------------------------------------------------------

class Executor:
    def __init__(self, ctx: "RunContext"):
        self.ctx = ctx

    def _artifact(self, url: str, outcome: str, session_ref: str | None,
                  status: int | None = None) -> "evidence.ExchangeArtifact":
        return evidence.ExchangeArtifact.make(
            request_ref=url, response_ref="" if status is None else f"HTTP {status}",
            actual_destination=ScopePolicy.origin_of(url), transport_outcome=outcome,
            session_ref=session_ref or "")

    async def execute(self, request: TypedRequest, *, capability: str,
                      session_ref: str | None = None, case_ref: str = "",
                      max_redirects: int = 5) -> ExecutionOutcome:
        """Send one request through scope + gate + budget, following redirects
        MANUALLY so every hop is re-checked. Captures an artifact on every path,
        including blocks and errors."""
        ctx = self.ctx
        session = ctx.sessions.get(session_ref)
        origin0 = ScopePolicy.origin_of(request.url)
        method = (request.method or "GET").upper()
        url = request.url
        headers = dict(request.headers or {})
        body = request.body

        for _hop in range(max_redirects + 1):
            if ctx.cancel.cancelled:
                return ExecutionOutcome(outcome="cancelled", final_url=url,
                                        artifact=self._artifact(url, "cancelled", session_ref))
            # 1. Scope -- BEFORE any send, so an off-scope (redirect) target is never contacted.
            if not ctx.scope.in_scope(url):
                return ExecutionOutcome(outcome="out_of_scope", final_url=url,
                                        artifact=self._artifact(url, "out_of_scope", session_ref))
            # 2. Gate -- reuse the SafetyGate decision (no contradictory rules). GET is
            #    not treated as universally harmless: scope + budget still bind it, and a
            #    mutating method is gated exactly as the validators' sends are.
            decision = ctx.gate.authorize(validator_name=capability, method=method, url=url,
                                          body=body if isinstance(body, str) else None,
                                          finding_id=case_ref or None)
            if not decision.allowed:
                return ExecutionOutcome(outcome="blocked", final_url=url, error=decision.reason,
                                        artifact=self._artifact(url, "blocked", session_ref))
            # 3. Budget -- reserve atomically before sending; a denial does not count as executed.
            if not ctx.budget.reserve(1):
                return ExecutionOutcome(outcome="budget_exhausted", final_url=url,
                                        artifact=self._artifact(url, "budget_exhausted", session_ref))
            # 4. Credential-forwarding rule: attach the session's auth headers ONLY
            #    when this hop is the session's own origin. Cross-origin -> no creds.
            send_headers = {k: v for k, v in headers.items()
                            if k.lower() not in _CREDENTIAL_HEADERS
                            or ctx.scope.same_origin(url, origin0)}
            if session and ctx.scope.same_origin(url, origin0):
                for k, v in session.headers.items():
                    send_headers.setdefault(k, v)
            client = session.client(ctx.timeout) if session else ctx.default_client()
            try:
                resp = await client.request(method, url, headers=send_headers or None,
                                            content=body if isinstance(body, str) else None)
            except Exception as e:  # transport error -> honest error artifact, never a crash
                return ExecutionOutcome(outcome="error", final_url=url, error=str(e),
                                        artifact=self._artifact(url, f"error:{type(e).__name__}", session_ref))

            if resp.status_code in _REDIRECT_CODES and resp.headers.get("location") and _hop < max_redirects:
                nxt = urljoin(url, resp.headers["location"])
                if resp.status_code in _REDIRECT_TO_GET:
                    method, body = "GET", None
                headers = {}          # drop one-shot headers; creds re-decided by same-origin next hop
                url = nxt
                continue
            return ExecutionOutcome(outcome="ok", status=resp.status_code, body=resp.text, final_url=url,
                                    artifact=self._artifact(url, "ok", session_ref, status=resp.status_code))
        # Redirect budget exhausted -> return the last hop as ok-ish (no further follow).
        return ExecutionOutcome(outcome="ok", status=None, final_url=url,
                                artifact=self._artifact(url, "redirect_limit", session_ref))


# ---------------------------------------------------------------------------
# RunContext -- the per-run bundle
# ---------------------------------------------------------------------------

@dataclass
class RunContext:
    run_id: str
    scope: ScopePolicy
    gate: SafetyGate
    budget: RequestBudget
    cancel: CancelToken
    sessions: SessionManager
    config: dict = field(default_factory=dict)
    timeout: float = 15.0
    _default_client: httpx.AsyncClient | None = None

    @classmethod
    def create(cls, *, run_id: str | None = None, allowed_hosts=None, gate_config: dict | None = None,
               max_requests: int | None = None, config: dict | None = None,
               timeout: float = 15.0) -> "RunContext":
        # A FRESH gate per run (never the process-global default) -- the #3 isolation
        # fix: authorization state is per run, so two runs cannot contaminate each
        # other's mutation budgets or audit log.
        return cls(
            run_id=run_id or uuid.uuid4().hex,
            scope=ScopePolicy(allowed_hosts=frozenset((h or "").lower() for h in (allowed_hosts or []))),
            gate=SafetyGate(SafetyGateConfig.from_dict(gate_config or {})),
            budget=RequestBudget(max_requests), cancel=CancelToken(),
            sessions=SessionManager(), config=config or {}, timeout=timeout)

    def default_client(self) -> httpx.AsyncClient:
        if self._default_client is None:
            self._default_client = httpx.AsyncClient(follow_redirects=False, verify=False,
                                                     timeout=self.timeout, cookies=httpx.Cookies())
        return self._default_client

    def executor(self) -> Executor:
        return Executor(self)

    async def aclose(self) -> None:
        if self._default_client is not None:
            await self._default_client.aclose()
            self._default_client = None
        await self.sessions.aclose()

    async def __aenter__(self) -> "RunContext":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()
