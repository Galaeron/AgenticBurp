"""
Route feedback -- routes seen AFTER discovery flow back into the worklist.

In the 8-hour Juice Shop run (2026-11-03) the worklist was fixed at 06:15, five
minutes in. Eleven method+path templates first seen later (sent by validators,
sqlmap and model-directed probes, plus every view the browser never visited) were
exercised once and never investigated: nothing fed them back.

A `RouteFeed` sits on the RunContext (`run_context.route_feed`) once an engagement
installs it. Two sources offer to it:
  - the transport: every response to a request this run sent (`observe_response`),
    kept only when it says the route exists -- 2xx with a non-HTML body (a single-
    page app answers unknown paths with its HTML shell), or 401/403;
  - captured exchanges (`offer_exchange`): the XHR/fetch calls a browser view fired.
A route already in the engagement, or already offered for the same principal, is a
duplicate; one out of scope or off the engagement origin is refused; and at most
`max_new_routes` are ever accepted per run (the budget guard). The engagement drains
the feed between phases and investigates what is new (orchestrator_chain recrawl).

OFF by default (`engagement.recrawl.enabled: false`): no feed is installed, the
transport offers nothing and the worklist is built once, as before.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

__all__ = ["RecrawlConfig", "RouteFeed", "RouteObservation"]

_CREDENTIAL_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization",
                                 "x-api-key", "x-auth-token"})
# Capabilities whose traffic is the run looking after itself, not the app's surface.
_IGNORED_CAPABILITIES = frozenset({"session_health", "session_refresh"})
_MAX_BODY = 4000


@dataclass(frozen=True)
class RecrawlConfig:
    enabled: bool = False
    max_rounds: int = 2           # re-crawl rounds per engagement
    min_new_routes: int = 1       # pending routes that trigger a round
    max_new_routes: int = 200     # routes ever accepted per run
    max_routes_per_round: int = 50

    @classmethod
    def from_config(cls, config: dict | None) -> "RecrawlConfig":
        raw = ((config or {}).get("engagement", {}) or {}).get("recrawl") or {}
        if not isinstance(raw, dict):
            return cls()
        return cls(enabled=bool(raw.get("enabled", False)),
                   max_rounds=max(0, int(raw.get("max_rounds", 2))),
                   min_new_routes=max(1, int(raw.get("min_new_routes", 1))),
                   max_new_routes=max(0, int(raw.get("max_new_routes", 200))),
                   max_routes_per_round=max(1, int(raw.get("max_routes_per_round", 50))))


@dataclass
class RouteObservation:
    method: str
    path: str                     # engagement.normalize_path template
    url: str
    source: str                   # transport:<capability> | browser | model | ...
    exchange: dict
    principal_id: str | None = None
    role: str | None = None
    session_ref: str | None = None
    status: int | None = None


@dataclass
class RouteFeed:
    origin: str
    in_scope: object                       # callable(url) -> bool
    max_new_routes: int = 200
    known: set = field(default_factory=set)        # {(METHOD, path)} already in the engagement
    accepted: int = 0
    refused: dict = field(default_factory=dict)    # reason -> count
    _offered: set = field(default_factory=set)     # {(METHOD, path, principal)}
    _pending: list = field(default_factory=list)

    def _refuse(self, reason: str) -> bool:
        self.refused[reason] = self.refused.get(reason, 0) + 1
        return False

    def offer_exchange(self, exchange: dict, *, source: str, principal_id: str | None = None,
                       role: str | None = None, session_ref: str | None = None) -> bool:
        from harness.engagement import normalize_path
        url = str(exchange.get("url") or "")
        method = str(exchange.get("method") or "GET").upper()
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or f"{parts.scheme}://{parts.netloc}" != self.origin:
            return self._refuse("off_origin")
        try:
            if not self.in_scope(url):
                return self._refuse("out_of_scope")
        except Exception:
            return self._refuse("out_of_scope")
        path = normalize_path(url)
        if (method, path) in self.known:
            return self._refuse("known")
        key = (method, path, principal_id)
        if key in self._offered:
            return self._refuse("duplicate")
        if self.accepted >= self.max_new_routes:
            return self._refuse("budget")
        self._offered.add(key)
        self.accepted += 1
        self._pending.append(RouteObservation(
            method=method, path=path, url=url, source=source, exchange=dict(exchange),
            principal_id=principal_id, role=role, session_ref=session_ref,
            status=exchange.get("response_status")))
        return True

    def observe_response(self, *, capability: str, method: str, url: str, status: int | None,
                         request_headers: dict | None, request_body, response_headers: dict | None,
                         response_body, session=None) -> bool:
        """The transport's hook: one response to a request this run sent.
        `response_body` may be a zero-arg callable, read only for a new route."""
        if capability in _IGNORED_CAPABILITIES or status is None:
            return False
        content_type = ""
        for k, v in (response_headers or {}).items():
            if k.lower() == "content-type":
                content_type = str(v).lower()
        exists = status in (401, 403) or (200 <= status < 300 and "html" not in content_type)
        if not exists:
            return False
        from harness.engagement import normalize_path
        if (method.upper(), normalize_path(url)) in self.known:
            return False          # the common case: skip building an exchange
        exchange = {
            "url": url, "method": method.upper(),
            # The session supplies credentials on replay; the template never holds them.
            "request_headers": {k: v for k, v in (request_headers or {}).items()
                                if k.lower() not in _CREDENTIAL_HEADERS},
            "request_body": request_body if isinstance(request_body, str) else "",
            "response_status": status,
            "response_headers": {k: v for k, v in (response_headers or {}).items()
                                 if k.lower() != "set-cookie"},
            "response_body": str((response_body() if callable(response_body)
                                  else response_body) or "")[:_MAX_BODY],
            "analyst_note": f"route_feed: first seen in a {capability} response",
        }
        return self.offer_exchange(
            exchange, source=f"transport:{capability}",
            principal_id=getattr(session, "principal_id", None),
            role=getattr(session, "role", None),
            session_ref=getattr(session, "session_id", None))

    def pending(self) -> int:
        return len(self._pending)

    def drain(self, limit: int | None = None) -> list[RouteObservation]:
        """Take up to `limit` pending observations (oldest first) and mark their
        routes known, so a route is investigated in one round only."""
        take = self._pending[:limit] if limit is not None else list(self._pending)
        self._pending = self._pending[len(take):]
        for obs in take:
            self.known.add((obs.method, obs.path))
        return take

    def stats(self) -> dict:
        return {"accepted": self.accepted, "pending": len(self._pending),
                "refused": dict(self.refused), "max_new_routes": self.max_new_routes}
