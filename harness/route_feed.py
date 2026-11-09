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
A route is keyed on its method, path template and the sorted NAMES of its inputs
(query parameter names and top-level body field names; values never count), so a new
input on a known route is new while a repeat with other values is not. A route key
already in the engagement, or already offered for the same principal, is a
duplicate; one out of scope or off the engagement origin is refused; and at most
`max_new_routes` are ever accepted per run (the budget guard). The engagement drains
the feed between phases and investigates what is new (orchestrator_chain recrawl).

OFF by default (`engagement.recrawl.enabled: false`): no feed is installed, the
transport offers nothing and the worklist is built once, as before.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

__all__ = ["RecrawlConfig", "RouteFeed", "RouteObservation", "input_names", "route_key",
           "endpoint_route_keys"]

_CREDENTIAL_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization",
                                 "x-api-key", "x-auth-token"})
# Capabilities whose traffic is the run looking after itself, not the app's surface.
_IGNORED_CAPABILITIES = frozenset({"session_health", "session_refresh"})
_MAX_BODY = 4000


def input_names(url: str, body=None) -> tuple:
    """The sorted, distinct names of a request's inputs: its query parameter names
    and its body's top-level field names (a JSON object's keys, or form-encoded
    names). Values are never part of it; a body that is neither gives no names."""
    names = {k for k, _ in parse_qsl(urlsplit(url or "").query, keep_blank_values=True) if k}
    text = body.strip() if isinstance(body, str) else ""
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            names.update(str(k) for k in parsed)
    elif text and "=" in text and not text.startswith(("<", "[")):
        names.update(k for k, _ in parse_qsl(text, keep_blank_values=True) if k)
    return tuple(sorted(names))


def route_key(method: str, path: str, inputs=()) -> tuple:
    """(METHOD, path template, sorted input names): what makes a route new."""
    return (str(method or "GET").upper(), path, tuple(sorted(set(inputs or ()))))


def _as_key(entry) -> tuple:
    """A `known` entry as a route key; a legacy (METHOD, path) pair means the route
    with no inputs."""
    entry = tuple(entry)
    return entry if len(entry) == 3 else route_key(entry[0], entry[1])


def endpoint_route_keys(ep) -> set:
    """The route keys an engagement endpoint already covers: its captured template
    and every capture variant's request, plus the bare route."""
    method, path = str(getattr(ep, "method", "GET")).upper(), getattr(ep, "path", "/")
    keys = {route_key(method, path)}
    templates = [getattr(ep, "template", None)] + [
        (v or {}).get("template") for v in (getattr(ep, "capture_variants", None) or [])
        if isinstance(v, dict)]
    for tmpl in templates:
        if isinstance(tmpl, dict):
            query = tmpl.get("query") or ""
            keys.add(route_key(method, path, input_names(f"/?{query}" if query else "/",
                                                         tmpl.get("body"))))
    return keys


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
    inputs: tuple = ()            # sorted input names (see input_names)


@dataclass
class RouteFeed:
    origin: str
    in_scope: object                       # callable(url) -> bool
    max_new_routes: int = 200
    # Route keys already in the engagement: {(METHOD, path, sorted input names)}; a
    # (METHOD, path) pair stands for the route with no inputs.
    known: set = field(default_factory=set)
    accepted: int = 0
    refused: dict = field(default_factory=dict)    # reason -> count
    _offered: set = field(default_factory=set)     # {(route key, principal)}
    _pending: list = field(default_factory=list)

    def __post_init__(self):
        self.known = {_as_key(k) for k in self.known}

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
        inputs = input_names(url, exchange.get("request_body"))
        route = route_key(method, path, inputs)
        if route in self.known:
            return self._refuse("known")
        key = (route, principal_id)
        if key in self._offered:
            return self._refuse("duplicate")
        if self.accepted >= self.max_new_routes:
            return self._refuse("budget")
        self._offered.add(key)
        self.accepted += 1
        self._pending.append(RouteObservation(
            method=method, path=path, url=url, source=source, exchange=dict(exchange),
            principal_id=principal_id, role=role, session_ref=session_ref,
            status=exchange.get("response_status"), inputs=inputs))
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
        if route_key(method, normalize_path(url), input_names(url, request_body)) in self.known:
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
        route keys known, so a route is investigated in one round only."""
        take = self._pending[:limit] if limit is not None else list(self._pending)
        self._pending = self._pending[len(take):]
        for obs in take:
            self.known.add(route_key(obs.method, obs.path, obs.inputs))
        return take

    def stats(self) -> dict:
        return {"accepted": self.accepted, "pending": len(self._pending),
                "refused": dict(self.refused), "max_new_routes": self.max_new_routes}
