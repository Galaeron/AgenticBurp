"""
Session freshness -- notice a principal's session going stale DURING a run.

The 8-hour Juice Shop run (2026-11-03) showed 401s on auth-required GETs rising from
12% to 50-80% after the first half hour, with no refresh ever logged: the E5a health
probe (run_context._recheck_session) only exists when `transport.session_probe` names
a request, and no production code registered a refresh callback. Denials from a dead
session were then read as access control.

This module is the statistical half that needs no operator-named probe. For each
session it remembers which routes (method + templated path) the target ACCEPTED
(2xx) with that session's credentials, and keeps a sliding window of the outcomes of
later sends to those same known-good routes. When the window holds at least
`min_denials` 401/403 answers spread over at least `min_routes` distinct known-good
routes, and the denial rate is at least `denial_rate`, the session is STALE: the
target refuses what it served this principal before. A route that has only ever
refused a principal never counts -- that is access control, the thing being tested.

What the transport then does (TargetTransport._session_stale): refresh the session
through its registered refresh callback (`login_refresher` below builds one from an
operator-declared login request) and log a `session_refresh` event; with no callback,
or once the refresh budget is spent, mark the session `stale` (sends are then refused
unsent, like an expired session, so no later denial is attributed to access control)
and log `session_stale`.

OFF by default (`transport.session_freshness.enabled: false`): with it off nothing is
tracked and no session changes state.
"""
from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit

__all__ = ["FreshnessConfig", "SessionFreshness", "login_refresher", "route_key"]

_NUMERIC_SEGMENT = re.compile(r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,})$")


def route_key(method: str, url: str) -> tuple[str, str]:
    """Method + path with numeric/uuid segments templated; the query is ignored."""
    path = urlsplit(url).path or "/"
    segments = ["{id}" if _NUMERIC_SEGMENT.match(s) else s for s in path.split("/")]
    return (method or "GET").upper(), "/".join(segments)


@dataclass(frozen=True)
class FreshnessConfig:
    enabled: bool = False
    window: int = 20          # last N sends to known-good routes considered
    min_denials: int = 6      # 401/403s in the window before a session can be stale
    min_routes: int = 2       # distinct known-good routes among those denials
    denial_rate: float = 0.6  # denials / window entries

    @classmethod
    def from_config(cls, config: dict | None) -> "FreshnessConfig":
        transport = (config or {}).get("transport", {}) or {}
        raw = transport.get("session_freshness") or {}
        if not isinstance(raw, dict):
            return cls()
        return cls(enabled=bool(raw.get("enabled", False)),
                   window=max(1, int(raw.get("window", 20))),
                   min_denials=max(1, int(raw.get("min_denials", 6))),
                   min_routes=max(1, int(raw.get("min_routes", 2))),
                   denial_rate=min(1.0, max(0.0, float(raw.get("denial_rate", 0.6)))))


@dataclass
class _SessionTrack:
    generation: int = 0
    good_routes: set = field(default_factory=set)
    recent: deque = field(default_factory=deque)   # (route, denied: bool)
    stale_reported: bool = False


class SessionFreshness:
    """Per-run tracker; the transport feeds it every send that carried a session."""

    def __init__(self, config: FreshnessConfig):
        self.config = config
        self._tracks: dict[str, _SessionTrack] = {}
        self.events: list[dict] = []

    def _track(self, session) -> _SessionTrack:
        track = self._tracks.get(session.session_id)
        if track is None or track.generation != session.generation:
            # A refreshed session (new generation) starts a fresh window but keeps
            # what the principal was served: its known-good routes still hold.
            fresh = _SessionTrack(generation=session.generation)
            if track is not None:
                fresh.good_routes = set(track.good_routes)
            track = self._tracks[session.session_id] = fresh
        return track

    def observe(self, session, method: str, url: str, status: int) -> bool:
        """Record one send; True when this send made the session stale."""
        if not self.config.enabled or status is None:
            return False
        track = self._track(session)
        key = route_key(method, url)
        if 200 <= status < 300:
            track.good_routes.add(key)
            track.recent.append((key, False))
        elif status in (401, 403):
            if key not in track.good_routes:
                return False      # never served to this principal: access control
            track.recent.append((key, True))
        else:
            return False
        while len(track.recent) > self.config.window:
            track.recent.popleft()
        return self._is_stale(track)

    def _is_stale(self, track: _SessionTrack) -> bool:
        denied = [route for route, was_denied in track.recent if was_denied]
        if len(denied) < self.config.min_denials:
            return False
        if len(set(denied)) < self.config.min_routes:
            return False
        return len(denied) / len(track.recent) >= self.config.denial_rate

    def evidence(self, session) -> dict:
        """Counts only (never a header, token or body) for the event log."""
        track = self._track(session)
        denied = [route for route, was_denied in track.recent if was_denied]
        return {"window": len(track.recent), "denials": len(denied),
                "denied_routes": len(set(denied)), "known_good_routes": len(track.good_routes)}

    def reset_window(self, session) -> None:
        self._track(session).recent.clear()

    def record(self, kind: str, session, **detail) -> dict:
        event = {"kind": kind, "session": session.name, "session_id": session.session_id,
                 **detail}
        self.events.append(event)
        return event


def login_refresher(run_context, login: dict, base_url: str):
    """Build a refresh callback from an operator-declared login request.

    `login` = {method, path, body (str or JSON object), content_type,
    token_pointer (JSON pointer into the response), header (default
    Authorization), scheme (default Bearer), cookie (a cookie name to take
    from Set-Cookie instead of a token)}. The login is sent anonymously through
    the run's transport, so scope, the safety gate (a POST login needs
    validators.allow_mutating_replay, like any POST) and the budget apply.
    Returns `async () -> dict | None`: the new credential headers, or None.
    Credentials stay in memory; nothing here logs or stores them."""
    from harness.run_context import TypedRequest
    from urllib.parse import urljoin

    method = str(login.get("method") or "POST").upper()
    url = urljoin(base_url, str(login.get("path") or "/"))
    body = login.get("body")
    if body is not None and not isinstance(body, str):
        body = json.dumps(body)
    headers = {"Content-Type": str(login.get("content_type") or "application/json")} if body else {}
    pointer = str(login.get("token_pointer") or "")
    header_name = str(login.get("header") or "Authorization")
    scheme = login.get("scheme", "Bearer")
    cookie_name = str(login.get("cookie") or "")

    async def refresh() -> dict | None:
        outcome = await run_context.target_transport().execute(
            TypedRequest(method, url, headers=dict(headers), body=body),
            capability="session_refresh", max_redirects=0)
        if not outcome.ok or outcome.status is None or not 200 <= outcome.status < 300:
            return None
        fresh: dict = {}
        if pointer:
            token = _json_pointer(outcome.body, pointer)
            if isinstance(token, str) and token:
                fresh[header_name] = f"{scheme} {token}" if scheme else token
        if cookie_name:
            for name, value in _set_cookies(outcome.headers):
                if name == cookie_name and value:
                    fresh["Cookie"] = f"{name}={value}"
        return fresh or None

    return refresh


def _json_pointer(body: str, pointer: str):
    try:
        node = json.loads(body or "")
    except ValueError:
        return None
    for part in pointer.lstrip("/").split("/") if pointer.strip("/") else []:
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return None
    return node


def _set_cookies(headers: dict) -> list[tuple[str, str]]:
    out = []
    for key, value in (headers or {}).items():
        if key.lower() != "set-cookie":
            continue
        for item in value if isinstance(value, list) else str(value).split("\n"):
            name, _, rest = str(item).partition("=")
            out.append((name.strip(), rest.split(";", 1)[0].strip()))
    return out
