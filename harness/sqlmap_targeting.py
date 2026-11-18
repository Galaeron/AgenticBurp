"""Which captured requests sqlmap may scan, and how long it may spend per endpoint family.

R11-3 (r11, 24 h run). sqlmap sent 52% of all target requests. About 2 h of that went
to a long-polling transport route and a few list routes, with no model calls in that
window. Two generic rules follow from that:

* A long-polling transport endpoint is recognised by its response framing, never by
  an app or product name: an Engine.IO open packet (a leading packet-type digit and a
  JSON handshake carrying `sid` with `upgrades`/`pingInterval`), a payload of
  Engine.IO packets (record-separated, or v3 length-prefixed), or a SockJS frame
  (`o`, `h`, `a[...]`, `c[...]`) or SockJS info object. Its query parameters
  (protocol version, transport name, session id, cache-buster) are transport state,
  not application input, so sqlmap is not run on them. Once one capture of a path
  shows the framing, every capture of that path is treated the same way, because a
  later poll may answer with a bare ping packet that is ambiguous on its own.
  A parameter called `t` or `sid` on any other route is ordinary input.
* sqlmap gets a wall-time share per endpoint family (method, origin, and path with
  object-id segments folded): `validators.sqlmap.endpoint_family_seconds`. A started
  scan always finishes; the next target on a family past its share is held, with a
  reason, and counted in `report()`. 0 disables the bound.

State is per run (keyed by run id). Without a run it lives on the validator.
"""
from __future__ import annotations

import json
import re
import threading
import time
from collections import OrderedDict
from urllib.parse import urlsplit

# A safe default: 15 min of sqlmap per endpoint family. One full scan is bounded by
# validators.sqlmap.timeout_seconds (90 s by default), so a family keeps roughly ten
# full scans before the next one is held.
DEFAULT_ENDPOINT_FAMILY_SECONDS = 900.0

_EIO_TYPES = "0123456"
_EIO_RS = "\x1e"
_ID_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{12,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")


def _json_value(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _is_eio_open(packet: str) -> bool:
    """An Engine.IO open packet: `0` then the handshake JSON."""
    if not packet.startswith("0{"):
        return False
    data = _json_value(packet[1:])
    return (isinstance(data, dict) and isinstance(data.get("sid"), str)
            and ("upgrades" in data or "pingInterval" in data))


def _is_sio_connect_ack(packet: str) -> bool:
    """A socket.io (v5) connect acknowledgement inside an Engine.IO message: `40{"sid":..}`."""
    if not packet.startswith("40{"):
        return False
    data = _json_value(packet[2:])
    return isinstance(data, dict) and isinstance(data.get("sid"), str)


def _length_prefixed(body: str) -> list[str] | None:
    """Engine.IO v3 text payload `<len>:<packet><len>:<packet>...`, or None."""
    packets, rest = [], body
    while rest:
        m = re.match(r"(\d{1,7}):", rest)
        if not m:
            return None
        n = int(m.group(1))
        packet = rest[m.end():m.end() + n]
        if n == 0 or len(packet) != n or packet[0] not in _EIO_TYPES:
            return None
        packets.append(packet)
        rest = rest[m.end() + n:]
    return packets or None


def _engineio_reason(body: str) -> str:
    text = body.strip()
    if not text or text[0] not in _EIO_TYPES:
        return ""
    if _EIO_RS in text:
        packets = text.split(_EIO_RS)
        framing = "record-separated Engine.IO packets"
    else:
        packets = _length_prefixed(text)
        framing = "length-prefixed Engine.IO packets"
        if packets is None:
            packets, framing = [text], ""
    if any(_is_eio_open(p) for p in packets):
        return "Engine.IO open packet (handshake with sid and upgrades/pingInterval)"
    if any(_is_sio_connect_ack(p) for p in packets):
        return "Engine.IO message carrying a connect acknowledgement with a sid"
    if framing and all(p and p[0] in _EIO_TYPES for p in packets):
        return framing
    return ""


def _sockjs_reason(body: str) -> str:
    if body in ("o\n", "h\n"):
        return f"SockJS {'open' if body[0] == 'o' else 'heartbeat'} frame"
    if body.endswith("\n") and body[:1] in ("a", "c") and body[1:2] == "[":
        data = _json_value(body[1:])
        if body[0] == "a" and isinstance(data, list) and all(isinstance(x, str) for x in data):
            return "SockJS message frame"
        if (body[0] == "c" and isinstance(data, list) and len(data) == 2
                and isinstance(data[0], int) and isinstance(data[1], str)):
            return "SockJS close frame"
        return ""
    data = _json_value(body)
    if isinstance(data, dict) and "websocket" in data and "entropy" in data:
        return "SockJS info object (websocket/entropy)"
    return ""


def transport_framing(response_body: str) -> str:
    """Why this response body is long-polling transport framing, or ''."""
    if not isinstance(response_body, str) or not response_body or len(response_body) > 65536:
        return ""
    return _engineio_reason(response_body) or _sockjs_reason(response_body)


def _origin_path(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower(), parts.path or "/"


def endpoint_family(method: str, url: str) -> str:
    """`METHOD origin/path` with object-id path segments folded to `{id}`."""
    origin, path = _origin_path(url)
    segments = ["{id}" if _ID_SEGMENT.match(s) else s for s in path.split("/")]
    return f"{(method or 'GET').upper()} {origin}{'/'.join(segments) or '/'}"


def _transport_key(url: str) -> str:
    origin, path = _origin_path(url)
    return origin + (path.rstrip("/") or "/")


def configured_family_seconds(run_context, default=None) -> float:
    """validators.sqlmap.endpoint_family_seconds from the run's config, else `default`."""
    cfg = getattr(run_context, "config", None) or {}
    sql = ((cfg.get("validators", {}) or {}).get("sqlmap", {}) or {}) if isinstance(cfg, dict) else {}
    value = sql.get("endpoint_family_seconds")
    if value is None:
        value = DEFAULT_ENDPOINT_FAMILY_SECONDS if default is None else default
    value = float(value)
    if value < 0:
        raise ValueError("validators.sqlmap.endpoint_family_seconds must be >= 0")
    return value


class SqlmapTargeting:
    """Per-run record of transport endpoints and sqlmap time per endpoint family."""

    def __init__(self, family_seconds: float = DEFAULT_ENDPOINT_FAMILY_SECONDS, clock=time.monotonic):
        self.family_seconds = float(family_seconds)
        self.clock = clock
        self._lock = threading.Lock()
        self._transport: dict[str, str] = {}
        self._spent: dict[str, float] = {}
        self._running: dict[int, tuple[str, float]] = {}
        self._held: dict[str, dict] = {}
        self._transport_skips: dict[str, int] = {}
        self._next = 0

    # -- transport endpoints -------------------------------------------------
    def transport_reason(self, exchange) -> str:
        """Why `exchange` is on a long-polling transport endpoint, or ''."""
        key = _transport_key(exchange.url)
        framing = transport_framing(getattr(exchange, "response_body", "") or "")
        with self._lock:
            if framing:
                self._transport.setdefault(key, framing)
            known = self._transport.get(key, "")
        if framing:
            return framing
        return f"another capture of this path answered with {known}" if known else ""

    def note_transport_skip(self, exchange) -> None:
        with self._lock:
            key = _transport_key(exchange.url)
            self._transport_skips[key] = self._transport_skips.get(key, 0) + 1

    # -- time share ----------------------------------------------------------
    def _spent_locked(self, family: str, now: float) -> float:
        running = sum(now - start for fam, start in self._running.values() if fam == family)
        return self._spent.get(family, 0.0) + running

    def hold_reason(self, method: str, url: str) -> str:
        """'' when sqlmap may start on this target; else why it is held (and count it)."""
        if self.family_seconds <= 0:
            return ""
        family = endpoint_family(method, url)
        with self._lock:
            spent = self._spent_locked(family, self.clock())
            if spent < self.family_seconds:
                return ""
            held = self._held.setdefault(family, {"endpoint_family": family,
                                                  "seconds_spent": 0.0, "targets_held": 0})
            held["seconds_spent"] = round(spent, 1)
            held["targets_held"] += 1
        return (f"endpoint_family_seconds: sqlmap used its {self.family_seconds:.1f} s share on "
                f"the endpoint family {family} ({spent:.1f} s spent); this target was held, "
                "not scanned")

    def start(self, method: str, url: str) -> int:
        family = endpoint_family(method, url)
        with self._lock:
            self._next += 1
            self._running[self._next] = (family, self.clock())
            return self._next

    def finish(self, token: int) -> None:
        with self._lock:
            entry = self._running.pop(token, None)
            if entry is not None:
                family, start = entry
                self._spent[family] = self._spent.get(family, 0.0) + max(0.0, self.clock() - start)

    def report(self) -> dict:
        """What was held or skipped, for the run's summary."""
        with self._lock:
            return {
                "endpoint_family_seconds": self.family_seconds,
                "seconds_by_family": {k: round(v, 1) for k, v in sorted(self._spent.items())},
                "held": [dict(v) for _, v in sorted(self._held.items())],
                "transport_endpoints": [
                    {"endpoint": k, "framing": v, "targets_skipped": self._transport_skips.get(k, 0)}
                    for k, v in sorted(self._transport.items())],
            }


_RUNS: "OrderedDict[str, SqlmapTargeting]" = OrderedDict()
_RUNS_LOCK = threading.Lock()
_MAX_RUNS = 16


def targeting_for(run_context, fallback_owner=None, default_seconds=None) -> SqlmapTargeting:
    """The run's SqlmapTargeting (shared by every sqlmap validator of the run).

    Without a run, the state lives on `fallback_owner` (the validator)."""
    run_id = getattr(run_context, "run_id", None) if run_context is not None else None
    if not run_id:
        state = getattr(fallback_owner, "_sqlmap_targeting", None)
        if state is None:
            state = SqlmapTargeting(configured_family_seconds(None, default_seconds))
            if fallback_owner is not None:
                fallback_owner._sqlmap_targeting = state
        return state
    with _RUNS_LOCK:
        state = _RUNS.get(run_id)
        if state is None:
            state = SqlmapTargeting(configured_family_seconds(run_context, default_seconds))
            _RUNS[run_id] = state
            while len(_RUNS) > _MAX_RUNS:
                _RUNS.popitem(last=False)
        else:
            _RUNS.move_to_end(run_id)
        return state


def run_report(run_context) -> dict | None:
    """The run's sqlmap targeting report, or None if sqlmap never consulted it."""
    run_id = getattr(run_context, "run_id", None)
    with _RUNS_LOCK:
        state = _RUNS.get(run_id) if run_id else None
    return state.report() if state is not None else None
