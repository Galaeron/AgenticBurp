"""Priority 2 (containment) — offline-verifiable half of the NC-O1 egress proof.

NC-O1 requires proving that a confined tool (sqlmap in a container run with
``--network none`` or behind a per-run egress proxy) sends ZERO packets to an
off-scope destination. The *live* proof needs Docker and is OWNER/LIVE. This
module is the instrument that proof uses: a control listener bound to an off-scope
sentinel address, plus a hard assertion that nothing reached it.

Owner workflow (live):

    probe = EgressProbe(host="0.0.0.0", port=9999).start()
    # ... run the confined sqlmap container; nothing legitimate points at 9999 ...
    probe.stop()
    probe.assert_contained()   # raises EgressLeak if the container leaked out

The listener and its accounting are pure Python and fully exercised offline (a
connection is a leak; no connection is containment); Docker supplies only the
subject under test, never this instrument's correctness. Binds to loopback by
default so tests never open a real external port.
"""
from __future__ import annotations

import argparse
import json
import socket
import socketserver
import threading
import time
from typing import Any


class EgressLeak(AssertionError):
    """Raised when the off-scope sentinel received one or more connections."""


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = b""
        try:
            self.request.settimeout(0.5)
            data = self.request.recv(256)
        except OSError:
            pass
        # server.probe is attached in EgressProbe.start()
        self.server.probe._record(self.request, self.client_address, data)  # type: ignore[attr-defined]


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False      # EgressProbe.stop() drains handlers itself, within a bound

    def process_request(self, request, client_address):
        # Recorded on the accepting thread, before a handler reads anything: an
        # accepted connection is a leak however its handler fares (R37).
        self.probe._record_accept(request, client_address)  # type: ignore[attr-defined]
        super().process_request(request, client_address)

    def finish_request(self, request, client_address):
        try:
            super().finish_request(request, client_address)
        finally:
            self.probe._handler_done(request)  # type: ignore[attr-defined]


class EgressProbe:
    """A control listener that records every connection it receives.

    A recorded connection means egress reached the sentinel — i.e. a containment
    failure. Zero recorded connections is the pass condition.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._host, self._port = host, port
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._connections: list[dict[str, Any]] = []
        self._open: dict[int, dict[str, Any]] = {}     # handler still running, by id(request)
        self._lock = threading.Lock()
        self._drained = threading.Condition(self._lock)
        self._stopped = False

    def start(self) -> "EgressProbe":
        self._server = _Server((self._host, self._port), _Handler)
        self._server.probe = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("probe not started")
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def _record_accept(self, request: Any, peer: Any) -> None:
        entry = {
            "peer": f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) else str(peer),
            "bytes": 0,
            "preview": "",
            "at": round(time.time(), 3),
        }
        with self._lock:
            self._connections.append(entry)
            if request is not None:
                self._open[id(request)] = entry

    def _record(self, request: Any, peer: Any, data: bytes) -> None:
        """What an accepted connection sent (a handler whose accept went unrecorded still counts)."""
        with self._lock:
            entry = self._open.get(id(request))
            if entry is None:
                entry = {"peer": f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) else str(peer),
                         "at": round(time.time(), 3)}
                self._connections.append(entry)
            entry["bytes"] = len(data)
            entry["preview"] = data[:64].decode("latin-1", "replace")

    def _handler_done(self, request: Any) -> None:
        with self._drained:
            self._open.pop(id(request), None)
            self._drained.notify_all()

    def connections(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(c) for c in self._connections]

    def wait_for_connection(self, timeout: float = 2.0) -> bool:
        """Block up to ``timeout`` for at least one connection (test/CLI helper)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.connections():
                return True
            time.sleep(0.02)
        return bool(self.connections())

    def assert_contained(self) -> None:
        conns = self.connections()
        if conns:
            raise EgressLeak(
                f"egress NOT contained: sentinel received {len(conns)} connection(s): "
                f"{[c['peer'] for c in conns]}")

    def summary(self) -> dict[str, Any]:
        conns = self.connections()
        host, port = (self.address if self._server is not None else (self._host, self._port))
        return {
            "kind": "egress_containment_probe",
            "listen_address": f"{host}:{port}",
            "contained": not conns,
            "connection_count": len(conns),
            "connections": conns,
        }

    def stop(self, drain_timeout: float = 2.0) -> None:
        """Stop listening and finalize the record: every connection the serve loop
        accepted is already recorded; connections the kernel completed but nobody
        accepted are accepted and recorded here; running handlers get up to
        `drain_timeout` to record what they read."""
        if self._server is not None and not self._stopped:
            self._stopped = True
            self._server.shutdown()
            self._accept_backlog()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        deadline = time.monotonic() + drain_timeout
        with self._drained:
            while self._open and (left := deadline - time.monotonic()) > 0:
                self._drained.wait(left)

    def _accept_backlog(self) -> None:
        sock = self._server.socket
        try:
            sock.setblocking(False)
            while True:
                conn, peer = sock.accept()
                conn.close()
                self._record_accept(None, peer)
        except OSError:          # BlockingIOError: the backlog is empty
            pass

    def __enter__(self) -> "EgressProbe":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="0.0.0.0",
                        help="sentinel bind address (off-scope for the confined tool)")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--duration", type=float, default=60.0,
                        help="listen this many seconds while you run the confined tool")
    args = parser.parse_args(argv)
    probe = EgressProbe(host=args.host, port=args.port).start()
    try:
        # Announce the actual bound address so the operator can target it if desired.
        print(json.dumps({"listening": probe.summary()["listen_address"],
                          "duration_seconds": args.duration}))
        time.sleep(args.duration)
    finally:
        probe.stop()
    summary = probe.summary()
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["contained"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
