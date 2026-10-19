"""
Out-of-band (OOB) collaborator -- an in-process HTTP callback listener.

Blind SSRF and blind XXE leave no evidence in the response: the only proof the
target performed the attacker-controlled fetch is that it CALLS BACK to a listener
we control. This is that listener -- the Burp-Collaborator role, but local and
dependency-free.

Why in-process (not a container): unlike sqlmap, this needs no offensive binary
and nothing lands on host disk -- it's a plain HTTP server. It binds an ephemeral
loopback port; a target running on the host reaches it at http://127.0.0.1:<port>/
<token>. (Full internet-facing OOB with DNS would want a real interactsh-style
service; for a local target a loopback HTTP listener is sufficient and simpler.)

Usage:
    c = collaborator.shared()
    tok = c.token(); url = c.url(tok)        # embed url in the payload
    ... send the payload ...
    if await c.wait_for_hit(tok): CONFIRMED   # the target fetched our url
"""
from __future__ import annotations

import asyncio
import atexit
import http.server
import secrets
import threading
import time


class _Recorder(http.server.BaseHTTPRequestHandler):
    def _hit(self):
        try:
            self.server.hits.append(self.path)  # type: ignore[attr-defined]
        except Exception:
            pass
        try:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        except Exception:
            pass

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = _hit

    def log_message(self, *args):  # silence the default stderr logging
        pass


class Collaborator:
    """A running loopback HTTP listener that records the paths it is hit on."""

    def __init__(self, host: str = "127.0.0.1"):
        self._srv = http.server.ThreadingHTTPServer((host, 0), _Recorder)
        self._srv.hits = []  # type: ignore[attr-defined]
        self.host, self.port = self._srv.server_address
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()

    def token(self) -> str:
        return "oob" + secrets.token_hex(8)

    def url(self, token: str) -> str:
        return f"http://{self.host}:{self.port}/{token}"

    def was_hit(self, token: str) -> bool:
        return any(token in p for p in list(self._srv.hits))  # type: ignore[attr-defined]

    async def wait_for_hit(self, token: str, timeout: float = 6.0) -> bool:
        """Poll for a callback carrying `token`, up to `timeout` seconds."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.was_hit(token):
                return True
            await asyncio.sleep(0.25)
        return False

    def stop(self) -> None:
        """Stop serving AND release the listening socket (idempotent). `shutdown()`
        alone only ends the serve loop; the bound socket stays open until
        `server_close()`, which leaked one loopback socket per stopped collaborator."""
        try:
            self._srv.shutdown()
        except Exception:
            pass
        try:
            self._srv.server_close()
        except Exception:
            pass
        self._thread.join(timeout=2.0)


_SHARED: Collaborator | None = None
_ATEXIT_REGISTERED = False


def shared() -> Collaborator:
    """The process-wide collaborator, started on first use. Its serve loop is a daemon
    thread, but its listening socket is not released by the daemon dying: it is closed
    by `stop_shared()`, which is registered to run at interpreter exit."""
    global _SHARED, _ATEXIT_REGISTERED
    if _SHARED is None:
        _SHARED = Collaborator()
        if not _ATEXIT_REGISTERED:
            atexit.register(stop_shared)
            _ATEXIT_REGISTERED = True
    return _SHARED


def stop_shared() -> None:
    """Stop and forget the process-wide collaborator (idempotent); the next `shared()`
    starts a fresh one."""
    global _SHARED
    collaborator, _SHARED = _SHARED, None
    if collaborator is not None:
        collaborator.stop()
