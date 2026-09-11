"""
Readable open-redirect fixture (WSTG-INPV-17). INTENTIONALLY readable -- an owned
regression target, NOT a blind one.

`GET /login?next=<url>` issues a 302 whose `Location` is derived from the client's
`next` parameter:

- `vulnerable` mode reflects `next` verbatim into `Location`, so an absolute or
  scheme-relative `next` sends the user OFF-ORIGIN (open redirect).
- `patched` mode only honours a SAME-ORIGIN relative `next` (a single leading slash,
  not a `//` or backslash form); anything else falls back to a safe default (`/`),
  so the redirect target can never leave the origin.

The two modes differ ONLY in that validation. The per-instance attacker host is
seeded so a given seed reproduces it. Binds an ephemeral loopback port; stop with
close().
"""
from __future__ import annotations

import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs


def is_safe_relative(nxt: str) -> bool:
    """A same-origin relative path: a single leading '/', not '//' or '/\\'."""
    if not nxt.startswith("/"):
        return False
    if nxt.startswith("//") or nxt.startswith("/\\") or nxt.startswith("\\"):
        return False
    return True


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        fx = self.server.fixture
        parts = urlsplit(self.path)
        fx._record(parts.path, "GET", self.path)
        if parts.path == "/login":
            nxt = (parse_qs(parts.query, keep_blank_values=True).get("next") or ["/"])[0]
            if fx.mode == "vulnerable":
                location = nxt                                   # reflected verbatim -> open redirect
            else:
                location = nxt if is_safe_relative(nxt) else "/"  # off-origin neutralised
            return self._redirect(location)
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


class OpenRedirectFixture:
    def __init__(self, mode: str = "patched", *, seed: int = 1729):
        assert mode in ("vulnerable", "patched")
        self.mode = mode
        self.nonce = f"{random.Random(f'{seed}:{mode}').getrandbits(32):08x}"
        self.attacker_host = f"attacker-{self.nonce}.example"
        self.received: list[dict] = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.fixture = self
        self.port = self.httpd.server_address[1]
        self._closed = False
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def _record(self, path: str, method: str, raw: str) -> None:
        self.received.append({"path": path, "method": method, "raw": raw})

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def login_url(self, next_value: str) -> str:
        from urllib.parse import quote
        return f"{self.base}/login?next={quote(next_value, safe='')}"

    def off_origin_next(self) -> str:
        """An absolute off-origin URL a client might supply as `next`."""
        return f"https://{self.attacker_host}/pwn"

    def reset(self) -> None:
        self.received.clear()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.httpd.shutdown()
        self.httpd.server_close()
