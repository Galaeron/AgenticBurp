"""
Readable mass-assignment fixture (WSTG-CONF-09). INTENTIONALLY readable -- an owned
regression target, NOT a blind one, so a deterministic test can assert the
protected-field invariant over real HTTP.

A user record has client-updatable fields (`username`, `email`) and SERVER-CONTROLLED
fields the API must never let a client set via an ordinary update (`role`, `is_admin`,
`account_balance`; `id` is bound to the path). `PATCH /users/{id}` with a JSON body:

- `vulnerable` mode blindly merges every body key into the record (mass assignment):
  a client can flip `is_admin` or `role`.
- `patched` mode updates ONLY the whitelisted fields and ignores server-controlled
  ones, so the protected-field invariant holds: *an ordinary update leaves
  server-controlled fields unchanged.*

The two modes differ ONLY in that whitelist. `GET /users/{id}` returns the current
record so a test can VERIFY PERSISTED STATE with an independent re-read (not the
write's own echo). Every record carries a per-instance marker so a generic 200 or an
unrelated field can never satisfy an assertion by accident.

Determinism: the marker nonce is seeded (`seed`) so a given seed reproduces the same
markers; the record store is rebuilt fresh per instance (state reset). Binds an
ephemeral loopback port; stop it with close().
"""
from __future__ import annotations

import json
import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The only fields an ordinary update may change.
WRITABLE_FIELDS = frozenset({"username", "email"})
# Server-controlled fields an ordinary update must NEVER change (the invariant).
# `id` is path-bound and also protected.
PROTECTED_FIELDS = frozenset({"id", "role", "is_admin", "account_balance"})


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep test output clean
        pass

    def _reply(self, status, obj=None):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _record_id(self):
        parts = self.path.split("?", 1)[0].strip("/").split("/")
        if len(parts) == 2 and parts[0] == "users":
            return parts[1]
        return None

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            obj = json.loads(raw or b"{}")
            return obj if isinstance(obj, dict) else None
        except (ValueError, TypeError):
            return None

    def do_GET(self):
        fx = self.server.fixture
        fx._record(self.path, "GET", None)
        uid = self._record_id()
        rec = fx.users.get(uid) if uid else None
        if rec is None:
            return self._reply(404, {"error": "not found"})
        return self._reply(200, dict(rec))

    def _do_write(self, method):
        fx = self.server.fixture
        body = self._read_json_body()
        fx._record(self.path, method, body)
        uid = self._record_id()
        rec = fx.users.get(uid) if uid else None
        if rec is None:
            return self._reply(404, {"error": "not found"})
        if body is None:
            return self._reply(400, {"error": "invalid JSON body"})
        if fx.mode == "vulnerable":
            # Mass assignment: merge everything the client sent, except the path-bound id.
            for k, v in body.items():
                if k == "id":
                    continue
                rec[k] = v
        else:
            # Patched: only the whitelisted fields; server-controlled fields untouched.
            for k, v in body.items():
                if k in WRITABLE_FIELDS:
                    rec[k] = v
        return self._reply(200, dict(rec))

    def do_PATCH(self):
        self._do_write("PATCH")

    def do_PUT(self):
        self._do_write("PUT")

    def do_POST(self):
        self._do_write("POST")


class MassAssignmentFixture:
    """A tiny user API with a mass-assignment bug in `vulnerable` mode."""

    def __init__(self, mode: str = "patched", *, seed: int = 1729):
        assert mode in ("vulnerable", "patched")
        self.mode = mode
        # Seeded nonce -> reproducible markers (control randomness). Distinct per mode
        # so a vulnerable and a patched instance in one test never share a marker.
        self.nonce = f"{random.Random(f'{seed}:{mode}').getrandbits(32):08x}"
        self.users = self._fresh_store()
        self.received: list[dict] = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.fixture = self
        self.port = self.httpd.server_address[1]
        self._closed = False
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def _fresh_store(self) -> dict:
        """Rebuild the record store from scratch (state reset on every instance)."""
        return {
            "1": {"id": "1", "username": "alice", "email": "alice@example.test",
                  "role": "user", "is_admin": False, "account_balance": 100,
                  "marker": f"USER1_{self.nonce}"},
        }

    def reset(self) -> None:
        """Reset mutable state to the seeded baseline without re-binding the port."""
        self.users = self._fresh_store()
        self.received.clear()

    def _record(self, path: str, method: str, body) -> None:
        self.received.append({"path": path.split("?", 1)[0], "method": method, "body": body})

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def user_url(self, uid: str = "1") -> str:
        return f"{self.base}/users/{uid}"

    def marker(self, uid: str = "1") -> str:
        return self.users[uid]["marker"]

    def protected_snapshot(self, uid: str = "1") -> dict:
        """The current values of the server-controlled fields (for an invariant diff)."""
        rec = self.users[uid]
        return {k: rec[k] for k in PROTECTED_FIELDS if k in rec}

    def requests_for(self, path: str) -> list[dict]:
        return [r for r in self.received if r["path"] == path]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.httpd.shutdown()
        self.httpd.server_close()
