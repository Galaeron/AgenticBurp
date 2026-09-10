"""
Readable authorization-workflow fixture (Astra T04). INTENTIONALLY readable -- this
is an owned test target, NOT a blind/protected one, so a smoke test can prove the
authorization confirmation slice over real HTTP.

Two known users own private objects; a third is in a different tenant; one object is
public. In `vulnerable` mode `GET /objects/{id}` returns the object to ANY
authenticated caller (broken object-level authorization); in `patched` mode it
returns 403 unless the caller owns it (public objects stay readable by anyone). The
two modes differ ONLY in that ownership check.

Every object carries a unique per-instance marker, so a login page, a generic 200,
or an unrelated object can never satisfy an oracle by accident. Binds an ephemeral
loopback port; stop it with close().
"""
from __future__ import annotations

import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Bearer token -> (principal_id, tenant). Pre-shared for the fixture; a real login
# endpoint would mint these, but pre-sharing keeps the fixture small and readable.
_TOKENS = {
    "alice-token": ("alice", "A"),
    "bob-token": ("bob", "A"),      # same tenant as Alice, but NOT the owner of her objects
    "carol-token": ("carol", "B"),  # different tenant
}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep test output clean
        pass

    def _caller(self):
        auth = self.headers.get("Authorization", "") or ""
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        return _TOKENS.get(token)  # (principal_id, tenant) or None (anonymous/invalid)

    def _reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        fx = self.server.fixture
        fx._record(self.path, "GET", self.headers.get("Authorization"))
        parts = self.path.split("?", 1)[0].strip("/").split("/")
        if len(parts) == 2 and parts[0] == "objects":
            obj = fx.objects.get(parts[1])
            if obj is None:
                return self._reply(404, b"not found")
            caller = self._caller()
            if obj["public"]:
                return self._reply(200, obj["marker"].encode())        # public: anyone, incl. anonymous
            if caller is None:
                return self._reply(401, b"authentication required")     # private: anon denied (a real control)
            if fx.mode == "vulnerable":
                return self._reply(200, obj["marker"].encode())         # BOLA: no ownership check
            if caller[0] == obj["owner"]:
                return self._reply(200, obj["marker"].encode())         # patched: owner only
            return self._reply(403, b"forbidden")
        return self._reply(404, b"not found")


class AuthorizationWorkflowFixture:
    def __init__(self, mode: str = "vulnerable"):
        assert mode in ("vulnerable", "patched")
        self.mode = mode
        self.nonce = uuid.uuid4().hex[:8]
        # id -> {owner, tenant, public, marker}. Markers are unique per instance.
        self.objects = {
            "7": {"owner": "alice", "tenant": "A", "public": False, "marker": f"ALICE_PRIVATE_{self.nonce}"},
            "5": {"owner": "alice", "tenant": "A", "public": False, "marker": f"ALICE_SHARED_{self.nonce}"},
            "1": {"owner": "alice", "tenant": "A", "public": True, "marker": f"PUBLIC_DOC_{self.nonce}"},
            "9": {"owner": "carol", "tenant": "B", "public": False, "marker": f"CAROL_PRIVATE_{self.nonce}"},
        }
        self.received: list[dict] = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.fixture = self
        self.port = self.httpd.server_address[1]
        self._closed = False
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def _record(self, path: str, method: str, auth: str | None) -> None:
        self.received.append({"path": path.split("?", 1)[0], "method": method, "authorization": auth})

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def object_url(self, oid: str) -> str:
        return f"{self.base}/objects/{oid}"

    def marker(self, oid: str) -> str:
        return self.objects[oid]["marker"]

    def paths(self) -> list[str]:
        return [r["path"] for r in self.received]

    def requests_for(self, path: str) -> list[dict]:
        return [r for r in self.received if r["path"] == path]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.httpd.shutdown()
        self.httpd.server_close()
