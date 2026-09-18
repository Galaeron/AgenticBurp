"""
Crawlable end-to-end pipeline fixture -- the target for the REAL-discovery gate
(test_pipeline_gate.py).

Unlike the other testing_fixtures (mass_assignment, authorization_workflow), this
one is NOT seeded into the harness. It ADVERTISES its own surface -- it serves a
minimal OpenAPI document at /openapi.json -- so the harness's REAL discovery
(api_surface_discovery.SurfaceDiscovery via role_crawl's active_discovery) finds
the routes on its own. That is the whole point: every existing "real HTTP" slice
supplies discovery ("the object endpoint is seeded via the tester-fed seed
interface"), so none of them can catch discovery dropping a route, a method, or a
body -- the exact failure pattern this project keeps hitting. This fixture lets a
test run discovery -> request construction -> confirmation -> persisted report end
to end and assert the whole chain survives.

Surface (all under /api), chosen so the audit's canonical scenario -- a constrained
discovery budget with GET and POST routes, query parameters and request bodies --
is exercised:

  GET  /api/notes/{id}   object-scoped. Note "1" is alice's PRIVATE note. In
                         `vulnerable` mode ANY authenticated caller reads ANY note
                         (broken object-level authorization / IDOR); in `patched`
                         mode a non-owner gets 403. This is the confirmable leg:
                         the real CrossIdentityValidator confirms the crossing.
  GET  /api/notes?q=     a collection GET carrying a QUERY parameter -- so the gate
                         can assert discovery preserved the query shape.
  POST /api/notes        a mutating route with a JSON request BODY -- so the gate
                         can assert discovery preserved the method and the body.

Two identities are pre-shared as bearer tokens (a real login would mint these;
pre-sharing keeps the fixture small): `alice` owns note 1, `bob` is a second user
who must not read it. Every note carries a unique per-instance marker so a generic
200 or an unrelated field can never satisfy an oracle by accident. The two modes
differ ONLY in the ownership check on GET /api/notes/{id}.

Binds an ephemeral loopback port; stop it with close().
"""
from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Bearer token -> principal_id. Pre-shared for the fixture.
TOKENS = {
    "alice-token": "alice",
    "bob-token": "bob",
}


def _spec_doc() -> dict:
    """A minimal but valid OpenAPI 3 document. api_surface_discovery keys off
    the `"openapi"`/`"paths"` shape (_looks_like_spec) and templates ids as {id}
    (_paths_from_spec), so listing /api/notes/{id} here is what makes the harness
    discover an OBJECT-SCOPED route on its own."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "notes", "version": "1.0.0"},
        "paths": {
            "/api/notes": {
                "get": {
                    "summary": "list notes",
                    "parameters": [{"name": "q", "in": "query",
                                    "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok"}},
                },
                "post": {
                    "summary": "create note",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "body": {"type": "string"},
                            },
                            "required": ["title"],
                        }}},
                    },
                    "responses": {"201": {"description": "created"}},
                },
            },
            "/api/notes/{id}": {
                "get": {
                    "summary": "read a note",
                    "parameters": [{"name": "id", "in": "path", "required": True,
                                    "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok"},
                                  "403": {"description": "forbidden"}},
                },
            },
        },
    }


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep test output clean
        pass

    def _caller(self):
        auth = self.headers.get("Authorization", "") or ""
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        return TOKENS.get(token)  # principal_id or None (anonymous/invalid)

    def _reply(self, status, obj=None):
        body = b"" if obj is None else (obj if isinstance(obj, bytes)
                                        else json.dumps(obj).encode())
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _path_only(self):
        return self.path.split("?", 1)[0]

    def do_GET(self):
        fx = self.server.fixture
        fx._record(self._path_only(), "GET", self.headers.get("Authorization"))
        path = self._path_only()
        if path in ("/openapi.json",):
            return self._reply(200, _spec_doc())
        parts = path.strip("/").split("/")
        # GET /api/notes/{id}  -- object-scoped, the IDOR leg.
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "notes":
            note = fx.notes.get(parts[2])
            if note is None:
                return self._reply(404, {"error": "not found"})
            caller = self._caller()
            if caller is None:
                return self._reply(401, {"error": "authentication required"})  # anon control
            if fx.mode == "vulnerable":
                return self._reply(200, {"id": parts[2], "marker": note["marker"]})  # BOLA
            if caller == note["owner"]:
                return self._reply(200, {"id": parts[2], "marker": note["marker"]})  # owner only
            return self._reply(403, {"error": "forbidden"})
        # GET /api/notes  -- collection, carries ?q=
        if len(parts) == 2 and parts[0] == "api" and parts[1] == "notes":
            if self._caller() is None:
                return self._reply(401, {"error": "authentication required"})
            return self._reply(200, {"notes": []})
        return self._reply(404, {"error": "not found"})

    def do_POST(self):
        fx = self.server.fixture
        fx._record(self._path_only(), "POST", self.headers.get("Authorization"))
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        parts = self._path_only().strip("/").split("/")
        if len(parts) == 2 and parts[0] == "api" and parts[1] == "notes":
            if self._caller() is None:
                return self._reply(401, {"error": "authentication required"})
            try:
                body = json.loads(raw or b"{}")
            except (ValueError, TypeError):
                return self._reply(400, {"error": "invalid JSON body"})
            fx.received_bodies.append(body)
            return self._reply(201, {"id": "new", "title": (body or {}).get("title")})
        return self._reply(404, {"error": "not found"})


class DiscoveryPipelineFixture:
    """A tiny notes API that ADVERTISES its surface via /openapi.json and hides a
    broken-object-level-authorization (IDOR) bug in `vulnerable` mode."""

    def __init__(self, mode: str = "vulnerable"):
        assert mode in ("vulnerable", "patched")
        self.mode = mode
        self.nonce = uuid.uuid4().hex[:8]
        # id -> {owner, marker}. Note "1" is the default id_fill build_engagement
        # probes, so the object-scoped route is captured for a note that EXISTS
        # and is owned by alice -- the precondition the cross-identity leg needs.
        self.notes = {
            "1": {"owner": "alice", "marker": f"ALICE_NOTE1_{self.nonce}"},
            "2": {"owner": "bob", "marker": f"BOB_NOTE2_{self.nonce}"},
        }
        self.received: list[dict] = []
        self.received_bodies: list[dict] = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.fixture = self
        self.port = self.httpd.server_address[1]
        self._closed = False
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def _record(self, path: str, method: str, auth: str | None) -> None:
        self.received.append({"path": path, "method": method, "authorization": auth})

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def note_url(self, nid: str = "1") -> str:
        return f"{self.base}/api/notes/{nid}"

    def marker(self, nid: str = "1") -> str:
        return self.notes[nid]["marker"]

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
