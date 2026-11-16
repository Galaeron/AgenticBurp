"""Surface discovery reads the spec behind an API documentation page, under the
base path the spec names.

Two gaps, both generic:
  - a spec path (`/api-docs`) that answers a Swagger UI page, not the document,
    gave no spec: the page's init script embeds it (`"swaggerDoc": {...}`, as
    swagger-ui-express writes it) or names its URL (`SwaggerUIBundle({url: ...})`);
  - an OpenAPI 3 `servers[].url` path (`/partner/v3`) or a Swagger 2 `basePath`
    was dropped, so `/orders` was recorded instead of `/partner/v3/orders`.

Covered here:
  - with a canned responder: the embedded spec, the named spec URL, the UI
    library's bundle never fetched, a basePath, and the controls (an SPA shell at
    a spec path is no docs page; a spec URL on another origin is not fetched; a
    server on another origin or a templated one leaves the paths as they are);
  - with a loopback server, through a RunContext as a run sends it: `/api-docs`
    redirects to `/api-docs/`, whose init script embeds the spec.
"""
import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from harness.api_surface_discovery import (SurfaceDiscovery, _embedded_spec, _spec_base_path,
                                           _under_base)
from harness.run_context import RunContext

_NF = ("Traceback (most recent call last):\n"
       "werkzeug.exceptions.NotFound: 404 Not Found: The requested URL was not found on the server.")

_SPEC = {"openapi": "3.0.0", "info": {"title": "Partner"},
         "servers": [{"url": "/partner/v3"}],
         "paths": {"/orders": {"post": {"responses": {"200": {"description": "ok"}}}}}}
_UI_PAGE = """<!doctype html><html><head><title>Swagger UI</title>
<link rel="stylesheet" href="./swagger-ui.css"></head><body><div id="swagger-ui"></div>
<script src="./swagger-ui-bundle.js"></script>
<script src="./swagger-ui-standalone-preset.js"></script>
<script src="./swagger-ui-init.js"></script></body></html>"""
_INIT_EMBEDDED = ("window.onload = function () {\n  var options = " +
                  json.dumps({"swaggerDoc": _SPEC, "customOptions": {}}) +
                  ";\n  SwaggerUIBundle({spec: options.swaggerDoc, dom_id: '#swagger-ui'});\n};")
_INIT_URL = "window.onload = function () { SwaggerUIBundle({url: \"/specs/partner.json\", dom_id: '#swagger-ui'}); };"
_SHELL = "<!doctype html><html><body><app-root></app-root><script src=\"/main.js\"></script></body></html>"


class _FakeDiscovery(SurfaceDiscovery):
    def __init__(self, responder, **kw):
        super().__init__("http://target.test", use_ffuf=False, prefixes=["/api/"], collections=[],
                         nouns=["nope"], actions=[], sensitive_files=[], **kw)
        self._responder = responder
        self.asked: list[str] = []

    async def _probe(self, method, path):
        self.asked.append(path)
        return self._responder(method, path)


def _known(table):
    def r(method, path):
        return table.get(path, (500, _NF, ""))
    return r


def _run(disc):
    return asyncio.run(disc.discover())


def _route(res, path):
    return next((r for r in res.routes if r.path == path), None)


class SpecBehindUiTest(unittest.TestCase):
    def test_the_spec_embedded_in_the_ui_init_script_is_the_surface_under_its_server_path(self):
        disc = _FakeDiscovery(_known({
            "/api-docs": (200, _UI_PAGE, ""),
            "/swagger-ui-init.js": (200, _INIT_EMBEDDED, "")}))
        res = _run(disc)
        self.assertEqual(res.spec_found, "/api-docs")
        route = _route(res, "/partner/v3/orders")
        self.assertIsNotNone(route, res.paths())
        self.assertEqual(route.methods, ("POST",))
        self.assertIsNone(_route(res, "/orders"))
        # The UI library's own bundles are never read.
        self.assertNotIn("/swagger-ui-bundle.js", disc.asked)
        self.assertNotIn("/swagger-ui-standalone-preset.js", disc.asked)

    def test_the_spec_url_the_ui_names_is_fetched(self):
        disc = _FakeDiscovery(_known({
            "/api-docs": (200, _UI_PAGE, ""),
            "/swagger-ui-init.js": (200, _INIT_URL, ""),
            "/specs/partner.json": (200, json.dumps(_SPEC), "")}))
        res = _run(disc)
        self.assertEqual(res.spec_found, "/api-docs")
        self.assertIn("/partner/v3/orders", res.paths())

    def test_control_an_spa_shell_at_a_spec_path_is_no_docs_page(self):
        disc = _FakeDiscovery(_known({"/api-docs": (200, _SHELL, "")}))
        res = _run(disc)
        self.assertIsNone(res.spec_found)
        self.assertNotIn("/main.js", disc.asked)

    def test_control_a_spec_url_on_another_origin_is_not_fetched(self):
        init = "SwaggerUIBundle({url: \"https://elsewhere.test/specs/partner.json\"});"
        disc = _FakeDiscovery(_known({
            "/api-docs": (200, _UI_PAGE, ""),
            "/swagger-ui-init.js": (200, init, "")}))
        res = _run(disc)
        self.assertIsNone(res.spec_found)
        self.assertFalse(any("partner.json" in p for p in disc.asked), disc.asked)

    def test_a_document_served_directly_keeps_its_paths_under_its_server_path(self):
        disc = _FakeDiscovery(_known({"/openapi.json": (200, json.dumps(_SPEC), "")}))
        res = _run(disc)
        self.assertEqual(res.spec_found, "/openapi.json")
        self.assertIn("/partner/v3/orders", res.paths())


class SpecBasePathTest(unittest.TestCase):
    BASE = "http://target.test"

    def test_servers_relative_and_same_origin(self):
        self.assertEqual(_spec_base_path(json.dumps(_SPEC), self.BASE), "/partner/v3")
        doc = dict(_SPEC, servers=[{"url": "http://target.test/v2/"}])
        self.assertEqual(_spec_base_path(json.dumps(doc), self.BASE), "/v2")

    def test_swagger2_base_path(self):
        doc = {"swagger": "2.0", "host": "target.test", "basePath": "/api/v1", "paths": {"/a": {}}}
        self.assertEqual(_spec_base_path(json.dumps(doc), self.BASE), "/api/v1")

    def test_a_base_url_with_its_own_path_is_not_counted_twice(self):
        self.assertEqual(_spec_base_path(json.dumps(dict(_SPEC, servers=[{"url": "/app/v3"}])),
                                         "http://target.test/app"), "/v3")

    def test_control_other_origin_templated_root_and_none(self):
        for servers in ([{"url": "https://api.other.test/v1"}], [{"url": "{scheme}://target.test/v1"}],
                        [{"url": "/"}], []):
            self.assertEqual(_spec_base_path(json.dumps(dict(_SPEC, servers=servers)), self.BASE), "",
                             servers)
        doc = {"swagger": "2.0", "host": "other.test", "basePath": "/api", "paths": {}}
        self.assertEqual(_spec_base_path(json.dumps(doc), self.BASE), "")
        self.assertEqual(_spec_base_path("not json", self.BASE), "")
        self.assertEqual(_under_base("", "/a"), "/a")
        self.assertEqual(_under_base("/v1", "/a"), "/v1/a")

    def test_embedded_spec_needs_a_spec_shaped_object(self):
        self.assertIsNone(_embedded_spec('var o = {"spec": {"name": "x"}};'))
        self.assertIsNone(_embedded_spec('var o = {"swaggerDoc": {"openapi": "3.0.0", broken'))
        self.assertEqual(json.loads(_embedded_spec(_INIT_EMBEDDED))["servers"], _SPEC["servers"])


class _Handler(BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):
        path = urlsplit(self.path).path
        _Handler.seen.append(path)
        if path == "/api-docs":
            self.send_response(301)
            self.send_header("Location", "/api-docs/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/api-docs/":
            self._reply(_UI_PAGE, "text/html")
        elif path == "/api-docs/swagger-ui-init.js":
            self._reply(_INIT_EMBEDDED, "application/javascript")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _reply(self, text, ctype):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SpecBehindRedirectedUiLoopbackTest(unittest.TestCase):
    def setUp(self):
        _Handler.seen = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_a_redirected_docs_page_yields_its_embedded_spec_through_the_run(self):
        async def scenario():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200,
                                         gate_config={"active_enabled": True}) as ctx:
                disc = SurfaceDiscovery(self.base, allowed_hosts=["127.0.0.1"], max_probes=120,
                                        use_ffuf=False, run_context=ctx, prefixes=["/api/"],
                                        collections=[], nouns=["nope"], actions=[],
                                        sensitive_files=[])
                return await disc.discover()
        res = asyncio.run(scenario())
        self.assertEqual(res.spec_found, "/api-docs")
        self.assertIn("/partner/v3/orders", res.paths())
        self.assertIn("/api-docs/swagger-ui-init.js", _Handler.seen)
        self.assertNotIn("/api-docs/swagger-ui-bundle.js", _Handler.seen)


if __name__ == "__main__":
    unittest.main()
