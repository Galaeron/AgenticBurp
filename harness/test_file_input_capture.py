"""File inputs on browser views become upload captures (driver_capture.file_uploads).

The fixture is a generic loopback single-page app (hash routes). Its home view
links to three views:
  - #/avatar: a file input (accept image/png, image/gif) whose change handler
    reads a preview (GET, carrying the file name) and uploads the file with
    fetch + FormData (POST /api/avatar);
  - #/docs: a multipart POST form with a hidden field and a file input (accept .pdf);
  - #/import: a file input (accept .csv) nothing uploads: no handler, no form.

Covered here:
  - upload_files: the benign file matches `accept` (extensions, exact and wildcard
    MIME types), is valid for its type, and nothing matches an unsupported list;
  - crawl_views with a fake adapter: once per input across views, the cap, a
    destructive form action, an adapter failure, and the default (0) never
    asking for file inputs;
  - through build_engagement with a real browser (skipped without Chromium):
    with writes on, both uploads are captured as the crawling identity with a
    benign accept-matching file, held in the browser (no upload reaches the
    server, the change log stays empty) and become endpoints; the input with no
    reachable upload is recorded as a skip. With writes off (the gate) nothing is
    attached (the preview read never fires) and each input is skipped with the
    reason; with the switch off nothing is tried;
  - the file_upload validator on such a capture (no source page renders a form)
    uploads under the captured file- and text-field names; controls: a
    non-multipart capture keeps the bare `file` part, and writes off send nothing.
"""
import asyncio
import io
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import yaml

from harness import cache, engagement_builder, store, upload_files
from harness.role_crawl import RoleSession
from harness.spa_navigation import UPLOAD_CAPABILITY, crawl_views, view_key

_HARNESS = Path(__file__).resolve().parent
LOW = RoleSession("user", {"Authorization": "Bearer low-token"}, name="low-user")


# --------------------------------------------------------------------------
# upload_files
# --------------------------------------------------------------------------

class BenignFileTest(unittest.TestCase):
    def test_the_file_type_follows_accept(self):
        cases = {"": "txt", "image/*": "png", "image/png,image/gif": "png",
                 ".gif": "gif", ".PDF": "pdf", "application/pdf": "pdf", ".csv": "csv",
                 "text/*": "txt", "application/json": "json", ".zip": "zip",
                 "*/*": "txt", "text/xml": "xml", " .png ; q=1 , .jpg": "png"}
        for accept, ext in cases.items():
            with self.subTest(accept=accept):
                name, mime, data = upload_files.benign_file(accept, "n0nce")
                self.assertEqual(name, f"harness-upload-n0nce.{ext}")
                self.assertTrue(data)

    def test_control_an_unsupported_accept_list_matches_nothing(self):
        for accept in ("application/msword", ".exe,.docx", "image/jpeg", "video/*"):
            with self.subTest(accept=accept):
                self.assertIsNone(upload_files.benign_file(accept, "n"))

    def test_each_file_is_valid_for_its_type(self):
        _n, mime, png = upload_files.benign_file("image/png", "n")
        self.assertEqual(mime, "image/png")
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        idat = png.index(b"IDAT")
        length = int.from_bytes(png[idat - 4:idat], "big")
        self.assertEqual(zlib.decompress(png[idat + 4:idat + 4 + length]), b"\x00\xff")
        _n, _m, gif = upload_files.benign_file(".gif", "n")
        self.assertTrue(gif.startswith(b"GIF89a") and gif.endswith(b";"))
        _n, _m, pdf = upload_files.benign_file(".pdf", "n")
        self.assertTrue(pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF"))
        xref = int(pdf.rsplit(b"startxref\n", 1)[1].split(b"\n", 1)[0])
        self.assertTrue(pdf[xref:].startswith(b"xref"))
        _n, _m, archive = upload_files.benign_file(".zip", "n")
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            self.assertEqual(z.read("harness-upload.txt"), b"harness upload test n\n")
        _n, _m, text = upload_files.benign_file("", "n0nce")
        self.assertIn(b"n0nce", text)


# --------------------------------------------------------------------------
# crawl_views with a fake adapter
# --------------------------------------------------------------------------

class _FakeUploads:
    """Two views; `inputs` maps a view key to its file inputs. `upload` answers a
    capture for inputs named in `uploads`, a skip otherwise."""

    def __init__(self, links, inputs, uploads=(), fail=()):
        self.links_by, self.inputs, self.uploads, self.fail = links, inputs, set(uploads), set(fail)
        self.cur, self.asked, self.tried = "", 0, []

    async def open(self, url):
        self.cur = url

    async def links(self):
        return self.links_by.get(view_key(self.cur), [])

    async def drain(self):
        return []

    def current_url(self):
        return self.cur

    async def file_inputs(self):
        self.asked += 1
        return self.inputs.get(view_key(self.cur), [])

    async def upload(self, desc):
        self.tried.append((desc["name"], desc["case_ref"]))
        if desc["name"] in self.fail:
            raise RuntimeError("boom")
        if desc["name"] in self.uploads:
            return {"method": "POST", "url": "http://desk.test/api/" + desc["name"],
                    "request_body": "x"}, "held, not sent"
        return None, "no upload request observed"


class CrawlViewsUploadsTest(unittest.TestCase):
    _START = "http://desk.test/#/"
    _LINKS = {"/#/": ["#/a", "#/b"]}

    def _inputs(self):
        shared = {"index": 0, "name": "doc", "accept": ".pdf",
                  "form": {"action": "http://desk.test/docs/upload", "method": "post"}}
        return {"/#/": [{"index": 0, "name": "pic", "accept": "image/*", "form": None}],
                "/#/a": [shared, {"index": 1, "name": "", "accept": "", "form": None},
                         {"index": 2, "name": "wipe",
                          "form": {"action": "http://desk.test/account/delete", "method": "post"}}],
                "/#/b": [dict(shared)]}

    def _crawl(self, app, **kw):
        return asyncio.run(crawl_views(app, self._START, in_scope=lambda u: "desk.test" in u, **kw))

    def test_each_input_is_tried_once_and_recorded(self):
        app = _FakeUploads(self._LINKS, self._inputs(), uploads={"pic"})
        res = self._crawl(app, uploads=4)
        by_input = {(u["view"], u["input"]): u for u in res.uploads}
        self.assertEqual(by_input[("/#/", "pic")]["outcome"], "captured")
        self.assertEqual(by_input[("/#/", "pic")]["request"], "POST /api/pic")
        self.assertEqual(by_input[("/#/a", "doc")]["reason"], "no upload request observed")
        self.assertEqual(by_input[("/#/a", "#1")]["outcome"], "skipped")
        self.assertEqual(by_input[("/#/a", "wipe")]["reason"], "destructive-looking form action")
        # The same form field on another view is not tried again.
        self.assertNotIn(("/#/b", "doc"), by_input)
        self.assertEqual([n for n, _c in app.tried], ["pic", "doc", ""])
        self.assertTrue(all(c.startswith(UPLOAD_CAPABILITY + ":") for _n, c in app.tried))
        self.assertEqual(len({c for _n, c in app.tried}), 3)
        self.assertEqual([e["url"] for e in res.exchanges], ["http://desk.test/api/pic"])

    def test_the_cap_and_an_adapter_failure_are_recorded(self):
        app = _FakeUploads(self._LINKS, self._inputs(), fail={"doc"})
        res = self._crawl(app, uploads=2)
        reasons = {u["input"]: u["reason"] for u in res.uploads}
        self.assertIn("upload attempt failed", reasons["doc"])
        self.assertEqual(reasons["#1"], "upload cap reached")
        self.assertEqual(len(app.tried), 2)

    def test_control_the_default_never_asks_for_file_inputs(self):
        app = _FakeUploads(self._LINKS, self._inputs(), uploads={"pic"})
        res = self._crawl(app)
        self.assertEqual((app.asked, app.tried, res.uploads, res.exchanges), (0, [], [], []))
        self.assertEqual(len(res.views), 3)


# --------------------------------------------------------------------------
# Through build_engagement with a real browser
# --------------------------------------------------------------------------

_SHELL = """<!doctype html><html><head><meta charset="utf-8"><title>Desk</title></head>
<body><main id="view"></main><script src="/static/app.js"></script></body></html>"""

_APP_JS = """(function () {
  var views = {
    "": '<a href="#/avatar">Avatar</a> <a href="#/docs">Docs</a> <a href="#/import">Import</a>',
    "avatar": '<input type="file" id="pic" name="avatar" accept="image/png,image/gif">',
    "docs": '<form method="post" action="/docs/upload" enctype="multipart/form-data">' +
            '<input type="hidden" name="t" value="x">' +
            '<input type="file" name="doc" accept=".pdf"></form>',
    "import": '<input type="file" name="dataset" accept=".csv">'
  };
  function render() {
    var p = (location.hash || "#/").replace(/^#\\/?/, "");
    document.getElementById("view").innerHTML = views[p] || views[""];
    var pic = document.getElementById("pic");
    if (pic) pic.addEventListener("change", function () {
      var f = pic.files[0];
      fetch("/api/avatar-preview?name=" + encodeURIComponent(f.name));
      var fd = new FormData(); fd.append("avatar", f); fd.append("kind", "profile");
      fetch("/api/avatar", {method: "POST", body: fd}).catch(function () {});
    });
  }
  window.addEventListener("hashchange", render);
  render();
})();
"""


class _Handler(BaseHTTPRequestHandler):
    seen: list = []
    uploads: list = []

    def do_GET(self):
        parts = urlsplit(self.path)
        _Handler.seen.append((parts.path, parse_qs(parts.query).get("name", [""])[0]))
        if parts.path == "/":
            self._reply(_SHELL, "text/html")
        elif parts.path == "/static/app.js":
            self._reply(_APP_JS, "application/javascript")
        elif parts.path.startswith("/api/"):
            self._reply(json.dumps({"ok": True}), "application/json")
        else:
            self._reply("", "text/plain", 404)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if b"harness-upload-" in body:
            _Handler.uploads.append(urlsplit(self.path).path)
        self._reply("{}", "application/json")

    def _reply(self, text, ctype, code=200):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _chromium_available() -> bool:
    try:
        from playwright.async_api import async_playwright

        async def probe():
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                await browser.close()
        asyncio.run(probe())
        return True
    except Exception:
        return False


def _config(*, writes: bool) -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    for name in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(name, {})["enabled"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    cfg.setdefault("validators", {}).update(active_enabled=writes, allow_mutating_replay=writes)
    return cfg


def _attached() -> list:
    """The preview reads the page fired for an attached benign file. (The role crawl
    also reads the paths the bundle names, with a placeholder value.)"""
    return [n for p, n in _Handler.seen
            if p == "/api/avatar-preview" and n.startswith("harness-upload-")]


@unittest.skipUnless(_chromium_available(), "Chromium (playwright) not available")
class BuildEngagementFileInputsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="file_inputs_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _build(self, capture, *, writes):
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config(writes=writes)
        _Handler.seen, _Handler.uploads = [], []
        out = {}

        async def build():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                state, result = await engagement_builder.build_engagement(
                    self.base, [LOW], allowed_hosts=["127.0.0.1"], crawl_max_pages=4,
                    active_discovery=False, run_context=ctx,
                    driver_capture_config={"enabled": True, "spa_navigation": True,
                                           "wait_ms": 600, "max_views": 8, **capture})
                out["changes"] = ctx.change_log.entries() if ctx.change_log else []
                return state, result
        state, result = asyncio.run(build())
        spa = next(v for v in result.spa_views if v["principal"] == "low-user")
        return state, result, spa, out

    @staticmethod
    def _uploads(result):
        return {urlsplit(c["url"]).path: c for c in result.captured
                if c.get("capture_source") == UPLOAD_CAPABILITY}

    def test_uploads_are_captured_held_and_never_sent(self):
        state, result, spa, out = self._build({"file_uploads": True}, writes=True)
        by_input = {u["input"]: u for u in spa["uploads"]}
        self.assertEqual(by_input["avatar"]["outcome"], "captured", spa["uploads"])
        self.assertEqual(by_input["doc"]["outcome"], "captured", spa["uploads"])
        captured = self._uploads(result)
        self.assertEqual(set(captured), {"/api/avatar", "/docs/upload"})
        avatar = captured["/api/avatar"]
        self.assertEqual(avatar["method"], "POST")
        self.assertIsNone(avatar["response_status"])
        self.assertEqual(avatar["request_headers"]["Authorization"], "Bearer low-token")
        ctype = next(v for k, v in avatar["request_headers"].items() if k.lower() == "content-type")
        self.assertTrue(ctype.startswith("multipart/form-data"))
        self.assertRegex(avatar["request_body"],
                         r'name="avatar"; filename="harness-upload-[0-9a-f]+\.png"')
        self.assertIn("Content-Type: image/png", avatar["request_body"])
        self.assertIn('name="kind"', avatar["request_body"])
        self.assertIn("held in the browser and never sent", avatar["analyst_note"])
        doc = captured["/docs/upload"]
        self.assertRegex(doc["request_body"], r'name="doc"; filename="harness-upload-[0-9a-f]+\.pdf"')
        self.assertIn('name="t"', doc["request_body"])
        # The file was attached (the page's own preview read fired) ...
        self.assertTrue(any(p == "/api/avatar-preview" and n.startswith("harness-upload-")
                            for p, n in _Handler.seen), _Handler.seen)
        # ... but no upload reached the server and nothing was written.
        self.assertEqual(_Handler.uploads, [])
        self.assertFalse([c for c in out["changes"] if c["capability"] == UPLOAD_CAPABILITY])
        # The captures are the endpoints' request shapes, seen as the crawling identity.
        self.assertIn("POST /api/avatar", state.endpoints)
        self.assertIn("POST /docs/upload", state.endpoints)
        self.assertIn("multipart/form-data",
                      state.endpoints["POST /api/avatar"].template["content_type"])

    def test_control_an_input_with_no_reachable_upload_is_a_recorded_skip(self):
        _state, result, spa, _out = self._build({"file_uploads": True}, writes=True)
        by_input = {u["input"]: u for u in spa["uploads"]}
        self.assertIn("dataset", by_input, (spa, result.errors))
        dataset = by_input["dataset"]
        self.assertEqual(dataset["outcome"], "skipped")
        self.assertIn("no upload request observed", dataset["reason"])
        self.assertIn(".csv", dataset["reason"])
        self.assertNotIn("/import", " ".join(self._uploads(result)))

    def test_control_writes_off_attach_nothing(self):
        _state, result, spa, out = self._build({"file_uploads": True}, writes=False)
        self.assertEqual({u["input"] for u in spa["uploads"]}, {"avatar", "doc", "dataset"})
        for entry in spa["uploads"]:
            self.assertEqual(entry["outcome"], "skipped")
            self.assertIn("writes are off", entry["reason"])
        self.assertEqual(self._uploads(result), {})
        self.assertFalse(_attached(), _Handler.seen)
        self.assertEqual(_Handler.uploads, [])
        self.assertEqual(out["changes"], [])

    def test_control_the_switch_off_tries_nothing(self):
        _state, result, spa, _out = self._build({}, writes=True)
        self.assertNotIn("uploads", spa)
        self.assertEqual(self._uploads(result), {})
        self.assertFalse(_attached(), _Handler.seen)
        self.assertGreaterEqual(spa["views"], 4)


# --------------------------------------------------------------------------
# the file_upload validator on a captured upload with no form to re-read
# --------------------------------------------------------------------------

def _captured_upload(field="picture", extra=(("caption", "hello"),)):
    """A capture as the browser hold records it: a script-issued multipart upload."""
    from harness.models import HttpExchange
    name, mime, data = upload_files.benign_file("image/png", "abc123")
    b = "----WebKitFormBoundaryFixture"
    parts = [f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n' for k, v in extra]
    parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{field}"; filename="{name}"\r\n'
                 f"Content-Type: {mime}\r\n\r\n{data.decode('latin-1')}\r\n")
    return HttpExchange(url="http://target.test/api/picture", method="POST",
                        request_headers={"Content-Type": f"multipart/form-data; boundary={b}"},
                        request_body="".join(parts) + f"--{b}--\r\n",
                        capture_source="file_upload_capture")


class FileUploadValidatorCapturedFieldTest(unittest.TestCase):
    """No source page renders a form, so the validator uses the captured upload's
    own file-field and text-field names instead of a bare `file` part."""

    def setUp(self):
        from harness import safety_gate
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                                      "allowed_hosts": ["target.test"]})
        self.posts: list[dict] = []

    def tearDown(self):
        from harness import safety_gate
        safety_gate.reset_default_gate()

    def _validate(self, exchange):
        from unittest.mock import AsyncMock, patch
        import httpx
        import harness.validators.file_upload_validator as fu_mod
        from harness.models import Finding
        stored: dict = {}

        def handler(request):
            if request.method == "GET" and request.url.path.startswith("/uploads/"):
                return httpx.Response(200, text=stored.get(request.url.path, ""),
                                      headers={"content-type": "text/html"})
            if request.method == "GET":
                return httpx.Response(404, text="not here", headers={"content-type": "text/html"})
            body = request.content.decode("latin-1")
            self.posts.append({"body": body})
            if 'name="picture"; filename="' not in body or 'name="caption"' not in body:
                return httpx.Response(400, json={"error": "picture and caption are required"})
            marker = re.search(r"<!-- harness-upload-[0-9a-f]+ -->", body).group(0)
            fname = body.split('filename="', 1)[1].split('"', 1)[0]
            stored[f"/uploads/{fname}"] = marker
            return httpx.Response(200, json={"url": f"/uploads/{fname}"})

        real_cls = fu_mod.GatedAsyncClient

        def factory(gate, name, **kw):
            kw.pop("verify", None)
            kw["transport"] = httpx.MockTransport(handler)
            return real_cls(gate, name, **kw)

        finding = Finding(vulnerability_class="file_upload", severity="medium", confidence=0.7,
                          summary="t", evidence="t", suggested_test="t", basis="derived")
        with patch.object(fu_mod, "GatedAsyncClient", factory), \
                patch("harness.global_throttle.acquire", new_callable=AsyncMock):
            return asyncio.run(fu_mod.FileUploadValidator(allowed_hosts=["target.test"])
                               .validate(finding, exchange))

    def test_the_captured_field_names_are_used(self):
        r = self._validate(_captured_upload())
        self.assertEqual(r.status, "confirmed", r.summary)
        self.assertEqual(len(self.posts), 1)
        self.assertIn('name="caption"\r\n\r\nhello', self.posts[0]["body"])
        self.assertNotIn('name="file"', self.posts[0]["body"])

    def test_control_a_non_multipart_capture_keeps_the_bare_file_part(self):
        ex = _captured_upload().model_copy(update={
            "request_headers": {"Content-Type": "application/json"}, "request_body": "{}"})
        r = self._validate(ex)
        self.assertEqual(r.status, "not_confirmed", r.summary)
        self.assertIn('name="file"; filename="', self.posts[0]["body"])

    def test_control_writes_off_sends_nothing(self):
        from harness import safety_gate
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": False,
                                      "allowed_hosts": ["target.test"]})
        r = self._validate(_captured_upload())
        self.assertEqual(r.status, "skipped")
        self.assertEqual(self.posts, [])


if __name__ == "__main__":
    unittest.main()
