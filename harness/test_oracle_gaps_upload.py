"""Oracle gap (file_upload): an app that declares an upload policy (types, size)
only client-side accepted a disallowed .html file and an over-size file, but kept
no retrievable copy, and the leg reported a plain negative ("not retrievable").

The owner rule (LEG_DECISIONS.md, ORACLE_RETIREMENTS.md) confirms only a stored
copy served back in an active context, so acceptance against the app's OWN
declared policy is now a clearly labelled lead (not_confirmed, control_outcome
"inconclusive"): the policy is read from the upload form's `accept`, a captured
file input's note, or an uploader config in a same-origin script near the
endpoint path; a conforming control file must be accepted alike, and a declared
size limit is probed with one conforming file just over it.

Every request goes through the real GatedAsyncClient to a loopback app.
Controls: a server enforcing the type, a declared policy that allows .html, a
server enforcing the size, a rejected conforming control, and no declared policy.
"""
import asyncio
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from harness import global_throttle, safety_gate
from harness.models import Finding, HttpExchange
from harness.validators.file_upload_validator import FileUploadValidator, declared_policy_in

_SCRIPTS = {
    "/app.js": ('var u=new FileUploader({url:host+"/docs/upload",'
                'allowedMimeType:["application/pdf","application/zip"],maxFileSize:100000});'),
    "/open.js": 'var u=new FileUploader({url:host+"/open/upload",allowedMimeType:["text/html"],'
                'maxFileSize:100000});',
    "/weird.js": 'var u=new FileUploader({url:host+"/weird/upload",allowedMimeType:["application/pdf"]});',
}


class _App(BaseHTTPRequestHandler):
    uploads: list = []

    def _reply(self, status, body=b"", ctype="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            scripts = "".join(f'<script src="{s}"></script>' for s in _SCRIPTS)
            return self._reply(200, f"<html><body><app-root></app-root>{scripts}</body></html>"
                               .encode(), "text/html")
        if path in _SCRIPTS:
            return self._reply(200, _SCRIPTS[path].encode(), "application/javascript")
        if path == "/form":
            return self._reply(200, (
                '<html><form action="/forms/upload" method="post" enctype="multipart/form-data">'
                '<input type="file" name="doc" accept=".pdf"></form></html>').encode(), "text/html")
        return self._reply(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        path = urlsplit(self.path).path
        name = raw.split(b'filename="', 1)[1].split(b'"', 1)[0].decode() if b'filename="' in raw else ""
        type(self).uploads.append((path, name, length))
        html = name.endswith(".html")
        if path == "/strict/upload" and html:
            return self._reply(400, b'{"error":"only pdf"}', "application/json")
        if path == "/weird/upload" and not html:
            return self._reply(415, b"unsupported")
        if path == "/sized/upload" and length > 100_000:
            return self._reply(413, b"payload too large")
        if length > 200_000:
            return self._reply(500, b"File too large")
        return self._reply(204)

    def log_message(self, *args):
        pass


class OracleGapUploadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global_throttle.configure(0)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def setUp(self):
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                                      "allowed_hosts": ["127.0.0.1"]})
        self.addCleanup(safety_gate.reset_default_gate)
        _App.uploads = []

    def run_leg(self, path, *, referer="", note=""):
        headers = {"Referer": self.base + referer} if referer else {}
        exchange = HttpExchange(url=self.base + path, method="POST", request_headers=headers,
                                request_body="", response_status=204, analyst_note=note)
        finding = Finding(vulnerability_class="file_upload", severity="medium", confidence=0.5,
                          summary="s", evidence="e", suggested_test="t", basis="derived")
        leg = FileUploadValidator(allowed_hosts=["127.0.0.1"], timeout=5.0)
        return asyncio.run(leg.validate(finding, exchange)), list(_App.uploads)

    def test_policy_parser_reads_generic_uploader_keys(self):
        self.assertEqual(declared_policy_in(_SCRIPTS["/app.js"]),
                         (["application/pdf", "application/zip"], 100000))
        self.assertEqual(declared_policy_in('Dropzone({acceptedFiles:"image/*,.pdf",maxFilesize:2})'),
                         (["image/*", ".pdf"], 2 * 1024 * 1024))
        # Minifiers emit plain string literals as template literals (backticks).
        self.assertEqual(declared_policy_in(
            "new e.FileUploader({url:t+`/up`,allowedMimeType:[`application/pdf`,`text/xml`],"
            "maxFileSize:1e5})"), (["application/pdf", "text/xml"], 100000))
        # An HTTP Accept header or an unrelated cache size is not an upload policy.
        self.assertEqual(declared_policy_in('fetch(u,{headers:{accept:"application/json"}})'),
                         ([], None))
        self.assertEqual(declared_policy_in("new LRU({maxSize: 50000})"), ([], None))

    def test_script_declared_type_and_size_violations_are_a_labelled_lead(self):
        result, uploads = self.run_leg("/docs/upload")
        self.assertFalse(result.confirmed)
        self.assertEqual((result.status, result.control_outcome), ("not_confirmed", "inconclusive"))
        self.assertTrue(result.summary.startswith("Lead, not confirmed (owner rule"), result.summary)
        self.assertIn("text/html", result.summary)
        self.assertIn("over the declared 100000-byte limit", result.summary)
        self.assertIn("conforming control", result.evidence)
        self.assertTrue(result.limitation and result.manual_verification)
        # The .html upload, one conforming control and one over-size conforming file.
        self.assertEqual(len(uploads), 3, uploads)
        self.assertTrue(uploads[1][1].endswith(".pdf") and uploads[2][2] > 100_000)

    def test_form_accept_violation_is_a_lead_with_the_form_field(self):
        result, uploads = self.run_leg("/forms/upload", referer="/form")
        self.assertEqual(result.control_outcome, "inconclusive", result.summary)
        self.assertIn("accept='.pdf'", result.summary)
        self.assertEqual([u[0] for u in uploads], ["/forms/upload"] * 2)

    def test_captured_file_input_note_declares_the_policy(self):
        note = ("driver_capture: upload request the page issued for file input '#0' on view / "
                "with a benign generated .pdf file (accept=.pdf,.zip); held in the browser")
        result, _ = self.run_leg("/notes/upload", note=note)
        self.assertEqual(result.control_outcome, "inconclusive", result.summary)
        self.assertIn("captured file input", result.summary)

    def test_control_server_enforcing_the_type_stays_a_negative(self):
        result, uploads = self.run_leg("/strict/upload")
        self.assertEqual((result.status, result.control_outcome), ("not_confirmed", ""))
        self.assertIn("rejected with status 400", result.summary)
        self.assertEqual(len(uploads), 1)

    def test_control_declared_policy_allowing_html_and_enforced_size_is_a_negative(self):
        result, uploads = self.run_leg("/open/upload")
        # open.js allows text/html; the size probe (110000 bytes) is accepted -> size lead.
        self.assertIn("over the declared 100000-byte limit", result.summary)
        self.assertNotIn("text/html, HTTP", result.summary)
        _App.uploads = []
        _SCRIPTS["/sized.js"] = ('var u=new FileUploader({url:host+"/sized/upload",'
                                 'allowedMimeType:["text/html"],maxFileSize:100000});')
        try:
            result, uploads = self.run_leg("/sized/upload")
        finally:
            del _SCRIPTS["/sized.js"]
        self.assertEqual((result.status, result.control_outcome), ("not_confirmed", ""),
                         result.summary)
        self.assertIn("not retrievable", result.summary)

    def test_control_rejected_conforming_file_is_inconclusive(self):
        result, _ = self.run_leg("/weird/upload")
        self.assertEqual(result.status, "inconclusive", result.summary)
        self.assertFalse(result.confirmed)

    def test_control_no_declared_policy_keeps_the_negative(self):
        saved = dict(_SCRIPTS)
        _SCRIPTS.clear()
        try:
            result, uploads = self.run_leg("/docs/upload")
        finally:
            _SCRIPTS.update(saved)
        self.assertEqual((result.status, result.control_outcome), ("not_confirmed", ""))
        self.assertIn("not retrievable", result.summary)
        self.assertEqual(len(uploads), 1)


if __name__ == "__main__":
    unittest.main()
