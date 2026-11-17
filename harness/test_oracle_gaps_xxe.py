"""Oracle gap (xxe): an XML document uploaded as a multipart file part was never
probed -- the leg only knew a whole-body XML request and skipped the upload as
"endpoint does not take XML".

The leg now finds an XML-bearing part (named or typed as XML, or XML content)
and puts the same in-band file-read and out-of-band entity payloads into that
part, keeping every other part, the boundary and the multipart Content-Type.
XXE is disabled on the live lab, so a loopback fixture whose "parser" resolves a
declared SYSTEM entity in the uploaded part is the proof. Controls: a parser
that keeps entities unresolved, and a multipart upload with no XML part.
"""
import asyncio
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harness import global_throttle, safety_gate
from harness.models import Finding, HttpExchange
from harness.validators.xxe_validator import XxeValidator, multipart_xml_part

_BOUNDARY = "----harnessFixtureBoundary7MA4YWxk"
_ENTITY = re.compile(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>')
_FAKE_PASSWD = "root:x:0:0:root:/root:/bin/sh\n"


def _multipart(parts) -> str:
    out = []
    for name, filename, ctype, content in parts:
        disp = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
        head = f"Content-Disposition: {disp}" + (f"\r\nContent-Type: {ctype}" if ctype else "")
        out.append(f"--{_BOUNDARY}\r\n{head}\r\n\r\n{content}\r\n")
    return "".join(out) + f"--{_BOUNDARY}--\r\n"


class _Upload(BaseHTTPRequestHandler):
    """POST /resolving parses each uploaded XML part and resolves its SYSTEM
    entities (file:// read, http:// fetch recorded as a callback); POST /inert
    parses it but leaves entity references as text."""
    bodies: list = []
    callbacks: set = set()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        type(self).bodies.append((self.headers.get("Content-Type", ""), raw))
        boundary = re.search(r"boundary=([^;]+)", self.headers.get("Content-Type", ""))
        echoed = []
        if boundary:
            for piece in raw.split("--" + boundary.group(1))[1:]:
                if piece.startswith("--"):
                    break
                head, _, content = piece.lstrip("\r\n").partition("\r\n\r\n")
                if "filename=" not in head or "<" not in content:
                    continue
                text = content
                for name, uri in _ENTITY.findall(content):
                    value = ""
                    if self.path == "/resolving":
                        if uri == "file:///etc/passwd":
                            value = _FAKE_PASSWD
                        elif uri.startswith("http"):
                            type(self).callbacks.add(uri.rsplit("/", 1)[-1])
                        text = text.replace(f"&{name};", value)
                if "image/" not in head:  # an image is stored, never echoed (blind)
                    echoed.append(re.sub(r"<[^>]+>", " ", _ENTITY.sub("", text)))
        body = ("Complaint received: " + " ".join(echoed)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _Collab:
    def __init__(self):
        self.n = 0

    def token(self):
        self.n += 1
        return f"oobtok{self.n}"

    def url(self, token):
        return f"http://collab.invalid/{token}"

    async def wait_for_hit(self, token, timeout=6.0):
        return token in _Upload.callbacks


class OracleGapXxeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global_throttle.configure(0)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Upload)
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
        _Upload.bodies, _Upload.callbacks = [], set()

    def _exchange(self, path, parts):
        return HttpExchange(
            url=self.base + path, method="POST",
            request_headers={"Content-Type": f"multipart/form-data; boundary={_BOUNDARY}"},
            request_body=_multipart(parts), response_status=200, response_body="ok")

    def _xml_upload(self, path, ctype="text/xml", filename="order.xml"):
        return self._exchange(path, [
            ("note", "", "", "keep me"),
            ("file", filename, ctype,
             '<?xml version="1.0"?><complaint><text>late delivery</text></complaint>')])

    def run_leg(self, exchange, finding_class="file_upload"):
        finding = Finding(vulnerability_class=finding_class, severity="medium", confidence=0.5,
                          summary="s", evidence="e", suggested_test="t", basis="derived")
        leg = XxeValidator(allowed_hosts=["127.0.0.1"], timeout=2.0, collaborator=_Collab())
        self.assertTrue(leg.applies(finding, exchange))
        return asyncio.run(leg.validate(finding, exchange))

    def test_xml_part_is_found_by_name_type_or_content(self):
        self.assertEqual(multipart_xml_part(self._xml_upload("/x"))[2], 1)
        self.assertIsNotNone(multipart_xml_part(self._xml_upload("/x", "", "logo.svg")))
        self.assertIsNotNone(multipart_xml_part(self._xml_upload("/x", "application/octet-stream",
                                                                 "upload.bin")))
        pdf = self._exchange("/x", [("file", "a.pdf", "application/pdf", "%PDF-1.4 ...")])
        self.assertIsNone(multipart_xml_part(pdf))

    def test_inband_entity_in_an_uploaded_xml_part_confirms(self):
        result = self.run_leg(self._xml_upload("/resolving"))
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("multipart part 'file'", result.evidence)
        self.assertNotIn("root:x:0:0", result.evidence)
        ctype, body = _Upload.bodies[0]
        self.assertIn(_BOUNDARY, ctype)
        self.assertIn('name="note"\r\n\r\nkeep me\r\n', body)
        self.assertIn('filename="order.xml"\r\nContent-Type: text/xml', body)
        self.assertIn('SYSTEM "file:///etc/passwd"', body)

    def test_blind_entity_in_an_svg_part_confirms_out_of_band(self):
        exchange = self._exchange("/resolving", [
            ("avatar", "me.svg", "image/svg+xml",
             '<svg xmlns="http://www.w3.org/2000/svg"><title>me</title></svg>')])
        # The image part is never echoed, so only the out-of-band entity can prove it.
        result = self.run_leg(exchange)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("out-of-band", result.summary)
        self.assertEqual(len(_Upload.bodies), 2)
        self.assertIn('filename="me.svg"\r\nContent-Type: image/svg+xml', _Upload.bodies[1][1])

    def test_control_parser_without_entity_resolution_is_a_negative(self):
        result = self.run_leg(self._xml_upload("/inert"))
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(len(_Upload.bodies), 2)
        self.assertTrue(all('name="note"' in b for _, b in _Upload.bodies))

    def test_control_multipart_without_an_xml_part_is_skipped_unsent(self):
        exchange = self._exchange("/resolving", [("file", "a.pdf", "application/pdf", "%PDF-1.4")])
        finding = Finding(vulnerability_class="xxe", severity="medium", confidence=0.5,
                          summary="s", evidence="e", suggested_test="t", basis="derived")
        leg = XxeValidator(allowed_hosts=["127.0.0.1"], collaborator=_Collab())
        result = asyncio.run(leg.validate(finding, exchange))
        self.assertEqual(result.status, "skipped")
        self.assertEqual(_Upload.bodies, [])

    def test_control_mutating_replay_off_sends_nothing(self):
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": False,
                                      "allowed_hosts": ["127.0.0.1"]})
        result = self.run_leg(self._xml_upload("/resolving"))
        self.assertEqual(result.status, "skipped")
        self.assertEqual(_Upload.bodies, [])


if __name__ == "__main__":
    unittest.main()
