"""A stored-XSS plant the server rejects is retried field by field.

The leg wrote its payload into EVERY string field of the captured write. A write
that also carries a checked string (a CAPTCHA answer, a token) was then refused,
nothing was stored, and the leg still reported "not reflected": a negative for a
write that never landed.

The fixture is a generic loopback app. `POST /notes` takes JSON
`{"captcha": <answer>, "text": <note>, "rating": <n>}` and stores the note only
when the answer is the captured one (else 401). `GET /notes` renders every note
unescaped in HTML. `POST /strict` refuses every write; `POST /open` stores any.
A recording driver stands in for the browser: it fetches the page and "runs" a
payload by logging the product its alert() computes.

Covered here:
  - the all-fields plant is refused; the text field alone is accepted, its other
    fields at their captured values; the stored payload runs (confirmed);
  - the accepted field carries the later payload shapes (no new field retries);
  - control: every plant refused is inconclusive, never a negative;
  - control: a write that takes the all-fields plant tries no single field;
  - the field order: free text first, checked names (captcha, token, id) last.
"""
import asyncio
import json
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import httpx

from harness.browser_driver import ExecutionObservation
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators.stored_xss_validator import StoredXssValidator, _plant_field_order

_ANSWER = "41"


class _Handler(BaseHTTPRequestHandler):
    notes: list = []
    writes: list = []

    def do_POST(self):
        path = urlsplit(self.path).path
        doc = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        _Handler.writes.append((path, doc))
        if path == "/notes" and doc.get("captcha") != _ANSWER:
            return self._reply(401, "Wrong answer", "text/plain")
        if path == "/strict":
            return self._reply(400, "Invalid", "text/plain")
        _Handler.notes.append(str(doc.get("text")))
        self._reply(201, json.dumps({"status": "ok"}), "application/json")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ("/notes", "/open", "/strict"):
            items = "".join(f"<li>{n}</li>" for n in _Handler.notes)
            return self._reply(200, f"<html><body><ul>{items}</ul></body></html>", "text/html")
        self._reply(404, "", "text/plain")

    def _reply(self, status, text, ctype):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _RunningDriver:
    """Fetches the page; an unescaped payload's alert(a*b) "runs" and logs a*b."""
    def __init__(self):
        self.visits: list[str] = []

    async def visit(self, url, *, wait_ms=1500, headers=None, **kw):
        self.visits.append(url)
        async with httpx.AsyncClient() as c:
            text = (await c.get(url)).text
        console = [str(int(a) * int(b)) for a, b in re.findall(r"alert\((\d+)\*(\d+)\)", text)]
        return ExecutionObservation(url=url, console=console[:1])


def _finding():
    return Finding(vulnerability_class="stored_xss", confidence=0.5, summary="stored xss candidate",
                   evidence="", suggested_test="plant and render", basis="assumed", severity="high")


def _write(base, path):
    body = json.dumps({"captcha": _ANSWER, "text": "a short note", "rating": 3})
    return HttpExchange(url=f"{base}{path}", method="POST",
                        request_headers={"Content-Type": "application/json"},
                        request_body=body, response_status=201,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"status": "ok"}')


class FieldPlantTest(unittest.TestCase):
    def setUp(self):
        _Handler.notes, _Handler.writes = [], []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.driver = _RunningDriver()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _validate(self, path):
        async def run():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200,
                                         gate_config={"active_enabled": True,
                                                      "allow_mutating_replay": True}) as ctx:
                v = StoredXssValidator(allowed_hosts=["127.0.0.1"], driver=self.driver,
                                       run_context=ctx)
                return await v.validate(_finding(), _write(self.base, path))
        return asyncio.run(run())

    def test_a_refused_all_fields_plant_lands_in_the_text_field_alone_and_runs(self):
        r = self._validate("/notes")
        self.assertTrue(r.confirmed, (r.status, r.summary, r.evidence))
        first, second = _Handler.writes[0][1], _Handler.writes[1][1]
        self.assertNotEqual(first["captcha"], _ANSWER)          # every string field planted
        self.assertEqual(second["captcha"], _ANSWER)            # then the text field alone
        self.assertIn("alert(", second["text"])
        self.assertEqual(second["rating"], 3)

    def test_the_accepted_field_carries_the_later_payload_shapes(self):
        self.driver.visit = _never_runs(self.driver)            # keep every shape going
        r = self._validate("/notes")
        self.assertFalse(r.confirmed)
        self.assertEqual(r.status, "inconclusive")              # an unescaped render is a candidate
        accepted = [d for p, d in _Handler.writes if d.get("captcha") == _ANSWER]
        self.assertEqual(len(_Handler.writes), 4, _Handler.writes)  # 1 refused + 3 shapes
        self.assertEqual(len(accepted), 3)

    def test_control_every_plant_refused_is_inconclusive_not_a_negative(self):
        r = self._validate("/strict")
        self.assertEqual(r.status, "inconclusive", (r.summary, r.evidence))
        self.assertIn("rejected every plant", r.summary)
        self.assertEqual(_Handler.notes, [])

    def test_control_a_write_that_takes_every_field_tries_no_single_field(self):
        self.driver.visit = _never_runs(self.driver)
        self._validate("/open")
        self.assertEqual(len(_Handler.writes), 3)               # one plant per payload shape
        self.assertTrue(all(d["captcha"] != _ANSWER for _p, d in _Handler.writes))


def _never_runs(driver):
    async def visit(url, **kw):
        driver.visits.append(url)
        return ExecutionObservation(url=url)
    return visit


class FieldOrderTest(unittest.TestCase):
    def test_free_text_first_checked_names_last(self):
        order = _plant_field_order([("captcha", "41"), ("authorToken", "abc"), ("title", "Hi"),
                                    ("comment", "a longer note"), ("userId", "7")])
        self.assertEqual(order[:2], ["comment", "title"])
        self.assertEqual(set(order[2:]), {"captcha", "authorToken", "userId"})

    def test_control_a_single_string_field_has_no_retry(self):
        v = StoredXssValidator(allowed_hosts=["shop.test"])
        ex = HttpExchange(url="https://shop.test/c", method="POST", request_headers={},
                          request_body='{"text": "hi", "n": 1}', response_status=201,
                          response_headers={}, response_body="")
        self.assertEqual(v._plant_fields(ex), [])
        body, _ = v._plant_body(_write("https://shop.test", "/c"), "P", "text")
        self.assertEqual(json.loads(body), {"captcha": _ANSWER, "text": "P", "rating": 3})


if __name__ == "__main__":
    unittest.main()
