"""Oracle gap (2026-11-14): a listed log file is rated by its content.

A directory listing served a rotated access log (`access.log.<date>`) and a
rotation-metadata JSON. The listing leg called both harmless: the log name does
not end in ".log", and no rule read the lines. These tests drive
Orchestrator._validate_findings against a generic loopback app.

  (i)   a listing whose rotated access log carries client addresses, request
        lines, statuses and user agents confirms as access_log (medium);
  (ii)  a log whose lines carry a token or session id is log_with_secrets (high),
        and the value never reaches the evidence;
  (iii) negative control: a listing of a changelog, a note, a README that quotes
        a stack trace and a rotation-metadata JSON stays not_confirmed;
  (iv)  the classifier itself: error logs, JSON-lines access logs, a redacted
        token, a one-document JSON and a UI-strings file.
"""
import asyncio
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from harness import cache, global_throttle, safety_gate, store
from harness.models import AgentReport, Finding, HttpExchange
from harness.validators.exposure_leads import classify_listed_file

_SECRET = "s3ss-" + "q" * 20


def _access_lines(n, *, extra=""):
    rows = [f'::ffff:10.0.0.{i} - - [14/Nov/2026:18:08:{i:02d} +0000] "GET /api/items/{i} HTTP/1.1" '
            f'200 {100 + i} "-" "Mozilla/5.0 (X11; Linux x86_64)"' for i in range(n)]
    if extra:
        rows.append(extra)
    return ("\n".join(rows) + "\n").encode()


_ROTATION = json.dumps({"keep": {"days": True, "amount": 2}, "auditLog": "logs/audit.json",
                        "files": [{"date": 1731600000000, "name": "logs/app.log.2026-11-14",
                                   "hash": "0" * 32}], "hashType": "md5"}, indent=2).encode()
_LISTINGS = {
    "/logs": {"access.log.2026-11-14": _access_lines(6), "audit.json": _ROTATION},
    "/debug": {"app.log.1": _access_lines(
        3, extra=f'10.0.0.9 - - [14/Nov/2026:18:09:00 +0000] "GET /account?session={_SECRET} '
                 f'HTTP/1.1" 200 12 "-" "curl/8.0"')},
    "/pub": {"CHANGELOG.md": b"# Changelog\n## [1.2.0] - 2024-01-02\n- fixed a bug\n"
                             b"## [1.1.0] - 2023-12-01\n- added a feature\n",
             "notes.txt": b"Meeting moved to 10:00 on Tuesday.\nBring the slides.\n",
             "README.md": b"# Troubleshooting\nIf startup fails you may see:\n\n```\n"
                          b"TypeError: x is undefined\n    at start (/app/server.js:10:5)\n"
                          b"    at main (/app/index.js:3:1)\n```\nReinstall and retry.\n"
                          b"See the docs for more.\nAsk on the forum.\nOr open an issue.\n",
             "rotation.json": _ROTATION},
}


def _index(directory, names):
    rows = "".join(f'<li><a href="{directory}/{n}">{n}</a></li>' for n in names)
    return (f"<!DOCTYPE html><html><head><title>Index of {directory}</title></head><body>"
            f'<a href="/">..</a><ul>{rows}</ul></body></html>').encode()


class _App(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body=b"", ctype="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.received.append(self.path)
        path = self.path.split("?", 1)[0]
        if path in _LISTINGS:
            return self.reply(200, _index(path, list(_LISTINGS[path])), "text/html")
        directory, _, name = path.rpartition("/")
        files = _LISTINGS.get(directory, {})
        if name in files:
            return self.reply(200, files[name], "application/octet-stream")
        return self.reply(404, b"Not found")


def _finding(cls):
    return Finding(vulnerability_class=cls, confidence=0.5, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived")


class ListingLogCallerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="oracle_gaps_listing_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        st = global_throttle.throttle.stats()
        prev = (st["rate_per_second"] if st["enabled"] else 0.0, st["burst"] if st["enabled"] else None)
        self.addCleanup(lambda: global_throttle.configure(*prev))
        global_throttle.configure(0)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
        self.server.received = []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def dispatch(self, path, cls="exposed_directory_listing"):
        from harness.orchestrator import Orchestrator
        from harness.run_context import RunContext
        from harness.test_default_history_caller import _RecordingModel, _config
        body = _index(path, list(_LISTINGS[path])).decode()
        exchange = HttpExchange(url=self.origin + path, method="GET", request_headers={},
                                response_status=200, response_headers={"Content-Type": "text/html"},
                                response_body=body)
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["127.0.0.1"]
        cfg["validators"].update(active_enabled=True)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for a in orch.agent_manager.agents.values():
            a.ollama = model
        orch.validator_registry.validators = {
            k: v for k, v in orch.validator_registry.validators.items()
            if k in ("listing_exposure", "filter_bypass")}

        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=100, config=cfg,
                                    gate_config={"active_enabled": True})
            async with run:
                reports, _proofs = await orch._validate_findings(
                    exchange, [AgentReport(agent="info_disclosure", model="fake",
                                           findings=[_finding(cls)])], run_context=run)
            await run.aclose()
            return reports

        reports = asyncio.run(go())
        return {r.validator: r for r in reports}

    def test_rotated_access_log_in_a_listing_confirms(self):
        report = self.dispatch("/logs")["listing_exposure_validator"]
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("access.log.2026-11-14 (access_log)", report.summary)
        self.assertIn("access_log (medium)", report.evidence)
        self.assertIn("user agents", report.evidence)
        # The rotation metadata JSON is not a log.
        self.assertNotIn("audit.json (", report.summary)
        self.assertNotIn("10.0.0.", report.evidence + report.summary)

    def test_log_carrying_a_session_id_is_high_and_redacted(self):
        report = self.dispatch("/debug")["listing_exposure_validator"]
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("log_with_secrets (high)", report.evidence)
        self.assertNotIn(_SECRET, report.evidence + report.summary)

    def test_benign_text_listing_is_a_negative(self):
        report = self.dispatch("/pub")["listing_exposure_validator"]
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("4 harmless file(s)", report.evidence)


class LogClassifierTests(unittest.TestCase):
    def kind(self, name, body):
        found = classify_listed_file(name, 200, {}, body)
        return (found.label, found.severity) if found else None

    def test_log_kinds(self):
        error = ("2026-11-14 12:00:00 ERROR request failed\nTypeError: x is undefined\n"
                 "    at Object.<anonymous> (/srv/app/server.js:10:5)\n"
                 "    at Layer.handle [as handle_request] (/srv/app/node_modules/r/layer.js:95:5)\n")
        self.assertEqual(self.kind("error.log.1", error), ("error_log", "medium"))
        py = ("Traceback (most recent call last):\n  File \"/srv/app/main.py\", line 3, in <module>\n"
              "  File \"/srv/app/db.py\", line 9, in connect\nValueError: bad\n")
        self.assertEqual(self.kind("crash.txt", py), ("error_log", "medium"))
        jsonl = ('{"level":30,"time":1,"req":{"method":"GET","url":"/a","remoteAddress":"::1"},'
                 '"res":{"statusCode":200}}\n'
                 '{"level":30,"time":2,"req":{"method":"POST","url":"/b"},"res":{"statusCode":201}}\n')
        self.assertEqual(self.kind("server.out", jsonl), ("access_log", "medium"))
        w3c = ("#Software: IIS\n#Fields: date time s-ip cs-method cs-uri-stem sc-status\n"
               "2026-11-14 10:00:00 10.0.0.1 GET /index.htm 200\n")
        self.assertEqual(self.kind("u_ex261114.log", w3c), ("access_log", "medium"))
        plain = "2026-11-14 12:00:00 INFO started\n2026-11-14 12:00:01 INFO ready\n"
        self.assertEqual(self.kind("app.log.2", plain), ("log_file", "medium"))
        # A plain ".log" keeps its existing rules.
        self.assertEqual(self.kind("app.log", plain)[0], "log_file")
        bearer = plain + "2026-11-14 12:00:02 DEBUG Authorization: Bearer " + "A" * 24 + "\n"
        self.assertEqual(self.kind("app.log.2", bearer), ("log_with_secrets", "high"))

    def test_non_logs_and_redacted_values_are_not_secrets(self):
        redacted = _access_lines(3, extra='10.0.0.9 - - [14/Nov/2026:18:09:00 +0000] '
                                          '"GET /x?token=[REDACTED] HTTP/1.1" 200 2').decode()
        self.assertEqual(self.kind("access.log.1", redacted), ("access_log", "medium"))
        self.assertIsNone(self.kind("audit.json", _ROTATION.decode()))
        self.assertIsNone(self.kind("audit.json", json.dumps(json.loads(_ROTATION))))
        for name, body in _LISTINGS["/pub"].items():
            with self.subTest(name=name):
                self.assertIsNone(self.kind(name, body.decode()))
        self.assertIsNone(self.kind("i18n.json", '{\n"LABEL_PASSWORD": "Repeat Password",\n'
                                                 '"time": "Time"\n}'))
        # One request line quoted in a document is not an access log.
        doc = ("# Log format\nEach line looks like:\n"
               + _access_lines(1).decode() + "Fields are space separated.\nSee RFC.\nEnd.\n")
        self.assertIsNone(self.kind("format.md", doc))


if __name__ == "__main__":
    unittest.main()
