"""BM-2: a secure endpoint of a class must not confirm; its vulnerable twin must.

Each pair runs through the production caller, ``Orchestrator._validate_findings``,
against an owned loopback server whose secure endpoint carries what makes a leg
without a differential fire:

  * command injection: a sanitiser strips shell metacharacters and echoes the
    rest, so ``& whoami & echo A^B`` comes back as ``whoami echo AB``;
  * path traversal: an unknown file name falls back to a default document that
    already quotes a passwd line;
  * SQL injection: a lookup that appends a rate-limit notice after its first
    answer, so two sequential probes differ whatever the predicate;
  * XSS: an escaping echo (regression only; the execution oracle was sound).

The twins are this test's own fixtures, not a corpus or a blind target. IDOR is
not covered: its single-principal leg never confirms (RV-D2 V2) and confirmation
belongs to cross_identity against ``authz.owners``.
"""
import asyncio
import html
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import httpx

from harness import cache, global_throttle, safety_gate, store
from harness.browser_driver import ExecutionObservation
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _config, _RecordingModel
from harness.validators.browser_xss_validator import BrowserXssValidator
from harness.validators.command_injection_validator import CommandInjectionValidator
from harness.validators.path_traversal_validator import PathTraversalValidator
from harness.validators.sqlmap import SqlmapValidator

_REPO = Path(__file__).resolve().parent.parent
_HOST = "127.0.0.1"

_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_GUIDE = ("<h1>Hardening guide</h1><p>A passwd entry looks like "
          "<code>root:x:0:0:root:/root:/bin/sh</code>; never expose the file.</p>")


def _shell(command: str) -> str:
    """A tiny POSIX/cmd emulation: run each segment between ; | & and return
    what printf/echo/whoami print. Nothing is executed on the host."""
    out = []
    for seg in re.split(r"[;|&\n]", command):
        words = seg.split()
        if not words:
            continue
        if words[0] == "whoami":
            out.append("www-data")
        elif words[0] == "printf" and len(words) >= 2:
            out.append(words[1].replace("%s", "".join(words[2:]), 1))
        elif words[0] == "echo":
            out.append(" ".join(words[1:]).replace("^", ""))
        elif words[0] == "ping":
            out.append(f"ping: unknown host {' '.join(words[2:])}")
    return "\n".join(out)


class _TwinServer:
    """Vulnerable and secure twins per class on one loopback server."""

    def __init__(self):
        self.lookups = 0
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.executescript(
            "CREATE TABLE items(owner TEXT, name TEXT);"
            "INSERT INTO items VALUES ('alice','lamp'),('bob','desk'),('carol','chair'),"
            "('dave','shelf'),('erin','rug'),('frank','sofa');")
        self.lock = threading.Lock()
        twins = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                parts = urlsplit(self.path)
                q = dict(parse_qsl(parts.query, keep_blank_values=True))
                route = getattr(twins, "route_" + parts.path.strip("/").replace("/", "_"), None)
                if route is None:
                    status, body = 404, "not found"
                else:
                    status, body = route(q)
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer((_HOST, 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path: str) -> str:
        return f"http://{_HOST}:{self.port}{path}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.db.close()

    # command injection
    def route_cmd_vuln(self, q):
        return 200, "<pre>" + _shell("ping -c1 " + q.get("host", "")) + "</pre>"

    def route_cmd_secure(self, q):
        cleaned = re.sub(r"[;|&^$`%<>\\\n]", "", q.get("host", ""))
        return 200, f"<pre>Queued host check for: {html.escape(cleaned)}</pre>"

    # path traversal
    def route_file_vuln(self, q):
        name = q.get("name", "")
        parts = []
        for seg in re.split(r"[\\/]+", name.replace("%2e", ".").replace("%2f", "/")):
            if seg == "..":
                if parts:
                    parts.pop()
            elif seg and seg != ".":
                parts.append(seg)
        resolved = "/".join(parts)
        if resolved == "etc/passwd":
            return 200, "<pre>" + _PASSWD + "</pre>"
        if resolved in ("report.txt", "var/www/docs/report.txt"):
            return 200, "<pre>Quarterly report</pre>"
        return 404, "no such file"

    def route_file_secure(self, q):
        name = os.path.basename(q.get("name", "").replace("\\", "/"))
        if name == "report.txt":
            return 200, "<pre>Quarterly report</pre>" + _GUIDE
        return 200, f"<p>Unknown document {html.escape(name)!s}; showing the default.</p>" + _GUIDE

    # SQL injection
    def _rows(self, sql, args=()):
        with self.lock:
            return [r[0] for r in self.db.execute(sql, args).fetchall()]

    def route_items_vuln(self, q):
        try:
            rows = self._rows(f"SELECT name FROM items WHERE owner='{q.get('owner', '')}'")
        except sqlite3.Error:
            rows = []
        return 200, "<ul>" + "".join(f"<li>{r}</li>" for r in rows) + "</ul>"

    def route_items_secure(self, q):
        rows = self._rows("SELECT name FROM items WHERE owner=?", (q.get("owner", ""),))
        with self.lock:
            self.lookups += 1
            first = self.lookups == 1
        notice = "" if first else (
            "<div class='notice'>You are making lookups quickly. Further lookups from this "
            "address are slowed down; complete the challenge to continue at full speed.</div>")
        return 200, "<ul>" + "".join(f"<li>{r}</li>" for r in rows) + "</ul>" + notice

    # XSS
    def route_search_vuln(self, q):
        return 200, f"<p>Results for {q.get('q', '')}</p>"

    def route_search_secure(self, q):
        return 200, f"<p>Results for {html.escape(q.get('q', ''))}</p>"


class _ExecutingDriver:
    """Fetches the page and evaluates the probe's `alert(a*b)` where a browser
    would run it: inside a <script> element or an on* handler of real markup.
    Escaped text never parses as markup, so it never runs."""
    _CALL = re.compile(r"alert\((\d+)\*(\d+)\)")

    async def visit(self, url, wait_ms=0, headers=None, **_):
        async with httpx.AsyncClient(timeout=5.0) as client:
            body = (await client.get(url)).text
        sinks = re.findall(r"<script>(.*?)</script>", body, re.S)
        sinks += re.findall(r"<\w+[^>]*\son\w+=([^>]*)>", body)
        products = [str(int(a) * int(b)) for js in sinks for a, b in self._CALL.findall(js)]
        return ExecutionObservation(url=url, dialogs=[f"alert:{p}" for p in products],
                                    console=list(products))


def _finding(cls: str) -> Finding:
    return Finding(vulnerability_class=cls, confidence=0.6, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived")


class SecureTwinCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _TwinServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def setUp(self):
        work = _REPO / ".test-work"
        work.mkdir(exist_ok=True)
        self._tmp = tempfile.mkdtemp(prefix="bm2_", dir=work)
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        st = global_throttle.throttle.stats()
        prev = (st["rate_per_second"] if st["enabled"] else 0.0, st["burst"] if st["enabled"] else None)
        self.addCleanup(lambda: global_throttle.configure(*prev))
        self.server.lookups = 0

    def tearDown(self):
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _confirmed(self, key, validator, cls, path) -> tuple[bool, list]:
        cfg = _config()
        cfg["server"]["allowed_hosts"] = [_HOST]
        cfg["validators"].update(active_enabled=True)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        global_throttle.configure(0)
        orch.validator_registry.validators = {key: validator}
        url = self.server.url(path)
        with httpx.Client() as client:
            resp = client.get(url)
        exchange = HttpExchange(url=url, method="GET", request_headers={},
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers), response_body=resp.text)
        self.server.lookups = 0
        finding = _finding(cls)
        reports, _proofs = asyncio.run(orch._validate_findings(
            exchange, [AgentReport(agent=key, model="fake", findings=[finding])]))
        self.assertTrue(reports, "the validator was not dispatched")
        return finding.confirmed, [(r.status, r.summary) for r in reports]

    def _pair(self, key, make, cls, vuln_path, secure_path):
        confirmed, verdicts = self._confirmed(key, make(), cls, vuln_path)
        self.assertTrue(confirmed, f"vulnerable twin lost: {verdicts}")
        confirmed, verdicts = self._confirmed(key, make(), cls, secure_path)
        self.assertFalse(confirmed, f"secure twin confirmed: {verdicts}")

    def test_command_injection_secure_sanitiser_does_not_confirm(self):
        self._pair("command_injection",
                   lambda: CommandInjectionValidator(allowed_hosts=[_HOST],
                                                     oob_callbacks_enabled=False),
                   "command_injection", "/cmd/vuln?host=example.org",
                   "/cmd/secure?host=example.org")

    def test_path_traversal_secure_default_document_does_not_confirm(self):
        self._pair("path_traversal",
                   lambda: PathTraversalValidator(allowed_hosts=[_HOST]),
                   "path_traversal", "/file/vuln?name=report.txt",
                   "/file/secure?name=report.txt")

    def test_sqli_secure_stateful_lookup_does_not_confirm(self):
        self._pair("sqlmap",
                   lambda: SqlmapValidator(allowed_hosts=[_HOST], quick_only=True),
                   "sqli", "/items/vuln?owner=alice", "/items/secure?owner=alice")

    def test_xss_secure_escaping_echo_does_not_confirm(self):
        self._pair("browser_xss",
                   lambda: BrowserXssValidator(allowed_hosts=[_HOST], driver=_ExecutingDriver()),
                   "xss", "/search/vuln?q=lamp", "/search/secure?q=lamp")


if __name__ == "__main__":
    unittest.main()
