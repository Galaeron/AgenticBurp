"""Code review 02, batch RV-E (I10): false confirmations in the API-security
(mass assignment), stored-XSS and auth-sequence (session fixation) validators,
and the post-confirmation relabel in attribution.py (R18, R19, R20, R33).

Each test drives the production caller -- ``Orchestrator._validate_findings`` or
``Orchestrator.analyze`` -- the way the reviewer's ``boundary_checks.py`` and
``attribution_checks.py`` did, with the reviewer's control as the negative
control. Genuine positives run against owned loopback servers; the stored-XSS
execution controls use a real headless Chromium when Playwright is installed.

Batch RV-E2 adds the residual cases E1, E2 and E3 that the independent
verification (reviews/2026-10-20-rvei-implementation-verification/REPORT.md)
found after RV-E: a pre-existing probe field, a logged payload source and an
anonymous HTTP 500 or timeout. Each has a positive control that must still
confirm.
"""
import asyncio
import json
import os
import re
import secrets
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qsl

import httpx

from harness import browser_driver, cache, global_throttle, safety_gate, store
from harness.browser_driver import ExecutionObservation
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _config, _exchange, _RecordingModel
from harness.testing_fixtures.mass_assignment import MassAssignmentFixture
from harness.validators import stored_xss_validator
from harness.validators.api_security_validator import ApiSecurityValidator
from harness.validators.auth_sequence_validator import AuthSequenceValidator
from harness.validators.base import ValidationResult, Validator
from harness.validators.stored_xss_validator import StoredXssValidator


def _finding(cls: str, **extra) -> Finding:
    return Finding(vulnerability_class=cls, confidence=0.5, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived", **extra)


def _verdicts(reports):
    return [(v.status, v.summary) for v in reports]


class _CallerBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="rve_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        st = global_throttle.throttle.stats()
        prev = (st["rate_per_second"] if st["enabled"] else 0.0, st["burst"] if st["enabled"] else None)
        self.addCleanup(lambda: global_throttle.configure(*prev))

    def tearDown(self):
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _orch(self, hosts=("shop.invalid",)):
        cfg = _config()
        cfg["server"]["allowed_hosts"] = list(hosts)
        cfg["validators"].update(active_enabled=True, allow_mutating_replay=True)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        global_throttle.configure(0)
        return orch

    def _validate(self, key, validator, finding, exchange, fake_request=None,
                  hosts=("shop.invalid",)):
        """One validator through Orchestrator._validate_findings. Without a
        fake_request the validator talks to a real (owned loopback) server."""
        orch = self._orch(hosts=hosts)
        orch.validator_registry.validators = {key: validator}
        run = lambda: asyncio.run(orch._validate_findings(  # noqa: E731
            exchange, [AgentReport(agent=key, model="fake", findings=[finding])]))
        if fake_request is None:
            reports, _proofs = run()
        else:
            with patch.object(httpx.AsyncClient, "request", fake_request):
                reports, _proofs = run()
        self.assertTrue(reports, "the validator was not dispatched")
        return reports


def _json_exchange(url, method, body):
    ex = _exchange(url, {"Content-Type": "application/json"})
    ex.method = method
    ex.request_body = body
    return ex


# ------------------------------------------------------- R18 mass assignment
class MassAssignmentCallerTests(_CallerBase):
    """R18: an echo of the probe field is not mass assignment. Confirmation
    needs an accepted write and an independent read-back of persisted state."""

    def _run(self, exchange, fake_request=None, hosts=("shop.invalid",)):
        return self._validate("api_security", ApiSecurityValidator(), _finding("mass_assignment"),
                              exchange, fake_request, hosts)

    def test_rejected_echo_is_not_confirmed_mass_assignment(self):
        # The reviewer's repro: HTTP 400 JSON that names the field to reject it.
        sent = []

        async def fake_request(client, method, url, **kwargs):
            sent.append(method)
            return httpx.Response(400, json={"harnessProbeIsAdmin": "Unknown field. Request rejected."},
                                  request=httpx.Request(method, url))
        reports = self._run(_json_exchange("http://shop.invalid/profile", "POST", '{"name":"Alice"}'),
                            fake_request)
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn("candidate", reports[0].summary.lower())
        # E1: the baseline GET precedes the write; nothing re-reads a rejected one.
        self.assertEqual(sent, ["GET", "POST"], "a rejected write must not be followed by a read-back")

    def test_accepted_echo_without_persisted_state_is_only_a_candidate(self):
        # 2xx echo, but an independent GET of the resource shows the field was
        # never stored (a validation/preview endpoint that echoes its input).
        sent = []

        async def fake_request(client, method, url, **kwargs):
            sent.append(method)
            if method == "POST":
                body = json.loads(kwargs["content"])
                return httpx.Response(200, json=body, request=httpx.Request(method, url))
            return httpx.Response(200, json={"name": "Alice", "role": "user"},
                                  request=httpx.Request(method, url))
        reports = self._run(_json_exchange("http://shop.invalid/profile", "POST", '{"name":"Alice"}'),
                            fake_request)
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))
        self.assertEqual(sent, ["GET", "POST", "GET"])  # baseline, write, read-back (E1)

    def test_silently_persisted_field_confirms_via_read_back(self):
        # No echo at all (204), but the independent read-back shows the
        # privileged field stored: that is the persisted-state proof.
        state = {"name": "Alice"}

        async def fake_request(client, method, url, **kwargs):
            if method == "POST":
                state.update(json.loads(kwargs["content"]))
                return httpx.Response(204, request=httpx.Request(method, url))
            return httpx.Response(200, json=dict(state), request=httpx.Request(method, url))
        reports = self._run(_json_exchange("http://shop.invalid/profile", "POST", '{"name":"Alice"}'),
                            fake_request)
        self.assertEqual([v.status for v in reports], ["confirmed"], _verdicts(reports))
        self.assertIn("read-back", reports[0].evidence.lower())

    def test_server_that_persists_privileged_field_confirms(self):
        # Genuine positive on an owned loopback API that merges every body key.
        fx = MassAssignmentFixture("vulnerable")
        self.addCleanup(fx.close)
        reports = self._run(_json_exchange(fx.user_url("1"), "PATCH", '{"username": "alice"}'),
                            hosts=("127.0.0.1",))
        self.assertEqual([v.status for v in reports], ["confirmed"], _verdicts(reports))
        self.assertIs(fx.users["1"].get("harnessProbeIsAdmin"), True)
        self.assertEqual([r["method"] for r in fx.requests_for("/users/1")], ["GET", "PATCH", "GET"],
                         "confirmation must rest on a baseline and an independent GET read-back")

    def test_server_with_field_allowlist_is_negative_control(self):
        fx = MassAssignmentFixture("patched")
        self.addCleanup(fx.close)
        reports = self._run(_json_exchange(fx.user_url("1"), "PATCH", '{"username": "alice"}'),
                            hosts=("127.0.0.1",))
        self.assertEqual([v.status for v in reports], ["not_confirmed"], _verdicts(reports))
        self.assertNotIn("harnessProbeIsAdmin", fx.users["1"])


# ---------------------------------------------------------------- R19 stored XSS
class _QuietDriver:
    """A browser that loaded the page and saw no script run (the reviewer's)."""

    def __init__(self):
        self.visits = []

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        return ExecutionObservation(url=url)


class _NoisyDriver(_QuietDriver):
    """A page that logs to the console, but not the payload's nonce."""

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        return ExecutionObservation(url=url, console=["analytics loaded"], page_errors=["x is undefined"])


def _note_server(state, render):
    async def fake_request(client, method, url, **kwargs):
        if method == "POST":
            state.update(json.loads(kwargs["content"]))
        return httpx.Response(200, text=render(state["note"]), headers={"Content-Type": "text/html"},
                              request=httpx.Request(method, url))
    return fake_request


class StoredXssCallerTests(_CallerBase):
    """R19: an unescaped string in HTML is a candidate. Only the payload's own
    nonce, observed executing in a browser, confirms stored XSS."""

    def _run(self, driver, render, url="http://shop.invalid/note"):
        state = {"note": "original"}
        v = StoredXssValidator(allowed_hosts=["shop.invalid"], driver=driver)
        return self._validate("stored_xss", v, _finding("xss"),
                              _json_exchange(url, "POST", '{"note":"original"}'),
                              _note_server(state, render))

    def test_inert_textarea_storage_is_not_confirmed_xss(self):
        # The reviewer's repro: stored inside an inert <textarea>, browser quiet.
        driver = _QuietDriver()
        reports = self._run(driver, lambda note: "<textarea>" + note + "</textarea>")
        self.assertFalse(any(v.confirmed for v in reports), [(v.status, v.evidence) for v in reports])
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn("candidate", reports[0].summary.lower())
        self.assertTrue(driver.visits, "the execution proof was never attempted")

    def test_console_noise_without_the_nonce_is_not_execution(self):
        reports = self._run(_NoisyDriver(), lambda note: "<div>" + note + "</div>")
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))

    def test_raw_render_without_a_browser_is_only_a_candidate(self):
        with patch.object(browser_driver, "default_driver", lambda *a, **k: None):
            reports = self._run(None, lambda note: "<div>" + note + "</div>")
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn("no browser", reports[0].evidence.lower())

    def test_escaped_render_negative_control(self):
        import html
        reports = self._run(_QuietDriver(), lambda note: "<div>" + html.escape(note) + "</div>")
        self.assertEqual([v.status for v in reports], ["not_confirmed"], _verdicts(reports))

    def test_driver_observing_the_nonce_confirms(self):
        # Boundary double for the browser: it logs what the planted payload's
        # console.log computes (the product, E2), as an executing browser does.
        class _ExecutingDriver(_QuietDriver):
            def __init__(self, state):
                super().__init__()
                self.state = state

            async def visit(self, url, **kwargs):
                import re
                self.visits.append(url)
                m = re.search(r"console\.log\((\d+)\*(\d+)\)", self.state["note"])
                return ExecutionObservation(url=url, console=[str(int(m[1]) * int(m[2]))] if m else [])
        state = {"note": "original"}
        v = StoredXssValidator(allowed_hosts=["shop.invalid"], driver=_ExecutingDriver(state))
        reports = self._validate("stored_xss", v, _finding("xss"),
                                 _json_exchange("http://shop.invalid/note", "POST", '{"note":"original"}'),
                                 _note_server(state, lambda note: "<div>" + note + "</div>"))
        self.assertEqual([v.status for v in reports], ["confirmed"], _verdicts(reports))


class _NoteApp:
    """Owned loopback app: POST /notes stores {"note": ...}; GET /notes renders
    it as HTML, raw in a <div> ("raw") or inside an inert <textarea>."""

    def __init__(self, mode: str):
        state = self.state = {"note": "original"}

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, body, ctype):
                data = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                state["note"] = str(json.loads(self.rfile.read(n) or b"{}").get("note", ""))
                self._send(201, '{"ok": true}', "application/json")

            def do_GET(self):
                if self.path.split("?")[0] != "/notes":
                    return self._send(404, "not found", "text/plain")
                inner = (f"<div>{state['note']}</div>" if mode == "raw"
                         else f"<textarea>{state['note']}</textarea>")
                self._send(200, f"<html><body><h1>Notes</h1>{inner}</body></html>", "text/html")

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/notes"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


@unittest.skipUnless(browser_driver.playwright_available(), "playwright not installed")
class StoredXssRealBrowserTests(_CallerBase):
    """R19 controls with a real headless Chromium against an owned loopback app."""

    def _run(self, mode):
        app = _NoteApp(mode)
        self.addCleanup(app.close)
        v = StoredXssValidator(allowed_hosts=["127.0.0.1"])
        return self._validate("stored_xss", v, _finding("xss"),
                              _json_exchange(app.url, "POST", '{"note":"original"}'),
                              hosts=("127.0.0.1",))

    def test_payload_that_executes_in_a_browser_confirms(self):
        reports = self._run("raw")
        self.assertEqual([v.status for v in reports], ["confirmed"], _verdicts(reports))
        self.assertIn("executed", reports[0].evidence.lower())

    def test_payload_inert_in_a_textarea_stays_a_candidate(self):
        reports = self._run("textarea")
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))


# --------------------------------------------------------- R20 session fixation
class SessionFixationCallerTests(_CallerBase):
    """R20: an unrotated pre-login cookie is not fixation by itself. The login
    must succeed and the fixed identifier must then be used authenticated."""

    def _login_exchange(self, url="http://shop.invalid/login", body="username=alice&password=incorrect"):
        ex = _exchange(url, {"Content-Type": "application/x-www-form-urlencoded"})
        ex.method = "POST"
        ex.request_body = body
        return ex

    def _run(self, exchange, fake_request=None, hosts=("shop.invalid",)):
        return self._validate("auth_sequence", AuthSequenceValidator(allowed_hosts=list(hosts)),
                              _finding("session_fixation"), exchange, fake_request, hosts)

    def _reviewer(self, rotated):
        sent = []

        async def fake_request(client, method, url, **kwargs):
            sent.append(method)
            if method == "GET":
                return httpx.Response(200, headers={"Set-Cookie": "session=anonymous; Path=/"},
                                      text="Welcome", request=httpx.Request(method, url))
            return httpx.Response(200 if rotated else 401,
                                  headers={"Set-Cookie": "session=authenticated-new; Path=/"} if rotated else {},
                                  text="Logged in" if rotated else "Invalid credentials. Authentication failed.",
                                  request=httpx.Request(method, url))
        return self._run(self._login_exchange(), fake_request), sent

    def test_failed_login_does_not_confirm_session_fixation(self):
        reports, sent = self._reviewer(rotated=False)
        self.assertEqual(sent, ["GET", "POST"])
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn("candidate", reports[0].summary.lower())

    def test_rotated_session_control(self):
        reports, sent = self._reviewer(rotated=True)
        self.assertEqual(sent, ["GET", "POST"])
        self.assertEqual([v.status for v in reports], ["not_confirmed"], _verdicts(reports))

    def test_owned_app_that_binds_the_fixed_id_confirms(self):
        app = _LoginApp("fixate")
        self.addCleanup(app.close)
        reports = self._run(self._login_exchange(app.url("/login"), app.good_body), hosts=("127.0.0.1",))
        self.assertEqual([v.status for v in reports], ["confirmed"], _verdicts(reports))
        self.assertIn("/my-account", reports[0].evidence)

    def test_owned_app_that_rotates_is_negative_control(self):
        app = _LoginApp("rotate")
        self.addCleanup(app.close)
        reports = self._run(self._login_exchange(app.url("/login"), app.good_body), hosts=("127.0.0.1",))
        self.assertEqual([v.status for v in reports], ["not_confirmed"], _verdicts(reports))

    def test_owned_app_failed_login_is_only_a_candidate(self):
        app = _LoginApp("fixate")
        self.addCleanup(app.close)
        reports = self._run(self._login_exchange(app.url("/login"), "username=alice&password=wrong"),
                            hosts=("127.0.0.1",))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))

    def test_unrotated_id_that_never_authenticates_is_only_a_candidate(self):
        # Login succeeds and re-issues the pre-login sid unchanged, but the
        # authenticated session lives in a separate cookie: sid alone is anonymous.
        app = _LoginApp("separate")
        self.addCleanup(app.close)
        reports = self._run(self._login_exchange(app.url("/login"), app.good_body), hosts=("127.0.0.1",))
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))


class _LoginApp:
    """Owned loopback login app. GET / issues a pre-login ``sid``. POST /login
    with alice's password logs in and redirects to /my-account, which shows the
    account only to an authenticated session.

    - "fixate": binds the presented sid to alice and re-issues it (vulnerable).
    - "rotate": issues a fresh sid bound to alice (safe).
    - "separate": re-issues the presented sid unchanged but authenticates a new
      ``auth`` cookie instead, so the fixed sid alone stays anonymous.
    """

    PASSWORD = "correct-horse"

    def __init__(self, mode: str):
        sessions = self.sessions = {}
        self.good_body = f"username=alice&password={self.PASSWORD}"

        class Handler(BaseHTTPRequestHandler):
            def _cookies(self):
                out = {}
                for part in (self.headers.get("Cookie") or "").split(";"):
                    if "=" in part:
                        k, _, v = part.strip().partition("=")
                        out[k] = v
                return out

            def _send(self, status, body="", headers=None):
                data = body.encode("utf-8")
                self.send_response(status)
                for k, v in (headers or []):
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                c = self._cookies()
                path = self.path.split("?")[0]
                if path == "/":
                    sid = c.get("sid") or secrets.token_hex(8)
                    return self._send(200, "<html>Welcome</html>", [("Set-Cookie", f"sid={sid}; Path=/")])
                if path == "/my-account":
                    user = sessions.get(c.get("auth") if mode == "separate" else c.get("sid"))
                    if user:
                        return self._send(200, f"<html><h1>My account</h1><p>Signed in as {user}</p>"
                                               f"<a href='/logout'>Log out</a></html>")
                    return self._send(302, "", [("Location", "/login")])
                self._send(404, "not found")

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                fields = dict(parse_qsl(self.rfile.read(n).decode("utf-8")))
                if fields.get("username") != "alice" or fields.get("password") != _LoginApp.PASSWORD:
                    return self._send(401, "Invalid credentials")
                presented = self._cookies().get("sid", "")
                hdrs = [("Location", "/my-account")]
                if mode == "fixate" and presented:
                    sessions[presented] = "alice"
                    hdrs.append(("Set-Cookie", f"sid={presented}; Path=/"))
                elif mode == "separate":
                    token = secrets.token_hex(8)
                    sessions[token] = "alice"
                    hdrs += [("Set-Cookie", f"sid={presented}; Path=/"),
                             ("Set-Cookie", f"auth={token}; Path=/")]
                else:
                    fresh = secrets.token_hex(8)
                    sessions[fresh] = "alice"
                    hdrs.append(("Set-Cookie", f"sid={fresh}; Path=/"))
                self._send(302, "", hdrs)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def url(self, path):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}{path}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


# ------------------------------------------------- R33 post-confirmation relabel
class _ExecutedSqlmapLeg(Validator):
    """Stand-in for the sqlmap leg having run and proved injection."""
    name = "sqlmap"
    finding_classes = {"sqli"}

    async def validate(self, finding, exchange):
        return ValidationResult("sqlmap", "confirmed", "sqli", confidence=0.95, confirmed=True,
                                summary="sqlmap confirmed injection in id (fixture)",
                                evidence="Parameter: id (GET) is injectable (fixture)")


class RelabelCallerTests(_CallerBase):
    """R33: the class a confirmation proved comes from the leg that executed
    (confirmed_by_leg), never from an unexecuted validation hint."""

    def _relabelled(self, confirmed=True, hints=None):
        from harness.attribution import relabel_confirmed_findings
        f = Finding(vulnerability_class="sqli", severity="high", confidence=0.95,
                    summary="Synthetic confirmed SQL injection", evidence="Original model evidence",
                    suggested_test="Synthetic test", basis="derived", confirmed=confirmed,
                    confirmed_by_leg="sqlmap", validation_hints=hints or [])
        relabel_confirmed_findings([f])
        return f

    # The reviewer's three checks, unchanged.
    def test_structured_confirmation_beats_unexecuted_hint(self):
        self.assertEqual(self._relabelled(hints=["ssrf:url"]).vulnerability_class, "sqli")

    def test_matching_hint_control(self):
        self.assertEqual(self._relabelled(hints=["sqlmap:id"]).vulnerability_class, "sqli")

    def test_unconfirmed_control(self):
        self.assertEqual(self._relabelled(confirmed=False, hints=["ssrf:url"]).vulnerability_class, "sqli")

    def test_hint_alone_never_relabels_a_confirmed_finding(self):
        # Legacy shape with no leg named anywhere but the model's hint: the
        # hint was never executed, so it proves nothing about the class.
        from harness.attribution import relabel_confirmed_finding
        f = {"vulnerability_class": "sqli", "confirmed": True, "evidence": "model evidence",
             "validation_hints": ["ssrf:url"]}
        self.assertFalse(relabel_confirmed_finding(f))
        self.assertEqual(f["vulnerability_class"], "sqli")

    def test_executed_leg_still_relabels_a_variant_label(self):
        # Positive control: the structured stamp of the leg that ran is authoritative.
        from harness.attribution import relabel_confirmed_finding
        f = {"vulnerability_class": "blind_sql_injection_variant", "confirmed": True,
             "confirmed_by_leg": "sqlmap", "validation_hints": ["ssrf:url"]}
        self.assertTrue(relabel_confirmed_finding(f))
        self.assertEqual(f["vulnerability_class"], "sqli")

    def _analyze(self, hints):
        from harness.models import StageOutcome
        orch = self._orch()
        orch.validator_registry.validators = {"sqlmap": _ExecutedSqlmapLeg()}
        f = Finding(vulnerability_class="sqli", severity="high", confidence=0.6,
                    summary="SQL injection candidate in id", evidence="Original model evidence",
                    suggested_test="sqlmap the id parameter", basis="derived",
                    validation_hints=hints)

        async def pipeline(*args, **kwargs):
            return ([AgentReport(agent="sqli", model="fake", findings=[f])], 0, 0,
                    StageOutcome(name="critique", status="skipped", reason="fixture"))

        async def no_network(client, method, url, **kwargs):
            raise AssertionError(f"unexpected network: {method} {url}")
        ex = HttpExchange(url="http://shop.invalid/products?id=1", method="GET", request_headers={},
                          response_status=200, response_headers={"Content-Type": "application/json"},
                          response_body='{"id": 1}')
        with patch("harness.analysis_pipeline.AnalysisPipeline.run_full_analysis", pipeline), \
                patch.object(httpx.AsyncClient, "request", no_network):
            result = asyncio.run(orch.analyze(ex, force_agents=["sqli"], bypass_cache=True))
        findings = [x for r in result.agent_reports for x in r.findings]
        return findings, result

    def test_analyze_keeps_the_executed_legs_class(self):
        findings, result = self._analyze(["ssrf:url"])
        self.assertTrue(any(v.confirmed for v in result.validation_reports),
                        _verdicts(result.validation_reports))
        # The agent's finding and the run's shape_precondition copy of it.
        confirmed = [x for x in findings if x.confirmed]
        self.assertTrue(confirmed, [(x.vulnerability_class, x.confirmed) for x in findings])
        self.assertEqual({x.confirmed_by_leg for x in confirmed}, {"sqlmap"})
        self.assertEqual({x.vulnerability_class for x in confirmed}, {"sqli"},
                         [(x.vulnerability_class, x.original_vulnerability_class) for x in confirmed])

    def test_analyze_matching_hint_control(self):
        findings, _result = self._analyze(["sqlmap:id"])
        confirmed = [x for x in findings if x.confirmed]
        self.assertTrue(confirmed)
        self.assertEqual({x.vulnerability_class for x in confirmed}, {"sqli"})


# ====================================================== RV-E2 residual cases
# Reviewer checks from adversarial_checks.py (E1, E2, E3) and their controls.


def _evidence(reports):
    return [(r.status, r.evidence) for r in reports]


# ------------------------------------------------------ E1 mass assignment
class MassAssignmentBaselineTests(_CallerBase):
    """E1: confirmation needs a controlled change on the written object -- the
    probe field absent or different in a baseline read before the write, and
    the submitted value in an independent read-back after an accepted write."""

    def _run(self, exchange, fake_request=None, hosts=("shop.invalid",)):
        return self._validate("api_security", ApiSecurityValidator(), _finding("mass_assignment"),
                              exchange, fake_request, hosts)

    def _profile(self):
        return _json_exchange("http://shop.invalid/profile", "POST", '{"name":"Alice"}')

    def test_existing_probe_field_is_not_a_proven_write(self):
        # The reviewer's repro: the write ignores every field; GET shows the
        # probe field already true from before.
        sent = []

        async def request(client, method, url, **kwargs):
            sent.append(method)
            body = {} if method == "POST" else {"name": "Alice", "harnessProbeIsAdmin": True}
            return httpx.Response(200, json=body, request=httpx.Request(method, url))
        reports = self._run(self._profile(), request)
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        self.assertEqual(sent[0], "GET", "the baseline must be read before the write")

    def test_previously_probed_object_confirms_by_writing_a_different_value(self):
        # Positive control: a vulnerable object that an earlier probe left at
        # true. The probe submits false, and the read-back shows the change.
        state = {"name": "Alice", "harnessProbeIsAdmin": True}
        written = []

        async def request(client, method, url, **kwargs):
            if method == "POST":
                body = json.loads(kwargs["content"])
                written.append(body.get("harnessProbeIsAdmin"))
                state.update(body)
            return httpx.Response(200, json=dict(state), request=httpx.Request(method, url))
        reports = self._run(self._profile(), request)
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))
        self.assertEqual(written, [False], "the submitted value must differ from the baseline")

    def test_unreadable_baseline_leaves_a_stored_field_a_candidate(self):
        # The field is stored, but the baseline GET failed, so "absent before"
        # was never shown.
        state, gets = {"name": "Alice"}, []

        async def request(client, method, url, **kwargs):
            if method == "POST":
                state.update(json.loads(kwargs["content"]))
                return httpx.Response(200, json={}, request=httpx.Request(method, url))
            gets.append(url)
            if len(gets) == 1:
                return httpx.Response(503, text="busy", request=httpx.Request(method, url))
            return httpx.Response(200, json=dict(state), request=httpx.Request(method, url))
        reports = self._run(self._profile(), request)
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn("baseline", reports[0].summary.lower())

    def test_new_object_without_a_baseline_is_a_candidate(self):
        # A create that points at a new object: its state before the write
        # cannot be read, so the field there is a candidate, not a change shown.
        async def request(client, method, url, **kwargs):
            req = httpx.Request(method, url)
            if method == "POST":
                return httpx.Response(201, headers={"Location": "/profile/9"}, request=req)
            if str(url).endswith("/profile/9"):
                return httpx.Response(200, json={"id": 9, "harnessProbeIsAdmin": True}, request=req)
            return httpx.Response(200, json={"items": []}, request=req)
        reports = self._run(self._profile(), request)
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))

    def test_confirmation_claims_field_binding_not_a_protected_property(self):
        # Positive control on the owned vulnerable API, and the wording: the
        # harness-invented field is arbitrary metadata, not a protected property.
        fx = MassAssignmentFixture("vulnerable")
        self.addCleanup(fx.close)
        reports = self._run(_json_exchange(fx.user_url("1"), "PATCH", '{"username": "alice"}'),
                            hosts=("127.0.0.1",))
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))
        text = (reports[0].summary + " " + reports[0].evidence).lower()
        self.assertNotIn("would be stored too", text)
        self.assertIn("protected property", text)
        self.assertIn("absent", text)
        self.assertEqual([r["method"] for r in fx.requests_for("/users/1")], ["GET", "PATCH", "GET"])


# ------------------------------------------------------------ E2 stored XSS
def _evaluate_logged(source: str) -> list[str]:
    """What a browser logs when the payload's console.log runs: the computed
    value, never the source text."""
    return [str(int(a) * int(b)) for a, b in re.findall(r"console\.log\((\d+)\*(\d+)\)", source)]


class _EchoingDriver:
    """A browser whose page logs the stored text itself (debugging that prints
    a field's value): the payload's source reaches the console, unexecuted."""

    def __init__(self, state):
        self.state, self.visits = state, []

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        return ExecutionObservation(url=url, console=[self.state["note"]],
                                    dialogs=[self.state["note"]], page_errors=[self.state["note"]])


class _ComputingDriver(_EchoingDriver):
    """A browser that runs the payload: it logs the computed value only."""

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        return ExecutionObservation(url=url, console=_evaluate_logged(self.state["note"]))


class StoredXssExactEventTests(_CallerBase):
    """E2: only an exact console event carrying a value the payload computes at
    run time confirms. The stored source holds the operands, not the result,
    so echoing the source never matches."""

    def _run(self, driver_cls, render):
        state = {"note": "original"}
        v = StoredXssValidator(allowed_hosts=["shop.invalid"], driver=driver_cls(state))
        return self._validate("stored_xss", v, _finding("xss"),
                              _json_exchange("http://shop.invalid/note", "POST", '{"note":"original"}'),
                              _note_server(state, render))

    def test_logged_payload_source_is_not_execution(self):
        reports = self._run(_EchoingDriver, lambda note: "<textarea>" + note + "</textarea>")
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))

    def test_computed_value_from_execution_confirms(self):
        reports = self._run(_ComputingDriver, lambda note: "<div>" + note + "</div>")
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))
        self.assertIn("executed", reports[0].evidence.lower())

    def test_expected_value_never_appears_in_the_stored_text(self):
        for _ in range(50):
            a, b, expected = stored_xss_validator._challenge()
            self.assertEqual(expected, str(a * b))
            for payload in stored_xss_validator._payloads(a, b):
                self.assertNotIn(expected, payload)
                self.assertEqual(_evaluate_logged(payload), [expected])


@unittest.skipUnless(browser_driver.playwright_available(), "playwright not installed")
class StoredXssSourceEchoRealBrowserTests(_CallerBase):
    """E2 with a real headless Chromium against the owned loopback note app."""

    def _run(self, mode, echo_script):
        app = _NoteApp(mode)
        self.addCleanup(app.close)
        handler = app.httpd.RequestHandlerClass
        original = handler._send

        def send(instance, status, body, ctype):
            if "html" in ctype:
                body += echo_script
            return original(instance, status, body, ctype)
        handler._send = send
        return self._validate("stored_xss", StoredXssValidator(allowed_hosts=["127.0.0.1"]),
                              _finding("xss"), _json_exchange(app.url, "POST", '{"note":"original"}'),
                              hosts=("127.0.0.1",))

    def test_logging_inert_payload_source_is_not_payload_execution(self):
        # The reviewer's repro: benign debugging logs the textarea, never runs it.
        reports = self._run("textarea",
                            "<script>console.log(document.querySelector('textarea').value)</script>")
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))

    def test_executing_payload_confirms_beside_unrelated_logging(self):
        reports = self._run("raw", "<script>console.log(document.title || 'notes page')</script>")
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))


# ------------------------------------------------------ E3 session fixation
class SessionFixationAnonymousControlTests(_CallerBase):
    """E3: the anonymous comparison counts only as a completed, healthy,
    interpretable denial (401/403, a redirect to a login page, a login page).
    A 5xx, a timeout or any other answer leaves fixation inconclusive."""

    def _run(self, anonymous):
        async def request(client, method, url, **kwargs):
            req = httpx.Request(method, url)
            if str(url).endswith("/"):
                return httpx.Response(200, text="Welcome", headers={"Set-Cookie": "sid=fixed; Path=/"},
                                      request=req)
            if method == "POST":
                return httpx.Response(302, headers={"Location": "/account"}, request=req)
            hdrs = {k.lower(): v for k, v in (kwargs.get("headers") or {}).items()}
            if "cookie" in hdrs:
                return httpx.Response(
                    200, text="<html>Account for alice, information and preferences. Log out</html>",
                    request=req)
            return anonymous(req)
        ex = _exchange("http://shop.invalid/login", {"Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "username=alice&password=correct"
        return self._validate("auth_sequence", AuthSequenceValidator(allowed_hosts=["shop.invalid"]),
                              _finding("session_fixation"), ex, request)

    def _assert_inconclusive(self, reports):
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        self.assertNotIn("was denied", reports[0].evidence)

    def test_anonymous_500_does_not_prove_session_denial(self):
        reports = self._run(lambda req: httpx.Response(500, text="temporary upstream failure", request=req))
        self._assert_inconclusive(reports)
        self.assertIn("500", reports[0].evidence)

    def test_anonymous_timeout_does_not_prove_session_denial(self):
        def timeout(req):
            raise httpx.ReadTimeout("synthetic unavailable anonymous control", request=req)
        reports = self._run(timeout)
        self._assert_inconclusive(reports)
        self.assertIn("ReadTimeout", reports[0].evidence)

    def test_anonymous_404_is_not_an_authorization_denial(self):
        reports = self._run(lambda req: httpx.Response(404, text="not found", request=req))
        self._assert_inconclusive(reports)

    def test_anonymous_401_confirms(self):
        reports = self._run(lambda req: httpx.Response(401, text="login required", request=req))
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))
        self.assertIn("HTTP 401", reports[0].evidence)

    def test_anonymous_redirect_to_login_confirms(self):
        reports = self._run(lambda req: httpx.Response(302, headers={"Location": "/login?next=/account"},
                                                       request=req))
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))

    def test_anonymous_login_page_confirms(self):
        page = ("<html><title>Sign in</title><form action='/login'>"
                "<input type='password' name='password'></form></html>")
        reports = self._run(lambda req: httpx.Response(200, text=page, request=req))
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))


if __name__ == "__main__":
    unittest.main()
