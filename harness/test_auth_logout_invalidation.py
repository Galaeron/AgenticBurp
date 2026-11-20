"""WG-3: auth_sequence's logout-invalidation leg (session_timeout, WSTG-SESS-06).

Every test drives the production caller, ``Orchestrator._validate_findings``,
against an owned loopback app that records each request it receives, so the
SafetyGate, the run transport and the registry dispatch all decide as in a run.

  (i)   confirm: logout only clears the cookie client-side, the old cookie still
        reaches the account page -> confirmed; the operator's captured cookie
        never reaches /logout.
  (ii)  negative control: logout invalidates the session server-side -> not
        confirmed.
  (iii) gate: validators.allow_mutating_replay off -> nothing is sent.
  (iv)  no fresh session (the finding's exchange is the operator's own logout):
        not confirmed, with a reason, and nothing reaches /logout.
  (v)   routing: a session_timeout finding dispatches the logout check; an
        unrelated auth class does not.
"""
import json
import secrets
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import harness.coverage_manifest as cm
from harness import global_throttle
from harness.coverage_evidence_case import EvidenceCase, evidence_for
from harness.models import HttpExchange
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _config, _RecordingModel
from harness.test_confirmation_soundness_rve import (_CallerBase, _finding, _json_exchange,
                                                     _verdicts)
from harness.validators.auth_sequence_validator import AuthSequenceValidator

_OPERATOR = "operator-session"
_ACCOUNT = "<html>Account of alice. <a href='/logout'>Log out</a></html>"


class _LogoutApp:
    """Login issues a fresh `sid`; /my-account needs a live sid; /logout clears
    the cookie client-side and, when `invalidates`, also server-side."""

    def __init__(self, invalidates: bool, account: str = _ACCOUNT):
        app = self
        self.account = account
        self.received: list[dict] = []
        self.sessions = {_OPERATOR}
        lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def _sid(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, _, value = part.strip().partition("=")
                    if name == "sid":
                        return value
                return ""

            def _send(self, status, body="", headers=None):
                data = body.encode("utf-8")
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _record(self):
                with lock:
                    app.received.append({"method": self.command, "path": urlsplit(self.path).path,
                                         "sid": self._sid()})

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self._record()
                if urlsplit(self.path).path != "/login":
                    return self._send(404)
                sid = secrets.token_hex(8)
                with lock:
                    app.sessions.add(sid)
                self._send(302, headers={"Location": "/my-account",
                                         "Set-Cookie": f"sid={sid}; Path=/; HttpOnly"})

            def do_GET(self):
                self._record()
                path = urlsplit(self.path).path
                if path == "/login":
                    return self._send(200, "<html><title>Log in</title>"
                                           "<form action='/login' method='post'>"
                                           "<input name='password' type='password'></form></html>")
                if path == "/logout":
                    if invalidates:
                        with lock:
                            app.sessions.discard(self._sid())
                    return self._send(302, headers={"Location": "/login",
                                                    "Set-Cookie": "sid=; Path=/; Max-Age=0"})
                if path == "/my-account":
                    if self._sid() in app.sessions:
                        return self._send(200, app.account)
                    return self._send(302, headers={"Location": "/login"})
                return self._send(404, "not found")

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def logout_sends(self):
        return [r for r in self.received if r["path"] == "/logout"]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


def _login(app, cookie=_OPERATOR):
    """The captured login, carrying the operator's own session cookie."""
    ex = _json_exchange(app.base + "/login", "POST", '{"username": "alice", "password": "pw"}')
    ex.request_headers["Cookie"] = f"sid={cookie}"
    return ex


# unittest.TestCase is listed explicitly so the static no-orphan check
# (test_no_orphan_test_files) sees these classes as test cases.
class _Base(_CallerBase, unittest.TestCase):
    mutating = True

    def _orch(self, hosts=("shop.invalid",)):
        """_CallerBase._orch with allow_mutating_replay set per class."""
        cfg = _config()
        cfg["server"]["allowed_hosts"] = list(hosts)
        cfg["validators"].update(active_enabled=True, allow_mutating_replay=self.mutating)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        global_throttle.configure(0)
        return orch

    def _app(self, invalidates, **kw):
        app = _LogoutApp(invalidates, **kw)
        self.addCleanup(app.close)
        return app

    def _run(self, finding_class, exchange):
        return self._validate("auth_sequence", AuthSequenceValidator(allowed_hosts=["127.0.0.1"]),
                              _finding(finding_class), exchange, hosts=("127.0.0.1",))


class LogoutInvalidationCallerTests(EvidenceCase, _Base):
    # EvidenceCase writes the WSTG-SESS-06 manifest evidence for the two bound tests.
    @evidence_for(**cm.caller_evidence("logout_confirm"))
    def test_client_side_only_logout_confirms(self):
        app = self._app(invalidates=False)
        reports = self._run("session_timeout", _login(app))
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        self.assertTrue(reports[0].confirmed)
        self.assertEqual("session_timeout", reports[0].finding_class)
        self.assertIn("still returned the authenticated page", reports[0].evidence)
        # The logout ran on the fresh throwaway session, never the operator's.
        logouts = app.logout_sends()
        self.assertEqual(1, len(logouts), app.received)
        self.assertNotIn(logouts[0]["sid"], ("", _OPERATOR))
        self.assertIn(_OPERATOR, app.sessions)
        # The account page was replayed with the same pre-logout cookie.
        after = [r for r in app.received[app.received.index(logouts[0]) + 1:]
                 if r["path"] == "/my-account"]
        self.assertEqual([logouts[0]["sid"]], [r["sid"] for r in after])
        self.assertFalse(any(r["sid"] == _OPERATOR for r in app.received), app.received)

    @evidence_for(**cm.caller_evidence("logout_control"))
    def test_server_side_invalidation_is_not_confirmed(self):
        app = self._app(invalidates=True)
        reports = self._run("logout_invalidation", _login(app))
        self.assertFalse(any(r.confirmed for r in reports), _verdicts(reports))
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))
        self.assertIn("Session invalidated on logout", reports[0].summary)
        # EFF-1: seen authenticated before the logout, denied after -> a held control.
        self.assertEqual(reports[0].control_outcome, "control_held")
        self.assertEqual(1, len(app.logout_sends()))
        self.assertNotEqual(_OPERATOR, app.logout_sends()[0]["sid"])

    def test_no_fresh_session_sends_nothing_to_logout(self):
        app = self._app(invalidates=False)
        logout = HttpExchange(url=app.base + "/logout", method="GET",
                              request_headers={"Cookie": f"sid={_OPERATOR}"},
                              response_status=302, response_body="")
        reports = self._run("session_timeout", logout)
        self.assertFalse(any(r.confirmed for r in reports), _verdicts(reports))
        self.assertEqual([r.status for r in reports], ["skipped"], _verdicts(reports))
        self.assertIn("no captured login to mint a fresh throwaway session", reports[0].summary)
        self.assertEqual([], app.logout_sends())
        self.assertEqual([], app.received)
        self.assertIn(_OPERATOR, app.sessions)

    def test_no_logout_control_is_inconclusive_and_sends_no_logout(self):
        app = self._app(invalidates=False, account="<html>Account of alice.</html>")
        reports = self._run("session_timeout", _login(app))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn("no same-origin logout link or form", reports[0].summary)
        self.assertEqual([], app.logout_sends())


class LogoutInvalidationGateTests(_Base):
    mutating = False

    def test_gate_off_sends_nothing(self):
        app = self._app(invalidates=False)
        reports = self._run("session_timeout", _login(app))
        self.assertFalse(any(r.confirmed for r in reports), _verdicts(reports))
        self.assertEqual([r.status for r in reports], ["skipped"], _verdicts(reports))
        self.assertEqual([], app.received)


class LogoutInvalidationRoutingTests(_Base):
    def test_session_timeout_finding_dispatches_the_logout_check(self):
        orch = self._orch(hosts=("127.0.0.1",))
        app = self._app(invalidates=False)
        login = _login(app)
        for cls in ("session_timeout", "Session Timeout", "logout_invalidation",
                    "Logout invalidation", "session not invalidated"):
            with self.subTest(cls=cls):
                routed = {v.name: v for v in
                          orch.validator_registry.for_finding(_finding(cls), login, agent="auth")}
                self.assertIn("auth_sequence", routed)
                self.assertEqual(["logout"], routed["auth_sequence"]._which_checks(cls, login))

    def test_logout_word_alone_does_not_dispatch_the_logout_check(self):
        # A different claim that merely mentions logout (CSRF on the logout
        # form) must not borrow a session_timeout confirmation.
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        login = _json_exchange("http://127.0.0.1/login", "POST",
                               '{"username": "alice", "password": "pw"}')
        self.assertEqual([], v._which_checks("csrf on logout", login))

    def test_other_not_invalidated_claims_do_not_dispatch_the_logout_check(self):
        # A reset token or a session kept after a password change is another
        # claim; logout evidence must not confirm it (the chain routes these
        # phrases to auth_sequence before its reset_token branch).
        from harness.validators.auth_sequence_validator import _is_logout_class
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        login = _json_exchange("http://127.0.0.1/login", "POST",
                               '{"username": "alice", "password": "pw"}')
        for cls in ("reset token not invalidated after use",
                    "password reset token not invalidated",
                    "session not invalidated after password change"):
            with self.subTest(cls=cls):
                self.assertFalse(_is_logout_class(cls))
                self.assertNotIn("logout", v._which_checks(cls, login))
        for cls in ("session not invalidated", "session not invalidated on logout",
                    "session token not invalidated after log out"):
            with self.subTest(cls=cls):
                self.assertTrue(_is_logout_class(cls))

    def test_existing_auth_classes_do_not_dispatch_the_logout_check(self):
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        login = _json_exchange("http://127.0.0.1/login", "POST",
                               '{"username": "alice", "password": "pw"}')
        for cls in v.finding_classes:
            if cls in ("session_timeout", "session timeout", "logout_invalidation",
                       "logout invalidation", "session not invalidated"):
                continue
            with self.subTest(cls=cls):
                self.assertNotIn("logout", v._which_checks(cls, login))
        self.assertEqual(["mfa"], v._which_checks("2fa_bypass", login))
        self.assertEqual(["enum"], v._which_checks("username_enumeration", login))
        self.assertEqual([], v._which_checks("auth", login))

    def test_unrelated_auth_class_sends_no_logout(self):
        app = self._app(invalidates=False)
        reports = self._run("username_enumeration", _login(app))
        self.assertTrue(reports)
        self.assertEqual([], app.logout_sends())
        self.assertNotIn("logout", json.dumps([r.summary for r in reports]).lower())


if __name__ == "__main__":
    unittest.main()
