"""Oracle gap (2026-11-14): auth_sequence on bearer-token sessions and on an
identifier-in-query lookup.

An app whose login sets no cookie but returns a JWT in its JSON body got
"no session cookie" from both the logout-invalidation (WSTG-SESS-06) and the
session-fixation legs, and a GET lookup taking the account email in its query
was not an enumeration candidate at all. Every test drives
Orchestrator._validate_findings against an owned loopback app that records each
request it receives.

  logout  (i)   the run observed no logout/revocation route: an inconclusive
                lead (0.5 for a token with no exp), and nothing is sent to any
                logout path;
          (ii)  a revocation route named by the login JSON revokes the token:
                not_confirmed (negative control);
          (iii) a route the crawled app called (client routes) does not revoke:
                confirmed, with the token never in the evidence;
          (iv)  the operator's captured token is never sent to the logout.
  fixation (v)  a token minted by the login: N/A, with the reason;
          (vi)  a token the pre-login page handed out and the login returns
                unchanged: a candidate only.
  enum    (vii) GET ?email= with a run identity's email answers unlike a missing
                account: confirmed;
          (viii) negative control: both answer alike -> not_confirmed;
          (ix)  no run identity names an existing account: inconclusive, not a
                negative;
          (x)   a body login whose wrong-password answers are identical stays
                "indistinguishable".
"""
import asyncio
import base64
import json
import secrets
import threading
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from harness.models import AgentReport, HttpExchange
from harness.test_confirmation_soundness_rve import _CallerBase, _finding, _json_exchange
from harness.validators.auth_sequence_validator import AuthSequenceValidator

_USERS = {"ann@example.test": ("pw-ann-123", 7, True), "bob@example.test": ("pw-bob-456", 8, False)}
_GENERIC_DENIAL = json.dumps({"error": "Invalid email or password."})


def _jwt(uid, email, *, exp=None):
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    payload = {"status": "success", "data": {"id": uid, "email": email}, "iat": 1731600000}
    if exp is not None:
        payload["exp"] = exp
    return f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part(payload)}.{secrets.token_urlsafe(16)}"


class _TokenApp:
    """POST /rest/login -> {"authentication": {"token": <JWT>}} and no cookie.
    GET /rest/me needs a live bearer token. `revoke_path` (when set) is a POST
    that revokes the presented token if `revokes`, and the login JSON names it
    when `advertise`. `pre_token`: the root page hands out that token and the
    login returns it unchanged. `lookup_differs`: GET /rest/question?email=
    answers with a question only for an account that has one."""

    def __init__(self, *, revoke_path=None, revokes=True, advertise=True, pre_token=None,
                 lookup_differs=True):
        app = self
        self.received: list[dict] = []
        self.live: dict[str, str] = {}
        lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _token(self):
                auth = self.headers.get("Authorization") or ""
                return auth[7:] if auth.lower().startswith("bearer ") else ""

            def _send(self, status, body=""):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _record(self, body=""):
                with lock:
                    app.received.append({"method": self.command, "path": urlsplit(self.path).path,
                                         "token": self._token(), "body": body})

            def do_GET(self):
                self._record()
                url = urlsplit(self.path)
                if url.path == "/":
                    return self._send(200, json.dumps({"app": "demo", "token": pre_token})
                                      if pre_token else "{}")
                if url.path == "/rest/me":
                    email = app.live.get(self._token())
                    if not email:
                        return self._send(401, json.dumps({"error": "unauthorized"}))
                    return self._send(200, json.dumps({"user": {"email": email}}))
                if url.path == "/rest/question":
                    email = (parse_qs(url.query).get("email") or [""])[0].lower()
                    has = email in _USERS and _USERS[email][2]
                    return self._send(200, json.dumps({"question": "First pet?"})
                                      if has and lookup_differs else "{}")
                return self._send(404, json.dumps({"error": "not found"}))

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                self._record(body)
                path = urlsplit(self.path).path
                if path == "/rest/login":
                    try:
                        sent = json.loads(body or "{}")
                    except ValueError:
                        sent = {}
                    email = str(sent.get("email") or "").lower()
                    if email not in _USERS or _USERS[email][0] != sent.get("password"):
                        return self._send(401, _GENERIC_DENIAL)
                    token = pre_token or _jwt(_USERS[email][1], email)
                    with lock:
                        app.live[token] = email
                    doc = {"authentication": {"token": token, "umail": email}}
                    if revoke_path and advertise:
                        doc["links"] = {"revoke": revoke_path}
                    return self._send(200, json.dumps(doc))
                if revoke_path and path == revoke_path:
                    if revokes:
                        with lock:
                            app.live.pop(self._token(), None)
                    return self._send(200, "{}")
                return self._send(404, json.dumps({"error": "not found"}))

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _login(app, email="ann@example.test", headers=None):
    ex = _json_exchange(app.origin + "/rest/login", "POST",
                        json.dumps({"email": email, "password": _USERS[email][0]}))
    ex.request_headers.update(headers or {})
    return ex


def _lookup(app, email):
    return HttpExchange(url=f"{app.origin}/rest/question?email={email}", method="GET",
                        request_headers={}, response_status=200,
                        response_headers={"Content-Type": "application/json"}, response_body="{}")


class _Base(_CallerBase, unittest.TestCase):   # base named for the static checks
    def app(self, **kw):
        app = _TokenApp(**kw)
        self.addCleanup(app.close)
        return app

    def dispatch(self, cls, exchange, *, identities=(), routes=None):
        """auth_sequence through _validate_findings inside an entered RunContext
        (identities: (principal, email) registered with a JWT naming the email)."""
        from harness.run_context import RunContext
        orch = self._orch(hosts=("127.0.0.1",))
        orch.validator_registry.validators = {
            "auth_sequence": AuthSequenceValidator(allowed_hosts=["127.0.0.1"])}
        origin = "{0.scheme}://{0.netloc}".format(urlsplit(exchange.url))

        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200,
                                    gate_config={"active_enabled": True,
                                                 "allow_mutating_replay": True})
            for i, (principal, email) in enumerate(identities):
                run.sessions.register(f"s{i}", principal,
                                      {"Authorization": "Bearer " + _jwt(90 + i, email)},
                                      allowed_origins=[origin])
            if routes is not None:
                run.client_routes = types.SimpleNamespace(api_links=dict.fromkeys(routes, []),
                                                          api_views={})
            async with run:
                reports, _proofs = await orch._validate_findings(
                    exchange, [AgentReport(agent="auth", model="fake", findings=[_finding(cls)])],
                    run_context=run)
            await run.aclose()
            return reports

        reports = asyncio.run(go())
        self.assertTrue(reports, "auth_sequence was not dispatched")
        return reports[0]


class TokenLogoutTests(_Base):
    def test_no_observed_route_is_a_lead_and_sends_no_logout(self):
        app = self.app()
        report = self.dispatch("session_timeout", _login(app))
        self.assertEqual(report.status, "inconclusive", report.summary)
        self.assertIn("Logout invalidation lead, not confirmed", report.summary)
        self.assertIn("never expires", report.summary)
        self.assertIn("/rest/me", report.summary)
        self.assertAlmostEqual(report.confidence, 0.5)
        self.assertFalse([r for r in app.received if "log" in r["path"] and r["path"] != "/rest/login"
                          or "revo" in r["path"]])
        # The bearer read and its anonymous control both reached /rest/me.
        reads = [r for r in app.received if r["path"] == "/rest/me"]
        self.assertEqual({bool(r["token"]) for r in reads}, {True, False})

    def test_token_with_exp_is_a_weaker_lead(self):
        from harness.validators import auth_sequence_validator as asv
        lifetime, never = asv._token_lifetime(_jwt(1, "a@b.test", exp=1731600000 + 6 * 3600))
        self.assertEqual((lifetime, never), ("a JWT valid for 6 hour(s)", False))

    def test_advertised_revocation_that_revokes_is_a_negative(self):
        app = self.app(revoke_path="/rest/session/revoke", revokes=True)
        report = self.dispatch("session_timeout", _login(app))
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("Token revoked on logout", report.summary)
        self.assertIn("/rest/session/revoke", [r["path"] for r in app.received])

    def test_crawled_logout_route_that_keeps_the_token_confirms(self):
        app = self.app(revoke_path="/rest/user/logout", revokes=False, advertise=False)
        operator = _jwt(5, "ann@example.test")
        report = self.dispatch("session_timeout",
                               _login(app, headers={"Authorization": "Bearer " + operator}),
                               routes=["POST /rest/user/logout", "GET /rest/items"])
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("still authorizes /rest/me after POST /rest/user/logout", report.summary)
        self.assertIn("an API call the crawled app made", report.evidence)
        logouts = [r for r in app.received if r["path"] == "/rest/user/logout"]
        self.assertEqual(len(logouts), 1)
        self.assertNotEqual(logouts[0]["token"], operator)
        self.assertIn(logouts[0]["token"], app.live)
        self.assertNotIn(logouts[0]["token"], report.evidence + report.summary)

    def test_unrelated_get_route_is_never_called_a_logout(self):
        app = self.app()
        report = self.dispatch("session_timeout", _login(app),
                               routes=["GET /rest/revocations", "GET /rest/items"])
        self.assertEqual(report.status, "inconclusive", report.summary)
        self.assertNotIn("/rest/revocations", [r["path"] for r in app.received])


class TokenFixationTests(_Base):
    def test_token_minted_at_login_is_not_applicable(self):
        app = self.app()
        report = self.dispatch("session_fixation", _login(app))
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("mints a bearer token in the JSON field 'token'", report.summary)
        self.assertIn("session fixation N/A", report.summary)

    def test_pre_login_token_returned_unchanged_is_only_a_candidate(self):
        app = self.app(pre_token=_jwt(3, "ann@example.test"))
        report = self.dispatch("session_fixation", _login(app))
        self.assertEqual(report.status, "inconclusive", report.summary)
        self.assertIn("Candidate only", report.summary)
        self.assertFalse(report.confirmed)


class QueryEnumerationTests(_Base):
    def test_lookup_answers_differently_for_a_run_identity(self):
        app = self.app()
        report = self.dispatch("username_enumeration", _lookup(app, "someone@example.test"),
                               identities=[("ann", "ann@example.test")])
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("at GET /rest/question?email=", report.summary)
        self.assertIn("in place of the captured value", report.evidence)
        sent = [r["path"] for r in app.received]
        self.assertTrue(sent and set(sent) == {"/rest/question"}, sent)

    def test_identical_answers_are_a_negative(self):
        app = self.app(lookup_differs=False)
        report = self.dispatch("username_enumeration", _lookup(app, "ann@example.test"),
                               identities=[("ann", "ann@example.test")])
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("a run identity's own identifier", report.summary)
        self.assertIn("indistinguishable", report.summary)

    def test_unknown_account_is_not_a_negative(self):
        app = self.app(lookup_differs=False)
        report = self.dispatch("username_enumeration", _lookup(app, "someone@example.test"))
        self.assertEqual(report.status, "inconclusive", report.summary)
        self.assertIn("not known to exist", report.summary)

    def test_generic_auth_class_on_a_plain_get_runs_nothing(self):
        app = self.app()
        ex = HttpExchange(url=app.origin + "/rest/items", method="GET", request_headers={},
                          response_status=200, response_headers={}, response_body="[]")
        self.assertFalse(AuthSequenceValidator().applies(_finding("broken_authentication"), ex))
        self.assertTrue(AuthSequenceValidator().applies(
            _finding("broken_authentication"), _lookup(app, "x@example.test")))

    def test_body_login_with_identical_denials_stays_indistinguishable(self):
        app = self.app()
        report = self.dispatch("username_enumeration", _login(app))
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertEqual("valid and invalid usernames produced indistinguishable responses "
                         "(no enumeration)", report.summary)


if __name__ == "__main__":
    unittest.main()
