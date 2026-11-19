"""R11-8 (b): the session legs the owner allowed on 2026-11-19, each through the
real dispatch (Orchestrator._validate_findings -> validators/registry.py inside an
entered RunContext) against an owned loopback app, with a matched negative.

  expiry   a session JWT with no exp claim confirms as its own class
           (session_expiry, WSTG-SESS-07); decode only, nothing is sent. Negative:
           a JWT with an exp claim.
  burst    min_attempts wrong-password logins for a run-owned identity, then its
           real login still succeeds with no throttle: no lockout or rate limit on
           failed logins (rate_limit). Negatives: a login that locks the account
           (named as left locked) and one that throttles with 429.
"""
import asyncio
import json
import unittest

from harness.models import AgentReport, Finding
from harness.test_oracle_gaps_auth_tokens import _jwt
from harness.test_r11_detection_legs import _ANN, _Base, _ex


def _finding(cls, summary="", basis="derived"):
    return Finding(vulnerability_class=cls, confidence=0.6, severity="medium",
                   summary=summary or cls, evidence="", suggested_test="", basis=basis)


class _LegBase(_Base):
    def run_finding(self, orch, exchange, finding, *, identities=(), gate=None,
                    max_requests=300, setup=None):
        """Dispatch one agent finding through _validate_findings inside a run."""
        from harness.run_context import RunContext
        from urllib.parse import urlsplit
        origin = "{0.scheme}://{0.netloc}".format(urlsplit(exchange.url))
        gate_config = {"active_enabled": True, "allow_mutating_replay": True,
                       "max_burst_size": 6}
        gate_config.update(gate or {})

        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=max_requests,
                                    gate_config=gate_config)
            for i, ident in enumerate(identities):
                headers = ident if isinstance(ident, dict) else {
                    "Authorization": "Bearer " + _jwt(90 + i, ident)}
                run.sessions.register(f"s{i}", f"p{i}", headers, allowed_origins=[origin],
                                      name=f"eval-user-{i + 1}")
            if setup is not None:
                setup(run)
            async with run:
                reports, _ = await orch._validate_findings(
                    exchange, [AgentReport(agent="auth", model="fake", findings=[finding])],
                    run_context=run)
            await run.aclose()
            return reports

        reports = asyncio.run(go())
        self.assertTrue(reports, f"{finding.vulnerability_class} was not dispatched")
        return reports[0]


# ------------------------------------------------------------- token expiry
def _login(origin, token, *, status=200):
    body = json.dumps({"email": _ANN, "password": "pw-ann-123"})
    return _ex(origin + "/rest/user/login", "POST", body, status,
               {"authentication": {"token": token, "bid": 1}})


class TokenExpiryTests(_LegBase):
    def _app(self):
        return self.app(lambda m, p, q, b: (200, {}))

    def test_login_token_without_exp_confirms_as_session_expiry(self):
        app = self._app()
        token = _jwt(7, _ANN)
        report = self.run_finding(self.orch("auth_sequence"), _login(app.origin, token),
                                  _finding("session_expiry"))
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertTrue(report.confirmed)
        self.assertEqual(report.finding_class, "session_expiry")
        self.assertIn("no exp claim", report.summary)
        self.assertIn("'token'", report.summary)
        for text in (report.summary, report.evidence):
            self.assertNotIn(token, text)
            self.assertNotIn(token.split(".")[1], text)
            self.assertNotIn(_ANN, text)
        self.assertEqual(app.received, [], "the decode-only check sent a request")

    def test_login_token_with_exp_is_a_negative(self):
        app = self._app()
        report = self.run_finding(self.orch("auth_sequence"),
                                  _login(app.origin, _jwt(7, _ANN, exp=1731603600)),
                                  _finding("session_expiry"))
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertFalse(report.confirmed)
        self.assertIn("carries an exp claim", report.summary)
        self.assertEqual(app.received, [])

    def test_run_identity_token_without_exp_confirms_and_names_the_identity(self):
        app = self._app()
        read = _ex(app.origin + "/api/items/5", response={"id": 5})
        report = self.run_finding(self.orch("auth_sequence"), read,
                                  _finding("JWT without exp claim"), identities=[_ANN])
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("eval-user-1", report.summary)
        self.assertNotIn(_ANN, report.summary + report.evidence)
        self.assertEqual(app.received, [])

    def test_no_session_jwt_is_skipped_and_sends_nothing(self):
        app = self._app()
        report = self.run_finding(self.orch("auth_sequence"),
                                  _ex(app.origin + "/api/items/5", response={"id": 5}),
                                  _finding("session_expiry"),
                                  identities=[{"Cookie": "sid=opaque-session-value"}])
        self.assertEqual(report.status, "skipped", report.summary)
        self.assertEqual(app.received, [])

    def test_needs_no_mutating_replay_permission(self):
        app = self._app()
        orch = self.orch("auth_sequence")
        orch.config["validators"]["allow_mutating_replay"] = False
        from harness import safety_gate
        safety_gate.reset_default_gate()
        report = self.run_finding(orch, _login(app.origin, _jwt(7, _ANN)),
                                  _finding("session_expiry"),
                                  gate={"allow_mutating_replay": False})
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertEqual(app.received, [])

    def test_class_gate_keeps_the_expiry_proof_to_its_own_class(self):
        """R11-1: the expiry proof is no logout proof and no JWT-forgery proof; a
        logout finding never runs the expiry check."""
        from harness.validators.auth_sequence_validator import AuthSequenceValidator
        from harness.validators.base import proves_finding_class
        validator = AuthSequenceValidator()
        exchange = _login("http://127.0.0.1:1", _jwt(7, _ANN))
        self.assertEqual(validator._which_checks("session_expiry", exchange), ["expiry"])
        self.assertEqual(validator._which_checks("session_timeout", exchange), ["logout"])
        self.assertNotIn("expiry", validator._which_checks("broken_authentication", exchange))
        self.assertEqual(validator._which_checks("password never expires", exchange), [])
        result = validator._check_token_expiry(exchange)
        self.assertTrue(result.confirmed)
        self.assertEqual(result.mechanism_classes, ("session_expiry",))
        self.assertTrue(proves_finding_class(validator, result, _finding("session_expiry"),
                                             exchange))
        self.assertFalse(proves_finding_class(validator, result, _finding("jwt"), exchange))

    def test_coverage_row_and_capability(self):
        from harness.categories import canonicalize
        from harness.coverage_model import CHECK_CATALOG
        from harness.wstg_ids import is_current_wstg_id
        row = next(c for c in CHECK_CATALOG if c.id == "WSTG-SESS-07")
        self.assertTrue(is_current_wstg_id(row.id))
        self.assertEqual(row.vulnerability_class, "session_expiry")
        self.assertEqual(canonicalize("JWT without exp"), "session_expiry")
        self.assertNotEqual(canonicalize("session timeout"), "session_expiry")
        logout = next(c for c in CHECK_CATALOG if c.id == "WSTG-SESS-06")
        self.assertNotEqual(canonicalize(logout.vulnerability_class), "session_expiry")
        from harness.run_context import RunContext
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=10,
                                gate_config={"active_enabled": True,
                                             "allow_mutating_replay": False})
        orch = self.orch("auth_sequence")
        decision = orch.validator_registry.capability_for_check(
            row, _login("http://127.0.0.1:1", _jwt(7, _ANN)), run_context=run)
        self.assertEqual(decision["status"], "ready", decision)
        self.assertEqual(decision["finding_class"], "session_expiry")
        self.assertEqual(decision["mechanism_id"], "auth.token_expiry")



# ------------------------------------------------------- failed-login burst
_PW = "pw-ann-123"
_LOGIN = {"method": "POST", "path": "/rest/user/login",
          "body": {"email": _ANN, "password": _PW},
          "token_pointer": "/authentication/token"}


class _LoginApp:
    """A login that accepts _ANN/_PW; `lock_after` failures lock the account
    silently (every later login is refused); `throttle_after` failures draw 429."""

    def __init__(self, *, lock_after=0, throttle_after=0):
        self.failures, self.lock_after, self.throttle_after = 0, lock_after, throttle_after

    def handle(self, method, path, query, body):
        if path != "/rest/user/login":
            return 404, {}
        doc = json.loads(body or "{}")
        if self.lock_after and self.failures >= self.lock_after:
            return 401, {"error": "Invalid email or password."}
        if doc.get("email") == _ANN and doc.get("password") == _PW:
            return 200, {"authentication": {"token": _jwt(3, _ANN), "bid": 1}}
        self.failures += 1
        if self.throttle_after and self.failures > self.throttle_after:
            return 429, {"error": "Too many requests"}
        return 401, {"error": "Invalid email or password."}


class FailedLoginBurstTests(_LegBase):
    def _run(self, model, *, login=_LOGIN, gate=None, **cfg):
        app = self.app(model.handle)
        cfg.setdefault("min_attempts", 4)
        exchange = _ex(app.origin + "/rest/user/login", "POST",
                       json.dumps({"email": _ANN, "password": _PW}), 200,
                       {"authentication": {"token": _jwt(3, _ANN)}})

        def setup(run):
            if login is not None:
                run.sessions.set_login("s0", login, app.origin)

        report = self.run_finding(self.orch("rate_limit", **cfg), exchange,
                                  _finding("no lockout"), identities=[_ANN], gate=gate,
                                  setup=setup)
        return app, report

    def _bodies(self, app):
        return [json.loads(r["body"]) for r in app.received]

    def assertRedacted(self, report):
        for text in (report.summary, report.evidence):
            self.assertNotIn(_ANN, text)
            self.assertNotIn(_PW, text)

    def test_no_lockout_confirms(self):
        app, report = self._run(_LoginApp())
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertEqual(report.finding_class, "rate_limit")
        self.assertIn("No lockout or rate limit on failed logins", report.summary)
        self.assertIn("eval-user-1", report.summary)
        self.assertRedacted(report)
        bodies = self._bodies(app)
        self.assertEqual(len(bodies), 5)
        self.assertEqual(len({b["password"] for b in bodies[:4]}), 4)
        self.assertNotIn(_PW, {b["password"] for b in bodies[:4]})
        self.assertEqual(bodies[4]["password"], _PW)
        self.assertEqual({b["email"] for b in bodies}, {_ANN})

    def test_lockout_is_a_negative_naming_the_account_left_locked(self):
        _app, report = self._run(_LoginApp(lock_after=3))
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertFalse(report.confirmed)
        self.assertIn("left locked", report.summary)
        self.assertIn("eval-user-1", report.summary)
        self.assertRedacted(report)

    def test_throttle_is_a_negative(self):
        app, report = self._run(_LoginApp(throttle_after=2))
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("are limited", report.summary)
        self.assertNotIn("left locked", report.summary)
        self.assertEqual(len(app.received), 4)   # 3 wrong (the third throttled) + the real one

    def test_fewer_allowed_than_min_attempts_is_a_lead(self):
        _app, report = self._run(_LoginApp(), min_attempts=8)
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("Lead, not confirmed", report.summary)

    def test_default_burst_ceiling_sends_nothing(self):
        app, report = self._run(_LoginApp(), gate={"max_burst_size": 1})
        self.assertEqual(report.status, "skipped", report.summary)
        self.assertEqual(app.received, [])

    def test_identity_without_a_declared_login_gets_no_wrong_password(self):
        app, _report = self._run(_LoginApp(), login=None)
        self.assertNotIn(True, [b["password"] != _PW for b in self._bodies(app)])

    def test_login_at_another_path_gets_no_wrong_password(self):
        app, _report = self._run(_LoginApp(), login=dict(_LOGIN, path="/other/login"))
        self.assertNotIn(True, [b.get("password") != _PW for b in self._bodies(app)])


if __name__ == "__main__":
    unittest.main()
