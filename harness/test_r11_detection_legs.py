"""R11-8 (c): the three detection legs r11 never opened, each through the real
dispatch (shape_precondition_findings -> Orchestrator._validate_findings inside an
entered RunContext) against an owned loopback app, with a matched negative.

  challenge  a challenge response that carries its own answer (passive pairs and
             the opt-in active submit) versus one that does not;
  lookup     a GET lookup that answers a run identity's account unlike an unknown
             one versus one that answers both alike;
  reset      a reset-answer POST with no throttle versus one that throttles, plus
             the safety gates (another account, a rejected capture).

Policy under test: every positive is a labelled LEAD (not_confirmed, with
manual_verification) by default, and confirms only with its config key on:
validators.challenge_echo.confirm, validators.auth_sequence.confirm_lookup,
validators.rate_limit.confirm_reset_answer.
"""
import asyncio
import itertools
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from harness import global_throttle
from harness.models import AgentReport, HttpExchange
from harness.orchestrator import Orchestrator
from harness.orchestrator_helpers import _SHAPE_LEG_AGENT, shape_precondition_findings
from harness.test_confirmation_soundness_rve import _CallerBase
from harness.test_default_history_caller import _config, _RecordingModel
from harness.test_oracle_gaps_auth_tokens import _jwt

_ANN = "ann@example.test"


class _App:
    """A loopback app; `handle(method, path, query, body)` -> (status, json)."""

    def __init__(self, handle):
        self.received = []
        app = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self):
                url = urlsplit(self.path)
                size = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(size).decode() if size else ""
                app.received.append({"method": self.command, "path": url.path,
                                     "query": parse_qs(url.query), "body": body})
                status, doc = handle(self.command, url.path, parse_qs(url.query), body)
                raw = json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = _serve

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _ex(url, method="GET", body="", status=200, response=None):
    headers = {"Content-Type": "application/json"} if body else {}
    return HttpExchange(url=url, method=method, request_headers=headers, request_body=body,
                        response_status=status,
                        response_headers={"Content-Type": "application/json"},
                        response_body=json.dumps(response if response is not None else {}))


class _Base(_CallerBase):
    def app(self, handle):
        app = _App(handle)
        self.addCleanup(app.close)
        return app

    def orch(self, leg, **leg_cfg):
        """An Orchestrator whose registry was built from config (so the leg's keys
        are read where a run reads them), narrowed to that one leg."""
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["127.0.0.1"]
        cfg["validators"].update(active_enabled=True, allow_mutating_replay=True)
        cfg["validators"].setdefault(leg, {}).update(leg_cfg)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        global_throttle.configure(0)
        orch.validator_registry.validators = {leg: orch.validator_registry.validators[leg]}
        return orch

    def dispatch(self, orch, exchange, cls, *, identities=(), captured=()):
        from harness.run_context import RunContext
        findings = [f for f in shape_precondition_findings(exchange)
                    if f.vulnerability_class == cls]
        self.assertTrue(findings, f"no {cls} shape leg for {exchange.method} {exchange.url}")
        origin = "{0.scheme}://{0.netloc}".format(urlsplit(exchange.url))

        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=300,
                                    gate_config={"active_enabled": True,
                                                 "allow_mutating_replay": True,
                                                 "max_burst_size": 6})
            for i, email in enumerate(identities):
                run.sessions.register(f"s{i}", f"p{i}",
                                      {"Authorization": "Bearer " + _jwt(90 + i, email)},
                                      allowed_origins=[origin])
            async with run:
                run.experiment_context = {"captured": list(captured)}
                reports, _proofs = await orch._validate_findings(
                    exchange, [AgentReport(agent=_SHAPE_LEG_AGENT, model="rule-based",
                                           findings=findings)], run_context=run)
            await run.aclose()
            return reports

        reports = asyncio.run(go())
        self.assertTrue(reports, f"{cls} was not dispatched")
        return reports[0]

    def assertLead(self, report):
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertFalse(report.confirmed)
        self.assertTrue(report.summary.startswith("Lead, not confirmed"), report.summary)


# --------------------------------------------------------------- challenge echo
class _Challenges:
    """GET /api/challenge issues {challengeId, question[, solution]}; POST
    /api/feedback passes with the right answer in `question` for that id."""

    def __init__(self, echo: bool):
        self.echo = echo
        self.ids = itertools.count(1001)
        self.answers = {}

    def handle(self, method, path, query, body):
        if method == "GET" and path == "/api/challenge":
            cid = next(self.ids)
            a, b = cid % 7 + 2, cid % 5 + 3
            self.answers[cid] = str(a * b + 1)
            doc = {"challengeId": cid, "question": f"{a}*{b}+1"}
            if self.echo:
                doc["solution"] = self.answers[cid]
            return 200, doc
        if method == "POST" and path == "/api/feedback":
            sub = json.loads(body or "{}")
            if self.answers.get(sub.get("challengeId")) == str(sub.get("question")):
                return 201, {"status": "success"}
            return 401, {"error": "Wrong answer to the challenge"}
        return 404, {}

    def pair(self, origin, *, accepted=True):
        """A captured challenge and a captured submission of its real answer."""
        _status, doc = self.handle("GET", "/api/challenge", {}, "")
        answer = self.answers[doc["challengeId"]] if accepted else "0"
        sub = {"challengeId": doc["challengeId"], "question": answer, "comment": "hi"}
        status, resp = self.handle("POST", "/api/feedback", {}, json.dumps(sub))
        return [_ex(origin + "/api/challenge", response=doc),
                _ex(origin + "/api/feedback", "POST", json.dumps(sub), status, resp)]


class ChallengeEchoTests(_Base):
    def _captures(self, echo, pairs=2, accepted=True):
        model = _Challenges(echo)
        app = self.app(model.handle)
        captured = []
        for _ in range(pairs):
            captured += model.pair(app.origin, accepted=accepted)
        return app, model, captured

    def test_echoing_challenge_is_a_lead_by_default(self):
        app, _m, captured = self._captures(echo=True)
        report = self.dispatch(self.orch("challenge_echo"), captured[-2], "challenge_echo",
                               captured=captured)
        self.assertLead(report)
        self.assertIn("confirm is off", report.summary)
        self.assertIn("'solution'", report.summary)
        self.assertIn("as 'question'", report.summary)
        self.assertIn("2 distinct value(s)", report.evidence)
        self.assertTrue(report.manual_verification)
        self.assertEqual(app.received, [], "the passive verdict sent a request")

    def test_echoing_challenge_confirms_with_the_key_on(self):
        _app, _m, captured = self._captures(echo=True)
        report = self.dispatch(self.orch("challenge_echo", confirm=True), captured[-2],
                               "challenge_echo", captured=captured)
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertTrue(report.confirmed)

    def test_one_pair_stays_a_lead_even_with_the_key_on(self):
        _app, _m, captured = self._captures(echo=True, pairs=1)
        report = self.dispatch(self.orch("challenge_echo", confirm=True), captured[0],
                               "challenge_echo", captured=captured)
        self.assertLead(report)
        self.assertIn("one pair only", report.summary)

    def test_challenge_without_its_answer_is_no_lead(self):
        app, _m, captured = self._captures(echo=False)
        report = self.dispatch(self.orch("challenge_echo", confirm=True), captured[-2],
                               "challenge_echo", captured=captured)
        self.assertIn(report.status, ("not_confirmed", "inconclusive"), report.summary)
        self.assertFalse(report.confirmed)
        self.assertFalse(report.summary.startswith("Lead"), report.summary)
        self.assertFalse(report.manual_verification)   # pruned on the analyze path
        self.assertEqual(app.received, [])

    def test_same_name_handle_is_never_the_answer(self):
        """A CSRF-style token forwarded under its own name is how tokens work."""
        from harness.validators.challenge_echo_validator import echo_match
        self.assertIsNone(echo_match({"csrfToken": "abc123", "form": "x"},
                                     {"csrfToken": "abc123", "comment": "x"}))
        self.assertEqual(echo_match({"id": "9", "question": "2+2", "solution": "4"},
                                    {"id": "9", "question": "4"}), ("solution", "question", "4"))

    def test_active_submit_is_off_by_default_and_sends_nothing(self):
        app, _m, captured = self._captures(echo=True, pairs=1, accepted=False)
        report = self.dispatch(self.orch("challenge_echo"), captured[0], "challenge_echo",
                               captured=captured)
        self.assertEqual(report.status, "inconclusive", report.summary)
        self.assertIn("active_submit", report.summary)
        self.assertEqual(app.received, [])

    def test_active_submit_finds_the_echoed_answer(self):
        app, _m, captured = self._captures(echo=True, pairs=1, accepted=False)
        report = self.dispatch(self.orch("challenge_echo", active_submit=True), captured[0],
                               "challenge_echo", captured=captured)
        self.assertLead(report)
        self.assertIn("'solution' passes the challenge", report.summary)
        self.assertIn("(rejected)", report.evidence)
        posts = [r for r in app.received if r["method"] == "POST"]
        self.assertEqual(len(posts), 2, posts)   # the control, then the one candidate
        report = self.dispatch(self.orch("challenge_echo", active_submit=True, confirm=True),
                               captured[0], "challenge_echo", captured=captured)
        self.assertEqual(report.status, "confirmed", report.summary)

    def test_active_submit_on_a_challenge_without_its_answer_is_negative(self):
        app, _m, captured = self._captures(echo=False, pairs=1, accepted=False)
        report = self.dispatch(self.orch("challenge_echo", active_submit=True, confirm=True),
                               captured[0], "challenge_echo", captured=captured)
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertFalse(report.confirmed)
        self.assertFalse([r for r in app.received if r["method"] == "POST"])

    def test_static_resource_is_not_a_challenge(self):
        app = self.app(lambda m, p, q, b: (200, {"id": 5, "name": "Lamp", "price": 9})
                       if m == "GET" else (200, {"status": "ok"}))
        read = _ex(app.origin + "/api/items/5", response={"id": 5, "name": "Lamp", "price": 9})
        update = _ex(app.origin + "/api/items", "POST", json.dumps({"name": "Lamp2"}), 400,
                     {"error": "invalid"})
        report = self.dispatch(self.orch("challenge_echo", active_submit=True), read,
                               "challenge_echo", captured=[read, update])
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("static resource", report.summary)
        self.assertFalse([r for r in app.received if r["method"] == "POST"])


# ------------------------------------------------------- recovery lookup enum
def _lookup_app(self, discriminates):
    def handle(method, path, query, body):
        email = (query.get("email") or [""])[0].lower()
        if path != "/rest/account/question":
            return 404, {}
        if not discriminates:
            return 200, {"question": "What is your favourite colour?"}
        return (200, {"question": {"id": 3, "text": "Name of your first pet?"}}
                if email == _ANN else {})
    return self.app(handle)


class LookupEnumerationTests(_Base):
    def _lookup(self, app):
        return _ex(app.origin + "/rest/account/question?email=someone@example.test")

    def test_discriminating_lookup_is_a_redacted_lead_by_default(self):
        app = _lookup_app(self, True)
        report = self.dispatch(self.orch("auth_sequence"), self._lookup(app),
                               "username_enumeration", identities=[_ANN])
        self.assertLead(report)
        self.assertIn("confirm_lookup is off", report.summary)
        self.assertIn("GET /rest/account/question?email=", report.summary)
        for text in (report.summary, report.evidence):
            self.assertNotIn(_ANN, text)
            self.assertNotIn("someone@example.test", text)
        sent = {(r["query"].get("email") or [""])[0] for r in app.received}
        self.assertIn(_ANN, sent)
        self.assertTrue(any(e.startswith("nouser_") for e in sent), sent)

    def test_discriminating_lookup_confirms_with_the_key_on(self):
        app = _lookup_app(self, True)
        report = self.dispatch(self.orch("auth_sequence", confirm_lookup=True),
                               self._lookup(app), "username_enumeration", identities=[_ANN])
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertNotIn(_ANN, report.summary + report.evidence)

    def test_uniform_lookup_is_a_negative(self):
        app = _lookup_app(self, False)
        report = self.dispatch(self.orch("auth_sequence", confirm_lookup=True),
                               self._lookup(app), "username_enumeration", identities=[_ANN])
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("indistinguishable", report.summary)

    def test_coverage_drive_opens_the_lookup_cell(self):
        """The coverage row and its capability gate let a GET lookup through; r11's
        lookup path named no auth word and the gate took only credential writes."""
        from harness.coverage_model import CHECK_CATALOG
        row = next(c for c in CHECK_CATALOG if c.id == "WSTG-IDNT-04")
        endpoint = {"path": "/rest/account/question", "methods": ("GET",),
                    "template": {"method": "GET", "query": "email=a@b.test"}}
        self.assertTrue(row.applies(endpoint)[0])
        self.assertFalse(row.applies({"path": "/rest/items", "methods": ("GET",),
                                      "template": {"method": "GET", "query": "q=x"}})[0])
        orch = self.orch("auth_sequence")
        decision = orch.validator_registry.capability_for_check(
            row, _ex("http://127.0.0.1/rest/account/question?email=a@b.test"))
        self.assertEqual(decision["status"], "ready", decision)
        self.assertEqual(decision["finding_class"], "username_enumeration")
        plain = orch.validator_registry.capability_for_check(
            row, _ex("http://127.0.0.1/rest/items?q=x"))
        self.assertNotEqual(plain["status"], "ready")


# --------------------------------------------------------- reset-answer burst
class _Reset:
    def __init__(self, throttle_after=None):
        self.throttle_after = throttle_after
        self.wrong = 0
        self.changed = []

    def handle(self, method, path, query, body):
        if method != "POST" or path != "/rest/user/reset-password":
            return 404, {}
        sub = json.loads(body or "{}")
        if self.throttle_after is not None and self.wrong >= self.throttle_after:
            return 429, {"error": "Too many requests"}
        if sub.get("email") == _ANN and sub.get("answer") == "Rex":
            self.changed.append(sub.get("new"))
            return 200, {"user": {"id": 7}}
        self.wrong += 1
        return 401, {"error": "Wrong answer to security question."}


def _reset_capture(app, email=_ANN, *, status=200):
    body = json.dumps({"email": email, "answer": "Rex", "new": "pw-ann-123",
                       "repeat": "pw-ann-123"})
    return _ex(app.origin + "/rest/user/reset-password", "POST", body, status,
               {"user": {"id": 7}} if status == 200 else {"error": "Wrong answer"})


class ResetAnswerRateLimitTests(_Base):
    def _run(self, model, capture_kw=None, **cfg):
        app = self.app(model.handle)
        cfg.setdefault("min_attempts", 5)
        report = self.dispatch(self.orch("rate_limit", **cfg),
                               _reset_capture(app, **(capture_kw or {})), "rate_limit",
                               identities=[_ANN])
        return app, report

    def test_unthrottled_wrong_answers_are_a_lead_by_default(self):
        model = _Reset()
        app, report = self._run(model)
        self.assertLead(report)
        self.assertIn("confirm_reset_answer is off", report.summary)
        self.assertNotIn(_ANN, report.summary + report.evidence)
        sent = [json.loads(r["body"]) for r in app.received]
        self.assertEqual(len(sent), 5)
        self.assertEqual(len({s["answer"] for s in sent}), 5)
        self.assertNotIn("Rex", {s["answer"] for s in sent})
        self.assertEqual({(s["email"], s["new"], s["repeat"]) for s in sent},
                         {(_ANN, "pw-ann-123", "pw-ann-123")})
        self.assertEqual(model.changed, [], "a wrong answer changed state")

    def test_unthrottled_wrong_answers_confirm_with_the_key_on(self):
        _app, report = self._run(_Reset(), confirm_reset_answer=True)
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("No limit on reset-answer guessing", report.summary)

    def test_throttled_reset_is_a_negative(self):
        _app, report = self._run(_Reset(throttle_after=3), confirm_reset_answer=True)
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("is limited", report.summary)
        self.assertFalse(report.confirmed)

    def test_another_account_gets_nothing_sent(self):
        app, report = self._run(_Reset(), {"email": "bob@example.test"})
        self.assertEqual(report.status, "skipped", report.summary)
        self.assertIn("run-owned", report.summary)
        self.assertNotIn("bob@example.test", report.summary)
        self.assertEqual(app.received, [])

    def test_rejected_capture_gets_nothing_sent(self):
        app, report = self._run(_Reset(), {"status": 401})
        self.assertEqual(report.status, "skipped", report.summary)
        self.assertIn("was not accepted", report.summary)
        self.assertEqual(app.received, [])

    def test_reset_page_get_is_not_the_reset_shape(self):
        from harness.validators.rate_limit_validator import reset_answer_shape
        self.assertIsNone(reset_answer_shape(_ex("http://h/rest/user/reset-password")))
        self.assertIsNone(reset_answer_shape(_ex("http://h/api/quiz", "POST",
                                                 json.dumps({"answer": "b", "score": 1}))))
        self.assertEqual(reset_answer_shape(_ex("http://h/x", "POST", json.dumps(
            {"email": "a@b", "answer": "x", "new": "p"}))), ("email", "answer"))


if __name__ == "__main__":
    unittest.main()
