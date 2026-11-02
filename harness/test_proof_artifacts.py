"""Ticket 6 follow-up: confirmations name the exchanges they rest on.

Strict accounting counts a proof as a vulnerability only when it is executed,
not legacy, and names three distinct exchanges (baseline, attack, controls) that
resolve as successful case-bound EXECUTION events with intact evidence blobs.

Caller-level: a real validator confirms against an owned loopback target through
Orchestrator._validate_findings inside an entered RunContext, so the real
transport, ledger and blob store write every exchange. The persisted proof must
resolve and confirmed_issue_accounting must count it. Defect injections (a
missing control, a missing or corrupted blob, a control from another case) keep
the same confirmation a candidate.
"""
from __future__ import annotations

import asyncio
import base64
import http.server
import json
import sqlite3
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qsl, unquote, urlsplit

import httpx

from harness import store
from harness.assessment_health import confirmed_issue_accounting, stored_proof_artifacts_resolve
from harness.models import AgentReport
from harness.orchestrator import Orchestrator
from harness.orchestrator_chain import _ConfirmationCache
from harness.run_context import (_CREDENTIAL_HEADERS, ExecutionOutcome, RunContext, ScopePolicy,
                                 TypedRequest, case_scope, current_case_ref)
from harness.test_confirmation_soundness_rve import _CallerBase, _finding, _json_exchange, _verdicts
from harness.test_default_history_caller import _exchange
from harness.validators.auth_sequence_validator import AuthSequenceValidator
from harness.validators.base import (SentAnswer, ValidationResult, Validator, artifact_id_of,
                                     proof_artifact_kwargs)
from harness.validators.command_injection_validator import CommandInjectionValidator
from harness.validators.cors_validator import CorsValidator
from harness.validators.jwt_forge_validator import JwtForgeValidator
from harness.validators.open_redirect_validator import _SENTINEL_HOST, OpenRedirectValidator
from harness.validators.sqlmap import SqlmapValidator
from harness.validators.ssrf_validator import SsrfValidator


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_JWT = (_b64url(b'{"alg":"HS256","typ":"JWT"}') + "." + _b64url(b'{"sub":"1","role":"user"}')
        + "." + _b64url(b"signature-not-real"))
_GARBAGE_SIG = _b64url(b"not-a-valid-signature-xxxx")
_PROFILE = '{"id": 1, "email": "alice@example.com"}'


class _Target:
    """Owned loopback app. `respond(method, path, headers, body)` returns
    (status, body) or (status, body, response_headers); headers arrive lower-cased."""

    def __init__(self, respond):
        seen = self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
                headers = {k.lower(): v for k, v in self.headers.items()}
                seen.append((self.command, self.path))
                status, text, *extra = respond(self.command, self.path, headers, body)
                data = text.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for name, value in (extra[0] if extra else {}).items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_OPTIONS = _serve

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


def _jwt_api(method, path, headers, body):
    """Reads a profile with the real token or an alg:none forgery; rejects the
    garbage-signature control and the tokenless request."""
    auth = headers.get("authorization", "")
    if not auth:
        return 401, '{"error": "login required"}'
    tok = auth.split()[-1]
    if tok == _JWT or tok.endswith("."):
        return 200, _PROFILE
    return 401, '{"error": "bad signature"}'


class _ProofCallerBase(_CallerBase, unittest.TestCase):
    HOSTS = ("127.0.0.1",)

    def _confirm(self, key, validator, finding, exchange, *, more_findings=(), max_requests=500):
        """One validator through _validate_findings inside an entered run, as
        production analyze() does. Returns (run_id, reports, proofs)."""
        orch = self._orch(hosts=self.HOSTS)
        orch.validator_registry.validators = {key: validator}
        gate_config = {"active_enabled": True, "allow_mutating_replay": True}

        async def go():
            async with RunContext.create(allowed_hosts=list(self.HOSTS), max_requests=max_requests,
                                         gate_config=gate_config) as run:
                creds = {k: v for k, v in (exchange.request_headers or {}).items()
                         if k.lower() in _CREDENTIAL_HEADERS}
                if creds:
                    run.sessions.register("captured", "captured", creds, name="captured",
                                          allowed_origins=[ScopePolicy.origin_of(exchange.url)])
                reports, proofs = await orch._validate_findings(
                    exchange, [AgentReport(agent=key, model="fake",
                                           findings=[finding, *more_findings])],
                    run_context=run)
                return run.run_id, reports, proofs
        run_id, reports, proofs = asyncio.run(go())
        self.assertTrue(reports, "the validator was not dispatched")
        return run_id, reports, proofs

    def _stored_proof(self, proofs):
        self.assertEqual(len(proofs), 1, proofs)
        case_id = proofs[0]["case"]["case_id"]
        stored = [p for p in store.proofs_for_case(case_id) if p["proof_id"] == proofs[0]["proof_id"]]
        self.assertEqual(len(stored), 1, "the proof was not persisted")
        return stored[0]

    def _accounting(self, run_id, proof, url, cls, *, lookup=None):
        finding = {"confirmed": True, "case_id": proof["case"]["case_id"],
                   "proof_id": proof["proof_id"], "url": url, "vulnerability_class": cls}
        if lookup is None:
            return confirmed_issue_accounting(
                [finding], run_id, store.proofs_for_case, run_proofs=store.proofs_for_run(run_id),
                artifact_resolver=stored_proof_artifacts_resolve)
        return confirmed_issue_accounting(
            [finding], run_id, lambda case_id: list(lookup), run_proofs=list(lookup),
            artifact_resolver=stored_proof_artifacts_resolve)

    def _assert_counted(self, run_id, proof, url, cls):
        self.assertEqual(proof["verdict"], "confirmed")
        self.assertTrue(proof["executed"])
        self.assertFalse(proof["legacy"])
        refs = [proof["baseline_artifact_id"], proof["attack_artifact_id"],
                *proof["control_artifact_ids"]]
        self.assertTrue(all(refs), refs)
        self.assertGreaterEqual(len(set(refs)), 3, refs)
        self.assertTrue(stored_proof_artifacts_resolve(proof))
        accounting = self._accounting(run_id, proof, url, cls)
        self.assertEqual(accounting["counts"]["vulnerabilities"], 1, accounting)
        self.assertEqual(accounting["counts"]["candidate_cases"], 0, accounting)
        self.assertEqual([i["kind"] for i in accounting["proof_instances"]], ["vulnerability"])

    def _assert_candidate(self, run_id, proof, url, cls, *, lookup=None):
        self.assertEqual(proof["verdict"], "confirmed")
        accounting = self._accounting(run_id, proof, url, cls, lookup=lookup)
        self.assertEqual(accounting["counts"]["vulnerabilities"], 0, accounting)
        self.assertEqual(accounting["counts"]["candidate_cases"], 1, accounting)
        self.assertEqual([i["kind"] for i in accounting["proof_instances"]], ["candidate"])
        self.assertEqual(accounting["counts"]["ledger_confirmed_proof_instances"], 1)


def _execution_event(proof, artifact_id):
    # Where the resolver looks: the case's own events, then its finding's.
    case = proof["case"]
    events = store.ledger_events_for(case["case_id"])
    if case.get("finding_ref") and case["finding_ref"] != case["case_id"]:
        events += store.ledger_events_for(case["finding_ref"])
    for event in events:
        if event["event_type"] == "execution" and (event["data"] or {}).get("artifact_id") == artifact_id:
            return event
    raise AssertionError(f"no execution event for {artifact_id}")


class _NoControlJwt(JwtForgeValidator):
    """Defect injection: confirms exactly as jwt_forge does, then drops its
    control exchange."""

    async def validate(self, finding, exchange):
        result = await super().validate(finding, exchange)
        result.control_artifact_ids = ()
        return result


class _CrossCaseJwt(JwtForgeValidator):
    """Defect injection: names, as its control, a real successful exchange that
    was recorded under another case."""

    async def validate(self, finding, exchange):
        result = await super().validate(finding, exchange)
        with case_scope("another-case"):
            sent = await self._probe(exchange.url, {"Authorization": f"Bearer {_JWT[:-2]}xx"})
        result.control_artifact_ids = (artifact_id_of(sent),)
        return result


class JwtForgeProofTests(_ProofCallerBase):
    def setUp(self):
        super().setUp()
        self.target = _Target(_jwt_api)
        self.addCleanup(self.target.close)
        self.url = self.target.origin + "/api/me"

    def _run(self, validator_cls=JwtForgeValidator):
        exchange = _exchange(self.url, {"Authorization": f"Bearer {_JWT}"})
        validator = validator_cls(allowed_hosts=list(self.HOSTS), timeout=5.0)
        run_id, reports, proofs = self._confirm("jwt_forge", validator, _finding("jwt"), exchange)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        return run_id, self._stored_proof(proofs)

    def test_forged_token_confirmation_is_a_counted_vulnerability(self):
        run_id, proof = self._run()
        self._assert_counted(run_id, proof, self.url, "jwt")
        # Each role is the exchange the verdict rests on, recorded under this case.
        roles = {"baseline": proof["baseline_artifact_id"], "attack": proof["attack_artifact_id"],
                 "control": proof["control_artifact_ids"][0]}
        answers = {role: json.loads(store.get_evidence_blob(
            _execution_event(proof, aid)["data"]["response_blob"]))["status"]
            for role, aid in roles.items()}
        self.assertEqual(answers, {"baseline": 200, "attack": 200, "control": 401})
        # The redacted request blobs keep only the JWT header: the forgery is alg:none.
        sent_auth = {role: json.loads(store.get_evidence_blob(
            _execution_event(proof, aid)["data"]["request_blob"]))["headers"]["Authorization"]
            for role, aid in roles.items()}
        self.assertIn('"alg": "none"', sent_auth["attack"])
        self.assertIn('"alg": "HS256"', sent_auth["baseline"])

    def test_missing_control_artifact_stays_a_candidate(self):
        run_id, proof = self._run(_NoControlJwt)
        self.assertFalse(proof["legacy"])
        self.assertEqual(proof["control_artifact_ids"], [])
        self.assertFalse(stored_proof_artifacts_resolve(proof))
        self._assert_candidate(run_id, proof, self.url, "jwt")

    def test_missing_control_blob_stays_a_candidate(self):
        run_id, proof = self._run()
        blob = _execution_event(proof, proof["control_artifact_ids"][0])["data"]["response_blob"]
        conn = sqlite3.connect(store._DB_PATH)
        try:
            conn.execute("DELETE FROM evidence_blobs WHERE sha256 = ?", (blob,))
            conn.commit()
        finally:
            conn.close()
        self.assertFalse(stored_proof_artifacts_resolve(proof))
        self._assert_candidate(run_id, proof, self.url, "jwt")

    def test_corrupted_attack_blob_stays_a_candidate(self):
        run_id, proof = self._run()
        blob = _execution_event(proof, proof["attack_artifact_id"])["data"]["request_blob"]
        conn = sqlite3.connect(store._DB_PATH)
        try:
            conn.execute("UPDATE evidence_blobs SET data = ? WHERE sha256 = ?", (b"{}", blob))
            conn.commit()
        finally:
            conn.close()
        self.assertFalse(stored_proof_artifacts_resolve(proof))
        self._assert_candidate(run_id, proof, self.url, "jwt")

    def test_control_from_another_case_stays_a_candidate(self):
        run_id, proof = self._run(_CrossCaseJwt)
        control = proof["control_artifact_ids"][0]
        self.assertTrue(control)
        # The exchange is real and intact, just recorded under another case.
        foreign = [e for e in store.ledger_events_for("another-case")
                   if (e["data"] or {}).get("artifact_id") == control]
        self.assertEqual([e["data"]["outcome"] for e in foreign], ["ok"])
        self.assertFalse(stored_proof_artifacts_resolve(proof))
        self._assert_candidate(run_id, proof, self.url, "jwt")

    def test_two_roles_naming_one_exchange_stays_a_candidate(self):
        run_id, proof = self._run()
        reused = dict(proof, control_artifact_ids=[proof["attack_artifact_id"]])
        self.assertFalse(stored_proof_artifacts_resolve(reused))
        self._assert_candidate(run_id, reused, self.url, "jwt", lookup=[reused])

    def test_rejected_forgeries_record_no_counted_proof(self):
        self.target.close()
        self.target = _Target(lambda m, p, h, b: (401, '{"error": "bad signature"}')
                              if h.get("authorization", "").split()[-1:] != [_JWT] else (200, _PROFILE))
        self.url = self.target.origin + "/api/me"
        exchange = _exchange(self.url, {"Authorization": f"Bearer {_JWT}"})
        run_id, reports, proofs = self._confirm(
            "jwt_forge", JwtForgeValidator(allowed_hosts=list(self.HOSTS), timeout=5.0),
            _finding("jwt"), exchange)
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))
        self.assertEqual([p["verdict"] for p in proofs], ["inconclusive"])
        self.assertEqual(self._accounting(run_id, proofs[0], self.url, "jwt")["counts"]["vulnerabilities"], 0)


def _query(path: str) -> dict:
    return dict(parse_qsl(urlsplit(path).query, keep_blank_values=True))


def _catalog(method, path, headers, body):
    """A category filter whose WHERE clause takes the parameter unquoted: the
    tautology lists every product, the contradiction lists none."""
    category = _query(path).get("category", "")
    if "'1'='1'" in category:
        rows = [{"id": i, "name": f"product-{i}"} for i in range(40)]
    elif "'1'='2'" in category:
        rows = []
    else:
        rows = [{"id": 1, "name": "product-1"}]
    return 200, json.dumps({"category": category, "rows": rows})


def _shell(method, path, headers, body):
    """A stock check that passes `host` to a shell: `;printf A%s B` prints AB.
    Anything else is reflected as given (the literal pieces, never joined)."""
    host = _query(path).get("host", "")
    if ";printf " in host:
        fmt, _, arg = host.rpartition(";printf ")[2].partition(" ")
        return 200, json.dumps({"output": fmt.replace("%s", arg, 1)})
    return 200, json.dumps({"output": f"pinged {host}"})


def _login(method, path, headers, body):
    """A login that answers a known account and an unknown one differently."""
    fields = json.loads(body or "{}")
    if fields.get("username") == "alice":
        return 401, '{"error": "wrong password"}'
    return 404, '{"error": "no such user"}'


class SqlBooleanProofTests(_ProofCallerBase):
    def test_boolean_differential_is_a_counted_vulnerability(self):
        target = _Target(_catalog)
        self.addCleanup(target.close)
        url = target.origin + "/filter?category=Pets"
        validator = SqlmapValidator(allowed_hosts=list(self.HOSTS), quick_only=True)
        run_id, reports, proofs = self._confirm("sqlmap", validator, _finding("sqli"), _exchange(url))
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        proof = self._stored_proof(proofs)
        self._assert_counted(run_id, proof, url, "sqli")
        rows = {role: len(json.loads(json.loads(store.get_evidence_blob(
            _execution_event(proof, aid)["data"]["response_blob"]))["body"])["rows"])
            for role, aid in (("baseline", proof["baseline_artifact_id"]),
                              ("attack", proof["attack_artifact_id"]),
                              ("control", proof["control_artifact_ids"][0]))}
        self.assertEqual(rows, {"baseline": 1, "attack": 40, "control": 0})


class CommandInjectionProofTests(_ProofCallerBase):
    def _run(self, respond):
        target = _Target(respond)
        self.addCleanup(target.close)
        url = target.origin + "/stock?host=127.0.0.1"
        validator = CommandInjectionValidator(allowed_hosts=list(self.HOSTS), timeout=5.0,
                                              oob_callbacks_enabled=False)
        run_id, reports, proofs = self._confirm(
            "command_injection", validator, _finding("command_injection"), _exchange(url))
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        return run_id, url, self._stored_proof(proofs)

    def test_in_band_marker_is_a_counted_vulnerability(self):
        run_id, url, proof = self._run(_shell)
        self._assert_counted(run_id, proof, url, "command_injection")

    def test_control_that_also_shows_the_marker_does_not_confirm(self):
        # A target that joins the pieces without any shell syntax: the control
        # shows the same marker, so the attack's marker proves nothing (BM-2;
        # before it, this confirmed with an unnamed control as a candidate).
        def joins_anything(method, path, headers, body):
            host = _query(path).get("host", "")
            if "%s " in host:
                fmt, _, arg = host.rpartition(";printf ")[2].partition(" ")
                return 200, json.dumps({"output": fmt.replace("%s", arg, 1)})
            return 200, json.dumps({"output": f"pinged {host}"})
        target = _Target(joins_anything)
        self.addCleanup(target.close)
        validator = CommandInjectionValidator(allowed_hosts=list(self.HOSTS), timeout=5.0,
                                              oob_callbacks_enabled=False)
        _run_id, reports, _proofs = self._confirm(
            "command_injection", validator, _finding("command_injection"),
            _exchange(target.origin + "/stock?host=127.0.0.1"))
        self.assertNotIn("confirmed", [r.status for r in reports], _verdicts(reports))


class UsernameEnumerationProofTests(_ProofCallerBase):
    def test_status_oracle_is_a_counted_vulnerability(self):
        target = _Target(_login)
        self.addCleanup(target.close)
        url = target.origin + "/login"
        exchange = _json_exchange(url, "POST", '{"username": "alice", "password": "pw"}')
        validator = AuthSequenceValidator(allowed_hosts=list(self.HOSTS), timeout=5.0)
        run_id, reports, proofs = self._confirm(
            "auth_sequence", validator, _finding("username_enumeration"), exchange)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        proof = self._stored_proof(proofs)
        self._assert_counted(run_id, proof, url, "username_enumeration")


def _request_blob(proof, artifact_id) -> dict:
    """The redacted request an exchange artifact recorded."""
    return json.loads(store.get_evidence_blob(_execution_event(proof, artifact_id)["data"]["request_blob"]))


def _sent_text(proof, artifact_id) -> str:
    """What that request carried, url-decoded so a query and a body read alike."""
    return unquote(json.dumps(_request_blob(proof, artifact_id)))


class _HitCollab:
    """OOB collaborator stub: every token reports a callback."""

    def __init__(self):
        self._n = 0

    def token(self):
        self._n += 1
        return f"oob{self._n}"

    def url(self, token):
        return f"http://collab.test/{token}"

    async def wait_for_hit(self, token, timeout=6.0):
        return True


def _send_failures() -> dict:
    """The ways a proof send can go wrong: no answer, or an exception."""
    return {"no answer": None, "ValueError": ValueError("bad proof url"),
            "ConnectError": httpx.ConnectError("refused"), "RuntimeError": RuntimeError("boom")}


class _ControlFailsSsrf(SsrfValidator):
    """Defect injection: the proof send named by `fails_on` ("proof control" unless
    a subclass says "proof baseline") gets no answer (failure None) or fails the
    way `failure` says."""
    fails_on = "proof control"
    failure = None

    async def _send(self, method, url, headers, body, unsent=None, label=""):
        if label == self.fails_on:
            if self.failure is not None:
                raise self.failure
            return None
        return await super()._send(method, url, headers, body, unsent, label)


class SsrfProofTests(_ProofCallerBase):
    """The out-of-band path inside a real run: the callback is the verdict; the
    original request (baseline), the callback URL (attack) and the same parameter
    at a closed loopback port (control) are the exchanges it names."""

    def setUp(self):
        super().setUp()
        self.target = _Target(lambda method, path, headers, body: (200, '{"fetched": true}'))
        self.addCleanup(self.target.close)

    def _exchange_for(self, where):
        if where == "body":
            return _json_exchange(self.target.origin + "/fetch", "POST",
                                  '{"url": "http://example.com/a", "note": "x"}')
        return _exchange(self.target.origin + "/fetch?url=http%3A%2F%2Fexample.com%2Fa&note=x")

    def _run(self, where, validator_cls=SsrfValidator, **kwargs):
        exchange = self._exchange_for(where)
        validator = validator_cls(allowed_hosts=list(self.HOSTS), timeout=5.0,
                                  collaborator=_HitCollab())
        run_id, reports, proofs = self._confirm(
            "ssrf", validator, _finding("ssrf"), exchange, **kwargs)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        return run_id, exchange, self._stored_proof(proofs)

    def _assert_counted_ssrf(self, where):
        run_id, exchange, proof = self._run(where)
        self._assert_counted(run_id, proof, exchange.url, "ssrf")
        sent = {role: _sent_text(proof, aid) for role, aid in (
            ("baseline", proof["baseline_artifact_id"]), ("attack", proof["attack_artifact_id"]),
            ("control", proof["control_artifact_ids"][0]))}
        # Each role is the send it is named for, recorded under this case.
        self.assertIn("example.com/a", sent["baseline"])
        self.assertIn("collab.test/oob", sent["attack"])
        self.assertNotIn("collab.test", sent["control"])
        self.assertIn("127.0.0.1:1/", sent["control"])
        if where == "body":
            # Every proof send replays the attack's headers: the same body type, not `{}`.
            types = [_request_blob(proof, aid)["headers"].get("Content-Type")
                     for aid in (proof["baseline_artifact_id"], proof["attack_artifact_id"],
                                 proof["control_artifact_ids"][0])]
            self.assertEqual(types, ["application/json"] * 3)

    def test_body_parameter_confirmation_is_a_counted_vulnerability(self):
        self._assert_counted_ssrf("body")

    def test_query_parameter_confirmation_is_a_counted_vulnerability(self):
        self._assert_counted_ssrf("query")

    def test_a_control_that_fails_leaves_the_verdict_and_names_no_control(self):
        for where in ("body", "query"):
            for label, failure in _send_failures().items():
                with self.subTest(where=where, failure=label):
                    validator_cls = type("_Failing", (_ControlFailsSsrf,), {"failure": failure})
                    run_id, exchange, proof = self._run(where, validator_cls)
                    self.assertEqual(proof["verdict"], "confirmed")
                    self.assertEqual(proof["control_artifact_ids"], [])
                    self.assertTrue(proof["baseline_artifact_id"] and proof["attack_artifact_id"])
                    self.assertFalse(stored_proof_artifacts_resolve(proof))
                    self._assert_candidate(run_id, proof, exchange.url, "ssrf")

    def test_a_control_the_run_refuses_stays_unnamed(self):
        # Two in-band reads, the callback send and the baseline spend the budget;
        # the run transport refuses the control, the real refusal path.
        run_id, exchange, proof = self._run("query", max_requests=4)
        self.assertEqual(len(self.target.seen), 4, self.target.seen)
        self.assertEqual(proof["control_artifact_ids"], [])
        self._assert_candidate(run_id, proof, exchange.url, "ssrf")

    def test_a_baseline_that_fails_leaves_the_verdict_and_names_no_baseline(self):
        for where in ("body", "query"):
            for label, failure in _send_failures().items():
                with self.subTest(where=where, failure=label):
                    validator_cls = type("_FailingBaseline", (_ControlFailsSsrf,),
                                         {"fails_on": "proof baseline", "failure": failure})
                    run_id, exchange, proof = self._run(where, validator_cls)
                    self.assertEqual(proof["verdict"], "confirmed")
                    self.assertEqual(proof["baseline_artifact_id"], "")
                    self.assertTrue(proof["attack_artifact_id"])
                    self.assertEqual(len(proof["control_artifact_ids"]), 1)
                    self.assertFalse(stored_proof_artifacts_resolve(proof))
                    self._assert_candidate(run_id, proof, exchange.url, "ssrf")


class SsrfProofSendTests(unittest.TestCase):
    """_proof_send is best effort for failures, never for cancellation."""

    def _proof_send_with(self, send):
        validator = SsrfValidator(allowed_hosts=["127.0.0.1"], timeout=1.0)
        validator._send = send
        return asyncio.run(validator._proof_send("GET", "http://127.0.0.1:1/", {}, "", "proof control"))

    def test_cancellation_propagates(self):
        async def cancelled(*args, **kwargs):
            raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            self._proof_send_with(cancelled)

    def test_any_other_failure_is_swallowed_and_an_answer_passes_through(self):
        async def boom(*args, **kwargs):
            raise RuntimeError("boom")

        async def answered(*args, **kwargs):
            return SentAnswer((200, "ok"), "art-1")
        self.assertIsNone(self._proof_send_with(boom))
        self.assertEqual(artifact_id_of(self._proof_send_with(answered)), "art-1")


class ArtifactIdOfTests(_ProofCallerBase):
    def test_a_send_that_was_not_answered_names_nothing(self):
        target = _Target(lambda *_: (200, "{}"))
        self.addCleanup(target.close)

        async def go():
            async with RunContext.create(allowed_hosts=list(self.HOSTS)) as run:
                execute = run.executor().execute
                return [await execute(TypedRequest("GET", url), capability="t") for url in (
                    target.origin + "/a",  # sent and answered
                    "http://127.0.0.1:1/",  # connection refused: recorded as an error
                    "http://elsewhere.invalid/")]  # out of scope: never sent
        answered, errored, refused = asyncio.run(go())
        self.assertEqual((answered.outcome, errored.outcome, refused.outcome),
                         ("ok", "error", "out_of_scope"))
        self.assertTrue(answered.artifact_id)
        self.assertEqual(artifact_id_of(answered), answered.artifact_id)
        # The errored send did record an exchange, yet it is not one the verdict
        # can rest on.
        self.assertTrue(errored.artifact_id, "the premise: an error outcome carries an id")
        self.assertEqual(artifact_id_of(errored), "")
        self.assertEqual(artifact_id_of(refused), "")

    def test_outcome_ok_decides_whether_an_outcome_is_named(self):
        artifact = SimpleNamespace(artifact_id="art-7")
        self.assertEqual(artifact_id_of(ExecutionOutcome("ok", artifact=artifact)), "art-7")
        for outcome in ("blocked", "error", "out_of_scope", "budget_exhausted", "cancelled"):
            with self.subTest(outcome=outcome):
                refused = ExecutionOutcome(outcome, artifact=artifact)
                self.assertEqual(refused.artifact_id, "art-7")
                self.assertEqual(artifact_id_of(refused), "")
        # A plain id is passed through, and a result names only the answered sends.
        self.assertEqual(artifact_id_of("art-9"), "art-9")
        result = ValidationResult("v", "confirmed", "x").with_artifacts(
            baseline=ExecutionOutcome("blocked", artifact=artifact), attack="art-1",
            controls=[ExecutionOutcome("error", artifact=artifact),
                      ExecutionOutcome("ok", artifact=SimpleNamespace(artifact_id="art-2"))])
        self.assertEqual((result.baseline_artifact_id, result.attack_artifact_id,
                          result.control_artifact_ids), ("", "art-1", ("art-2",)))


class _SendingValidator(Validator):
    """A leg that sends three real exchanges through the run it is dispatched in
    and names them as its baseline, attack and control."""
    name = "sender"
    active = True

    def __init__(self, origin):
        self.origin = origin
        self.runs = 0

    async def validate(self, finding, exchange):
        self.runs += 1
        sent = [await self.run_context.executor().execute(
            TypedRequest("GET", f"{self.origin}/{role}"), capability=self.name)
            for role in ("baseline", "attack", "control")]
        return ValidationResult(self.name, "confirmed", "xss", confidence=0.9, confirmed=True,
                                summary="sent").with_artifacts(
            baseline=sent[0], attack=sent[1], controls=[sent[2]])


def _executions(case_ref) -> dict:
    """artifact id -> the execution event recorded for it under this case."""
    return {(e["data"] or {}).get("artifact_id"): e for e in store.ledger_events_for(case_ref)
            if e["event_type"] == "execution"}


def _named(result) -> set:
    return {result.baseline_artifact_id, result.attack_artifact_id, *result.control_artifact_ids}


class ConfirmationCacheProofTests(_ProofCallerBase):
    """A cache hit for another case must not hand it the first case's exchanges:
    they were recorded under the first case and do not resolve for this one."""

    def _drive(self, steps):
        """Run the steps (each (exchange, case_ref)) through one real cache, in one
        entered run, with a validator that really sends. Returns the results."""
        target = _Target(lambda *_: (200, "{}"))
        self.addCleanup(target.close)
        validator = _SendingValidator(target.origin)

        async def go():
            async with RunContext.create(allowed_hosts=list(self.HOSTS), max_requests=100) as run:
                cache = _ConfirmationCache(run, lambda cls, exchange: f"derived-{cls}")
                return [await cache.validate(validator, _finding("xss"), exchange, case_ref=ref)
                        for exchange, ref in steps]
        return validator, asyncio.run(go()), target

    def test_a_hit_for_another_case_is_a_copy_without_the_first_cases_exchanges(self):
        exchange = _exchange("http://127.0.0.1/page")
        validator, (first, same, other), _ = self._drive(
            [(exchange, "case-a"), (exchange, "case-a"), (exchange, "case-b")])
        self.assertEqual(validator.runs, 1, "the hits must not send again")
        named = _named(first)
        self.assertEqual(len(named), 3)
        self.assertTrue(named <= set(_executions("case-a")))
        # Same case: the cached result as it is, its exchanges intact.
        self.assertIs(same, first)
        self.assertEqual(_named(same), named)
        # Another case: a copy that names nothing, the original untouched.
        self.assertIsNot(other, first)
        self.assertEqual((other.baseline_artifact_id, other.attack_artifact_id,
                          other.control_artifact_ids), ("", "", ()))
        self.assertEqual(_named(first), named)
        self.assertEqual(len(first.control_artifact_ids), 1)
        # E4: the copy keeps the status and confidence but is not a confirmation (the
        # proof belongs to case-a) and says which case covered it.
        self.assertEqual((other.status, other.confidence), (first.status, first.confidence))
        self.assertTrue(first.confirmed)
        self.assertFalse(other.confirmed)
        self.assertTrue(other.summary.startswith("covered by case-a "), other.summary)
        self.assertTrue(other.summary.endswith(first.summary), other.summary)
        # Nothing was recorded for the other case, and a proof built from the copy
        # carries no exchanges, so it stays legacy (a candidate).
        self.assertFalse(named & set(_executions("case-b")))
        self.assertEqual(proof_artifact_kwargs(other), {})
        self.assertEqual(proof_artifact_kwargs(first)["control_artifact_ids"], first.control_artifact_ids)

    def test_the_default_case_is_the_one_a_miss_derives(self):
        exchange = _exchange("http://127.0.0.1/page")
        validator, (first, same, other), _ = self._drive(
            [(exchange, None), (exchange, "derived-xss"), (exchange, "case-b")])
        self.assertEqual(validator.runs, 1)
        named = _named(first)
        # The miss ran under the derived case, so that is where its exchanges live.
        self.assertTrue(named <= set(_executions("derived-xss")))
        self.assertIs(same, first)
        self.assertEqual(_named(other), {""})
        # And a hit that also derives its case keeps them.
        _, (first_again, derived_hit), _ = self._drive([(exchange, None), (exchange, None)])
        self.assertIs(derived_hit, first_again)
        self.assertEqual(len(_named(derived_hit)), 3)

    def test_a_different_key_is_a_miss_that_runs_and_names_its_own_exchanges(self):
        validator, (one, two), _ = self._drive(
            [(_exchange("http://127.0.0.1/one"), "case-a"), (_exchange("http://127.0.0.1/two"), "case-b")])
        self.assertEqual(validator.runs, 2)
        self.assertEqual(len(_named(one) | _named(two)), 6)
        self.assertTrue(_named(two) <= set(_executions("case-b")))
        self.assertFalse(_named(two) & set(_executions("case-a")))


def _redirect_by_next(method, path, headers, body):
    """Sends the visitor wherever `next` says: the open redirect."""
    return 302, "", {"Location": _query(path).get("next", "/")}


def _always_to_sentinel(method, path, headers, body):
    """Redirects every request off-origin whatever the parameter says."""
    return 302, "", {"Location": f"https://{_SENTINEL_HOST}/landing"}


class OpenRedirectProofTests(_ProofCallerBase):
    def _run(self, respond):
        target = _Target(respond)
        self.addCleanup(target.close)
        url = target.origin + "/go?next=/home"
        run_id, reports, proofs = self._confirm(
            "open_redirect", OpenRedirectValidator(allowed_hosts=list(self.HOSTS), timeout=5.0),
            _finding("open_redirect"), _exchange(url))
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        return run_id, url, self._stored_proof(proofs)

    def test_on_origin_control_makes_a_counted_vulnerability(self):
        run_id, url, proof = self._run(_redirect_by_next)
        self._assert_counted(run_id, proof, url, "open_redirect")
        self.assertIn("/query-next", _sent_text(proof, proof["control_artifact_ids"][0]))

    def test_control_that_also_redirects_to_the_sentinel_is_not_named(self):
        # The redirect does not depend on the parameter: the control shows it too,
        # so it proves nothing and the proof stays a candidate.
        run_id, url, proof = self._run(_always_to_sentinel)
        self.assertEqual(proof["control_artifact_ids"], [])
        self.assertTrue(proof["baseline_artifact_id"] and proof["attack_artifact_id"])
        self._assert_candidate(run_id, proof, url, "open_redirect")


def _cors_answer(method, path, headers, body, *, null=False, random="none", evil=False, anyone=False):
    """The ACAO this target grants each origin: "null" when `null`; a random
    control origin per `random` (none | reflect | wildcard); the probe origin when
    `evil`; every origin when `anyone`."""
    origin = headers.get("origin", "")
    allow = ""
    if origin == "null":
        allow = "null" if null or anyone else ""
    elif origin.endswith(".cors-control.invalid"):
        allow = {"none": "", "reflect": origin, "wildcard": "*"}[random]
        allow = origin if anyone else allow
    elif origin == "https://evil-attacker.com":
        allow = origin if evil or anyone else ""
    if not allow:
        return 200, "{}", {}
    return 200, "{}", {"Access-Control-Allow-Origin": allow, "Access-Control-Allow-Credentials": "true"}


class CorsProofTests(_ProofCallerBase):
    def _run(self, **policy):
        target = _Target(lambda method, path, headers, body: _cors_answer(
            method, path, headers, body, **policy))
        self.addCleanup(target.close)
        url = target.origin + "/api/me"
        run_id, reports, proofs = self._confirm(
            "cors", CorsValidator(allowed_hosts=list(self.HOSTS), timeout=5.0),
            _finding("cors"), _exchange(url))
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        return run_id, url, self._stored_proof(proofs)

    def test_null_origin_with_an_ungranted_random_origin_is_a_counted_vulnerability(self):
        run_id, url, proof = self._run(null=True)
        self._assert_counted(run_id, proof, url, "cors")
        origins = {role: _request_blob(proof, aid)["headers"].get("Origin")
                   for role, aid in (("baseline", proof["baseline_artifact_id"]),
                                     ("attack", proof["attack_artifact_id"]),
                                     ("control", proof["control_artifact_ids"][0]))}
        self.assertEqual(origins["attack"], "null")
        self.assertIsNone(origins["baseline"])
        self.assertTrue(origins["control"].endswith(".cors-control.invalid"), origins)

    def test_null_origin_with_a_granted_random_origin_names_no_control(self):
        # The server grants every origin, so "null" being granted is not the finding
        # the proof is about: the control shows the grant is not specific.
        for random in ("reflect", "wildcard"):
            with self.subTest(random=random):
                run_id, url, proof = self._run(null=True, random=random)
                self.assertEqual(proof["control_artifact_ids"], [])
                self.assertTrue(proof["baseline_artifact_id"] and proof["attack_artifact_id"])
                self._assert_candidate(run_id, proof, url, "cors")

    def test_origin_reflection_keeps_its_rule(self):
        # Reflected for the random origin too: any origin, so the control is named.
        run_id, url, proof = self._run(anyone=True)
        self._assert_counted(run_id, proof, url, "cors")
        # Reflected for the probe origin only: one origin, so the control is not.
        run_id, url, proof = self._run(evil=True)
        self.assertEqual(proof["control_artifact_ids"], [])
        self._assert_candidate(run_id, proof, url, "cors")


class _Interleaved(Validator):
    """A leg that rendezvous with its sibling before each of its three sends, so
    the two jobs' sends are in flight together, and names what it sent."""
    name = "interleaved"
    active = True

    def __init__(self, origin, classes):
        self.origin = origin
        self.classes = classes
        self._arrived: dict[tuple, asyncio.Event] = {}
        self.order: list[tuple] = []

    def applies(self, finding, exchange):
        return True

    def _event(self, phase, cls):
        return self._arrived.setdefault((phase, cls), asyncio.Event())

    async def _send(self, cls, phase):
        self._event(phase, cls).set()
        for other in self.classes:
            if other != cls:
                await asyncio.wait_for(self._event(phase, other).wait(), 10)
        self.order.append((phase, cls, current_case_ref()))
        return await self.run_context.executor().execute(
            TypedRequest("GET", f"{self.origin}/{cls}/{phase}"), capability=self.name)

    async def validate(self, finding, exchange):
        cls = finding.vulnerability_class
        baseline = await self._send(cls, "baseline")
        attack = await self._send(cls, "attack")
        control = await self._send(cls, "control")
        return ValidationResult(self.name, "confirmed", cls, confidence=0.9, confirmed=True,
                                summary=cls).with_artifacts(
            baseline=baseline, attack=attack, controls=[control])


class ConcurrentCasesProofTests(_ProofCallerBase):
    """Two validator jobs for two cases run together through the path
    _validate_findings takes (bounded_gather over _in_case jobs); each proof names
    only the exchanges its own job sent, recorded under its own case."""
    CLASSES = ("sqli", "xss")

    def _run(self, *, defect=None):
        target = _Target(lambda *_: (200, "{}"))
        self.addCleanup(target.close)
        validator = _Interleaved(target.origin, self.CLASSES)
        url = target.origin + "/page"
        if defect is not None:
            patcher = patch.object(Orchestrator, "_in_case", staticmethod(defect))
            patcher.start()
            self.addCleanup(patcher.stop)
        run_id, reports, proofs = self._confirm(
            "interleaved", validator, _finding(self.CLASSES[0]), _exchange(url),
            more_findings=[_finding(c) for c in self.CLASSES[1:]])
        self.assertEqual(sorted(r.status for r in reports), ["confirmed"] * len(self.CLASSES))
        self.assertEqual(len(proofs), len(self.CLASSES))
        return run_id, url, validator, {p["case"]["check_id"]: self._stored(p) for p in proofs}

    def _stored(self, proof):
        stored = [p for p in store.proofs_for_case(proof["case"]["case_id"])
                  if p["proof_id"] == proof["proof_id"]]
        self.assertEqual(len(stored), 1, "the proof was not persisted")
        return stored[0]

    def _counts(self, run_id, url, by_class):
        """The accounting of both confirmed findings together (they share the
        exchange's url, so each finding's instances include its sibling's)."""
        findings = [{"confirmed": True, "case_id": p["case"]["case_id"], "proof_id": p["proof_id"],
                     "url": url, "vulnerability_class": cls} for cls, p in by_class.items()]
        return confirmed_issue_accounting(
            findings, run_id, store.proofs_for_case, run_proofs=store.proofs_for_run(run_id),
            artifact_resolver=stored_proof_artifacts_resolve)["counts"]

    def test_each_proof_names_only_exchanges_recorded_under_its_own_case(self):
        run_id, url, validator, by_class = self._run()
        self.assertEqual(set(by_class), set(self.CLASSES))
        cases = {cls: proof["case"]["case_id"] for cls, proof in by_class.items()}
        self.assertEqual(len(set(cases.values())), 2)
        # The two jobs really overlapped: every phase had both in flight, and each
        # send ran inside its own case's scope.
        self.assertEqual(len(validator.order), 6)
        self.assertEqual({(phase, cls, case) for phase, cls, case in validator.order},
                         {(phase, cls, cases[cls]) for phase in ("baseline", "attack", "control")
                          for cls in self.CLASSES})
        named = {}
        for cls, proof in by_class.items():
            self.assertTrue(proof["executed"] and not proof["legacy"], cls)
            self.assertTrue(stored_proof_artifacts_resolve(proof), cls)
            ids = [proof["baseline_artifact_id"], proof["attack_artifact_id"],
                   *proof["control_artifact_ids"]]
            self.assertEqual(len(set(ids)), 3, ids)
            named[cls] = set(ids)
            for role, aid in zip(("baseline", "attack", "control"), ids):
                event = _execution_event(proof, aid)
                self.assertEqual(event["case_ref"], cases[cls])
                # It is the request this class's own job made, not its sibling's.
                self.assertEqual(urlsplit(_request_blob(proof, aid)["url"]).path, f"/{cls}/{role}")
        self.assertFalse(named["sqli"] & named["xss"])
        for cls, other in (("sqli", "xss"), ("xss", "sqli")):
            self.assertFalse(named[cls] & set(_executions(cases[other])), (cls, other))
        counts = self._counts(run_id, url, by_class)
        self.assertEqual((counts["vulnerabilities"], counts["candidate_cases"]), (2, 0), counts)

    def test_without_the_case_scope_neither_proof_resolves(self):
        async def unscoped(case, job):
            return await job
        run_id, url, validator, by_class = self._run(defect=unscoped)
        self.assertEqual(set(by_class), set(self.CLASSES))
        for cls, proof in by_class.items():
            self.assertEqual(proof["verdict"], "confirmed")
            self.assertFalse(stored_proof_artifacts_resolve(proof), cls)
        counts = self._counts(run_id, url, by_class)
        self.assertEqual((counts["vulnerabilities"], counts["candidate_cases"]), (0, 2), counts)


class CaseScopeRecordTests(_ProofCallerBase):
    """The scope binds the record's case; its finding_ref stays the caller's own
    ref, so per-finding reconstruction is unchanged."""

    def test_scope_binds_the_case_and_keeps_the_callers_finding_ref(self):
        target = _Target(lambda *_: (200, "{}"))
        self.addCleanup(target.close)

        async def go():
            async with RunContext.create(allowed_hosts=list(self.HOSTS)) as run:
                with case_scope("case-1"):
                    own = await run.executor().execute(
                        TypedRequest("GET", target.origin + "/a"), capability="t", case_ref="finding-1")
                    bare = await run.executor().execute(
                        TypedRequest("GET", target.origin + "/b"), capability="t")
                return own.artifact_id, bare.artifact_id
        own, bare = asyncio.run(go())

        def placed(ref, artifact_id):
            return [(e["event_type"], e["case_ref"]) for e in store.ledger_events_for(ref)
                    if (e["data"] or {}).get("artifact_id") == artifact_id]
        self.assertEqual(placed("finding-1", own), [("execution", "case-1")])
        self.assertEqual(placed("case-1", own), [])
        self.assertEqual(placed("case-1", bare), [("execution", "case-1")])


class ProofArtifactKwargsTests(unittest.TestCase):
    def test_only_reached_verdicts_that_name_exchanges_declare_execution(self):
        named = dict(baseline="b", attack="a", controls=["c"])
        for status in ("confirmed", "not_confirmed"):
            result = ValidationResult("v", status, "x").with_artifacts(**named)
            self.assertEqual(proof_artifact_kwargs(result),
                             {"executed": True, "baseline_artifact_id": "b",
                              "attack_artifact_id": "a", "control_artifact_ids": ("c",)})
        for status in ("skipped", "error", "inconclusive"):
            self.assertEqual(proof_artifact_kwargs(
                ValidationResult("v", status, "x").with_artifacts(**named)), {})
        self.assertEqual(proof_artifact_kwargs(ValidationResult("v", "confirmed", "x")), {})

    def test_sends_that_never_went_through_a_run_name_nothing(self):
        result = ValidationResult("v", "confirmed", "x").with_artifacts(
            baseline=(200, "body"), attack=SentAnswer((200, "body")), controls=[None, ""])
        self.assertEqual((result.baseline_artifact_id, result.attack_artifact_id,
                          result.control_artifact_ids), ("", "", ()))
        self.assertEqual(artifact_id_of(SentAnswer((200, ""), "art-1")), "art-1")


if __name__ == "__main__":
    unittest.main()
