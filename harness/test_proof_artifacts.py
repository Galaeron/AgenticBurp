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

from harness import store
from harness.assessment_health import confirmed_issue_accounting, stored_proof_artifacts_resolve
from harness.models import AgentReport
from harness.run_context import (_CREDENTIAL_HEADERS, RunContext, ScopePolicy, TypedRequest,
                                 case_scope)
from harness.test_confirmation_soundness_rve import _CallerBase, _finding, _verdicts
from harness.test_default_history_caller import _exchange
from harness.validators.base import (SentAnswer, ValidationResult, artifact_id_of,
                                     proof_artifact_kwargs)
from harness.validators.jwt_forge_validator import JwtForgeValidator


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_JWT = (_b64url(b'{"alg":"HS256","typ":"JWT"}') + "." + _b64url(b'{"sub":"1","role":"user"}')
        + "." + _b64url(b"signature-not-real"))
_GARBAGE_SIG = _b64url(b"not-a-valid-signature-xxxx")
_PROFILE = '{"id": 1, "email": "alice@example.com"}'


class _Target:
    """Owned loopback app. `respond(method, path, headers, body)` returns
    (status, body); headers arrive lower-cased."""

    def __init__(self, respond):
        seen = self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
                headers = {k.lower(): v for k, v in self.headers.items()}
                seen.append((self.command, self.path))
                status, text = respond(self.command, self.path, headers, body)
                data = text.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _serve

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

    def _confirm(self, key, validator, finding, exchange):
        """One validator through _validate_findings inside an entered run, as
        production analyze() does. Returns (run_id, reports, proofs)."""
        orch = self._orch(hosts=self.HOSTS)
        orch.validator_registry.validators = {key: validator}
        gate_config = {"active_enabled": True, "allow_mutating_replay": True}

        async def go():
            async with RunContext.create(allowed_hosts=list(self.HOSTS), max_requests=500,
                                         gate_config=gate_config) as run:
                creds = {k: v for k, v in (exchange.request_headers or {}).items()
                         if k.lower() in _CREDENTIAL_HEADERS}
                if creds:
                    run.sessions.register("captured", "captured", creds, name="captured",
                                          allowed_origins=[ScopePolicy.origin_of(exchange.url)])
                reports, proofs = await orch._validate_findings(
                    exchange, [AgentReport(agent=key, model="fake", findings=[finding])],
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
