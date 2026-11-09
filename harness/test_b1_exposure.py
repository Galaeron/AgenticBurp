"""B1-T1: the sensitive-field exposure oracle (api_security, "excessive data exposure").

Every case drives the production confirmation caller,
``Orchestrator._validate_findings``, through the real registry routing against an
owned loopback JSON service, with two registered sessions (alice, bob). Positive
cases must carry three distinct executed exchange artifacts (baseline, attack,
anonymous control); each has negative controls that must stay not_confirmed.
"""
import asyncio
import itertools
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
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext
from harness.test_default_history_caller import _config, _RecordingModel
from harness.validators.api_security_validator import ApiSecurityValidator


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.received.append(dict(self.headers))
        if not self.headers.get("Authorization"):
            body, status = b'{"error": "login required"}', 401
        else:
            doc = self.server.doc
            body, status = json.dumps(doc() if callable(doc) else doc).encode(), 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _finding(cls="excessive data exposure"):
    return Finding(vulnerability_class=cls, confidence=0.7, summary="secret exposed",
                   evidence="capture", suggested_test="replay", basis="derived")


class ExposureCallerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="b1t1_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        st = global_throttle.throttle.stats()
        prev = (st["rate_per_second"] if st["enabled"] else 0.0, st["burst"] if st["enabled"] else None)
        self.addCleanup(lambda: global_throttle.configure(*prev))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.received = []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.url = self.origin + "/api/accounts"
        self.observe = None

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _orch(self):
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["127.0.0.1"]
        cfg["validators"].update(active_enabled=True)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        global_throttle.configure(0)
        orch.validator_registry.validators = {"api_security": ApiSecurityValidator()}
        return orch, cfg

    def dispatch(self, doc, *, cls="excessive data exposure", caller="Bearer a",
                 register=True, method="GET"):
        """One finding through Orchestrator._validate_findings; returns
        (validation report, proofs, run)."""
        self.server.doc = doc
        self.server.received.clear()
        orch, cfg = self._orch()

        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=50, config=cfg,
                                    gate_config={"active_enabled": True})
            if register:
                run.sessions.register("a", "alice", {"Authorization": "Bearer a"},
                                      allowed_origins=[self.origin])
                run.sessions.register("b", "bob", {"Authorization": "Bearer b"},
                                      allowed_origins=[self.origin])
            if self.observe:
                self.observe(run)
            ex = HttpExchange(url=self.url, method=method,
                              request_headers={"Authorization": caller})
            async with run:
                reports, proofs = await orch._validate_findings(
                    ex, [AgentReport(agent="api_security", model="fake", findings=[_finding(cls)])],
                    run_context=run)
            used = run.budget.used
            await run.aclose()
            return reports, proofs, used

        reports, proofs, used = asyncio.run(go())
        mine = [r for r in reports if r.validator == "api_security_validator"]
        self.assertEqual(len(mine), 1, [(r.validator, r.status) for r in reports])
        return mine[0], proofs, used

    def assert_proof_bound(self, proofs):
        """The confirmation's proof names three distinct exchanges that strict
        accounting resolves to case-bound, executed sends with intact blobs."""
        from harness.assessment_health import stored_proof_artifacts_resolve
        mine = [p for p in proofs if p.get("validator") == "api_security_validator"
                and p.get("attack_artifact_id")]
        self.assertEqual(len(mine), 1, proofs)
        proof = mine[0]
        ids = [proof["baseline_artifact_id"], proof["attack_artifact_id"],
               *proof.get("control_artifact_ids", [])]
        self.assertEqual(len(set(filter(None, ids))), 3, ids)
        self.assertTrue(stored_proof_artifacts_resolve(proof), proof)

    # ------------------------------------------------------------ positives
    def test_self_password_hash_and_totp_secret_confirm(self):
        report, proofs, used = self.dispatch(
            {"id": "alice", "password": "a3f1c8b7a091", "totpSecret": "JBSWY3DPEHPK3PXP"})
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("field=$.password", report.evidence)
        self.assertIn("field=$.totpSecret", report.evidence)
        self.assertIn("owner=alice; reader=alice", report.evidence)
        self.assertNotIn("JBSWY3DPEHPK3PXP", report.evidence)
        self.assertNotIn("a3f1c8b7a091", report.evidence)
        self.assert_proof_bound(proofs)
        # baseline + attack as alice, control anonymous.
        auth = [h.get("Authorization") for h in self.server.received]
        self.assertEqual(auth, ["Bearer a", "Bearer a", None])
        self.assertEqual(used, 3)

    def test_user_listing_exposing_another_users_token_confirms(self):
        report, proofs, _ = self.dispatch(
            {"users": [{"id": "alice", "email": "a@example.test"},
                       {"id": "bob", "email": "b@example.test", "token": "opaque-other-credential"}]})
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("field=$.users[1].token; object=$.users[1]; owner=bob; reader=alice",
                      report.evidence)
        self.assertIn("another account", report.evidence)
        self.assert_proof_bound(proofs)

    def test_owner_bound_by_observed_numeric_account_id(self):
        from harness.self_ownership import SelfOwnership

        def observe(run):
            run.self_ownership = SelfOwnership(persist=False)
            run.self_ownership.observe(source="transport", principal_id="bob", method="GET",
                                       url=self.origin + "/api/me", status=200,
                                       response_body='{"id":17}')
        self.observe = observe
        report, _, _ = self.dispatch([{"id": 16, "name": "x"},
                                      {"id": 17, "apiKey": "84d6e20da53c71aa"}])
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("owner=bob", report.evidence)

    # ---------------------------------------------------- negative controls
    def test_non_secret_and_masked_responses_are_not_confirmed(self):
        for doc in ([{"id": 1, "question": "Your first pet's name?"},
                     {"id": 2, "question": "Password recovery question?"}],
                    {"Password": "Password", "labels": {"password": "Enter password"}},
                    {"id": "alice", "label": {"password": "Enter your password"}},
                    {"id": "bob", "createdAt": "2026-01-01", "updatedAt": "2026-02-01"},
                    {"id": "alice", "password": "********", "totpSecret": None},
                    {"id": "bob", "password": "[redacted]", "totpSecret": "", "token": "xxxxxxxx"},
                    {"id": "bob", "password": "Password", "apiKey": "null"},
                    {"id": "alice", "token": "normal-self-session-token"},
                    {"id": "unknown", "token": "unattributed-token"},
                    {"id": "bob", "passwordHint": "favourite colour"}):
            with self.subTest(doc=doc):
                report, _, _ = self.dispatch(doc)
                self.assertEqual(report.status, "not_confirmed", report.summary)
                self.assertFalse(report.confirmed)
                # Answered and read, not an unsent probe: the oracle itself said no.
                self.assertIn("No unmasked credential secret", report.summary)
                self.assertEqual(len(self.server.received), 1)

    def test_ambiguous_owner_is_not_confirmed(self):
        # One object naming both accounts names no single owner.
        report, _, _ = self.dispatch({"id": "alice", "ownerId": "bob", "token": "opaque-credential"})
        self.assertEqual(report.status, "not_confirmed", report.summary)

    def test_per_response_value_is_not_a_stored_secret(self):
        counter = itertools.count()
        report, _, _ = self.dispatch(lambda: {"id": "bob", "token": f"nonce-{next(counter)}"})
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("changed between two reads", report.summary)

    def test_unregistered_caller_sends_nothing(self):
        report, _, _ = self.dispatch({"id": "alice", "password": "opaque-password"},
                                     caller="Bearer someone-else")
        self.assertEqual(report.status, "skipped", report.summary)
        self.assertEqual(self.server.received, [])

    def test_versioning_and_inventory_stay_agent_only(self):
        for cls in ("api versioning", "improper inventory management"):
            with self.subTest(cls=cls):
                report, _, _ = self.dispatch({"id": "bob", "token": "opaque-credential"}, cls=cls)
                self.assertEqual(report.status, "skipped", report.summary)
                self.assertEqual(self.server.received, [])


if __name__ == "__main__":
    unittest.main()
