"""r5 proof-binding regressions (10 h Juice Shop run, job ec2d4f39326d).

1. A proof confirms only the finding of its own class on an endpoint: the
   id-in-URL idor_read leg used to apply to (and "confirm") every GET finding
   on /rest/basket/<id> -- XSS, missing headers, insecure transmission.
2. Model review annotates a proven finding; it never leaves it "downgraded".
3. A graph-loop proof binds to the stored finding of its class and parameter
   (sqlmap on POST /rest/user/login, email), never to another class/parameter.
4. A jwt_forge confirmation reproduced N-of-N reaches verification_state
   "verified" (its confirmation carries an executed in-probe control).

All sends are faked; no traffic leaves the process.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from harness import cache, safety_gate, store
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _RecordingModel, _config
from harness.validators.base import ValidationResult

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImN1c3RvbWVyIn0.c2lnbmF0dXJl"


def _finding(cls: str, *, verdict=None, confidence=0.9, **kw) -> Finding:
    return Finding(vulnerability_class=cls, confidence=confidence, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived",
                   review_verdict=verdict, **kw)


def _get(url: str, headers=None) -> HttpExchange:
    return HttpExchange(url=url, method="GET", request_headers=dict(headers or {}),
                        response_status=200, response_headers={"Content-Type": "application/json"},
                        response_body='{"id": 7, "total": 10}')


def _confirmed(name: str, cls: str):
    async def validate(self, finding, exchange):
        return ValidationResult(name, "confirmed", cls, confidence=0.9, confirmed=True,
                                summary=f"{name} confirmed")
    return validate


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="r5_binding_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()

    def tearDown(self):
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _orch(self, validators: dict, *, oracle=None) -> Orchestrator:
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["shop.invalid"]
        if oracle is not None:
            cfg["oracle"] = oracle
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        orch.validator_registry.active_enabled = True
        orch.validator_registry.validators = validators
        return orch


class OwnClassBindingTests(_StoreCase):
    """Defect 1 (+ defect 2 at the confirmation site), through _validate_findings."""

    def test_idor_proof_confirms_only_the_access_control_finding(self):
        from harness.validators.idor_read_validator import IdorReadValidator
        orch = self._orch({"idor_read": IdorReadValidator(allowed_hosts=["shop.invalid"])})
        xss = _finding("Cross-Site Scripting (XSS)", verdict="downgraded")
        headers = _finding("Missing Security Headers")
        transport = _finding("Insecure Transmission")
        idor = _finding("Insecure Direct Object Reference (IDOR)", verdict="downgraded")
        reports = [AgentReport(agent="xss", model="m", findings=[xss]),
                   AgentReport(agent="misconfig", model="m", findings=[headers]),
                   AgentReport(agent="auth", model="m", findings=[transport]),
                   AgentReport(agent="idor", model="m", findings=[idor])]
        with patch.object(IdorReadValidator, "validate", new=_confirmed("idor_read", "idor")):
            asyncio.run(orch._validate_findings(
                _get("http://shop.invalid/rest/basket/7", {"Cookie": "s=alice"}), reports))
        self.assertTrue(idor.confirmed)
        self.assertTrue(idor.proof_id)
        for other in (xss, headers, transport):
            self.assertFalse(other.confirmed, other.vulnerability_class)
            self.assertFalse(other.proof_id, other.vulnerability_class)
        # Defect 2: the proven finding is no longer left "downgraded" by the
        # pre-validation critique; the unproven one keeps its demotion.
        self.assertEqual(idor.review_verdict, "validator-confirmed")
        self.assertEqual(xss.review_verdict, "downgraded")


class CritiqueAnnotatesProvenTests(unittest.IsolatedAsyncioTestCase):
    """Defect 2 at the critique stage: annotate a proven finding, never demote it."""

    async def test_critique_cannot_demote_or_reject_a_proven_finding(self):
        from harness.analysis_pipeline import AnalysisPipeline
        from harness.effort import BudgetMode, EffortBudget
        client = MagicMock()
        result = MagicMock()
        result.data = {"reviews": [
            {"index": 0, "verdict": "rejected", "note": "looks benign", "adjusted_confidence": 0.1},
            {"index": 1, "verdict": "downgraded", "note": "weak", "adjusted_confidence": 0.2}]}
        client.chat_json_metered = AsyncMock(return_value=result)
        pipeline = AnalysisPipeline(MagicMock(), EffortBudget(BudgetMode.HARD), MagicMock(),
                                    {"critique": {"enabled": True, "confidence_threshold": 0.5},
                                     "coordinator": {"model": "m"}}, ollama_client=client)
        proven = _finding("jwt", confidence=0.95, confirmed=True, proof_id="p1",
                          case_id="c1", confirmed_by_leg="jwt_forge",
                          verdict="validator-confirmed")
        unproven = _finding("Cross-Site Scripting (XSS)", confidence=0.9)
        report = AgentReport(agent="jwt", model="m", findings=[proven, unproven])
        await pipeline._critique(HttpExchange(url="http://shop.invalid/x", method="GET"), [report])
        self.assertIn(proven, report.findings)
        self.assertEqual(proven.review_verdict, "validator-confirmed")
        self.assertEqual(proven.confidence, 0.95)
        self.assertIn("looks benign", proven.review_note or "")
        # Negative control: an unproven finding is still demoted by review.
        self.assertEqual(unproven.review_verdict, "downgraded")
        self.assertEqual(unproven.confidence, 0.2)


class StoredProofBindingTests(_StoreCase):
    """Defect 3: store.bind_confirmation_proof, the graph loop's binding seam."""

    _URL = "http://shop.invalid/rest/user/login"

    def _post(self) -> HttpExchange:
        return HttpExchange(url=self._URL, method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"email": "a", "password": "b"}', response_status=401)

    def _rows(self):
        return {(r["vulnerability_class"], r["parameter_name"]): r
                for r in store.all_host_findings(self._URL)}

    def _seed(self):
        ex = self._post()
        store.persist_findings(ex, "iterative:auth", [
            _finding("Broken Authentication", confidence=1.0),
            _finding("sqli", confidence=0.35, parameter_location="body", parameter_name="email"),
            _finding("sqli", confidence=0.35, parameter_location="body", parameter_name="password")])
        return ex

    def _proof(self, **kw) -> Finding:
        # A real persisted sqlmap proof: the read side counts a confirmation only
        # while its exact proof record is on file.
        from harness.evidence import ProofRecord, TestCaseRef
        case = TestCaseRef.make(run_id="r5", request_template_id="login", check_id="sqli",
                                parameter_location="body", parameter_name="email")
        pr = ProofRecord.from_validation_result(case=case, validator="sqlmap",
                                                status="confirmed", confirmed=True)
        ok, reason = store.persist_proof_record(pr)
        self.assertTrue(ok, reason)
        base = dict(confirmed=True, proof_id=pr.proof_id, case_id=case.case_id,
                    confirmed_by_leg="sqlmap", verdict="validator-confirmed")
        base.update(kw)
        self.proof_id = pr.proof_id
        return _finding("sqli", confidence=0.95, **base)

    def test_proof_binds_its_class_and_parameter_only(self):
        ex = self._seed()
        n = store.bind_confirmation_proof(
            ex, self._proof(parameter_location="body", parameter_name="email"), "sqlmap")
        self.assertEqual(n, 1)
        rows = self._rows()
        email = rows[("sqli", "email")]
        self.assertTrue(email["confirmed"])
        self.assertEqual(email["proof_id"], self.proof_id)
        self.assertEqual(email["review_verdict"], "validator-confirmed")
        # Negative controls: another parameter, another class stay unconfirmed.
        self.assertFalse(rows[("sqli", "password")]["confirmed"])
        self.assertFalse(rows[("Broken Authentication", "")]["confirmed"])
        self.assertEqual(len(rows), 3, "no extra row when a matching finding exists")

    def test_unmatched_proof_creates_its_own_sqli_finding(self):
        ex = self._post()
        store.persist_findings(ex, "iterative:auth", [_finding("Broken Authentication")])
        store.bind_confirmation_proof(
            ex, self._proof(parameter_location="body", parameter_name="email"), "sqlmap")
        rows = self._rows()
        self.assertFalse(rows[("Broken Authentication", "")]["confirmed"],
                         "a different-class finding must never be relabelled or confirmed")
        created = rows[("sqli", "email")]
        self.assertTrue(created["confirmed"])
        self.assertEqual(created["proof_id"], self.proof_id)

    def test_finding_without_a_proof_binds_nothing(self):
        ex = self._seed()
        self.assertEqual(store.bind_confirmation_proof(
            ex, self._proof(proof_id="", parameter_name="email"), "sqlmap"), 0)
        self.assertFalse(any(r["confirmed"] for r in self._rows().values()))


if __name__ == "__main__":
    unittest.main()
