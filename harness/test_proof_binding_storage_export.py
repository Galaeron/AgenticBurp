"""I02 batch A: claim/proof binding through real storage and API/Markdown/SARIF export.

test_confirmation_class_binding_caller proves claim-A evidence cannot confirm
claim B at the decision seam, but mocks proof persistence, the oracle gate and
the submission store. Here nothing between the decision and the operator is
mocked: Orchestrator.analyze runs with a canned model and a passive fake
validator, real proof records and findings are written to a temporary SQLite
store, and the API response, stored rows, issue export, SARIF and Markdown are
read back.

One exchange, two claims: A (sqli) is matched directly by a validator that
confirms sqli; B (cleartext_transmission) reaches that same validator only via
the agent-fallback route. A may become confirmed with its own proof; B must
never borrow A's proof, confidence or confirmation. After a simulated restart, a
missing, stale, unresolvable or re-pointed proof must not keep an export "confirmed".
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from harness import cache, evidence_ledger, report_generator, safety_gate, sarif_adapter, store
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.validators.base import ValidationResult

_HARNESS = Path(__file__).resolve().parent
_URL = "http://bind.invalid/api/items/7"   # no query: keeps analyze's shape legs out
_A, _B = "sqli", "cleartext_transmission"


class _Model:
    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._reply(user_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data=self._reply(user_prompt), prompt_tokens=1, completion_tokens=1)

    @staticmethod
    def _reply(user_prompt):
        if f"\nURL: {_URL}\n" not in user_prompt:
            return {"findings": [], "components": []}
        claim = lambda cls, text: {"vulnerability_class": cls, "severity": "medium",
                                   "confidence": 0.5, "summary": text, "evidence": "benign",
                                   "suggested_test": "review", "basis": "derived"}
        return {"findings": [claim(_A, "claim A: id parameter reaches SQL"),
                             claim(_B, "claim B: credentials over cleartext")], "components": []}


class _DirectAndFallback:
    """Passive validator: confirms sqli when matched directly; when the agent
    fallback routes another claim to it, it still reports its own class (sqli)."""
    name = "dual"
    active = False
    run_context = None
    version = "test"
    finding_classes = {_A}

    def applies(self, finding, exchange):
        return finding.vulnerability_class in (_A, "idor")   # "idor" = producing agent token

    def plan(self, finding, exchange):
        return None

    async def validate(self, finding, exchange):
        await asyncio.sleep(0)
        return ValidationResult(self.name, "confirmed", _A, confirmed=True, confidence=0.9,
                                summary="sqli proof (claim A only)", evidence="boolean differential")


def _config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = False
    for k in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    return cfg


class ProofBindingStorageExportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i02a_binding_")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()
        self.response = self._analyze()

    def tearDown(self):
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _analyze(self):
        orch = Orchestrator(_config())
        model = _Model()
        orch.ollama = model
        for agent in getattr(orch.agent_manager, "agents", {}).values():
            agent.ollama = model
        if getattr(orch, "analysis_pipeline", None) is not None:
            orch.analysis_pipeline.ollama_client = model
        orch.validator_registry.validators = {"dual": _DirectAndFallback()}
        exchange = HttpExchange(url=_URL, method="GET", response_status=200,
                                response_body='{"id": 7}')
        return asyncio.run(orch.analyze(exchange, force_agents=["idor"]))

    # --- readers over every operator surface ------------------------------------
    def _api(self, cls):
        return next(f for r in self.response.agent_reports for f in r.findings
                    if f.vulnerability_class == cls)

    def _stored(self, cls):
        return next(f for f in store.all_host_findings(_URL) if f["vulnerability_class"] == cls)

    def _restart(self):
        """Drop in-memory evidence so every read below comes from SQLite."""
        evidence_ledger.reset_default_ledger()

    def _issues(self):
        self._restart()
        return {i["vulnerability_class"]: i for i in report_generator.export_issues_for_host(_URL)}

    def _markdown_counts(self):
        self._restart()
        md = report_generator.generate_report_for_host(_URL)
        line = next(l for l in md.splitlines() if "confirmed finding(s)" in l)
        confirmed = int(line.split("**")[1].split()[0])
        unconfirmed = int(line.split("**")[3].split()[0])
        return confirmed, unconfirmed

    def _sql(self, statement, *params):
        conn = sqlite3.connect(str(store._DB_PATH))
        try:
            conn.execute(statement, params)
            conn.commit()
        finally:
            conn.close()

    # --- positive control and A/B isolation -------------------------------------
    def test_claim_a_keeps_its_own_proof_on_every_surface(self):
        a = self._api(_A)
        self.assertTrue(a.confirmed)
        self.assertTrue(a.proof_id and a.case_id)
        proofs = store.proofs_for_case(a.case_id)
        self.assertTrue(any(p["proof_id"] == a.proof_id and p["verdict"] == "confirmed" for p in proofs))
        self.assertTrue(self._stored(_A)["confirmed"])
        self.assertEqual(self._stored(_A)["proof_status"], "resolved")
        issue = self._issues()[_A]
        self.assertTrue(issue["confirmed"])
        self.assertIn(a.proof_id, json.dumps(issue["proof_references"]))
        self.assertTrue(issue["artifacts"]["replayable"])
        self.assertEqual(self._markdown_counts(), (1, 1))

    def test_claim_b_never_borrows_a_s_proof_on_any_surface(self):
        a, b = self._api(_A), self._api(_B)
        self.assertFalse(b.confirmed)
        self.assertEqual(b.proof_id, "")
        self.assertLess(b.confidence, 0.9)
        stored_b = self._stored(_B)
        self.assertFalse(stored_b["confirmed"])
        self.assertNotEqual(stored_b.get("proof_id"), a.proof_id)
        issues = self._issues()
        self.assertFalse(issues[_B]["confirmed"])
        self.assertNotIn(a.proof_id, json.dumps(issues[_B]))
        sarif = sarif_adapter.export_issues_to_sarif(list(issues.values()))
        b_results = [r for run in sarif["runs"] for r in run["results"]
                     if _B in json.dumps(r) and _A not in r.get("ruleId", "")]
        self.assertTrue(b_results)
        self.assertNotIn(a.proof_id, json.dumps(b_results))

    # --- dangling, unresolvable and re-pointed proofs after a restart -----------
    def _assert_not_confirmed_anywhere(self, *, replayable: bool):
        issue = self._issues()[_A]
        self.assertFalse(issue["confirmed"], "an unresolvable proof kept the export confirmed")
        self.assertEqual(issue["artifacts"]["replayable"], replayable)
        stored = self._stored(_A)
        self.assertFalse(stored["confirmed"])
        self.assertEqual(stored["proof_status"], "unavailable")
        self.assertEqual(self._markdown_counts(), (0, 2))

    def test_missing_proof_record_does_not_keep_confirmation(self):
        self._sql("DELETE FROM proof_records WHERE proof_id = ?", self._api(_A).proof_id)
        self._assert_not_confirmed_anywhere(replayable=False)

    def test_unresolvable_proof_pointer_does_not_keep_confirmation(self):
        self._sql("UPDATE findings SET proof_id = 'proof-that-does-not-exist' WHERE vulnerability_class = ?", _A)
        # The finding's own pointer is broken, so it is no longer confirmed; the
        # case's real recorded attempt still exists and stays replayable evidence.
        self._assert_not_confirmed_anywhere(replayable=True)

    def test_stale_proof_verdict_does_not_keep_confirmation(self):
        # The record still exists but no longer says confirmed: it remains a
        # replayable attempt, yet cannot carry the confirmation.
        self._sql("UPDATE proof_records SET verdict = 'inconclusive' WHERE proof_id = ?",
                  self._api(_A).proof_id)
        self._assert_not_confirmed_anywhere(replayable=True)

    def test_proof_of_another_case_does_not_keep_confirmation(self):
        self._sql("UPDATE findings SET case_id = 'case-of-something-else' WHERE vulnerability_class = ?", _A)
        self._assert_not_confirmed_anywhere(replayable=False)

    # --- fault injection at the decision seam -----------------------------------
    def test_removing_the_binding_check_is_detected(self):
        """With the fallback class binding disabled, B borrows the sqli result; the
        isolation assertions above must catch it."""
        store._DB_PATH = Path(self._tmp) / "state-fault.db"
        with patch("harness.orchestrator_confirm._fallback_result_binds", return_value=True):
            self.response = self._analyze()
        with self.assertRaises(AssertionError):
            self.test_claim_b_never_borrows_a_s_proof_on_any_surface()


if __name__ == "__main__":
    unittest.main()
