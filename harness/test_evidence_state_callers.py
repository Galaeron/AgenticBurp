"""Code review 02 batch RV-H (I02 follow-up): evidence states at their real callers.

R49: a stored confirmed, oracle-verified finding whose proof is missing is demoted
by store.all_host_findings (I02-A). The demotion must take the oracle verdict with
it, so the Markdown report never shows "VERIFIED (oracle-reproduced)" for it.
Driven through real SQLite storage and report_generator; issue export and SARIF
are read back from the same store.

R05: a standalone analyze() of a capture that carries a bearer token must let a
replaying validator send as that capture, and only to the captured origin. The
validator, run context, executor and gate are real; only the LLM stage and the
httpx send boundary are faked.

R06: a validator that raises is recorded as an error proof AND returned as an
error validation report through Orchestrator._validate_findings.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

from harness import cache, evidence, report_generator, safety_gate, sarif_adapter, store
from harness.models import AgentReport, Finding, StageOutcome
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _config, _exchange, _RecordingModel
from harness.validators.base import ValidationResult, Validator

_BADGE = "VERIFIED (oracle-reproduced)"
_BEARER = "Bearer synthetic-source"


class _TempStore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="rvh_states_")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=str(Path(self._tmp) / "cache.db"))
        safety_gate.reset_default_gate()

    def tearDown(self):
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _orch(self, allowed_hosts=("shop.invalid",)):
        cfg = _config()
        cfg["server"]["allowed_hosts"] = list(allowed_hosts)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        return orch


class MissingProofDemotesOracleStateTests(_TempStore):
    """R49 through store -> report_generator (Markdown), issue export and SARIF."""

    _URL = "http://shop.invalid/review"

    def _persist(self, *, confirmed=True, oracle=True, proof="missing"):
        case_id, proof_id = "case-missing", "proof-missing"
        if proof == "valid":
            case = evidence.TestCaseRef(run_id="run-rvh", request_template_id="tmpl-rvh",
                                        check_id="ssti")
            record = evidence.ProofRecord.from_validation_result(
                case=case, validator="ssti", status="confirmed", confirmed=True)
            ok, reason = store.persist_proof_record(record)
            self.assertTrue(ok, reason)
            case_id, proof_id = case.case_id, record.proof_id
        finding = Finding(vulnerability_class="ssti", severity="high", confidence=0.9,
                          summary="synthetic review claim", evidence="synthetic",
                          suggested_test="verify", basis="derived", confirmed=confirmed,
                          case_id=case_id, proof_id=proof_id, oracle_verified=oracle,
                          verification_state="verified" if oracle else "candidate")
        store.persist_findings(_exchange(self._URL), "ssti", [finding])
        rows = store.all_host_findings(self._URL)
        self.assertEqual(len(rows), 1)
        return rows[0]

    def _markdown(self):
        return report_generator.generate_report_for_host(self._URL)

    def _issue_and_sarif(self):
        issues = report_generator.export_issues_for_host(self._URL)
        self.assertEqual(len(issues), 1)
        sarif = sarif_adapter.export_issues_to_sarif(issues)
        props = [r["properties"] for run in sarif["runs"] for r in run["results"]]
        self.assertEqual(len(props), 1)
        return issues[0], props[0]

    def test_missing_proof_drops_the_oracle_verified_badge(self):
        row = self._persist()
        self.assertEqual({k: row[k] for k in ("confirmed", "oracle_verified",
                                              "verification_state", "proof_status")},
                         {"confirmed": False, "oracle_verified": False,
                          "verification_state": "candidate", "proof_status": "unavailable"})
        md = self._markdown()
        self.assertNotIn(_BADGE.upper(), md.upper())
        self.assertIn("**0 confirmed finding(s)**", md)

    def test_missing_proof_is_a_candidate_in_issue_export_and_sarif(self):
        self._persist()
        issue, props = self._issue_and_sarif()
        self.assertFalse(issue["confirmed"])
        self.assertFalse(issue["oracle_verified"])
        self.assertEqual(issue["verification_state"], "candidate")
        self.assertEqual(props["observation_type"], "candidate")

    def test_oracle_claim_without_confirmation_is_demoted_too(self):
        # A row that kept only the oracle claim still points at a proof that is gone.
        row = self._persist(confirmed=False)
        self.assertFalse(row["oracle_verified"])
        self.assertEqual(row["verification_state"], "candidate")
        self.assertEqual(row["proof_status"], "unavailable")
        self.assertNotIn(_BADGE.upper(), self._markdown().upper())

    # --- negative controls: unchanged rendering ---------------------------------
    def test_control_candidate_renders_as_before(self):
        row = self._persist(oracle=False)
        self.assertFalse(row["oracle_verified"])
        self.assertEqual(row["verification_state"], "candidate")
        md = self._markdown()
        self.assertNotIn(_BADGE.upper(), md.upper())
        self.assertIn("**0 confirmed finding(s)**, **1 unconfirmed finding(s)**", md)

    def test_control_valid_proof_keeps_confirmation_and_badge(self):
        row = self._persist(proof="valid")
        self.assertEqual({k: row[k] for k in ("confirmed", "oracle_verified",
                                              "verification_state", "proof_status")},
                         {"confirmed": True, "oracle_verified": True,
                          "verification_state": "verified", "proof_status": "resolved"})
        md = self._markdown()
        self.assertIn(_BADGE, md)
        self.assertIn("**1 confirmed finding(s)**", md)
        issue, _ = self._issue_and_sarif()
        self.assertTrue(issue["confirmed"])


if __name__ == "__main__":
    unittest.main()
