"""A sqlmap detection the harness could not reproduce is its own evidence tier.

Through the production confirmation path (Orchestrator._validate_findings in an
entered run, sqlmap's launch replaced by recorded output, an owned 127.0.0.1
fixture), then the real accounting, issue export and Markdown report over the
stored proof and finding. The negative controls are the reproduced path (a real
confirmation) and the unreproduced path with the structured marker patched out
(the old behaviour: a generic candidate).
"""
import unittest
from unittest.mock import patch

from harness import store
from harness.assessment_health import (confirmed_issue_accounting, confirmed_issue_inventory,
                                       stored_proof_artifacts_resolve)
from harness.models import HttpExchange
from harness.report_generator import generate_markdown_report, issue_exports
from harness.test_confirmation_soundness_rve import _finding
from harness.test_proof_artifacts import _ProofCallerBase, _Target
from harness.test_sqlmap_points import _JSON_Q_BOOLEAN, _search_app, _sqlmap_says
from harness.validators.sqlmap import SqlmapValidator


class ToolReportedAccountingTests(_ProofCallerBase, unittest.TestCase):

    def _run(self, blind):
        target = _Target(_search_app(blind=blind))
        self.addCleanup(target.close)
        exchange = HttpExchange(
            url=target.origin + "/search", method="POST",
            request_headers={"Content-Type": "application/json"}, request_body='{"q": "x", "r": "y"}',
            response_status=200, response_body='{"rows": []}')
        cm = _sqlmap_says(_JSON_Q_BOOLEAN)
        cm.start()
        self.addCleanup(cm.stop)
        finding = _finding("sqli")
        run_id, reports, proofs = self._confirm(
            "sqlmap", SqlmapValidator(allowed_hosts=list(self.HOSTS)), finding, exchange)
        self.assertEqual([r.status for r in reports], ["confirmed"])
        self.assertTrue(finding.confirmed and finding.proof_id and finding.case_id)
        # The stored finding row, as analyze() persists a validated finding.
        store.persist_findings(exchange, "sqlmap", [finding])
        rows = store.all_host_findings(exchange.url)
        self.assertEqual(len(rows), 1, rows)
        return exchange, run_id, rows

    def _surfaces(self, exchange, run_id, rows):
        accounting = confirmed_issue_accounting(
            rows, run_id, store.proofs_for_case, run_proofs=store.proofs_for_run(run_id),
            artifact_resolver=stored_proof_artifacts_resolve)
        inventory = confirmed_issue_inventory(rows, run_id, store.proofs_for_case)
        exports = issue_exports(rows, proofs_by_case={
            r["case_id"]: store.proofs_for_case(r["case_id"]) for r in rows if r["case_id"]})
        report = generate_markdown_report(store.host_of(exchange.url), rows)
        return accounting, inventory, exports, report

    def test_unreproduced_sqlmap_proof_is_tool_reported_on_every_surface(self):
        exchange, run_id, rows = self._run(blind=())        # the fixture ignores q
        proof = store.proofs_for_run(run_id)[0]
        self.assertEqual(proof["evidence_source"], "tool_reported")   # persisted, structured
        self.assertEqual(rows[0].get("evidence_source"), "tool_reported")
        accounting, inventory, exports, report = self._surfaces(exchange, run_id, rows)
        counts = accounting["counts"]
        self.assertEqual((counts["tool_reported_cases"], counts["tool_reported_issues"]), (1, 1), counts)
        self.assertEqual((counts["proof_bound_cases"], counts["candidate_cases"],
                          counts["vulnerabilities"], counts["ledger_confirmed_proof_instances"]),
                         (0, 0, 0, 0), counts)
        self.assertEqual([i["kind"] for i in accounting["proof_instances"]], ["tool_reported"])
        self.assertEqual(inventory, [])                      # job["confirmed_issues"]
        self.assertEqual(len(exports), 1)
        self.assertEqual((exports[0]["evidence_state"], exports[0]["confirmed"]),
                         ("tool_reported", False))
        self.assertIn("**0 confirmed finding(s)**, **1 tool-reported finding(s) not reproduced "
                      "by the harness**, **0 unconfirmed finding(s)**", report)
        self.assertIn("## Tool-Reported Findings (not reproduced)", report)
        self.assertNotIn("## Confirmed Findings", report)

    def test_control_reproduced_sqlmap_proof_is_a_confirmed_vulnerability(self):
        exchange, run_id, rows = self._run(blind={"q"})
        proof = store.proofs_for_run(run_id)[0]
        self.assertNotIn("evidence_source", proof)
        accounting, inventory, exports, report = self._surfaces(exchange, run_id, rows)
        counts = accounting["counts"]
        self.assertEqual((counts["vulnerabilities"], counts["proof_bound_cases"],
                          counts["tool_reported_cases"], counts["candidate_cases"]), (1, 1, 0, 0), counts)
        self.assertEqual(len(inventory), 1)
        self.assertEqual((exports[0]["evidence_state"], exports[0]["confirmed"]), ("confirmed", True))
        self.assertIn("**1 confirmed finding(s)**, **0 unconfirmed finding(s)**", report)
        self.assertNotIn("Tool-Reported", report)

    def test_control_without_the_marker_it_is_a_generic_proof_bound_candidate(self):
        with patch("harness.validators.sqlmap.TOOL_REPORTED", ""):
            exchange, run_id, rows = self._run(blind=())
        accounting, inventory, exports, report = self._surfaces(exchange, run_id, rows)
        counts = accounting["counts"]
        # The pre-fix accounting: counted proof-bound and as a generic candidate.
        self.assertEqual((counts["tool_reported_cases"], counts["candidate_cases"],
                          counts["proof_bound_cases"]), (0, 1, 1), counts)
        self.assertEqual(len(inventory), 1)
        self.assertEqual((exports[0]["evidence_state"], exports[0]["confirmed"]), ("confirmed", True))

    def test_rollback_drops_only_the_marker(self):
        # Rollback is DROP TABLE proof_evidence_source: the proof and finding rows
        # are untouched and read back as before the migration (no marker).
        import sqlite3
        exchange, run_id, rows = self._run(blind=())
        conn = sqlite3.connect(store._DB_PATH)
        try:
            conn.execute("DROP TABLE proof_evidence_source")
            conn.commit()
        finally:
            conn.close()
        store._INITIALISED.clear()                       # re-migration recreates it empty
        (proof,) = store.proofs_for_run(run_id)
        self.assertNotIn("evidence_source", proof)
        self.assertNotIn("evidence_source", store.all_host_findings(exchange.url)[0])


if __name__ == "__main__":
    unittest.main()
