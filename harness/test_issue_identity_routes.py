"""AR-08b: route-independent issue identity through the real report path.

Caller-level: the real JwtForgeValidator confirms against an owned loopback API
through Orchestrator._validate_findings inside one entered RunContext, and the
confirmed findings are persisted with store.persist_findings as analyze does.
The issue export (report_generator.export_issues_for_host, which backs /issues,
SARIF and the MCP issues resource) and the Markdown report
(generate_report_for_host) then read only what the store kept.

A route-independent mechanism (a token verification policy) proven on several
routes is one issue that lists every route. Negative controls: a different token
policy, a different principal, or a proof with no persisted fingerprint stays a
separate issue per route.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import unittest

from harness import report_generator, store, telemetry
from harness.evidence import ProofRecord, TestCaseRef
from harness.models import AgentReport, Finding, HttpExchange
from harness.run_context import _CREDENTIAL_HEADERS, RunContext, ScopePolicy
from harness.test_confirmation_soundness_rve import _CallerBase, _finding
from harness.test_default_history_caller import _exchange
from harness.test_proof_artifacts import _JWT, _Target
from harness.test_proof_identity import _OTHER_JWT, _api
from harness.validators.jwt_forge_validator import JwtForgeValidator


class RouteIndependentIssueIdentityTests(_CallerBase, unittest.TestCase):
    HOSTS = ("127.0.0.1",)

    def setUp(self):
        super().setUp()
        self.target = _Target(_api)
        self.addCleanup(self.target.close)

    def _confirm_and_persist(self, legs):
        """legs: [(path, token, principal)], all inside ONE run. Returns the proofs."""
        orch = self._orch(hosts=self.HOSTS)
        orch.validator_registry.validators = {
            "jwt_forge": JwtForgeValidator(allowed_hosts=list(self.HOSTS), timeout=5.0)}
        gate = {"active_enabled": True, "allow_mutating_replay": True}

        async def go():
            out = []
            async with RunContext.create(allowed_hosts=list(self.HOSTS), max_requests=500,
                                         gate_config=gate) as run:
                for path, token, principal in legs:
                    url = self.target.origin + path
                    exchange = _exchange(url, {"Authorization": f"Bearer {token}"})
                    creds = {k: v for k, v in exchange.request_headers.items()
                             if k.lower() in _CREDENTIAL_HEADERS}
                    run.sessions.register("captured", "captured", creds, name="captured",
                                          allowed_origins=[ScopePolicy.origin_of(url)])
                    findings = [_finding("jwt", principal_id=principal)]
                    reports, proofs = await orch._validate_findings(
                        exchange, [AgentReport(agent="jwt_forge", model="fake", findings=findings)],
                        run_context=run)
                    self.assertEqual([r.status for r in reports], ["confirmed"])
                    out.extend(proofs)
                    telemetry.bind_current_run(run.run_id)
                    store.persist_findings(exchange, "jwt_forge", [findings[-1]])
                telemetry.bind_current_run(None)
            return out
        return asyncio.run(go())

    def _issues(self):
        return [i for i in report_generator.export_issues_for_host(self.target.origin)
                if i["vulnerability_class"] == "jwt"]

    def _report(self):
        return report_generator.generate_report_for_host(self.target.origin)

    def _routes(self, *paths):
        return sorted(self.target.origin + p for p in paths)

    def test_equivalent_policy_on_two_routes_is_one_issue_with_both_locations(self):
        proofs = self._confirm_and_persist([("/api/me", _JWT, "captured"),
                                            ("/api/orders", _JWT, "captured")])
        issues = self._issues()
        self.assertEqual(len(issues), 1, json.dumps(issues, indent=1, default=str))
        issue = issues[0]
        self.assertEqual(sorted(issue["affected_instances"]), self._routes("/api/me", "/api/orders"))
        self.assertEqual(issue["affected_routes"], ["/api/me", "/api/orders"])
        self.assertEqual(issue["instances_count"], 2)
        self.assertEqual(sorted(r["proof_id"] for r in issue["proof_references"]),
                         sorted(p["proof_id"] for p in proofs))
        # The Markdown report collapses the same way and names every route.
        report = self._report()
        self.assertEqual(report.count("_Issue: `" + issue["issue_id"] + "`"), 1, report)
        for path in ("/api/me", "/api/orders"):
            self.assertIn(self.target.origin + path, report)

    def test_stable_issue_id_across_runs(self):
        self._confirm_and_persist([("/api/me", _JWT, "captured")])
        first = self._issues()[0]["issue_id"]
        self._confirm_and_persist([("/api/orders", _JWT, "captured")])
        issues = self._issues()
        self.assertEqual([i["issue_id"] for i in issues], [first])
        self.assertEqual(issues[0]["instances_count"], 2)

    def test_distinct_token_policies_stay_separate(self):
        self._confirm_and_persist([("/api/me", _JWT, "captured"),
                                   ("/api/orders", _OTHER_JWT, "captured")])
        issues = self._issues()
        self.assertEqual(len(issues), 2, json.dumps(issues, indent=1, default=str))
        self.assertEqual(sorted(i["instances_count"] for i in issues), [1, 1])

    def test_distinct_principals_stay_separate(self):
        proofs = self._confirm_and_persist([("/api/me", _JWT, "alice"),
                                            ("/api/orders", _JWT, "bob")])
        self.assertEqual(sorted(p["case"]["principal_id"] for p in proofs), ["alice", "bob"])
        issues = self._issues()
        self.assertEqual(len(issues), 2, json.dumps(issues, indent=1, default=str))

    def test_proof_without_persisted_fingerprint_never_merges(self):
        proofs = self._confirm_and_persist([("/api/me", _JWT, "captured"),
                                            ("/api/orders", _JWT, "captured")])
        conn = sqlite3.connect(store._DB_PATH)
        try:
            self.assertEqual(conn.execute("DELETE FROM proof_identity WHERE proof_id = ?",
                                          (proofs[1]["proof_id"],)).rowcount, 1)
            conn.commit()
        finally:
            conn.close()
        issues = self._issues()
        self.assertEqual(len(issues), 2, json.dumps(issues, indent=1, default=str))
        self.assertTrue(all("affected_routes" not in i for i in issues
                            if i["instances_count"] == 1 and i["endpoint_family"]))


class HeaderPolicyStorePathTests(_CallerBase, unittest.TestCase):
    """E2 csp/cors grouping read the in-run Finding.header_fingerprint only, which
    the findings table does not keep. The report path now reads the fingerprint
    AR-08a persists with the proof, so a stored csp policy on two routes is one
    issue. Proofs and findings go through the real persistence functions."""
    ORIGIN = "http://shop.test"

    def _persist(self, path, policy):
        case = TestCaseRef.make(run_id="run-csp", request_template_id=f"GET {path}", check_id="csp",
                                principal_id="captured")
        proof = ProofRecord.from_validation_result(
            case=case, validator="csp_validator", status="confirmed", confirmed=True,
            validator_version="1", executed=True, baseline_artifact_id=f"{path}-b",
            attack_artifact_id=f"{path}-a", control_artifact_ids=(f"{path}-c",),
            policy_fingerprint=policy)
        ok, why = store.persist_proof_record(proof)
        self.assertTrue(ok, why)
        exchange = HttpExchange(url=self.ORIGIN + path, method="GET")
        store.persist_findings(exchange, "csp", [Finding(
            vulnerability_class="csp", confidence=0.9, summary=f"no CSP on {path}", evidence="fixture",
            suggested_test="verify", basis="derived", confirmed=True,
            proof_id=proof.proof_id, case_id=case.case_id)])

    def _issues(self):
        return report_generator.export_issues_for_host(self.ORIGIN)

    def test_one_stored_policy_on_two_routes_is_one_issue(self):
        self._persist("/a", "csp-fp-1")
        self._persist("/b", "csp-fp-1")
        issues = self._issues()
        self.assertEqual(len(issues), 1, json.dumps(issues, indent=1, default=str))
        self.assertEqual(issues[0]["affected_routes"], ["/a", "/b"])

    def test_distinct_stored_policies_stay_separate(self):
        self._persist("/a", "csp-fp-1")
        self._persist("/b", "csp-fp-2")
        self.assertEqual(len(self._issues()), 2)

    def test_unfingerprinted_stored_proofs_keep_one_issue_per_route(self):
        self._persist("/a", "")
        self._persist("/b", "")
        self.assertEqual(len(self._issues()), 2)


if __name__ == "__main__":
    unittest.main()
