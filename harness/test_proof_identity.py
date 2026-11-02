"""Batch 08: proof reuse and issue identity, through the production confirm path.

Caller-level: the real JwtForgeValidator confirms against an owned loopback API
through Orchestrator._validate_findings inside one entered RunContext, so the real
transport, ledger, blob store and proof persistence run. confirmed_issue_accounting
then reads the persisted proofs exactly as server.py does (store.proofs_for_case,
store.proofs_for_run, stored_proof_artifacts_resolve).

Identity: equivalent proven mechanisms group on host, mechanism, principal/carrier
boundary, check family and the relevant policy fingerprint; every proof instance
and route is kept. Distinct policies stay separate. Every shown proof link
resolves, orphaned links are listed for repair, and a reused result never counts
as a second execution.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import unittest

from harness import store, telemetry
from harness.assessment_health import confirmed_issue_accounting, stored_proof_artifacts_resolve
from harness.evidence import ProofRecord
from harness.models import AgentReport
from harness.run_context import _CREDENTIAL_HEADERS, RunContext, ScopePolicy
from harness.test_confirmation_soundness_rve import _CallerBase, _finding
from harness.test_default_history_caller import _exchange
from harness.test_proof_artifacts import _JWT, _PROFILE, _Target, _b64url
from harness.validators.jwt_forge_validator import JwtForgeValidator

# A token from another issuer and key id: a different verification policy.
_OTHER_JWT = (_b64url(b'{"alg":"HS256","typ":"JWT","kid":"tenant-b"}') + "."
              + _b64url(b'{"sub":"1","role":"user","iss":"https://idp-b.invalid"}')
              + "." + _b64url(b"another-signature"))


def _api(method, path, headers, body):
    """Every route reads a profile with either real token or an alg:none forgery;
    rejects garbage signatures and the tokenless request."""
    auth = headers.get("authorization", "")
    if not auth:
        return 401, '{"error": "login required"}'
    tok = auth.split()[-1]
    if tok in (_JWT, _OTHER_JWT) or tok.endswith("."):
        return 200, _PROFILE
    return 401, '{"error": "bad signature"}'


class ProofIdentityCallerTests(_CallerBase, unittest.TestCase):
    HOSTS = ("127.0.0.1",)

    def setUp(self):
        super().setUp()
        self.target = _Target(_api)
        self.addCleanup(self.target.close)

    def _confirm_routes(self, legs):
        """legs: [(path, token)], all inside ONE run. Returns (run_id, [(url, proof dict)])."""
        orch = self._orch(hosts=self.HOSTS)
        validator = JwtForgeValidator(allowed_hosts=list(self.HOSTS), timeout=5.0)
        orch.validator_registry.validators = {"jwt_forge": validator}
        gate = {"active_enabled": True, "allow_mutating_replay": True}

        async def go():
            out = []
            async with RunContext.create(allowed_hosts=list(self.HOSTS), max_requests=500,
                                         gate_config=gate) as run:
                for path, token in legs:
                    url = self.target.origin + path
                    exchange = _exchange(url, {"Authorization": f"Bearer {token}"})
                    creds = {k: v for k, v in exchange.request_headers.items()
                             if k.lower() in _CREDENTIAL_HEADERS}
                    run.sessions.register("captured", "captured", creds, name="captured",
                                          allowed_origins=[ScopePolicy.origin_of(url)])
                    reports_findings = [_finding("jwt")]
                    reports, proofs = await orch._validate_findings(
                        exchange, [AgentReport(agent="jwt_forge", model="fake",
                                               findings=reports_findings)], run_context=run)
                    self.assertEqual([r.status for r in reports], ["confirmed"])
                    # The finding as the confirm path left it (proof link, policy).
                    confirmed = reports_findings[-1]
                    out.extend((url, p, confirmed.model_dump()) for p in proofs)
                    # AR-08a: also persist it the way analyze does, so a later read
                    # (store.all_host_findings) sees only what the store kept.
                    telemetry.bind_current_run(run.run_id)
                    store.persist_findings(exchange, "jwt_forge", [confirmed])
                telemetry.bind_current_run(None)
                return run.run_id, out
        return asyncio.run(go())

    @staticmethod
    def _findings(legs):
        return [dict(f, url=url, vulnerability_class="jwt") for url, _, f in legs]

    def _account(self, run_id, findings):
        return confirmed_issue_accounting(
            findings, run_id, store.proofs_for_case, run_proofs=store.proofs_for_run(run_id),
            artifact_resolver=stored_proof_artifacts_resolve)

    def test_equivalent_jwt_route_evidence_is_one_issue_with_locations(self):
        run_id, legs = self._confirm_routes([("/api/me", _JWT), ("/api/orders", _JWT)])
        acc = self._account(run_id, self._findings(legs))
        self.assertEqual(acc["counts"]["vulnerabilities"], 1, json.dumps(acc["groups"], indent=1))
        group = acc["groups"][0]
        self.assertEqual(group["routes"], sorted(self.target.origin + p for p in ("/api/me", "/api/orders")))
        # Every proof instance is retained; nothing is deleted to obtain one issue.
        self.assertEqual(sorted(group["proof_ids"]), sorted(p["proof_id"] for _, p, _ in legs))
        self.assertEqual(len(acc["proof_instances"]), 2)
        self.assertEqual(len(group["case_ids"]), 2)

    def test_distinct_token_policies_stay_separate(self):
        run_id, legs = self._confirm_routes([("/api/me", _JWT), ("/api/orders", _OTHER_JWT)])
        acc = self._account(run_id, self._findings(legs))
        self.assertEqual(acc["counts"]["vulnerabilities"], 2, json.dumps(acc["groups"], indent=1))

    def _stored_account(self, run_id):
        """AR-08a: the accounting server.py computes from the store alone: findings
        read back with store.all_host_findings (no header_fingerprint column) and
        proofs read back with store.proofs_for_run."""
        rows = store.all_host_findings(self.target.origin, run_id=run_id)
        self.assertTrue(rows and all(not r.get("header_fingerprint") for r in rows))
        return self._account(run_id, rows)

    @staticmethod
    def _shape(acc):
        return sorted((g["group_id"], sorted(g["proof_ids"]), g["routes"], g["identity"])
                      for g in acc["groups"])

    def test_store_only_proofs_group_exactly_as_in_run_proofs(self):
        for second in (_JWT, _OTHER_JWT):
            with self.subTest(same_policy=second == _JWT):
                run_id, legs = self._confirm_routes([("/api/me", _JWT), ("/api/orders", second)])
                in_run = self._account(run_id, self._findings(legs))
                stored = self._stored_account(run_id)
                self.assertEqual(stored["counts"]["vulnerabilities"], 1 if second == _JWT else 2,
                                 json.dumps(stored["groups"], indent=1))
                self.assertEqual(self._shape(stored), self._shape(in_run))
                self.assertEqual(stored["counts"], in_run["counts"])
                policies = {i["policy_fingerprint"] for i in stored["proof_instances"]}
                self.assertTrue(all(policies), policies)

    def test_legacy_proof_without_fingerprint_degrades_and_never_merges(self):
        # Control: the same two equivalent routes, but one proof predates AR-08a
        # (no persisted fingerprint) and its finding was read back from the store.
        run_id, legs = self._confirm_routes([("/api/me", _JWT), ("/api/orders", _JWT)])
        legacy_id = legs[1][1]["proof_id"]
        conn = sqlite3.connect(store._DB_PATH)
        try:
            self.assertEqual(conn.execute("DELETE FROM proof_identity WHERE proof_id = ?",
                                          (legacy_id,)).rowcount, 1)
            conn.commit()
        finally:
            conn.close()
        stored = self._stored_account(run_id)
        self.assertEqual(stored["counts"]["vulnerabilities"], 2, json.dumps(stored["groups"], indent=1))
        legacy = next(i for i in stored["proof_instances"] if i["proof_id"] == legacy_id)
        self.assertEqual(legacy["policy_fingerprint"], "")
        # Still a counted, artifact-resolved proof: degraded identity, not dropped.
        self.assertTrue(legacy["artifacts_resolved"] and legacy["referenced"])
        self.assertEqual(len(stored["proof_instances"]), 2)

    def test_distinct_principals_stay_separate(self):
        run_id, legs = self._confirm_routes([("/api/me", _JWT), ("/api/orders", _JWT)])
        findings = self._findings(legs)
        proofs = store.proofs_for_run(run_id)
        other = next(p for p in proofs if p["proof_id"] == legs[1][1]["proof_id"])
        other["case"]["principal_id"] = "another-principal"
        acc = confirmed_issue_accounting(
            findings, run_id, lambda cid: [p for p in proofs if p["case"]["case_id"] == cid],
            run_proofs=proofs, artifact_resolver=stored_proof_artifacts_resolve)
        self.assertEqual(acc["counts"]["vulnerabilities"], 2)

    def test_every_shown_proof_link_resolves_and_orphans_are_listed(self):
        run_id, legs = self._confirm_routes([("/api/me", _JWT)])
        findings = self._findings(legs)
        findings.append(dict(findings[0], proof_id="missing-proof"))
        acc = self._account(run_id, findings)
        shown = {pid for g in acc["groups"] for pid in g["proof_ids"]}
        self.assertTrue(shown)
        self.assertLessEqual(shown, {i["proof_id"] for i in acc["proof_instances"]})
        self.assertEqual([(o["case_id"], o["proof_id"]) for o in acc["orphaned_proof_links"]],
                         [(legs[0][1]["case"]["case_id"], "missing-proof")])
        self.assertTrue(acc["orphaned_proof_links"][0]["repair"])

    def test_cached_reference_does_not_inflate_executions(self):
        # A real retest of the same route sends again: two executions, both kept.
        run_id, legs = self._confirm_routes([("/api/me", _JWT), ("/api/me", _JWT)])
        acc = self._account(run_id, self._findings(legs))
        self.assertEqual(acc["counts"]["executed_attempts"], 2)
        self.assertEqual(acc["counts"]["reused_proof_references"], 0)
        # A proof built from a reused result (same artifacts, nothing sent) goes
        # through the real persistence path and stays visible as a reference.
        original = ProofRecord.from_dict(legs[0][1])
        ok, why = store.persist_proof_record(ProofRecord.from_validation_result(
            case=original.case, validator=original.validator, status="confirmed", confirmed=True,
            validator_version=original.validator_version, executed=True,
            baseline_artifact_id=original.baseline_artifact_id,
            attack_artifact_id=original.attack_artifact_id,
            control_artifact_ids=original.control_artifact_ids))
        self.assertTrue(ok, why)
        acc = self._account(run_id, self._findings(legs))
        self.assertEqual(len(acc["proof_instances"]), 3)
        self.assertEqual(acc["counts"]["executed_attempts"], 2, acc["proof_instances"])
        reused = [i for i in acc["proof_instances"] if i.get("reuses_attempt_of")]
        self.assertEqual([i["reuses_attempt_of"] for i in reused], [original.proof_id])
        self.assertEqual(acc["counts"]["vulnerabilities"], 1)


if __name__ == "__main__":
    unittest.main()
