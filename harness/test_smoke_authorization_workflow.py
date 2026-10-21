"""
Astra T04 -- authorization vertical slice over ACTUAL HTTP.

Drives the REAL cross-identity confirmation path against a local vulnerable/patched
fixture: real socket transport (no mock), the real CrossIdentityValidator, the real
T03 RunContext Executor (scope + gate + budget, per-hop redirect re-check), the real
T02 ownership decision, and real T01 proof persistence + finding ingestion.

Seeded + model-stubbed, honestly: discovery is supplied (the object endpoint and the
other identity are seeded via identity_headers, the tester-fed seed interface), and
NO model is invoked -- the confirmation path here is deterministic. This proves the
authorization confirmation SLICE, not full-pipeline recall.
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import unittest
from pathlib import Path

import httpx

import harness.coverage_manifest as cm
from harness import engagement
from harness import evidence
from harness import identity_headers
from harness import principals
from harness import store
from harness.coverage_evidence_case import EvidenceCase, evidence_for
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators.cross_identity_validator import CrossIdentityValidator
from harness.testing_fixtures.authorization_workflow import AuthorizationWorkflowFixture
from harness.testing_fixtures.leg_fault import bound_test_names, outcomes_with_leg_severed

HOST = "127.0.0.1"


class AuthorizationSliceSmokeTest(EvidenceCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="t04_")
        self._orig_db = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "state.db"
        identity_headers.clear(HOST)

    def tearDown(self):
        store._DB_PATH = self._orig_db
        identity_headers.clear(HOST)
        shutil.rmtree(self._tmp, ignore_errors=True)

    # --- helpers -----------------------------------------------------------

    def _ledger(self, fx):
        led = principals.OwnershipLedger()
        ref = lambda oid: principals.object_reference(fx.object_url(oid), run_id="t04")
        led.record(principals.OwnershipFact(object_ref=ref("7"), owner_principal_id="alice", tenant="A",
                                            provenance="created-as:alice"))
        led.record(principals.OwnershipFact(object_ref=ref("5"), owner_principal_id="alice", tenant="A",
                                            shared_with=frozenset({"bob"}), provenance="shared-with:bob"))
        led.record(principals.OwnershipFact(object_ref=ref("1"), public=True, provenance="public listing"))
        return led

    def _validate(self, fx, oid, *, ledger=None, source_token="alice-token",
                  identities=(("bob", "bob-token"),)):
        # Seed the OTHER identity/identities via the real tester-fed seed interface.
        for name, tok in identities:
            identity_headers.set_identity(HOST, name, {"Authorization": f"Bearer {tok}"}, "user")
        # Capture the authenticated owner read over REAL HTTP -> the candidate exchange.
        url = fx.object_url(oid)
        r = httpx.get(url, headers={"Authorization": f"Bearer {source_token}"})
        exchange = HttpExchange(url=url, method="GET",
                                request_headers={"Authorization": f"Bearer {source_token}"},
                                response_status=r.status_code, response_body=r.text)
        ctx = RunContext.create(run_id="t04", allowed_hosts=[HOST], max_requests=25,
                                gate_config={"active_enabled": True})
        for name, tok in identities:
            ctx.sessions.register(
                f"principal:{name}", name, {"Authorization": f"Bearer {tok}"},
                allowed_origins=[fx.base], role="user", name=name)
        ctx.sessions.register("anonymous", "anonymous", allowed_origins=[fx.base],
                              role="anonymous", name="anonymous")
        v = CrossIdentityValidator(allowed_hosts=[HOST], run_context=ctx, ownership=ledger)
        finding = Finding(vulnerability_class="idor", confidence=0.6, summary="possible idor",
                          evidence="", suggested_test="", basis="derived")

        async def scenario():
            res = await v.validate(finding, exchange)
            await ctx.aclose()
            return res

        return exchange, asyncio.run(scenario())

    # --- assertions (handoff's required list) ------------------------------

    @evidence_for(**cm.caller_evidence("idor_confirm"))
    def test_1_vulnerable_confirms_the_crossing(self):
        fx = AuthorizationWorkflowFixture("vulnerable")
        self.addCleanup(fx.close)
        _ex, res = self._validate(fx, "7", ledger=self._ledger(fx))
        # Target-side proof that the validator's own cross-identity attempt ran (taken
        # before this test sends anything itself), so the verdict cannot be vacuous.
        attempts = [r["authorization"] for r in fx.requests_for("/objects/7")]
        self.record_observation({"validator": res.validator, "status": res.status,
                                 "confirmed": res.confirmed,
                                 "second_principal_attempt_reached_target": "Bearer bob-token" in attempts,
                                 "anonymous_control_reached_target": None in attempts})
        self.assertEqual(res.status, "confirmed")
        self.assertTrue(res.confirmed)
        self.assertGreaterEqual(res.confidence, 0.7)
        self.assertIn("Bearer bob-token", attempts)
        # Exact unauthorized private-object evidence, proven at the HTTP layer: Bob,
        # who is NOT the owner, receives Alice's exact private marker in vulnerable mode.
        bob = httpx.get(fx.object_url("7"), headers={"Authorization": "Bearer bob-token"})
        self.assertEqual(bob.status_code, 200)
        self.assertIn(fx.marker("7"), bob.text)

    @evidence_for(**cm.caller_evidence("idor_control"))
    def test_2_patched_does_not_confirm(self):
        fx = AuthorizationWorkflowFixture("patched")
        self.addCleanup(fx.close)
        _ex, res = self._validate(fx, "7", ledger=self._ledger(fx))
        # A controlled negative needs the leg to have RUN: the second principal's attempt
        # reached the target (counted before this test sends anything). The patched
        # fixture answers that principal 403 but the anonymous baseline 401, so
        # identity_compare cannot match the denial to the baseline and the validator
        # reports "skipped" (inconclusive) rather than a clean "not_confirmed"; both are
        # non-confirmations. A leg that never tried (no identity, out of scope, egress cut)
        # has no attempt at the target and fails the attempt assertion below.
        attempts = [r["authorization"] for r in fx.requests_for("/objects/7")]
        self.record_observation({"validator": res.validator, "status": res.status,
                                 "confirmed": res.confirmed,
                                 "second_principal_attempt_reached_target": "Bearer bob-token" in attempts})
        self.assertIn(res.status, ("not_confirmed", "skipped"))
        self.assertIn("Bearer bob-token", attempts)
        self.assertFalse(res.confirmed)
        # The controlled negative is real: Bob's request actually ran and was denied.
        bob = httpx.get(fx.object_url("7"), headers={"Authorization": "Bearer bob-token"})
        self.assertEqual(bob.status_code, 403)

    def test_3a_public_object_cannot_confirm(self):
        fx = AuthorizationWorkflowFixture("vulnerable")
        self.addCleanup(fx.close)
        _ex, res = self._validate(fx, "1", ledger=self._ledger(fx))
        self.assertFalse(res.confirmed)   # a public object read by another identity is not BOLA

    def test_3b_identical_principal_cannot_confirm(self):
        fx = AuthorizationWorkflowFixture("vulnerable")
        self.addCleanup(fx.close)
        # Seed the SOURCE principal (Alice) as the only "other" identity -> self-comparison.
        _ex, res = self._validate(fx, "7", ledger=self._ledger(fx),
                                  identities=(("alice", "alice-token"),))
        self.assertNotEqual(res.status, "confirmed")   # R10: you cannot IDOR against yourself

    def test_3c_ownership_declaration_decides_lead_sharing_or_crossing_over_real_http(self):
        fx = AuthorizationWorkflowFixture("vulnerable")
        self.addCleanup(fx.close)
        # Object 5 is Alice's. WL-04: WITHOUT any ownership declaration the crossing is
        # a `supported` lead, never a confirmation (a resource shared with every account
        # would match identically); WITH the shared-with-Bob fact it is authorized
        # sharing; WITH an owner-only fact (Bob not entitled) it confirms. The
        # declaration, not the response similarity, decides -- over real transport.
        _ex, res_undeclared = self._validate(fx, "5", ledger=None)
        self.assertEqual(res_undeclared.status, "supported")
        self.assertFalse(res_undeclared.confirmed)
        self.assertIn("ownership", res_undeclared.manual_verification.lower())
        _ex2, res_shared = self._validate(fx, "5", ledger=self._ledger(fx))
        self.assertFalse(res_shared.confirmed)
        self.assertIn("authorized", res_shared.summary.lower())
        owner_only = principals.OwnershipLedger()
        owner_only.record(principals.OwnershipFact(
            object_ref=principals.object_reference(fx.object_url("5"), run_id="t04"),
            owner_principal_id="alice", tenant="A", provenance="created-as:alice"))
        _ex3, res_owner_only = self._validate(fx, "5", ledger=owner_only)
        self.assertTrue(res_owner_only.confirmed)

    def test_4_target_side_counters_show_attempt_and_control(self):
        fx = AuthorizationWorkflowFixture("vulnerable")
        self.addCleanup(fx.close)
        self._validate(fx, "7", ledger=self._ledger(fx))
        auths = [r["authorization"] for r in fx.requests_for("/objects/7")]
        self.assertIn("Bearer bob-token", auths)   # the unauthorized attempt actually ran
        self.assertIn(None, auths)                  # the anonymous control actually ran

    def test_5_proof_roundtrips_and_links_to_finding(self):
        fx = AuthorizationWorkflowFixture("vulnerable")
        self.addCleanup(fx.close)
        ex, res = self._validate(fx, "7", ledger=self._ledger(fx))
        self.assertTrue(res.confirmed)
        case = evidence.TestCaseRef.make(run_id="t04", request_template_id="/objects/7",
                                         check_id="idor", principal_id="bob")
        proof = evidence.ProofRecord.from_validation_result(
            case=case, validator=res.validator, status=res.status, confirmed=res.confirmed,
            observed_result=(res.summary or "") + " " + (res.evidence or ""),
            expected_invariant="another principal must not read the owner's private object")
        ok, _ = store.persist_proof_record(proof)
        self.assertTrue(ok)
        # Round-trips through the store.
        back = store.best_proof_for_case(case.case_id)
        self.assertEqual(back["verdict"], "confirmed")
        # Stays linked to the finding after ingestion into state.
        st = engagement.EngagementState(host=HOST)
        st.ingest_findings(ex.url, "GET", [{
            "vulnerability_class": "idor", "confirmed": True, "confidence": res.confidence,
            "evidence": res.evidence, "proof_id": proof.proof_id, "case_id": case.case_id}])
        ep = next(iter(st.endpoints.values()))
        best = ep.best_finding()
        self.assertTrue(best.get("confirmed"))
        self.assertEqual(best.get("proof_id"), proof.proof_id)   # the link survived ingestion

    def test_bound_aspects_fail_when_the_leg_is_disconnected(self):
        # Fault injection: with the leg's egress cut, the evidence-bound confirmation AND
        # its negative control must both fail -- a control that survives a disconnected
        # leg only proves the validator did nothing.
        names = bound_test_names(type(self))
        self.assertEqual(len(names), 2, f"expected the IDOR confirm+control pair, got {names}")
        for name, outcome in outcomes_with_leg_severed(type(self), names).items():
            with self.subTest(test=name):
                self.assertIn(outcome, ("failed", "errored"),
                              f"{name} still {outcome} with the leg disconnected: not evidence")

    def test_6_rerun_isolated_reproduces(self):
        fx = AuthorizationWorkflowFixture("vulnerable")
        self.addCleanup(fx.close)
        r1 = self._validate(fx, "7", ledger=self._ledger(fx))[1]
        identity_headers.clear(HOST)
        r2 = self._validate(fx, "7", ledger=self._ledger(fx))[1]
        self.assertTrue(r1.confirmed and r2.confirmed)   # reproducible with isolated state


if __name__ == "__main__":
    unittest.main()
