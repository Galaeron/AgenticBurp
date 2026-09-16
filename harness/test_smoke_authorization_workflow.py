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

from harness import engagement
from harness import evidence
from harness import identity_headers
from harness import principals
from harness import store
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators.cross_identity_validator import CrossIdentityValidator
from harness.testing_fixtures.authorization_workflow import AuthorizationWorkflowFixture

HOST = "127.0.0.1"


class AuthorizationSliceSmokeTest(unittest.TestCase):
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

    def test_1_vulnerable_confirms_the_crossing(self):
        fx = AuthorizationWorkflowFixture("vulnerable")
        self.addCleanup(fx.close)
        _ex, res = self._validate(fx, "7", ledger=self._ledger(fx))
        self.assertEqual(res.status, "confirmed")
        self.assertTrue(res.confirmed)
        self.assertGreaterEqual(res.confidence, 0.7)
        # Exact unauthorized private-object evidence, proven at the HTTP layer: Bob,
        # who is NOT the owner, receives Alice's exact private marker in vulnerable mode.
        bob = httpx.get(fx.object_url("7"), headers={"Authorization": "Bearer bob-token"})
        self.assertEqual(bob.status_code, 200)
        self.assertIn(fx.marker("7"), bob.text)

    def test_2_patched_does_not_confirm(self):
        fx = AuthorizationWorkflowFixture("patched")
        self.addCleanup(fx.close)
        _ex, res = self._validate(fx, "7", ledger=self._ledger(fx))
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

    def test_3c_ownership_gate_suppresses_authorized_sharing_over_real_http(self):
        fx = AuthorizationWorkflowFixture("vulnerable")
        self.addCleanup(fx.close)
        # Object 5 is Alice's but shared with Bob. WITHOUT ownership info the crossing
        # confirms; WITH the shared-fact the ownership gate suppresses it -> proving the
        # gate (T02b) is what made the difference, over real transport.
        _ex, res_no_owner = self._validate(fx, "5", ledger=None)
        self.assertTrue(res_no_owner.confirmed)
        _ex2, res_shared = self._validate(fx, "5", ledger=self._ledger(fx))
        self.assertFalse(res_shared.confirmed)

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

    def test_6_rerun_isolated_reproduces(self):
        fx = AuthorizationWorkflowFixture("vulnerable")
        self.addCleanup(fx.close)
        r1 = self._validate(fx, "7", ledger=self._ledger(fx))[1]
        identity_headers.clear(HOST)
        r2 = self._validate(fx, "7", ledger=self._ledger(fx))[1]
        self.assertTrue(r1.confirmed and r2.confirmed)   # reproducible with isolated state


if __name__ == "__main__":
    unittest.main()
