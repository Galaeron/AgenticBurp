"""One class name per class, and a capture's proofs name its identity (r9 review).

r9 reported one issue as several:
- the model filed one class under two spellings ("sql_injection" / "SQL Injection",
  "insecure_direct_object_reference" / "Insecure Direct Object Reference", "CSP
  Weakness" / "Missing Content Security Policy"), and the issue accounting grouped
  on the raw lowercased label ("info_disclosure" and "information_disclosure" on one
  origin were two hardening observations);
- the forged-JWT root cause (one mechanism and policy) was two vulnerabilities: the
  role session's proofs named the user, the proofs of a capture made with that same
  user's token named "captured".

Callers: categories.canonicalize; confirmed_issue_accounting over stored-shape proofs;
and ConfirmMixin._validate_findings over a capture carrying a registered identity's
credentials, feeding its case into the accounting. Each fix has a control.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from harness import assessment_health
from harness.assessment_health import confirmed_issue_accounting
from harness.categories import canonicalize, legacy_canonicalize
from harness.evidence import TestCaseRef
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator_confirm import ConfirmMixin
from harness.run_context import RunContext
from harness.validators.base import ValidationResult
from harness.validators.registry import ValidatorRegistry

ORIGIN = "https://grouping.invalid"


class CanonicalSpellingTests(unittest.TestCase):

    def test_snake_case_labels_read_as_their_class(self):
        for label, cls in (("sql_injection", "sqli"), ("insecure_direct_object_reference", "idor"),
                           ("nosql_injection", "nosql"), ("broken_authentication", "auth"),
                           ("broken_function_level_authorization", "bfla"),
                           ("missing_security_header", "missing_headers"),
                           ("CSP Weakness", "csp"), ("weak_csp", "csp")):
            self.assertEqual(canonicalize(label), cls, label)

    def test_control_umbrella_and_two_class_labels_stay_unmapped(self):
        for label in ("broken_access_control", "broken_access_control / idor",
                      "sql_injection / xss", "made_up_label"):
            self.assertIsNone(canonicalize(label), label)

    def test_control_the_stored_fingerprint_reading_does_not_move(self):
        for label in ("sql_injection", "insecure_direct_object_reference", "csp weakness"):
            self.assertIsNone(legacy_canonicalize(label), label)


def _proof(n, *, route, cls, validator, principal="alice", policy=""):
    case = TestCaseRef.make(run_id="run1", request_template_id=f"tpl{route}", check_id=cls,
                            principal_id=principal).to_dict()
    proof = {"proof_id": f"p{n}", "case": case, "validator": validator, "verdict": "confirmed",
             "executed": True, "legacy": False, "created_at": float(n),
             "baseline_artifact_id": f"b{n}", "attack_artifact_id": f"a{n}",
             "control_artifact_ids": [f"c{n}"], "policy_fingerprint": policy}
    finding = {"confirmed": True, "case_id": case["case_id"], "proof_id": proof["proof_id"],
               "url": f"{ORIGIN}{route}", "vulnerability_class": cls, "finding_id": f"f{n}"}
    return proof, finding


def _accounting(pairs):
    proofs = [p for p, _ in pairs]
    by_case = {}
    for p in proofs:
        by_case.setdefault(p["case"]["case_id"], []).append(p)
    return confirmed_issue_accounting([f for _, f in pairs], "run1", lambda c: by_case.get(c, []),
                                      run_proofs=proofs, artifact_resolver=lambda proof: True)


class AccountingClassTests(unittest.TestCase):
    """The accounting groups on the report's class, not the raw spelling."""

    PAIRS = [dict(route="/api/config", cls="info_disclosure"),
             dict(route="/api/version", cls="information_disclosure")]

    def _groups(self):
        pairs = [_proof(n, validator="content_exposure_validator", **kw)
                 for n, kw in enumerate(self.PAIRS)]
        return _accounting(pairs)["groups"]

    def test_two_spellings_on_one_origin_are_one_observation(self):
        groups = self._groups()
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["vulnerability_class"], "info_disclosure")
        self.assertEqual(len(groups[0]["routes"]), 2)

    def test_control_the_raw_label_splits_them(self):
        with patch.object(assessment_health, "issue_class", lambda vc: (vc or "").strip().lower()):
            self.assertEqual(len(self._groups()), 2)


class _JwtForge:
    """A confirming leg for the 'jwt' class, named as the route-independent mechanism."""
    active = False
    run_context = None
    version = "test"
    name = "jwt_forge"

    def applies(self, finding, exchange):
        return finding.vulnerability_class == "jwt"

    def plan(self, finding, exchange):
        return None

    async def validate(self, finding, exchange):
        await asyncio.sleep(0)
        return ValidationResult(self.name, "confirmed", "jwt", confirmed=True, confidence=0.9,
                                summary="forged token accepted")


class CapturePrincipalTests(unittest.IsolatedAsyncioTestCase):
    """A capture made with alice's token: its proofs are alice's."""

    ALICE = {"Authorization": "Bearer alice-token"}

    async def _case(self, *, register=True, ephemeral=False):
        config = {"validators": {"enabled": True}}
        caller = ConfirmMixin()
        caller.config, caller.allowed_hosts = config, ["grouping.invalid"]
        caller.validator_registry = ValidatorRegistry(config)
        caller.validator_registry.validators = {"jwt_forge": _JwtForge()}
        context = RunContext.create(allowed_hosts=caller.allowed_hosts, config=config)
        if register:
            context.sessions.register("principal:0:alice", "alice", dict(self.ALICE),
                                      allowed_origins=[ORIGIN], ephemeral=ephemeral)
        exchange = HttpExchange(url=f"{ORIGIN}/api/orders", method="GET", response_status=200,
                                request_headers={**self.ALICE, "Accept": "application/json",
                                                 "User-Agent": "capture"})
        finding = Finding(vulnerability_class="jwt", confidence=0.6, severity="high",
                          summary="forged token", evidence="", suggested_test="t",
                          basis="derived", finding_id="f-jwt")
        persist = AsyncMock(return_value=(True, {"proof_id": "proof-1"}, ""))
        try:
            with patch.object(caller, "_persist_confirmation_proof", persist), \
                 patch.object(caller, "_oracle_gate", AsyncMock()), \
                 patch("harness.store.persist_validation_submission", return_value=(True, "")):
                await caller._validate_findings(
                    exchange, [AgentReport(agent="auth", model="synthetic", findings=[finding])],
                    run_context=context)
        finally:
            await context.aclose()
        self.assertEqual(persist.await_count, 1)
        return persist.call_args.kwargs["case"]

    async def test_the_capture_case_names_the_identity_owning_its_credentials(self):
        case = await self._case()
        self.assertEqual(case.principal_id, "alice")

    async def test_control_unknown_credentials_stay_captured(self):
        self.assertEqual((await self._case(register=False)).principal_id, "captured")

    async def test_control_a_one_send_session_is_not_an_identity(self):
        self.assertEqual((await self._case(ephemeral=True)).principal_id, "captured")

    async def _jwt_groups(self, **kw):
        case = {**(await self._case(**kw)).to_dict(), "run_id": "run1"}   # one run's accounting
        # the role session's own proof on another route, under alice's name
        role_proof, role_finding = _proof(1, route="/api/basket", cls="jwt", validator="jwt_forge",
                                          policy="hs256-none")
        capture_proof = {**role_proof, "proof_id": "p2", "case": case, "baseline_artifact_id": "b2",
                         "attack_artifact_id": "a2", "control_artifact_ids": ["c2"]}
        capture_finding = {**role_finding, "case_id": case["case_id"], "proof_id": "p2",
                           "url": f"{ORIGIN}/api/orders", "finding_id": "f2"}
        return [g for g in _accounting([(role_proof, role_finding), (capture_proof, capture_finding)])
                ["groups"] if g["kind"] == "vulnerability"]

    async def test_one_forged_jwt_root_cause_is_one_vulnerability(self):
        groups = await self._jwt_groups()
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["principal_id"], "alice")
        self.assertEqual(len(groups[0]["routes"]), 2)

    async def test_control_the_captured_label_splits_it_in_two(self):
        self.assertEqual(len(await self._jwt_groups(register=False)), 2)   # the r9 split


if __name__ == "__main__":
    unittest.main()
