"""B2-4(a): offline proof that the deterministic cross-identity REJECT ->
downgrade path in harness/orchestrator_confirm.py:_validate_findings (the
block right after the proof-persistence loop, guarded by
`result.validator == "cross_identity" and result.status == "not_confirmed"
and getattr(result, "control_outcome", "") == "control_held" and not
finding.confirmed and finding.confidence > _CROSS_IDENTITY_REJECT_CAP`)
actually fires and downgrades a finding when armed, and does NOT fire when
the cross_identity validator is absent.

RA-7: cross_identity_validator.py returns status="not_confirmed" for THREE
distinct outcomes -- a genuine control-held reject (every considered identity
+ anon denied), a BFLA reached-but-unproven observation, and an
ownership-authorized observation. Only the control-held reject sets
control_outcome="control_held"; the other two leave it unset ("") so the
downgrade block must NOT fire for them. This module's negative-control tests
(test_bfla_reached_unproven_does_not_downgrade,
test_ownership_authorized_observation_does_not_downgrade) prove that.

This block is deliberately NOT gated by any config flag -- in production,
"REJECT on" means the active cross_identity validator is armed and returned
by validator_registry.for_finding for this finding; "REJECT off" means it
never appears in that call's output. So this test models on/off purely by
the PRESENCE/ABSENCE of a stub cross_identity validator, exactly as the
production code branches, and never touches config.yaml, active_enabled, or
a real network target.

Pattern mirrors harness/test_orchestrator_precondition.py's
ValidatorEvidenceBackfillTests (setUp/store-swap, patch
orch.validator_registry.for_finding with a fake validator, drive
asyncio.run(orch._validate_findings(...))). Only the model boundary the
Orchestrator constructor touches is a stub ollama base_url that is never
contacted (no finding here originates from the model -- both findings are
built directly as synthetic Finding objects, same as that module's
placeholder pattern).
"""
import asyncio
import unittest


def _ex():
    from harness.models import HttpExchange
    return HttpExchange(
        url="http://example.test/api/tickets/5", method="GET",
        request_headers={"Authorization": "Bearer bob-token"}, request_body="",
        response_status=200, response_headers={"Content-Type": "application/json"},
        response_body='{"id": 5, "owner": "alice"}',
    )


def _idor_finding():
    from harness.models import Finding
    return Finding(
        vulnerability_class="idor", confidence=0.6, severity="high",
        summary="Ticket referenced by a sequential id; ownership not verified in this single exchange",
        evidence="single-exchange heuristic only -- not a confirmed exploit",
        suggested_test="Re-request the same id with a different identity's token",
        basis="derived", confirmed=False,
    )


class _CrossIdentityNotConfirmedValidator:
    """Stub standing in for the real active cross_identity validator reporting
    a GENUINE control-held reject: every other configured identity and the
    anonymous baseline were denied, so it reports not_confirmed/confirmed=False
    WITH control_outcome="control_held" -- the exact signal the deterministic
    downgrade block keys on (RA-7: this is one of the two "rejects ==
    considered" return sites in cross_identity_validator.py, which are the
    only sites that set control_outcome)."""
    name = "cross_identity"
    version = ""

    def plan(self, finding, exchange):
        return None

    async def validate(self, finding, exchange):
        from harness.validators.base import ValidationResult
        return ValidationResult(
            validator="cross_identity", status="not_confirmed",
            finding_class=finding.vulnerability_class,
            confidence=0.0, confirmed=False,
            summary="Every configured other identity and the anon baseline were denied",
            evidence="cross-identity probe: 403 for bob, carol, anon",
            control_outcome="control_held")


class _CrossIdentityBflaReachedUnprovenValidator:
    """RA-7 NEGATIVE CONTROL stub: models cross_identity_validator's BFLA
    reached-but-unproven observation (_confirm_bfla, ~340-349) -- a
    non-privileged identity REACHED an admin-namespaced function but this leg
    could not prove it returned the same privileged data an admin sees. This
    is status="not_confirmed" but control_outcome is UNSET (not a
    control-held reject) -- "a lead, not proof". Must NOT be capped/demoted."""
    name = "cross_identity"
    version = ""

    def plan(self, finding, exchange):
        return None

    async def validate(self, finding, exchange):
        from harness.validators.base import ValidationResult
        return ValidationResult(
            validator="cross_identity", status="not_confirmed",
            finding_class=finding.vulnerability_class,
            confidence=0.4, confirmed=False,
            summary="OBSERVATION (not confirmed): non-privileged identity reached the "
                    "admin-namespaced function, but this leg could not establish it "
                    "returned the same privileged data an admin sees.",
            evidence="admin namespace is a lead, not proof")


class _CrossIdentityOwnershipAuthorizedValidator:
    """RA-7 NEGATIVE CONTROL stub: models cross_identity_validator's
    ownership-authorized observation (~452-460) -- a principal reached the
    object but OwnershipLedger says it was explicitly authorized (own /
    shared / public), so this is authorized sharing, not BOLA. Also
    status="not_confirmed" with control_outcome UNSET. Must NOT be
    capped/demoted."""
    name = "cross_identity"
    version = ""

    def plan(self, finding, exchange):
        return None

    async def validate(self, finding, exchange):
        from harness.validators.base import ValidationResult
        return ValidationResult(
            validator="cross_identity", status="not_confirmed",
            finding_class=finding.vulnerability_class,
            confidence=0.3, confirmed=False,
            summary="OBSERVATION (not confirmed): 1 authorized principal(s) reached the "
                    "resource with explicit ownership/share/public permission; all "
                    "configured principals were still evaluated.",
            evidence="OwnershipLedger authorized 1 of 1 tested principal(s)")


class _UnrelatedNonDowngradingValidator:
    """Negative-control stand-in for a validator that is NOT cross_identity --
    proves the downgrade block is keyed on the validator name, not just any
    not_confirmed result."""
    name = "some_other_validator"
    version = ""

    def plan(self, finding, exchange):
        return None

    async def validate(self, finding, exchange):
        from harness.validators.base import ValidationResult
        return ValidationResult(
            validator="some_other_validator", status="not_confirmed",
            finding_class=finding.vulnerability_class,
            confidence=0.0, confirmed=False,
            summary="Inconclusive", evidence="")


class CrossIdentityRejectTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        from harness import store
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmp.name) / "t.db"

    def tearDown(self):
        from harness import store
        store._DB_PATH = self._orig_db_path
        self._tmp.cleanup()

    def _orchestrator(self):
        from harness.orchestrator import Orchestrator
        return Orchestrator({
            "ollama": {"base_url": "http://localhost:11434"},
            "coordinator": {"model": "llama3.1:8b"},
            "agent_defaults": {"model": "gemma2:9b"},
            "agents": {},
            "server": {"allowed_hosts": ["example.test"]},
        })

    def test_reject_on_downgrades_the_finding(self):
        """POSITIVE: an armed cross_identity validator returning not_confirmed
        on an unconfirmed, above-cap finding downgrades it deterministically."""
        from unittest.mock import patch
        from harness.models import AgentReport

        finding = _idor_finding()
        report = AgentReport(agent="idor", model="rule-based", findings=[finding])
        exchange = _ex()

        orch = self._orchestrator()
        with patch.object(orch.validator_registry, "for_finding",
                           return_value=[_CrossIdentityNotConfirmedValidator()]):
            asyncio.run(orch._validate_findings(exchange, [report]))

        self.assertEqual(finding.confidence, 0.15)
        self.assertEqual(finding.severity, "low")
        self.assertEqual(finding.review_verdict, "downgraded")
        self.assertEqual(finding.original_confidence, 0.6)
        self.assertFalse(finding.confirmed)
        self.assertIn("Cross-identity probe", finding.review_note or "")

    def test_reject_off_leaves_the_finding_untouched(self):
        """NEGATIVE CONTROL: the SAME finding, but no cross_identity validator
        is present at all (validator_registry.for_finding returns an unrelated
        validator instead) -- REJECT off, so nothing downgrades and the
        finding still surfaces at its original confidence/severity."""
        from unittest.mock import patch
        from harness.models import AgentReport

        finding = _idor_finding()
        report = AgentReport(agent="idor", model="rule-based", findings=[finding])
        exchange = _ex()

        orch = self._orchestrator()
        with patch.object(orch.validator_registry, "for_finding",
                           return_value=[_UnrelatedNonDowngradingValidator()]):
            asyncio.run(orch._validate_findings(exchange, [report]))

        self.assertEqual(finding.confidence, 0.6)
        self.assertEqual(finding.severity, "high")
        self.assertIsNone(finding.review_verdict)
        self.assertIsNone(finding.original_confidence)
        self.assertFalse(finding.confirmed)

    def test_reject_off_when_no_validator_at_all(self):
        """NEGATIVE CONTROL (variant): validator_registry.for_finding returns
        an empty list -- no leg runs, so the finding is untouched (same
        assertions as the unrelated-validator control, proving REJECT is off
        by simple absence, not just by a differently-named validator)."""
        from unittest.mock import patch
        from harness.models import AgentReport

        finding = _idor_finding()
        report = AgentReport(agent="idor", model="rule-based", findings=[finding])
        exchange = _ex()

        orch = self._orchestrator()
        with patch.object(orch.validator_registry, "for_finding", return_value=[]):
            asyncio.run(orch._validate_findings(exchange, [report]))

        self.assertEqual(finding.confidence, 0.6)
        self.assertEqual(finding.severity, "high")
        self.assertIsNone(finding.review_verdict)
        self.assertIsNone(finding.original_confidence)

    def test_reject_does_not_fire_when_already_below_cap(self):
        """Edge case: a finding whose confidence is already <= the reject cap
        (0.15) must not be "downgraded" again (no spurious original_confidence/
        review_verdict stamp) -- the guard is confidence > cap, not >=0."""
        from unittest.mock import patch
        from harness.models import AgentReport, Finding

        finding = Finding(
            vulnerability_class="idor", confidence=0.15, severity="low",
            summary="Weak guess", evidence="", suggested_test="", basis="assumed",
            confirmed=False,
        )
        report = AgentReport(agent="idor", model="rule-based", findings=[finding])
        exchange = _ex()

        orch = self._orchestrator()
        with patch.object(orch.validator_registry, "for_finding",
                           return_value=[_CrossIdentityNotConfirmedValidator()]):
            asyncio.run(orch._validate_findings(exchange, [report]))

        self.assertEqual(finding.confidence, 0.15)
        self.assertIsNone(finding.review_verdict)
        self.assertIsNone(finding.original_confidence)

    def test_bfla_reached_unproven_does_not_downgrade(self):
        """RA-7 NEGATIVE CONTROL: cross_identity returns not_confirmed for the
        BFLA reached-but-unproven observation (confidence 0.4, control_outcome
        UNSET -- a non-admin REACHED an admin function but this leg couldn't
        prove privileged data was returned: "a lead, not proof"). This must
        NOT be capped/demoted/stamped -- it is an inconclusive observation,
        not a genuine control-held reject."""
        from unittest.mock import patch
        from harness.models import AgentReport

        finding = _idor_finding()
        report = AgentReport(agent="idor", model="rule-based", findings=[finding])
        exchange = _ex()

        orch = self._orchestrator()
        with patch.object(orch.validator_registry, "for_finding",
                           return_value=[_CrossIdentityBflaReachedUnprovenValidator()]):
            asyncio.run(orch._validate_findings(exchange, [report]))

        self.assertEqual(finding.confidence, 0.6)
        self.assertEqual(finding.severity, "high")
        self.assertIsNone(finding.review_verdict)
        self.assertIsNone(finding.original_confidence)
        self.assertNotEqual(finding.review_verdict, "downgraded")
        self.assertNotIn("access correctly restricted", finding.review_note or "")
        self.assertNotIn("every configured other", finding.review_note or "")

    def test_ownership_authorized_observation_does_not_downgrade(self):
        """RA-7 NEGATIVE CONTROL: cross_identity returns not_confirmed for the
        ownership-authorized observation (confidence 0.3, control_outcome
        UNSET -- a principal REACHED the object but OwnershipLedger says it
        was explicitly authorized/shared/public, so this is authorized
        sharing, not BOLA). This must NOT be capped/demoted/stamped either."""
        from unittest.mock import patch
        from harness.models import AgentReport

        finding = _idor_finding()
        report = AgentReport(agent="idor", model="rule-based", findings=[finding])
        exchange = _ex()

        orch = self._orchestrator()
        with patch.object(orch.validator_registry, "for_finding",
                           return_value=[_CrossIdentityOwnershipAuthorizedValidator()]):
            asyncio.run(orch._validate_findings(exchange, [report]))

        self.assertEqual(finding.confidence, 0.6)
        self.assertEqual(finding.severity, "high")
        self.assertIsNone(finding.review_verdict)
        self.assertIsNone(finding.original_confidence)
        self.assertNotEqual(finding.review_verdict, "downgraded")
        self.assertNotIn("access correctly restricted", finding.review_note or "")
        self.assertNotIn("every configured other", finding.review_note or "")


if __name__ == "__main__":
    unittest.main()
