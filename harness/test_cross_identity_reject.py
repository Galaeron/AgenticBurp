"""B2-4(a): offline proof that the deterministic cross-identity REJECT ->
downgrade path in harness/orchestrator_confirm.py:_validate_findings (the
block right after the proof-persistence loop, guarded by
`result.validator == "cross_identity" and result.status == "not_confirmed"
and not finding.confirmed and finding.confidence > _CROSS_IDENTITY_REJECT_CAP`)
actually fires and downgrades a finding when armed, and does NOT fire when
the cross_identity validator is absent.

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
    """Stub standing in for the real active cross_identity validator: every
    other configured identity and the anonymous baseline were denied, so it
    reports not_confirmed/confirmed=False -- the exact signal the deterministic
    downgrade block keys on."""
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
            evidence="cross-identity probe: 403 for bob, carol, anon")


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


if __name__ == "__main__":
    unittest.main()
