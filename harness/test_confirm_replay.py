"""Tests for ER-4: the optional reproduction-replay determinism gate.

A single successful observation can confirm an active leg (ssrf/ssti/
command_injection); a flaky one-shot confirmation would not reproduce,
inflating precision. `confirm_replay` (config: validators.confirm_replay,
DEFAULT OFF) re-runs the confirming request ONCE via the SAME validate()
path (never a hand-rolled re-send) and keeps confirmed=True only if both
agree; on disagreement it downgrades to the existing provisional/unproven
path -- no new downgrade mechanism.

These are caller-level tests against Orchestrator._validate_findings, mirroring
the offline pattern in test_orchestrator_precondition.py's
ValidatorEvidenceBackfillTests (stub validator via patched
validator_registry.for_finding, temp store, no live Ollama call needed since
_validate_findings never touches the coordinator model)."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.models import AgentReport, Finding, HttpExchange
from harness.validators.base import ValidationResult


def _ex(url="http://example.test/probe", method="GET", headers=None, body=""):
    return HttpExchange(url=url, method=method, request_headers=headers or {},
                        request_body=body, response_status=None,
                        response_headers={}, response_body="")


class _ScriptedValidator:
    """Stub active-leg validator: returns results from a scripted sequence,
    one per call to validate(), and counts how many times it was called."""

    version = ""

    def __init__(self, name, results):
        self.name = name
        self._results = list(results)
        self.call_count = 0

    def plan(self, finding, exchange):
        return None

    async def validate(self, finding, exchange):
        self.call_count += 1
        # Fall back to repeating the last scripted result if over-called --
        # a test bug should show up as a wrong count/value, not an IndexError.
        idx = min(self.call_count - 1, len(self._results) - 1)
        return self._results[idx]


def _confirmed(name, finding_class="ssrf"):
    return ValidationResult(
        validator=name, status="confirmed", finding_class=finding_class,
        confidence=0.9, confirmed=True, summary="confirmed on this attempt",
        evidence="observed callback")


def _not_confirmed(name, finding_class="ssrf"):
    return ValidationResult(
        validator=name, status="not_confirmed", finding_class=finding_class,
        confidence=0.2, confirmed=False, summary="did not reproduce",
        evidence="")


class ConfirmReplayTests(unittest.TestCase):
    def setUp(self):
        from harness import store
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmp.name) / "t.db"

    def tearDown(self):
        from harness import store
        store._DB_PATH = self._orig_db_path
        self._tmp.cleanup()

    def _orchestrator(self, confirm_replay):
        from harness.orchestrator import Orchestrator
        return Orchestrator({
            "ollama": {"base_url": "http://localhost:11434"},
            "coordinator": {"model": "llama3.1:8b"},
            "agent_defaults": {"model": "gemma2:9b"},
            "agents": {},
            "server": {"allowed_hosts": ["example.test"]},
            "validators": {"confirm_replay": confirm_replay},
        })

    def _finding(self, vuln_class="ssrf"):
        return Finding(
            vulnerability_class=vuln_class, confidence=0.3, severity="high",
            summary="SSRF-shaped outbound fetch", evidence="",
            suggested_test="", basis="derived")

    def test_positive_agree_confirms_and_calls_validate_twice(self):
        finding = self._finding("ssrf")
        report = AgentReport(agent="ssrf", model="m", findings=[finding])
        exchange = _ex()
        validator = _ScriptedValidator("ssrf", [
            _confirmed("ssrf"), _confirmed("ssrf"),
        ])

        orch = self._orchestrator(confirm_replay=True)
        self.assertTrue(orch.confirm_replay)
        with patch.object(orch.validator_registry, "for_finding", return_value=[validator]):
            asyncio.run(orch._validate_findings(exchange, [report]))

        self.assertTrue(finding.confirmed)
        self.assertEqual(validator.call_count, 2)

    def test_downgrade_on_disagreement_stays_unconfirmed(self):
        finding = self._finding("ssrf")
        report = AgentReport(agent="ssrf", model="m", findings=[finding])
        exchange = _ex()
        validator = _ScriptedValidator("ssrf", [
            _confirmed("ssrf"), _not_confirmed("ssrf"),
        ])

        orch = self._orchestrator(confirm_replay=True)
        with patch.object(orch.validator_registry, "for_finding", return_value=[validator]):
            reports, _proofs = asyncio.run(orch._validate_findings(exchange, [report]))

        self.assertEqual(validator.call_count, 2)
        # Never surfaced as confirmed -- the ONLY place finding.confirmed is
        # set to True (orchestrator_confirm.py ~488) is gated on
        # result.confirmed, which the downgraded result sets False. This
        # leaves the finding exactly where a genuinely not-confirmed active
        # leg would: routed to the existing provisional/unproven path by
        # confirmation_gate downstream, not a new mechanism.
        self.assertFalse(finding.confirmed)
        self.assertEqual(len(reports), 1)
        self.assertFalse(reports[0].confirmed)
        self.assertEqual(reports[0].status, "not_confirmed")

    def test_off_is_byte_for_byte_one_call_negative_control(self):
        """The key regression guard: confirm_replay OFF (the shipped default)
        must be indistinguishable from before ER-4 existed -- one validate()
        call, confirmed=True passed straight through, no second send."""
        finding = self._finding("ssrf")
        report = AgentReport(agent="ssrf", model="m", findings=[finding])
        exchange = _ex()
        validator = _ScriptedValidator("ssrf", [_confirmed("ssrf")])

        orch = self._orchestrator(confirm_replay=False)
        self.assertFalse(orch.confirm_replay)
        with patch.object(orch.validator_registry, "for_finding", return_value=[validator]):
            asyncio.run(orch._validate_findings(exchange, [report]))

        self.assertTrue(finding.confirmed)
        self.assertEqual(validator.call_count, 1)

    def test_out_of_scope_marker_is_never_replayed(self):
        """confirm_replay ON but the leg's name isn't one of the three scoped
        markers (ssrf/ssti/command_injection) -- replay must not apply."""
        finding = self._finding("sqli")
        report = AgentReport(agent="sqli", model="m", findings=[finding])
        exchange = _ex()
        validator = _ScriptedValidator("sqlmap", [_confirmed("sqlmap", "sqli")])

        orch = self._orchestrator(confirm_replay=True)
        with patch.object(orch.validator_registry, "for_finding", return_value=[validator]):
            asyncio.run(orch._validate_findings(exchange, [report]))

        self.assertTrue(finding.confirmed)
        self.assertEqual(validator.call_count, 1)


if __name__ == "__main__":
    unittest.main()
