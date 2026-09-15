"""
W-2 / W-17: central scope backstop in orchestrator validator dispatch.

`_validate_findings` is the one chokepoint every validator goes through. It
must refuse to dispatch ANY validator against an out-of-scope exchange, so a
single validator constructed without its own allowed_hosts (the pre-W-1 CORS
bug) can never send unscoped live traffic. And with active mode on, an empty
scope must fail closed (W-17) rather than authorize the whole internet.

These are hermetic: the backstop returns before any RunContext, store write,
or network path, so nothing is sent.
"""
import asyncio
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import yaml

from orchestrator import Orchestrator
from models import AgentReport, Finding, HttpExchange

_HARNESS = Path(__file__).resolve().parent


def _config(allowed_hosts, active_enabled=False):
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("validators", {})["active_enabled"] = active_enabled
    cfg["validators"]["allow_mutating_replay"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("autonomous_discovery", {})["enabled"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = allowed_hosts
    return cfg


def _finding():
    # cors matches a registered validator, so "zero validators" is a real
    # scope decision, not just "nothing applied".
    return Finding(vulnerability_class="cors", confidence=0.6, summary="s",
                   evidence="e", suggested_test="t", basis="assumed")


def _report():
    return AgentReport(agent="cors_agent", model="stub", findings=[_finding()])


class ScopeBackstopTests(unittest.TestCase):
    def test_out_of_scope_exchange_dispatches_zero_validators(self):
        orch = Orchestrator(_config(allowed_hosts=["good.example"]))
        # Spy: the backstop must return before the registry is even consulted.
        orch.validator_registry.for_finding = MagicMock(
            side_effect=AssertionError("for_finding must not be reached out of scope"))
        exchange = HttpExchange(url="http://evil.example/api/x", method="GET")
        reports, proofs = asyncio.run(orch._validate_findings(exchange, [_report()]))
        self.assertEqual(reports, [])
        self.assertEqual(proofs, [])
        orch.validator_registry.for_finding.assert_not_called()

    def test_in_scope_exchange_consults_the_registry(self):
        # Control: the same finding on an in-scope host DOES reach the registry
        # (proving the zero above is the scope guard, not a dead path). We stub
        # for_finding to return no validators so nothing is actually sent.
        orch = Orchestrator(_config(allowed_hosts=["good.example"]))
        orch.validator_registry.for_finding = MagicMock(return_value=[])
        exchange = HttpExchange(url="http://good.example/api/x", method="GET")
        reports, proofs = asyncio.run(orch._validate_findings(exchange, [_report()]))
        self.assertEqual(reports, [])
        self.assertEqual(proofs, [])
        orch.validator_registry.for_finding.assert_called()

    def test_active_mode_empty_scope_fails_closed(self):
        # W-17: active testing on + no configured scope must NOT authorize live
        # dispatch. Passive analysis is unaffected; only this dispatch is gated.
        orch = Orchestrator(_config(allowed_hosts=[], active_enabled=True))
        orch.validator_registry.for_finding = MagicMock(
            side_effect=AssertionError("must fail closed with empty scope in active mode"))
        exchange = HttpExchange(url="http://anything.example/api/x", method="GET")
        reports, proofs = asyncio.run(orch._validate_findings(exchange, [_report()]))
        self.assertEqual(reports, [])
        self.assertEqual(proofs, [])
        orch.validator_registry.for_finding.assert_not_called()


if __name__ == "__main__":
    unittest.main()
