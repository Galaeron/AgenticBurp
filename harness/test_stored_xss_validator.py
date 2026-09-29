"""Tests for the stored/second-order XSS validator (R7): a bound RunContext
must be consulted for its OWN gate (plant/render) and must thread its
scope/gate/budget/cancel into the optional execution-grade browser confirm --
the same wiring gap browser_xss and dom_xss had. Deterministic and offline:
no real network send is exercised here (the plant/render HTTP flow itself is
covered live/manually); these prove the wiring, not the network behavior.
"""
import asyncio
import unittest

from harness import global_throttle
from harness.browser_driver import ExecutionObservation
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.safety_gate import SafetyGate, SafetyGateConfig, get_default_gate, reset_default_gate
from harness.validators.stored_xss_validator import StoredXssValidator


def _finding():
    return Finding(vulnerability_class="xss", confidence=0.6, summary="stored xss",
                   evidence="e", suggested_test="t", basis="derived")


def _exchange(url="https://shop.test/comments"):
    return HttpExchange(url=url, method="POST", request_headers={}, request_body="text=hi",
                        response_status=200, response_headers={}, response_body="")


class StoredXssGateSelectionTests(unittest.TestCase):
    """R7: validate() must consult a BOUND RunContext's own gate, not always
    the process-wide default -- otherwise a run with its own mutation policy
    (stricter OR looser than the global) silently falls back to whatever the
    global happens to be, rather than the policy this run was actually given."""

    def setUp(self):
        global_throttle.configure(0)
        reset_default_gate()

    def tearDown(self):
        reset_default_gate()

    def test_run_context_gate_denial_is_honored_even_when_global_allows(self):
        # Global default ALLOWS mutating replay...
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True})
        # ...but the bound run's OWN gate DENIES it.
        strict_gate = SafetyGate(SafetyGateConfig(allow_mutating_replay=False))
        rc = RunContext.create(allowed_hosts=["shop.test"], gate=strict_gate)
        v = StoredXssValidator(allowed_hosts=["shop.test"], run_context=rc)
        r = asyncio.run(v.validate(_finding(), _exchange()))
        # If the code still read the (permissive) global default instead of
        # rc.gate, this would NOT skip here and would instead attempt a real
        # network send -- the skip proves rc.gate was actually consulted.
        self.assertEqual(r.status, "skipped")
        self.assertIn("allow_mutating_replay", r.summary)


class _PolicyAwareDriver:
    """Records the SC-7 policy kwargs a caller forwards."""
    def __init__(self):
        self.calls = []

    async def visit(self, url, *, wait_ms=1200, headers=None,
                     scope=None, cancel=None, gate=None, budget=None):
        self.calls.append(dict(scope=scope, cancel=cancel, gate=gate, budget=budget))
        return ExecutionObservation(url=url, console=["fired"])


class _LegacyDriver:
    """No scope/gate/budget/cancel in its signature -- the pre-R7 contract."""
    async def visit(self, url, *, wait_ms=1200, headers=None):
        return ExecutionObservation(url=url, console=["fired"])


class StoredXssBrowserConfirmWiringTests(unittest.TestCase):
    """R7: the optional execution-grade browser confirm must thread a bound
    RunContext's scope/gate/budget/cancel into the driver, same as the
    reflected/DOM legs (browser_xss_validator, dom_xss_validator)."""

    def test_forwards_run_context_policy_to_driver(self):
        rc = RunContext.create(allowed_hosts=["shop.test"])
        driver = _PolicyAwareDriver()
        v = StoredXssValidator(allowed_hosts=["shop.test"], driver=driver, run_context=rc)
        note = asyncio.run(v._browser_confirm("https://shop.test/comments"))
        self.assertIn("confirmed", note.lower())
        self.assertTrue(driver.calls)
        call = driver.calls[0]
        self.assertIs(call["scope"], rc.scope)
        self.assertIs(call["gate"], rc.gate)
        self.assertIs(call["budget"], rc.budget)
        self.assertIs(call["cancel"], rc.cancel)

    def test_no_run_context_calls_driver_without_policy_kwargs(self):
        """NEGATIVE CONTROL: no RunContext bound -> legacy call shape, so a
        driver that doesn't accept the new kwargs keeps working unchanged."""
        v = StoredXssValidator(allowed_hosts=["shop.test"], driver=_LegacyDriver())
        note = asyncio.run(v._browser_confirm("https://shop.test/comments"))
        self.assertIn("confirmed", note.lower())


class RegistryTests(unittest.TestCase):
    def test_stored_xss_registered_and_active(self):
        from harness.validators.registry import ValidatorRegistry
        reg = ValidatorRegistry({"validators": {"active_enabled": True}})
        self.assertIn("stored_xss", reg.validators)
        self.assertTrue(reg.validators["stored_xss"].active)


if __name__ == "__main__":
    unittest.main()
