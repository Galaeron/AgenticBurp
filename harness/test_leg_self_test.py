"""P0-2: run-derived confirmation trust tiers.

Exercises harness/leg_self_test.py (fires confirmation legs against the
owned loopback fixture testing/leg-verification/vuln_fixture.py and its
paired negative controls) and the wiring of its result through the existing
`live_verified_markers` override seam in confirmation_gate.leg_tier() /
apply_confirmation_suppression(), plus the caching/fail-safe wrapper added to
ConfirmMixin (orchestrator_confirm.get_run_derived_live_markers).

Positive/negative control: a HEALTHY leg passes its self-test and its class
stays "live". Defect injection: a BROKEN leg (patched to always report
not_confirmed, even against the vulnerable endpoint) drops its class out of
the run-derived live set and its findings get demoted to provisional/medium.
Fail-safe: a leg whose supporting tool is unavailable, or that the self-test
never got to run at all, is never counted as live.
"""
from __future__ import annotations

import asyncio
import unittest

from harness import leg_self_test
from harness.confirmation_gate import apply_confirmation_suppression, leg_tier
from harness.leg_self_test import LegCase, run_self_test
from harness.models import AgentReport, Finding
from harness.validators.base import ValidationResult


def _finding(vc, severity="high", confidence=0.85):
    return Finding(vulnerability_class=vc, confidence=confidence, severity=severity,
                   summary=f"{vc} on /x", evidence="e", suggested_test="t",
                   basis="derived", confirmed=False)


def _apply(finding, **kw):
    apply_confirmation_suppression([AgentReport(agent="a", model="test", findings=[finding])], **kw)
    return finding


class _AlwaysNotConfirmedValidator:
    """A deliberately BROKEN stand-in leg: reports not_confirmed no matter
    what it is pointed at, including the real vulnerable endpoint. Simulates
    a leg that has silently regressed (its oracle no longer fires)."""

    def __init__(self, *, allowed_hosts=None, **kw):
        self.allowed_hosts = allowed_hosts or []

    async def validate(self, finding, exchange) -> ValidationResult:
        return ValidationResult("broken_leg", "not_confirmed", finding.vulnerability_class,
                                confidence=0.0, confirmed=False, summary="broken leg: never confirms")


class LegSelfTestFixtureTest(unittest.TestCase):
    """Runs the real self-test against the real loopback fixture."""

    def test_healthy_leg_confirms_true_and_refutes_false_stays_live(self):
        cases = [c for c in leg_self_test._default_cases() if c.marker == "ssti"]
        derived = run_self_test(cases=cases)
        self.assertEqual(derived, frozenset({"ssti"}),
                         "a healthy leg (ssti) must pass its self-test and land in the "
                         "run-derived live set")
        # (a) the override wins over the static default: without any override,
        # "ssti" is ALSO live (it's in the static seed), but the point here is
        # that the RUN-DERIVED set -- not the hand-maintained table -- is what
        # produced "live" this time.
        self.assertEqual(leg_tier("ssti", live_verified_markers=derived), "live")
        finding = _finding("ssti")
        _apply(finding, live_verified_markers=derived)
        # A live-tier unconfirmed finding is capped hard (severity -> low) --
        # the ordinary live-tier behavior, unchanged by this feature. What
        # matters here is it did NOT fall to the (higher, medium-capped)
        # provisional path.
        self.assertEqual(finding.severity, "low")
        self.assertIn(finding.review_verdict, ("unconfirmed_hypothesis", "inconclusive_unverified"))

    def test_unavailable_leg_tool_is_never_counted_as_live(self):
        called = {"build": False}

        def _boom(base_url):
            called["build"] = True
            raise AssertionError("build_tp must not be called for an unavailable case")

        case = LegCase(
            marker="command_injection", finding_class="command_injection",
            validator_factory=lambda: _AlwaysNotConfirmedValidator(),
            build_tp=_boom, build_neg=_boom,
            available=lambda: False,  # simulates curl missing on this host
        )
        derived = run_self_test(cases=[case])
        self.assertEqual(derived, frozenset())
        self.assertFalse(called["build"], "an unavailable case must be skipped before probing anything")
        # (b) fail-safe: the class falls to provisional, never stays live.
        self.assertEqual(leg_tier("command_injection", live_verified_markers=derived), "provisional")

    def test_fixture_startup_failure_yields_empty_set_not_a_crash(self):
        real_load = leg_self_test._load_make_app
        leg_self_test._load_make_app = lambda: (_ for _ in ()).throw(RuntimeError("fixture boom"))
        try:
            derived = run_self_test()
        finally:
            leg_self_test._load_make_app = real_load
        self.assertEqual(derived, frozenset(),
                         "a self-test that could not even start must demote everything, "
                         "not raise and not silently keep the static table")


class LegSelfTestDefectInjectionTest(unittest.TestCase):
    """Runs one healthy leg (open_redirect) alongside one deliberately BROKEN
    stand-in for ssti's own vulnerable-endpoint pair, proving the broken
    leg's class is excluded while the healthy one's is not."""

    def _cases(self):
        real = leg_self_test._default_cases()
        healthy = next(c for c in real if c.marker == "open_redirect")
        broken_ssti = next(c for c in real if c.marker == "ssti")._replace(
            validator_factory=lambda: _AlwaysNotConfirmedValidator())
        return [healthy, broken_ssti]

    def test_broken_leg_drops_out_healthy_leg_stays(self):
        derived = run_self_test(cases=self._cases())
        self.assertIn("open_redirect", derived, "the healthy leg must still pass")
        self.assertNotIn("ssti", derived, "a leg that never confirms (even on the real "
                                          "vulnerable endpoint) must be dropped from the "
                                          "run-derived live set")

    def test_broken_leg_demotes_its_findings_to_provisional_medium(self):
        derived = run_self_test(cases=self._cases())
        # (c) the ONLY behavioral effect is demotion: open_redirect (still
        # live) is unaffected by this override versus the static default,
        # while ssti (dropped) is demoted from the "live" cap (low/[Hypothesis]
        # or [Unverified]) to the "provisional" cap (medium/[Unconfirmed]).
        healthy_finding = _finding("open_redirect", severity="critical")
        _apply(healthy_finding, live_verified_markers=derived)
        self.assertEqual(healthy_finding.severity, "low")  # unchanged live-tier behavior

        broken_finding = _finding("ssti", severity="critical")
        self.assertEqual(leg_tier("ssti", live_verified_markers=derived), "provisional")
        _apply(broken_finding, live_verified_markers=derived)
        self.assertEqual(broken_finding.severity, "medium")
        self.assertEqual(broken_finding.review_verdict, "unproven_unverified_leg")
        self.assertTrue(broken_finding.summary.startswith("[Unconfirmed]"))
        self.assertLessEqual(broken_finding.confidence, 0.5)


class GetRunDerivedLiveMarkersTest(unittest.TestCase):
    """Exercises the ConfirmMixin caching/fail-safe wrapper without spinning
    up a full Orchestrator -- the mixin only reads self.config and caches on
    self, both of which a bare object supports."""

    def _mixin_instance(self, config):
        from harness.orchestrator_confirm import ConfirmMixin

        class _Bare(ConfirmMixin):
            def __init__(self, cfg):
                self.config = cfg

        return _Bare(config)

    def test_disabled_by_default_returns_none_static_default_applies(self):
        inst = self._mixin_instance({})  # leg_self_test.enabled absent -> off
        result = asyncio.run(inst.get_run_derived_live_markers())
        self.assertIsNone(result, "with leg_self_test not enabled, the override must be "
                                  "absent so confirmation_gate falls back to its static "
                                  "offline default -- no behavior change for existing runs")

    def test_enabled_but_self_test_crashes_yields_empty_frozenset_not_none(self):
        inst = self._mixin_instance({"leg_self_test": {"enabled": True}})

        def _boom():
            raise RuntimeError("self-test blew up")

        real = leg_self_test.run_self_test
        leg_self_test.run_self_test = _boom
        try:
            result = asyncio.run(inst.get_run_derived_live_markers())
        finally:
            leg_self_test.run_self_test = real
        self.assertEqual(result, frozenset(),
                         "a crashed self-test must demote everything (empty override), "
                         "never fall back to the static table while enabled")

    def test_result_is_cached_across_calls(self):
        inst = self._mixin_instance({"leg_self_test": {"enabled": True}})
        calls = {"n": 0}

        def _once():
            calls["n"] += 1
            return frozenset({"ssti"})

        real = leg_self_test.run_self_test
        leg_self_test.run_self_test = _once
        try:
            first = asyncio.run(inst.get_run_derived_live_markers())
            second = asyncio.run(inst.get_run_derived_live_markers())
        finally:
            leg_self_test.run_self_test = real
        self.assertEqual(first, frozenset({"ssti"}))
        self.assertEqual(second, frozenset({"ssti"}))
        self.assertEqual(calls["n"], 1, "the self-test must run at most once per instance")


if __name__ == "__main__":
    unittest.main()
