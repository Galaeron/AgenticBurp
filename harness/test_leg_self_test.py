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
import threading
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


def _confirmed_result(vc):
    return ValidationResult("fake", "confirmed", vc, confidence=0.9, confirmed=True,
                            summary="positive probe confirmed")


class _NegativeOutcomeValidator:
    """Stand-in leg whose POSITIVE probe always genuinely confirms, and
    whose NEGATIVE-control outcome is whatever the test asks for --
    including outcomes that never reach a decisive executed verdict at all
    (skipped / errored / a custom non-"not_confirmed" status standing in for
    "blocked" or "inconclusive"). Used to prove P0-7: none of those may be
    accepted as a refutation, however "not confirmed" they superficially
    look."""

    def __init__(self, *, neg_status=None, neg_confirmed=False, neg_raises=False, **kw):
        self._neg_status = neg_status
        self._neg_confirmed = neg_confirmed
        self._neg_raises = neg_raises
        self._calls = 0

    async def validate(self, finding, exchange) -> ValidationResult:
        self._calls += 1
        if self._calls == 1:
            return _confirmed_result(finding.vulnerability_class)
        if self._neg_raises:
            raise RuntimeError("negative control blew up mid-run")
        return ValidationResult("fake", self._neg_status, finding.vulnerability_class,
                                confidence=0.0, confirmed=self._neg_confirmed,
                                summary="negative control did not reach a decisive executed verdict")


def _noop_exchange(base_url):
    return None


class ExecutedNegativeControlRequiredTest(unittest.TestCase):
    """P0-7 core: a leg must NOT qualify unless the negative control
    genuinely EXECUTED and was refuted (status == "not_confirmed" and not
    confirmed). A positive probe that confirms is not enough on its own --
    every flavor of a control that never reached that decisive outcome must
    refuse qualification."""

    def _case(self, **validator_kwargs):
        return LegCase(
            marker="ssti", finding_class="ssti",
            validator_factory=lambda: _NegativeOutcomeValidator(**validator_kwargs),
            build_tp=_noop_exchange, build_neg=_noop_exchange,
        )

    def test_skipped_negative_control_does_not_qualify(self):
        # The validator declined to run the negative probe at all (e.g. its
        # own precondition, or the safety gate, blocked it) -- status
        # "skipped", confirmed False. Positive still confirmed.
        derived = run_self_test(cases=[self._case(neg_status="skipped", neg_confirmed=False)])
        self.assertEqual(derived, frozenset(),
                         "a skipped (never-executed) negative control must not qualify the leg, "
                         "even though the positive probe confirmed")

    def test_errored_negative_control_does_not_qualify(self):
        derived = run_self_test(cases=[self._case(neg_raises=True)])
        self.assertEqual(derived, frozenset(),
                         "a negative control that raised mid-run is inconclusive, not a refutation")

    def test_blocked_negative_control_does_not_qualify(self):
        # Stand-in for a safety-gate-blocked probe reporting a custom status
        # rather than the canonical "skipped" -- still not "not_confirmed",
        # so still not a genuine executed refutation.
        derived = run_self_test(cases=[self._case(neg_status="blocked", neg_confirmed=False)])
        self.assertEqual(derived, frozenset(),
                         "a blocked negative control must not qualify the leg")

    def test_unavailable_negative_control_does_not_qualify(self):
        derived = run_self_test(cases=[self._case(neg_status="unavailable", neg_confirmed=False)])
        self.assertEqual(derived, frozenset(),
                         "an unavailable negative control must not qualify the leg")

    def test_inconclusive_negative_control_does_not_qualify(self):
        derived = run_self_test(cases=[self._case(neg_status="inconclusive", neg_confirmed=False)])
        self.assertEqual(derived, frozenset(),
                         "an inconclusive negative control must not qualify the leg")

    def test_healthy_executed_pair_still_qualifies(self):
        # POSITIVE control for this feature: both probes genuinely executed
        # -- positive confirmed-true, negative executed and decisively
        # not_confirmed -- so the leg still qualifies. P0-7 must only make
        # qualification stricter, never break the healthy case.
        derived = run_self_test(cases=[self._case(neg_status="not_confirmed", neg_confirmed=False)])
        self.assertEqual(derived, frozenset({"ssti"}),
                         "a genuinely executed positive-confirm/negative-refute pair must still qualify")


class ThrottleIsolationTest(unittest.TestCase):
    """P0-7: the self-test's fixture-only rate policy must not clobber a
    concurrent production run's throttle -- neither during self-test
    execution nor after its cleanup."""

    def test_concurrent_global_throttle_unchanged_before_and_after(self):
        from harness import global_throttle
        global_throttle.configure(5, burst=10)
        self.addCleanup(lambda: global_throttle.configure(0))
        prev_rate, prev_burst = global_throttle.throttle._rate, global_throttle.throttle._burst
        real_acquire = global_throttle.acquire

        cases = [c for c in leg_self_test._default_cases() if c.marker == "ssti"]
        derived = run_self_test(cases=cases)

        self.assertEqual(derived, frozenset({"ssti"}))
        self.assertEqual(global_throttle.throttle._rate, prev_rate,
                         "the shared throttle's configured rate must be unchanged after "
                         "self-test execution and cleanup")
        self.assertEqual(global_throttle.throttle._burst, prev_burst)
        self.assertIs(global_throttle.acquire, real_acquire,
                      "the module-level acquire() free function every validator calls must be "
                      "restored to the exact original object after cleanup")

    def test_concurrent_thread_keeps_using_the_real_throttle_during_self_test(self):
        # Simulates a genuinely concurrent production caller: a different OS
        # thread (its own default contextvars.Context, so it never observes
        # the self-test's `_SCOPED_THROTTLE` override) calling
        # global_throttle.acquire() WHILE the self-test is still running.
        # It must go through the real, unmodified shared throttle the whole
        # time -- not the fixture's local unlimited one.
        from harness import global_throttle
        global_throttle.configure(1000, burst=1000)
        self.addCleanup(lambda: global_throttle.configure(0))
        before_acquired = global_throttle.throttle.stats()["acquired"]
        observed = {}

        def _concurrent_production_caller():
            asyncio.run(global_throttle.acquire())
            observed["rate_seen"] = global_throttle.throttle._rate
            observed["acquired_after"] = global_throttle.throttle.stats()["acquired"]

        class _SpawnsConcurrentCaller:
            def __init__(self, **kw):
                self._calls = 0

            async def validate(self, finding, exchange) -> ValidationResult:
                self._calls += 1
                # Fire the "concurrent production" acquire from a separate
                # thread while this self-test case is mid-flight, and wait
                # for it so the assertion below can rely on it having run.
                t = threading.Thread(target=_concurrent_production_caller)
                t.start()
                t.join(timeout=5.0)
                if self._calls == 1:
                    return _confirmed_result(finding.vulnerability_class)
                return ValidationResult("fake", "not_confirmed", finding.vulnerability_class,
                                        confidence=0.0, confirmed=False, summary="refuted")

        case = LegCase(marker="ssti", finding_class="ssti",
                       validator_factory=lambda: _SpawnsConcurrentCaller(),
                       build_tp=_noop_exchange, build_neg=_noop_exchange)
        derived = run_self_test(cases=[case])

        self.assertEqual(derived, frozenset({"ssti"}))
        self.assertEqual(observed.get("rate_seen"), 1000,
                         "a concurrent caller in a different thread must still see the real "
                         "configured rate, not the self-test's local unlimited throttle")
        self.assertGreater(observed.get("acquired_after", 0), before_acquired,
                           "the concurrent caller's acquire() must have gone through the real "
                           "shared throttle (its stats must reflect it)")


if __name__ == "__main__":
    unittest.main()
