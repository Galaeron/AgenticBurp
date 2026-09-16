"""
Tests for safety_proxy_addon.py.

Uses mitmproxy's OWN test fixtures (mitmproxy.test.tflow) to build real
http.HTTPFlow/Request/Response objects -- not hand-rolled mocks -- so
these tests exercise the addon against the actual mitmproxy API shape,
not against an assumed one. This is "unit-tested against real mitmproxy
objects in-process," not "live-tested against a running proxy and a
real client" -- see safety_proxy_addon.py's own module docstring for
exactly what that distinction does and doesn't cover.
"""
import time
import unittest
from pathlib import Path

from mitmproxy.test import tflow

from harness import safety_gate
from harness.safety_proxy_addon import (
    CombinedBurstTracker,
    ProxyConfigurationError,
    SafetyProxyAddon,
    _safe_decode_body,
)


def _make_flow(method: str = "GET", url: str = "https://target.test/x", content: bytes = b"") -> "tflow.tflow":
    req = tflow.treq(method=method.encode(), content=content)
    req.url = url
    return tflow.tflow(req=req)


def _addon_with_config(active_enabled=False, allow_mutating_replay=False,
                        max_burst_size=1, config_path: Path | None = None) -> SafetyProxyAddon:
    """
    Builds an addon with a gate configured directly (bypassing the
    config.yaml file read) by constructing the gate the same way
    SafetyProxyAddon._load_gate does, then swapping it in. Keeps these
    tests independent of the repo's actual config.yaml contents, which
    could change for unrelated reasons.
    """
    addon = SafetyProxyAddon.__new__(SafetyProxyAddon)
    addon._gate = safety_gate.SafetyGate(safety_gate.SafetyGateConfig(
        active_enabled=active_enabled,
        allow_mutating_replay=allow_mutating_replay,
        max_burst_size=max_burst_size,
        max_mutating_requests_per_finding=max_burst_size,
    ))
    addon._combined_tracker = CombinedBurstTracker()
    return addon


class SafeMethodsPassThroughTests(unittest.TestCase):
    def test_get_is_allowed(self):
        addon = _addon_with_config()
        flow = _make_flow(method="GET")
        addon.request(flow)
        self.assertIsNone(flow.response)
        self.assertIsNone(flow.error)


class MutatingMethodsAreGatedTests(unittest.TestCase):
    def test_post_blocked_when_active_testing_disabled(self):
        addon = _addon_with_config(active_enabled=False)
        flow = _make_flow(method="POST")
        addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        self.assertIn(b"active testing", flow.response.content.lower().replace(b"_", b" "))

    def test_post_blocked_when_active_enabled_but_not_allow_mutating_replay(self):
        addon = _addon_with_config(active_enabled=True, allow_mutating_replay=False)
        flow = _make_flow(method="POST")
        addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)

    def test_post_allowed_when_fully_authorized(self):
        addon = _addon_with_config(active_enabled=True, allow_mutating_replay=True, max_burst_size=5)
        flow = _make_flow(method="POST")
        addon.request(flow)
        self.assertIsNone(flow.response)


class HardDenyPatternsAreNeverAllowedTests(unittest.TestCase):
    def test_drop_table_blocked_even_with_full_authorization(self):
        """
        Hard-denied content is blocked regardless of config -- this is
        the one tier safety_gate.py never allows an override for, and
        the proxy must preserve that, not just the mutating-method gate.
        """
        addon = _addon_with_config(active_enabled=True, allow_mutating_replay=True, max_burst_size=20)
        flow = _make_flow(method="POST", content=b"'; DROP TABLE users;--")
        addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)

    def test_get_with_hard_denied_url_is_blocked(self):
        addon = _addon_with_config()
        flow = _make_flow(method="GET", url="https://target.test/x?cmd=rm+-rf+/")
        addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)


class NonUtf8BodyDoesNotCrashTests(unittest.TestCase):
    def test_binary_body_is_decoded_with_replace_not_raised(self):
        result = _safe_decode_body(b"\xff\xfe\x00garbage")
        self.assertIsInstance(result, str)

    def test_binary_upload_still_gets_scanned_for_hard_deny_patterns(self):
        addon = _addon_with_config()
        # A DROP TABLE string embedded in otherwise-invalid-UTF8 bytes
        # must still trip the hard-deny check, not be silently exempted
        # because decoding wasn't clean.
        content = b"\xff\xfe" + b"DROP TABLE users;" + b"\xff"
        flow = _make_flow(method="GET", content=content)
        # DROP TABLE is checked against body for any method, per
        # safety_gate.classify()'s own logic (body is checked regardless
        # of method).
        addon.request(flow)
        self.assertIsNotNone(flow.response)

    def test_empty_body_does_not_raise(self):
        self.assertEqual(_safe_decode_body(b""), "")
        self.assertEqual(_safe_decode_body(None), "")


class FailClosedOnUnexpectedExceptionTests(unittest.TestCase):
    def test_gate_raising_kills_the_flow_rather_than_allowing_it(self):
        """
        The single most important test in this file: if anything inside
        request-handling raises for a reason nobody anticipated, the
        flow must be killed, not allowed through. This directly
        contradicts mitmproxy's own default behavior for an addon
        exception (log and continue = allow), which is exactly why
        request() wraps everything in its own try/except.
        """
        addon = _addon_with_config()

        class ExplodingGate:
            def authorize(self, **kwargs):
                raise RuntimeError("simulated unexpected failure")

        addon._gate = ExplodingGate()
        flow = _make_flow(method="GET")
        addon.request(flow)

        self.assertIsNotNone(flow.error)
        self.assertFalse(flow.killable)
        self.assertIsNone(flow.response)  # killed, not given a 403 -- connection is just gone

    def test_malformed_flow_missing_expected_attributes_kills_rather_than_crashes_uncaught(self):
        addon = _addon_with_config()

        class BrokenRequest:
            @property
            def method(self):
                raise AttributeError("simulated malformed flow")

        flow = _make_flow(method="GET")
        flow.request = BrokenRequest()  # type: ignore[assignment]

        # Must not raise out of request() itself -- the whole point of
        # the outer try/except is that this call completes normally
        # from the caller's (mitmproxy's) point of view, with the flow
        # killed as the side effect, not an exception propagating up
        # into mitmproxy's own hook dispatch.
        try:
            addon.request(flow)
        except Exception as e:  # pragma: no cover - this failing IS the test failure
            self.fail(f"request() must catch all exceptions internally, but raised: {e}")

        self.assertIsNotNone(flow.error)


class CombinedBurstTrackerTests(unittest.TestCase):
    def test_allows_up_to_the_ceiling(self):
        tracker = CombinedBurstTracker(window_seconds=10.0, hard_ceiling=3)
        for _ in range(3):
            allowed, count = tracker.check_and_record("target.test")
            self.assertTrue(allowed)
        allowed, count = tracker.check_and_record("target.test")
        self.assertFalse(allowed)
        self.assertEqual(count, 3)

    def test_different_hosts_have_independent_budgets(self):
        tracker = CombinedBurstTracker(window_seconds=10.0, hard_ceiling=1)
        allowed_a, _ = tracker.check_and_record("a.test")
        allowed_b, _ = tracker.check_and_record("b.test")
        self.assertTrue(allowed_a)
        self.assertTrue(allowed_b)

    def test_window_expiry_frees_up_budget(self):
        tracker = CombinedBurstTracker(window_seconds=0.05, hard_ceiling=1)
        allowed_1, _ = tracker.check_and_record("target.test")
        self.assertTrue(allowed_1)
        allowed_2, _ = tracker.check_and_record("target.test")
        self.assertFalse(allowed_2)
        time.sleep(0.1)
        allowed_3, _ = tracker.check_and_record("target.test")
        self.assertTrue(allowed_3, "budget should free up once the window has passed")

    def test_denied_request_does_not_consume_a_slot(self):
        tracker = CombinedBurstTracker(window_seconds=10.0, hard_ceiling=1)
        tracker.check_and_record("target.test")
        allowed, count_after_denied = tracker.check_and_record("target.test")
        self.assertFalse(allowed)
        # Confirm a further denied call doesn't keep incrementing beyond
        # the true recorded count -- count reported must reflect actual
        # in-window recordings only.
        self.assertEqual(count_after_denied, 1)


class CombinedCeilingEnforcedThroughAddonTests(unittest.TestCase):
    def test_combined_ceiling_blocks_even_when_gate_alone_would_allow(self):
        """
        The actual point of the combined tracker: even a fully-authorized
        mutating request (active_enabled + allow_mutating_replay both on,
        under safety_gate.py's own per-call ceiling) still gets blocked
        once the PROXY's cross-source ceiling for that host is exceeded.
        """
        addon = _addon_with_config(active_enabled=True, allow_mutating_replay=True, max_burst_size=20)
        addon._combined_tracker = CombinedBurstTracker(window_seconds=10.0, hard_ceiling=2)

        flow1 = _make_flow(method="POST", url="https://target.test/checkout")
        flow2 = _make_flow(method="POST", url="https://target.test/checkout")
        flow3 = _make_flow(method="POST", url="https://target.test/checkout")

        addon.request(flow1)
        addon.request(flow2)
        addon.request(flow3)

        self.assertIsNone(flow1.response)
        self.assertIsNone(flow2.response)
        self.assertIsNotNone(flow3.response)
        self.assertEqual(flow3.response.status_code, 403)
        self.assertIn(b"combined", flow3.response.content.lower())

    def test_safe_methods_never_touch_the_combined_tracker(self):
        """
        Only mutating-tier requests should consume combined-tracker
        budget -- a host getting a lot of legitimate GET traffic must
        not eat into the ceiling meant for mutating replay specifically.
        """
        addon = _addon_with_config()
        addon._combined_tracker = CombinedBurstTracker(window_seconds=10.0, hard_ceiling=1)
        for _ in range(5):
            flow = _make_flow(method="GET", url="https://target.test/x")
            addon.request(flow)
            self.assertIsNone(flow.response)


class StartupBypassOptionCheckTests(unittest.TestCase):
    """
    Confirms `running()` refuses to start if mitmproxy is configured
    with any option that would let matching traffic skip inspection.
    Uses a minimal fake `ctx.options`-shaped object rather than a real
    mitmproxy Options instance, since exercising the real option-parsing
    machinery isn't needed to test this addon's own reaction to the
    values -- only the addon's logic is under test here.
    """

    def _run_with_options(self, addon: SafetyProxyAddon, overrides: dict):
        import sys
        from types import ModuleType
        import mitmproxy.options as o

        real_options = o.Options()
        for key, value in overrides.items():
            setattr(real_options, key, value)

        fake_ctx = ModuleType("mitmproxy.ctx")
        fake_ctx.options = real_options
        sys.modules["mitmproxy.ctx"] = fake_ctx
        try:
            addon.running()
        finally:
            del sys.modules["mitmproxy.ctx"]
        return real_options

    def _clean_options(self) -> dict:
        return {
            "ignore_hosts": [], "allow_hosts": [], "tcp_hosts": [], "udp_hosts": [],
            "ssl_insecure": False,
        }

    def test_starts_normally_with_no_bypass_options(self):
        addon = _addon_with_config()
        self._run_with_options(addon, self._clean_options())  # must not raise

    def test_refuses_to_start_with_ignore_hosts_set(self):
        addon = _addon_with_config()
        opts = self._clean_options()
        opts["ignore_hosts"] = ["some-host.example"]
        with self.assertRaises(ProxyConfigurationError):
            self._run_with_options(addon, opts)

    def test_refuses_to_start_with_allow_hosts_set(self):
        addon = _addon_with_config()
        opts = self._clean_options()
        opts["allow_hosts"] = ["only-this-host.example"]
        with self.assertRaises(ProxyConfigurationError):
            self._run_with_options(addon, opts)

    def test_refuses_to_start_with_tcp_hosts_set(self):
        addon = _addon_with_config()
        opts = self._clean_options()
        opts["tcp_hosts"] = ["raw-tcp-host.example"]
        with self.assertRaises(ProxyConfigurationError):
            self._run_with_options(addon, opts)

    def test_forces_ssl_insecure_on(self):
        addon = _addon_with_config()
        opts = self._clean_options()
        del opts["ssl_insecure"]  # let running() set it; confirm it does
        result_options = self._run_with_options(addon, opts)
        self.assertTrue(result_options.ssl_insecure)


if __name__ == "__main__":
    unittest.main()
