"""Tests for the browser-driven XSS validator (A2), using a fake driver."""
import asyncio
import re
import unittest
from urllib.parse import unquote

from harness import global_throttle
from harness import browser_driver
from harness.browser_driver import ExecutionObservation
from harness.models import Finding, HttpExchange
from harness.validators.browser_xss_validator import BrowserXssValidator

_NONCE = re.compile(r"HARNESSXSS[0-9a-f]+")


class _VulnDriver:
    """Simulates a page that EXECUTES a reflected payload: whatever nonce shows
    up in the URL's payload is echoed into the console (as real execution would).
    `sink` picks which execution channel carries it."""
    def __init__(self, sink="console"):
        self.sink = sink
        self.visited = []

    async def visit(self, url, *, wait_ms=1500, headers=None):
        self.visited.append(url)
        obs = ExecutionObservation(url=url)
        m = _NONCE.search(url)
        if m:
            getattr(obs, self.sink).append(f"fired {m.group(0)}")
        return obs


class _SafeDriver:
    """Simulates a page that reflects nothing executable -- empty sinks."""
    def __init__(self):
        self.visited = []

    async def visit(self, url, *, wait_ms=1500, headers=None):
        self.visited.append(url)
        return ExecutionObservation(url=url)


class _BrokenDriver:
    async def visit(self, url, *, wait_ms=1500, headers=None):
        return ExecutionObservation(url=url, load_error="Timeout")


def _finding():
    return Finding(vulnerability_class="xss", confidence=0.6, summary="reflected xss on q",
                   evidence="e", suggested_test="t", basis="derived")


def _exchange(url="https://shop.test/search?q=hello&lang=en"):
    return HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                        response_status=200, response_headers={}, response_body="")


class BrowserXssValidatorTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    def _validate(self, driver, exchange=None, **kw):
        v = BrowserXssValidator(allowed_hosts=["shop.test"], driver=driver, **kw)
        return asyncio.run(v.validate(_finding(), exchange or _exchange()))

    def test_confirms_on_console_execution(self):
        r = self._validate(_VulnDriver("console"))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertIn("console", r.evidence)

    def test_forwards_identity_headers_to_browser_R25(self):
        # R25: the browser must be driven AS the captured identity, not anonymously.
        class _RecDriver:
            def __init__(self): self.seen = []
            async def visit(self, url, *, wait_ms=1500, headers=None):
                self.seen.append(headers)
                return ExecutionObservation(url=url)
        drv = _RecDriver()
        ex = _exchange()
        ex.request_headers = {"Authorization": "Bearer alice", "Cookie": "session=abc"}
        self._validate(drv, exchange=ex)
        self.assertTrue(drv.seen)
        self.assertEqual(drv.seen[0].get("Authorization"), "Bearer alice")
        self.assertEqual(drv.seen[0].get("Cookie"), "session=abc")

    def test_confirms_on_dialog_execution(self):
        r = self._validate(_VulnDriver("dialogs"))
        self.assertEqual(r.status, "confirmed")
        self.assertIn("dialog", r.evidence)

    def test_first_payload_uses_dialog_for_external_completion_oracle(self):
        driver = _SafeDriver()
        self._validate(driver, max_visits=1)
        self.assertEqual(len(driver.visited), 1)
        self.assertIn("<script>alert('", unquote(driver.visited[0]))

    def test_not_confirmed_when_nothing_executes(self):
        r = self._validate(_SafeDriver())
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)

    def test_nonce_prevents_false_positive(self):
        # A page that echoes a DIFFERENT nonce-shaped string must not confirm.
        class _WrongNonce:
            async def visit(self, url, *, wait_ms=1500, headers=None):
                return ExecutionObservation(url=url, console=["HARNESSXSSdeadbeefdeadbeef"])
        r = self._validate(_WrongNonce())
        self.assertEqual(r.status, "not_confirmed")

    def test_out_of_scope_skips(self):
        r = self._validate(_VulnDriver(), exchange=_exchange("https://evil.test/x?q=1"))
        self.assertEqual(r.status, "skipped")
        self.assertIn("scope", r.summary)

    def test_no_driver_available_skips(self):
        # Force the no-engine state -- patch BOTH default_driver (returns None) and
        # available() (the reason), so the test is independent of whether a real
        # browser engine happens to be installed in the environment.
        orig_d, orig_a = browser_driver.default_driver, browser_driver.available
        # Stubs accept the cdp_endpoint arg the validator now threads through
        # (containerised-browser mode); the no-engine behaviour is unchanged.
        browser_driver.default_driver = lambda *a, **k: None
        browser_driver.available = lambda *a, **k: (False, "no engine -- run `pip install playwright && playwright install chromium`")
        try:
            v = BrowserXssValidator(allowed_hosts=["shop.test"], driver=None)
            r = asyncio.run(v.validate(_finding(), _exchange()))
        finally:
            browser_driver.default_driver, browser_driver.available = orig_d, orig_a
        self.assertEqual(r.status, "skipped")
        self.assertIn("install", r.evidence)

    def test_all_visits_error_is_error_status(self):
        r = self._validate(_BrokenDriver())
        self.assertEqual(r.status, "error")

    def test_visits_are_bounded_by_max_visits(self):
        driver = _SafeDriver()
        self._validate(driver, max_visits=3)
        self.assertLessEqual(len(driver.visited), 3)

    def test_no_query_params_uses_synthetic_q(self):
        driver = _VulnDriver()
        r = self._validate(driver, exchange=_exchange("https://shop.test/page"))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(all("q=" in u for u in driver.visited))

    def test_applies_to_xss_finding(self):
        v = BrowserXssValidator()
        self.assertTrue(v.applies(_finding(), _exchange()))


class _PolicyAwareDriver:
    """Like _VulnDriver, but also accepts the SC-7 policy kwargs (scope/gate/
    budget/cancel) so a test can prove R7 propagation without a real browser."""
    def __init__(self, sink="console"):
        self.sink = sink
        self.calls = []

    async def visit(self, url, *, wait_ms=1500, headers=None,
                     scope=None, cancel=None, gate=None, budget=None):
        self.calls.append(dict(scope=scope, cancel=cancel, gate=gate, budget=budget))
        obs = ExecutionObservation(url=url)
        m = _NONCE.search(url)
        if m:
            getattr(obs, self.sink).append(f"fired {m.group(0)}")
        return obs


class BrowserXssRunContextWiringTests(unittest.TestCase):
    """R7: a bound RunContext's scope/gate/budget/cancel must reach the
    browser driver's own request interception (SC-7), so a redirect or
    subresource the payload triggers mid-visit is policed too -- not just the
    initial navigation. Previously these validators never supplied them."""

    def setUp(self):
        global_throttle.configure(0)

    def test_forwards_run_context_policy_to_driver(self):
        from harness.run_context import RunContext
        rc = RunContext.create(allowed_hosts=["shop.test"])
        driver = _PolicyAwareDriver()
        v = BrowserXssValidator(allowed_hosts=["shop.test"], driver=driver, run_context=rc)
        r = asyncio.run(v.validate(_finding(), _exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(driver.calls)
        call = driver.calls[0]
        self.assertIs(call["scope"], rc.scope)
        self.assertIs(call["gate"], rc.gate)
        self.assertIs(call["budget"], rc.budget)
        self.assertIs(call["cancel"], rc.cancel)

    def test_no_run_context_calls_driver_without_policy_kwargs(self):
        """NEGATIVE CONTROL: with no RunContext bound, the call must carry NO
        new kwargs at all -- a driver that doesn't accept them (every
        pre-existing fake driver, and any pre-R7 real caller) must keep
        working unchanged."""
        driver = _VulnDriver("console")  # legacy signature: no scope/gate/budget/cancel
        v = BrowserXssValidator(allowed_hosts=["shop.test"], driver=driver)
        r = asyncio.run(v.validate(_finding(), _exchange()))
        self.assertEqual(r.status, "confirmed")

    def test_budget_exhaustion_denies_visit_and_is_not_confirmed(self):
        """R7 (denial/exhaustion actually honored, not merely passed through):
        a driver that ENFORCES the forwarded budget (as the real SC-7 request
        interception does) denies the navigation when the run's budget is
        exhausted, so the payload never executes and the validator must NOT
        confirm. Non-vacuous: pre-R7 `budget` was never forwarded, so the driver
        would see budget=None, skip the check, fire the nonce, and (wrongly)
        confirm -- exactly the ungoverned behavior R7 closes."""
        from harness.run_context import RunContext
        rc = RunContext.create(allowed_hosts=["shop.test"], max_requests=0)  # exhausted
        driver = _BudgetEnforcingDriver()
        v = BrowserXssValidator(allowed_hosts=["shop.test"], driver=driver, run_context=rc)
        r = asyncio.run(v.validate(_finding(), _exchange()))
        self.assertNotEqual(r.status, "confirmed")
        self.assertFalse(r.confirmed)
        self.assertGreater(driver.denied, 0, "the forwarded budget never actually denied a visit")


class _BudgetEnforcingDriver:
    """Simulates the real driver's SC-7 interception: consult the forwarded
    budget before 'navigating'. If it is exhausted, deny -- the payload never
    executes, so no sink is populated. A driver that received budget=None (the
    pre-R7 call shape) would instead fire the nonce."""
    def __init__(self):
        self.denied = 0

    async def visit(self, url, *, wait_ms=1500, headers=None,
                     scope=None, cancel=None, gate=None, budget=None):
        if budget is not None and not budget.reserve(1):
            self.denied += 1
            return ExecutionObservation(url=url)  # denied: no execution sink
        obs = ExecutionObservation(url=url)
        m = _NONCE.search(url)
        if m:
            obs.console.append(f"fired {m.group(0)}")
        return obs


class BrowserDriverAvailabilityTests(unittest.TestCase):
    def test_available_reports_reason(self):
        ok, reason = browser_driver.available()
        self.assertIsInstance(ok, bool)
        self.assertTrue(reason)
        if not ok:
            self.assertIn("install", reason)


if __name__ == "__main__":
    unittest.main()
