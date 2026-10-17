"""Regression guards for the browser execution plane (NC-2, from re-review N04).

The re-review worried a browser-using validator might run on a NON-intercepted
path and so skip PR-10's per-request policy. Auditing the source shows it cannot
today: there is exactly ONE place a browser context is created (`PlaywrightDriver.
visit`), it always installs `context.route("**/*")` before navigating, and every
browser-using validator obtains its driver from `browser_driver.default_driver`,
which only ever returns that intercepting driver or `None` (fail-closed). These
tests LOCK THAT IN so a future refactor cannot silently reintroduce the gap, and
re-assert PR-10's policy under the exact same-host fallback the validators rely on
(they call `visit` without an explicit scope).

Pure and offline: no Playwright, no browser, no network. `evaluate_browser_request`
and `is_cancelled` are the pure policy/seam functions the real interception handler
reuses unchanged.
"""
from __future__ import annotations

import asyncio
import re
import unittest
from pathlib import Path

from harness import browser_driver
from harness.browser_driver import (
    BrowserDriver, PlaywrightDriver, evaluate_browser_request, is_cancelled,
)
from harness.run_context import ScopePolicy

_HARNESS_DIR = Path(__file__).resolve().parent

# The browser-using validators (source-scanned below).
_BROWSER_VALIDATORS = (
    "validators/browser_xss_validator.py",
    "validators/dom_xss_validator.py",
    "validators/stored_xss_validator.py",
)

# Call patterns that CREATE a browser context/engine. If any of these appears
# outside browser_driver.py, a second (possibly non-intercepted) context site has
# been introduced and the single-source invariant is broken.
_CONTEXT_CREATION = re.compile(
    r"\.new_context\(|async_playwright\(|connect_over_cdp\(|chromium\.launch\(")


def _nontest_py_files():
    for p in _HARNESS_DIR.rglob("*.py"):
        if p.name.startswith("test_"):
            continue
        yield p


class FactoryIsFailClosedTests(unittest.TestCase):
    def test_default_driver_returns_intercepting_driver_or_none(self):
        # Never a third, non-intercepting driver type -- PlaywrightDriver (which
        # installs the route interceptor) or None when Playwright is absent.
        driver = browser_driver.default_driver()
        self.assertTrue(driver is None or isinstance(driver, PlaywrightDriver),
                        f"default_driver() returned a non-intercepting {type(driver)!r}")

    def test_playwright_driver_satisfies_the_browser_protocol(self):
        self.assertIsInstance(PlaywrightDriver(), BrowserDriver)


class SingleContextSiteTests(unittest.TestCase):
    def test_only_browser_driver_creates_a_browser_context(self):
        offenders = []
        for p in _nontest_py_files():
            if p.name == "browser_driver.py":
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
            if _CONTEXT_CREATION.search(text):
                offenders.append(str(p.relative_to(_HARNESS_DIR)))
        self.assertEqual(
            offenders, [],
            "browser context/engine created outside browser_driver.py -- a new "
            f"context site can bypass the route interceptor: {offenders}")

    def test_browser_validators_use_the_factory_not_raw_playwright(self):
        for rel in _BROWSER_VALIDATORS:
            text = (_HARNESS_DIR / rel).read_text(encoding="utf-8", errors="ignore")
            self.assertIn("default_driver", text,
                          f"{rel} must obtain its driver via browser_driver.default_driver")
            self.assertIsNone(
                _CONTEXT_CREATION.search(text),
                f"{rel} constructs a browser context directly instead of using the "
                "intercepting driver")


class ScopelessFallbackPolicyTests(unittest.TestCase):
    """The validators call visit() without a scope, so it falls back to
    ScopePolicy(allowed_hosts={host_of(url)}) (browser_driver.py:266). Re-assert
    PR-10's policy under exactly that fallback."""

    URL = "http://app.example/page"

    def setUp(self):
        self.run_origin = ScopePolicy.origin_of(self.URL)
        self.fallback = ScopePolicy(
            allowed_hosts=frozenset({ScopePolicy.host_of(self.URL)}))

    def _eval(self, url, *, method="GET", resource_type="document", is_navigation=True):
        return evaluate_browser_request(
            url=url, method=method, resource_type=resource_type,
            is_navigation=is_navigation, run_origin=self.run_origin, scope=self.fallback)

    def test_same_origin_navigation_allowed_with_credentials(self):
        d = self._eval(self.URL)
        self.assertTrue(d.allow)
        self.assertTrue(d.attach_credentials)

    def test_cross_host_navigation_blocked_no_credentials(self):
        d = self._eval("http://evil.example/x")
        self.assertFalse(d.allow)
        self.assertFalse(d.attach_credentials)

    def test_same_host_different_port_allowed_but_no_credentials(self):
        # host-scoped fallback admits the same host on another port, but the
        # cross-ORIGIN request must NOT receive the run identity's credentials.
        d = self._eval("http://app.example:9443/x", resource_type="fetch",
                       is_navigation=False)
        self.assertTrue(d.allow)
        self.assertFalse(d.attach_credentials)

    def test_non_get_navigation_blocked(self):
        d = self._eval(self.URL, method="POST")
        self.assertFalse(d.allow)

    def test_non_get_cross_origin_subrequest_blocked(self):
        d = self._eval("http://app.example:9443/x", method="POST",
                       resource_type="fetch", is_navigation=False)
        self.assertFalse(d.allow)

    def test_non_http_scheme_blocked(self):
        d = self._eval("ftp://app.example/x", resource_type="fetch", is_navigation=False)
        self.assertFalse(d.allow)

    def test_websocket_and_download_like_types_blocked(self):
        for rt in ("websocket", "other"):
            d = self._eval(self.URL, resource_type=rt, is_navigation=False)
            self.assertFalse(d.allow, f"resource_type {rt!r} should be blocked")


class CancellationSeamTests(unittest.TestCase):
    def test_none_is_never_cancelled(self):
        self.assertFalse(is_cancelled(None))

    def test_callable_and_event_signal_cancellation(self):
        self.assertTrue(is_cancelled(lambda: True))
        self.assertFalse(is_cancelled(lambda: False))
        ev = asyncio.Event()
        self.assertFalse(is_cancelled(ev))
        ev.set()
        self.assertTrue(is_cancelled(ev))


if __name__ == "__main__":
    unittest.main()
