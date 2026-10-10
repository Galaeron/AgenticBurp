"""
Unit tests for browser_driver's two engine modes: local launch vs a
CONTAINERISED Chromium driven over CDP (the host-cleanliness option, mirroring
sqlmap-in-container). The Playwright layer is the mocked seam -- exactly how
sqlmap-in-container was unit-tested (docker seam mocked) -- so these run with or
without a real Playwright install and assert the ROUTING (which engine is used
and that the container endpoint is threaded through), not a live browser.

Live verification (a real `browserless/chrome` container answering CDP) is a
separate, environment-dependent step and is NOT what these cover.
"""
import asyncio
import sys
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from harness import browser_driver


def _fake_playwright():
    """A fake `async_playwright()` context manager whose chromium records whether
    launch() or connect_over_cdp() was used. Returns (callable, chromium_mock)."""
    chromium = MagicMock()
    browser = MagicMock()
    context = MagicMock()
    page = MagicMock()
    chromium.launch = AsyncMock(return_value=browser)
    chromium.connect_over_cdp = AsyncMock(return_value=browser)
    browser.new_context = AsyncMock(return_value=context)
    browser.close = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    context.close = AsyncMock()
    context.route = AsyncMock()  # PR-10: visit() now registers per-request interception
    context.add_cookies = AsyncMock()
    page.goto = AsyncMock()
    page.wait_for_timeout = AsyncMock()
    page.on = MagicMock()

    p = MagicMock()
    p.chromium = chromium

    class _CM:
        async def __aenter__(self):
            return p

        async def __aexit__(self, *a):
            return False

    return (lambda: _CM()), chromium


class CdpModeTest(unittest.TestCase):
    def _run_visit(self, cdp_endpoint):
        ap, chromium = _fake_playwright()
        # Inject a fake playwright.async_api so visit()'s lazy import resolves
        # whether or not real Playwright is installed here.
        fake_mod = types.ModuleType("playwright.async_api")
        fake_mod.async_playwright = ap
        fake_pkg = types.ModuleType("playwright")
        with patch.dict(sys.modules, {"playwright": fake_pkg, "playwright.async_api": fake_mod}):
            d = browser_driver.PlaywrightDriver(cdp_endpoint=cdp_endpoint)
            obs = asyncio.run(d.visit("http://localhost/x", wait_ms=0))
        return chromium, obs

    def test_cdp_endpoint_connects_over_cdp_not_launch(self):
        chromium, obs = self._run_visit("ws://127.0.0.1:3000")
        chromium.connect_over_cdp.assert_awaited_once()
        chromium.launch.assert_not_called()
        self.assertEqual(obs.load_error, "", f"unexpected load error: {obs.load_error}")

    def test_no_endpoint_launches_locally(self):
        chromium, obs = self._run_visit(None)
        chromium.launch.assert_awaited_once()
        chromium.connect_over_cdp.assert_not_called()
        self.assertEqual(obs.load_error, "", f"unexpected load error: {obs.load_error}")


class FactoryTest(unittest.TestCase):
    def test_default_driver_propagates_cdp_endpoint(self):
        with patch.object(browser_driver, "playwright_available", return_value=True):
            d = browser_driver.default_driver(cdp_endpoint="ws://c:3000")
        self.assertIsInstance(d, browser_driver.PlaywrightDriver)
        self.assertEqual(d.cdp_endpoint, "ws://c:3000")

    def test_default_driver_none_when_no_engine(self):
        with patch.object(browser_driver, "playwright_available", return_value=False):
            self.assertIsNone(browser_driver.default_driver(cdp_endpoint="ws://c:3000"))

    def test_available_reason_names_container_in_cdp_mode(self):
        with patch.object(browser_driver, "playwright_available", return_value=False):
            ok, reason = browser_driver.available("ws://c:3000")
        self.assertFalse(ok)
        self.assertIn("container", reason.lower())


class ValidatorThreadingTest(unittest.TestCase):
    def test_validator_threads_cdp_endpoint_to_driver(self):
        from harness.models import Finding, HttpExchange
        from harness.validators.browser_xss_validator import BrowserXssValidator

        v = BrowserXssValidator(allowed_hosts=["localhost"], cdp_endpoint="ws://c:3000")
        captured = {}

        def fake_default_driver(cdp_endpoint=None):
            captured["cdp"] = cdp_endpoint
            return None  # -> validator returns "skipped"; we only assert threading

        import harness.browser_driver as bd
        with patch.object(bd, "default_driver", side_effect=fake_default_driver), \
             patch.object(bd, "available", return_value=(False, "unavailable")):
            f = Finding(vulnerability_class="xss", confidence=0.5, summary="x",
                        evidence="", suggested_test="", basis="derived")
            ex = HttpExchange(url="http://localhost/x?q=1", method="GET",
                              request_headers={}, request_body="", response_status=200,
                              response_headers={}, response_body="<html></html>")
            asyncio.run(v.validate(f, ex))
        self.assertEqual(captured.get("cdp"), "ws://c:3000")


class ExtraHeadersAndCookiesTests(unittest.TestCase):
    """R25: splitting an identity's headers into Playwright's two channels."""

    def test_authorization_goes_to_extra_headers_cookie_to_cookies(self):
        from harness.browser_driver import _extra_headers_and_cookies
        extra, cookies = _extra_headers_and_cookies(
            {"Authorization": "Bearer alice", "Cookie": "session=abc; theme=dark"},
            "https://shop.test/x")
        self.assertEqual(extra, {"Authorization": "Bearer alice"})
        names = {c["name"]: c["value"] for c in cookies}
        self.assertEqual(names["session"], "abc")
        self.assertTrue(all(c["domain"] == "shop.test" for c in cookies))

    def test_none_headers_yield_anonymous(self):
        from harness.browser_driver import _extra_headers_and_cookies
        extra, cookies = _extra_headers_and_cookies(None, "https://shop.test/x")
        self.assertIsNone(extra)
        self.assertEqual(cookies, [])


if __name__ == "__main__":
    unittest.main()
