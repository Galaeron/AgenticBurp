"""
Unit tests for the PR-10 / R01 browser interception policy.

`browser_driver.evaluate_browser_request` and `browser_driver.is_cancelled` are
pure, stdlib-only functions -- no Playwright import anywhere in this module or
in the code paths under test -- so these tests are deterministic and run with
Playwright ABSENT (it is not installed in this environment). They cover the
OFFLINE half of PR-10: the interception-DECISION function and the cancel seam.
The LIVE half (a real two-origin browser run proving an owned off-scope
listener gets zero requests/credentials) is OWNER/LIVE and is NOT covered here.

No `*ANSWER_KEY*` or blind-target `app.py` is read by this file.
"""
from __future__ import annotations

import asyncio
import unittest

from harness.browser_driver import (
    BrowserRequestDecision,
    evaluate_browser_request,
    is_cancelled,
    playwright_available,
)
from harness.run_context import ScopePolicy


TARGET_SCOPE = ScopePolicy(allowed_hosts=frozenset({"target.test"}))
TWO_HOST_SCOPE = ScopePolicy(allowed_hosts=frozenset({"target.test", "second.test"}))
RUN_ORIGIN = "https://target.test"


def _decide(url, *, method="GET", resource_type="document", is_navigation=True,
            run_origin=RUN_ORIGIN, scope=TARGET_SCOPE) -> BrowserRequestDecision:
    return evaluate_browser_request(
        url=url, method=method, resource_type=resource_type,
        is_navigation=is_navigation, run_origin=run_origin, scope=scope)


class ModuleImportsWithoutPlaywrightTest(unittest.TestCase):
    """PR-10 requires the decision function to work with Playwright ABSENT."""

    def test_playwright_is_not_installed_here(self):
        # Documents the environment this suite actually runs in -- if this
        # ever flips true, the other assertions in this class still hold
        # (evaluate_browser_request never imports playwright either way).
        self.assertFalse(playwright_available())

    def test_evaluate_browser_request_runs_with_playwright_absent(self):
        decision = _decide("https://target.test/", resource_type="document")
        self.assertTrue(decision.allow)


class NegativeControlTest(unittest.TestCase):
    """The normal happy path must not be broken by the new policy."""

    def test_in_scope_same_origin_get_document_allowed_with_credentials(self):
        decision = _decide(
            "https://target.test/page", method="GET",
            resource_type="document", is_navigation=True)
        self.assertTrue(decision.allow, decision.reason)
        self.assertTrue(decision.attach_credentials, decision.reason)


class OffOriginSubresourceTest(unittest.TestCase):
    def test_subresource_to_different_origin_out_of_scope_is_blocked(self):
        decision = _decide(
            "https://evil.test/steal.js", method="GET",
            resource_type="script", is_navigation=False)
        self.assertFalse(decision.allow)
        self.assertFalse(decision.attach_credentials)
        self.assertIn("scope", decision.reason)

    def test_subresource_to_different_but_in_scope_origin_is_allowed(self):
        # Two hosts approved for this run; a same-run-origin page pulling a
        # script from the OTHER approved host is allowed (it's in scope)...
        decision = _decide(
            "https://second.test/lib.js", method="GET",
            resource_type="script", is_navigation=False, scope=TWO_HOST_SCOPE)
        self.assertTrue(decision.allow, decision.reason)


class CredentialAttachmentTest(unittest.TestCase):
    def test_same_origin_in_scope_request_attaches_credentials(self):
        decision = _decide(
            "https://target.test/api/data", method="GET",
            resource_type="xhr", is_navigation=False)
        self.assertTrue(decision.allow)
        self.assertTrue(decision.attach_credentials)

    def test_off_origin_request_never_attaches_credentials_even_when_allowed(self):
        # In scope (second host is approved) but NOT the run's own origin --
        # allowed, but credentials must never be forwarded there.
        decision = _decide(
            "https://second.test/lib.js", method="GET",
            resource_type="script", is_navigation=False, scope=TWO_HOST_SCOPE)
        self.assertTrue(decision.allow, decision.reason)
        self.assertFalse(decision.attach_credentials,
                          "Authorization must not follow a request off the run's origin")

    def test_out_of_scope_off_origin_request_blocked_and_no_credentials(self):
        decision = _decide(
            "https://evil.test/collect", method="GET",
            resource_type="xhr", is_navigation=False)
        self.assertFalse(decision.allow)
        self.assertFalse(decision.attach_credentials)


class RedirectReEvaluationTest(unittest.TestCase):
    """A redirect is a NEW request/origin and must be re-checked independently."""

    def test_redirect_to_new_out_of_scope_origin_is_blocked(self):
        first = _decide(
            "https://target.test/login", method="GET",
            resource_type="document", is_navigation=True)
        self.assertTrue(first.allow, first.reason)

        redirected = _decide(
            "https://attacker.test/login", method="GET",
            resource_type="document", is_navigation=True)
        self.assertFalse(redirected.allow)
        self.assertFalse(redirected.attach_credentials)

    def test_redirect_within_scope_and_same_origin_stays_allowed_with_credentials(self):
        redirected = _decide(
            "https://target.test/login?next=/dashboard", method="GET",
            resource_type="document", is_navigation=True)
        self.assertTrue(redirected.allow)
        self.assertTrue(redirected.attach_credentials)


class SchemeTest(unittest.TestCase):
    def test_websocket_scheme_blocked(self):
        decision = _decide("ws://target.test/socket", resource_type="websocket",
                           is_navigation=False)
        self.assertFalse(decision.allow)
        self.assertIn("scheme", decision.reason)

    def test_secure_websocket_scheme_blocked(self):
        decision = _decide("wss://target.test/socket", resource_type="websocket",
                           is_navigation=False)
        self.assertFalse(decision.allow)

    def test_file_scheme_blocked(self):
        decision = _decide("file:///etc/passwd", resource_type="document",
                           is_navigation=True)
        self.assertFalse(decision.allow)
        self.assertIn("scheme", decision.reason)

    def test_data_uri_navigation_blocked(self):
        decision = _decide("data:text/html,<script>alert(1)</script>",
                           resource_type="document", is_navigation=True)
        self.assertFalse(decision.allow)
        self.assertIn("scheme", decision.reason)

    def test_blob_scheme_blocked(self):
        decision = _decide("blob:https://target.test/uuid",
                           resource_type="document", is_navigation=False)
        self.assertFalse(decision.allow)


class ResourceTypeTest(unittest.TestCase):
    def test_service_worker_resource_type_blocked(self):
        decision = _decide("https://target.test/sw.js", resource_type="service_worker",
                           is_navigation=False)
        self.assertFalse(decision.allow)
        self.assertIn("resource_type", decision.reason)

    def test_websocket_resource_type_blocked(self):
        decision = _decide("https://target.test/socket", resource_type="websocket",
                           is_navigation=False)
        self.assertFalse(decision.allow)

    def test_download_like_other_resource_type_blocked(self):
        # Playwright has no distinct "download" resource_type; a download-style
        # response is conservatively covered by blocking its catch-all "other".
        decision = _decide("https://target.test/report.pdf", resource_type="other",
                           is_navigation=False)
        self.assertFalse(decision.allow)

    def test_allowed_resource_types_pass_when_in_scope(self):
        for rtype in ("document", "script", "xhr", "fetch", "image", "stylesheet", "font"):
            with self.subTest(resource_type=rtype):
                decision = _decide("https://target.test/asset", resource_type=rtype,
                                   is_navigation=(rtype == "document"))
                self.assertTrue(decision.allow, f"{rtype}: {decision.reason}")


class MethodTest(unittest.TestCase):
    def test_navigation_must_be_get(self):
        decision = _decide("https://target.test/", method="POST",
                           resource_type="document", is_navigation=True)
        self.assertFalse(decision.allow)
        self.assertIn("GET", decision.reason)

    def test_non_get_subrequest_same_origin_allowed(self):
        decision = _decide("https://target.test/api/items", method="POST",
                           resource_type="xhr", is_navigation=False)
        self.assertTrue(decision.allow, decision.reason)
        self.assertTrue(decision.attach_credentials)

    def test_non_get_subrequest_off_origin_blocked(self):
        decision = _decide("https://second.test/api/items", method="POST",
                           resource_type="xhr", is_navigation=False, scope=TWO_HOST_SCOPE)
        self.assertFalse(decision.allow)
        self.assertFalse(decision.attach_credentials)

    def test_get_subrequest_off_run_origin_but_in_scope_still_allowed(self):
        decision = _decide("https://second.test/api/items", method="GET",
                           resource_type="xhr", is_navigation=False, scope=TWO_HOST_SCOPE)
        self.assertTrue(decision.allow, decision.reason)
        self.assertFalse(decision.attach_credentials)


class CancelSeamTest(unittest.TestCase):
    """The interception handler checks `is_cancelled(cancel)` before dispatching
    every request and aborts when it is set. This exercises that seam directly,
    without launching a browser, per the PR-10 acceptance criteria."""

    def test_none_is_never_cancelled(self):
        self.assertFalse(is_cancelled(None))

    def test_unset_asyncio_event_is_not_cancelled(self):
        self.assertFalse(is_cancelled(asyncio.Event()))

    def test_set_asyncio_event_is_cancelled(self):
        ev = asyncio.Event()
        ev.set()
        self.assertTrue(is_cancelled(ev))

    def test_callable_returning_false_is_not_cancelled(self):
        self.assertFalse(is_cancelled(lambda: False))

    def test_callable_returning_true_is_cancelled(self):
        self.assertTrue(is_cancelled(lambda: True))

    def test_visit_short_circuits_before_navigation_when_pre_cancelled(self):
        """End-to-end offline proof (Playwright ABSENT in this environment):
        `PlaywrightDriver.visit` checks the cancel signal before it even
        attempts the Playwright import, so a cancelled visit never dispatches
        anything -- observable here as "cancelled before navigation" rather
        than the "playwright import failed" error a non-cancelled call would
        get in this environment."""
        from harness.browser_driver import PlaywrightDriver

        driver = PlaywrightDriver()
        ev = asyncio.Event()
        ev.set()
        obs = asyncio.run(driver.visit("https://target.test/", cancel=ev))
        self.assertEqual(obs.load_error, "cancelled before navigation")

    def test_visit_without_cancel_does_not_short_circuit(self):
        """Sanity: omitting `cancel` does not accidentally trip the seam above
        -- with Playwright absent it fails later, on the import, not on a
        cancel check that should never have fired."""
        from harness.browser_driver import PlaywrightDriver

        driver = PlaywrightDriver()
        obs = asyncio.run(driver.visit("https://target.test/"))
        self.assertNotEqual(obs.load_error, "cancelled before navigation")


if __name__ == "__main__":
    unittest.main()
