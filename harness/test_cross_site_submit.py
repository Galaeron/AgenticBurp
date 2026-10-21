"""Pure unit tests for the LB-5 cross-site-submit route POLICY
(`evaluate_cross_site_submit_request` / `CrossSitePlan` in browser_driver.py).

Mirrors how `evaluate_browser_request` is unit-tested in
test_browser_interception_gate.py: this is pure stdlib code with no
Playwright import, so the policy itself is fully exercised with Playwright
ABSENT. The real interception handler inside
`PlaywrightDriver.cross_site_submit` reuses this function unchanged -- these
tests lock in its narrow allow-list: EXACTLY the plan's three declared
requests (the synthesized attacker page, the one declared cross-origin
victim POST, the GET-only readback), everything else fails closed."""
from __future__ import annotations

import unittest

from harness.browser_driver import CrossSitePlan, evaluate_cross_site_submit_request


class CrossSiteSubmitPolicyTests(unittest.TestCase):
    def setUp(self):
        self.plan = CrossSitePlan(
            attacker_url="http://attacker.localhost/csrf-poc-attacker",
            victim_url="http://127.0.0.1:8080/csrf-poc/transfer",
            victim_method="POST",
            readback_url="http://127.0.0.1:8080/csrf-poc/state")

    def _eval(self, url, *, method="GET", resource_type="document", is_navigation=True):
        return evaluate_cross_site_submit_request(
            url=url, method=method, resource_type=resource_type,
            is_navigation=is_navigation, plan=self.plan)

    # --- the three declared requests -----------------------------------
    def test_attacker_page_is_fulfilled_locally_not_allowed_to_network(self):
        d = self._eval(self.plan.attacker_url)
        self.assertTrue(d.allow)
        self.assertTrue(d.fulfill_locally,
                        "the attacker page must be FULFILLED locally, never continue_()'d "
                        "to a real network fetch")

    def test_declared_victim_post_is_allowed_through_unchanged(self):
        d = self._eval(self.plan.victim_url, method="POST")
        self.assertTrue(d.allow)
        self.assertFalse(d.fulfill_locally,
                         "the victim POST must be a REAL network request, not fulfilled")

    def test_readback_get_is_allowed(self):
        d = self._eval(self.plan.readback_url, method="GET")
        self.assertTrue(d.allow)
        self.assertFalse(d.fulfill_locally)

    def test_method_matching_is_case_insensitive(self):
        d = self._eval(self.plan.victim_url, method="post")
        self.assertTrue(d.allow)

    # --- fail-closed on everything else ---------------------------------
    def test_attacker_page_wrong_method_blocked(self):
        d = self._eval(self.plan.attacker_url, method="POST")
        self.assertFalse(d.allow)
        self.assertFalse(d.fulfill_locally)

    def test_victim_url_wrong_method_blocked(self):
        d = self._eval(self.plan.victim_url, method="GET")
        self.assertFalse(d.allow)

    def test_readback_url_wrong_method_blocked(self):
        d = self._eval(self.plan.readback_url, method="POST")
        self.assertFalse(d.allow)

    def test_undeclared_url_blocked(self):
        d = self._eval("http://127.0.0.1:8080/csrf-poc/transfer-origin", method="POST")
        self.assertFalse(d.allow)

    def test_subresource_to_attacker_page_blocked(self):
        d = self._eval(self.plan.attacker_url, resource_type="script", is_navigation=False)
        self.assertFalse(d.allow)

    def test_subresource_to_victim_url_blocked(self):
        # Even the exact declared (method, url) pair must be a top-level
        # navigation -- a subresource fetch/xhr to the same URL is NOT one
        # of the three declared requests and must fail closed.
        d = self._eval(self.plan.victim_url, method="POST", resource_type="fetch",
                       is_navigation=False)
        self.assertFalse(d.allow)

    def test_non_navigation_document_blocked(self):
        d = self._eval(self.plan.victim_url, method="POST", is_navigation=False)
        self.assertFalse(d.allow)

    def test_non_http_scheme_blocked(self):
        d = self._eval("ftp://127.0.0.1:8080/csrf-poc/transfer", method="POST")
        self.assertFalse(d.allow)

    def test_websocket_resource_type_blocked(self):
        d = self._eval(self.plan.victim_url, method="POST", resource_type="websocket")
        self.assertFalse(d.allow)

    def test_unrelated_cross_origin_url_blocked(self):
        d = self._eval("http://evil.example/steal", method="GET")
        self.assertFalse(d.allow)
        self.assertFalse(d.fulfill_locally)

    # --- decisions are always a well-formed, reasoned tuple --------------
    def test_blocked_decisions_always_carry_a_reason(self):
        d = self._eval("http://evil.example/steal")
        self.assertFalse(d.allow)
        self.assertTrue(d.reason)

    def test_allowed_decisions_always_carry_a_reason(self):
        d = self._eval(self.plan.victim_url, method="POST")
        self.assertTrue(d.allow)
        self.assertTrue(d.reason)


if __name__ == "__main__":
    unittest.main()
