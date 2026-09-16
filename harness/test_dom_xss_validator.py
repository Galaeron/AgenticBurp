"""Tests for the DOM-based XSS leg (V29), using a fake browser driver.

The distinguishing property vs browser_xss: the payload rides in the URL FRAGMENT
(never sent to the server), so a confirmed execution can only be a client-side
source->sink taint. The fake drivers model exactly that difference."""
import asyncio
import re
import unittest
from urllib.parse import urlsplit

from harness import global_throttle
from harness.browser_driver import ExecutionObservation
from harness.models import Finding, HttpExchange
from harness.validators.dom_xss_validator import DomXssValidator

_NONCE = re.compile(r"HARNESSDOM[0-9a-f]+")


class _DomSinkDriver:
    """A page whose DOM sink reads location.hash -> executes: fires the nonce only
    when it appears in the FRAGMENT (a real DOM-based XSS)."""
    def __init__(self):
        self.visited = []

    async def visit(self, url, *, wait_ms=1200, headers=None):
        self.visited.append(url)
        obs = ExecutionObservation(url=url)
        frag = urlsplit(url).fragment
        m = _NONCE.search(frag)
        if m:
            obs.console.append(f"fired {m.group(0)}")
        return obs


class _ServerReflectionOnlyDriver:
    """A page that reflects only what the SERVER echoes (query), never the
    fragment. Since dom_xss puts the payload in the fragment, this driver never
    fires -- the negative control proving dom_xss confirms DOM, not reflection."""
    def __init__(self):
        self.visited = []

    async def visit(self, url, *, wait_ms=1200, headers=None):
        self.visited.append(url)
        obs = ExecutionObservation(url=url)
        m = _NONCE.search(urlsplit(url).query)  # only query, never fragment
        if m:
            obs.console.append(f"fired {m.group(0)}")
        return obs


class _BrokenDriver:
    async def visit(self, url, *, wait_ms=1200, headers=None):
        return ExecutionObservation(url=url, load_error="Timeout")


def _finding():
    return Finding(vulnerability_class="dom_xss", confidence=0.6, summary="dom xss",
                   evidence="e", suggested_test="t", basis="derived")


def _exchange(url="https://shop.test/page?ref=1"):
    return HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                        response_status=200, response_headers={}, response_body="")


class DomXssValidatorTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    def _validate(self, driver, exchange=None, **kw):
        v = DomXssValidator(allowed_hosts=["shop.test"], driver=driver, **kw)
        return asyncio.run(v.validate(_finding(), exchange or _exchange()))

    def test_confirms_dom_sink_execution_from_fragment(self):
        r = self._validate(_DomSinkDriver())
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertIn("fragment", r.evidence.lower())

    def test_not_confirmed_when_only_server_reflection(self):
        # The key negative control: a server-reflection-only page never fires on a
        # fragment payload, so dom_xss must NOT confirm (that's browser_xss's job).
        r = self._validate(_ServerReflectionOnlyDriver())
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)

    def test_payload_is_in_fragment_never_query(self):
        d = _DomSinkDriver()
        self._validate(d)
        # every candidate URL carries the payload in the fragment, not the query
        self.assertTrue(d.visited)
        for u in d.visited:
            self.assertTrue(urlsplit(u).fragment, f"no fragment in {u}")

    def test_skips_out_of_scope(self):
        r = self._validate(_DomSinkDriver(), exchange=_exchange("https://evil.test/x#y"))
        self.assertEqual(r.status, "skipped")

    def test_degrades_cleanly_without_injected_driver(self):
        # No injected driver: either no browser is installed (-> skipped) or a real
        # browser is present but the fake host doesn't resolve (-> error/not_confirmed).
        # The contract is that it returns a clean result and never confirms/crashes.
        v = DomXssValidator(allowed_hosts=["shop.test"], driver=None)
        r = asyncio.run(v.validate(_finding(), _exchange()))
        self.assertIn(r.status, ("skipped", "not_confirmed", "error"))
        self.assertFalse(r.confirmed)

    def test_error_when_all_visits_fail(self):
        r = self._validate(_BrokenDriver())
        self.assertIn(r.status, ("error", "not_confirmed"))
        self.assertFalse(r.confirmed)


class RegistryTests(unittest.TestCase):
    def test_dom_xss_registered_and_active(self):
        from harness.validators.registry import ValidatorRegistry
        reg = ValidatorRegistry({"validators": {"active_enabled": True}})
        self.assertIn("dom_xss", reg.validators)
        self.assertTrue(reg.validators["dom_xss"].active)


if __name__ == "__main__":
    unittest.main()
