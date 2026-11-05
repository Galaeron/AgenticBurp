"""ValidationResult.tested_parameters: what a per-parameter dispatch reports.

The coverage case driver binds a leg's verdict to a parameter case only when the
leg names exactly that input here. Each leg reports the one input a
parameter_only finding bound it to, sends to that input alone, and reports
nothing when it was not bound (the request-level R01 rule then applies).
Controls: an unbound run reports nothing, and a bound input the request lacks
is skipped as untested rather than reported.
"""
import asyncio
import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl, urlsplit

from harness import global_throttle, safety_gate
from harness.browser_driver import ExecutionObservation
from harness.models import Finding, HttpExchange
from harness.validators.browser_xss_validator import BrowserXssValidator
from harness.validators.injection_targets import NAMED_PARAMETER_UNTESTED, tested_inputs
from harness.validators.open_redirect_validator import OpenRedirectValidator
from harness.validators.ssrf_validator import SsrfValidator


def _finding(cls, name="", location="", only=False):
    return Finding(vulnerability_class=cls, confidence=0.5, summary="s", evidence="",
                   suggested_test="t", basis="derived", parameter_name=name,
                   parameter_location=location, parameter_only=only)


class TestedInputsTests(unittest.TestCase):
    def test_bound_single_target_is_reported_in_case_vocabulary(self):
        f = _finding("ssti", "note", "body_json", only=True)
        self.assertEqual(tested_inputs(f, [("body", "note")]), (("body_json", "note"),))

    def test_control_unbound_or_widened_reports_nothing(self):
        self.assertEqual(tested_inputs(_finding("ssti", "note", "query"), [("query", "note")]), ())
        bound = _finding("ssti", "note", "query", only=True)
        self.assertEqual(tested_inputs(bound, []), ())
        self.assertEqual(tested_inputs(bound, [("query", "note"), ("query", "q")]), ())


class _SafeDriver:
    def __init__(self):
        self.visited = []

    async def visit(self, url, *, wait_ms=1500, headers=None):
        self.visited.append(url)
        return ExecutionObservation(url=url)


class BrowserXssParameterOnlyTests(unittest.TestCase):
    URL = "https://shop.test/search?q=hello&lang=en"

    def setUp(self):
        global_throttle.configure(0)

    def _validate(self, finding):
        driver = _SafeDriver()
        v = BrowserXssValidator(allowed_hosts=["shop.test"], driver=driver)
        ex = HttpExchange(url=self.URL, method="GET", request_headers={}, request_body="",
                          response_status=200, response_headers={}, response_body="")
        return asyncio.run(v.validate(finding, ex)), driver.visited

    def test_bound_query_parameter_is_the_only_one_mutated(self):
        res, visited = self._validate(_finding("xss", "lang", "query", only=True))
        self.assertEqual(res.status, "not_confirmed")
        self.assertEqual(res.tested_parameters, (("query", "lang"),))
        self.assertTrue(visited)
        for url in visited:
            params = dict(parse_qsl(urlsplit(url).query))
            self.assertEqual(params["q"], "hello")
            self.assertNotEqual(params["lang"], "en")

    def test_control_unbound_run_reports_nothing(self):
        res, visited = self._validate(_finding("xss"))
        self.assertEqual(res.status, "not_confirmed")
        self.assertEqual(res.tested_parameters, ())
        self.assertTrue(any(dict(parse_qsl(urlsplit(u).query))["q"] != "hello" for u in visited))

    def test_control_bound_input_outside_the_query_is_untested(self):
        for name, location in (("zzz", "query"), ("lang", "body_form")):
            with self.subTest(location=location, name=name):
                res, visited = self._validate(_finding("xss", name, location, only=True))
                self.assertEqual(res.status, "skipped")
                self.assertEqual(res.control_outcome, NAMED_PARAMETER_UNTESTED)
                self.assertEqual(res.tested_parameters, ())
                self.assertEqual(visited, [])


class _FakeCollab:
    def __init__(self):
        self._n = 0

    def token(self):
        self._n += 1
        return f"oob{self._n}"

    def url(self, t):
        return f"http://collab.test/{t}"

    async def wait_for_hit(self, t, timeout=6.0):
        return False


class SsrfParameterOnlyTests(unittest.TestCase):
    def setUp(self):
        # The SSRF sends are mutating POSTs: the gate must allow mutating replay.
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                                      "allowed_hosts": ["t.test"]})
        self.addCleanup(safety_gate.reset_default_gate)

    def _validate(self, finding):
        bodies = []

        async def record(client, method, url, headers=None, content=None, **kw):
            bodies.append(json.loads(content) if content else {})

            class _R:
                status_code = 200
                text = "ok"
                headers = {}
            return _R()

        ex = HttpExchange(url="http://t.test/api/fetch", method="POST",
                          request_headers={"Content-Type": "application/json"},
                          request_body='{"url":"http://example.com","note":"x"}',
                          response_status=200, response_body="{}")
        v = SsrfValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(), timeout=0.01)
        with patch("httpx.AsyncClient.request", record):
            return asyncio.run(v.validate(finding, ex)), bodies

    def test_bound_body_key_is_the_only_one_mutated(self):
        res, bodies = self._validate(_finding("ssrf", "note", "body_json", only=True))
        self.assertEqual(res.status, "not_confirmed", res.summary)
        self.assertEqual(res.tested_parameters, (("body_json", "note"),))
        self.assertTrue(bodies)
        self.assertTrue(all(b["url"] == "http://example.com" for b in bodies))
        self.assertTrue(any(b["note"] != "x" for b in bodies))

    def test_control_unbound_run_reports_nothing(self):
        res, bodies = self._validate(_finding("ssrf"))
        self.assertEqual(res.status, "not_confirmed", res.summary)
        self.assertEqual(res.tested_parameters, ())
        self.assertTrue(any(b["url"] != "http://example.com" for b in bodies))

    def test_control_bound_input_the_request_lacks_is_untested(self):
        res, bodies = self._validate(_finding("ssrf", "zzz", "body_json", only=True))
        self.assertEqual(res.status, "skipped")
        self.assertEqual(res.control_outcome, NAMED_PARAMETER_UNTESTED)
        self.assertEqual(bodies, [])


class OpenRedirectParameterOnlyTests(unittest.TestCase):
    def test_control_bound_input_the_request_lacks_is_untested(self):
        ex = HttpExchange(url="http://t.test/login?next=/home", method="GET", request_headers={},
                          request_body="", response_status=200, response_body="")
        res = asyncio.run(OpenRedirectValidator(allowed_hosts=["t.test"]).validate(
            _finding("open_redirect", "zzz", "query", only=True), ex))
        self.assertEqual(res.status, "skipped")
        self.assertEqual(res.control_outcome, NAMED_PARAMETER_UNTESTED)
        self.assertEqual(res.tested_parameters, ())


if __name__ == "__main__":
    unittest.main()
