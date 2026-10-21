"""Code review 02, batch RV-O: RV-L's rule for four more validators, SSRF's late
callback, and RV-M's coverage-record residuals.

O1 header_injection, O2 command_injection, O3 stored_xss and O4
web_cache_poisoning returned a negative when no probe was answered. O5 lets an
SSRF out-of-band send that may have been delivered (the request was written,
the response was lost) wait for its callback. O6 lists unfinished coverage
cells and keeps unavailable live-leg reasons where the run can show them.

Each test drives the production caller, ``Orchestrator._validate_findings``,
with the transport faked below the gated client and the run transport (so the
gate and the run budget still decide). Every reproduction has a control that
must keep its old result.
"""
import asyncio
import html
import json
import re
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, unquote_plus

import httpx

from harness.browser_driver import ExecutionObservation
from harness.test_confirmation_soundness_rve import _finding, _json_exchange, _verdicts
from harness.test_default_history_caller import _exchange
from harness.test_unsent_not_negative_rvl import (_Collaborator, _RvlBase, _refuse_all, _response,
                                                  _text)
from harness.validators.command_injection_validator import CommandInjectionValidator
from harness.validators.header_injection_validator import HeaderInjectionValidator
from harness.validators.ssrf_validator import SsrfValidator
from harness.validators.stored_xss_validator import StoredXssValidator
from harness.validators.web_cache_poisoning_validator import WebCachePoisoningValidator


def _connect_error(method, url):
    return httpx.ConnectError("synthetic refused connection", request=httpx.Request(method, url))


# unittest.TestCase is named explicitly (already in _RvlBase's MRO) so the static
# collection guard in test_no_orphan_test_files sees these as test cases.
class _RvoBase(_RvlBase, unittest.TestCase):
    pass


# ---------------------------------------------------------- O1 header injection
def _header_echo(sent, *, inject=False, fail=lambda url: False):
    """A search page. With inject=True it splits a CRLF-carrying value into a
    response header, as a vulnerable server does."""
    async def request(client, method, url, **kwargs):
        u = unquote(str(url))
        sent.append((method, u))
        if fail(u):
            raise _connect_error(method, url)
        headers = ({"X-Harness-Crlf-Probe": "injected"}
                   if inject and "\r\nX-Harness-Crlf-Probe: injected" in u else {})
        return _response(method, url, text="<p>results</p>", headers=headers)
    return request


class HeaderInjectionUnsentTests(_RvoBase):
    """O1: no injected header after probes that never reached the target is not
    a negative."""

    URL = "http://shop.invalid/search?q=shoes&lang=en"

    def _run(self, fake, *, max_requests=None):
        v = HeaderInjectionValidator(allowed_hosts=["shop.invalid"], timeout=1.0)
        if max_requests is not None:
            return self._in_run("header_injection", v, _finding("header_injection"),
                                _exchange(self.URL), max_requests=max_requests, fake_request=fake)
        return self._validate("header_injection", v, _finding("header_injection"),
                              _exchange(self.URL), fake)

    def test_every_probe_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertEqual(len(sent), 2, "both parameters should have been probed")
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_every_probe_refused_by_the_budget_reads_as_blocked(self):
        sent = []
        reports = self._run(_refuse_all(sent), max_requests=0)
        self.assertEqual(sent, [], "a refused send reached the target")
        self._assert_not_negative(reports, "blocked")
        self.assertIn("budget_exhausted", _text(reports))

    def test_one_failed_probe_leaves_the_check_inconclusive(self):
        sent = []
        reports = self._run(_header_echo(sent, fail=lambda u: "lang=en\r\n" in u))
        self.assertEqual(len(sent), 2)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("'lang'", _text(reports))

    def test_injected_header_confirms(self):
        reports = self._run(_header_echo([], inject=True))
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))

    def test_answered_probes_without_injection_stay_negative(self):
        sent = []
        reports = self._run(_header_echo(sent))
        self.assertEqual(len(sent), 2)
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))


if __name__ == "__main__":
    unittest.main()
