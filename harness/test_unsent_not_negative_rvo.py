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


# --------------------------------------------------------- O2 command injection
class _LoopbackCollaborator(_Collaborator):
    """A collaborator a remote target cannot reach, so the out-of-band phase is
    skipped and only the in-band probes decide."""

    def url(self, token):
        return f"http://127.0.0.1:9/{token}"


def _shell(collab, sent, *, echo=False, fetches=False, fail=lambda url: False):
    """A ping page. echo=True runs the in-band printf (joins its two pieces);
    fetches=True runs the out-of-band fetch (records the collaborator hit)."""
    async def request(client, method, url, **kwargs):
        u = unquote_plus(str(url))
        sent.append((method, u))
        if fail(u):
            raise _connect_error(method, url)
        text = "<p>pinged</p>"
        m = re.search(r"printf (\S+)%s (\S+)", u)
        if echo and m:
            text += m[1] + m[2]
        if fetches:
            collab.hits.update(t for t in collab.issued if t in u)
        return _response(method, url, text=text)
    return request


class CommandInjectionUnsentTests(_RvoBase):
    """O2: no marker and no callback after sends that never reached the target
    is not a negative. The leg has no timing branch (in-band marker and
    out-of-band callback only), so there is no 'no delay' negative to fix."""

    URL = "http://shop.invalid/ping?host=example.com"

    def _run(self, fake, *, collab=None, max_requests=None):
        collab = collab or _Collaborator()
        v = CommandInjectionValidator(allowed_hosts=["shop.invalid"], timeout=1.0,
                                      collaborator=collab)
        if max_requests is not None:
            return self._in_run("command_injection", v, _finding("command_injection"),
                                _exchange(self.URL), max_requests=max_requests, fake_request=fake)
        return self._validate("command_injection", v, _finding("command_injection"),
                              _exchange(self.URL), fake)

    def test_every_send_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertGreater(len(sent), 3, "the out-of-band phase never ran")
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_every_send_failing_inside_a_run_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent), max_requests=200)
        self.assertGreater(len(sent), 3)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_every_send_refused_by_the_budget_reads_as_blocked(self):
        sent = []
        reports = self._run(_refuse_all(sent), max_requests=0)
        self.assertEqual(sent, [], "a refused send reached the target")
        self._assert_not_negative(reports, "blocked")
        self.assertIn("budget_exhausted", _text(reports))

    def test_failed_in_band_sends_before_the_loopback_exit_are_not_a_negative(self):
        # The second exit: a loopback collaborator skips the out-of-band phase.
        sent = []
        reports = self._run(_refuse_all(sent), collab=_LoopbackCollaborator())
        self.assertEqual(len(sent), 3, "only the in-band forms should run")
        self._assert_not_negative(reports, "inconclusive")

    def test_failed_out_of_band_sends_after_answered_in_band_probes_are_inconclusive(self):
        sent, collab = [], _Collaborator()
        reports = self._run(_shell(collab, sent, fail=lambda u: "oob.collab.invalid" in u),
                            collab=collab)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("out-of-band", _text(reports))

    def test_in_band_marker_confirms(self):
        sent, collab = [], _Collaborator()
        reports = self._run(_shell(collab, sent, echo=True), collab=collab)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))

    def test_callback_confirms(self):
        sent, collab = [], _Collaborator()
        reports = self._run(_shell(collab, sent, fetches=True), collab=collab)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))

    def test_answered_probes_without_marker_or_callback_stay_negative(self):
        sent, collab = [], _Collaborator()
        reports = self._run(_shell(collab, sent), collab=collab)
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))

    def test_answered_in_band_probes_before_the_loopback_exit_stay_negative(self):
        sent = []
        reports = self._run(_shell(None, sent), collab=_LoopbackCollaborator())
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))


if __name__ == "__main__":
    unittest.main()
