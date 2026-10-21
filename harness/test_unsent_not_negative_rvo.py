"""Code review 02, batch RV-O: RV-L's rule for four more validators, SSRF's late
callback, RV-M's coverage-record residuals, and the owner's XSS dialog rule.

O1 header_injection, O2 command_injection, O3 stored_xss and O4
web_cache_poisoning returned a negative when no probe was answered. O5 lets an
SSRF out-of-band send that may have been delivered (the request was written,
the response was lost) wait for its callback. O6 lists unfinished coverage
cells and keeps unavailable live-leg reasons where the run can show them. O8
(owner decision, 2026-10-21) lets a dialog showing the computed product confirm
XSS, and makes any other dialog or a page error a labelled candidate.

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

from harness import leg_self_test
from harness.browser_driver import ExecutionObservation
from harness.coverage_model import CellStatus, derive_input_cases
from harness.coverage_tracker import CoverageTracker, build_coverage, endpoint_view
from harness.orchestrator_confirm import log as confirm_log
from harness.test_coverage_tracker import _state_with
from harness.test_confirmation_soundness_rve import (_finding, _json_exchange, _note_server,
                                                     _verdicts)
from harness.test_default_history_caller import _exchange
from harness.test_unsent_not_negative_rvl import (_Collaborator, _RvlBase, _evaluate_logged,
                                                  _injected, _refuse_all, _response, _text)
from harness.validators import browser_xss_validator, dom_xss_validator, stored_xss_validator
from harness.validators.browser_xss_validator import BrowserXssValidator
from harness.validators.dom_xss_validator import DomXssValidator
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


# ---------------------------------------------------------------- O3 stored XSS
def _note_api(state, sent, *, render=lambda note: "<div>" + html.escape(note) + "</div>",
              fail=lambda method, url: False):
    """POST stores {"note": ...}; GET renders it as HTML (escaped by default)."""
    async def request(client, method, url, **kwargs):
        sent.append((method, str(url)))
        if fail(method, str(url)):
            raise _connect_error(method, url)
        if method == "POST":
            state.update(json.loads(kwargs["content"]))
            state["posted"] = True
            return _response(method, url, 201, "{}")
        return httpx.Response(200, text=render(state["note"]), headers={"Content-Type": "text/html"},
                              request=httpx.Request(method, url))
    return request


_FORM = ('<form method="POST" action="/post/comment">'
         '<input type="hidden" name="csrf" value="fresh-token">'
         '<input type="hidden" name="postId" value="1">'
         '<input type="text" name="comment"></form>')


def _blog(state, sent, *, fail=lambda method, url: False):
    """A blog post page carrying a CSRF-bound comment form; POST /post/comment
    stores the comment, rendered escaped under the form."""
    async def request(client, method, url, **kwargs):
        sent.append((method, str(url)))
        if fail(method, str(url)):
            raise _connect_error(method, url)
        if method == "POST":
            state["comment"] = parse_qs(kwargs.get("content") or "").get("comment", [""])[0]
            state["posted"] = True
            return _response(method, url, 302, "")
        return httpx.Response(200, text=_FORM + "<div>" + html.escape(state["comment"]) + "</div>",
                              headers={"Content-Type": "text/html"}, request=httpx.Request(method, url))
    return request


class _ExecutingDriver:
    """Boundary double for the browser: it logs what the planted payload's
    console.log computes (the product, E2), as an executing browser does."""

    def __init__(self, state):
        self.state, self.visits = state, []

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        m = re.search(r"console\.log\((\d+)\*(\d+)\)", self.state["note"])
        return ExecutionObservation(url=url, console=[str(int(m[1]) * int(m[2]))] if m else [])


class StoredXssUnsentTests(_RvoBase):
    """O3: a plant that never landed, or a render that was never read back, is
    not a negative. RV-E2's execution rule is unchanged."""

    URL = "http://shop.invalid/note"

    def _run(self, fake, *, driver=None, max_requests=None):
        v = StoredXssValidator(allowed_hosts=["shop.invalid"], timeout=1.0, driver=driver)
        ex = _json_exchange(self.URL, "POST", '{"note":"original"}')
        if max_requests is not None:
            return self._in_run("stored_xss", v, _finding("xss"), ex,
                                max_requests=max_requests, fake_request=fake)
        return self._validate("stored_xss", v, _finding("xss"), ex, fake)

    def _form_run(self, fake):
        ex = _json_exchange("http://shop.invalid/post/comment", "POST",
                            "postId=1&comment=hello&csrf=stale")
        ex.request_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        v = StoredXssValidator(allowed_hosts=["shop.invalid"], timeout=1.0)
        return self._validate("stored_xss", v, _finding("xss"), ex, fake)

    def test_every_plant_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertEqual([m for m, _ in sent], ["POST"] * 3, "each payload's plant should be tried")
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_every_plant_refused_by_the_budget_reads_as_blocked(self):
        sent = []
        reports = self._run(_refuse_all(sent), max_requests=0)
        self.assertEqual(sent, [], "a refused send reached the target")
        self._assert_not_negative(reports, "blocked")
        self.assertIn("budget_exhausted", _text(reports))

    def test_failed_render_after_a_successful_plant_is_not_a_negative(self):
        state, sent = {"note": "original"}, []
        reports = self._run(_note_api(state, sent, fail=lambda m, u: m == "GET"),
                            driver=_ExecutingDriver(state))
        self.assertTrue(state.get("posted"), "no plant landed -- vacuous")
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("render", _text(reports))

    def test_failed_render_through_a_fresh_source_form_is_not_a_negative(self):
        state, sent = {"comment": ""}, []
        reports = self._form_run(_blog(state, sent,
                                       fail=lambda m, u: m == "GET" and state.get("posted")))
        self.assertTrue(state.get("posted"), "no plant landed -- vacuous")
        self._assert_not_negative(reports, "inconclusive")

    def test_failed_plants_through_a_fresh_source_form_are_not_a_negative(self):
        state, sent = {"comment": ""}, []
        reports = self._form_run(_blog(state, sent, fail=lambda m, u: m == "POST"))
        self.assertIn(("GET", "http://shop.invalid/post?postId=1"), sent,
                      "the source form was never fetched")
        self._assert_not_negative(reports, "inconclusive")

    def test_executed_payload_still_confirms(self):
        state = {"note": "original"}
        reports = self._run(_note_api(state, [], render=lambda note: "<div>" + note + "</div>"),
                            driver=_ExecutingDriver(state))
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))

    def test_completed_plants_and_renders_without_execution_stay_negative(self):
        state, sent = {"note": "original"}, []
        reports = self._run(_note_api(state, sent), driver=_ExecutingDriver(state))
        self.assertIn("GET", [m for m, _ in sent])
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))

    def test_completed_source_form_plants_stay_negative(self):
        state, sent = {"comment": ""}, []
        reports = self._form_run(_blog(state, sent))
        self.assertTrue(state.get("posted"))
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))


# -------------------------------------------------------- O4 web cache poisoning
def _cache_front(sent, *, reflect=False, fail=lambda url, headers: False):
    """An origin behind a shared cache. reflect=True echoes X-Forwarded-Host
    into the body, the unkeyed-input primitive."""
    async def request(client, method, url, **kwargs):
        headers = kwargs.get("headers") or {}
        sent.append((method, str(url)))
        if fail(str(url), headers):
            raise _connect_error(method, url)
        xfh = headers.get("X-Forwarded-Host", "")
        body = f"<p>account</p>{xfh if reflect else ''}"
        return _response(method, url, text=body, headers={"Cache-Control": "public, max-age=60"})
    return request


class WebCachePoisoningUnsentTests(_RvoBase):
    """O4: no primitive observed after probes that never reached the target is
    not a negative. The candidate output (confirmation is retired) is unchanged."""

    URL = "http://shop.invalid/account/profile"

    def _run(self, fake, *, max_requests=None):
        v = WebCachePoisoningValidator(allowed_hosts=["shop.invalid"], timeout=1.0)
        if max_requests is not None:
            return self._in_run("web_cache_poisoning", v, _finding("web_cache_poisoning"),
                                _exchange(self.URL), max_requests=max_requests, fake_request=fake)
        return self._validate("web_cache_poisoning", v, _finding("web_cache_poisoning"),
                              _exchange(self.URL), fake)

    def test_every_probe_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertEqual(len(sent), 3)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_every_probe_refused_by_the_budget_reads_as_blocked(self):
        sent = []
        reports = self._run(_refuse_all(sent), max_requests=0)
        self.assertEqual(sent, [], "a refused send reached the target")
        self._assert_not_negative(reports, "blocked")
        self.assertIn("budget_exhausted", _text(reports))

    def test_failed_poisoning_probe_leaves_the_check_inconclusive(self):
        sent = []
        reports = self._run(_cache_front(sent, fail=lambda u, h: "X-Forwarded-Host" in h))
        self.assertEqual(len(sent), 3)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("poisoning probe", _text(reports))

    def test_unkeyed_reflection_keeps_the_candidate_output(self):
        reports = self._run(_cache_front([], reflect=True))
        self.assertEqual([(r.status, r.confidence) for r in reports], [("not_confirmed", 0.4)],
                         _verdicts(reports))
        self.assertIn("CANDIDATE", reports[0].summary)

    def test_answered_probes_without_a_primitive_stay_negative(self):
        sent = []
        reports = self._run(_cache_front(sent))
        self.assertEqual(len(sent), 3)
        self.assertEqual([(r.status, r.confidence) for r in reports], [("not_confirmed", 0.1)],
                         _verdicts(reports))


# ------------------------------------------------------- O5 SSRF late callback
class _WaitingCollaborator(_Collaborator):
    """Records every token the validator waited on, and for how long."""

    def __init__(self):
        super().__init__()
        self.waited = []

    async def wait_for_hit(self, token, timeout=0.0):
        self.waited.append((token, timeout))
        return token in self.hits


def _slow_fetcher(collab, sent, exc, *, fetches):
    """The in-band reads are answered. An out-of-band send fails with `exc`;
    with fetches=True the server fetched the callback URL first (a late callback
    from a request that did reach it)."""
    async def request(client, method, url, **kwargs):
        u = unquote_plus(str(url))
        sent.append((method, u))
        if "oob.collab.invalid" in u:
            if fetches:
                collab.hits.update(t for t in collab.issued if t in u)
            raise exc("synthetic: no response to the out-of-band send",
                      request=httpx.Request(method, url))
        return _response(method, url, text="<p>preview unavailable</p>")
    return request


class SsrfLateCallbackTests(_RvoBase):
    """O5: an out-of-band send whose response was lost after the request was
    written may still have been fetched; it waits the normal callback window.
    A send that never connected is not waited on."""

    URL = "http://shop.invalid/fetch?url=http%3A%2F%2Fexample.com%2Fa"

    def _run(self, fake, collab, *, in_run=False):
        v = SsrfValidator(allowed_hosts=["shop.invalid"], timeout=1.0, collaborator=collab)
        if in_run:
            return self._in_run("ssrf", v, _finding("ssrf"), _exchange(self.URL),
                                max_requests=200, fake_request=fake)
        return self._validate("ssrf", v, _finding("ssrf"), _exchange(self.URL), fake)

    def _late(self, exc, *, fetches, in_run):
        collab, sent = _WaitingCollaborator(), []
        reports = self._run(_slow_fetcher(collab, sent, exc, fetches=fetches), collab, in_run=in_run)
        self.assertTrue(any("oob.collab.invalid" in u for _, u in sent), "no out-of-band send")
        return reports, collab

    def test_late_callback_after_a_read_timeout_confirms(self):
        reports, collab = self._late(httpx.ReadTimeout, fetches=True, in_run=False)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))

    def test_late_callback_after_a_read_timeout_confirms_inside_a_run(self):
        reports, collab = self._late(httpx.ReadTimeout, fetches=True, in_run=True)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))

    def test_late_callback_after_the_server_dropped_the_reply_confirms(self):
        reports, collab = self._late(httpx.RemoteProtocolError, fetches=True, in_run=True)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))

    def test_read_timeout_without_a_callback_waits_and_stays_inconclusive(self):
        for in_run in (False, True):
            with self.subTest(in_run=in_run):
                reports, collab = self._late(httpx.ReadTimeout, fetches=False, in_run=in_run)
                self.assertEqual(collab.waited, [(collab.issued[0], 1.0)],
                                 "the delivered send's callback window was not waited")
                self._assert_not_negative(reports, "inconclusive")
                self.assertIn("ReadTimeout", _text(reports))
                self.assertIn("callback", reports[0].summary)

    def test_refused_connection_is_not_waited_on(self):
        for in_run in (False, True):
            with self.subTest(in_run=in_run):
                reports, collab = self._late(httpx.ConnectError, fetches=True, in_run=in_run)
                self.assertEqual(collab.waited, [], "a send that never connected was waited on")
                self._assert_not_negative(reports, "inconclusive")
                self.assertIn("ConnectError", _text(reports))


# ------------------------------------------------------ O6 coverage records
_TICKETS = "GET /api/tickets/{id}"
_IDOR = "WSTG-ATHZ-04"
# The statuses not_tested() listed before O6: a finalized report keeps exactly these.
_PRE_O6 = ("not_applicable", "skipped", "blocked", "inconclusive", "error")


def _tickets_state():
    return _state_with([("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]})])


class CoverageNotTestedTests(unittest.TestCase):
    """CoverageTracker.report() is the not_tested reader every build_coverage*
    run returns; build() leaves applicable cells PENDING until finalize."""

    def test_unfinalized_report_lists_pending_and_running_cells(self):
        tracker = CoverageTracker()
        tracker.build(endpoint_view(_tickets_state()), ["anonymous", "user"])
        tracker.matrix.record("user", _TICKETS, _IDOR, status=CellStatus.RUNNING)
        pending = [(ident, check) for (ident, _ep, check), cell in tracker.matrix.cells().items()
                   if cell.status == CellStatus.PENDING]
        self.assertTrue(pending)
        listed = {(item["identity"], item["check"]): item for item in tracker.report()["not_tested"]}
        for key in pending:
            self.assertEqual(listed[key]["status"], "pending")
            self.assertTrue(listed[key]["reason"])
        self.assertEqual(listed[("user", _IDOR)]["status"], "running")
        self.assertIn("still running", listed[("user", _IDOR)]["reason"])

    def test_finalized_report_is_unchanged(self):
        # Control: finalize turns every case-free PENDING cell SKIPPED, so the
        # production report lists the same cells as before O6.
        report = build_coverage(_tickets_state(), [type("R", (), {"role": "user"})()],
                                investigated_keys={_TICKETS})
        self.assertTrue(report["not_tested"])
        for item in report["not_tested"]:
            self.assertIn(item["status"], _PRE_O6)
        listed = sum(1 for item in report["not_tested"])
        self.assertEqual(listed, sum(report["by_status"].get(s, 0) for s in _PRE_O6))

    def test_case_bearing_parent_is_left_to_cases_not_tested(self):
        # Control: a parent whose cases are still open stays PENDING after
        # finalize; its open cases are already named in cases_not_tested, so
        # the finalized not_tested list is unchanged for it too.
        tracker = CoverageTracker()
        tracker.build(endpoint_view(_tickets_state()), ["user"])
        tracker.matrix.expand_cases("user", _TICKETS, _IDOR, derive_input_cases(query="id=7"))
        tracker.finalize_pending_reasons(investigated_keys={_TICKETS})
        self.assertEqual(tracker.matrix.get("user", _TICKETS, _IDOR).status, CellStatus.PENDING)
        report = tracker.report()
        self.assertNotIn(_IDOR, {item["check"] for item in report["not_tested"]})
        self.assertIn(_IDOR, {item["check"] for item in report["cases_not_tested"]})


class LiveMarkerReportTests(_RvoBase):
    """get_run_derived_live_markers on a real Orchestrator (the
    _analyze_inner caller reads only its return value)."""

    def _markers(self, fake):
        orch = self._orch()
        orch.config["leg_self_test"] = {"enabled": True}
        with patch.object(leg_self_test, "run_self_test", fake):
            return orch, asyncio.run(orch.get_run_derived_live_markers())

    def test_unavailable_reason_is_kept_on_the_orchestrator(self):
        seen = []

        def fake(report_out=None):
            seen.append(report_out)
            report_out.update({
                "xss": {"status": "unavailable", "reason": "needs Playwright"},
                "ssti": {"status": "live", "reason": "confirmed and refuted"}})
            return frozenset({"ssti"})

        with self.assertLogs(confirm_log, "INFO") as logs:
            orch, markers = self._markers(fake)
        self.assertEqual(markers, frozenset({"ssti"}))
        self.assertIs(seen[0], orch.leg_self_test_report)
        self.assertEqual(orch.leg_self_test_report["xss"],
                         {"status": "unavailable", "reason": "needs Playwright"})
        self.assertTrue(any("xss" in line and "needs Playwright" in line for line in logs.output))

    def test_markers_are_unchanged_by_the_report(self):
        # Control: the report never adds or removes a marker.
        def fake(report_out=None):
            report_out["xss"] = {"status": "unavailable", "reason": "needs Playwright"}
            return frozenset()

        _orch, markers = self._markers(fake)
        self.assertEqual(markers, frozenset())

    def test_crash_still_demotes_everything(self):
        # Control: the fail-safe is unchanged; the report is whatever was reached.
        def fake(report_out=None):
            raise RuntimeError("fixture would not start")

        orch, markers = self._markers(fake)
        self.assertEqual(markers, frozenset())
        self.assertEqual(orch.leg_self_test_report, {})


# ------------------------------------------------------ O8 XSS dialog rule
def _alerted(source: str) -> list[str]:
    """What a browser's alert dialog shows when an alert(a*b) payload runs."""
    return [f"alert:{int(a) * int(b)}" for a, b in re.findall(r"alert\((\d+)\*(\d+)\)", source)]


class _Page:
    """A browser double: `run(source)` maps the injected or stored text to the
    observation the page produces. A stored page reads the stored note."""

    def __init__(self, run, part="query", state=None):
        self.run, self.part, self.state, self.visits = run, part, state, []

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        source = self.state["note"] if self.state is not None else _injected(url, self.part)
        return ExecutionObservation(url=url, **self.run(source))


def _console(src):
    return {"console": _evaluate_logged(src)}


def _dialog_only(src):
    return {"dialogs": _alerted(src)}


def _own_alert(src):
    return {"dialogs": ["alert:Welcome back!"]}


def _page_error(src):
    return {"page_errors": ["TypeError: widget is undefined"]}


def _echo_console(src):
    return {"console": [src]}


def _echo_dialog(src):
    return {"dialogs": [f"alert:{src}"]}


class XssDialogRuleTests(_RvoBase):
    """O8 (owner decision, 2026-10-21): a console message or an alert/confirm/
    prompt dialog exactly equal to str(a*b) confirms; any other dialog or a page
    error is a labelled candidate, never not_confirmed; an echo never confirms."""

    def _browser(self, run):
        page = _Page(run, "query")
        return page, self._validate(
            "browser_xss", BrowserXssValidator(allowed_hosts=["shop.invalid"], driver=page),
            _finding("xss"), _exchange("http://shop.invalid/search?q=hello"))

    def _dom(self, run):
        page = _Page(run, "fragment")
        return page, self._validate(
            "dom_xss", DomXssValidator(allowed_hosts=["shop.invalid"], driver=page),
            _finding("dom_xss"), _exchange("http://shop.invalid/page?ref=1"))

    def _stored(self, run):
        state = {"note": "original"}
        page = _Page(run, state=state)
        return page, self._validate(
            "stored_xss", StoredXssValidator(allowed_hosts=["shop.invalid"], driver=page),
            _finding("xss"), _json_exchange("http://shop.invalid/note", "POST", '{"note":"original"}'),
            _note_server(state, lambda note: "<div>" + note + "</div>"))

    def _each(self):
        return (("browser_xss", self._browser), ("dom_xss", self._dom), ("stored_xss", self._stored))

    def test_console_execution_confirms(self):
        for key, run in self._each():
            with self.subTest(key):
                _page, reports = run(_console)
                self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))
                self.assertIn("console", _text(reports))
                self.assertNotIn("dialog only", _text(reports))

    def test_dialog_only_execution_with_the_product_confirms_and_says_so(self):
        for key, run in self._each():
            with self.subTest(key):
                _page, reports = run(_dialog_only)
                self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))
                self.assertTrue(reports[0].confirmed)
                self.assertIn("dialog only", reports[0].summary)
                self.assertIn("not by the console", reports[0].evidence)

    def test_page_alerting_something_else_is_a_labelled_candidate(self):
        for key, run in self._each():
            with self.subTest(key):
                page, reports = run(_own_alert)
                self.assertTrue(page.visits, "no page was loaded -- vacuous")
                self.assertFalse(any(r.confirmed for r in reports), _text(reports))
                self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
                self.assertIn("a dialog fired, but not with the computed value; check manually",
                              _text(reports))

    def test_page_error_is_a_labelled_candidate(self):
        for key, run in self._each():
            with self.subTest(key):
                page, reports = run(_page_error)
                self.assertTrue(page.visits, "no page was loaded -- vacuous")
                self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
                self.assertIn("a page error was raised, but no computed value was shown; "
                              "check manually", _text(reports))

    def test_echoed_payload_never_confirms(self):
        # Control: the payload's source, logged or shown in a dialog, holds the
        # operands, not the product. A console echo keeps its old verdict
        # (stored XSS: the raw render is a candidate); a dialog echo is a
        # labelled candidate (O8), never a confirm.
        old = {"browser_xss": "not_confirmed", "dom_xss": "not_confirmed", "stored_xss": "inconclusive"}
        for key, run in self._each():
            with self.subTest(key, echo="console"):
                page, reports = run(_echo_console)
                self.assertTrue(page.visits, "no page was loaded -- vacuous")
                self.assertFalse(any(r.confirmed for r in reports), _text(reports))
                self.assertEqual([r.status for r in reports], [old[key]], _verdicts(reports))
            with self.subTest(key, echo="dialog"):
                _page, reports = run(_echo_dialog)
                self.assertFalse(any(r.confirmed for r in reports), _text(reports))
                self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
                self.assertIn("not with the computed value", _text(reports))

    def test_every_payload_alerts_and_logs_the_product_it_never_contains(self):
        payload_sets = (browser_xss_validator._payloads, dom_xss_validator._fragment_payloads,
                        stored_xss_validator._payloads)
        for _ in range(20):
            a, b, expected = stored_xss_validator._challenge()
            for make in payload_sets:
                for payload in make(a, b):
                    with self.subTest(payload=payload):
                        self.assertNotIn(expected, payload)
                        self.assertEqual(_evaluate_logged(payload), [expected])
                        self.assertEqual(_alerted(payload), [f"alert:{expected}"])


if __name__ == "__main__":
    unittest.main()
