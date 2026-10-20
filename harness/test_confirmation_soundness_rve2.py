"""Code review 02, batch RV-E2 (I10): the residual false confirmations E1, E2
and E3 that RV-E left in the mass-assignment, stored-XSS and session-fixation
legs (reviews/2026-10-20-rvei-implementation-verification/REPORT.md).

Each reviewer check from adversarial_checks.py is ported unchanged in substance
and drives the production caller, ``Orchestrator._validate_findings``, through
the helpers of test_confirmation_soundness_rve. Every finding also has a
positive control that must still confirm. The stored-XSS source-echo check runs
in a real headless Chromium when Playwright is installed, and as a driver double
everywhere.
"""
import json
import re
import unittest

import httpx

from harness import browser_driver
from harness.browser_driver import ExecutionObservation
from harness.test_confirmation_soundness_rve import (
    _CallerBase, _exchange, _finding, _json_exchange, _NoteApp, _note_server, _verdicts,
)
from harness.testing_fixtures.mass_assignment import MassAssignmentFixture
from harness.validators import stored_xss_validator
from harness.validators.api_security_validator import ApiSecurityValidator
from harness.validators.auth_sequence_validator import AuthSequenceValidator
from harness.validators.stored_xss_validator import StoredXssValidator


def _evidence(reports):
    return [(r.status, r.evidence) for r in reports]


# ------------------------------------------------------ E1 mass assignment
class MassAssignmentBaselineTests(_CallerBase):
    """E1: confirmation needs a controlled change on the written object -- the
    probe field absent or different in a baseline read before the write, and
    the submitted value in an independent read-back after an accepted write."""

    def _run(self, exchange, fake_request=None, hosts=("shop.invalid",)):
        return self._validate("api_security", ApiSecurityValidator(), _finding("mass_assignment"),
                              exchange, fake_request, hosts)

    def _profile(self):
        return _json_exchange("http://shop.invalid/profile", "POST", '{"name":"Alice"}')

    def test_existing_probe_field_is_not_a_proven_write(self):
        # The reviewer's repro: the write ignores every field; GET shows the
        # probe field already true from before.
        sent = []

        async def request(client, method, url, **kwargs):
            sent.append(method)
            body = {} if method == "POST" else {"name": "Alice", "harnessProbeIsAdmin": True}
            return httpx.Response(200, json=body, request=httpx.Request(method, url))
        reports = self._run(self._profile(), request)
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        self.assertEqual(sent[0], "GET", "the baseline must be read before the write")

    def test_previously_probed_object_confirms_by_writing_a_different_value(self):
        # Positive control: a vulnerable object that an earlier probe left at
        # true. The probe submits false, and the read-back shows the change.
        state = {"name": "Alice", "harnessProbeIsAdmin": True}
        written = []

        async def request(client, method, url, **kwargs):
            if method == "POST":
                body = json.loads(kwargs["content"])
                written.append(body.get("harnessProbeIsAdmin"))
                state.update(body)
            return httpx.Response(200, json=dict(state), request=httpx.Request(method, url))
        reports = self._run(self._profile(), request)
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))
        self.assertEqual(written, [False], "the submitted value must differ from the baseline")

    def test_unreadable_baseline_leaves_a_stored_field_a_candidate(self):
        # The field is stored, but the baseline GET failed, so "absent before"
        # was never shown.
        state, gets = {"name": "Alice"}, []

        async def request(client, method, url, **kwargs):
            if method == "POST":
                state.update(json.loads(kwargs["content"]))
                return httpx.Response(200, json={}, request=httpx.Request(method, url))
            gets.append(url)
            if len(gets) == 1:
                return httpx.Response(503, text="busy", request=httpx.Request(method, url))
            return httpx.Response(200, json=dict(state), request=httpx.Request(method, url))
        reports = self._run(self._profile(), request)
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn("baseline", reports[0].summary.lower())

    def test_new_object_without_a_baseline_is_a_candidate(self):
        # A create that points at a new object: its state before the write
        # cannot be read, so the field there is a candidate, not a change shown.
        async def request(client, method, url, **kwargs):
            req = httpx.Request(method, url)
            if method == "POST":
                return httpx.Response(201, headers={"Location": "/profile/9"}, request=req)
            if str(url).endswith("/profile/9"):
                return httpx.Response(200, json={"id": 9, "harnessProbeIsAdmin": True}, request=req)
            return httpx.Response(200, json={"items": []}, request=req)
        reports = self._run(self._profile(), request)
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))

    def test_confirmation_claims_field_binding_not_a_protected_property(self):
        # Positive control on the owned vulnerable API, and the wording: the
        # harness-invented field is arbitrary metadata, not a protected property.
        fx = MassAssignmentFixture("vulnerable")
        self.addCleanup(fx.close)
        reports = self._run(_json_exchange(fx.user_url("1"), "PATCH", '{"username": "alice"}'),
                            hosts=("127.0.0.1",))
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))
        text = (reports[0].summary + " " + reports[0].evidence).lower()
        self.assertNotIn("would be stored too", text)
        self.assertIn("protected property", text)
        self.assertIn("absent", text)
        self.assertEqual([r["method"] for r in fx.requests_for("/users/1")], ["GET", "PATCH", "GET"])


# ------------------------------------------------------------ E2 stored XSS
def _evaluate_logged(source: str) -> list[str]:
    """What a browser logs when the payload's console.log runs: the computed
    value, never the source text."""
    return [str(int(a) * int(b)) for a, b in re.findall(r"console\.log\((\d+)\*(\d+)\)", source)]


class _EchoingDriver:
    """A browser whose page logs the stored text itself (debugging that prints
    a field's value): the payload's source reaches the console, unexecuted."""

    def __init__(self, state):
        self.state, self.visits = state, []

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        return ExecutionObservation(url=url, console=[self.state["note"]],
                                    dialogs=[self.state["note"]], page_errors=[self.state["note"]])


class _ComputingDriver(_EchoingDriver):
    """A browser that runs the payload: it logs the computed value only."""

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        return ExecutionObservation(url=url, console=_evaluate_logged(self.state["note"]))


class StoredXssExactEventTests(_CallerBase):
    """E2: only an exact console event carrying a value the payload computes at
    run time confirms. The stored source holds the operands, not the result,
    so echoing the source never matches."""

    def _run(self, driver_cls, render):
        state = {"note": "original"}
        v = StoredXssValidator(allowed_hosts=["shop.invalid"], driver=driver_cls(state))
        return self._validate("stored_xss", v, _finding("xss"),
                              _json_exchange("http://shop.invalid/note", "POST", '{"note":"original"}'),
                              _note_server(state, render))

    def test_logged_payload_source_is_not_execution(self):
        reports = self._run(_EchoingDriver, lambda note: "<textarea>" + note + "</textarea>")
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))

    def test_computed_value_from_execution_confirms(self):
        reports = self._run(_ComputingDriver, lambda note: "<div>" + note + "</div>")
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))
        self.assertIn("executed", reports[0].evidence.lower())

    def test_expected_value_never_appears_in_the_stored_text(self):
        for _ in range(50):
            a, b, expected = stored_xss_validator._challenge()
            self.assertEqual(expected, str(a * b))
            for payload in stored_xss_validator._payloads(a, b):
                self.assertNotIn(expected, payload)
                self.assertEqual(_evaluate_logged(payload), [expected])


@unittest.skipUnless(browser_driver.playwright_available(), "playwright not installed")
class StoredXssSourceEchoRealBrowserTests(_CallerBase):
    """E2 with a real headless Chromium against the owned loopback note app."""

    def _run(self, mode, echo_script):
        app = _NoteApp(mode)
        self.addCleanup(app.close)
        handler = app.httpd.RequestHandlerClass
        original = handler._send

        def send(instance, status, body, ctype):
            if "html" in ctype:
                body += echo_script
            return original(instance, status, body, ctype)
        handler._send = send
        return self._validate("stored_xss", StoredXssValidator(allowed_hosts=["127.0.0.1"]),
                              _finding("xss"), _json_exchange(app.url, "POST", '{"note":"original"}'),
                              hosts=("127.0.0.1",))

    def test_logging_inert_payload_source_is_not_payload_execution(self):
        # The reviewer's repro: benign debugging logs the textarea, never runs it.
        reports = self._run("textarea",
                            "<script>console.log(document.querySelector('textarea').value)</script>")
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))

    def test_executing_payload_confirms_beside_unrelated_logging(self):
        reports = self._run("raw", "<script>console.log(document.title || 'notes page')</script>")
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))


# ------------------------------------------------------ E3 session fixation
class SessionFixationAnonymousControlTests(_CallerBase):
    """E3: the anonymous comparison counts only as a completed, healthy,
    interpretable denial (401/403, a redirect to a login page, a login page).
    A 5xx, a timeout or any other answer leaves fixation inconclusive."""

    def _run(self, anonymous):
        async def request(client, method, url, **kwargs):
            req = httpx.Request(method, url)
            if str(url).endswith("/"):
                return httpx.Response(200, text="Welcome", headers={"Set-Cookie": "sid=fixed; Path=/"},
                                      request=req)
            if method == "POST":
                return httpx.Response(302, headers={"Location": "/account"}, request=req)
            hdrs = {k.lower(): v for k, v in (kwargs.get("headers") or {}).items()}
            if "cookie" in hdrs:
                return httpx.Response(
                    200, text="<html>Account for alice, information and preferences. Log out</html>",
                    request=req)
            return anonymous(req)
        ex = _exchange("http://shop.invalid/login", {"Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "username=alice&password=correct"
        return self._validate("auth_sequence", AuthSequenceValidator(allowed_hosts=["shop.invalid"]),
                              _finding("session_fixation"), ex, request)

    def _assert_inconclusive(self, reports):
        self.assertFalse(any(r.confirmed for r in reports), _evidence(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        self.assertNotIn("was denied", reports[0].evidence)

    def test_anonymous_500_does_not_prove_session_denial(self):
        reports = self._run(lambda req: httpx.Response(500, text="temporary upstream failure", request=req))
        self._assert_inconclusive(reports)
        self.assertIn("500", reports[0].evidence)

    def test_anonymous_timeout_does_not_prove_session_denial(self):
        def timeout(req):
            raise httpx.ReadTimeout("synthetic unavailable anonymous control", request=req)
        reports = self._run(timeout)
        self._assert_inconclusive(reports)
        self.assertIn("ReadTimeout", reports[0].evidence)

    def test_anonymous_404_is_not_an_authorization_denial(self):
        reports = self._run(lambda req: httpx.Response(404, text="not found", request=req))
        self._assert_inconclusive(reports)

    def test_anonymous_401_confirms(self):
        reports = self._run(lambda req: httpx.Response(401, text="login required", request=req))
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))
        self.assertIn("HTTP 401", reports[0].evidence)

    def test_anonymous_redirect_to_login_confirms(self):
        reports = self._run(lambda req: httpx.Response(302, headers={"Location": "/login?next=/account"},
                                                       request=req))
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))

    def test_anonymous_login_page_confirms(self):
        page = ("<html><title>Sign in</title><form action='/login'>"
                "<input type='password' name='password'></form></html>")
        reports = self._run(lambda req: httpx.Response(200, text=page, request=req))
        self.assertEqual([r.status for r in reports], ["confirmed"], _evidence(reports))


if __name__ == "__main__":
    unittest.main()
