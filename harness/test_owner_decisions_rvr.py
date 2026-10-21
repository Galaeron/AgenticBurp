"""Code review 02, batch RV-R: two owner decisions of 2026-10-21 (CURRENT_STATE
"Owner decisions") on questions batch RV-L recorded.

R1 An MFA step-up redirect is not a denial. The MFA-bypass anonymous control
   takes the healthy-denial rule session fixation uses (RV-E2 E3): HTTP 401/403,
   a redirect to a login path or a 2xx login page. A redirect to a step-up page
   is never a login path here, even under a login-looking path. Any other answer
   (another 3xx, a 429, an empty 200) leaves a candidate that names it.
R2 CORS origin reflection without Access-Control-Allow-Credentials still
   confirms, with a note: a cross-origin page reads the response only as a
   visitor without the user's cookies, so the impact is limited to data the
   server returns without credentials. With credentials allowed, the wording
   says the authenticated response is readable cross-origin.

Each test drives the production caller. R1 runs Orchestrator._validate_findings
against RV-L's owned loopback app; R2 runs it with the transport faked below the
gated client, and follows the confirmed finding through Orchestrator.analyze
into a temporary store and back out of every export.
"""
import asyncio
import json
import sqlite3
import unittest
from unittest.mock import patch

import httpx

from harness import evidence_ledger, report_generator, sarif_adapter, store
from harness.models import AgentReport, StageOutcome
from harness.test_confirmation_soundness_rve import _CallerBase, _finding, _json_exchange, _verdicts
from harness.test_default_history_caller import _exchange
from harness.test_unsent_not_negative_rvl import _MfaApp, _text
from harness.validators.auth_sequence_validator import AuthSequenceValidator
from harness.validators.cors_validator import CorsValidator


# ------------------------------------------- R1 MFA step-up is not a denial
# unittest.TestCase is named explicitly (already in _CallerBase's MRO) so the
# static collection guard in test_no_orphan_test_files sees this as a test case.
class MfaStepUpRedirectTests(_CallerBase, unittest.TestCase):
    """The step-1-only session reaches the account page in every case below;
    only the answer to the same path with no session changes."""

    def _run(self, anonymous):
        app = _MfaApp(anonymous)
        self.addCleanup(app.close)
        return self._validate("auth_sequence", AuthSequenceValidator(allowed_hosts=["127.0.0.1"]),
                              _finding("2fa_bypass"),
                              _json_exchange(app.url, "POST", '{"username": "alice", "password": "pw"}'),
                              hosts=("127.0.0.1",))

    def _assert_candidate(self, reports, *names):
        self.assertFalse(any(r.confirmed for r in reports), _text(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        for name in names:
            self.assertIn(name, _text(reports))
        self.assertNotIn("was denied", _text(reports))

    def _assert_confirmed(self, reports, denial):
        self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))
        self.assertIn(f"was denied ({denial}", _text(reports))

    # Reproductions: each confirmed before R1.
    def test_step_up_redirect_is_a_candidate(self):
        self._assert_candidate(self._run((302, {"Location": "/2fa/verify"}, "")),
                               "HTTP 302", "/2fa/verify", "second-factor step")

    def test_step_up_redirect_under_a_login_path_is_a_candidate(self):
        # /login/2fa has a login path segment, but it is the second-factor step.
        self._assert_candidate(self._run((302, {"Location": "/login/2fa?next=/my-account"}, "")),
                               "HTTP 302", "/login/2fa", "second-factor step")

    def test_redirect_to_a_non_login_page_is_a_candidate(self):
        self._assert_candidate(self._run((302, {"Location": "/"}, "")), "HTTP 302")

    def test_rate_limit_is_a_candidate(self):
        self._assert_candidate(self._run((429, {"Retry-After": "30"}, "slow down")), "HTTP 429")

    def test_empty_200_is_a_candidate(self):
        self._assert_candidate(self._run((200, {}, "")), "HTTP 200")

    # Controls: a healthy denial still confirms, and its evidence names it.
    def test_anonymous_401_and_403_still_confirm(self):
        for status in (401, 403):
            with self.subTest(status=status):
                self._assert_confirmed(self._run((status, {}, "login required")), f"HTTP {status}")

    def test_redirect_to_the_login_page_still_confirms(self):
        self._assert_confirmed(self._run((302, {"Location": "/login?next=/my-account"}, "")),
                               "HTTP 302 redirect to the login page /login?next=/my-account")

    def test_login_page_still_confirms(self):
        page = ("<html><title>Sign in</title><form action='/login' method='POST'>"
                "<input name='username'><input type='password' name='password'></form></html>")
        self._assert_confirmed(self._run((200, {}, page)), "HTTP 200 login page")


# ------------------------------------- R2 CORS reflection: the impact note
_LIMITED = "without the user's cookies"
_CREDENTIALED = "authenticated response"


def _cors_server(*, credentials, reflect=True, wildcard=False):
    """Fake transport below the gated client: answers every probe as the
    configured CORS policy would."""
    sent = []

    async def request(client, method, url, **kwargs):
        origin = (kwargs.get("headers") or {}).get("Origin", "")
        sent.append((method, str(url), origin))
        headers = {}
        if wildcard:
            headers["Access-Control-Allow-Origin"] = "*"
        elif reflect and origin:
            headers["Access-Control-Allow-Origin"] = origin
        if credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        return httpx.Response(200, text='{"id": 1}', headers=headers, request=httpx.Request(method, url))
    return request, sent


class CorsReflectionNoteTests(_CallerBase, unittest.TestCase):
    def _run(self, **policy):
        """Reports from the caller, plus the Origin Reflection probe's own record
        from the ValidationResult's raw output (a ValidationReport drops it)."""
        request, sent = _cors_server(**policy)
        validator = CorsValidator(allowed_hosts=["shop.invalid"])
        results, validate = [], validator.validate

        async def recording(finding, exchange):
            results.append(await validate(finding, exchange))
            return results[-1]
        validator.validate = recording
        reports = self._validate("cors_validator", validator, _finding("cors"),
                                 _exchange("http://shop.invalid/api/profile"), request)
        self.assertTrue(sent)
        self.assertEqual(len(results), 1)
        tests = json.loads(results[0].raw_output or "[]")
        return reports, next((t for t in tests if t["test"] == "Origin Reflection"), None)

    def test_reflection_without_credentials_confirms_with_the_limited_note(self):
        reports, probe = self._run(credentials=False)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        self.assertTrue(reports[0].confirmed)
        for text in (reports[0].summary, reports[0].evidence):
            self.assertIn("Origin Reflection: Server reflects arbitrary Origin header", text)
            self.assertIn(_LIMITED, text)
            self.assertIn("limited to data the server returns without credentials", text)
            self.assertNotIn(_CREDENTIALED, text)
        self.assertIn("(medium)", reports[0].evidence)
        self.assertEqual(probe["severity"], "medium")
        self.assertIn("no Access-Control-Allow-Credentials", probe["evidence"])
        self.assertIn(_LIMITED, probe["evidence"])

    def test_reflection_with_credentials_says_the_authenticated_response_is_readable(self):
        reports, probe = self._run(credentials=True)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        for text in (reports[0].summary, reports[0].evidence):
            self.assertIn("Origin Reflection: Server reflects arbitrary Origin header", text)
            self.assertIn(_CREDENTIALED, text)
            self.assertIn("readable cross-origin", text)
            self.assertNotIn(_LIMITED, text)
        self.assertIn("(medium)", reports[0].evidence)
        self.assertEqual(probe["severity"], "medium")
        self.assertIn("Access-Control-Allow-Credentials: true", probe["evidence"])

    # Controls.
    def test_wildcard_with_credentials_stays_informational(self):
        reports, probe = self._run(credentials=True, wildcard=True)
        self.assertIsNone(probe)
        self.assertFalse(any(r.confirmed for r in reports), _verdicts(reports))
        self.assertEqual([r.status for r in reports], ["safe"], _verdicts(reports))
        self.assertIn("Fetch standard", reports[0].evidence)
        self.assertNotIn(_LIMITED, _text(reports))

    def test_non_reflecting_server_stays_negative(self):
        reports, probe = self._run(credentials=False, reflect=False)
        self.assertIsNone(probe)
        self.assertFalse(any(r.confirmed for r in reports), _verdicts(reports))
        self.assertEqual([r.status for r in reports], ["safe"], _verdicts(reports))
        self.assertNotIn(_LIMITED, _text(reports))


class CorsNoteStorageExportTests(_CallerBase, unittest.TestCase):
    """Where the note is persisted and exported. analyze() writes to the
    temporary store _CallerBase installs, and each reader below comes back out
    of SQLite.

    What each surface can carry is asserted as it is today. The validation run
    and the confirmation proof keep the validator's own text for every finding.
    The stored finding has no column for the validator's summary, so its
    evidence carries the note only when the finding arrived without evidence of
    its own (a shape-precondition placeholder), and the issue export and the
    Markdown report read that evidence. SARIF's message is the issue title, so
    it carries no validator text for any check."""

    URL = "http://shop.invalid/api/profile"

    def setUp(self):
        super().setUp()
        evidence_ledger.reset_default_ledger()
        self.addCleanup(evidence_ledger.reset_default_ledger)

    def _analyze(self, *, credentials, finding_evidence="fixture"):
        orch = self._orch()
        orch.validator_registry.active_enabled = True
        orch.validator_registry.validators = {"cors": CorsValidator(allowed_hosts=["shop.invalid"])}
        finding = _finding("cors").model_copy(update={"evidence": finding_evidence})

        async def pipeline(*args, **kwargs):
            return ([AgentReport(agent="cors", model="fake", findings=[finding])], 0, 0,
                    StageOutcome(name="critique", status="skipped", reason="fixture"))
        request, sent = _cors_server(credentials=credentials)
        with patch("harness.analysis_pipeline.AnalysisPipeline.run_full_analysis", pipeline), \
                patch.object(httpx.AsyncClient, "request", request):
            result = asyncio.run(orch.analyze(_exchange(self.URL), force_agents=["cors"],
                                              bypass_cache=True))
        self.assertTrue(sent)
        self.assertTrue(any(v.confirmed for v in result.validation_reports),
                        _verdicts(result.validation_reports))
        evidence_ledger.reset_default_ledger()  # read back from SQLite only
        return result

    def _stored(self):
        stored = [f for f in store.all_host_findings(self.URL) if f["vulnerability_class"] == "cors"]
        self.assertEqual(len(stored), 1, "the confirmed cors finding was not stored once")
        self.assertTrue(stored[0]["confirmed"])
        return stored[0]

    def _validator_records(self):
        """The validation run and the confirmation proof, each as stored."""
        conn = sqlite3.connect(str(store._DB_PATH))
        try:
            runs = conn.execute("SELECT summary, evidence FROM validation_runs "
                                "WHERE status = 'confirmed'").fetchall()
        finally:
            conn.close()
        proofs = store.proofs_for_case(self._stored()["case_id"])
        self.assertTrue(runs, "no confirmed validation run was stored")
        self.assertTrue(proofs, "no confirmation proof was stored")
        return {"validation run": json.dumps(runs),
                "confirmation proof": json.dumps([p["observed_result"] for p in proofs])}

    def _finding_surfaces(self):
        issues = [i for i in report_generator.export_issues_for_host(self.URL)
                  if i["vulnerability_class"] == "cors"]
        self.assertTrue(issues and all(i["confirmed"] for i in issues), issues)
        return {"stored finding": self._stored()["evidence"],
                "issue export": json.dumps([i["evidence"] for i in issues]),
                "Markdown report": report_generator.generate_report_for_host(self.URL)}

    def test_limited_note_is_persisted_with_the_validation(self):
        self._analyze(credentials=False)
        for surface, text in self._validator_records().items():
            with self.subTest(surface=surface):
                self.assertIn(_LIMITED, text)

    def test_limited_note_reaches_a_placeholder_finding_and_its_exports(self):
        self._analyze(credentials=False, finding_evidence="")
        for surface, text in {**self._validator_records(), **self._finding_surfaces()}.items():
            with self.subTest(surface=surface):
                self.assertIn(_LIMITED, text)
                self.assertNotIn(_CREDENTIALED, text)

    def test_credentialed_wording_reaches_a_placeholder_finding_and_its_exports(self):
        self._analyze(credentials=True, finding_evidence="")
        for surface, text in {**self._validator_records(), **self._finding_surfaces()}.items():
            with self.subTest(surface=surface):
                self.assertIn(_CREDENTIALED, text)
                self.assertNotIn(_LIMITED, text)

    def test_sarif_still_marks_the_finding_confirmed(self):
        # SARIF carries the title, not the evidence; the confirmation must survive.
        self._analyze(credentials=False, finding_evidence="")
        issues = report_generator.export_issues_for_host(self.URL)
        results = [r for run in sarif_adapter.export_issues_to_sarif(issues)["runs"]
                   for r in run["results"] if r["ruleId"] == "cors"]
        self.assertEqual(len(results), 1, results)
        title = next(i["title"] for i in issues if i["vulnerability_class"] == "cors")
        self.assertEqual(results[0]["message"]["text"], title)  # no unconfirmed-state marker


if __name__ == "__main__":
    unittest.main()
