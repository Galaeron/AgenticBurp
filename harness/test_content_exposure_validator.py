"""AV-EXPOSURE-01 passive content-exposure adapter: the oracle and the engagement
coverage drive that calls it (r5: /ftp, /metrics and whoami?callback= reached but
no check judged them)."""
import asyncio
import unittest

from harness.coverage_model import CHECKS_BY_ID, CellStatus
from harness.models import HttpExchange
from harness.test_security_headers_validator import PassiveLegCallerTest, _finding
from harness.validators.content_exposure_validator import (
    ContentExposureValidator, audit_exposure)

_HTML = {"Content-Type": "text/html; charset=utf-8"}
_TEXT = {"Content-Type": "text/plain; version=0.0.4"}
_JS = {"Content-Type": "text/javascript; charset=utf-8"}
_JSON = {"Content-Type": "application/json"}
# Express serve-index, as Juice Shop serves /ftp.
_LISTING = ("<!DOCTYPE html><html><head><meta charset='utf-8'><title>listing directory /ftp</title>"
            "</head><body><ul id=\"files\"><li><a href=\"/ftp/acquisitions.md\">acquisitions.md</a>"
            "</li></ul></body></html>")
_METRICS = ("# HELP process_cpu_user_seconds_total Total user CPU time spent in seconds.\n"
            "# TYPE process_cpu_user_seconds_total counter\n"
            "process_cpu_user_seconds_total 12.5\n")
_JSONP = "/**/ typeof 1 === 'function' && 1({\"user\":{\"id\":1,\"email\":\"a@b.test\"}});"


def _ex(status=200, body="", headers=None, method="GET", url="http://t/a"):
    return HttpExchange(url=url, method=method, response_status=status,
                        response_headers=_HTML if headers is None else headers, response_body=body)


class AuditTests(unittest.TestCase):
    def test_r5_listing_metrics_and_jsonp_fail(self):
        self.assertEqual(audit_exposure(_ex(body=_LISTING))["matches"][0][0], "directory_listing")
        self.assertEqual(audit_exposure(_ex(body="<title>Index of /backup</title>"))["verdict"], "fail")
        self.assertEqual(audit_exposure(_ex(body=_METRICS, headers=_TEXT))["matches"][0][0],
                         "metrics_exposition")
        jsonp = audit_exposure(_ex(body=_JSONP, headers=_JS, url="http://t/rest/user/whoami?callback=1"))
        self.assertEqual(jsonp["matches"][0][0], "jsonp_callback")
        bare = audit_exposure(_ex(body="cb({})", headers=_JS, url="http://t/x?jsonp=cb"))
        self.assertEqual(bare["verdict"], "fail")

    def test_negative_controls_pass(self):
        # JSON for a request with no callback, a callback the body does not call,
        # prose that mentions a listing, and a comment line that is not an exposition.
        for ex in (_ex(body='{"user":{}}', headers=_JSON, url="http://t/rest/user/whoami"),
                   _ex(body='{"user":{}}', headers=_JSON, url="http://t/rest/user/whoami?callback=1"),
                   _ex(body="<p>Index of /docs is below</p>"),
                   _ex(body="# HELP wanted\nnot metrics", headers=_TEXT)):
            with self.subTest(url=ex.url, body=ex.response_body):
                self.assertEqual(audit_exposure(ex)["verdict"], "pass")

    def test_responses_that_cannot_decide_are_skipped(self):
        self.assertEqual(audit_exposure(_ex(404, _LISTING))["verdict"], "skip")
        self.assertEqual(audit_exposure(_ex(None, _LISTING))["verdict"], "skip")
        self.assertEqual(audit_exposure(_ex(body=_LISTING, method="POST"))["verdict"], "skip")
        self.assertEqual(audit_exposure(_ex(body=""))["verdict"], "skip")

    def test_check_is_a_passive_leg(self):
        from harness.coverage_tracker import _LEG_CONFIRMATIONS, _PASSIVE_LEG_CONFIRMATIONS
        check = CHECKS_BY_ID["AV-EXPOSURE-01"]
        self.assertEqual(check.confirmation, "content_exposure")
        self.assertIn("content_exposure", _LEG_CONFIRMATIONS)
        self.assertIn("content_exposure", _PASSIVE_LEG_CONFIRMATIONS)
        self.assertFalse(ContentExposureValidator.active)


class ValidateTests(unittest.TestCase):
    def test_confirmed_not_confirmed_and_skipped(self):
        def run(ex):
            return asyncio.run(ContentExposureValidator().validate(_finding(), ex))
        res = run(_ex(body=_LISTING))
        self.assertEqual((res.status, res.confirmed), ("confirmed", True))
        self.assertIn("directory_listing", res.evidence)
        self.assertEqual(run(_ex(body="<html>ok</html>")).status, "not_confirmed")
        self.assertEqual(run(_ex(500, _LISTING)).status, "skipped")


# path -> captures of one GET request (status, headers, body, query)
_PATHS = {
    "/ftp": [(200, _HTML, _LISTING, "")],
    "/metrics": [(200, _TEXT, _METRICS, "")],
    "/rest/user/whoami": [(200, _JS, _JSONP, "callback=1")],
    # Control: an ordinary JSON page.
    "/api/Products": [(200, _JSON, '{"data":[]}', "")],
    # No 2xx captured: skipped, never a negative.
    "/api/missing": [(404, _JSON, '{"error":"Not found"}', "")],
}


def _exposure_state(base, roles, **kwargs):
    from harness.engagement import EngagementState
    from harness.role_crawl import RoleCrawlResult
    state = EngagementState("localhost")
    for path, captures in _PATHS.items():
        for role in roles:
            for status, headers, body, query in captures:
                url = base + path + (f"?{query}" if query else "")
                state.record_template(url, "GET", HttpExchange(
                    url=url, method="GET", request_headers=role.headers,
                    response_status=status, response_headers=headers, response_body=body))
    for ep in state.endpoints.values():
        ep.reachable_roles = sorted({r.role for r in roles})
    return state, RoleCrawlResult(base_url=base)


class EngagementCallerTests(PassiveLegCallerTest):
    def run_caller(self, enabled, case_drive):
        return self.drive("content_exposure", "AV-EXPOSURE-01", ContentExposureValidator.name,
                          _exposure_state, enabled, case_drive)

    def test_r5_drive_judges_listing_metrics_and_jsonp_without_sending(self):
        for case_drive in (False, True):
            with self.subTest(case_drive=case_drive):
                calls, rows, found, sent = self.run_caller(True, case_drive)
                self.assertGreater(calls.await_count, 0)
                rows = self.by_path(rows, _PATHS)
                for path in ("/ftp", "/metrics", "/rest/user/whoami"):
                    self.assertTrue(rows[path] and all(
                        r["observation_status"] == CellStatus.CONFIRMED.value for r in rows[path]),
                        (path, rows[path]))
                self.assertTrue(all(r["observation_status"] == CellStatus.NOT_DETECTED.value
                                    for r in rows["/api/Products"]), rows["/api/Products"])
                self.assertTrue(all(not r["conclusive"] for r in rows["/api/missing"]), rows["/api/missing"])
                # The leg sends nothing. (whoami's captured query is a parameter, so
                # the pipeline's existing parameter probes may send to it.)
                quiet = ("/ftp", "/metrics", "/api/Products", "/api/missing")
                self.assertFalse([u for u in sent if any(p in u for p in quiet)], sent[:5])
                self.assertTrue(found)

    def test_disabled_adapter_is_unavailable_and_finds_nothing(self):
        calls, rows, found, _sent = self.run_caller(False, False)
        calls.assert_not_called()
        self.assertTrue(rows)
        self.assertTrue(all(r["terminal_reason"] == "validator_unavailable" for r in rows), rows)
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
