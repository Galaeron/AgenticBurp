"""WSTG-ERRH-01 passive error-disclosure adapter: the oracle and the engagement
coverage drive that calls it."""
import asyncio
import unittest

from harness.coverage_model import CellStatus
from harness.models import HttpExchange
from harness.test_security_headers_validator import PassiveLegCallerTest, _finding
from harness.validators.error_handling_validator import (
    ErrorHandlingValidator, audit_error_response)

_HTML = {"Content-Type": "text/html; charset=utf-8"}
_NODE_TRACE = ("<h1>Error: Unexpected path: /api/crash</h1><ul id=\"stacktrace\">"
               "<li> &nbsp; &nbsp;at /app/build/routes/angular.js:15:18</li>"
               "<li> &nbsp; &nbsp;at Layer.handle [as handle_request] "
               "(/app/node_modules/express/lib/router/layer.js:95:5)</li></ul>")


def _ex(status=500, body="", headers=None, method="GET"):
    return HttpExchange(url="http://t/a", method=method, response_status=status,
                        response_headers=_HTML if headers is None else headers, response_body=body)


class AuditTests(unittest.TestCase):
    def audit(self, *args, **kwargs):
        return audit_error_response(_ex(*args, **kwargs))

    def test_runtime_traces_and_framework_pages_fail(self):
        cases = {
            "node_stacktrace": _NODE_TRACE,
            "python_traceback": "Traceback (most recent call last):\n  ValueError: x",
            "python_frame": "File &quot;/srv/app/views.py&quot;, line 12, in index",
            "java_stacktrace": "java.lang.NullPointerException\n\tat com.acme.web.Ctl.show(Ctl.java:42)",
            "dotnet_stacktrace": r"at Acme.Web.Ctl.Show(Int32 id) in C:\src\Ctl.cs:line 42",
            "php_error": "<b>Fatal error</b>:  Uncaught Error in <b>/var/www/x.php</b> on line <b>3</b>",
            "werkzeug_debugger": "<title>ValueError // Werkzeug Debugger</title>",
            "django_debug": "You&#x27;re seeing this error because you have DEBUG = True",
            "rails_debug": "<h1>Action Controller: Exception caught</h1>",
            "aspnet_error_page": "<h1>Server Error in '/' Application.</h1>",
            "spring_whitelabel": "<h1>Whitelabel Error Page</h1>",
            "sql_error": "SQLITE_ERROR: near \"'\": syntax error",
        }
        for name, body in cases.items():
            with self.subTest(name=name):
                audit = self.audit(500, body)
                self.assertEqual(audit["verdict"], "fail")
                self.assertIn(name, [m[0] for m in audit["matches"]])
        # JSON error bodies carry traces as escaped strings.
        self.assertEqual(self.audit(500, '{"stack":"Error: x\\n    at /app/server.js:12:5"}',
                                    {"Content-Type": "application/json"})["verdict"], "fail")

    def test_severity_is_the_worst_signature(self):
        self.assertEqual(self.audit(500, "Werkzeug Debugger")["severity"], "high")
        self.assertEqual(self.audit(500, _NODE_TRACE)["severity"], "medium")
        self.assertEqual(self.audit(404, "Whitelabel Error Page")["severity"], "low")

    def test_clean_error_responses_pass(self):
        self.assertEqual(self.audit(404, '{"error":"Not found"}', {"Content-Type": "application/json"})["verdict"], "pass")
        self.assertEqual(self.audit(500, "<h1>Something went wrong</h1>")["verdict"], "pass")
        # Ordinary prose that shares words with a signature is not one.
        for body in ("Warning: invalid input", "Meet us at 10:30 at /about", "An error occurred at line 3",
                     "See File \"report\" for details", "There was an unexpected error"):
            with self.subTest(body=body):
                self.assertEqual(self.audit(500, body)["verdict"], "pass")
        # A body that is empty on the wire is judged empty.
        self.assertEqual(self.audit(404, "", dict(_HTML, **{"Content-Length": "0"}))["verdict"], "pass")

    def test_responses_that_cannot_decide_are_skipped(self):
        # A 2xx page may quote a trace as content; errors are not provoked here.
        self.assertEqual(self.audit(200, _NODE_TRACE)["verdict"], "skip")
        self.assertEqual(self.audit(302, "")["verdict"], "skip")
        self.assertEqual(self.audit(None, _NODE_TRACE)["verdict"], "skip")
        self.assertEqual(self.audit(500, _NODE_TRACE, method="HEAD")["verdict"], "skip")
        # A static asset may carry the strings as code.
        self.assertEqual(self.audit(500, _NODE_TRACE, {"Content-Type": "application/javascript"})["verdict"], "skip")
        # A body that was not kept (an access-matrix probe keeps only its digest).
        self.assertEqual(self.audit(500, "", dict(_HTML, **{"Content-Length": "900"}))["verdict"], "skip")
        self.assertEqual(self.audit(500, "")["verdict"], "skip")


class ValidateTests(unittest.TestCase):
    def validate(self, exchange):
        return asyncio.run(ErrorHandlingValidator().validate(_finding(), exchange))

    def test_confirmed_not_confirmed_and_skipped(self):
        res = self.validate(_ex(500, _NODE_TRACE))
        self.assertEqual((res.status, res.confirmed, res.severity), ("confirmed", True, "medium"))
        self.assertIn("node_stacktrace", res.evidence)
        held = self.validate(_ex(404, "<h1>Not found</h1>"))
        self.assertEqual((held.status, held.confirmed), ("not_confirmed", False))
        skipped = self.validate(_ex(200, "<html>ok</html>"))
        self.assertEqual((skipped.status, skipped.confirmed), ("skipped", False))

    def test_cache_key_follows_the_captured_response(self):
        from harness.execution_registry import execution_key
        name = ErrorHandlingValidator.name
        self.assertNotEqual(execution_key(name, _ex(500, _NODE_TRACE), "info_disclosure"),
                            execution_key(name, _ex(500, "<h1>oops</h1>"), "info_disclosure"))


# path -> captures of one GET request (status, headers, body)
_PATHS = {
    # Positive: an error page with a stack trace, also captured once as a 200 and
    # once with its body not kept -- neither may hide the trace.
    "/api/crash": [(500, _HTML, _NODE_TRACE), (200, _HTML, "<html>ok</html>"),
                   (500, dict(_HTML, **{"Content-Length": "900"}), "")],
    # Control: a clean error response.
    "/api/missing": [(404, {"Content-Type": "application/json"}, '{"error":"Not found"}'),
                     (200, _HTML, "<html>ok</html>")],
    # No error response captured: skipped, never a negative.
    "/api/ok": [(200, _HTML, "<html>ok</html>")],
}


def _error_state(base, roles, **kwargs):
    from harness.engagement import EngagementState
    from harness.role_crawl import RoleCrawlResult
    state = EngagementState("localhost")
    for path, captures in _PATHS.items():
        for role in roles:
            for status, headers, body in captures:
                state.record_template(base + path, "GET", HttpExchange(
                    url=base + path, method="GET", request_headers=role.headers,
                    response_status=status, response_headers=headers, response_body=body))
    for ep in state.endpoints.values():
        ep.reachable_roles = sorted({r.role for r in roles})
    return state, RoleCrawlResult(base_url=base)


class EngagementCallerTests(PassiveLegCallerTest):
    def run_caller(self, enabled, case_drive):
        return self.drive("error_handling", "WSTG-ERRH-01", ErrorHandlingValidator.name,
                          _error_state, enabled, case_drive)

    def test_drive_confirms_controls_and_skips_without_sending(self):
        for case_drive in (False, True):
            with self.subTest(case_drive=case_drive):
                calls, rows, found, sent = self.run_caller(True, case_drive)
                self.assertGreater(calls.await_count, 0)
                rows = self.by_path(rows, _PATHS)
                for path in _PATHS:
                    self.assertTrue(rows[path], path)
                self.assertTrue(all(r["observation_status"] == CellStatus.CONFIRMED.value and r["conclusive"]
                                    for r in rows["/api/crash"]), rows["/api/crash"])
                self.assertTrue(all(r["observation_status"] == CellStatus.NOT_DETECTED.value
                                    for r in rows["/api/missing"]), rows["/api/missing"])
                self.assertTrue(all(r["observation_status"] in (CellStatus.SKIPPED.value, CellStatus.PENDING.value)
                                    and not r["conclusive"] and r["terminal_reason"] == "leg_precondition_unmet"
                                    for r in rows["/api/ok"]), rows["/api/ok"])
                self.assertFalse([u for u in sent if any(p in u for p in _PATHS)], sent)
                self.assertTrue(found)
                self.assertTrue(all(f["url"].endswith("/api/crash") for f in found), found)
                self.assertTrue(all(f["severity"] == "medium" for f in found), found)

    def test_disabled_adapter_is_unavailable_and_finds_nothing(self):
        calls, rows, found, _sent = self.run_caller(False, False)
        calls.assert_not_called()
        self.assertTrue(rows)
        self.assertTrue(all(r["terminal_reason"] == "validator_unavailable" for r in rows), rows)
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
