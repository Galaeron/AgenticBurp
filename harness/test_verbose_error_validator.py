"""Tests for the verbose-error / stack-trace / debug-info detector."""
import unittest

from harness.models import HttpExchange
from harness.validators.verbose_error_validator import (
    scan_exchange, findings_from_exchange, extract_disclosed_paths,
)


def _ex(body="", status=200, headers=None):
    return HttpExchange(
        url="http://t.test/api/endpoint",
        method="GET",
        request_headers={},
        request_body="",
        response_status=status,
        response_headers=headers or {},
        response_body=body,
    )


class ScanTests(unittest.TestCase):
    def test_python_traceback_detected(self):
        body = ('HTTP 500\nTraceback (most recent call last):\n'
                '  File "/app/views.py", line 42, in handle\n'
                '    result = db.query(sql)\nsqlite3.OperationalError: no such table')
        matches = scan_exchange(_ex(body, 500))
        names = {m[0] for m in matches}
        self.assertIn("python_traceback", names)
        self.assertIn("sql_error_detail", names)

    def test_java_stacktrace_detected(self):
        body = ("java.lang.NullPointerException\n"
                "at com.app.Service.process(Service.java:123)\n"
                "at com.app.Controller.handle(Controller.java:45)")
        matches = scan_exchange(_ex(body, 500))
        self.assertTrue(any(m[0] == "java_stacktrace" for m in matches))

    def test_flask_debug_detected(self):
        body = '<div class="debugger"><h1>Werkzeug Debugger</h1></div>'
        matches = scan_exchange(_ex(body))
        self.assertTrue(any(m[0] == "flask_debug" for m in matches))

    def test_env_variable_leak_detected(self):
        body = "SECRET_KEY=abc123\nDATABASE_URL=postgres://user:pass@db:5432/app"
        matches = scan_exchange(_ex(body))
        self.assertTrue(any(m[0] == "environment_variable_leak" for m in matches))

    def test_clean_response_no_matches(self):
        body = '{"users": [{"id": 1, "name": "Alice"}]}'
        matches = scan_exchange(_ex(body))
        self.assertEqual(len(matches), 0)

    def test_internal_path_disclosure(self):
        body = "Error loading config from /home/deploy/app/config.yaml"
        matches = scan_exchange(_ex(body))
        self.assertTrue(any(m[0] == "internal_path_disclosure" for m in matches))

    def test_x_powered_by_with_version(self):
        matches = scan_exchange(_ex("ok", headers={"X-Powered-By": "Express 4.18.2"}))
        self.assertTrue(any("x-powered-by" in m[0] for m in matches))

    def test_x_powered_by_without_version_ignored(self):
        matches = scan_exchange(_ex("ok", headers={"X-Powered-By": "Express"}))
        self.assertFalse(any("x-powered-by" in m[0] for m in matches))


class FindingsTests(unittest.TestCase):
    def test_produces_confirmed_finding(self):
        body = 'Traceback (most recent call last):\n  File "app.py", line 1'
        findings = findings_from_exchange(_ex(body, 500))
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].confirmed)
        self.assertEqual(findings[0].vulnerability_class, "verbose_error_disclosure")

    def test_no_finding_for_clean_response(self):
        findings = findings_from_exchange(_ex('{"ok": true}'))
        self.assertEqual(len(findings), 0)


class PathExtractionTests(unittest.TestCase):
    def test_extracts_routes_from_error(self):
        body = ('Route not found: GET /api/admin/secret-panel\n'
                'Available routes: "/api/users", "/web/dashboard"')
        paths = extract_disclosed_paths(_ex(body))
        self.assertIn("/api/admin/secret-panel", paths)
        self.assertIn("/api/users", paths)
        self.assertIn("/web/dashboard", paths)

    def test_extracts_flask_route_decorator(self):
        body = '@app.route("/api/internal/config")\ndef get_config():'
        paths = extract_disclosed_paths(_ex(body))
        self.assertIn("/api/internal/config", paths)

    def test_no_paths_from_clean_json(self):
        body = '{"items": [{"id": 1}]}'
        paths = extract_disclosed_paths(_ex(body))
        self.assertEqual(paths, [])


if __name__ == "__main__":
    unittest.main()
