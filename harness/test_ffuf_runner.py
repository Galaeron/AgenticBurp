"""Tests for ffuf_runner -- container-based content discovery."""
import base64
import json
import unittest
from unittest.mock import patch, MagicMock

from harness import ffuf_runner
from harness.api_surface_discovery import Route


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class BuildArgsTests(unittest.TestCase):
    """build_args is pure -- test it without Docker or network."""

    def test_basic_args(self):
        args = ffuf_runner.build_args("http://localhost:5002")
        self.assertIn("-u", args)
        url_idx = args.index("-u") + 1
        self.assertIn("host.docker.internal:5002/FUZZ", args[url_idx])
        self.assertIn("-s", args)
        self.assertIn("-json", args)
        self.assertIn("-ac", args)

    def test_localhost_rewritten(self):
        args = ffuf_runner.build_args("http://127.0.0.1:8080")
        url_idx = args.index("-u") + 1
        self.assertIn("host.docker.internal:8080", args[url_idx])

    def test_non_loopback_unchanged(self):
        args = ffuf_runner.build_args("http://example.com")
        url_idx = args.index("-u") + 1
        self.assertIn("example.com/FUZZ", args[url_idx])

    def test_headers_passed(self):
        args = ffuf_runner.build_args("http://localhost:5002",
                                      headers={"Authorization": "Bearer tok123"})
        h_idx = args.index("-H")
        self.assertEqual(args[h_idx + 1], "Authorization: Bearer tok123")

    def test_no_auto_calibrate(self):
        args = ffuf_runner.build_args("http://localhost:5002", auto_calibrate=False)
        self.assertNotIn("-ac", args)

    def test_threads_configurable(self):
        args = ffuf_runner.build_args("http://localhost:5002", threads=10)
        t_idx = args.index("-t") + 1
        self.assertEqual(args[t_idx], "10")

    def test_trailing_slash_stripped(self):
        args = ffuf_runner.build_args("http://localhost:5002/")
        url_idx = args.index("-u") + 1
        self.assertNotIn("//FUZZ", args[url_idx])
        self.assertTrue(args[url_idx].endswith("/FUZZ"))


class ParseJsonLinesTests(unittest.TestCase):
    """parse_json_lines converts ffuf -json output to Route objects."""

    def _line(self, fuzz, status=200, length=42):
        return json.dumps({"input": {"FUZZ": fuzz}, "status": status, "length": length})

    def test_single_result(self):
        stdout = self._line("api/health", 200, 15)
        routes = ffuf_runner.parse_json_lines(stdout)
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].path, "/api/health")
        self.assertEqual(routes[0].status, 200)
        self.assertEqual(routes[0].length, 15)
        self.assertEqual(routes[0].source, "ffuf")

    def test_multiple_results(self):
        stdout = "\n".join([
            self._line("api/login", 200, 50),
            self._line("api/tickets", 401, 30),
            self._line(".env", 200, 100),
        ])
        routes = ffuf_runner.parse_json_lines(stdout)
        self.assertEqual(len(routes), 3)
        paths = [r.path for r in routes]
        self.assertIn("/api/login", paths)
        self.assertIn("/api/tickets", paths)
        self.assertIn("/.env", paths)

    def test_empty_stdout(self):
        self.assertEqual(ffuf_runner.parse_json_lines(""), [])
        self.assertEqual(ffuf_runner.parse_json_lines("\n\n"), [])

    def test_malformed_json_skipped(self):
        stdout = "not json\n" + self._line("api/health") + "\nalso garbage"
        routes = ffuf_runner.parse_json_lines(stdout)
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].path, "/api/health")

    def test_missing_fuzz_skipped(self):
        stdout = json.dumps({"input": {}, "status": 200})
        routes = ffuf_runner.parse_json_lines(stdout)
        self.assertEqual(len(routes), 0)

    def test_leading_slash_normalized(self):
        stdout = self._line("/already/slashed")
        routes = ffuf_runner.parse_json_lines(stdout)
        self.assertEqual(routes[0].path, "/already/slashed")


class ParseJsonLinesBase64Tests(unittest.TestCase):
    """Real ffuf -json output base64-encodes each `input` keyword value (so a
    binary/non-UTF8 wordlist entry survives JSON safely) -- parse_json_lines
    must decode it back to the real path, not feed the base64 blob itself
    back into discovery as a candidate route. Regression for a live run where
    role_crawl's active-discovery sweep fed base64 blobs like /LmVudg== back
    into the probe queue instead of the real /.env they decode to, silently
    starving 9 of 13 ground-truth findings that only the real path would
    have reached."""

    def _b64_line(self, real_value, status=200, length=42):
        return json.dumps({"input": {"FUZZ": _b64(real_value)}, "status": status, "length": length})

    def test_dotenv_decoded_not_left_base64(self):
        stdout = self._b64_line(".env", 200, 146)
        routes = ffuf_runner.parse_json_lines(stdout)
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].path, "/.env")
        self.assertNotEqual(routes[0].path, "/LmVudg==")

    def test_nested_api_path_decoded(self):
        stdout = self._b64_line("api/account/profile")
        routes = ffuf_runner.parse_json_lines(stdout)
        self.assertEqual(routes[0].path, "/api/account/profile")

    def test_multiple_real_ffuf_style_results(self):
        stdout = "\n".join([
            self._b64_line("api/login"),
            self._b64_line("api/tickets/search"),
            self._b64_line("api/integrations"),
        ])
        routes = ffuf_runner.parse_json_lines(stdout)
        paths = {r.path for r in routes}
        self.assertEqual(paths, {"/api/login", "/api/tickets/search", "/api/integrations"})
        # negative control: none of the base64 encodings themselves leak through
        for p in paths:
            self.assertNotIn("=", p)

    def test_non_base64_fuzz_value_falls_back_to_raw(self):
        # Defensive path for a hypothetical ffuf version that stops
        # base64-encoding `input` -- a raw value that ISN'T valid base64
        # (most real path segments, since '.' and unpadded lengths aren't
        # valid base64) must still come through unchanged, not get dropped.
        stdout = json.dumps({"input": {"FUZZ": "api/plain-path"}, "status": 200, "length": 10})
        routes = ffuf_runner.parse_json_lines(stdout)
        self.assertEqual(routes[0].path, "/api/plain-path")


class ParseSilentLinesTests(unittest.TestCase):
    """parse_silent_lines handles -s (no -json) output."""

    def test_basic(self):
        stdout = "api/health\napi/login\n"
        routes = ffuf_runner.parse_silent_lines(stdout)
        self.assertEqual(len(routes), 2)
        self.assertEqual(routes[0].path, "/api/health")
        self.assertEqual(routes[1].path, "/api/login")

    def test_empty(self):
        self.assertEqual(ffuf_runner.parse_silent_lines(""), [])

    def test_blank_lines_skipped(self):
        routes = ffuf_runner.parse_silent_lines("  \n\napi/x\n  \n")
        self.assertEqual(len(routes), 1)


class AvailabilityTests(unittest.TestCase):
    """ffuf_available checks Docker + image presence."""

    @patch("harness.tool_runner.available", return_value=(True, "ok"))
    @patch("harness.tool_runner.image_present", return_value=True)
    def test_available(self, _img, _dock):
        ok, reason = ffuf_runner.ffuf_available()
        self.assertTrue(ok)

    @patch("harness.tool_runner.available", return_value=(False, "no docker"))
    def test_no_docker(self, _dock):
        ok, reason = ffuf_runner.ffuf_available()
        self.assertFalse(ok)
        self.assertIn("docker", reason.lower())

    @patch("harness.tool_runner.available", return_value=(True, "ok"))
    @patch("harness.tool_runner.image_present", return_value=False)
    def test_no_image(self, _img, _dock):
        ok, reason = ffuf_runner.ffuf_available()
        self.assertFalse(ok)
        self.assertIn("not found", reason)


class RunSyncTests(unittest.TestCase):
    """run_sync with mocked tool_runner.run -- never touches Docker."""

    def _mock_run(self, stdout="", stderr="", rc=0):
        return patch("harness.tool_runner.run", return_value=(rc, stdout, stderr))

    def test_success_json(self):
        line = json.dumps({"input": {"FUZZ": "api/login"}, "status": 200, "length": 42})
        with self._mock_run(stdout=line):
            result = ffuf_runner.run_sync("http://localhost:5002")
        self.assertIsNone(result.error)
        self.assertEqual(len(result.routes), 1)
        self.assertEqual(result.routes[0].path, "/api/login")

    def test_success_silent_fallback(self):
        with self._mock_run(stdout="api/health\napi/login\n"):
            result = ffuf_runner.run_sync("http://localhost:5002")
        self.assertIsNone(result.error)
        self.assertEqual(len(result.routes), 2)

    def test_error_no_output(self):
        with self._mock_run(stdout="", stderr="connection refused", rc=1):
            result = ffuf_runner.run_sync("http://localhost:5002")
        self.assertIsNotNone(result.error)
        self.assertEqual(result.routes, [])

    def test_nonzero_exit_with_output_still_parses(self):
        line = json.dumps({"input": {"FUZZ": "api/x"}, "status": 200, "length": 10})
        with self._mock_run(stdout=line, rc=1):
            result = ffuf_runner.run_sync("http://localhost:5002")
        self.assertIsNone(result.error)
        self.assertEqual(len(result.routes), 1)

    def test_exception_handled(self):
        with patch("harness.tool_runner.run", side_effect=Exception("boom")):
            result = ffuf_runner.run_sync("http://localhost:5002")
        self.assertIsNotNone(result.error)
        self.assertIn("boom", result.error)

    def test_headers_forwarded(self):
        with patch("harness.tool_runner.run", return_value=(0, "", "")) as mock_run:
            ffuf_runner.run_sync("http://localhost:5002",
                                 headers={"Authorization": "Bearer t"})
        args_passed = mock_run.call_args[0][1]
        self.assertIn("-H", args_passed)
        h_idx = args_passed.index("-H")
        self.assertEqual(args_passed[h_idx + 1], "Authorization: Bearer t")


class NegativeControlTests(unittest.TestCase):
    """The negative controls: ffuf never produces routes from empty/error output."""

    def test_no_routes_from_empty(self):
        self.assertEqual(ffuf_runner.parse_json_lines(""), [])
        self.assertEqual(ffuf_runner.parse_silent_lines(""), [])

    def test_no_routes_from_pure_garbage(self):
        garbage = "!!!@@@###\nERROR: cannot connect\n{broken json\n"
        self.assertEqual(ffuf_runner.parse_json_lines(garbage), [])
        # silent parser treats each line as a path -- that's intentional (ffuf -s
        # output is one FUZZ value per line); the real negative control is that
        # run_sync won't reach the parser when rc!=0 and stdout is empty.

    def test_run_sync_error_produces_no_routes(self):
        with patch("harness.tool_runner.run", return_value=(1, "", "error")):
            result = ffuf_runner.run_sync("http://localhost:5002")
        self.assertEqual(result.routes, [])
        self.assertIsNotNone(result.error)


class StrictSilentParseTests(unittest.TestCase):
    """#10: the silent fallback must not turn arbitrary diagnostic output into paths."""

    def test_diagnostic_lines_are_not_fabricated_as_paths(self):
        noise = ("[ERR] connection reset\n"
                 ":: Progress: [1000/1000] :: Job [1/1]\n"
                 "https://evil.example/leak\n"
                 "admin panel here\n"       # has a space -> not a single token
                 "api/real-endpoint\n")     # the only legitimate FUZZ value
        routes = ffuf_runner.parse_silent_lines(noise)
        paths = [r.path for r in routes]
        self.assertEqual(paths, ["/api/real-endpoint"])

    def test_used_fallback_flag_surfaced(self):
        from harness import tool_runner
        from unittest.mock import patch
        with patch.object(tool_runner, "run", return_value=(0, "api/x\n", "")):
            result = ffuf_runner.run_sync("http://t.test")
        self.assertTrue(result.used_fallback)
        self.assertEqual([r.path for r in result.routes], ["/api/x"])


if __name__ == "__main__":
    unittest.main()
